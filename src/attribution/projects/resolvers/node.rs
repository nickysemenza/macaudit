//! pnpm/npm/yarn/bun package caches and the pinned Node toolchain: `~/Library/pnpm/store` membership, `package-lock.json` -> `~/.npm/_cacache`, `yarn.lock`/`bun.lock(b)` caches, `.nvmrc`/`.node-version`/`mise.toml`/`volta.node` -> installed toolchain.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::super::Project;
use crate::attribution::model::{Claim, EntryKind, EvidenceTier, ResolveEnv, BASELINE_OWNER};
use crate::attribution::paths as attribution_paths;
use crate::model::ScannerId;

/// `env.read_head`'s cap for a lockfile (`package-lock.json`, `yarn.lock`,
/// `bun.lock`) — generous, since a large monorepo lockfile runs into the
/// low megabytes.
const MAX_LOCKFILE_BYTES: usize = 8 * 1024 * 1024;
/// Files scanned in `~/.npm/_cacache/index-v5` before giving up — that
/// directory can hold entries for every package ever installed anywhere.
const MAX_INDEX_FILES: usize = 50_000;

/// Resolve this resource kind's claims for `project`. Stub until its lane
/// lands (see the module doc for which chunk).
pub fn resolve(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    if !project.root.join("package.json").exists() {
        return Vec::new();
    }
    let owner = project.root.to_string_lossy().into_owned();
    let mut claims = Vec::new();

    claims.extend(pnpm_claims(project, env, &owner));

    if let Some(text) = env.read_head(&project.root.join("package-lock.json"), MAX_LOCKFILE_BYTES) {
        let wanted: HashSet<(String, String)> = parse_package_lock(&text)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        claims.extend(npm_cache_claims(env, &owner, &wanted));
    }

    claims.extend(yarn_berry_claims(project, env, &owner));
    claims.extend(bun_claims(project, env, &owner));

    if let Some(pin) = node_version_pin(project, env) {
        if let Some(claim) = node_toolchain_claim(env, &owner, &pin) {
            claims.push(claim);
        }
    }

    claims.into_iter().map(|c| c.ecosystem("node")).collect()
}

/// pnpm's global/dlx caches, npm's index + logs, bun's shared cache (when no
/// project claimed it more specifically), and the Homebrew-installed
/// default `node`.
pub fn baseline(env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut claims = Vec::new();

    for rel in ["Library/Caches/pnpm/dlx", "Library/pnpm/global"] {
        let path = env.paths.home.join(rel);
        if path.exists() {
            claims.push(pnpm_baseline_claim(path, rel));
        }
    }
    // `Library/Caches/pnpm/metadata*` and `Library/Caches/pnpm/v*` — pnpm's
    // per-registry metadata caches, not globbable without listing the dir.
    let caches_pnpm = env.paths.home.join("Library/Caches/pnpm");
    if let Ok(read) = std::fs::read_dir(&caches_pnpm) {
        for entry in read.filter_map(|e| e.ok()) {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if name.starts_with("metadata") || name.starts_with('v') {
                claims.push(pnpm_baseline_claim(entry.path(), &name));
            }
        }
    }

    for (rel, kind, label) in [
        (
            ".npm/_cacache/index-v5",
            EntryKind::PackageCache,
            "npm cache index",
        ),
        (".npm/_logs", EntryKind::Logs, "npm logs"),
        (".bun/install/cache", EntryKind::PackageCache, "bun cache"),
    ] {
        let path = env.paths.home.join(rel);
        if path.exists() {
            claims.push(
                Claim::new(
                    path,
                    BASELINE_OWNER,
                    kind,
                    EvidenceTier::EcosystemDefault,
                    "node ecosystem resource",
                )
                .label(label)
                .baseline("node"),
            );
        }
    }

    if let Some(cellar) = homebrew_node_cellar(env) {
        claims.push(
            Claim::new(
                cellar,
                BASELINE_OWNER,
                EntryKind::Toolchain,
                EvidenceTier::EcosystemDefault,
                "Homebrew default node",
            )
            .label("node (Homebrew default)")
            .baseline("node"),
        );
    }

    claims
}

fn pnpm_baseline_claim(path: PathBuf, label: &str) -> Claim {
    Claim::new(
        path,
        BASELINE_OWNER,
        EntryKind::PackageCache,
        EvidenceTier::EcosystemDefault,
        "pnpm ecosystem resource",
    )
    .label(label.to_string())
    .baseline("node")
}

fn homebrew_node_cellar(env: &ResolveEnv<'_>) -> Option<PathBuf> {
    env.findings(ScannerId::Brew)
        .iter()
        .find(|f| f.title == "node" || f.meta.get("name").and_then(Value::as_str) == Some("node"))
        .and_then(|f| f.path.clone())
}

// ---------------------------------------------------------------------
// pnpm
// ---------------------------------------------------------------------

/// pnpm store membership (via the nested `store/<v>/<v>/projects/*` symlink
/// layout) plus the `node_modules/.pnpm` reflink clone.
fn pnpm_claims(project: &Project, env: &ResolveEnv<'_>, owner: &str) -> Vec<Claim> {
    let mut claims = Vec::new();
    let mut store_roots: Vec<PathBuf> = vec![
        env.paths.home.join("Library/pnpm/store"),
        env.paths.home.join(".local/share/pnpm/store"),
        env.paths.home.join(".pnpm-store"),
    ];
    if let Some(text) = env.read_head(&project.root.join("node_modules/.modules.yaml"), 65536) {
        if let Some(store_dir) = parse_store_dir(&text) {
            let path = PathBuf::from(store_dir);
            if !store_roots.contains(&path) {
                store_roots.push(path);
            }
        }
    }

    let canon_root = attribution_paths::tree_path(&project.root);
    for store_root in &store_roots {
        for version_dir in find_projects_dirs(store_root) {
            let projects_dir = version_dir.join("projects");
            let Ok(read) = std::fs::read_dir(&projects_dir) else {
                continue;
            };
            let mut links_this_project = false;
            for entry in read.filter_map(|e| e.ok()) {
                let link_path = entry.path();
                let Ok(target) = std::fs::read_link(&link_path) else {
                    continue;
                };
                let resolved = if target.is_absolute() {
                    target
                } else {
                    link_path
                        .parent()
                        .map(|p| p.join(&target))
                        .unwrap_or(target)
                };
                let canon_target = attribution_paths::tree_path(&normalize_path(&resolved));
                if canon_target == canon_root || canon_target.starts_with(&canon_root) {
                    links_this_project = true;
                    break;
                }
            }
            if links_this_project {
                let label = version_dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("pnpm store")
                    .to_string();
                claims.push(
                    Claim::new(
                        version_dir,
                        owner,
                        EntryKind::PackageCache,
                        EvidenceTier::Exact,
                        "pnpm store links this project",
                    )
                    .label(format!("pnpm store {label}")),
                );
            }
        }
    }

    let dot_pnpm = project.root.join("node_modules/.pnpm");
    if dot_pnpm.exists() {
        claims.push(
            Claim::new(
                dot_pnpm,
                owner,
                EntryKind::Artifacts,
                EvidenceTier::Exact,
                "node_modules/.pnpm is a reflink clone of the pnpm store",
            )
            .label("node_modules/.pnpm (clone of store)")
            .clone_of_store(),
        );
    }

    claims
}

/// `.modules.yaml`'s `storeDir:` value. No YAML dependency in this crate —
/// same narrow line-parser shape as `names.rs`'s `pnpm-workspace.yaml`
/// reader.
fn parse_store_dir(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("storeDir:") {
            let value = rest.trim().trim_matches('\'').trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Every store-version directory (e.g. `store/v10/v11`) that has a
/// `projects/` child — the layout is nested one level deeper than the
/// version dir itself.
fn find_projects_dirs(store_root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(depth1) = std::fs::read_dir(store_root) else {
        return out;
    };
    for e1 in depth1.filter_map(|e| e.ok()) {
        let p1 = e1.path();
        if !p1.is_dir() {
            continue;
        }
        if p1.join("projects").is_dir() {
            out.push(p1.clone());
        }
        let Ok(depth2) = std::fs::read_dir(&p1) else {
            continue;
        };
        for e2 in depth2.filter_map(|e| e.ok()) {
            let p2 = e2.path();
            if p2.is_dir() && p2.join("projects").is_dir() {
                out.push(p2);
            }
        }
    }
    out
}

/// Resolve `..`/`.` components without touching the filesystem — a
/// relative symlink target may point at a checkout that no longer exists.
fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

// ---------------------------------------------------------------------
// npm
// ---------------------------------------------------------------------

struct PackageRef {
    name: String,
    version: String,
}

/// `package-lock.json`'s `"node_modules/<name>": { "version": "x" }`
/// entries (lockfile v2/v3 shape). Pure so it gets a direct test instead of
/// a tempdir fixture.
fn parse_package_lock(text: &str) -> Vec<PackageRef> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let Some(packages) = json.get("packages").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, val) in packages {
        let Some(after_prefix) = key.strip_prefix("node_modules/") else {
            continue;
        };
        // A nested dependency's key looks like
        // `node_modules/foo/node_modules/bar` — the package's own name is
        // whatever follows the *last* `node_modules/` segment.
        let name = after_prefix
            .rsplit("node_modules/")
            .next()
            .unwrap_or(after_prefix);
        let Some(version) = val.get("version").and_then(Value::as_str) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        out.push(PackageRef {
            name: name.to_string(),
            version: version.to_string(),
        });
    }
    out
}

/// Scan `~/.npm/_cacache/index-v5` for entries matching any `(name,
/// version)` in `wanted`, resolving each match's `integrity` to its
/// `content-v2` blob.
fn npm_cache_claims(
    env: &ResolveEnv<'_>,
    owner: &str,
    wanted: &HashSet<(String, String)>,
) -> Vec<Claim> {
    if wanted.is_empty() {
        return Vec::new();
    }
    let index_dir = env.paths.home.join(".npm/_cacache/index-v5");
    let mut claims = Vec::new();
    let mut scanned = 0usize;
    let mut stack = vec![index_dir];
    'outer: while let Some(dir) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.filter_map(|e| e.ok()) {
            if scanned >= MAX_INDEX_FILES {
                break 'outer;
            }
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            scanned += 1;
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            for line in content.lines() {
                // Each line is `<hex digest>\t{...json...}`.
                let Some(brace) = line.find('{') else {
                    continue;
                };
                let Ok(value) = serde_json::from_str::<Value>(&line[brace..]) else {
                    continue;
                };
                let Some(key) = value.get("key").and_then(Value::as_str) else {
                    continue;
                };
                for (name, version) in wanted {
                    let marker = format!("/{name}/-/{name}-{version}.tgz");
                    if !key.contains(&marker) {
                        continue;
                    }
                    let Some(integrity) = value.get("integrity").and_then(Value::as_str) else {
                        continue;
                    };
                    if let Some(claim) = content_v2_claim(env, owner, name, version, integrity) {
                        claims.push(claim);
                    }
                }
            }
        }
    }
    claims
}

fn content_v2_claim(
    env: &ResolveEnv<'_>,
    owner: &str,
    name: &str,
    version: &str,
    integrity: &str,
) -> Option<Claim> {
    let b64 = integrity.strip_prefix("sha512-")?;
    let bytes = decode_base64(b64)?;
    let hex = hex_encode(&bytes);
    if hex.len() < 4 {
        return None;
    }
    let path = env
        .paths
        .home
        .join(".npm/_cacache/content-v2/sha512")
        .join(&hex[0..2])
        .join(&hex[2..4])
        .join(&hex[4..]);
    Some(
        Claim::new(
            path,
            owner,
            EntryKind::PackageCache,
            EvidenceTier::Exact,
            "package-lock.json",
        )
        .label(format!("{name} {version}")),
    )
}

/// Standard-alphabet base64 decode — no `base64` dependency in this crate.
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lut = [255u8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        lut[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for b in s.bytes().filter(|&b| b != b'=' && !b.is_ascii_whitespace()) {
        let v = lut[b as usize];
        if v == 255 {
            return None;
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------
// yarn berry
// ---------------------------------------------------------------------

fn yarn_berry_claims(project: &Project, env: &ResolveEnv<'_>, owner: &str) -> Vec<Claim> {
    let Some(text) = env.read_head(&project.root.join("yarn.lock"), MAX_LOCKFILE_BYTES) else {
        return Vec::new();
    };
    let entries = parse_yarn_berry_resolutions(&text);
    if entries.is_empty() {
        return Vec::new();
    }
    let cache_dir = env.paths.home.join("Library/Caches/Yarn/berry/cache");
    let Ok(read) = std::fs::read_dir(&cache_dir) else {
        return Vec::new();
    };
    let files: Vec<String> = read
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    let mut claims = Vec::new();
    for (name, version) in &entries {
        let prefix = format!("{}-npm-{}-", name.replace('/', "-"), version);
        for file in &files {
            if file.starts_with(&prefix) {
                claims.push(
                    Claim::new(
                        cache_dir.join(file),
                        owner,
                        EntryKind::PackageCache,
                        EvidenceTier::Exact,
                        "yarn.lock",
                    )
                    .label(format!("{name} {version}")),
                );
            }
        }
    }
    claims
}

/// `yarn.lock`'s `resolution: "<name>@npm:<version>"` lines — the most
/// reliable single line per entry (the header key line can list several
/// version ranges for one resolved package). Pure so it gets a direct test.
fn parse_yarn_berry_resolutions(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("resolution:") else {
            continue;
        };
        let spec = rest.trim().trim_matches('"');
        if let Some(parsed) = parse_npm_spec(spec) {
            out.push(parsed);
        }
    }
    out
}

/// `<name>@npm:<version>` → `(name, version)` — `None` for anything that
/// isn't a plain npm-registry resolution (patches, workspaces, git deps).
fn parse_npm_spec(spec: &str) -> Option<(String, String)> {
    let (name, version) = spec.split_once("@npm:")?;
    if name.is_empty() || version.is_empty() || version.contains('#') {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

// ---------------------------------------------------------------------
// bun
// ---------------------------------------------------------------------

fn bun_claims(project: &Project, env: &ResolveEnv<'_>, owner: &str) -> Vec<Claim> {
    if let Some(text) = env.read_head(&project.root.join("bun.lock"), MAX_LOCKFILE_BYTES) {
        let entries = parse_bun_lock(&text);
        if !entries.is_empty() {
            let cache_dir = env.paths.home.join(".bun/install/cache");
            if let Ok(read) = std::fs::read_dir(&cache_dir) {
                let files: Vec<String> = read
                    .filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect();
                let mut claims = Vec::new();
                for (name, version) in &entries {
                    let prefix = format!("{name}@{version}");
                    for file in &files {
                        if file.starts_with(&prefix) {
                            claims.push(
                                Claim::new(
                                    cache_dir.join(file),
                                    owner,
                                    EntryKind::PackageCache,
                                    EvidenceTier::Exact,
                                    "bun.lock",
                                )
                                .label(format!("{name} {version}")),
                            );
                        }
                    }
                }
                return claims;
            }
        }
        return Vec::new();
    }

    if project.root.join("bun.lockb").exists() {
        let cache_dir = env.paths.home.join(".bun/install/cache");
        if cache_dir.exists() {
            return vec![Claim::new(
                cache_dir,
                owner,
                EntryKind::PackageCache,
                EvidenceTier::EcosystemDefault,
                "bun.lockb present",
            )
            .label("bun cache")];
        }
    }
    Vec::new()
}

/// `bun.lock`'s `"packages"` object: `{ "<name>": ["<name>@<version>", ...]
/// }`. `bun.lock` is JSONC (comments, trailing commas allowed) — a strict
/// parse is tried first since most files have neither, falling back to a
/// best-effort comment strip.
fn parse_bun_lock(text: &str) -> Vec<(String, String)> {
    let json = serde_json::from_str::<Value>(text)
        .or_else(|_| serde_json::from_str::<Value>(&strip_line_comments(text)));
    let Ok(json) = json else {
        return Vec::new();
    };
    let Some(packages) = json.get("packages").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for val in packages.values() {
        let Some(spec) = val
            .as_array()
            .and_then(|a| a.first())
            .and_then(Value::as_str)
        else {
            continue;
        };
        // The scoped-name case (`@scope/name@1.2.3`) needs the *last* `@`,
        // unlike npm's `@npm:` marker.
        if let Some((name, version)) = spec.rsplit_once('@') {
            if !name.is_empty() && !version.is_empty() {
                out.push((name.to_string(), version.to_string()));
            }
        }
    }
    out
}

/// Drop whole-line `//` comments (JSONC's other allowances — trailing
/// commas, block comments — aren't attempted; a file that needs them just
/// yields no claims, which is safe).
fn strip_line_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------
// Node version pin
// ---------------------------------------------------------------------

fn node_version_pin(project: &Project, env: &ResolveEnv<'_>) -> Option<String> {
    if let Some(text) = env.read_head(&project.root.join(".nvmrc"), 256) {
        if let Some(v) = text.lines().next().and_then(normalise_node_pin) {
            return Some(v);
        }
    }
    if let Some(text) = env.read_head(&project.root.join(".node-version"), 256) {
        if let Some(v) = text.lines().next().and_then(normalise_node_pin) {
            return Some(v);
        }
    }
    if let Some(text) = env.read_head(&project.root.join(".tool-versions"), 4096) {
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            if parts.next() == Some("nodejs") {
                if let Some(v) = parts.next().and_then(normalise_node_pin) {
                    return Some(v);
                }
            }
        }
    }
    for name in [".mise.toml", "mise.toml"] {
        if let Some(text) = env.read_head(&project.root.join(name), 4096) {
            if let Some(v) = parse_mise_node_version(&text)
                .as_deref()
                .and_then(normalise_node_pin)
            {
                return Some(v);
            }
        }
    }
    if let Some(text) = env.read_head(&project.root.join("package.json"), 262_144) {
        if let Ok(json) = serde_json::from_str::<Value>(&text) {
            if let Some(v) = json
                .get("volta")
                .and_then(|v| v.get("node"))
                .and_then(Value::as_str)
                .and_then(normalise_node_pin)
            {
                return Some(v);
            }
        }
    }
    None
}

fn parse_mise_node_version(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("node") else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let value = rest.trim().trim_matches('"').trim_matches('\'');
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// Normalise a version pin (`v24`, `24.1`, `20.11.1`) to `vMAJOR[.MINOR[.PATCH]]`.
/// `None` for anything that isn't a numeric version at all (`lts/*`,
/// `lts/iron`, `system`, `*`). Pure so it gets a direct test.
fn normalise_node_pin(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_prefix('v').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split('.');
    let major = parts.next()?;
    if major.is_empty() || !major.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut out = format!("v{major}");
    for part in parts {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            break;
        }
        out.push('.');
        out.push_str(part);
    }
    Some(out)
}

fn node_toolchain_claim(env: &ResolveEnv<'_>, owner: &str, pin: &str) -> Option<Claim> {
    let roots = [
        env.paths.home.join(".nvm/versions/node"),
        env.paths.home.join(".fnm/node-versions"),
        env.paths.home.join(".volta/tools/image/node"),
        env.paths.home.join(".local/share/mise/installs/node"),
        env.paths.home.join("Library/pnpm/nodejs"),
    ];
    let mut by_name: HashMap<String, PathBuf> = HashMap::new();
    for root in &roots {
        for (name, path) in list_version_dirs(root) {
            by_name.entry(name).or_insert(path);
        }
    }
    let names: Vec<String> = by_name.keys().cloned().collect();
    let best = newest_matching_version_dir(pin, &names)?;
    let path = by_name.get(&best)?.clone();
    Some(
        Claim::new(
            path,
            owner,
            EntryKind::Toolchain,
            EvidenceTier::Exact,
            "node version pin",
        )
        .label(format!("node {best}")),
    )
}

/// `(vX.Y.Z name, path)` for every child directory of `root`, normalising
/// names that don't already carry a `v` prefix (volta/mise/pnpm install
/// dirs are bare `20.11.0`; nvm/fnm are `v20.11.0`).
fn list_version_dirs(root: &Path) -> Vec<(String, PathBuf)> {
    let Ok(read) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    read.filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let normalised = if name.starts_with('v') {
                name
            } else {
                format!("v{name}")
            };
            Some((normalised, e.path()))
        })
        .collect()
}

/// The newest `vX.Y.Z`-shaped name in `candidates` whose version starts
/// with `pin`'s digits at a component boundary (so pin `v24` matches
/// `v24.15.0` but not `v240.1.0`). Pure so it gets a direct test.
fn newest_matching_version_dir(pin: &str, candidates: &[String]) -> Option<String> {
    let pin_digits = pin.trim_start_matches('v');
    let mut best: Option<(semver::Version, String)> = None;
    for candidate in candidates {
        let cand_digits = candidate.trim_start_matches('v');
        if !cand_digits.starts_with(pin_digits) {
            continue;
        }
        let rest = &cand_digits[pin_digits.len()..];
        if !(rest.is_empty() || rest.starts_with('.')) {
            continue;
        }
        let Ok(version) = semver::Version::parse(cand_digits) else {
            continue;
        };
        if best.as_ref().is_none_or(|(v, _)| version > *v) {
            best = Some((version, candidate.clone()));
        }
    }
    best.map(|(_, name)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_lock_v3_packages_entries() {
        let text = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.21" },
                "node_modules/@scope/thing": { "version": "2.0.0" },
                "node_modules/foo/node_modules/lodash": { "version": "4.17.20" }
            }
        }"#;
        let mut got: Vec<(String, String)> = parse_package_lock(text)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("@scope/thing".to_string(), "2.0.0".to_string()),
                ("lodash".to_string(), "4.17.20".to_string()),
                ("lodash".to_string(), "4.17.21".to_string()),
            ]
        );
    }

    #[test]
    fn parses_yarn_berry_resolution_lines() {
        let text = r#"
"lodash@npm:^4.17.21, lodash@npm:^4.17.4":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10c0/abcd
  languageName: node
  linkType: hard

"@babel/core@npm:^7.20.0":
  version: 7.20.0
  resolution: "@babel/core@npm:7.20.0"
  languageName: node
  linkType: hard

"local-pkg@workspace:packages/local-pkg":
  version: 0.0.0-use.local
  resolution: "local-pkg@workspace:packages/local-pkg"
  languageName: unknown
  linkType: soft
"#;
        let mut got = parse_yarn_berry_resolutions(text);
        got.sort();
        assert_eq!(
            got,
            vec![
                ("@babel/core".to_string(), "7.20.0".to_string()),
                ("lodash".to_string(), "4.17.21".to_string()),
            ]
        );
    }

    #[test]
    fn normalise_node_pin_handles_major_only_and_dotted_forms() {
        assert_eq!(normalise_node_pin("v24"), Some("v24".to_string()));
        assert_eq!(normalise_node_pin("24.1"), Some("v24.1".to_string()));
        assert_eq!(normalise_node_pin("20.11.1"), Some("v20.11.1".to_string()));
    }

    #[test]
    fn normalise_node_pin_rejects_non_numeric_refs() {
        assert_eq!(normalise_node_pin("lts/*"), None);
        assert_eq!(normalise_node_pin("lts/iron"), None);
        assert_eq!(normalise_node_pin("system"), None);
        assert_eq!(normalise_node_pin(""), None);
    }

    #[test]
    fn newest_matching_version_dir_picks_the_newest_within_the_pin() {
        let candidates = vec![
            "v24.2.0".to_string(),
            "v24.15.0".to_string(),
            "v20.1.0".to_string(),
            "v240.1.0".to_string(),
        ];
        assert_eq!(
            newest_matching_version_dir("v24", &candidates),
            Some("v24.15.0".to_string())
        );
    }

    #[test]
    fn newest_matching_version_dir_respects_a_minor_pin() {
        let candidates = vec![
            "v24.1.5".to_string(),
            "v24.1.9".to_string(),
            "v24.10.0".to_string(),
        ];
        assert_eq!(
            newest_matching_version_dir("v24.1", &candidates),
            Some("v24.1.9".to_string())
        );
    }

    #[test]
    fn base64_round_trips_a_known_npm_integrity_value() {
        // "hi" -> base64 "aGk=" -> bytes [0x68, 0x69].
        assert_eq!(decode_base64("aGk="), Some(vec![0x68, 0x69]));
        assert_eq!(hex_encode(&[0x68, 0x69]), "6869");
    }
}
