//! Cargo registry (crate files + extracted sources + git checkouts) from every non-artifact `Cargo.lock`, and the pinned rustup toolchain from `rust-toolchain(.toml)`.

use std::path::{Path, PathBuf};

use super::super::{find_node, Project};
use crate::attribution::model::{Claim, EntryKind, EvidenceTier, ResolveEnv, BASELINE_OWNER};
use crate::scan::walk::listing::{self, Kind};
use crate::scan::walk::DirNode;

/// `env.read_head`'s cap for a `Cargo.lock` — generous, since a workspace
/// lockfile with hundreds of crates can run into the hundreds of KiB.
const MAX_LOCKFILE_BYTES: usize = 4 * 1024 * 1024;
/// How deep below a project's root the `Cargo.lock` sweep goes.
const MAX_LOCKFILE_DEPTH: usize = 5;
/// Directories that hold build output or vendored checkouts, never a
/// `Cargo.lock` of the project's own — pruned from the sweep (hidden
/// directories are pruned unconditionally alongside these).
const RUST_ARTIFACT_DIR_NAMES: &[&str] = &["target", "node_modules", ".build", "Pods"];

/// One `[[package]]` entry from a `Cargo.lock`.
#[derive(Debug, Clone, PartialEq)]
struct LockPackage {
    name: String,
    version: String,
    source: Option<String>,
}

/// Resolve this resource kind's claims for `project`. Stub until its lane
/// lands (see the module doc for which chunk).
pub fn resolve(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let owner = project.root.to_string_lossy().into_owned();
    let mut claims = Vec::new();
    let mut index_dirs: Option<Vec<String>> = None;

    for lockfile in find_cargo_locks(project, env) {
        let Some(text) = env.read_head(&lockfile, MAX_LOCKFILE_BYTES) else {
            continue;
        };
        let packages = parse_cargo_lock(&text);
        if packages.is_empty() {
            continue;
        }
        let rel = relative_dir_label(&project.root, &lockfile);
        let evidence = if rel.is_empty() {
            "Cargo.lock".to_string()
        } else {
            format!("Cargo.lock in {rel}/")
        };
        for pkg in &packages {
            match pkg.source.as_deref() {
                Some(src) if src.starts_with("git+") => {
                    if let Some(basename) = git_repo_basename(src) {
                        claims.extend(claim_git_source(
                            env,
                            &owner,
                            &basename,
                            &pkg.name,
                            &pkg.version,
                            &evidence,
                        ));
                    }
                }
                Some(src) if !src.is_empty() => {
                    let dirs = index_dirs.get_or_insert_with(|| registry_index_dirs(env));
                    claims.extend(claim_registry_source(
                        env,
                        dirs,
                        &owner,
                        &pkg.name,
                        &pkg.version,
                        &evidence,
                    ));
                }
                _ => {}
            }
        }
    }

    if let Some(claim) = toolchain_claim(project, env, &owner) {
        claims.push(claim);
    }

    claims.into_iter().map(|c| c.ecosystem("rust")).collect()
}

/// Ecosystem-wide rustup/cargo resources: the default toolchain
/// (`~/.rustup/settings.toml default_toolchain`), plus rustup/cargo dirs
/// that aren't tied to any one project's `Cargo.lock`.
pub fn baseline(env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut claims = Vec::new();

    if let Some(default_toolchain) = default_toolchain_name(env) {
        let path = env
            .paths
            .home
            .join(".rustup/toolchains")
            .join(&default_toolchain);
        if path.exists() {
            claims.push(
                Claim::new(
                    path,
                    BASELINE_OWNER,
                    EntryKind::Toolchain,
                    EvidenceTier::EcosystemDefault,
                    "default rustup toolchain",
                )
                .label(default_toolchain)
                .baseline("rust"),
            );
        }
    }

    for (rel, kind, label) in [
        (
            ".rustup/downloads",
            EntryKind::Toolchain,
            "rustup downloads",
        ),
        (".rustup/tmp", EntryKind::Toolchain, "rustup tmp"),
        (
            ".cargo/registry/index",
            EntryKind::PackageCache,
            "cargo registry index",
        ),
        (".cargo/bin", EntryKind::PackageCache, "cargo bin"),
        (".cargo/git/db", EntryKind::PackageCache, "cargo git db"),
    ] {
        let path = env.paths.home.join(rel);
        if path.exists() {
            claims.push(
                Claim::new(
                    path,
                    BASELINE_OWNER,
                    kind,
                    EvidenceTier::EcosystemDefault,
                    "rust ecosystem resource",
                )
                .label(label)
                .baseline("rust"),
            );
        }
    }

    claims
}

/// `~/.rustup/settings.toml`'s `default_toolchain` value.
fn default_toolchain_name(env: &ResolveEnv<'_>) -> Option<String> {
    let text = env.read_head(&env.paths.home.join(".rustup/settings.toml"), 8192)?;
    parse_default_toolchain(&text)
}

fn parse_default_toolchain(text: &str) -> Option<String> {
    text.lines()
        .find_map(|line| parse_toml_string_field(line.trim(), "default_toolchain"))
}

/// Walk `project`'s subtree (tree-only, one `listing::list` per candidate
/// directory to check for a `Cargo.lock` file, since `DirNode` carries no
/// file entries) collecting every non-artifact `Cargo.lock` — cubby has
/// theirs at `recipebridge/Cargo.lock` and `cubby-ffi/Cargo.lock`, not the
/// root.
fn find_cargo_locks(project: &Project, env: &ResolveEnv<'_>) -> Vec<PathBuf> {
    let Some((_, root_node)) = find_node(env.trees, &project.root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, &DirNode, usize)> = vec![(project.root.clone(), root_node, 0)];
    while let Some((path, node, depth)) = stack.pop() {
        if let Ok(dir_listing) = listing::list(&path) {
            let has_lock = dir_listing
                .entries
                .iter()
                .any(|e| e.kind != Kind::Dir && e.name.to_str() == Some("Cargo.lock"));
            if has_lock {
                out.push(path.join("Cargo.lock"));
            }
        }
        if depth >= MAX_LOCKFILE_DEPTH {
            continue;
        }
        for child in node.children.iter() {
            let name = &*child.name;
            if name.starts_with('.') || RUST_ARTIFACT_DIR_NAMES.contains(&name) {
                continue;
            }
            stack.push((path.join(name), child, depth + 1));
        }
    }
    out
}

/// `Cargo.lock`'s directory relative to the project root, e.g.
/// `"recipebridge"` — empty for a root-level lockfile.
fn relative_dir_label(root: &Path, lockfile: &Path) -> String {
    let dir = lockfile.parent().unwrap_or(root);
    if dir == root {
        String::new()
    } else {
        dir.strip_prefix(root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

/// Parse every `[[package]]` block's `name`/`version`/`source` out of a
/// `Cargo.lock`. Pure so a realistic 3-package snippet (incl. a git source)
/// gets a direct test instead of a tempdir fixture.
fn parse_cargo_lock(text: &str) -> Vec<LockPackage> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut source: Option<String> = None;
    let mut in_block = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                out.push(LockPackage {
                    name: n,
                    version: v,
                    source: source.take(),
                });
            }
            source = None;
            in_block = true;
            continue;
        }
        if !in_block {
            continue;
        }
        if let Some(v) = parse_toml_string_field(trimmed, "name") {
            name = Some(v);
        } else if let Some(v) = parse_toml_string_field(trimmed, "version") {
            version = Some(v);
        } else if let Some(v) = parse_toml_string_field(trimmed, "source") {
            source = Some(v);
        }
    }
    if let (Some(n), Some(v)) = (name, version) {
        out.push(LockPackage {
            name: n,
            version: v,
            source,
        });
    }
    out
}

/// A `key = "value"` line's string value, if `line` starts with `key`.
/// Shared by the lockfile parser, the toolchain-channel parser and the
/// rustup `settings.toml` reader — all the same narrow TOML shape.
fn parse_toml_string_field(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.trim_start().strip_prefix('=')?;
    let rest = rest.trim();
    let rest = rest.strip_prefix('"')?;
    let (value, _) = rest.split_once('"')?;
    Some(value.to_string())
}

/// `git+<url>[?query]#<rev>` → the repository's basename (`.git` suffix
/// stripped), the prefix `~/.cargo/git/{checkouts,db}/<basename>-*` are
/// keyed on.
fn git_repo_basename(source: &str) -> Option<String> {
    let rest = source.strip_prefix("git+")?;
    let rest = rest.split('#').next()?;
    let rest = rest.split('?').next()?;
    let name = rest.rsplit('/').next()?;
    let name = name.strip_suffix(".git").unwrap_or(name);
    (!name.is_empty()).then(|| name.to_string())
}

/// Every index directory under `~/.cargo/registry/cache` (typically a
/// single `index.crates.io-<hash>`, but a project may have used an
/// alternate/mirrored registry too).
fn registry_index_dirs(env: &ResolveEnv<'_>) -> Vec<String> {
    let cache_dir = env.paths.home.join(".cargo/registry/cache");
    let Ok(read) = std::fs::read_dir(&cache_dir) else {
        return Vec::new();
    };
    read.filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

fn claim_registry_source(
    env: &ResolveEnv<'_>,
    index_dirs: &[String],
    owner: &str,
    name: &str,
    version: &str,
    evidence: &str,
) -> Vec<Claim> {
    let mut claims = Vec::new();
    for idx in index_dirs {
        let crate_path = env
            .paths
            .home
            .join(".cargo/registry/cache")
            .join(idx)
            .join(format!("{name}-{version}.crate"));
        if crate_path.exists() {
            claims.push(
                Claim::new(
                    crate_path,
                    owner,
                    EntryKind::PackageCache,
                    EvidenceTier::Exact,
                    evidence.to_string(),
                )
                .label(format!("{name} {version}")),
            );
        }
        let src_path = env
            .paths
            .home
            .join(".cargo/registry/src")
            .join(idx)
            .join(format!("{name}-{version}"));
        if src_path.exists() {
            claims.push(
                Claim::new(
                    src_path,
                    owner,
                    EntryKind::PackageCache,
                    EvidenceTier::Exact,
                    evidence.to_string(),
                )
                .label(format!("{name} {version}")),
            );
        }
    }
    claims
}

fn claim_git_source(
    env: &ResolveEnv<'_>,
    owner: &str,
    basename: &str,
    name: &str,
    version: &str,
    evidence: &str,
) -> Vec<Claim> {
    let mut claims = Vec::new();
    let prefix = format!("{basename}-");
    for sub in ["git/checkouts", "git/db"] {
        let dir = env.paths.home.join(".cargo").join(sub);
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.filter_map(|e| e.ok()) {
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            if file_name.starts_with(&prefix) {
                claims.push(
                    Claim::new(
                        entry.path(),
                        owner,
                        EntryKind::PackageCache,
                        EvidenceTier::NameMatch,
                        evidence.to_string(),
                    )
                    .label(format!("{name} {version}")),
                );
            }
        }
    }
    claims
}

/// `rust-toolchain(.toml)`'s pinned channel → the matching installed
/// toolchain directory under `~/.rustup/toolchains`.
fn toolchain_claim(project: &Project, env: &ResolveEnv<'_>, owner: &str) -> Option<Claim> {
    let channel = read_toolchain_channel(project, env)?;
    let dir_name = resolve_toolchain_dir(env, &channel)?;
    let path = env.paths.home.join(".rustup/toolchains").join(&dir_name);
    Some(
        Claim::new(
            path,
            owner,
            EntryKind::Toolchain,
            EvidenceTier::Exact,
            format!("rust-toolchain pins {channel}"),
        )
        .label(dir_name),
    )
}

fn read_toolchain_channel(project: &Project, env: &ResolveEnv<'_>) -> Option<String> {
    for name in ["rust-toolchain.toml", "rust-toolchain"] {
        let path = project.root.join(name);
        if let Some(text) = env.read_head(&path, 4096) {
            if let Some(channel) = parse_toolchain_channel(&text) {
                return Some(channel);
            }
        }
    }
    None
}

/// `channel = "..."` (the `.toml` form) or a bare channel name on its own
/// line (the legacy plain-text form) — both forms are just "the first
/// usable line", so one parser covers both.
fn parse_toolchain_channel(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(channel) = parse_toml_string_field(line.trim(), "channel") {
            return Some(channel);
        }
    }
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('['))
        .map(str::to_string)
}

/// The installed toolchain directory matching `channel`: an exact name
/// match (a full `<channel>-<host>` string given directly), else the
/// (alphabetically last, which for `X-Y-Z` triples is also the newest)
/// installed `<channel>-<host>` directory.
fn resolve_toolchain_dir(env: &ResolveEnv<'_>, channel: &str) -> Option<String> {
    let toolchains_dir = env.paths.home.join(".rustup/toolchains");
    let read = std::fs::read_dir(&toolchains_dir).ok()?;
    let mut names: Vec<String> = read
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    if names.iter().any(|n| n == channel) {
        return Some(channel.to_string());
    }
    let prefix = format!("{channel}-");
    names.retain(|n| n.starts_with(&prefix));
    names.sort();
    names.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_lockfile_with_a_registry_and_a_git_source() {
        let text = r#"
# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "cubby-core"
version = "0.1.0"
source = "git+https://github.com/nickysemenza/cubby-core.git?branch=main#deadbeef"

[[package]]
name = "cubby-ffi"
version = "0.1.0"
"#;
        let packages = parse_cargo_lock(text);
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].name, "serde");
        assert_eq!(packages[0].version, "1.0.210");
        assert_eq!(
            packages[0].source.as_deref(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        assert_eq!(packages[1].name, "cubby-core");
        assert_eq!(
            packages[1].source.as_deref(),
            Some("git+https://github.com/nickysemenza/cubby-core.git?branch=main#deadbeef")
        );
        // A local/workspace member has no `source` line at all.
        assert_eq!(packages[2].name, "cubby-ffi");
        assert_eq!(packages[2].source, None);
    }

    #[test]
    fn git_repo_basename_strips_the_dot_git_suffix_and_query() {
        assert_eq!(
            git_repo_basename(
                "git+https://github.com/nickysemenza/cubby-core.git?branch=main#deadbeef"
            ),
            Some("cubby-core".to_string())
        );
        assert_eq!(
            git_repo_basename("git+https://github.com/org/repo#deadbeef"),
            Some("repo".to_string())
        );
    }

    #[test]
    fn toolchain_channel_parses_the_toml_form() {
        let text = "[toolchain]\nchannel = \"1.75.0\"\ncomponents = [\"rustfmt\"]\n";
        assert_eq!(parse_toolchain_channel(text), Some("1.75.0".to_string()));
    }

    #[test]
    fn toolchain_channel_parses_the_legacy_bare_form() {
        let text = "stable-x86_64-apple-darwin\n";
        assert_eq!(
            parse_toolchain_channel(text),
            Some("stable-x86_64-apple-darwin".to_string())
        );
    }

    #[test]
    fn default_toolchain_parses_from_settings_toml() {
        let text = "default_host_triple = \"aarch64-apple-darwin\"\ndefault_toolchain = \"stable-aarch64-apple-darwin\"\nversion = \"12\"\n";
        assert_eq!(
            parse_default_toolchain(text),
            Some("stable-aarch64-apple-darwin".to_string())
        );
    }
}
