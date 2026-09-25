// Named `Target::Derive`/`Extract::Fn`/`Label::Fn` functions for rows in
// `rules.rs` that need real code rather than a template. Spliced into
// `rules::derive` via `include!` (see the bottom of `rules.rs`), so `self`/
// `super` here mean the same as if this were written inline there.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::Key;
use super::super::parsers;
use crate::attribution::model::ResolveEnv;
use crate::attribution::projects::Project;

/// `~/.npm/_cacache/index-v5` entries before giving up — that directory can
/// hold entries for every package ever installed anywhere.
const MAX_NPM_INDEX_FILES: usize = 50_000;

/// `(name, version) -> integrity` built once per process from the whole
/// cacache index (a full scan can touch tens of thousands of small files),
/// then reused for every package `npm-cacache` rows look up — the
/// per-`Key` signature `Target::Derive` calls with would otherwise re-walk
/// the index once per locked package.
static NPM_INDEX: Mutex<Option<HashMap<(String, String), String>>> = Mutex::new(None);

pub fn npm_cacache(key: &Key, _project: &Project, env: &ResolveEnv<'_>) -> Vec<PathBuf> {
    let index_dir = env.paths.home.join(".npm/_cacache/index-v5");
    let mut guard = NPM_INDEX.lock().unwrap();
    if guard.is_none() {
        *guard = Some(scan_npm_index(&index_dir));
    }
    let index = guard.as_ref().unwrap();
    let Some(integrity) = index.get(&(key.name.clone(), key.version.clone())) else {
        return Vec::new();
    };
    let Some((a, b, rest)) = parsers::npm_integrity_to_shard(integrity) else {
        return Vec::new();
    };
    vec![env
        .paths
        .home
        .join(".npm/_cacache/content-v2/sha512")
        .join(a)
        .join(b)
        .join(rest)]
}

fn scan_npm_index(index_dir: &Path) -> HashMap<(String, String), String> {
    let mut out = HashMap::new();
    let mut scanned = 0usize;
    let mut stack = vec![index_dir.to_path_buf()];
    'outer: while let Some(dir) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.filter_map(|e| e.ok()) {
            if scanned >= MAX_NPM_INDEX_FILES {
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
                let Ok(value) = serde_json::from_str::<serde_json::Value>(&line[brace..]) else {
                    continue;
                };
                let (Some(key_str), Some(integrity)) = (
                    value.get("key").and_then(|v| v.as_str()),
                    value.get("integrity").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                // `key` looks like `make-fetch-happen:request-cache:https://
                // registry.npmjs.org/<name>/-/<name>-<version>.tgz`.
                let Some(tgz) = key_str.rsplit('/').next() else {
                    continue;
                };
                let Some(name_version) = tgz.strip_suffix(".tgz") else {
                    continue;
                };
                // `<name>-<version>` — split on the last `-` that precedes a
                // digit (the version always starts with one).
                if let Some(idx) = name_version.rfind('-') {
                    let (name, version) = name_version.split_at(idx);
                    let version = &version[1..];
                    if !name.is_empty() && !version.is_empty() {
                        out.insert(
                            (name.to_string(), version.to_string()),
                            integrity.to_string(),
                        );
                    }
                }
            }
        }
    }
    out
}

/// `key.name` is the raw, unexpanded `CARGO_TARGET_DIR`/`target-dir` value —
/// expand `$HOME`/`${HOME}`/`~`, then resolve relative to the project root.
pub fn cargo_target_dir(key: &Key, project: &Project, env: &ResolveEnv<'_>) -> Vec<PathBuf> {
    vec![parsers::expand_target_dir(
        &key.name,
        &env.paths.home,
        &project.root,
    )]
}

/// `key.name`/`key.version` are one `go.sum` module identity — the module's
/// extracted source dir plus its three download-cache files, if present.
pub fn go_module_cache(key: &Key, _project: &Project, env: &ResolveEnv<'_>) -> Vec<PathBuf> {
    let mod_cache = parsers::go_module_cache_dir(&env.paths.home);
    let escaped = parsers::escape_module_path(&key.name);
    let mut out = Vec::new();

    let mod_dir = mod_cache.join(format!("{escaped}@{}", key.version));
    if mod_dir.exists() {
        out.push(mod_dir);
    }
    let download_dir = mod_cache.join("cache/download").join(&escaped).join("@v");
    for ext in ["zip", "mod", "info"] {
        let f = download_dir.join(format!("{}.{ext}", key.version));
        if f.exists() {
            out.push(f);
        }
    }
    out
}

/// The Claude Code CLI's per-project cache dir, keyed by the same encoded
/// path convention as its session directories.
pub fn claude_cli_cache(_key: &Key, project: &Project, env: &ResolveEnv<'_>) -> Vec<PathBuf> {
    let encoded = parsers::encode_claude_project_dir(&project.root);
    let dir = env.paths.home.join("Library/Caches/claude-cli-nodejs").join(encoded);
    if dir.exists() { vec![dir] } else { Vec::new() }
}

/// Parent directories swept once (via the walked tree) for a child matching
/// one of the project's candidate names.
const CACHE_PARENT_DIRS: &[&str] = &[
    "Library/Caches",
    "Library/HTTPStorages",
    "Library/WebKit",
    "Library/Application Support",
    "Library/Logs",
    ".cache",
    ".config",
    ".local/share",
];

/// Names too short or too generic to trust as a name-match signal on their
/// own — `"core"`, `"lib"` etc. show up as real cache-dir names all over a
/// typical `~/Library/Caches`, unrelated to any one project.
const GENERIC_NAMES: &[&str] = &[
    "app", "web", "api", "test", "demo", "src", "ui", "cli", "core", "lib", "main",
];

/// `key.name` is one of the project's known names — every variant worth
/// trying as a cache-dir name (lowercased, with `-`/`_` swapped), filtered
/// of anything too short or generic to be a trustworthy signal, matched
/// against one listing of each hub in `CACHE_PARENT_DIRS`.
pub fn project_name_cache(key: &Key, _project: &Project, env: &ResolveEnv<'_>) -> Vec<PathBuf> {
    let lower = key.name.to_ascii_lowercase();
    if lower.len() < 4 || GENERIC_NAMES.contains(&lower.as_str()) {
        return Vec::new();
    }
    let mut variants = vec![lower.clone()];
    if lower.contains('-') {
        variants.push(lower.replace('-', "_"));
    }
    if lower.contains('_') {
        variants.push(lower.replace('_', "-"));
    }

    let mut out = Vec::new();
    for parent_rel in CACHE_PARENT_DIRS {
        let parent = env.paths.home.join(parent_rel);
        let Some(node) = crate::attribution::paths::node_at(env.trees, &parent) else {
            continue;
        };
        for child in node.children.iter() {
            let child_lower = child.name.to_ascii_lowercase();
            if variants.contains(&child_lower) {
                out.push(parent.join(&*child.name));
            }
        }
    }
    out
}

/// JetBrains keeps two parallel per-IDE roots, each holding
/// `<ide>/<project-name>.<hash>` (or `-<hash>`) directories.
const JETBRAINS_ROOTS: &[&str] = &[
    "Library/Caches/JetBrains",
    "Library/Application Support/JetBrains",
];

/// `key.name` is one of the project's known names — every JetBrains
/// per-project cache directory whose `<name>.<hash>`/`<name>-<hash>` prefix
/// matches it exactly (case-sensitive: JetBrains preserves the project's
/// own casing here).
pub fn jetbrains_dirs(key: &Key, _project: &Project, env: &ResolveEnv<'_>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root_rel in JETBRAINS_ROOTS {
        let root = env.paths.home.join(root_rel);
        let Ok(ide_dirs) = std::fs::read_dir(&root) else {
            continue;
        };
        for ide_entry in ide_dirs.filter_map(|e| e.ok()) {
            let Ok(ide_file_type) = ide_entry.file_type() else {
                continue;
            };
            if !ide_file_type.is_dir() {
                continue;
            }
            let Ok(project_dirs) = std::fs::read_dir(ide_entry.path()) else {
                continue;
            };
            for proj_entry in project_dirs.filter_map(|e| e.ok()) {
                let Ok(proj_file_type) = proj_entry.file_type() else {
                    continue;
                };
                if !proj_file_type.is_dir() {
                    continue;
                }
                let dir_name = proj_entry.file_name().to_string_lossy().into_owned();
                if jetbrains_name_matches(&dir_name, &key.name) {
                    out.push(proj_entry.path());
                }
            }
        }
    }
    out
}

fn jetbrains_name_matches(dir_name: &str, name: &str) -> bool {
    for sep in ['.', '-'] {
        if let Some((prefix, _hash)) = dir_name.rsplit_once(sep) {
            if prefix == name {
                return true;
            }
        }
    }
    false
}

/// The owning bundle id of one simulator app container: `Data` containers
/// carry it directly in their metadata plist; `Bundle` containers only have
/// the `.app` itself, so fall back to its `Info.plist`. The device's
/// display name (for the row's `{device}` label token) comes from walking
/// up to the `Devices/<udid>` ancestor.
pub fn container_bundle_id(container_dir: &Path) -> Option<super::Extracted> {
    let metadata = container_dir.join(".com.apple.mobile_container_manager.metadata.plist");
    let bundle_id = if let Ok(value) = plist::Value::from_file(&metadata) {
        value
            .as_dictionary()
            .and_then(|d| d.get("MCMMetadataIdentifier"))
            .and_then(|v| v.as_string())
            .map(str::to_string)
    } else {
        None
    };
    let bundle_id = bundle_id.or_else(|| {
        let listing = crate::scan::walk::listing::list(container_dir).ok()?;
        for entry in &listing.entries {
            if entry.kind != crate::scan::walk::listing::Kind::Dir {
                continue;
            }
            let Some(name) = entry.name.to_str() else {
                continue;
            };
            if !name.ends_with(".app") {
                continue;
            }
            let info_plist = container_dir.join(name).join("Info.plist");
            if let Ok(value) = plist::Value::from_file(&info_plist) {
                if let Some(id) = value
                    .as_dictionary()
                    .and_then(|d| d.get("CFBundleIdentifier"))
                    .and_then(|v| v.as_string())
                {
                    return Some(id.to_string());
                }
            }
        }
        None
    })?;

    let device_dir = device_dir_ancestor(container_dir)?;
    let device_name = simulator_device_label(&device_dir);
    Some(super::Extracted {
        // A bundle id isn't a filesystem path, but `Matcher::BundleId` reads
        // it back out of this same field rather than resolving it as one.
        path: PathBuf::from(bundle_id),
        label_extra: Some(device_name),
    })
}

/// Walk up from a simulator app-container path to find its
/// `Devices/<udid>` ancestor.
fn device_dir_ancestor(container_dir: &Path) -> Option<PathBuf> {
    let mut components: Vec<&std::ffi::OsStr> = container_dir.iter().collect();
    let idx = components.iter().position(|c| *c == "Devices")?;
    components.truncate(idx + 2);
    let mut out = PathBuf::new();
    for c in components {
        out.push(c);
    }
    Some(out)
}

/// A simulator device's display name (from `device.plist`'s `name`), with
/// its short runtime identifier appended when known (e.g. `iPhone 16
/// (iOS 17.0)`) — the doubled use as both the baseline row's `Label::Fn` and
/// `container_bundle_id`'s `{device}` label token is deliberate, so a
/// project's simulator claims describe the same device the same way the
/// baseline row does.
pub fn simulator_device_label(device_dir: &Path) -> String {
    let name = plist::Value::from_file(device_dir.join("device.plist"))
        .ok()
        .and_then(|v| {
            v.as_dictionary()
                .and_then(|d| d.get("name"))
                .and_then(|v| v.as_string())
                .map(str::to_string)
        })
        .unwrap_or_else(|| {
            device_dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        });
    match device_runtime_label(device_dir) {
        Some(runtime) => format!("{name} ({runtime})"),
        None => name,
    }
}

/// A short runtime label (e.g. `iOS 17.0`) from `device.plist`'s `runtime`
/// identifier (`com.apple.CoreSimulator.SimRuntime.iOS-17-0`).
fn device_runtime_label(device_dir: &Path) -> Option<String> {
    let value = plist::Value::from_file(device_dir.join("device.plist")).ok()?;
    let runtime = value
        .as_dictionary()?
        .get("runtime")
        .and_then(|v| v.as_string())?;
    Some(format_runtime_identifier(runtime))
}

fn format_runtime_identifier(runtime: &str) -> String {
    let Some((_, rest)) = runtime.rsplit_once("SimRuntime.") else {
        return runtime.to_string();
    };
    match rest.split_once('-') {
        // "iOS-17-0" -> platform "iOS", version "17-0" -> "17.0".
        Some((platform, version)) => format!("{platform} {}", version.replace('-', ".")),
        None => rest.to_string(),
    }
}

/// `<X> DeviceSupport`/one of `~/.claude`'s top-level entries → a friendly
/// label. `~/.claude`'s entries are labelled `"Claude Code <name>"`; kept as
/// a `Label::Fn` rather than `Label::Basename` for that prefix.
pub fn claude_state_label(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("Claude Code {name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jetbrains_name_match_checks_the_prefix_before_the_hash() {
        assert!(jetbrains_name_matches("cubby.a1b2c3d4", "cubby"));
        assert!(jetbrains_name_matches("cubby-a1b2c3d4", "cubby"));
        assert!(!jetbrains_name_matches("other.a1b2c3d4", "cubby"));
    }

    #[test]
    fn formats_a_simruntime_identifier() {
        assert_eq!(
            format_runtime_identifier("com.apple.CoreSimulator.SimRuntime.iOS-17-0"),
            "iOS 17.0"
        );
        assert_eq!(format_runtime_identifier("weird"), "weird");
    }

    #[test]
    fn device_dir_ancestor_finds_the_devices_udid_component() {
        let p = Path::new(
            "/Users/x/Library/Developer/CoreSimulator/Devices/ABCD/data/Containers/Bundle/Application/EFGH",
        );
        assert_eq!(
            device_dir_ancestor(p),
            Some(PathBuf::from(
                "/Users/x/Library/Developer/CoreSimulator/Devices/ABCD"
            ))
        );
    }
}
