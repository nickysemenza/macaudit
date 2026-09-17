//! Every path that might belong to an app-axis owner: children of the
//! `~/Library/{Application Support, Caches, Containers, Group Containers,
//! Logs, HTTPStorages, WebKit, Saved Application State, Cookies,
//! Application Scripts, Preferences}` family, `~/.config`, `~/.cache`,
//! `~/.local/{share,state}`, `~/.<name>` dotdirs, the system-wide
//! equivalents, plus the curated Apple data-location table (`curated.rs`).
//! Each owner's own bundle/Cellar/install dir is claimed directly by
//! `linkers::owner_own_claims`, not enumerated here.
//!
//! Directories come from the walked `DirTree` (`env.trees`) wherever
//! possible; the tree carries no file nodes, so the handful of hubs that
//! hold *files* (Preferences, Cookies, Saved Application State, and
//! HTTPStorages's `.binarycookies` entries) are listed with a bounded
//! `std::fs::read_dir` on the live directory instead.

use std::path::{Path, PathBuf};

use crate::attribution::model::{EntryKind, ResolveEnv};

use super::curated;

/// One path that might belong to an app-axis owner, before linking.
pub(crate) struct Candidate {
    pub path: PathBuf,
    /// Leaf name — the file/dir name for depth-1 candidates, the stem for
    /// file-based ones (`.plist`/`.binarycookies`/`.savedState` stripped).
    pub name: String,
    pub parent_kind: EntryKind,
    /// The depth-1 directory name, for a depth-2 `<Vendor>/<Name>`
    /// candidate under a vendor-looking `Application Support`/`Caches` dir.
    pub vendor: Option<String>,
    /// Whether this candidate is a single file (a `.plist`/`.binarycookies`)
    /// rather than a directory. `linkers.rs`/`paths::Sizer` don't need this
    /// — `Sizer` already tells files from dirs itself when it sizes the
    /// claimed path — it's kept on the candidate for a future consumer that
    /// wants to distinguish the two without re-`stat`ing (e.g. a UI badge).
    #[allow(dead_code)]
    pub is_file: bool,
}

/// Home dotdirs that are either handled by their own dedicated hub below
/// (`.config`, `.cache`, `.local`) or never belong to an app
/// (`.Trash`, `.git`, `.ssh`, `.DS_Store`).
const SKIP_HOME_DOTDIRS: &[&str] = &[
    ".Trash",
    ".git",
    ".ssh",
    ".DS_Store",
    ".config",
    ".cache",
    ".local",
];

/// Enumerate every app-axis candidate path.
pub(crate) fn collect(env: &ResolveEnv<'_>) -> Vec<Candidate> {
    let home = env.paths.home.clone();
    let mut out = Vec::new();

    let lib = home.join("Library");
    push_depth1_and_vendor2(
        env,
        &lib.join("Application Support"),
        EntryKind::AppSupport,
        &mut out,
    );
    push_depth1_and_vendor2(env, &lib.join("Caches"), EntryKind::Cache, &mut out);
    push_depth1(env, &lib.join("Containers"), EntryKind::Container, &mut out);
    push_depth1(
        env,
        &lib.join("Group Containers"),
        EntryKind::GroupContainer,
        &mut out,
    );
    push_depth1(env, &lib.join("Logs"), EntryKind::Logs, &mut out);
    push_depth1(env, &lib.join("HTTPStorages"), EntryKind::WebData, &mut out);
    push_binarycookies(&lib.join("HTTPStorages"), &mut out);
    push_depth1(env, &lib.join("WebKit"), EntryKind::WebData, &mut out);
    push_saved_state(&lib.join("Saved Application State"), &mut out);
    push_cookie_files(&lib.join("Cookies"), &mut out);
    push_depth1(
        env,
        &lib.join("Application Scripts"),
        EntryKind::Other,
        &mut out,
    );
    push_plists(&lib.join("Preferences"), EntryKind::Preferences, &mut out);

    push_depth1(env, &home.join(".config"), EntryKind::DotDir, &mut out);
    push_depth1(env, &home.join(".cache"), EntryKind::Cache, &mut out);
    push_depth1(env, &home.join(".local/share"), EntryKind::DotDir, &mut out);
    push_depth1(env, &home.join(".local/state"), EntryKind::DotDir, &mut out);
    push_home_dotdirs(env, &home, &mut out);

    let sys_lib = Path::new("/Library");
    push_depth1(
        env,
        &sys_lib.join("Application Support"),
        EntryKind::AppSupport,
        &mut out,
    );
    push_depth1(env, &sys_lib.join("Caches"), EntryKind::Cache, &mut out);
    push_depth1(env, &sys_lib.join("Logs"), EntryKind::Logs, &mut out);
    push_plists(
        &sys_lib.join("Preferences"),
        EntryKind::Preferences,
        &mut out,
    );

    if let Some(prefix) = crate::scan::brew::brew_prefix() {
        push_depth1(env, &prefix.join("var"), EntryKind::Other, &mut out);
        push_depth1(env, &prefix.join("etc"), EntryKind::Other, &mut out);
        push_depth1(env, &prefix.join("share"), EntryKind::Other, &mut out);
    }

    out
}

/// The well-known Apple data locations (`curated::APPLE_DATA`, plus Photos
/// libraries and `CloudStorage` providers, which need a live directory
/// listing rather than a fixed path) as pre-resolved `(path, bundle id,
/// kind, label)` tuples — these skip the tiered linker entirely since the
/// owning bundle id is already known.
pub(crate) fn apple_data(env: &ResolveEnv<'_>) -> Vec<(PathBuf, &'static str, EntryKind, String)> {
    let home = &env.paths.home;
    let mut out = Vec::new();

    for loc in curated::APPLE_DATA {
        out.push((
            home.join(loc.home_suffix),
            loc.bundle_id,
            EntryKind::Data,
            loc.label.to_string(),
        ));
    }

    // Photos: the default library, plus any other *.photoslibrary under
    // ~/Pictures (a user can have several).
    if let Ok(entries) = std::fs::read_dir(home.join("Pictures")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("photoslibrary") {
                continue;
            }
            let label = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "Photos Library".to_string());
            out.push((path, curated::PHOTOS_BUNDLE_ID, EntryKind::Data, label));
        }
    }

    // iCloud-style CloudStorage providers: `<Provider>-<account>` dirs.
    if let Ok(entries) = std::fs::read_dir(home.join("Library/CloudStorage")) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some((provider, _account)) = name.split_once('-') else {
                continue;
            };
            if let Some((_, bundle_id)) = curated::CLOUD_STORAGE_PROVIDERS
                .iter()
                .find(|(p, _)| *p == provider)
            {
                let label = name.to_string();
                out.push((path, *bundle_id, EntryKind::Data, label));
            }
        }
    }

    out
}

/// Directory children of `dir` in whichever walked tree reached it — the
/// tree carries no file nodes, so this only ever returns subdirectories.
fn tree_child_names(env: &ResolveEnv<'_>, dir: &Path) -> Vec<String> {
    for tree in env.trees {
        if let Some(node) = tree.node.find(&tree.root, dir) {
            return node.children.iter().map(|c| c.name.to_string()).collect();
        }
    }
    Vec::new()
}

fn push_depth1(env: &ResolveEnv<'_>, hub: &Path, kind: EntryKind, out: &mut Vec<Candidate>) {
    for name in tree_child_names(env, hub) {
        out.push(Candidate {
            path: hub.join(&name),
            name,
            parent_kind: kind,
            vendor: None,
            is_file: false,
        });
    }
}

/// Depth-1 children, plus depth-2 children of any depth-1 dir that "looks
/// like a vendor": its name has no dot (ruling out per-bundle-id dirs like
/// `com.apple.Safari`) and it has at least one child dir.
fn push_depth1_and_vendor2(
    env: &ResolveEnv<'_>,
    hub: &Path,
    kind: EntryKind,
    out: &mut Vec<Candidate>,
) {
    for name in tree_child_names(env, hub) {
        let dir_path = hub.join(&name);
        out.push(Candidate {
            path: dir_path.clone(),
            name: name.clone(),
            parent_kind: kind,
            vendor: None,
            is_file: false,
        });
        if name.contains('.') {
            continue;
        }
        for name2 in tree_child_names(env, &dir_path) {
            out.push(Candidate {
                path: dir_path.join(&name2),
                name: name2,
                parent_kind: kind,
                vendor: Some(name.clone()),
                is_file: false,
            });
        }
    }
}

fn push_home_dotdirs(env: &ResolveEnv<'_>, home: &Path, out: &mut Vec<Candidate>) {
    for name in tree_child_names(env, home) {
        if !name.starts_with('.') || SKIP_HOME_DOTDIRS.contains(&name.as_str()) {
            continue;
        }
        out.push(Candidate {
            path: home.join(&name),
            name,
            parent_kind: EntryKind::DotDir,
            vendor: None,
            is_file: false,
        });
    }
}

/// `*.plist` files directly under `hub` (skipping the `ByHost` subdir) —
/// `~/Library/Preferences` and `/Library/Preferences`.
fn push_plists(hub: &Path, kind: EntryKind, out: &mut Vec<Candidate>) {
    let Ok(entries) = std::fs::read_dir(hub) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == "ByHost" {
            continue;
        }
        let Some(stem) = name.strip_suffix(".plist") else {
            continue;
        };
        let stem = stem.to_string();
        out.push(Candidate {
            path,
            name: stem,
            parent_kind: kind,
            vendor: None,
            is_file: true,
        });
    }
}

/// `~/Library/Cookies` — legacy per-app `.binarycookies` files.
fn push_cookie_files(hub: &Path, out: &mut Vec<Candidate>) {
    let Ok(entries) = std::fs::read_dir(hub) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let stem = name.strip_suffix(".binarycookies").unwrap_or(name);
        out.push(Candidate {
            path: path.clone(),
            name: stem.to_string(),
            parent_kind: EntryKind::WebData,
            vendor: None,
            is_file: true,
        });
    }
}

/// `~/Library/HTTPStorages`'s `.binarycookies` files (its per-bundle
/// subdirectories are already covered by `push_depth1` — the tree finds
/// those since they're directories).
fn push_binarycookies(hub: &Path, out: &mut Vec<Candidate>) {
    let Ok(entries) = std::fs::read_dir(hub) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".binarycookies") else {
            continue;
        };
        out.push(Candidate {
            path: path.clone(),
            name: stem.to_string(),
            parent_kind: EntryKind::WebData,
            vendor: None,
            is_file: true,
        });
    }
}

/// `~/Library/Saved Application State`'s `*.savedState` dirs — directories
/// on disk, but grouped with the other file-hub reads for consistency
/// rather than relying on the tree to have walked into them.
fn push_saved_state(hub: &Path, out: &mut Vec<Candidate>) {
    let Ok(entries) = std::fs::read_dir(hub) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".savedState") else {
            continue;
        };
        out.push(Candidate {
            path: path.clone(),
            name: stem.to_string(),
            parent_kind: EntryKind::SavedState,
            vendor: None,
            is_file: false,
        });
    }
}
