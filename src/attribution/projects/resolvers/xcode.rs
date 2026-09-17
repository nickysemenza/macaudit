//! DerivedData joined to its project via `*/info.plist WorkspacePath`; stale
//! entries (workspace deleted) flagged for Unattributed. The ecosystem-wide
//! module/SDK caches and device-support baggage inside/around DerivedData
//! are claimed once by `baseline()`, tagged `"xcode"`.

use std::path::{Path, PathBuf};

use super::super::{find_node, Project};
use crate::attribution::model::{
    Claim, EntryKind, EvidenceTier, ResolveEnv, BASELINE_OWNER, UNATTRIBUTED_OWNER,
};
use crate::attribution::paths as attribution_paths;
use crate::model::{FindingKind, ScannerId};
use crate::scan::walk::listing::{self, Kind};

/// Top-level entries inside `DerivedData` that are shared module/SDK caches
/// rather than one project's build output — claimed by `baseline()`.
const GLOBAL_DERIVED_DATA_DIRS: &[&str] = &[
    "ModuleCache.noindex",
    "SDKStatCaches.noindex",
    "SymbolCache.noindex",
    "CompilationCache.noindex",
    "SDKExplicitPrecompiledModules",
];

/// Fixed ecosystem-wide Xcode/simulator dirs, each claimed once by
/// `baseline()` — `(path relative to `Paths::expand`, label, kind)`.
const FIXED_XCODE_BASELINE_DIRS: &[(&str, &str, EntryKind)] = &[
    (
        "~/Library/Developer/Xcode/UserData",
        "Xcode UserData",
        EntryKind::Xcode,
    ),
    (
        "~/Library/Developer/CoreSimulator/Caches",
        "Simulator caches",
        EntryKind::Simulator,
    ),
    (
        "~/Library/Developer/XCPGDevices",
        "XCPG devices",
        EntryKind::Simulator,
    ),
    (
        "~/Library/Developer/CoreSimulator/Images",
        "Simulator images",
        EntryKind::Simulator,
    ),
    (
        "/Library/Developer/CoreSimulator/Volumes",
        "Simulator runtimes",
        EntryKind::Simulator,
    ),
];

pub fn resolve(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    if !is_xcode_project(project, env) {
        return Vec::new();
    }
    let owner = project.root.to_string_lossy().into_owned();
    let derived_data_dir = derived_data_dir(env);
    let Ok(dir_listing) = listing::list(&derived_data_dir) else {
        return Vec::new();
    };

    let mut claims = Vec::new();
    for entry in &dir_listing.entries {
        if entry.kind != Kind::Dir {
            continue;
        }
        let Some(name) = entry.name.to_str() else {
            continue;
        };
        if GLOBAL_DERIVED_DATA_DIRS.contains(&name) {
            continue;
        }
        let dir_path = derived_data_dir.join(name);
        let Some(workspace_path) = derived_data_workspace_path(&dir_path) else {
            continue;
        };
        let ws_path = attribution_paths::tree_path(&workspace_path);
        if !under_project(&ws_path, project) {
            continue;
        }

        let mut claim = Claim::new(
            dir_path.clone(),
            owner.clone(),
            EntryKind::Xcode,
            EvidenceTier::Exact,
            "DerivedData WorkspacePath",
        )
        .label(format!("DerivedData {}", derived_data_display_name(name)))
        .ecosystem("xcode");

        if let Some(finding_id) = matching_fs_cache_dir_finding(env, &dir_path) {
            claim = claim.finding(finding_id);
        }
        claims.push(claim);
    }
    claims
}

/// Claimed once per scan: every DerivedData entry whose `WorkspacePath` no
/// longer exists (Unattributed, stale), the shared module/SDK caches
/// alongside project dirs inside `DerivedData`, the `* DeviceSupport` dirs,
/// and the other fixed ecosystem-wide Xcode/simulator locations.
pub fn baseline(env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut claims = Vec::new();
    let derived_data_dir = derived_data_dir(env);

    if let Ok(dir_listing) = listing::list(&derived_data_dir) {
        for entry in &dir_listing.entries {
            if entry.kind != Kind::Dir {
                continue;
            }
            let Some(name) = entry.name.to_str() else {
                continue;
            };
            let dir_path = derived_data_dir.join(name);

            if GLOBAL_DERIVED_DATA_DIRS.contains(&name) {
                claims.push(
                    Claim::new(
                        dir_path,
                        BASELINE_OWNER,
                        EntryKind::Xcode,
                        EvidenceTier::EcosystemDefault,
                        "Xcode module/SDK cache",
                    )
                    .label(name.to_string())
                    .baseline("xcode"),
                );
                continue;
            }

            let Some(workspace_path) = derived_data_workspace_path(&dir_path) else {
                continue;
            };
            let ws_path = attribution_paths::tree_path(&workspace_path);
            if !ws_path.exists() {
                claims.push(
                    Claim::new(
                        dir_path,
                        UNATTRIBUTED_OWNER,
                        EntryKind::Xcode,
                        EvidenceTier::Observed,
                        format!("workspace deleted: {}", ws_path.display()),
                    )
                    .label(format!("DerivedData {}", derived_data_display_name(name)))
                    .stale(),
                );
            }
        }
    }

    for (rel, label, kind) in FIXED_XCODE_BASELINE_DIRS {
        claims.push(
            Claim::new(
                env.paths.expand(rel),
                BASELINE_OWNER,
                *kind,
                EvidenceTier::EcosystemDefault,
                "ecosystem default",
            )
            .label(label.to_string())
            .baseline("xcode"),
        );
    }

    // `<X> DeviceSupport` dirs (iOS, watchOS, tvOS, visionOS, ...) live
    // directly under `~/Library/Developer/Xcode`.
    let xcode_dir = env.paths.home.join("Library/Developer/Xcode");
    if let Ok(dir_listing) = listing::list(&xcode_dir) {
        for entry in &dir_listing.entries {
            if entry.kind != Kind::Dir {
                continue;
            }
            let Some(name) = entry.name.to_str() else {
                continue;
            };
            if name.ends_with("DeviceSupport") {
                claims.push(
                    Claim::new(
                        xcode_dir.join(name),
                        BASELINE_OWNER,
                        EntryKind::Xcode,
                        EvidenceTier::EcosystemDefault,
                        "Xcode device support",
                    )
                    .label(name.to_string())
                    .baseline("xcode"),
                );
            }
        }
    }

    claims
}

fn derived_data_dir(env: &ResolveEnv<'_>) -> PathBuf {
    env.paths.home.join("Library/Developer/Xcode/DerivedData")
}

/// `<Name>-<hash>` → `<Name>` (the random hash is always the last `-`
/// separated component).
fn derived_data_display_name(dir_name: &str) -> &str {
    dir_name.rsplit_once('-').map_or(dir_name, |(n, _)| n)
}

fn derived_data_workspace_path(dir_path: &Path) -> Option<PathBuf> {
    let value = plist::Value::from_file(dir_path.join("info.plist")).ok()?;
    let workspace_path = value.as_dictionary()?.get("WorkspacePath")?.as_string()?;
    Some(PathBuf::from(workspace_path))
}

/// The Fs `CacheDir` finding, if any, whose path is exactly this DerivedData
/// entry — `FIXED_TARGETS` in `scan/fs.rs` currently emits one `CacheDir`
/// finding for the whole `DerivedData` directory rather than per-project
/// subdirs, so this rarely matches today; kept generic so a future
/// per-subdir Fs finding is picked up without a resolver change.
fn matching_fs_cache_dir_finding(
    env: &ResolveEnv<'_>,
    dir_path: &Path,
) -> Option<crate::model::FindingId> {
    let wanted = attribution_paths::tree_path(dir_path);
    env.findings(ScannerId::Fs)
        .iter()
        .find(|f| {
            f.kind == FindingKind::CacheDir
                && f.path
                    .as_deref()
                    .map(attribution_paths::tree_path)
                    .as_deref()
                    == Some(wanted.as_path())
        })
        .map(|f| f.id)
}

fn is_xcode_project(project: &Project, env: &ResolveEnv<'_>) -> bool {
    if project.root.join("Package.swift").exists() {
        return true;
    }
    let Some((_, root_node)) = find_node(env.trees, &project.root) else {
        return false;
    };
    root_node.children.iter().any(|c| {
        let name = &*c.name;
        name.ends_with(".xcodeproj") || name.ends_with(".xcworkspace")
    })
}

fn under_project(path: &Path, project: &Project) -> bool {
    path.starts_with(&project.root) || project.worktrees.iter().any(|wt| path.starts_with(wt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_data_display_name_strips_the_trailing_hash() {
        assert_eq!(derived_data_display_name("Cubby-abcdefghijklmnop"), "Cubby");
        assert_eq!(derived_data_display_name("Cubby"), "Cubby");
    }

    #[test]
    fn under_project_matches_root_and_worktrees() {
        let project = Project {
            root: PathBuf::from("/Users/dev/cubby"),
            name: "cubby".into(),
            worktrees: vec![PathBuf::from("/Users/dev/cubby-worktrees/feature")],
            names: Vec::new(),
            bundle_ids: Vec::new(),
            is_git: true,
        };
        assert!(under_project(
            Path::new("/Users/dev/cubby/apps/api"),
            &project
        ));
        assert!(under_project(
            Path::new("/Users/dev/cubby-worktrees/feature/apps/api"),
            &project
        ));
        assert!(!under_project(Path::new("/Users/dev/other"), &project));
    }
}
