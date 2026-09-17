//! Project-name caches: `~/Library/{Caches,HTTPStorages,WebKit,Application
//! Support,Logs}/<name>`, `~/.cache/<name>`, `~/.config/<name>`,
//! `~/.local/share/<name>` (name match), plus bundle-id-keyed locations
//! (`~/Library/Containers/<id>`, ...) from `project.pbxproj` (exact). No
//! baseline: these are per-project by construction.

use super::super::{find_node, Project};
use crate::attribution::model::{Claim, EntryKind, EvidenceTier, ResolveEnv};

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

pub fn resolve(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let owner = project.root.to_string_lossy().into_owned();
    let mut claims = Vec::new();

    let candidates = candidate_project_names(project);
    if !candidates.is_empty() {
        for parent_rel in CACHE_PARENT_DIRS {
            let parent = env.paths.home.join(parent_rel);
            let Some((_, node)) = find_node(env.trees, &parent) else {
                continue;
            };
            for child in node.children.iter() {
                let child_name = &*child.name;
                let Some(matched) = matches_any_name(child_name, &candidates) else {
                    continue;
                };
                claims.push(
                    Claim::new(
                        parent.join(child_name),
                        owner.clone(),
                        EntryKind::ProjectCache,
                        EvidenceTier::NameMatch,
                        format!("named after project ({matched})"),
                    )
                    .label(child_name.to_string()),
                );
            }
        }
    }

    for bundle_id in &project.bundle_ids {
        for (rel, kind) in bundle_id_targets(bundle_id) {
            let path = env.paths.home.join(&rel);
            if !path.exists() {
                continue;
            }
            claims.push(
                Claim::new(
                    path,
                    owner.clone(),
                    kind,
                    EvidenceTier::Exact,
                    "bundle id from project.pbxproj",
                )
                .label(bundle_id.clone()),
            );
        }
    }

    claims
}

/// Every one of `project.names` worth trying as a cache-dir name: lowercased,
/// with `-`/`_` variants added, filtered of anything too short or generic to
/// be a trustworthy signal.
fn candidate_project_names(project: &Project) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for name in &project.names {
        let lower = name.to_ascii_lowercase();
        if lower.len() < 4 || GENERIC_NAMES.contains(&lower.as_str()) {
            continue;
        }
        names.push(lower.clone());
        if lower.contains('-') {
            names.push(lower.replace('-', "_"));
        }
        if lower.contains('_') {
            names.push(lower.replace('_', "-"));
        }
    }
    names.sort();
    names.dedup();
    names
}

fn matches_any_name<'a>(child_name: &str, candidates: &'a [String]) -> Option<&'a str> {
    let lower = child_name.to_ascii_lowercase();
    candidates
        .iter()
        .find(|c| c.as_str() == lower)
        .map(String::as_str)
}

fn bundle_id_targets(bundle_id: &str) -> [(String, EntryKind); 6] {
    [
        (
            format!("Library/Containers/{bundle_id}"),
            EntryKind::Container,
        ),
        (format!("Library/Caches/{bundle_id}"), EntryKind::Cache),
        (
            format!("Library/HTTPStorages/{bundle_id}"),
            EntryKind::WebData,
        ),
        (
            format!("Library/Preferences/{bundle_id}.plist"),
            EntryKind::Preferences,
        ),
        (format!("Library/WebKit/{bundle_id}"), EntryKind::WebData),
        (
            format!("Library/Saved Application State/{bundle_id}.savedState"),
            EntryKind::SavedState,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn project_with_names(names: &[&str]) -> Project {
        Project {
            root: PathBuf::from("/Users/dev/cubby"),
            name: "cubby".into(),
            worktrees: Vec::new(),
            names: names.iter().map(|n| n.to_string()).collect(),
            bundle_ids: Vec::new(),
            is_git: true,
        }
    }

    #[test]
    fn candidate_names_skips_short_and_generic_names() {
        let project = project_with_names(&["cubby", "api", "ui", "src"]);
        assert_eq!(candidate_project_names(&project), vec!["cubby".to_string()]);
    }

    #[test]
    fn candidate_names_adds_dash_underscore_variants() {
        let project = project_with_names(&["recipe-bridge"]);
        let names = candidate_project_names(&project);
        assert!(names.contains(&"recipe-bridge".to_string()));
        assert!(names.contains(&"recipe_bridge".to_string()));
    }

    #[test]
    fn matches_any_name_is_case_insensitive() {
        let candidates = vec!["cubby".to_string()];
        assert_eq!(matches_any_name("Cubby", &candidates), Some("cubby"));
        assert_eq!(matches_any_name("other", &candidates), None);
    }

    #[test]
    fn bundle_id_targets_covers_every_known_location() {
        let targets = bundle_id_targets("com.example.app");
        assert_eq!(targets.len(), 6);
        assert!(targets
            .iter()
            .any(|(p, _)| p == "Library/Containers/com.example.app"));
        assert!(targets
            .iter()
            .any(|(p, _)| p == "Library/Preferences/com.example.app.plist"));
    }
}
