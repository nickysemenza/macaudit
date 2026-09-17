//! SwiftPM package cache (`~/Library/Caches/org.swift.swiftpm/repositories`)
//! from `Package.resolved` identities — root, or inside an Xcode
//! project/workspace's `xcshareddata/swiftpm`. `.build/checkouts` inside the
//! project is already claimed as an artifact by `artifacts.rs`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::super::{find_node, Project};
use crate::attribution::model::{Claim, EntryKind, EvidenceTier, ResolveEnv, BASELINE_OWNER};

/// `env.read_head`'s cap for `Package.resolved` — a large dependency graph
/// can run to a few hundred KiB.
const MAX_RESOLVED_BYTES: usize = 512 * 1024;

pub fn resolve(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let owner = project.root.to_string_lossy().into_owned();
    let cache_root = swiftpm_repositories_dir(env);
    let mut claims = Vec::new();
    let mut claimed: HashSet<PathBuf> = HashSet::new();

    for path in candidate_resolved_paths(project, env) {
        let Some(text) = env.read_head(&path, MAX_RESOLVED_BYTES) else {
            continue;
        };
        for pin in parse_package_resolved(&text) {
            let Some(basename) = repo_basename(&pin.location) else {
                continue;
            };
            let Some(cache_dir) = find_repo_cache_dir(&cache_root, &basename) else {
                continue;
            };
            if !claimed.insert(cache_dir.clone()) {
                continue;
            }
            claims.push(
                Claim::new(
                    cache_dir,
                    owner.clone(),
                    EntryKind::PackageCache,
                    EvidenceTier::Exact,
                    "Package.resolved",
                )
                .label(pin.identity)
                .ecosystem("swift"),
            );
        }
    }
    claims
}

/// Claimed once per scan: SwiftPM's manifest cache and other shared state
/// that isn't a per-dependency repository checkout.
pub fn baseline(env: &ResolveEnv<'_>) -> Vec<Claim> {
    vec![
        Claim::new(
            env.paths
                .home
                .join("Library/Caches/org.swift.swiftpm/manifests"),
            BASELINE_OWNER,
            EntryKind::PackageCache,
            EvidenceTier::EcosystemDefault,
            "SwiftPM manifest cache",
        )
        .label("SwiftPM manifests")
        .baseline("swift"),
        Claim::new(
            env.paths.home.join("Library/org.swift.swiftpm"),
            BASELINE_OWNER,
            EntryKind::PackageCache,
            EvidenceTier::EcosystemDefault,
            "SwiftPM shared state",
        )
        .label("SwiftPM")
        .baseline("swift"),
    ]
}

fn swiftpm_repositories_dir(env: &ResolveEnv<'_>) -> PathBuf {
    env.paths
        .home
        .join("Library/Caches/org.swift.swiftpm/repositories")
}

/// `Package.resolved` at the project root, plus inside every direct-child
/// `.xcodeproj`/`.xcworkspace`'s `xcshareddata/swiftpm` (the two places
/// Xcode itself keeps its resolved-package snapshot when SwiftPM isn't
/// driven by a standalone `Package.swift`).
fn candidate_resolved_paths(project: &Project, env: &ResolveEnv<'_>) -> Vec<PathBuf> {
    let mut paths = vec![project.root.join("Package.resolved")];
    if let Some((_, root_node)) = find_node(env.trees, &project.root) {
        for child in root_node.children.iter() {
            let name = &*child.name;
            if name.ends_with(".xcodeproj") {
                paths.push(
                    project
                        .root
                        .join(name)
                        .join("project.xcworkspace/xcshareddata/swiftpm/Package.resolved"),
                );
            } else if name.ends_with(".xcworkspace") {
                paths.push(
                    project
                        .root
                        .join(name)
                        .join("xcshareddata/swiftpm/Package.resolved"),
                );
            }
        }
    }
    paths
}

/// One resolved dependency's identity + source location.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedPin {
    identity: String,
    location: String,
}

/// `Package.resolved` v1 (`{"object":{"pins":[{"package","repositoryURL"}]}}`)
/// and v2/v3 (`{"pins":[{"identity","location"}]}`).
fn parse_package_resolved(text: &str) -> Vec<ResolvedPin> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let version = json.get("version").and_then(Value::as_i64).unwrap_or(2);
    let pins = if version <= 1 {
        json.get("object").and_then(|o| o.get("pins"))
    } else {
        json.get("pins")
    };
    let Some(pins) = pins.and_then(Value::as_array) else {
        return Vec::new();
    };

    pins.iter()
        .filter_map(|p| {
            if version <= 1 {
                let identity = p.get("package").and_then(Value::as_str)?.to_string();
                let location = p.get("repositoryURL").and_then(Value::as_str)?.to_string();
                Some(ResolvedPin { identity, location })
            } else {
                let identity = p.get("identity").and_then(Value::as_str)?.to_string();
                let location = p.get("location").and_then(Value::as_str)?.to_string();
                Some(ResolvedPin { identity, location })
            }
        })
        .collect()
}

/// The repo name SwiftPM keys its cache directory by: the URL's last path
/// component with a trailing `.git`/`/` stripped.
fn repo_basename(url: &str) -> Option<String> {
    let trimmed = url.trim_end_matches('/').trim_end_matches(".git");
    trimmed
        .rsplit(['/', ':'])
        .next()
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

/// SwiftPM names each repository cache dir `<Name>-<hash>`; match
/// case-insensitively on the `<Name>-` prefix over one listing of the
/// repositories store.
fn find_repo_cache_dir(cache_root: &Path, basename: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(cache_root).ok()?;
    let prefix = format!("{}-", basename.to_ascii_lowercase());
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with(&prefix)
        {
            return Some(entry.path());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v2_pins() {
        let text = r#"{
            "version": 2,
            "pins": [
                { "identity": "swift-algorithms", "kind": "remoteSourceControl",
                  "location": "https://github.com/apple/swift-algorithms.git",
                  "state": { "revision": "abc", "version": "1.2.0" } }
            ]
        }"#;
        let pins = parse_package_resolved(text);
        assert_eq!(
            pins,
            vec![ResolvedPin {
                identity: "swift-algorithms".to_string(),
                location: "https://github.com/apple/swift-algorithms.git".to_string(),
            }]
        );
    }

    #[test]
    fn parses_v1_pins() {
        let text = r#"{
            "object": {
                "pins": [
                    { "package": "swift-algorithms",
                      "repositoryURL": "https://github.com/apple/swift-algorithms.git",
                      "state": { "branch": null, "revision": "abc", "version": "1.2.0" } }
                ]
            },
            "version": 1
        }"#;
        let pins = parse_package_resolved(text);
        assert_eq!(
            pins,
            vec![ResolvedPin {
                identity: "swift-algorithms".to_string(),
                location: "https://github.com/apple/swift-algorithms.git".to_string(),
            }]
        );
    }

    #[test]
    fn repo_basename_strips_dot_git_and_trailing_slash() {
        assert_eq!(
            repo_basename("https://github.com/apple/swift-algorithms.git"),
            Some("swift-algorithms".to_string())
        );
        assert_eq!(
            repo_basename("https://github.com/apple/swift-algorithms/"),
            Some("swift-algorithms".to_string())
        );
    }

    #[test]
    fn repo_basename_handles_scp_style_urls() {
        assert_eq!(
            repo_basename("git@github.com:apple/swift-algorithms.git"),
            Some("swift-algorithms".to_string())
        );
    }

    #[test]
    fn malformed_json_yields_no_pins() {
        assert_eq!(parse_package_resolved("not json"), Vec::new());
        assert_eq!(parse_package_resolved("{}"), Vec::new());
    }
}
