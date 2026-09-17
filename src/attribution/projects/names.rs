//! Project/owner name extraction, for the name-match evidence tier and the
//! simulator/bundle-id joins: directory basename (already seeded by
//! `discovery.rs`); `package.json` `name` (root + `workspaces`); every
//! non-artifact `Cargo.toml`'s `[package].name` and `[[bin]].name`;
//! `PRODUCT_BUNDLE_IDENTIFIER`/`PRODUCT_NAME` out of
//! `*.xcodeproj/project.pbxproj`; `Package.swift`'s `name:`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::attribution::model::ResolveEnv;
use crate::scan::global_tools::projects::SKIP_DIRS;
use crate::scan::walk::listing::{self, Kind};
use crate::scan::walk::DirNode;

use super::discovery::is_package_dir;
use super::{find_node, Project, ARTIFACT_DIR_NAMES};

/// How deep below a project's root the Cargo.toml/`.xcodeproj` search goes.
const NAME_SEARCH_DEPTH: usize = 4;
/// `ResolveEnv::read_head`'s cap for every manifest this module reads.
const MAX_MANIFEST_BYTES: usize = 256 * 1024;

/// Fill in `project.names`/`project.bundle_ids` from every manifest this
/// project's subtree carries. `project.names` already holds the directory
/// basename (from `discovery.rs`) — everything found here is added to it,
/// deduplicated, in the order it's found.
pub fn collect(project: &mut Project, env: &ResolveEnv<'_>) {
    let mut seen: HashSet<String> = project.names.iter().cloned().collect();
    collect_package_json(project, env, &mut seen);
    collect_cargo_and_xcode(project, env, &mut seen);
    collect_package_swift(project, env, &mut seen);
}

fn push_unique(project: &mut Project, seen: &mut HashSet<String>, name: &str) {
    let name = name.trim();
    if name.is_empty() {
        return;
    }
    if seen.insert(name.to_string()) {
        project.names.push(name.to_string());
    }
}

/// Root `package.json` `name`, plus every workspace package's own `name`
/// (globs from `package.json`'s `workspaces` and `pnpm-workspace.yaml`'s
/// `packages:`, resolved against the walked tree rather than the disk).
fn collect_package_json(project: &mut Project, env: &ResolveEnv<'_>, seen: &mut HashSet<String>) {
    let root_pkg = project.root.join("package.json");
    if let Some(text) = env.read_head(&root_pkg, MAX_MANIFEST_BYTES) {
        if let Ok(json) = serde_json::from_str::<Value>(&text) {
            if let Some(name) = json.get("name").and_then(Value::as_str) {
                push_unique(project, seen, name);
            }
            for glob in workspace_globs(&json) {
                for child in resolve_simple_glob(env, &project.root, &glob) {
                    collect_workspace_package(project, env, seen, &child);
                }
            }
        }
    }
    for glob in pnpm_workspace_globs(env, &project.root.join("pnpm-workspace.yaml")) {
        for child in resolve_simple_glob(env, &project.root, &glob) {
            collect_workspace_package(project, env, seen, &child);
        }
    }
}

fn collect_workspace_package(
    project: &mut Project,
    env: &ResolveEnv<'_>,
    seen: &mut HashSet<String>,
    dir: &Path,
) {
    let Some(text) = env.read_head(&dir.join("package.json"), MAX_MANIFEST_BYTES) else {
        return;
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return;
    };
    if let Some(name) = json.get("name").and_then(Value::as_str) {
        push_unique(project, seen, name);
    }
}

/// `package.json`'s `workspaces` field: either a bare array of globs, or the
/// older Lerna-style `{ "packages": [...] }`.
fn workspace_globs(json: &Value) -> Vec<String> {
    match json.get("workspaces") {
        Some(Value::Array(globs)) => globs
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(Value::Object(obj)) => obj
            .get("packages")
            .and_then(Value::as_array)
            .map(|globs| {
                globs
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// `pnpm-workspace.yaml`'s `packages:` list. No YAML dependency in this
/// crate, so this is a deliberately narrow line parser: a `packages:` line,
/// then `- "glob"` lines until the list ends — the shape pnpm's own docs and
/// every real workspace file use.
fn pnpm_workspace_globs(env: &ResolveEnv<'_>, path: &Path) -> Vec<String> {
    let Some(text) = env.read_head(path, MAX_MANIFEST_BYTES) else {
        return Vec::new();
    };
    parse_pnpm_workspace_packages(&text)
}

fn parse_pnpm_workspace_packages(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_packages = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("packages:") {
            in_packages = true;
            continue;
        }
        if !in_packages {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix('-') else {
            break; // the list ended
        };
        let glob = rest.trim().trim_matches(|c| c == '"' || c == '\'');
        if !glob.is_empty() {
            out.push(glob.to_string());
        }
    }
    out
}

/// Resolve a single-wildcard glob (`"apps/*"`) against the walked tree's
/// directory names — anything with more than one `*`, or one that isn't the
/// final path component, is left alone (not worth a real glob engine for
/// workspace layouts, which are overwhelmingly `dir/*`).
fn resolve_simple_glob(env: &ResolveEnv<'_>, root: &Path, glob: &str) -> Vec<PathBuf> {
    let Some(prefix) = glob.strip_suffix("/*") else {
        return Vec::new();
    };
    if prefix.is_empty() || prefix.contains('*') {
        return Vec::new();
    }
    let dir = root.join(prefix);
    let Some((_, node)) = find_node(env.trees, &dir) else {
        return Vec::new();
    };
    node.children.iter().map(|c| dir.join(&*c.name)).collect()
}

/// Walk the project's subtree once (depth-bounded, artifact/vendor dirs
/// pruned) looking for every non-artifact `Cargo.toml` and `.xcodeproj`.
fn collect_cargo_and_xcode(
    project: &mut Project,
    env: &ResolveEnv<'_>,
    seen: &mut HashSet<String>,
) {
    let Some((_, root_node)) = find_node(env.trees, &project.root) else {
        return;
    };
    let mut stack: Vec<(PathBuf, &DirNode, usize)> = vec![(project.root.clone(), root_node, 0)];
    while let Some((path, node, depth)) = stack.pop() {
        if let Ok(dir_listing) = listing::list(&path) {
            let has_cargo_toml = dir_listing
                .entries
                .iter()
                .any(|e| e.kind != Kind::Dir && e.name.to_str() == Some("Cargo.toml"));
            if has_cargo_toml {
                if let Some(text) = env.read_head(&path.join("Cargo.toml"), MAX_MANIFEST_BYTES) {
                    collect_cargo_toml_names(&text, project, seen);
                }
            }
        }

        for child in node.children.iter() {
            let name = &*child.name;
            if name.ends_with(".xcodeproj") {
                let pbxproj = path.join(name).join("project.pbxproj");
                if let Some(text) = env.read_head(&pbxproj, MAX_MANIFEST_BYTES) {
                    collect_pbxproj(&text, project, seen);
                }
                continue; // never descend into the package itself
            }
            if depth >= NAME_SEARCH_DEPTH {
                continue;
            }
            if name.starts_with('.')
                || name == "Library"
                || SKIP_DIRS.contains(&name)
                || ARTIFACT_DIR_NAMES.contains(&name)
                || is_package_dir(name)
            {
                continue;
            }
            stack.push((path.join(name), child, depth + 1));
        }
    }
}

fn collect_cargo_toml_names(text: &str, project: &mut Project, seen: &mut HashSet<String>) {
    let Ok(table) = toml::from_str::<toml::Table>(text) else {
        return;
    };
    if let Some(name) = table
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
    {
        push_unique(project, seen, name);
    }
    if let Some(bins) = table.get("bin").and_then(|b| b.as_array()) {
        for bin in bins {
            if let Some(name) = bin.get("name").and_then(|n| n.as_str()) {
                push_unique(project, seen, name);
            }
        }
    }
}

fn collect_pbxproj(text: &str, project: &mut Project, seen: &mut HashSet<String>) {
    for id in extract_pbxproj_field(text, "PRODUCT_BUNDLE_IDENTIFIER") {
        if !project.bundle_ids.contains(&id) {
            project.bundle_ids.push(id);
        }
    }
    for name in extract_pbxproj_field(text, "PRODUCT_NAME") {
        push_unique(project, seen, &name);
    }
}

/// `KEY = value;` lines from a `.pbxproj` build-settings block. Values
/// carrying an unresolved build variable (`$(TARGET_NAME)`) are skipped —
/// they aren't a usable name/bundle id on their own. Pure so the pbxproj
/// snippet in the tests below covers it directly, no fixture file needed.
fn extract_pbxproj_field(text: &str, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix(key) else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let value = rest.trim().trim_end_matches(';').trim().trim_matches('"');
        if !value.is_empty() && !value.contains('$') {
            out.push(value.to_string());
        }
    }
    out
}

fn collect_package_swift(project: &mut Project, env: &ResolveEnv<'_>, seen: &mut HashSet<String>) {
    let path = project.root.join("Package.swift");
    let Some(text) = env.read_head(&path, MAX_MANIFEST_BYTES) else {
        return;
    };
    if let Some(name) = extract_swift_package_name(&text) {
        push_unique(project, seen, &name);
    }
}

/// The package's own `name: "X"` — the first one in the file, which for a
/// well-formed manifest is `Package(name: "X", ...)` itself; later `name:`
/// occurrences belong to individual targets/products.
fn extract_swift_package_name(text: &str) -> Option<String> {
    let after_key = text.split_once("name:")?.1;
    let after_quote = after_key.split_once('"')?.1;
    let (name, _) = after_quote.split_once('"')?;
    (!name.is_empty()).then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bundle_identifier_from_a_pbxproj_snippet() {
        let snippet = r#"
            buildSettings = {
                PRODUCT_BUNDLE_IDENTIFIER = com.example.overboard;
                PRODUCT_NAME = "$(TARGET_NAME)";
            };
        "#;
        assert_eq!(
            extract_pbxproj_field(snippet, "PRODUCT_BUNDLE_IDENTIFIER"),
            vec!["com.example.overboard".to_string()]
        );
        // A macro-valued PRODUCT_NAME is not a usable name on its own.
        assert!(extract_pbxproj_field(snippet, "PRODUCT_NAME").is_empty());
    }

    #[test]
    fn extracts_a_literal_product_name() {
        let snippet = r#"PRODUCT_NAME = Overboard;"#;
        assert_eq!(
            extract_pbxproj_field(snippet, "PRODUCT_NAME"),
            vec!["Overboard".to_string()]
        );
    }

    #[test]
    fn extracts_the_packages_own_name_from_package_swift() {
        let text = r#"
            // swift-tools-version:5.9
            let package = Package(
                name: "Overboard",
                targets: [
                    .target(name: "OverboardKit"),
                ]
            )
        "#;
        assert_eq!(
            extract_swift_package_name(text),
            Some("Overboard".to_string())
        );
    }

    #[test]
    fn parses_pnpm_workspace_packages_list() {
        let text = "packages:\n  - \"apps/*\"\n  - 'tools/*'\n\nsomething-else: true\n";
        assert_eq!(
            parse_pnpm_workspace_packages(text),
            vec!["apps/*".to_string(), "tools/*".to_string()]
        );
    }
}
