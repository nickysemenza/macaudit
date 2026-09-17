//! VS Code family workspace storage (`workspace.json`'s `folder`/`workspace`
//! URI) and JetBrains per-project caches (name match). Zed keeps its
//! project state inside a shared SQLite db rather than per-project
//! directories, so there's nothing path-shaped to claim here — skipped.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::super::Project;
use crate::attribution::model::{Claim, EntryKind, EvidenceTier, ResolveEnv};
use crate::attribution::paths as attribution_paths;

/// `env.read_head`'s cap for `workspace.json` — a small handful of fields.
const MAX_WORKSPACE_JSON_BYTES: usize = 16 * 1024;

/// VS Code and its forks, all sharing the same `User/workspaceStorage`
/// layout under `~/Library/Application Support/<app>`.
const VSCODE_FAMILY: &[&str] = &[
    "Code",
    "Code - Insiders",
    "Cursor",
    "Antigravity",
    "VSCodium",
];

/// JetBrains keeps two parallel per-IDE roots, each holding
/// `<ide>/<project-name>.<hash>` (or `-<hash>`) directories.
const JETBRAINS_ROOTS: &[&str] = &[
    "Library/Caches/JetBrains",
    "Library/Application Support/JetBrains",
];

pub fn resolve(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let owner = project.root.to_string_lossy().into_owned();
    let mut claims = vscode_claims(project, &owner, env);
    claims.extend(jetbrains_claims(project, &owner, env));
    claims
}

fn vscode_claims(project: &Project, owner: &str, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut claims = Vec::new();
    for app in VSCODE_FAMILY {
        let storage_dir = env
            .paths
            .home
            .join("Library/Application Support")
            .join(app)
            .join("User/workspaceStorage");
        let Ok(entries) = std::fs::read_dir(&storage_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let hash_dir = entry.path();
            let Some(text) =
                env.read_head(&hash_dir.join("workspace.json"), MAX_WORKSPACE_JSON_BYTES)
            else {
                continue;
            };
            let Some(folder) = parse_workspace_json_folder(&text) else {
                continue;
            };
            if !under_project(&attribution_paths::tree_path(&folder), project) {
                continue;
            }
            claims.push(
                Claim::new(
                    hash_dir,
                    owner.to_string(),
                    EntryKind::EditorState,
                    EvidenceTier::Exact,
                    format!("{app} workspace.json"),
                )
                .label(format!("{app} workspace storage")),
            );
        }
    }
    claims
}

/// `workspace.json`'s `folder` (a single-root window) or `workspace` (a
/// multi-root `.code-workspace` window) — both `file://` URIs.
fn parse_workspace_json_folder(text: &str) -> Option<PathBuf> {
    let json: Value = serde_json::from_str(text).ok()?;
    if let Some(folder) = json.get("folder").and_then(Value::as_str) {
        return attribution_paths::from_file_uri(folder);
    }
    if let Some(workspace) = json.get("workspace").and_then(Value::as_str) {
        return attribution_paths::from_file_uri(workspace);
    }
    None
}

fn jetbrains_claims(project: &Project, owner: &str, env: &ResolveEnv<'_>) -> Vec<Claim> {
    if project.names.is_empty() {
        return Vec::new();
    }
    let mut claims = Vec::new();
    for root_rel in JETBRAINS_ROOTS {
        let root = env.paths.home.join(root_rel);
        let Ok(ide_dirs) = std::fs::read_dir(&root) else {
            continue;
        };
        for ide_entry in ide_dirs.flatten() {
            let Ok(ide_file_type) = ide_entry.file_type() else {
                continue;
            };
            if !ide_file_type.is_dir() {
                continue;
            }
            let Ok(project_dirs) = std::fs::read_dir(ide_entry.path()) else {
                continue;
            };
            for proj_entry in project_dirs.flatten() {
                let Ok(proj_file_type) = proj_entry.file_type() else {
                    continue;
                };
                if !proj_file_type.is_dir() {
                    continue;
                }
                let dir_name = proj_entry.file_name().to_string_lossy().into_owned();
                let Some(matched_name) = jetbrains_name_match(&dir_name, &project.names) else {
                    continue;
                };
                claims.push(
                    Claim::new(
                        proj_entry.path(),
                        owner.to_string(),
                        EntryKind::EditorState,
                        EvidenceTier::NameMatch,
                        format!("JetBrains cache named after {matched_name}"),
                    )
                    .label(dir_name),
                );
            }
        }
    }
    claims
}

/// JetBrains project cache dirs are `<name>.<hash>` or `<name>-<hash>`; the
/// prefix before the final separator must equal one of the project's known
/// names exactly (case-sensitive — JetBrains preserves the project's own
/// casing here).
fn jetbrains_name_match<'a>(dir_name: &str, names: &'a [String]) -> Option<&'a str> {
    for sep in ['.', '-'] {
        if let Some((prefix, _hash)) = dir_name.rsplit_once(sep) {
            if let Some(found) = names.iter().find(|n| n.as_str() == prefix) {
                return Some(found.as_str());
            }
        }
    }
    None
}

fn under_project(path: &Path, project: &Project) -> bool {
    path.starts_with(&project.root) || project.worktrees.iter().any(|wt| path.starts_with(wt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_single_root_folder_form() {
        let text = r#"{"folder":"file:///Users/dev/cubby"}"#;
        assert_eq!(
            parse_workspace_json_folder(text),
            Some(PathBuf::from("/Users/dev/cubby"))
        );
    }

    #[test]
    fn parses_the_multi_root_workspace_form() {
        let text = r#"{"workspace":"file:///Users/dev/cubby/cubby.code-workspace"}"#;
        assert_eq!(
            parse_workspace_json_folder(text),
            Some(PathBuf::from("/Users/dev/cubby/cubby.code-workspace"))
        );
    }

    #[test]
    fn neither_field_present_is_none() {
        assert_eq!(parse_workspace_json_folder(r#"{"other":1}"#), None);
        assert_eq!(parse_workspace_json_folder("not json"), None);
    }

    #[test]
    fn jetbrains_name_match_checks_the_prefix_before_the_hash() {
        let names = vec!["cubby".to_string()];
        assert_eq!(
            jetbrains_name_match("cubby.a1b2c3d4", &names),
            Some("cubby")
        );
        assert_eq!(
            jetbrains_name_match("cubby-a1b2c3d4", &names),
            Some("cubby")
        );
        assert_eq!(jetbrains_name_match("other.a1b2c3d4", &names), None);
    }
}
