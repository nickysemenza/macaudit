//! Working tree + build artifacts: the repo root/manifest dir itself, plus
//! every Fs artifact finding under the project (hard-link-subtracted
//! exclusive bytes), the linked git worktrees, and redirected cargo target
//! dirs (`.cargo/config.toml`, `CARGO_TARGET_DIR` in scripts/shell files).

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use super::super::{find_node, Project, ARTIFACT_DIR_NAMES};
use crate::attribution::model::{Claim, EntryKind, EvidenceTier, ResolveEnv};
use crate::model::{FindingKind, ScannerId};
use crate::scan::walk::listing::{self, Kind};
use crate::scan::walk::DirNode;

/// `env.read_head`'s cap for the small text files this resolver parses
/// (`.cargo/config.toml`, `package.json`, `Makefile`, shell scripts, ...).
const MAX_FILE_BYTES: usize = 256 * 1024;

/// How deep below the project root shell/make files are searched for a
/// redirected `CARGO_TARGET_DIR`.
const SHELL_FILE_DEPTH: usize = 4;

pub fn resolve(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let owner = project.root.to_string_lossy().into_owned();
    let mut claims = Vec::with_capacity(1 + project.worktrees.len());

    claims.push(working_tree_claim(project, &owner));
    claims.extend(
        project
            .worktrees
            .iter()
            .map(|wt| worktree_claim(wt, &owner)),
    );
    claims.extend(artifact_claims(project, env, &owner));
    claims.extend(cargo_target_dir_claims(project, env, &owner));

    claims
}

fn working_tree_claim(project: &Project, owner: &str) -> Claim {
    let evidence = if project.is_git {
        "git repository"
    } else {
        "project manifest"
    };
    // Sized from the walk like every nested artifact/worktree entry — never
    // from the Git section's `du`, which comes out of a 24 h size cache and
    // can lag behind a `target/` that grew since, making children exceed
    // their parent.
    Claim::new(
        project.root.clone(),
        owner.to_string(),
        EntryKind::WorkingTree,
        EvidenceTier::Exact,
        evidence,
    )
    .label(project.name.clone())
}

fn worktree_claim(worktree: &Path, owner: &str) -> Claim {
    let label = worktree
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| worktree.display().to_string());
    Claim::new(
        worktree.to_path_buf(),
        owner.to_string(),
        EntryKind::Worktree,
        EvidenceTier::Exact,
        ".git/worktrees",
    )
    .label(label)
}

/// Every `BuildArtifact` finding from the Fs section whose path falls inside
/// this project's root or one of its worktrees.
fn artifact_claims(project: &Project, env: &ResolveEnv<'_>, owner: &str) -> Vec<Claim> {
    let mut claims = Vec::new();
    for finding in env.findings(ScannerId::Fs) {
        if finding.kind != FindingKind::BuildArtifact {
            continue;
        }
        let Some(path) = &finding.path else { continue };
        if !under_project(path, project) {
            continue;
        }

        let marker = finding.meta.get("marker").and_then(Value::as_str);
        let evidence = match marker {
            Some(m) => format!("{m} beside it"),
            None => finding
                .meta
                .get("artifact")
                .and_then(Value::as_str)
                .map(|a| format!("{a} artifact"))
                .unwrap_or_else(|| "build artifact".to_string()),
        };

        let mut claim = Claim::new(
            path.clone(),
            owner.to_string(),
            EntryKind::Artifacts,
            EvidenceTier::Exact,
            evidence,
        )
        .label(relative_label(project, path))
        .finding(finding.id);

        if let Some(size_bytes) = finding.size_bytes {
            let shared = finding
                .meta
                .get("shared_hardlink_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            claim = claim.raw_bytes_override(size_bytes.saturating_sub(shared));
        }
        claims.push(claim);
    }
    claims
}

/// `path` relative to the project root, for use as an artifact's label — the
/// basename alone when `path` isn't actually under the root (shouldn't
/// happen given `under_project` already filtered, but cheap to guard).
fn relative_label(project: &Project, path: &Path) -> String {
    path.strip_prefix(&project.root)
        .ok()
        .map(|rel| rel.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
}

fn under_project(path: &Path, project: &Project) -> bool {
    path.starts_with(&project.root) || project.worktrees.iter().any(|wt| path.starts_with(wt))
}

// --- Redirected cargo target dirs ------------------------------------------

static CARGO_TARGET_DIR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"CARGO_TARGET_DIR=(["']?)([^"'\s;&|]+)"#).unwrap());

/// Every `CARGO_TARGET_DIR=<value>` occurrence in `text` (any quoting, or
/// none). Pure so the package.json-script shape below gets a direct test.
fn extract_cargo_target_dir(text: &str) -> Vec<String> {
    CARGO_TARGET_DIR_RE
        .captures_iter(text)
        .map(|c| unwrap_shell_default(&c[2]).to_string())
        .collect()
}

/// `${CARGO_TARGET_DIR:-<default>}` (the "respect an override, else use
/// this" idiom) → `<default>`; anything else passes through unchanged.
fn unwrap_shell_default(value: &str) -> &str {
    value
        .strip_prefix("${")
        .and_then(|v| v.strip_suffix('}'))
        .and_then(|v| v.split_once(":-"))
        .map(|(_, default)| default)
        .unwrap_or(value)
}

/// `$HOME`/`${HOME}`/`~` expansion, then relative-to-`project_root`
/// resolution — the same rule `Paths::expand` applies to config values, just
/// against an arbitrary home rather than always `env.paths.home`.
fn expand_target_dir(value: &str, home: &Path, project_root: &Path) -> PathBuf {
    let home_str = home.to_string_lossy();
    let expanded = if let Some(rest) = value.strip_prefix("${HOME}") {
        format!("{home_str}{rest}")
    } else if let Some(rest) = value.strip_prefix("$HOME") {
        format!("{home_str}{rest}")
    } else if let Some(rest) = value.strip_prefix('~') {
        format!("{home_str}{rest}")
    } else {
        value.to_string()
    };
    let path = PathBuf::from(expanded);
    if path.is_absolute() {
        path
    } else {
        project_root.join(path)
    }
}

fn cargo_target_dir_claims(project: &Project, env: &ResolveEnv<'_>, owner: &str) -> Vec<Claim> {
    let mut claims = Vec::new();
    let root = &project.root;

    // `.cargo/config.toml`'s `[build] target-dir`.
    if let Some(text) = env.read_head(&root.join(".cargo/config.toml"), MAX_FILE_BYTES) {
        if let Ok(table) = toml::from_str::<toml::Table>(&text) {
            if let Some(dir) = table
                .get("build")
                .and_then(|b| b.get("target-dir"))
                .and_then(|v| v.as_str())
            {
                let path = expand_target_dir(dir, &env.paths.home, root);
                claims.push(target_dir_claim(
                    owner,
                    path,
                    "target-dir in .cargo/config.toml",
                ));
            }
        }
    }

    // `CARGO_TARGET_DIR=` inside root `package.json`'s `scripts` values.
    if let Some(text) = env.read_head(&root.join("package.json"), MAX_FILE_BYTES) {
        for value in cargo_target_dirs_in_package_json_scripts(&text) {
            let path = expand_target_dir(&value, &env.paths.home, root);
            claims.push(target_dir_claim(
                owner,
                path,
                "CARGO_TARGET_DIR in package.json",
            ));
        }
    }

    // `CARGO_TARGET_DIR=` in Makefile/justfile/.env*/`.sh` files in the tree.
    for path in candidate_shell_files(root, env) {
        let name = path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
        if let Some(text) = env.read_head(&path, MAX_FILE_BYTES) {
            for value in extract_cargo_target_dir(&text) {
                let target = expand_target_dir(&value, &env.paths.home, root);
                claims.push(target_dir_claim(
                    owner,
                    target,
                    format!("CARGO_TARGET_DIR in {name}"),
                ));
            }
        }
    }

    claims
}

/// `package.json`'s `scripts` object's string values only — `scripts` is
/// where a redirected `CARGO_TARGET_DIR` realistically shows up (a wasm
/// build step, a `cargo build` wrapper), and scanning the rest of the
/// manifest would risk matching unrelated string fields.
fn cargo_target_dirs_in_package_json_scripts(text: &str) -> Vec<String> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let Some(scripts) = json.get("scripts").and_then(Value::as_object) else {
        return Vec::new();
    };
    scripts
        .values()
        .filter_map(Value::as_str)
        .flat_map(extract_cargo_target_dir)
        .collect()
}

/// `Makefile`, `justfile`, `.env`, `.env.*` and `*.sh` files anywhere in
/// the project's subtree down to `SHELL_FILE_DEPTH` (directories from the
/// walked tree, one `listing::list` per directory for filenames; artifact
/// and hidden dirs skipped) — a redirected `CARGO_TARGET_DIR` is as likely
/// to live in `apps/apple/scripts/build-rust.sh` as at the root.
fn candidate_shell_files(root: &Path, env: &ResolveEnv<'_>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Some((_, root_node)) = find_node(env.trees, root) else {
        return files;
    };
    let mut stack: Vec<(PathBuf, &DirNode, usize)> = vec![(root.to_path_buf(), root_node, 0)];
    while let Some((dir, node, depth)) = stack.pop() {
        if let Ok(dir_listing) = listing::list(&dir) {
            for entry in &dir_listing.entries {
                if entry.kind == Kind::Dir {
                    continue;
                }
                let Some(name) = entry.name.to_str() else {
                    continue;
                };
                if matches!(name, "Makefile" | "justfile" | ".env")
                    || name.starts_with(".env.")
                    || name.ends_with(".sh")
                {
                    files.push(dir.join(name));
                }
            }
        }
        if depth >= SHELL_FILE_DEPTH {
            continue;
        }
        for child in node.children.iter() {
            let name = &*child.name;
            if name.starts_with('.') || ARTIFACT_DIR_NAMES.contains(&name) {
                continue;
            }
            stack.push((dir.join(name), child, depth + 1));
        }
    }
    files.sort();
    files
}

fn target_dir_claim(owner: &str, path: PathBuf, evidence: impl Into<String>) -> Claim {
    let label = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "target".to_string());
    Claim::new(
        path,
        owner.to_string(),
        EntryKind::Artifacts,
        EvidenceTier::Exact,
        evidence,
    )
    .label(label)
    .ecosystem("rust")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_cargo_target_dir_from_a_package_json_script_string() {
        let script = "CARGO_TARGET_DIR=$HOME/.cache/cubby/recipebridge-target wasm-pack build";
        assert_eq!(
            extract_cargo_target_dir(script),
            vec!["$HOME/.cache/cubby/recipebridge-target".to_string()]
        );
    }

    #[test]
    fn unwraps_the_shell_default_expansion_idiom() {
        let script = r#"CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/cubby/recipebridge-target}" wasm-pack build"#;
        assert_eq!(
            extract_cargo_target_dir(script),
            vec!["$HOME/.cache/cubby/recipebridge-target".to_string()]
        );
    }

    #[test]
    fn extracts_from_a_full_package_json_scripts_block() {
        let text = r#"{
            "name": "recipebridge",
            "scripts": {
                "wasm": "CARGO_TARGET_DIR=$HOME/.cache/cubby/recipebridge-target wasm-pack build",
                "build": "tsc"
            }
        }"#;
        assert_eq!(
            cargo_target_dirs_in_package_json_scripts(text),
            vec!["$HOME/.cache/cubby/recipebridge-target".to_string()]
        );
    }

    #[test]
    fn expands_home_variants_and_tilde() {
        let home = Path::new("/Users/nicky");
        let root = Path::new("/Users/nicky/dev/recipebridge");
        assert_eq!(
            expand_target_dir("$HOME/.cache/x", home, root),
            PathBuf::from("/Users/nicky/.cache/x")
        );
        assert_eq!(
            expand_target_dir("${HOME}/.cache/x", home, root),
            PathBuf::from("/Users/nicky/.cache/x")
        );
        assert_eq!(
            expand_target_dir("~/.cache/x", home, root),
            PathBuf::from("/Users/nicky/.cache/x")
        );
    }

    #[test]
    fn relative_target_dir_resolves_against_the_project_root() {
        let home = Path::new("/Users/nicky");
        let root = Path::new("/Users/nicky/dev/recipebridge");
        assert_eq!(
            expand_target_dir("build/target", home, root),
            PathBuf::from("/Users/nicky/dev/recipebridge/build/target")
        );
    }

    #[test]
    fn extracts_a_quoted_occurrence_too() {
        let text = r#"export CARGO_TARGET_DIR="/tmp/target" && cargo build"#;
        assert_eq!(
            extract_cargo_target_dir(text),
            vec!["/tmp/target".to_string()]
        );
    }
}
