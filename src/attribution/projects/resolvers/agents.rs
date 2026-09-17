//! Claude/Codex agent session state, joined to a project via the session
//! file's `cwd` (read from the first 64 KiB, not necessarily line 1). A
//! session whose directory name matches the project's Claude-encoded path
//! but carries no readable `cwd` falls back to a name match; everything
//! else in `~/.claude`/`~/.codex` that isn't a per-project session is
//! ecosystem baggage claimed once by `baseline()`.

use std::path::Path;

use super::super::Project;
use crate::attribution::model::{
    Claim, EntryKind, EvidenceTier, ResolveEnv, BASELINE_OWNER, UNATTRIBUTED_OWNER,
};
use crate::attribution::paths as attribution_paths;

/// `env.read_head`'s cap for a Claude Code session `.jsonl` — `cwd` is
/// written near the top, but the very first line can be a long system
/// prompt, so this needs real headroom.
const CLAUDE_HEAD_BYTES: usize = 64 * 1024;
/// Same, for a Codex `rollout-*.jsonl`.
const CODEX_HEAD_BYTES: usize = 16 * 1024;
/// Session `.jsonl` files inspected per Claude Code project directory before
/// giving up on finding a `cwd`.
const MAX_JSONL_PER_DIR: usize = 5;
/// Codex session files walked in total before giving up (bounds a pathological
/// `~/.codex/sessions` tree).
const MAX_CODEX_FILES: usize = 5000;

pub fn resolve(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let owner = project.root.to_string_lossy().into_owned();
    let mut claims = claude_claims(project, &owner, env);
    claims.extend(codex_claims(project, &owner, env));
    claims
}

fn claude_claims(project: &Project, owner: &str, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut claims = Vec::new();
    let projects_dir = env.paths.home.join(".claude/projects");
    let encoded_root = encode_claude_project_dir(&project.root);

    if let Ok(entries) = std::fs::read_dir(&projects_dir) {
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let session_dir = entry.path();
            let dir_name = entry.file_name().to_string_lossy().into_owned();

            let cwd = first_cwd_in_session_dir(&session_dir, env);
            let cwd_inside_project = cwd
                .as_deref()
                .map(|c| under_project(&attribution_paths::tree_path(Path::new(c)), project))
                .unwrap_or(false);

            if cwd_inside_project {
                claims.push(
                    Claim::new(
                        session_dir,
                        owner.to_string(),
                        EntryKind::AgentState,
                        EvidenceTier::Exact,
                        "Claude Code session cwd",
                    )
                    .label("Claude Code sessions"),
                );
            } else if cwd.is_none()
                && (dir_name == encoded_root || dir_name.starts_with(&format!("{encoded_root}-")))
            {
                claims.push(
                    Claim::new(
                        session_dir,
                        owner.to_string(),
                        EntryKind::AgentState,
                        EvidenceTier::NameMatch,
                        "encoded project path",
                    )
                    .label("Claude Code sessions"),
                );
            }
        }
    }

    let cli_cache_dir = env
        .paths
        .home
        .join("Library/Caches/claude-cli-nodejs")
        .join(&encoded_root);
    if cli_cache_dir.exists() {
        claims.push(
            Claim::new(
                cli_cache_dir,
                owner.to_string(),
                EntryKind::AgentState,
                EvidenceTier::Exact,
                "Claude Code CLI cache",
            )
            .label("Claude Code CLI cache"),
        );
    }

    claims
}

fn codex_claims(project: &Project, owner: &str, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut claims = Vec::new();
    let codex_dir = env.paths.home.join(".codex");
    let mut visited = 0usize;

    walk_codex_files(
        &codex_dir.join("sessions"),
        &mut visited,
        &|name| name.starts_with("rollout-") && name.ends_with(".jsonl"),
        &mut |path| {
            if let Some(claim) = codex_session_claim(path, project, owner, env) {
                claims.push(claim);
            }
        },
    );
    walk_codex_files(
        &codex_dir.join("archived_sessions"),
        &mut visited,
        &|_name| true,
        &mut |path| {
            if let Some(claim) = codex_session_claim(path, project, owner, env) {
                claims.push(claim);
            }
        },
    );

    claims
}

fn codex_session_claim(
    path: &Path,
    project: &Project,
    owner: &str,
    env: &ResolveEnv<'_>,
) -> Option<Claim> {
    let text = env.read_head(path, CODEX_HEAD_BYTES)?;
    let cwd = extract_cwd(&text)?;
    if !under_project(&attribution_paths::tree_path(Path::new(&cwd)), project) {
        return None;
    }
    Some(
        Claim::new(
            path.to_path_buf(),
            owner.to_string(),
            EntryKind::AgentState,
            EvidenceTier::Exact,
            "Codex session cwd",
        )
        .label(codex_session_label(path)),
    )
}

/// Claimed once per scan: everything in `~/.claude`/`~/.codex` that isn't
/// per-project session state, plus per-project `~/.claude/projects/<dir>`
/// entries whose session `cwd` no longer exists on disk (their owning
/// project vanished, so the session state is orphaned rather than baseline).
pub fn baseline(env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut claims = Vec::new();
    let claude_dir = env.paths.home.join(".claude");

    if let Ok(entries) = std::fs::read_dir(&claude_dir) {
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "projects" {
                continue;
            }
            claims.push(
                Claim::new(
                    entry.path(),
                    BASELINE_OWNER,
                    EntryKind::AgentState,
                    EvidenceTier::EcosystemDefault,
                    "Claude Code state",
                )
                .label(format!("Claude Code {name}"))
                .baseline("agents"),
            );
        }
    }

    let codex_dir = env.paths.home.join(".codex");
    if let Ok(entries) = std::fs::read_dir(&codex_dir) {
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.contains(".sqlite") || name.starts_with("logs") {
                claims.push(
                    Claim::new(
                        entry.path(),
                        BASELINE_OWNER,
                        EntryKind::AgentState,
                        EvidenceTier::EcosystemDefault,
                        "Codex state",
                    )
                    .label(name)
                    .baseline("agents"),
                );
            }
        }
    }

    let projects_dir = claude_dir.join("projects");
    if let Ok(entries) = std::fs::read_dir(&projects_dir) {
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let session_dir = entry.path();
            let Some(cwd) = first_cwd_in_session_dir(&session_dir, env) else {
                continue;
            };
            let cwd_path = attribution_paths::tree_path(Path::new(&cwd));
            if !cwd_path.exists() {
                claims.push(Claim::new(
                    session_dir,
                    UNATTRIBUTED_OWNER,
                    EntryKind::AgentState,
                    EvidenceTier::Observed,
                    format!("session cwd no longer exists: {cwd}"),
                ));
            }
        }
    }

    claims
}

/// The first `"cwd":"…"` found across up to `MAX_JSONL_PER_DIR` `.jsonl`
/// files in a Claude Code session directory.
fn first_cwd_in_session_dir(session_dir: &Path, env: &ResolveEnv<'_>) -> Option<String> {
    let entries = std::fs::read_dir(session_dir).ok()?;
    let mut checked = 0usize;
    for entry in entries.flatten() {
        if checked >= MAX_JSONL_PER_DIR {
            break;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        checked += 1;
        let Some(text) = env.read_head(&path, CLAUDE_HEAD_BYTES) else {
            continue;
        };
        if let Some(cwd) = extract_cwd(&text) {
            return Some(cwd);
        }
    }
    None
}

/// Bounded recursive walk over `dir`, calling `visit` for every file whose
/// name passes `filter`. `visited` is shared across the whole agents.rs
/// resolve pass so `sessions` + `archived_sessions` together stay under
/// `MAX_CODEX_FILES`.
fn walk_codex_files(
    dir: &Path,
    visited: &mut usize,
    filter: &dyn Fn(&str) -> bool,
    visit: &mut dyn FnMut(&Path),
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *visited >= MAX_CODEX_FILES {
            return;
        }
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            walk_codex_files(&path, visited, filter, visit);
        } else if file_type.is_file() {
            *visited += 1;
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if filter(name) {
                visit(&path);
            }
        }
    }
}

fn codex_session_label(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("session");
    let stem = stem.strip_prefix("rollout-").unwrap_or(stem);
    let date = stem.get(0..10).unwrap_or(stem);
    format!("Codex session {date}")
}

/// The Claude Code convention for a project's session directory name: every
/// `/` and `.` in the absolute path becomes `-`.
fn encode_claude_project_dir(path: &Path) -> String {
    path.to_string_lossy()
        .chars()
        .map(|c| if c == '/' || c == '.' { '-' } else { c })
        .collect()
}

/// The first `"cwd":"…"` value anywhere in `text`, with minimal JSON
/// unescaping (`\/` and `\\`) — not a full JSON parser, since a session
/// head is read as raw bytes precisely to avoid parsing the whole record.
fn extract_cwd(text: &str) -> Option<String> {
    let idx = text.find("\"cwd\":\"")?;
    let rest = &text[idx + 7..];
    let end = find_unescaped_quote(rest)?;
    Some(unescape_json_minimal(&rest[..end]))
}

fn find_unescaped_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

fn unescape_json_minimal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek().copied() {
                Some('/') => {
                    out.push('/');
                    chars.next();
                }
                Some('\\') => {
                    out.push('\\');
                    chars.next();
                }
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                    chars.next();
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn under_project(path: &Path, project: &Project) -> bool {
    path.starts_with(&project.root) || project.worktrees.iter().any(|wt| path.starts_with(wt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cwd_finds_the_field_anywhere_in_the_head() {
        let text = r#"{"type":"user","cwd":"/Users/nicky/dev/cubby","other":1}"#;
        assert_eq!(
            extract_cwd(text),
            Some("/Users/nicky/dev/cubby".to_string())
        );
    }

    #[test]
    fn extract_cwd_unescapes_forward_slashes() {
        let text = r#"{"cwd":"\/Users\/nicky\/dev\/cubby"}"#;
        assert_eq!(
            extract_cwd(text),
            Some("/Users/nicky/dev/cubby".to_string())
        );
    }

    #[test]
    fn extract_cwd_is_none_when_absent() {
        assert_eq!(extract_cwd(r#"{"type":"user"}"#), None);
    }

    #[test]
    fn extract_cwd_is_none_on_an_unterminated_string() {
        assert_eq!(extract_cwd(r#"{"cwd":"/Users/nicky"#), None);
    }

    #[test]
    fn encode_claude_project_dir_maps_slashes_and_dots() {
        assert_eq!(
            encode_claude_project_dir(Path::new("/Users/nicky/dev/cubby")),
            "-Users-nicky-dev-cubby"
        );
        assert_eq!(
            encode_claude_project_dir(Path::new("/Users/nicky/dev/my.app")),
            "-Users-nicky-dev-my-app"
        );
    }

    #[test]
    fn codex_session_label_extracts_the_date_prefix() {
        assert_eq!(
            codex_session_label(Path::new("/x/rollout-2024-05-01T12-34-56-abc123.jsonl")),
            "Codex session 2024-05-01"
        );
    }
}
