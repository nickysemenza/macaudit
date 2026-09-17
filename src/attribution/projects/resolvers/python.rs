//! Python interpreter (uv/pyenv) from `.python-version`, and the shared `~/.cache/uv` among uv-managed projects.

use std::path::{Path, PathBuf};

use super::super::Project;
use crate::attribution::model::{Claim, EntryKind, EvidenceTier, ResolveEnv, BASELINE_OWNER};

/// Resolve this resource kind's claims for `project`. Stub until its lane
/// lands (see the module doc for which chunk).
pub fn resolve(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let owner = project.root.to_string_lossy().into_owned();
    let mut claims = Vec::new();

    if let Some(version) = python_version_pin(project, env) {
        claims.extend(python_version_claims(env, &owner, &version));
    }

    if project.root.join("uv.lock").exists() {
        let cache = env.paths.home.join(".cache/uv");
        if cache.exists() {
            claims.push(
                Claim::new(
                    cache,
                    &owner,
                    EntryKind::PackageCache,
                    EvidenceTier::EcosystemDefault,
                    "uv.lock present",
                )
                .label("uv cache"),
            );
        }
    }

    if project.root.join("poetry.lock").exists() {
        let cache = env.paths.home.join("Library/Caches/pypoetry");
        if cache.exists() {
            claims.push(
                Claim::new(
                    cache,
                    &owner,
                    EntryKind::PackageCache,
                    EvidenceTier::EcosystemDefault,
                    "poetry.lock present",
                )
                .label("Poetry cache"),
            );
        }
    }

    // A project with a manifest (`pyproject.toml`/`requirements.txt`) but
    // none of the above claims nothing at all — it can't be tagged into the
    // Python ecosystem without a claim to carry the tag.
    claims.into_iter().map(|c| c.ecosystem("python")).collect()
}

/// pip/virtualenv/pipx caches shared by every Python project regardless of
/// which interpreter or lockfile it uses.
pub fn baseline(env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut claims = Vec::new();
    for (rel, label) in [
        ("Library/Caches/pip", "pip cache"),
        (".cache/pip", "pip cache"),
        (
            "Library/Application Support/virtualenv",
            "virtualenv support",
        ),
        (".local/pipx", "pipx"),
    ] {
        let path = env.paths.home.join(rel);
        if path.exists() {
            claims.push(
                Claim::new(
                    path,
                    BASELINE_OWNER,
                    EntryKind::Cache,
                    EvidenceTier::EcosystemDefault,
                    "python ecosystem cache",
                )
                .label(label)
                .baseline("python"),
            );
        }
    }
    claims
}

/// `.python-version`'s first non-empty line, trimmed.
fn python_version_pin(project: &Project, env: &ResolveEnv<'_>) -> Option<String> {
    let text = env.read_head(&project.root.join(".python-version"), 256)?;
    let version = text.lines().find(|l| !l.trim().is_empty())?.trim();
    (!version.is_empty()).then(|| version.to_string())
}

/// The pinned version's installed interpreter, from either manager that
/// might have it: uv's own Python installs, or pyenv's.
fn python_version_claims(env: &ResolveEnv<'_>, owner: &str, version: &str) -> Vec<Claim> {
    let mut claims = Vec::new();

    let uv_python_dir = env.paths.home.join(".local/share/uv/python");
    if let Some(dir) = prefix_match_dir(&uv_python_dir, &format!("cpython-{version}")) {
        claims.push(
            Claim::new(
                dir,
                owner,
                EntryKind::Toolchain,
                EvidenceTier::Exact,
                ".python-version pin",
            )
            .label(format!("Python {version} (uv)")),
        );
    }

    let pyenv_dir = env.paths.home.join(".pyenv/versions");
    if let Some(dir) = prefix_match_dir(&pyenv_dir, version) {
        claims.push(
            Claim::new(
                dir,
                owner,
                EntryKind::Toolchain,
                EvidenceTier::Exact,
                ".python-version pin",
            )
            .label(format!("Python {version} (pyenv)")),
        );
    }

    claims
}

/// The alphabetically-last (for dotted version directories, also the
/// newest) entry under `dir` whose name starts with `prefix`.
fn prefix_match_dir(dir: &Path, prefix: &str) -> Option<PathBuf> {
    let read = std::fs::read_dir(dir).ok()?;
    let mut names: Vec<String> = read
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with(prefix))
        .collect();
    names.sort();
    names.pop().map(|n| dir.join(n))
}
