//! The handful of claim sources that join against another section's
//! findings snapshot rather than walking `~`: the working tree + Fs
//! `BuildArtifact` findings + redirected cargo target dirs, the three-phase
//! Docker compose join, and the live-process/port join over
//! `attribution::lsof`.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::attribution::lsof;
use crate::attribution::model::{
    Claim, EntryKind, EvidenceTier, Proc, ProcKind, ResolveEnv, UNATTRIBUTED_OWNER,
};
use crate::attribution::paths as attribution_paths;
use crate::attribution::projects::Project;
use crate::model::{FindingKind, ScannerId};

use super::apply::under_project;

/// The repo root/manifest dir itself, its linked worktrees, every Fs
/// `BuildArtifact` finding under the project (hard-link-subtracted
/// exclusive bytes), and any `CARGO_TARGET_DIR` this project redirects
/// elsewhere.
pub fn artifacts(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let owner = project.root.to_string_lossy().into_owned();
    let mut claims = Vec::with_capacity(1 + project.worktrees.len());

    claims.push(working_tree_claim(project, &owner));
    claims.extend(
        project
            .worktrees
            .iter()
            .map(|wt| worktree_claim(wt, &owner)),
    );
    claims.extend(fs_artifact_claims(project, env, &owner));

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

/// Every `BuildArtifact` finding from the Fs section whose path falls
/// inside this project's root or one of its worktrees.
fn fs_artifact_claims(project: &Project, env: &ResolveEnv<'_>, owner: &str) -> Vec<Claim> {
    let mut claims = Vec::new();
    for finding in env.findings(ScannerId::Fs) {
        if finding.kind != FindingKind::BuildArtifact {
            continue;
        }
        let Some(path) = &finding.path else { continue };
        if !under_project(path, project) {
            continue;
        }

        let marker = finding.meta_str("marker");
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
            let shared = finding.meta_u64("shared_hardlink_bytes").unwrap_or(0);
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

// ---------------------------------------------------------------------
// Docker
// ---------------------------------------------------------------------

/// Whether `root` itself (not a subdirectory) carries Compose or Dockerfile
/// evidence — gates the `.ecosystem("docker")` tag: a project whose
/// containers just happen to run from its directory (the `working_dir`
/// label points there, but there's no compose file in the repo) still gets
/// its containers/images claimed, just not charged for Docker Desktop's
/// shared overhead.
pub fn project_uses_docker(root: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        is_compose_file_name(&name) || name.starts_with("Dockerfile")
    })
}

/// Docker Compose's own discovery names: bare `compose.yml`/`compose.yaml`,
/// or any `docker-compose*.y*ml` variant (override files, per-environment
/// suffixes, ...), case-insensitively.
fn is_compose_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let Some(stem) = lower
        .strip_suffix(".yml")
        .or_else(|| lower.strip_suffix(".yaml"))
    else {
        return false;
    };
    stem == "compose" || stem.starts_with("docker-compose")
}

/// This project's Docker claims: containers whose Compose `working_dir`
/// label lands inside the project (root or a worktree), then the images and
/// volumes that go with them — bytes are Docker's own reported sizes, never
/// `lstat`ed (see `synthetic_path`).
pub fn docker(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let findings = env.findings(ScannerId::Docker);
    let owner = project.root.to_string_lossy().into_owned();
    let tag_ecosystem = project_uses_docker(&project.root);

    let mut claims = Vec::new();
    let mut compose_projects: BTreeSet<String> = BTreeSet::new();
    let mut claimed_container_ids: BTreeSet<String> = BTreeSet::new();

    for finding in findings {
        if finding.meta_str("object") != Some("container") {
            continue;
        }
        let Some(working_dir) = finding.meta_str("compose_working_dir") else {
            continue;
        };
        let working_dir = attribution_paths::tree_path(Path::new(working_dir));
        if !under_project(&working_dir, project) {
            continue;
        }
        let Some(id) = finding.meta_str("id") else {
            continue;
        };
        let name = finding.meta_str("name").unwrap_or(id);
        let bytes = finding.meta_u64("size_rw_bytes").unwrap_or(0);

        let mut claim = Claim::new(
            synthetic_path(env, "containers", id),
            owner.clone(),
            EntryKind::Docker,
            EvidenceTier::Exact,
            "compose working_dir label",
        )
        .label(format!("container {name}"))
        .raw_bytes_override(bytes)
        .virtual_bytes()
        .finding(finding.id);
        if tag_ecosystem {
            claim = claim.ecosystem("docker");
        }
        claims.push(claim);
        claimed_container_ids.insert(id.to_string());
        if let Some(cp) = finding.meta_str("compose_project") {
            compose_projects.insert(cp.to_string());
        }
    }

    if claimed_container_ids.is_empty() {
        return claims;
    }

    let mut claimed_image_ids: BTreeSet<String> = BTreeSet::new();
    for finding in findings {
        if finding.meta_str("object") != Some("image") {
            continue;
        }
        let Some(id) = finding.meta_str("id") else {
            continue;
        };
        let used_by_this_project = finding
            .meta
            .get("used_by")
            .and_then(|v| v.as_array())
            .is_some_and(|ids| {
                ids.iter()
                    .filter_map(|v| v.as_str())
                    .any(|cid| claimed_container_ids.contains(cid))
            });
        if !used_by_this_project || !claimed_image_ids.insert(id.to_string()) {
            continue;
        }
        let repo = finding.meta_str("repository").unwrap_or("");
        let tag = finding.meta_str("tag").unwrap_or("");
        let bytes = finding.meta_u64("size_bytes").unwrap_or(0);

        let mut claim = Claim::new(
            synthetic_path(env, "images", id),
            owner.clone(),
            EntryKind::Docker,
            EvidenceTier::Exact,
            "compose working_dir label",
        )
        .label(format!("image {repo}:{tag}"))
        .raw_bytes_override(bytes)
        .virtual_bytes()
        .finding(finding.id);
        if tag_ecosystem {
            claim = claim.ecosystem("docker");
        }
        claims.push(claim);
    }

    for finding in findings {
        if finding.meta_str("object") != Some("volume") {
            continue;
        }
        let Some(cp) = finding.meta_str("compose_project") else {
            continue;
        };
        if !compose_projects.contains(cp) {
            continue;
        }
        let Some(name) = finding.meta_str("name") else {
            continue;
        };
        let bytes = finding.meta_u64("size_bytes").unwrap_or(0);

        let mut claim = Claim::new(
            synthetic_path(env, "volumes", name),
            owner.clone(),
            EntryKind::Docker,
            EvidenceTier::Exact,
            "compose project label",
        )
        .label(format!("volume {name}"))
        .raw_bytes_override(bytes)
        .virtual_bytes()
        .finding(finding.id);
        if tag_ecosystem {
            claim = claim.ecosystem("docker");
        }
        claims.push(claim);
    }

    claims
}

/// Docker objects with no Compose linkage at all — claimed once for the
/// whole scan, not once per project.
///
/// Caveat (unchanged from before the consolidation): an object *can* carry
/// a `compose_working_dir`/`compose_project` label pointing somewhere
/// macaudit never discovered a `Project` (a deleted checkout, a directory
/// outside every configured root); it then has a link, so it isn't claimed
/// here, but no project's root matches it either — it silently has no claim
/// at all. Accepted gap, not a bug to chase.
pub fn docker_unlinked(env: &ResolveEnv<'_>) -> Vec<Claim> {
    let findings = env.findings(ScannerId::Docker);
    let mut claims = Vec::new();

    for finding in findings {
        if finding.meta_str("object") != Some("container") {
            continue;
        }
        if finding.meta_str("compose_working_dir").is_some() {
            continue;
        }
        let Some(id) = finding.meta_str("id") else {
            continue;
        };
        let name = finding.meta_str("name").unwrap_or(id);
        let bytes = finding.meta_u64("size_rw_bytes").unwrap_or(0);
        claims.push(
            Claim::new(
                synthetic_path(env, "containers", id),
                UNATTRIBUTED_OWNER,
                EntryKind::Docker,
                EvidenceTier::Observed,
                "no compose project links it",
            )
            .label(format!("container {name}"))
            .raw_bytes_override(bytes)
            .virtual_bytes()
            .finding(finding.id),
        );
    }

    for finding in findings {
        if finding.meta_str("object") != Some("image") {
            continue;
        }
        if finding.meta_str("compose_project").is_some() {
            continue;
        }
        let Some(id) = finding.meta_str("id") else {
            continue;
        };
        let repo = finding.meta_str("repository").unwrap_or("");
        let tag = finding.meta_str("tag").unwrap_or("");
        let bytes = finding.meta_u64("size_bytes").unwrap_or(0);
        claims.push(
            Claim::new(
                synthetic_path(env, "images", id),
                UNATTRIBUTED_OWNER,
                EntryKind::Docker,
                EvidenceTier::Observed,
                "no compose project links it",
            )
            .label(format!("image {repo}:{tag}"))
            .raw_bytes_override(bytes)
            .virtual_bytes()
            .finding(finding.id),
        );
    }

    for finding in findings {
        if finding.meta_str("object") != Some("volume") {
            continue;
        }
        if finding.meta_str("compose_project").is_some() {
            continue;
        }
        let Some(name) = finding.meta_str("name") else {
            continue;
        };
        let bytes = finding.meta_u64("size_bytes").unwrap_or(0);
        claims.push(
            Claim::new(
                synthetic_path(env, "volumes", name),
                UNATTRIBUTED_OWNER,
                EntryKind::Docker,
                EvidenceTier::Observed,
                "no compose project links it",
            )
            .label(format!("volume {name}"))
            .raw_bytes_override(bytes)
            .virtual_bytes()
            .finding(finding.id),
        );
    }

    claims
}

/// `~/Library/Containers/com.docker.docker` — Docker Desktop's real,
/// `lstat`-sized container directory on the host, holding the VM's backing
/// disk image among other things.
fn docker_desktop_root(env: &ResolveEnv<'_>) -> PathBuf {
    env.paths.home.join("Library/Containers/com.docker.docker")
}

/// A per-object identifier path for a container/image/volume claim. Docker
/// objects live inside the Docker Desktop Linux VM, not on the host
/// filesystem, so there is nothing to `lstat` for them individually — every
/// claim built from this instead carries a `raw_bytes_override` (Docker's
/// own reported size) and `.virtual_bytes()`. Nesting it under
/// `docker_desktop_root`'s real VM-disk baseline claim is deliberate: the
/// VM disk's own (real, `lstat`ed) bytes end up as whatever isn't already
/// accounted for by a specific claimed object, the same nesting rule every
/// other claim follows (`accounting.rs`'s module doc).
fn synthetic_path(env: &ResolveEnv<'_>, kind: &str, id: &str) -> PathBuf {
    docker_desktop_root(env)
        .join("Data/vms/0/data/docker")
        .join(kind)
        .join(id)
}

// ---------------------------------------------------------------------
// Live processes / ports
// ---------------------------------------------------------------------

const SHELLS: &[&str] = &["zsh", "bash", "fish", "sh", "nu"];

fn classify(command: &str, pid: u32, listening: &HashMap<u32, Vec<u16>>) -> ProcKind {
    if SHELLS.contains(&command) {
        ProcKind::Shell
    } else if listening.get(&pid).is_some_and(|ports| !ports.is_empty()) {
        ProcKind::Server
    } else {
        ProcKind::Other
    }
}

fn listening_ports_by_pid(env: &ResolveEnv<'_>) -> HashMap<u32, Vec<u16>> {
    let mut map: HashMap<u32, Vec<u16>> = HashMap::new();
    for finding in env.findings(ScannerId::Ports) {
        let Some(pid) = finding.meta_u64("pid") else {
            continue;
        };
        let Some(port) = finding.meta_u64("port") else {
            continue;
        };
        map.entry(pid as u32).or_default().push(port as u16);
    }
    map
}

/// The processes whose cwd is inside `project` (or one of its worktrees),
/// one per pid, plus every port from the Ports snapshot owned by one of
/// those pids.
pub fn processes_for(project: &Project, env: &ResolveEnv<'_>) -> (Vec<Proc>, Vec<u16>) {
    let files = lsof::snapshot(env);
    let cwds = lsof::cwd_by_pid(&files);
    let commands: HashMap<u32, &str> = files.iter().map(|f| (f.pid, f.command.as_str())).collect();
    let listening = listening_ports_by_pid(env);

    let mut procs = Vec::new();
    let mut ports: Vec<u16> = Vec::new();

    for (&pid, cwd) in &cwds {
        let tree_cwd = attribution_paths::tree_path(cwd);
        if !under_project(&tree_cwd, project) {
            continue;
        }
        let command = commands.get(&pid).copied().unwrap_or_default();
        let kind = classify(command, pid, &listening);
        procs.push(Proc {
            pid,
            name: command.to_string(),
            kind,
            cwd: cwd.clone(),
        });
        if let Some(pid_ports) = listening.get(&pid) {
            ports.extend(pid_ports.iter().copied());
        }
    }
    procs.sort_by_key(|p| p.pid);
    ports.sort_unstable();
    ports.dedup();
    (procs, ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::testutil::EnvFixture;

    #[test]
    fn compose_file_name_matches_bare_and_docker_prefixed_forms() {
        assert!(is_compose_file_name("compose.yml"));
        assert!(is_compose_file_name("compose.yaml"));
        assert!(is_compose_file_name("docker-compose.yml"));
        assert!(is_compose_file_name("docker-compose.prod.yaml"));
        assert!(is_compose_file_name("DOCKER-COMPOSE.YML"));
        assert!(!is_compose_file_name("compose.prod.yaml"));
        assert!(!is_compose_file_name("recompose.yml"));
        assert!(!is_compose_file_name("compose.txt"));
    }

    #[test]
    fn classify_recognises_known_shells() {
        let listening = HashMap::new();
        assert_eq!(classify("zsh", 1, &listening), ProcKind::Shell);
        assert_eq!(classify("bash", 1, &listening), ProcKind::Shell);
    }

    #[test]
    fn classify_flags_a_port_owning_pid_as_server() {
        let mut listening = HashMap::new();
        listening.insert(42, vec![3000]);
        assert_eq!(classify("node", 42, &listening), ProcKind::Server);
        assert_eq!(classify("node", 43, &listening), ProcKind::Other);
    }

    fn project() -> Project {
        Project {
            root: PathBuf::from("/Users/dev/cubby"),
            name: "cubby".into(),
            worktrees: Vec::new(),
            names: Vec::new(),
            bundle_ids: Vec::new(),
            is_git: true,
        }
    }

    #[test]
    fn artifacts_claims_the_working_tree_and_worktrees() {
        let fixture = EnvFixture::new();
        let env = fixture.env();
        let claims = artifacts(&project(), &env);
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].kind, EntryKind::WorkingTree);
    }
}
