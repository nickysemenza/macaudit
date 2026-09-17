//! Docker containers/images/volumes whose compose project working dir is inside the project (`com.docker.compose.project.working_dir`), via the Docker inventory built in `src/scan/docker.rs`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::attribution::model::{
    Claim, EntryKind, EvidenceTier, ResolveEnv, BASELINE_OWNER, UNATTRIBUTED_OWNER,
};
use crate::attribution::paths;
use crate::model::ScannerId;

use super::super::Project;

/// Resolve this project's Docker claims: containers whose Compose
/// `working_dir` label lands inside `project.root` (or equals it), then the
/// image and volumes that go with them — bytes are Docker's own reported
/// sizes, never `lstat`ed (see `synthetic_path`).
pub fn resolve(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let findings = env.findings(ScannerId::Docker);
    let owner = project.root.to_string_lossy().into_owned();
    // Only a project that itself carries compose/Dockerfile evidence shares
    // the Docker Desktop VM disk baseline — a project whose containers just
    // happen to run from its directory (working_dir label points there, but
    // there's no compose file in the repo) still gets its containers/images
    // claimed, just not charged for Docker Desktop's overhead.
    let tag_ecosystem = project_has_docker_files(&project.root);

    let mut claims = Vec::new();
    let mut compose_projects: BTreeSet<String> = BTreeSet::new();
    let mut claimed_container_ids: BTreeSet<String> = BTreeSet::new();

    for finding in findings {
        if meta_str(&finding.meta, "object") != Some("container") {
            continue;
        }
        let Some(working_dir) = meta_str(&finding.meta, "compose_working_dir") else {
            continue;
        };
        let working_dir = paths::tree_path(Path::new(working_dir));
        if working_dir != project.root && !working_dir.starts_with(&project.root) {
            continue;
        }
        let Some(id) = meta_str(&finding.meta, "id") else {
            continue;
        };
        let name = meta_str(&finding.meta, "name").unwrap_or(id);
        let bytes = meta_u64(&finding.meta, "size_rw_bytes").unwrap_or(0);

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
        if let Some(cp) = meta_str(&finding.meta, "compose_project") {
            compose_projects.insert(cp.to_string());
        }
    }

    if claimed_container_ids.is_empty() {
        // Nothing of this project's ran under Docker — no image/volume can
        // be linked either.
        return claims;
    }

    // Images used by any container just claimed above — `used_by` was
    // computed once, in the scanner, from every container's `Image` field.
    let mut claimed_image_ids: BTreeSet<String> = BTreeSet::new();
    for finding in findings {
        if meta_str(&finding.meta, "object") != Some("image") {
            continue;
        }
        let Some(id) = meta_str(&finding.meta, "id") else {
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
        let repo = meta_str(&finding.meta, "repository").unwrap_or("");
        let tag = meta_str(&finding.meta, "tag").unwrap_or("");
        let bytes = meta_u64(&finding.meta, "size_bytes").unwrap_or(0);

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

    // Volumes sharing any Compose project name this project's containers
    // carried.
    for finding in findings {
        if meta_str(&finding.meta, "object") != Some("volume") {
            continue;
        }
        let Some(cp) = meta_str(&finding.meta, "compose_project") else {
            continue;
        };
        if !compose_projects.contains(cp) {
            continue;
        }
        let Some(name) = meta_str(&finding.meta, "name") else {
            continue;
        };
        let bytes = meta_u64(&finding.meta, "size_bytes").unwrap_or(0);

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

/// Docker objects with no Compose linkage at all (claimed once here, not
/// once per project — see `model.rs`'s `BASELINE_OWNER` doc), plus the
/// Docker Desktop VM disk itself.
///
/// Caveat: an object *does* carry a `compose_working_dir`/`compose_project`
/// label pointing somewhere macaudit never discovered a `Project` (a
/// deleted checkout, a directory outside every configured root) neither
/// gets claimed here (it has a link) nor by any `resolve()` call (no
/// project's root matches) — it silently has no claim at all. `baseline`
/// has no `ProjectIndex` to check against (see the module wiring in
/// `resolvers/mod.rs::all_baseline`), so this is a known, accepted gap
/// rather than a bug to chase.
pub fn baseline(env: &ResolveEnv<'_>) -> Vec<Claim> {
    let findings = env.findings(ScannerId::Docker);
    let mut claims = Vec::new();

    for finding in findings {
        if meta_str(&finding.meta, "object") != Some("container") {
            continue;
        }
        if meta_str(&finding.meta, "compose_working_dir").is_some() {
            continue;
        }
        let Some(id) = meta_str(&finding.meta, "id") else {
            continue;
        };
        let name = meta_str(&finding.meta, "name").unwrap_or(id);
        let bytes = meta_u64(&finding.meta, "size_rw_bytes").unwrap_or(0);
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
        if meta_str(&finding.meta, "object") != Some("image") {
            continue;
        }
        if meta_str(&finding.meta, "compose_project").is_some() {
            continue;
        }
        let Some(id) = meta_str(&finding.meta, "id") else {
            continue;
        };
        let repo = meta_str(&finding.meta, "repository").unwrap_or("");
        let tag = meta_str(&finding.meta, "tag").unwrap_or("");
        let bytes = meta_u64(&finding.meta, "size_bytes").unwrap_or(0);
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
        if meta_str(&finding.meta, "object") != Some("volume") {
            continue;
        }
        if meta_str(&finding.meta, "compose_project").is_some() {
            continue;
        }
        let Some(name) = meta_str(&finding.meta, "name") else {
            continue;
        };
        let bytes = meta_u64(&finding.meta, "size_bytes").unwrap_or(0);
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

    let vm_disk = docker_desktop_root(env);
    if vm_disk.exists() {
        claims.push(
            Claim::new(
                vm_disk,
                BASELINE_OWNER,
                EntryKind::Docker,
                EvidenceTier::EcosystemDefault,
                "Docker Desktop VM disk",
            )
            .label("Docker Desktop VM disk (allocated)")
            .baseline("docker"),
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
/// other claim follows (`accounting.rs`'s module doc). Everything from
/// `Data/vms/0/data/docker/` down is an identifier, never resolved on disk.
fn synthetic_path(env: &ResolveEnv<'_>, kind: &str, id: &str) -> PathBuf {
    docker_desktop_root(env)
        .join("Data/vms/0/data/docker")
        .join(kind)
        .join(id)
}

fn meta_str<'a>(meta: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    meta.get(key).and_then(|v| v.as_str())
}

fn meta_u64(meta: &serde_json::Value, key: &str) -> Option<u64> {
    meta.get(key).and_then(|v| v.as_u64())
}

/// Whether `root` itself (not a subdirectory) carries Compose or Dockerfile
/// evidence — see `resolve`'s `tag_ecosystem` doc for why this gates the
/// `.ecosystem("docker")` tag rather than the container/image/volume claims
/// themselves.
fn project_has_docker_files(root: &Path) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_file_name_matches_bare_and_docker_prefixed_forms() {
        assert!(is_compose_file_name("compose.yml"));
        assert!(is_compose_file_name("compose.yaml"));
        assert!(is_compose_file_name("docker-compose.yml"));
        assert!(is_compose_file_name("docker-compose.prod.yaml"));
        assert!(is_compose_file_name("DOCKER-COMPOSE.YML"));
        // `compose.<extra>.yaml` is not one of Compose's own discovery
        // names (only `docker-compose*` gets the extra-suffix leniency).
        assert!(!is_compose_file_name("compose.prod.yaml"));
        assert!(!is_compose_file_name("recompose.yml"));
        assert!(!is_compose_file_name("compose.txt"));
    }
}
