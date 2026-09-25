//! DockerScanner (spec §3.7) — `docker system df --format json` → dangling
//! images, stopped containers, unused volumes, build cache, plus a
//! per-object inventory (every container/image/volume, not just the
//! aggregates) that `src/attribution/projects/resolvers/docker.rs` joins to
//! a project via Compose labels. If the CLI is missing or the daemon is
//! unreachable, emit a single Info finding and return Ok — never fail the
//! whole scan over an optional tool.

use async_trait::async_trait;

use std::collections::HashMap;

use serde::Deserialize;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::{ScanCtx, Scanner};

/// Docker Compose stamps every object it creates with these two labels (plus
/// `com.docker.compose.service`, `.container-number`, ... we don't need).
/// The Projects resolver joins a container to a project via
/// `COMPOSE_WORKING_DIR_LABEL`, then pulls in its image/volumes via
/// `COMPOSE_PROJECT_LABEL`.
const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";
const COMPOSE_WORKING_DIR_LABEL: &str = "com.docker.compose.project.working_dir";

#[derive(Default)]
pub struct DockerScanner;

#[async_trait]
impl Scanner for DockerScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Docker
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        // NOTE: `--format json` is ignored when `-v`/`--verbose` is passed (docker
        // prints the human-readable verbose tables instead), so we must NOT pass
        // `-v`. The plain `docker system df --format json` emits the NDJSON summary
        // (Type/TotalCount/Active/Size/Reclaimable) this parser expects. This also
        // means a per-volume size (which only `-v` reports) isn't available —
        // `emit_volumes` below leaves `size_bytes` absent rather than parse the
        // verbose text tables.
        let out = match ctx
            .runner
            .run("docker", &["system", "df", "--format", "json"], &ctx.token)
            .await
        {
            Ok(o) if o.success() => o,
            Ok(o) => {
                emit_unreachable(&ctx, o.stderr_str().trim()).await;
                return Ok(());
            }
            Err(e) => {
                emit_unreachable(&ctx, &e.to_string()).await;
                return Ok(());
            }
        };

        for line in out.stdout_str().lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(row) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(ty) = row.get("Type").and_then(|v| v.as_str()) else {
                continue;
            };
            let total_count = value_to_u64(row.get("TotalCount"));
            let active = value_to_u64(row.get("Active"));
            let size_str = row.get("Size").and_then(|v| v.as_str()).unwrap_or("");
            let reclaimable_str = row
                .get("Reclaimable")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let size_bytes = parse_human_size(size_str);
            let reclaimable_bytes = parse_human_size(reclaimable_str);

            let remedy = match ty {
                "Images" => Some(("Remove unused images", vec!["image", "prune", "-f"])),
                "Containers" => Some((
                    "Remove stopped containers",
                    vec!["container", "prune", "-f"],
                )),
                "Local Volumes" => Some(("Remove unused volumes", vec!["volume", "prune", "-f"])),
                "Build Cache" => Some(("Prune build cache", vec!["builder", "prune", "-f"])),
                _ => None,
            };

            let reclaimable_nonzero = reclaimable_bytes.unwrap_or(0) > 0;
            let severity = if reclaimable_nonzero {
                Severity::Reclaimable
            } else {
                Severity::Info
            };

            let key = format!("type:{ty}");
            let mut finding = Finding::new(
                FindingKind::DockerObject,
                &key,
                format!("Docker {ty} — {size_str}"),
            )
            .detail(format!(
                "{total_count} total, {active} active, {size_str} used, {reclaimable_str} reclaimable"
            ))
            .severity(severity)
            .meta(serde_json::json!({
                "object": "summary",
                "type": ty,
                "total_count": total_count,
                "active": active,
                "size": size_str,
                "reclaimable": reclaimable_str,
            }));

            // Show what a prune would actually RECLAIM as the finding's size —
            // total usage includes active images/containers that no remedy
            // touches, and the sidebar sums size_bytes of Reclaimable findings.
            // Total stays visible in the detail/meta.
            if let Some(bytes) = reclaimable_bytes.or(size_bytes) {
                finding = finding.size(bytes);
            }
            if let Some(total) = size_bytes {
                finding.meta["total_size_bytes"] = serde_json::json!(total);
            }

            if reclaimable_nonzero {
                if let Some((label, args)) = remedy {
                    finding = finding.remedy(Remedy {
                        label: label.to_string(),
                        command: RemedyCommand::Shell {
                            program: "docker".to_string(),
                            args: args.into_iter().map(str::to_string).collect(),
                        },
                        reclaims_bytes: reclaimable_bytes,
                        destructive: true,
                        alternative: false,
                        guard: None,
                    });
                }
            }

            ctx.emit(finding).await;
        }

        // Per-object inventory: every container (running or not), every
        // image, every volume — not just the aggregates above. The Projects
        // resolver joins these to a project via Compose's
        // `com.docker.compose.project[.working_dir]` labels.
        let containers = fetch_containers(&ctx).await;
        emit_containers(&ctx, &containers).await;
        emit_images(&ctx, &containers).await;
        emit_volumes(&ctx).await;

        Ok(())
    }
}

async fn emit_unreachable(ctx: &ScanCtx, detail: &str) {
    ctx.emit(
        Finding::new(
            FindingKind::DockerObject,
            "docker:unreachable",
            "Docker daemon not reachable",
        )
        .detail(if detail.is_empty() {
            "docker CLI missing or daemon not running".to_string()
        } else {
            detail.to_string()
        })
        .severity(Severity::Info),
    )
    .await;
}

/// Docker's `TotalCount`/`Active` fields may be emitted as a JSON number or a
/// numeric string depending on CLI version; accept either.
fn value_to_u64(v: Option<&serde_json::Value>) -> u64 {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(serde_json::Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

/// Parse a docker `go-units`-style human size like "1.113GB" or
/// "800MB (66%)" into bytes. Decimal (1000-based) units, matching docker's
/// own formatting. Returns `None` if the string can't be parsed.
fn parse_human_size(s: &str) -> Option<u64> {
    let s = s.split('(').next().unwrap_or(s).trim();
    if s.is_empty() {
        return None;
    }
    let split_at = s.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
    let (num_part, unit_part) = s.split_at(split_at);
    let num: f64 = num_part.parse().ok()?;
    let unit = unit_part.trim();
    let normalized = unit.to_ascii_lowercase().replace("ib", "b");
    let mult: f64 = match normalized.as_str() {
        "b" => 1.0,
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        _ => return None,
    };
    Some((num * mult) as u64)
}

/// Parse a container's `Size` column: `"<rw> (virtual <total>)"`, or just
/// `"<rw>"` when Docker omits the virtual part (older CLI versions). The RW
/// size is the container's own writable layer; the virtual size is what the
/// full image + layer stack would take if nothing were shared.
fn parse_container_size(s: &str) -> (Option<u64>, Option<u64>) {
    let s = s.trim();
    match s.split_once('(') {
        Some((rw, rest)) => {
            let virt = rest
                .trim_end_matches(')')
                .trim()
                .strip_prefix("virtual")
                .unwrap_or(rest)
                .trim();
            (parse_human_size(rw.trim()), parse_human_size(virt))
        }
        None => (parse_human_size(s), None),
    }
}

/// Parse Docker's `k=v,k=v` label string — the flat comma-joined form
/// `--format`'s `.Labels` template value always prints, never nested JSON.
fn parse_labels(s: &str) -> HashMap<String, String> {
    s.split(',')
        .filter_map(|pair| {
            let pair = pair.trim();
            if pair.is_empty() {
                return None;
            }
            let (k, v) = pair.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// Compose's two project-identifying labels, pulled out of a parsed label
/// map — the same `(meta key, value)` pairs `emit_containers`, `emit_images`,
/// and `emit_volumes` each write into their finding's `meta` when present.
/// Volumes never carry `working_dir`, so that half is simply always `None`
/// there, same as it always was.
fn compose_meta(labels: &HashMap<String, String>) -> [(&'static str, Option<&str>); 2] {
    [
        (
            "compose_project",
            labels.get(COMPOSE_PROJECT_LABEL).map(String::as_str),
        ),
        (
            "compose_working_dir",
            labels.get(COMPOSE_WORKING_DIR_LABEL).map(String::as_str),
        ),
    ]
}

/// Deserialize one NDJSON line per row (the shape every `docker ... --format
/// '{{json .}}'` subcommand emits); a line that fails to parse is dropped
/// rather than aborting the whole inventory.
fn parse_ndjson<T: serde::de::DeserializeOwned>(input: &str) -> Vec<T> {
    input
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            serde_json::from_str(line).ok()
        })
        .collect()
}

/// One row of `docker ps -a -s --format '{{json .}}'`.
#[derive(Debug, Clone, Deserialize)]
struct PsRow {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Names")]
    names: String,
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "Labels")]
    labels: String,
    #[serde(rename = "Size")]
    size: String,
    #[serde(rename = "State")]
    state: String,
    #[serde(rename = "CreatedAt")]
    created_at: String,
}

/// One row of `docker image ls --format '{{json .}}'`.
#[derive(Debug, Deserialize)]
struct ImageRow {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Repository")]
    repository: String,
    #[serde(rename = "Tag")]
    tag: String,
    #[serde(rename = "Size")]
    size: String,
    #[serde(rename = "CreatedAt")]
    created_at: String,
}

/// One row of `docker volume ls --format '{{json .}}'`.
#[derive(Debug, Deserialize)]
struct VolumeRow {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Labels")]
    labels: String,
    #[serde(rename = "Driver")]
    driver: String,
    #[serde(rename = "Mountpoint")]
    mountpoint: String,
}

async fn fetch_containers(ctx: &ScanCtx) -> Vec<PsRow> {
    match ctx
        .runner
        .run(
            "docker",
            &["ps", "-a", "-s", "--format", "{{json .}}"],
            &ctx.token,
        )
        .await
    {
        Ok(o) if o.success() => parse_ndjson(&o.stdout_str()),
        _ => Vec::new(),
    }
}

/// One finding per container (running or not) — `docker ps` alone; CPU/RAM
/// are sampled once for whichever of them `docker stats` reports (only the
/// running ones). Previously this section covered only running containers,
/// each getting its own finding built from two separate commands; now every
/// container gets exactly one finding, built by merging both commands' data
/// up front, so there's still only one `container:<id>` finding per
/// container rather than two competing writes to the same key.
async fn emit_containers(ctx: &ScanCtx, containers: &[PsRow]) {
    if containers.is_empty() {
        return;
    }
    let stats: HashMap<String, ContainerStats> = match ctx
        .runner
        .run(
            "docker",
            &[
                "stats",
                "--no-stream",
                "--format",
                "{{.ID}}\t{{.CPUPerc}}\t{{.MemUsage}}",
            ],
            &ctx.token,
        )
        .await
    {
        Ok(o) if o.success() => parse_stats(&o.stdout_str()),
        _ => HashMap::new(),
    };

    for row in containers {
        let labels = parse_labels(&row.labels);
        let (size_rw_bytes, size_virtual_bytes) = parse_container_size(&row.size);
        let running = row.state == "running";
        let stat = stats.get(&row.id);
        let cpu = stat.map(|s| s.cpu_percent).unwrap_or(0.0);
        let memory = stat.and_then(|s| s.memory_bytes);

        let severity = if !running {
            Severity::Info
        } else if cpu >= 100.0 || memory.unwrap_or(0) >= 2 * 1024 * 1024 * 1024 {
            Severity::Warning
        } else if cpu >= 50.0 || memory.unwrap_or(0) >= 1024 * 1024 * 1024 {
            Severity::Attention
        } else {
            Severity::Info
        };
        let detail = if running {
            match memory {
                Some(memory) => {
                    format!(
                        "{} · {:.1}% CPU · {} RAM",
                        row.state,
                        cpu,
                        format_size(memory)
                    )
                }
                None => format!("{} · {:.1}% CPU", row.state, cpu),
            }
        } else {
            format!("{} · created {}", row.state, row.created_at)
        };

        let mut meta = serde_json::json!({
            "object": "container",
            "id": row.id,
            "name": row.names,
            "image": row.image,
            "labels": labels,
            "state": row.state,
            "cpu_percent": cpu,
            "memory_bytes": memory,
        });
        if let Some(rw) = size_rw_bytes {
            meta["size_rw_bytes"] = serde_json::json!(rw);
        }
        if let Some(v) = size_virtual_bytes {
            meta["size_virtual_bytes"] = serde_json::json!(v);
        }
        for (key, value) in compose_meta(&labels) {
            if let Some(value) = value {
                meta[key] = serde_json::json!(value);
            }
        }

        let mut finding = Finding::new(
            FindingKind::DockerObject,
            &format!("container:{}", row.id),
            format!("{} — container", row.names),
        )
        .detail(detail)
        .severity(severity)
        .provenance("docker ps -a -s; docker stats --no-stream")
        .meta(meta);
        if let Some(sz) = size_rw_bytes.or(size_virtual_bytes) {
            finding = finding.size(sz);
        }
        ctx.emit(finding).await;
    }
}

/// One finding per image, `used_by` listing which of `containers` reference
/// it (by tag or by id) — plus one `docker inspect` call across every image
/// id to pick up Compose's labels on the image itself (a compose-built
/// image carries `com.docker.compose.project[.working_dir]` even when no
/// container from it happens to be running).
async fn emit_images(ctx: &ScanCtx, containers: &[PsRow]) {
    let out = match ctx
        .runner
        .run(
            "docker",
            &["image", "ls", "--format", "{{json .}}"],
            &ctx.token,
        )
        .await
    {
        Ok(o) if o.success() => o.stdout_str().into_owned(),
        _ => return,
    };
    let rows: Vec<ImageRow> = parse_ndjson(&out);
    if rows.is_empty() {
        return;
    }

    let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    let mut inspect_args = vec!["inspect", "--format", "{{.Id}} {{json .Config.Labels}}"];
    inspect_args.extend(ids.iter().copied());
    let inspected = match ctx.runner.run("docker", &inspect_args, &ctx.token).await {
        Ok(o) if o.success() => parse_inspect_labels(&o.stdout_str()),
        _ => Vec::new(),
    };

    for row in rows {
        let labels = inspected
            .iter()
            .find(|(full_id, _)| {
                let full_id = full_id.trim_start_matches("sha256:");
                full_id.starts_with(&row.id)
            })
            .map(|(_, labels)| labels.clone())
            .unwrap_or_default();
        let size_bytes = parse_human_size(&row.size);
        let repo_tag = format!("{}:{}", row.repository, row.tag);
        let used_by: Vec<&str> = containers
            .iter()
            .filter(|c| image_matches(&c.image, &row.id, &repo_tag))
            .map(|c| c.id.as_str())
            .collect();

        let mut meta = serde_json::json!({
            "object": "image",
            "id": row.id,
            "repository": row.repository,
            "tag": row.tag,
            "labels": labels,
            "used_by": used_by,
        });
        for (key, value) in compose_meta(&labels) {
            if let Some(value) = value {
                meta[key] = serde_json::json!(value);
            }
        }
        if let Some(sz) = size_bytes {
            meta["size_bytes"] = serde_json::json!(sz);
        }

        let mut finding = Finding::new(
            FindingKind::DockerObject,
            &format!("image:{}", row.id),
            format!("{repo_tag} — image"),
        )
        .detail(format!("created {}", row.created_at))
        .severity(Severity::Info)
        .provenance("docker image ls; docker inspect")
        .meta(meta);
        if let Some(sz) = size_bytes {
            finding = finding.size(sz);
        }
        ctx.emit(finding).await;
    }
}

/// Whether a container's `Image` field (a `repo:tag`, or an id/digest for an
/// untagged pull) refers to this image.
fn image_matches(container_image: &str, image_id: &str, repo_tag: &str) -> bool {
    if container_image == repo_tag {
        return true;
    }
    let stripped = container_image.trim_start_matches("sha256:");
    stripped.starts_with(image_id) || image_id.starts_with(stripped)
}

/// Parse `docker inspect --format '{{.Id}} {{json .Config.Labels}}'`
/// output: one `<full sha256 id> <json labels object>` line per image.
/// `.Config.Labels` is `null` for an unlabelled image, which fails to
/// deserialize as a map and falls back to empty rather than dropping the
/// row.
fn parse_inspect_labels(input: &str) -> Vec<(String, HashMap<String, String>)> {
    input
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (id, json_part) = line.split_once(' ')?;
            let labels: HashMap<String, String> =
                serde_json::from_str(json_part).unwrap_or_default();
            Some((id.to_string(), labels))
        })
        .collect()
}

/// One finding per volume. `docker system df -v` is the only subcommand
/// that reports a volume's size, and it ignores `--format json` (see the
/// module-level NOTE above), so `size_bytes` is left absent rather than
/// parsed from its verbose text tables.
async fn emit_volumes(ctx: &ScanCtx) {
    let out = match ctx
        .runner
        .run(
            "docker",
            &["volume", "ls", "--format", "{{json .}}"],
            &ctx.token,
        )
        .await
    {
        Ok(o) if o.success() => o.stdout_str().into_owned(),
        _ => return,
    };
    let rows: Vec<VolumeRow> = parse_ndjson(&out);
    for row in rows {
        let labels = parse_labels(&row.labels);

        let mut meta = serde_json::json!({
            "object": "volume",
            "name": row.name,
            "driver": row.driver,
            "mountpoint": row.mountpoint,
            "labels": labels,
        });
        for (key, value) in compose_meta(&labels) {
            if let Some(value) = value {
                meta[key] = serde_json::json!(value);
            }
        }

        ctx.emit(
            Finding::new(
                FindingKind::DockerObject,
                &format!("volume:{}", row.name),
                format!("{} — volume", row.name),
            )
            .severity(Severity::Info)
            .provenance("docker volume ls")
            .meta(meta),
        )
        .await;
    }
}

#[derive(Debug)]
struct ContainerStats {
    cpu_percent: f64,
    memory_bytes: Option<u64>,
}

fn parse_stats(input: &str) -> HashMap<String, ContainerStats> {
    input
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            let id = parts.next()?.trim().to_string();
            let cpu_percent = parts.next()?.trim().trim_end_matches('%').parse().ok()?;
            let memory = parts.next()?.split('/').next()?.trim();
            Some((
                id,
                ContainerStats {
                    cpu_percent,
                    memory_bytes: parse_human_size(memory),
                },
            ))
        })
        .collect()
}

fn format_size(bytes: u64) -> String {
    humansize::format_size(bytes, humansize::BINARY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockCommandRunner;

    const DF_FIXTURE: &str = concat!(
        r#"{"Type":"Images","TotalCount":12,"Active":3,"Size":"1.113GB","Reclaimable":"800MB (71%)"}"#,
        "\n",
        r#"{"Type":"Containers","TotalCount":5,"Active":1,"Size":"45.2MB","Reclaimable":"20MB (44%)"}"#,
        "\n",
        r#"{"Type":"Local Volumes","TotalCount":3,"Active":0,"Size":"120MB","Reclaimable":"120MB (100%)"}"#,
        "\n",
        r#"{"Type":"Build Cache","TotalCount":40,"Active":0,"Size":"500MB","Reclaimable":"500MB (100%)"}"#,
        "\n",
    );

    fn ctx_with(mock: MockCommandRunner) -> ScanCtx {
        let (tx, _rx) = tokio::sync::mpsc::channel(256);
        ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: std::sync::Arc::new(crate::config::Config::default()),
            paths: std::sync::Arc::new(crate::config::Paths::from_home("/tmp/fh")),
            runner: std::sync::Arc::new(mock),
            current: crate::model::ScannerId::Docker,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        }
    }

    async fn run_and_collect(mock: MockCommandRunner) -> Vec<Finding> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mut ctx = ctx_with(mock);
        ctx.tx = tx;
        DockerScanner.scan(ctx).await.unwrap();
        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let crate::model::ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        findings
    }

    #[tokio::test]
    async fn daemon_unreachable_emits_single_info_finding() {
        let mock = MockCommandRunner::new().on_fail(
            "docker",
            &["system", "df", "--format", "json"],
            1,
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
        );
        let findings = run_and_collect(mock).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].title, "Docker daemon not reachable");
    }

    #[tokio::test]
    async fn missing_binary_emits_single_info_finding() {
        // No response registered ⇒ MockCommandRunner errors, simulating a
        // missing `docker` binary.
        let findings = run_and_collect(MockCommandRunner::new()).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[tokio::test]
    async fn parses_df_rows_into_findings_with_remedies() {
        let mock = MockCommandRunner::new().on(
            "docker",
            &["system", "df", "--format", "json"],
            DF_FIXTURE,
        );
        let findings = run_and_collect(mock).await;
        assert_eq!(findings.len(), 4);

        let images = findings
            .iter()
            .find(|f| f.meta["type"] == "Images")
            .unwrap();
        assert_eq!(images.severity, Severity::Reclaimable);
        // size_bytes now reports RECLAIMABLE (what a prune frees), not total.
        assert_eq!(images.size_bytes, Some(800_000_000));
        assert_eq!(images.meta["total_size_bytes"], 1_113_000_000u64);
        assert_eq!(images.remedies.len(), 1);
        assert!(images.remedies[0].destructive);
        assert_eq!(
            images.remedies[0].command,
            RemedyCommand::Shell {
                program: "docker".into(),
                args: vec!["image".into(), "prune".into(), "-f".into()],
            }
        );

        let volumes = findings
            .iter()
            .find(|f| f.meta["type"] == "Local Volumes")
            .unwrap();
        assert_eq!(
            volumes.remedies[0].command,
            RemedyCommand::Shell {
                program: "docker".into(),
                args: vec!["volume".into(), "prune".into(), "-f".into()],
            }
        );
    }

    #[tokio::test]
    async fn compose_labelled_container_yields_compose_working_dir() {
        let ps_fixture = concat!(
            r#"{"ID":"abc123","Names":"cubby-db","Image":"postgres:15","#,
            r#""Labels":"com.docker.compose.project=cubby,com.docker.compose.project.working_dir=/Users/dev/cubby","#,
            r#""Size":"12B (virtual 1.2GB)","State":"running","CreatedAt":"2026-01-01 00:00:00 +0000 UTC"}"#,
            "\n",
        );
        let mock = MockCommandRunner::new()
            .on("docker", &["system", "df", "--format", "json"], DF_FIXTURE)
            .on(
                "docker",
                &["ps", "-a", "-s", "--format", "{{json .}}"],
                ps_fixture,
            )
            .on(
                "docker",
                &[
                    "stats",
                    "--no-stream",
                    "--format",
                    "{{.ID}}\t{{.CPUPerc}}\t{{.MemUsage}}",
                ],
                "abc123\t2.0%\t50MiB / 8GiB\n",
            );
        let findings = run_and_collect(mock).await;

        let container = findings
            .iter()
            .find(|f| f.meta["object"] == "container")
            .expect("container finding");
        assert_eq!(container.meta["compose_project"], "cubby");
        assert_eq!(container.meta["compose_working_dir"], "/Users/dev/cubby");
        assert_eq!(container.meta["size_rw_bytes"], 12u64);
        assert_eq!(container.meta["size_virtual_bytes"], 1_200_000_000u64);
        assert_eq!(container.meta["state"], "running");
        assert_eq!(
            container.meta["labels"]["com.docker.compose.project"],
            "cubby"
        );
    }

    #[test]
    fn human_size_parsing() {
        assert_eq!(parse_human_size("1.113GB"), Some(1_113_000_000));
        assert_eq!(parse_human_size("800MB (71%)"), Some(800_000_000));
        assert_eq!(parse_human_size("0B"), Some(0));
        assert_eq!(parse_human_size("45.2kB"), Some(45_200));
        assert_eq!(parse_human_size(""), None);
    }

    #[test]
    fn container_size_parsing_splits_rw_and_virtual() {
        assert_eq!(
            parse_container_size("12B (virtual 1.2GB)"),
            (Some(12), Some(1_200_000_000))
        );
        assert_eq!(
            parse_container_size("456.7MB (virtual 456.7MB)"),
            (Some(456_700_000), Some(456_700_000))
        );
        assert_eq!(parse_container_size("0B"), (Some(0), None));
        assert_eq!(parse_container_size(""), (None, None));
    }

    #[test]
    fn label_string_parsing() {
        let labels = parse_labels(
            "com.docker.compose.project=cubby,com.docker.compose.project.working_dir=/Users/dev/cubby",
        );
        assert_eq!(
            labels.get("com.docker.compose.project").map(String::as_str),
            Some("cubby")
        );
        assert_eq!(
            labels
                .get("com.docker.compose.project.working_dir")
                .map(String::as_str),
            Some("/Users/dev/cubby")
        );
        assert_eq!(parse_labels("").len(), 0);
        // A value containing '=' (base64-ish) only splits on the first '='.
        let with_eq = parse_labels("key=va=lue");
        assert_eq!(with_eq.get("key").map(String::as_str), Some("va=lue"));
    }

    #[test]
    fn image_matches_by_repo_tag_or_id() {
        assert!(image_matches("postgres:15", "abcdef123456", "postgres:15"));
        assert!(image_matches(
            "abcdef123456",
            "abcdef123456789",
            "postgres:15"
        ));
        assert!(image_matches(
            "sha256:abcdef123456789",
            "abcdef123456",
            "postgres:15"
        ));
        assert!(!image_matches("redis:7", "abcdef123456", "postgres:15"));
    }

    #[test]
    fn parses_stats_rows() {
        let stats = parse_stats("abc\t12.5%\t780MiB / 8GiB\n");
        assert_eq!(stats["abc"].cpu_percent, 12.5);
        assert!(stats["abc"].memory_bytes.unwrap() > 700 * 1024 * 1024);
    }
}
