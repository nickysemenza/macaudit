//! DockerScanner (spec §3.7) — `docker system df --format json` → dangling
//! images, stopped containers, unused volumes, build cache. If the CLI is
//! missing or the daemon is unreachable, emit a single Info finding and
//! return Ok — never fail the whole scan over an optional tool.

use async_trait::async_trait;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::{ScanCtx, Scanner};

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
        // (Type/TotalCount/Active/Size/Reclaimable) this parser expects.
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
                "Build Cache" => Some(("Prune build cache", vec!["system", "prune", "-f"])),
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
                "type": ty,
                "total_count": total_count,
                "active": active,
                "size": size_str,
                "reclaimable": reclaimable_str,
            }));

            if let Some(bytes) = size_bytes {
                finding = finding.size(bytes);
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
                    });
                }
            }

            ctx.emit(finding).await;
        }

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
    let mult: f64 = match unit.to_ascii_lowercase().as_str() {
        "b" => 1.0,
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        _ => return None,
    };
    Some((num * mult) as u64)
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

    #[tokio::test]
    async fn daemon_unreachable_emits_single_info_finding() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mock = MockCommandRunner::new().on_fail(
            "docker",
            &["system", "df", "--format", "json"],
            1,
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
        );
        let mut ctx = ctx_with(mock);
        ctx.tx = tx;
        DockerScanner.scan(ctx).await.unwrap();

        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let crate::model::ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].title, "Docker daemon not reachable");
    }

    #[tokio::test]
    async fn missing_binary_emits_single_info_finding() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        // No response registered ⇒ MockCommandRunner errors, simulating a
        // missing `docker` binary.
        let mock = MockCommandRunner::new();
        let mut ctx = ctx_with(mock);
        ctx.tx = tx;
        DockerScanner.scan(ctx).await.unwrap();

        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let crate::model::ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[tokio::test]
    async fn parses_df_rows_into_findings_with_remedies() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mock = MockCommandRunner::new().on(
            "docker",
            &["system", "df", "--format", "json"],
            DF_FIXTURE,
        );
        let mut ctx = ctx_with(mock);
        ctx.tx = tx;
        DockerScanner.scan(ctx).await.unwrap();

        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let crate::model::ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        assert_eq!(findings.len(), 4);

        let images = findings
            .iter()
            .find(|f| f.meta["type"] == "Images")
            .unwrap();
        assert_eq!(images.severity, Severity::Reclaimable);
        assert_eq!(images.size_bytes, Some(1_113_000_000));
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

    #[test]
    fn human_size_parsing() {
        assert_eq!(parse_human_size("1.113GB"), Some(1_113_000_000));
        assert_eq!(parse_human_size("800MB (71%)"), Some(800_000_000));
        assert_eq!(parse_human_size("0B"), Some(0));
        assert_eq!(parse_human_size("45.2kB"), Some(45_200));
        assert_eq!(parse_human_size(""), None);
    }
}
