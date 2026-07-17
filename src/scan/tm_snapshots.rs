//! TmSnapshotsScanner (spec §3.12) — `tmutil listlocalsnapshots /` → one
//! Reclaimable finding per local Time Machine snapshot, each with a
//! destructive `tmutil deletelocalsnapshots <date>` remedy. If tmutil is
//! absent or errors, emit a single Info finding and return Ok.

use async_trait::async_trait;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct TmSnapshotsScanner;

#[async_trait]
impl Scanner for TmSnapshotsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::TmSnapshots
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        let out = match ctx
            .runner
            .run("tmutil", &["listlocalsnapshots", "/"], &ctx.token)
            .await
        {
            Ok(o) if o.success() => o,
            Ok(o) => {
                emit_unavailable(&ctx, o.stderr_str().trim()).await;
                return Ok(());
            }
            Err(e) => {
                emit_unavailable(&ctx, &e.to_string()).await;
                return Ok(());
            }
        };

        for line in out.stdout_str().lines() {
            let Some((name, date)) = parse_snapshot_line(line) else {
                continue;
            };

            let title = format!("Local snapshot {}", humanize_date(&date));
            let finding = Finding::new(FindingKind::LocalSnapshot, &name, title)
                .detail(format!("Time Machine local snapshot {name}"))
                .severity(Severity::Reclaimable)
                .meta(serde_json::json!({ "name": name, "date": date }))
                .remedy(Remedy {
                    label: "Delete local snapshot".to_string(),
                    command: RemedyCommand::Shell {
                        program: "tmutil".to_string(),
                        args: vec!["deletelocalsnapshots".to_string(), date.clone()],
                    },
                    reclaims_bytes: None,
                    destructive: true,
                });

            ctx.emit(finding).await;
        }

        Ok(())
    }
}

async fn emit_unavailable(ctx: &ScanCtx, detail: &str) {
    ctx.emit(
        Finding::new(
            FindingKind::LocalSnapshot,
            "tmutil:unavailable",
            "tmutil not available",
        )
        .detail(if detail.is_empty() {
            "tmutil is missing or failed to list local snapshots".to_string()
        } else {
            detail.to_string()
        })
        .severity(Severity::Info),
    )
    .await;
}

/// Parse one line of `tmutil listlocalsnapshots /` output. Data lines look
/// like `com.apple.TimeMachine.2024-06-01-120000.local`; header/prose lines
/// (e.g. "Snapshots for disk /:") are skipped. Returns the full snapshot
/// identifier and the extracted `YYYY-MM-DD-HHMMSS` date string.
fn parse_snapshot_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    let rest = line.strip_prefix("com.apple.TimeMachine.")?;
    let date = rest.strip_suffix(".local").unwrap_or(rest);
    if date.is_empty() {
        return None;
    }
    Some((line.to_string(), date.to_string()))
}

/// Best-effort "YYYY-MM-DD-HHMMSS" -> "YYYY-MM-DD HH:MM:SS" formatting for
/// the finding title. Falls back to the raw string if it isn't the expected
/// fixed-width shape.
fn humanize_date(date: &str) -> String {
    let bytes = date.as_bytes();
    if bytes.len() == 17 && date.chars().filter(|c| *c == '-').count() == 3 {
        let ymd = &date[0..10];
        let hms = &date[11..17];
        format!("{ymd} {}:{}:{}", &hms[0..2], &hms[2..4], &hms[4..6])
    } else {
        date.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanEvent;
    use crate::runner::MockCommandRunner;

    const SNAPSHOTS_FIXTURE: &str = "\
Snapshots for volume group containing disk /:
com.apple.TimeMachine.2024-06-01-120000.local
com.apple.TimeMachine.2024-06-15-093015.local
";

    fn ctx_with(mock: MockCommandRunner, tx: tokio::sync::mpsc::Sender<ScanEvent>) -> ScanCtx {
        ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: std::sync::Arc::new(crate::config::Config::default()),
            paths: std::sync::Arc::new(crate::config::Paths::from_home("/tmp/fh")),
            runner: std::sync::Arc::new(mock),
            current: crate::model::ScannerId::TmSnapshots,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        }
    }

    #[tokio::test]
    async fn parses_snapshots_with_destructive_remedy() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mock =
            MockCommandRunner::new().on("tmutil", &["listlocalsnapshots", "/"], SNAPSHOTS_FIXTURE);
        let ctx = ctx_with(mock, tx);
        TmSnapshotsScanner.scan(ctx).await.unwrap();

        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        assert_eq!(findings.len(), 2);

        let first = &findings[0];
        assert_eq!(first.severity, Severity::Reclaimable);
        assert_eq!(first.title, "Local snapshot 2024-06-01 12:00:00");
        assert_eq!(first.remedies.len(), 1);
        assert!(first.remedies[0].destructive);
        assert_eq!(
            first.remedies[0].command,
            RemedyCommand::Shell {
                program: "tmutil".into(),
                args: vec!["deletelocalsnapshots".into(), "2024-06-01-120000".into(),],
            }
        );
    }

    #[tokio::test]
    async fn missing_tmutil_emits_single_info_finding() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mock = MockCommandRunner::new();
        let ctx = ctx_with(mock, tx);
        TmSnapshotsScanner.scan(ctx).await.unwrap();

        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[tokio::test]
    async fn no_snapshots_emits_nothing() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mock = MockCommandRunner::new().on(
            "tmutil",
            &["listlocalsnapshots", "/"],
            "Snapshots for volume group containing disk /:\n",
        );
        let ctx = ctx_with(mock, tx);
        TmSnapshotsScanner.scan(ctx).await.unwrap();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn date_humanization() {
        assert_eq!(humanize_date("2024-06-01-120000"), "2024-06-01 12:00:00");
        assert_eq!(humanize_date("garbage"), "garbage");
    }
}
