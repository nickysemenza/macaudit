//! AppsScanner — lane S1.
//!
//! Runs `system_profiler SPApplicationsDataType -json`, parses the
//! `SPApplicationsDataType` array, and emits one `Finding` (kind `App`) per
//! installed application. Classification (System/User/App Store/Unmanaged),
//! architecture (flagging Intel/Rosetta apps on Apple Silicon), and
//! obtained-from all land in `meta` for the UI and for `correlate.rs` to join
//! against BrewScanner's cask inventory.
//!
//! Implementation contract: depend only on the frozen types (Finding,
//! FindingKind, Remedy, RemedyCommand, Severity, ScanEvent, ScannerId, Scanner,
//! ScanCtx, CommandRunner, Config, Paths). Send Progress/Finding only. Touch
//! only this file and tests/fixtures/apps/.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use crate::model::{Finding, FindingKind, RemedyCommand, ScannerId, Severity};
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct AppsScanner;

/// Raw shape of one entry in `system_profiler SPApplicationsDataType -json`'s
/// `SPApplicationsDataType` array. Only the fields we use; `system_profiler`
/// emits many more that we ignore.
#[derive(Debug, Deserialize)]
struct RawApp {
    #[serde(rename = "_name")]
    name: String,
    path: Option<String>,
    version: Option<String>,
    arch_kind: Option<String>,
    obtained_from: Option<String>,
    signed_by: Option<AnySignedBy>,
}

/// `signed_by` is documented as a string but some macOS versions emit an
/// array of certificate-chain names. Accept both without failing the parse.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AnySignedBy {
    One(String),
    Many(Vec<String>),
}

impl AnySignedBy {
    fn display(&self) -> String {
        match self {
            AnySignedBy::One(s) => s.clone(),
            AnySignedBy::Many(v) => v.join(", "),
        }
    }
}

#[derive(Debug, Deserialize)]
struct SpRoot {
    #[serde(rename = "SPApplicationsDataType", default)]
    apps: Vec<RawApp>,
}

/// App classification bucket (spec §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Classification {
    System,
    User,
    AppStore,
    Unmanaged,
}

impl Classification {
    fn as_str(self) -> &'static str {
        match self {
            Classification::System => "system",
            Classification::User => "user",
            Classification::AppStore => "app_store",
            Classification::Unmanaged => "unmanaged",
        }
    }
}

fn classify(path: &str, obtained_from: Option<&str>, ctx: &ScanCtx) -> Classification {
    if obtained_from == Some("mac_app_store") {
        return Classification::AppStore;
    }
    let system_apps = "/System/Applications";
    let user_apps = "/Applications";
    let home_apps = ctx.paths.expand("~/Applications");
    let home_apps = home_apps.to_string_lossy();

    if path.starts_with(system_apps) {
        Classification::System
    } else if path.starts_with(user_apps) || path.starts_with(home_apps.as_ref()) {
        Classification::User
    } else {
        // Anywhere else (identified_developer/unknown, unusual locations) —
        // treated as User-installed-but-not-in-a-standard-managed-location.
        // Whether it's flagged Unmanaged is decided by obtained_from below.
        Classification::User
    }
}

/// "Unmanaged" is the interesting bucket the spec calls out: apps obtained
/// outside the App Store / Apple that aren't (yet) known to be cask-managed.
/// Cask correlation happens later in `correlate.rs`; here we just flag
/// candidates by `obtained_from`.
fn is_unmanaged_candidate(classification: Classification, obtained_from: Option<&str>) -> bool {
    if classification == Classification::System || classification == Classification::AppStore {
        return false;
    }
    matches!(
        obtained_from,
        Some("identified_developer") | Some("unknown") | None
    )
}

/// Bundle id best-effort extraction: `system_profiler` doesn't always give us
/// one directly in this dataset; we derive nothing fake here — left `None`
/// unless a future field supplies it. Kept as a function so tests / future
/// extensions have one place to extend.
fn bundle_id(_raw: &RawApp) -> Option<String> {
    None
}

#[async_trait]
impl Scanner for AppsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Apps
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        let out = ctx
            .runner
            .run(
                "system_profiler",
                &["SPApplicationsDataType", "-json"],
                &ctx.token,
            )
            .await?;

        if !out.success() {
            ctx.emit(
                Finding::new(
                    FindingKind::App,
                    "system_profiler-error",
                    "system_profiler failed",
                )
                .detail(out.stderr_str().trim().to_string())
                .severity(Severity::Attention),
            )
            .await;
            return Ok(());
        }

        let parsed: SpRoot = match serde_json::from_str(&out.stdout_str()) {
            Ok(p) => p,
            Err(e) => {
                ctx.emit(
                    Finding::new(
                        FindingKind::App,
                        "system_profiler-parse-error",
                        "Failed to parse system_profiler output",
                    )
                    .detail(e.to_string())
                    .severity(Severity::Attention),
                )
                .await;
                return Ok(());
            }
        };

        let total = parsed.apps.len() as u64;
        // Apple Silicon detection: the simplest reliable signal is `uname -m`
        // (== "arm64" on Apple Silicon), independent of per-app arch_kind.
        let is_apple_silicon = {
            let uname = ctx.runner.run("uname", &["-m"], &ctx.token).await;
            matches!(uname, Ok(o) if o.success() && o.stdout_str().trim() == "arm64")
        };

        for (i, raw) in parsed.apps.into_iter().enumerate() {
            if ctx.cancelled() {
                break;
            }
            ctx.progress(format!("Scanning {}", raw.name), i as u64 + 1, Some(total))
                .await;

            let path = raw
                .path
                .clone()
                .unwrap_or_else(|| format!("/Applications/{}.app", raw.name));
            let classification = classify(&path, raw.obtained_from.as_deref(), &ctx);
            let unmanaged = is_unmanaged_candidate(classification, raw.obtained_from.as_deref());
            let final_classification = if unmanaged {
                Classification::Unmanaged
            } else {
                classification
            };

            let arch = raw
                .arch_kind
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            // Real `system_profiler SPApplicationsDataType -json` reports the
            // architecture as `arch_kind`: `arch_i64` = Intel-only (x86_64),
            // `arch_arm` = native Apple Silicon, `arch_arm_i64` = Universal,
            // `arch_ios`/`arch_other` = iOS-on-Mac / other. Intel-only apps run
            // under Rosetta on Apple Silicon.
            let is_intel_only = arch == "arch_i64";
            let rosetta_flag = is_apple_silicon && is_intel_only;

            let mut severity = match final_classification {
                Classification::Unmanaged => Severity::Attention,
                _ => Severity::Info,
            };
            if rosetta_flag {
                severity = Severity::Attention;
            }

            let title = format!("{} {}", raw.name, raw.version.as_deref().unwrap_or(""));
            let title = title.trim().to_string();

            let meta = json!({
                "classification": final_classification.as_str(),
                "arch": arch,
                "obtained_from": raw.obtained_from,
                "signed_by": raw.signed_by.as_ref().map(|s| s.display()),
                "version": raw.version,
                "bundle_id": bundle_id(&raw),
                "rosetta_or_intel_only": rosetta_flag,
                "is_apple_silicon_host": is_apple_silicon,
            });

            let mut finding = Finding::new(
                FindingKind::App,
                &path,
                if title.is_empty() {
                    raw.name.clone()
                } else {
                    title
                },
            )
            .detail(format!(
                "{} — {}",
                final_classification.as_str(),
                raw.obtained_from.as_deref().unwrap_or("unknown source")
            ))
            .path(path.clone())
            .severity(severity)
            .meta(meta)
            .remedy(crate::model::Remedy {
                label: "Reveal in Finder".to_string(),
                command: RemedyCommand::RevealInFinder {
                    path: path.clone().into(),
                },
                reclaims_bytes: None,
                destructive: false,
            });

            if rosetta_flag {
                let detail = format!("{} (Intel/Rosetta on Apple Silicon)", finding.detail);
                finding = finding.detail(detail);
            }

            ctx.emit(finding).await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanEvent;
    use crate::runner::MockCommandRunner;

    const FIXTURE_JSON: &str = r#"
    {
      "SPApplicationsDataType": [
        {
          "_name": "Safari",
          "path": "/System/Applications/Safari.app",
          "version": "17.0",
          "arch_kind": "arch_arm_i64",
          "obtained_from": "apple",
          "signed_by": "Software Signing, Apple Root CA"
        },
        {
          "_name": "Xcode",
          "path": "/Applications/Xcode.app",
          "version": "15.0",
          "arch_kind": "arch_arm_i64",
          "obtained_from": "mac_app_store",
          "signed_by": "Apple Mac OS Application Signing"
        },
        {
          "_name": "Slack",
          "path": "/Applications/Slack.app",
          "version": "4.36.0",
          "arch_kind": "arch_arm_i64",
          "obtained_from": "identified_developer",
          "signed_by": "Developer ID Application: Slack Technologies, Inc."
        },
        {
          "_name": "OldTool",
          "path": "/Applications/OldTool.app",
          "version": "1.2",
          "arch_kind": "arch_i64",
          "obtained_from": "identified_developer",
          "signed_by": "Developer ID Application: Some Dev"
        },
        {
          "_name": "Mystery",
          "path": "/Applications/Mystery.app",
          "version": "0.1",
          "arch_kind": "arch_arm_i64",
          "obtained_from": "unknown"
        }
      ]
    }
    "#;

    async fn run_scan() -> Vec<Finding> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mock = MockCommandRunner::new()
            .on(
                "system_profiler",
                &["SPApplicationsDataType", "-json"],
                FIXTURE_JSON,
            )
            .on("uname", &["-m"], "arm64\n");
        let ctx = ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: std::sync::Arc::new(crate::config::Config::default()),
            paths: std::sync::Arc::new(crate::config::Paths::from_home("/tmp/fh")),
            runner: std::sync::Arc::new(mock),
            current: ScannerId::Apps,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        AppsScanner.scan(ctx).await.unwrap();
        let mut findings = vec![];
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        findings
    }

    #[tokio::test]
    async fn emits_one_finding_per_app() {
        let findings = run_scan().await;
        assert_eq!(findings.len(), 5);
    }

    #[tokio::test]
    async fn classifies_system_user_app_store_and_unmanaged() {
        let findings = run_scan().await;
        let by_path = |p: &str| {
            findings
                .iter()
                .find(|f| f.path.as_deref() == Some(std::path::Path::new(p)))
                .unwrap()
        };

        assert_eq!(
            by_path("/System/Applications/Safari.app").meta["classification"],
            "system"
        );
        assert_eq!(
            by_path("/Applications/Xcode.app").meta["classification"],
            "app_store"
        );
        assert_eq!(
            by_path("/Applications/Slack.app").meta["classification"],
            "unmanaged"
        );
        assert_eq!(
            by_path("/Applications/Mystery.app").meta["classification"],
            "unmanaged"
        );
    }

    #[tokio::test]
    async fn flags_intel_app_on_apple_silicon() {
        let findings = run_scan().await;
        let old_tool = findings
            .iter()
            .find(|f| f.path.as_deref() == Some(std::path::Path::new("/Applications/OldTool.app")))
            .unwrap();
        assert_eq!(old_tool.meta["rosetta_or_intel_only"], true);
        assert_eq!(old_tool.severity, Severity::Attention);
    }

    #[tokio::test]
    async fn unmanaged_apps_get_attention_severity() {
        let findings = run_scan().await;
        let slack = findings
            .iter()
            .find(|f| f.path.as_deref() == Some(std::path::Path::new("/Applications/Slack.app")))
            .unwrap();
        assert_eq!(slack.severity, Severity::Attention);
        assert_eq!(slack.meta["classification"], "unmanaged");
    }

    #[tokio::test]
    async fn every_finding_has_reveal_in_finder_remedy() {
        let findings = run_scan().await;
        for f in &findings {
            assert!(f
                .remedies
                .iter()
                .any(|r| matches!(r.command, RemedyCommand::RevealInFinder { .. })));
        }
    }

    #[tokio::test]
    async fn finding_id_is_stable_and_keyed_by_path() {
        let findings = run_scan().await;
        let id1 = crate::model::FindingId::new(FindingKind::App, "/Applications/Slack.app");
        let slack = findings
            .iter()
            .find(|f| f.path.as_deref() == Some(std::path::Path::new("/Applications/Slack.app")))
            .unwrap();
        assert_eq!(slack.id, id1);
    }

    #[tokio::test]
    async fn system_profiler_failure_emits_single_info_finding_and_returns_ok() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mock = MockCommandRunner::new().on_fail(
            "system_profiler",
            &["SPApplicationsDataType", "-json"],
            1,
            "boom",
        );
        let ctx = ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: std::sync::Arc::new(crate::config::Config::default()),
            paths: std::sync::Arc::new(crate::config::Paths::from_home("/tmp/fh")),
            runner: std::sync::Arc::new(mock),
            current: ScannerId::Apps,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        let result = AppsScanner.scan(ctx).await;
        assert!(result.is_ok());
        let mut findings = vec![];
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        assert_eq!(findings.len(), 1);
    }
}
