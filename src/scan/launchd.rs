//! LaunchdScanner — enumerates plists under `~/Library/LaunchAgents`,
//! `/Library/LaunchAgents`, and `/Library/LaunchDaemons`; cross-references
//! `launchctl list` for running state; flags orphaned items whose
//! `Program`/`ProgramArguments[0]` binary no longer exists on disk.
//!
//! We deliberately do NOT call `sfltool dumpbtm` (the Ventura+ background-items
//! registry): it requires admin rights and pops a password prompt on every
//! scan, which is unacceptable for a read-only audit that rescans freely.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct LaunchdScanner;

/// Just the fields we care about; unknown plist keys are ignored by serde.
#[derive(Debug, Deserialize, Default)]
struct LaunchdPlist {
    #[serde(rename = "Label")]
    label: Option<String>,
    #[serde(rename = "Program")]
    program: Option<String>,
    #[serde(rename = "ProgramArguments")]
    program_arguments: Option<Vec<String>>,
    #[serde(rename = "RunAtLoad")]
    run_at_load: Option<bool>,
    #[serde(rename = "Disabled")]
    disabled: Option<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Domain {
    UserAgent,
    LibraryAgent,
    LibraryDaemon,
}

impl Domain {
    fn tag(self) -> &'static str {
        match self {
            Domain::UserAgent => "user_agent",
            Domain::LibraryAgent => "library_agent",
            Domain::LibraryDaemon => "library_daemon",
        }
    }
}

#[async_trait]
impl Scanner for LaunchdScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Launchd
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        let dirs: [(PathBuf, Domain); 3] = [
            (
                ctx.paths.expand("~/Library/LaunchAgents"),
                Domain::UserAgent,
            ),
            (PathBuf::from("/Library/LaunchAgents"), Domain::LibraryAgent),
            (
                PathBuf::from("/Library/LaunchDaemons"),
                Domain::LibraryDaemon,
            ),
        ];

        let running = running_labels(&ctx).await;

        for (dir, domain) in dirs {
            if ctx.cancelled() {
                break;
            }
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue, // absent/unreadable dir — nothing to report
            };
            let mut paths: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("plist"))
                .collect();
            paths.sort();

            for path in paths {
                if ctx.cancelled() {
                    break;
                }
                self.emit_for_plist(&ctx, &path, domain, &running).await;
            }
        }

        Ok(())
    }
}

impl LaunchdScanner {
    async fn emit_for_plist(
        &self,
        ctx: &ScanCtx,
        path: &Path,
        domain: Domain,
        running: &HashSet<String>,
    ) {
        let parsed: LaunchdPlist = match plist::from_file(path) {
            Ok(v) => v,
            Err(_) => return, // corrupted/unreadable plist — skip rather than crash
        };

        let label = parsed.label.clone().unwrap_or_else(|| {
            path.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default()
        });

        let program_path = parsed.program.clone().or_else(|| {
            parsed
                .program_arguments
                .as_ref()
                .and_then(|a| a.first().cloned())
        });

        let is_running = running.contains(&label);

        let meta = json!({
            "label": label,
            "program": program_path,
            "program_arguments": parsed.program_arguments,
            "running": is_running,
            "domain": domain.tag(),
            "run_at_load": parsed.run_at_load,
            "disabled": parsed.disabled,
        });

        let key = path.to_string_lossy().to_string();
        let missing = program_path
            .as_ref()
            .map(|p| !Path::new(p).exists())
            .unwrap_or(false);

        let mut finding = Finding::new(FindingKind::LaunchdItem, &key, label.clone())
            .path(path.to_path_buf())
            .meta(meta);

        if missing {
            let program_str = program_path.clone().unwrap_or_default();
            finding = finding
                .detail(format!(
                    "{label}: binary `{program_str}` referenced by this launchd item no \
                     longer exists on disk — likely an orphaned leftover from an uninstalled app."
                ))
                .severity(Severity::Warning);

            if let Some(target) = domain_target(ctx, domain, &label).await {
                finding = finding.remedy(Remedy {
                    label: "Unload via `launchctl bootout` — do this first".into(),
                    command: RemedyCommand::Shell {
                        program: "launchctl".into(),
                        args: vec!["bootout".into(), target],
                    },
                    reclaims_bytes: None,
                    destructive: true,
                    alternative: false,
                    guard: None,
                });
            }
            finding = finding.remedy(Remedy {
                label: "Move plist to Trash — do this after unloading".into(),
                command: RemedyCommand::Trash {
                    path: path.to_path_buf(),
                },
                reclaims_bytes: None,
                destructive: true,
                alternative: false,
                guard: None,
            });
        } else {
            let program_display = program_path
                .clone()
                .unwrap_or_else(|| "(no program path)".into());
            finding = finding
                .detail(format!("{label} — {program_display}"))
                .severity(Severity::Info);
        }

        ctx.emit(finding).await;
    }
}

/// Parse `launchctl list` output (tab-separated `PID\tStatus\tLabel`, header
/// optional) into the set of currently-loaded labels.
async fn running_labels(ctx: &ScanCtx) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(out) = ctx.runner.run("launchctl", &["list"], &ctx.token).await {
        if out.success() {
            for line in out.stdout_str().lines() {
                if line.starts_with("PID") {
                    continue; // header row
                }
                let mut parts = line.split('\t');
                let _pid = parts.next();
                let _status = parts.next();
                if let Some(label) = parts.next() {
                    let label = label.trim();
                    if !label.is_empty() {
                        set.insert(label.to_string());
                    }
                }
            }
        }
    }
    set
}

/// Resolve the `launchctl` domain-target for bootout. LaunchDaemons live in
/// `system/<label>`; agents live in `gui/<uid>/<label>` — the uid must be
/// resolved (no shell interpolation happens since args are passed as argv,
/// not through a shell), so we shell out to `id -u`. If that fails we simply
/// omit the bootout remedy rather than emit a bogus command.
async fn domain_target(ctx: &ScanCtx, domain: Domain, label: &str) -> Option<String> {
    match domain {
        Domain::LibraryDaemon => Some(format!("system/{label}")),
        Domain::UserAgent | Domain::LibraryAgent => {
            let out = ctx.runner.run("id", &["-u"], &ctx.token).await.ok()?;
            if !out.success() {
                return None;
            }
            let uid = out.stdout_str().trim().to_string();
            if uid.is_empty() {
                return None;
            }
            Some(format!("gui/{uid}/{label}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn ctx_with(
        tmp: &tempfile::TempDir,
        mock: crate::runner::MockCommandRunner,
    ) -> (
        ScanCtx,
        tokio::sync::mpsc::Receiver<crate::model::ScanEvent>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let ctx = ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: std::sync::Arc::new(crate::config::Config::default()),
            paths: std::sync::Arc::new(crate::config::Paths::from_home(tmp.path())),
            runner: std::sync::Arc::new(mock),
            current: ScannerId::Launchd,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        (ctx, rx)
    }

    fn write_plist(dir: &Path, name: &str, label: &str, program: &str) {
        std::fs::create_dir_all(dir).unwrap();
        let contents = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>Program</key>
    <string>{program}</string>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"#
        );
        std::fs::write(dir.join(name), contents).unwrap();
    }

    /// The two `/Library/...` dirs are deliberately absolute (per spec), so on
    /// the machine actually running `cargo test` they may contain real system
    /// launchd items. Tests must filter to findings under the fixture home
    /// rather than asserting exact totals, or they become flaky depending on
    /// what's installed on the box.
    fn findings_under(
        rx: &mut tokio::sync::mpsc::Receiver<crate::model::ScanEvent>,
        root: &Path,
    ) -> Vec<crate::model::Finding> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let crate::model::ScanEvent::Finding { finding, .. } = ev {
                if finding.path.as_deref().is_some_and(|p| p.starts_with(root)) {
                    out.push(*finding);
                }
            }
        }
        out
    }

    #[tokio::test]
    async fn healthy_plist_is_info() {
        let tmp = tempfile::tempdir().unwrap();
        let agents = tmp.path().join("Library/LaunchAgents");
        // Program points at a binary that really exists (this crate's own binary
        // location isn't guaranteed, so use a file we create ourselves).
        let bin = tmp.path().join("real-binary");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        write_plist(
            &agents,
            "com.example.ok.plist",
            "com.example.ok",
            bin.to_str().unwrap(),
        );

        let mock = crate::runner::MockCommandRunner::new().on(
            "launchctl",
            &["list"],
            "PID\tStatus\tLabel\n1234\t0\tcom.example.ok\n",
        );
        let (ctx, mut rx) = ctx_with(&tmp, mock);

        LaunchdScanner.scan(ctx).await.unwrap();

        let findings = findings_under(&mut rx, tmp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].meta["label"], "com.example.ok");
        assert_eq!(findings[0].meta["running"], true);
        assert!(findings[0].remedies.is_empty());
    }

    #[tokio::test]
    async fn orphaned_plist_is_warning_with_two_step_remedy() {
        let tmp = tempfile::tempdir().unwrap();
        let agents = tmp.path().join("Library/LaunchAgents");
        write_plist(
            &agents,
            "com.example.orphan.plist",
            "com.example.orphan",
            "/nonexistent/path/to/binary",
        );

        let mock = crate::runner::MockCommandRunner::new()
            .on("launchctl", &["list"], "PID\tStatus\tLabel\n")
            .on("id", &["-u"], "501\n");
        let (ctx, mut rx) = ctx_with(&tmp, mock);

        LaunchdScanner.scan(ctx).await.unwrap();

        let findings = findings_under(&mut rx, tmp.path());
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.remedies.len(), 2);
        assert!(f.remedies[0].destructive);
        match &f.remedies[0].command {
            RemedyCommand::Shell { program, args } => {
                assert_eq!(program, "launchctl");
                assert_eq!(
                    args,
                    &vec![
                        "bootout".to_string(),
                        "gui/501/com.example.orphan".to_string()
                    ]
                );
            }
            other => panic!("expected Shell remedy, got {other:?}"),
        }
        match &f.remedies[1].command {
            RemedyCommand::Trash { path } => assert!(path.ends_with("com.example.orphan.plist")),
            other => panic!("expected Trash remedy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_launch_agents_dir_emits_nothing_under_fixture_home() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = crate::runner::MockCommandRunner::new().on("launchctl", &["list"], "");
        let (ctx, mut rx) = ctx_with(&tmp, mock);

        LaunchdScanner.scan(ctx).await.unwrap();
        assert!(findings_under(&mut rx, tmp.path()).is_empty());
    }
}
