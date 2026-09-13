//! ShellEnvScanner — parses `$PATH` from a login shell looking for
//! duplicates, entries pointing at nonexistent directories, and ordering
//! surprises (system bin shadowing a brew/local bin); also measures shell
//! startup latency.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::json;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct ShellEnvScanner;

/// Directories that ship with the OS. If one of these precedes a
/// brew/local bin directory in `$PATH`, binaries installed there shadow the
/// user's brew-managed versions of the same name.
const SYSTEM_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
const BREW_DIRS: &[&str] = &[
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
];

const SLOW_STARTUP_THRESHOLD: Duration = Duration::from_millis(500);

#[async_trait]
impl Scanner for ShellEnvScanner {
    fn id(&self) -> ScannerId {
        ScannerId::ShellEnv
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        scan_path(&ctx).await;
        scan_startup_time(&ctx).await;
        Ok(())
    }
}

async fn scan_path(ctx: &ScanCtx) {
    let out = match ctx
        .runner
        .run("zsh", &["-ilc", "echo $PATH"], &ctx.token)
        .await
    {
        Ok(o) if o.success() => o,
        _ => return,
    };

    // Interactive login shells may print MOTD/rc noise before the `echo`
    // output; the PATH value is the last non-empty line.
    let raw = out.stdout_str();
    let Some(path_line) = raw.lines().rev().find(|l| !l.trim().is_empty()) else {
        return;
    };

    let entries: Vec<&str> = path_line
        .trim()
        .split(':')
        .filter(|s| !s.is_empty())
        .collect();
    if entries.is_empty() {
        return;
    }

    let mut counts: HashMap<&str, u32> = HashMap::new();
    for &e in &entries {
        *counts.entry(e).or_insert(0) += 1;
    }
    let mut first_index: HashMap<&str, usize> = HashMap::new();
    for (i, &e) in entries.iter().enumerate() {
        first_index.entry(e).or_insert(i);
    }

    let mut seen: HashSet<&str> = HashSet::new();
    for (i, &entry) in entries.iter().enumerate() {
        if !seen.insert(entry) {
            continue; // only report each distinct entry once, at its first occurrence
        }

        let exists = Path::new(entry).is_dir();
        let occurrences = counts[entry];

        let shadowed_by = if BREW_DIRS.contains(&entry) {
            SYSTEM_DIRS
                .iter()
                .filter_map(|sd| first_index.get(sd).map(|si| (*sd, *si)))
                .filter(|(_, si)| *si < i)
                .min_by_key(|(_, si)| *si)
                .map(|(sd, _)| sd.to_string())
        } else {
            None
        };

        let mut issues = Vec::new();
        if !exists {
            issues.push("directory does not exist".to_string());
        }
        if occurrences > 1 {
            issues.push(format!("duplicated {occurrences}x in PATH"));
        }
        if let Some(sd) = &shadowed_by {
            issues.push(format!("shadowed by earlier system directory {sd}"));
        }

        let severity = if issues.is_empty() {
            Severity::Info
        } else {
            Severity::Attention
        };
        let detail = if issues.is_empty() {
            format!("{entry} — OK")
        } else {
            format!("{entry} — {}", issues.join("; "))
        };

        let meta = json!({
            "entry": entry,
            "index": i,
            "occurrences": occurrences,
            "exists": exists,
            "shadowed_by": shadowed_by,
        });

        let mut finding = Finding::new(FindingKind::PathEntry, entry, entry.to_string())
            .detail(detail)
            .path(entry)
            .severity(severity)
            .meta(meta);
        // Dead PATH entry: we can't know which rc file added it (we only parse the
        // resolved $PATH), so we don't auto-edit shell config. Copy the offending
        // entry so the user can grep it out of their dotfiles themselves.
        if !exists {
            finding = finding.remedy(Remedy {
                label: "Copy path to clipboard".to_string(),
                command: RemedyCommand::CopyToClipboard {
                    text: entry.to_string(),
                },
                reclaims_bytes: None,
                destructive: false,
                alternative: false,
                guard: None,
            });
        }
        ctx.emit(finding).await;
    }
}

async fn scan_startup_time(ctx: &ScanCtx) {
    let mut timings = Vec::with_capacity(3);
    for _ in 0..3 {
        let start = Instant::now();
        let res = ctx
            .runner
            .run("zsh", &["-i", "-c", "exit"], &ctx.token)
            .await;
        let elapsed = start.elapsed();
        if res.is_ok() {
            timings.push(elapsed);
        }
    }
    if timings.is_empty() {
        return;
    }
    timings.sort();
    let median = timings[timings.len() / 2];

    let severity = if median > SLOW_STARTUP_THRESHOLD {
        Severity::Attention
    } else {
        Severity::Info
    };
    let detail = format!(
        "Median shell startup: {:.0}ms across {} run(s)",
        median.as_secs_f64() * 1000.0,
        timings.len()
    );

    let meta = json!({
        "median_ms": median.as_secs_f64() * 1000.0,
        "runs_ms": timings.iter().map(|d| d.as_secs_f64() * 1000.0).collect::<Vec<_>>(),
    });

    let finding = Finding::new(
        FindingKind::PathEntry,
        "__shell_startup__",
        "Shell startup time",
    )
    .detail(detail)
    .severity(severity)
    .meta(meta);
    ctx.emit(finding).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanEvent;

    fn ctx_with(
        tmp: &tempfile::TempDir,
        mock: crate::runner::MockCommandRunner,
    ) -> (ScanCtx, tokio::sync::mpsc::Receiver<ScanEvent>) {
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let ctx = ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: std::sync::Arc::new(crate::config::Config::default()),
            paths: std::sync::Arc::new(crate::config::Paths::from_home(tmp.path())),
            runner: std::sync::Arc::new(mock),
            current: ScannerId::ShellEnv,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        (ctx, rx)
    }

    async fn drain(rx: &mut tokio::sync::mpsc::Receiver<ScanEvent>) -> Vec<crate::model::Finding> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                out.push(*finding);
            }
        }
        out
    }

    #[tokio::test]
    async fn detects_duplicate_missing_and_shadowed_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&real_dir).unwrap();
        let real = real_dir.to_str().unwrap();

        // /usr/bin (system, real on any macOS/unix box) appears before
        // /opt/homebrew/bin (brew) ⇒ shadowing. /does/not/exist is missing.
        // `real` is duplicated.
        let path_value = format!("/usr/bin:{real}:/opt/homebrew/bin:/does/not/exist:{real}");

        let mock = crate::runner::MockCommandRunner::new()
            .on("zsh", &["-ilc", "echo $PATH"], &format!("{path_value}\n"))
            .on("zsh", &["-i", "-c", "exit"], "");
        let (ctx, mut rx) = ctx_with(&tmp, mock);

        ShellEnvScanner.scan(ctx).await.unwrap();
        let findings = drain(&mut rx).await;

        // 4 distinct PATH entries + 1 startup-time finding.
        assert_eq!(findings.len(), 5);

        let by_entry = |e: &str| {
            findings
                .iter()
                .find(|f| f.meta.get("entry").and_then(|v| v.as_str()) == Some(e))
                .unwrap_or_else(|| panic!("no finding for {e}"))
        };

        let dup = by_entry(real);
        assert_eq!(dup.severity, Severity::Attention);
        assert_eq!(dup.meta["occurrences"], 2);

        let missing = by_entry("/does/not/exist");
        assert_eq!(missing.severity, Severity::Attention);
        assert_eq!(missing.meta["exists"], false);
        // A dead PATH entry gets a copy-to-clipboard remedy (non-destructive);
        // we never auto-edit shell rc files.
        assert!(matches!(
            missing.remedies.as_slice(),
            [Remedy {
                command: RemedyCommand::CopyToClipboard { text },
                destructive: false,
                ..
            }] if text == "/does/not/exist"
        ));

        let shadowed = by_entry("/opt/homebrew/bin");
        assert_eq!(shadowed.severity, Severity::Attention);
        assert_eq!(shadowed.meta["shadowed_by"], "/usr/bin");

        let sys = by_entry("/usr/bin");
        assert_eq!(sys.severity, Severity::Info);
        // An existing directory is not a dead entry → no remedy.
        assert!(sys.remedies.is_empty());

        let startup = findings
            .iter()
            .find(|f| f.title == "Shell startup time")
            .unwrap();
        assert_eq!(startup.severity, Severity::Info); // mock returns instantly
        assert!(startup.meta["median_ms"].is_number());
    }

    #[tokio::test]
    async fn no_path_output_emits_only_startup_finding() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = crate::runner::MockCommandRunner::new()
            .on_fail("zsh", &["-ilc", "echo $PATH"], 1, "boom")
            .on("zsh", &["-i", "-c", "exit"], "");
        let (ctx, mut rx) = ctx_with(&tmp, mock);

        ShellEnvScanner.scan(ctx).await.unwrap();
        let findings = drain(&mut rx).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Shell startup time");
    }
}
