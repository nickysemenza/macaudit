//! ShellEnvScanner — the user's *login shell* `$PATH` (fish, zsh or bash,
//! found via directory services) looking for duplicates, entries pointing
//! at nonexistent directories, and ordering surprises (system bin shadowing
//! a brew/local bin); how that PATH differs from MacAudit's own process
//! PATH (agents and apps often launch with a different environment); and
//! shell startup latency.
//!
//! Reading the login shell's PATH starts that shell, which executes its
//! startup configuration. No rc file is read or shown.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::json;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::global_tools::shellpath::{self, ShellPath};
use crate::scan::{run_with_timeout, ScanCtx, Scanner};

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
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

#[async_trait]
impl Scanner for ShellEnvScanner {
    fn id(&self) -> ScannerId {
        ScannerId::ShellEnv
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        let sp = shellpath::detect(&ctx).await;
        scan_path(&ctx, &sp).await;
        scan_startup_time(&ctx, &sp).await;
        Ok(())
    }
}

async fn scan_path(ctx: &ScanCtx, sp: &ShellPath) {
    let (entries, source, from_shell): (Vec<PathBuf>, String, bool) = match &sp.shell_path {
        Some(p) => (p.clone(), sp.source.clone(), true),
        None => (sp.process_path.clone(), "process PATH".into(), false),
    };
    if entries.is_empty() {
        return;
    }
    let shell_name = sp.shell_name().map(str::to_string);
    let entries: Vec<String> = entries.iter().map(|p| p.display().to_string()).collect();
    let process: HashSet<String> = sp
        .process_path
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    let mut counts: HashMap<&str, u32> = HashMap::new();
    for e in &entries {
        *counts.entry(e.as_str()).or_insert(0) += 1;
    }
    let mut first_index: HashMap<&str, usize> = HashMap::new();
    for (i, e) in entries.iter().enumerate() {
        first_index.entry(e.as_str()).or_insert(i);
    }

    let mut seen: HashSet<&str> = HashSet::new();
    for (i, entry) in entries.iter().enumerate() {
        let entry = entry.as_str();
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
            "shell": shell_name,
            "from_login_shell": from_shell,
            "in_process_path": process.contains(entry),
            "group": "$PATH entries",
        });

        let mut finding = Finding::new(FindingKind::PathEntry, entry, entry.to_string())
            .detail(detail)
            .path(entry)
            .severity(severity)
            .provenance(source.clone())
            .meta(meta);
        // Dead PATH entry: we can't know which rc file added it (we only parse the
        // resolved $PATH), so we don't auto-edit shell config. Copy the offending
        // entry so the user can grep it out of their dotfiles themselves.
        if !exists {
            finding = finding.remedy(Remedy::new(
                "Copy path to clipboard",
                RemedyCommand::CopyToClipboard {
                    text: entry.to_string(),
                },
            ));
        }
        ctx.emit(finding).await;
    }

    // Login shell vs this process.
    if from_shell {
        let (only_shell, only_process) = sp.diff();
        let differs = !only_shell.is_empty() || !only_process.is_empty();
        let name = shell_name.clone().unwrap_or_else(|| "login shell".into());
        let detail = if differs {
            format!(
                "{name} PATH has {} entr{} this process lacks; this process has {} the shell lacks",
                only_shell.len(),
                if only_shell.len() == 1 { "y" } else { "ies" },
                only_process.len()
            )
        } else {
            format!("{name} PATH and this process PATH match")
        };
        ctx.emit(
            Finding::new(FindingKind::PathEntry, "__path_diff__", "Login shell vs process PATH")
                .detail(detail)
                .severity(if differs { Severity::Attention } else { Severity::Info })
                .provenance(format!("{} ({})", sp.source, shellpath::DISCLOSURE))
                .coverage("Tools launched by an agent or app inherit the process PATH, not the login shell's; command resolution can differ between the two.")
                .meta(json!({
                    "login_shell": sp.login_shell,
                    "shell": shell_name,
                    "source": sp.source,
                    "only_in_shell": only_shell,
                    "only_in_process": only_process,
                    "shell_entries": entries.len(),
                    "process_entries": sp.process_path.len(),
                    "notes": sp.notes,
                    "group": "Comparison",
                })),
        )
        .await;
    }
}

async fn scan_startup_time(ctx: &ScanCtx, sp: &ShellPath) {
    let Some(shell) = &sp.login_shell else {
        return;
    };
    let name = sp.shell_name().unwrap_or("");
    if shellpath::path_probe_args(name).is_none() {
        return; // unsupported shell: never start something we don't understand
    }
    let program = shell.display().to_string();
    let mut timings = Vec::with_capacity(3);
    for _ in 0..3 {
        let start = Instant::now();
        let res = run_with_timeout(ctx, &program, &["-i", "-c", "exit"], STARTUP_TIMEOUT).await;
        let elapsed = start.elapsed();
        if res.is_some() {
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
        "Median {name} startup: {:.0}ms across {} run(s)",
        median.as_secs_f64() * 1000.0,
        timings.len()
    );

    let meta = json!({
        "shell": name,
        "median_ms": median.as_secs_f64() * 1000.0,
        "runs_ms": timings.iter().map(|d| d.as_secs_f64() * 1000.0).collect::<Vec<_>>(),
        "group": "Startup",
    });

    let finding = Finding::new(
        FindingKind::PathEntry,
        "__shell_startup__",
        "Shell startup time",
    )
    .detail(detail)
    .severity(severity)
    .provenance(format!("{program} -i -c exit ×3 (starts the login shell)"))
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

        let user = tmp
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let mock = crate::runner::MockCommandRunner::new()
            .on(
                "dscl",
                &[".", "-read", &format!("/Users/{user}"), "UserShell"],
                "UserShell: /bin/zsh\n",
            )
            .on(
                "/bin/zsh",
                &["-ilc", "echo $PATH"],
                &format!("{path_value}\n"),
            )
            .on("/bin/zsh", &["-i", "-c", "exit"], "");
        let (ctx, mut rx) = ctx_with(&tmp, mock);

        ShellEnvScanner.scan(ctx).await.unwrap();
        let findings = drain(&mut rx).await;

        // 4 distinct PATH entries + shell-vs-process comparison + startup time.
        assert_eq!(findings.len(), 6);
        let diff = findings
            .iter()
            .find(|f| f.title == "Login shell vs process PATH")
            .unwrap();
        assert_eq!(diff.meta["shell"], "zsh");
        assert!(diff.meta["only_in_shell"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "/does/not/exist"));

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
        assert_eq!(startup.meta["shell"], "zsh");
        assert_eq!(sys.meta["from_login_shell"], true);
    }

    #[tokio::test]
    async fn fish_login_shell_uses_string_join() {
        let tmp = tempfile::tempdir().unwrap();
        let user = tmp
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let pnpm_bin = tmp.path().join("Library/pnpm/bin");
        std::fs::create_dir_all(&pnpm_bin).unwrap();
        let mock = crate::runner::MockCommandRunner::new()
            .on(
                "dscl",
                &[".", "-read", &format!("/Users/{user}"), "UserShell"],
                "UserShell: /opt/homebrew/bin/fish\n",
            )
            .on(
                "/opt/homebrew/bin/fish",
                &["-lc", "string join : $PATH"],
                &format!("{}:/usr/bin\n", pnpm_bin.display()),
            )
            .on("/opt/homebrew/bin/fish", &["-i", "-c", "exit"], "");
        let (ctx, mut rx) = ctx_with(&tmp, mock);
        ShellEnvScanner.scan(ctx).await.unwrap();
        let findings = drain(&mut rx).await;
        let pnpm = findings
            .iter()
            .find(|f| f.title == pnpm_bin.display().to_string())
            .unwrap();
        assert_eq!(pnpm.meta["shell"], "fish");
        assert_eq!(pnpm.meta["in_process_path"], false);
        assert!(pnpm.provenance.as_deref().unwrap().contains("string join"));
        let diff = findings
            .iter()
            .find(|f| f.title == "Login shell vs process PATH")
            .unwrap();
        assert_eq!(diff.severity, Severity::Attention);
        assert_eq!(
            diff.meta["only_in_shell"][0],
            pnpm_bin.display().to_string()
        );
    }

    #[tokio::test]
    async fn shell_path_failure_falls_back_to_process_path_and_notes_it() {
        let tmp = tempfile::tempdir().unwrap();
        let user = tmp
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let mock = crate::runner::MockCommandRunner::new()
            .on(
                "dscl",
                &[".", "-read", &format!("/Users/{user}"), "UserShell"],
                "UserShell: /bin/zsh\n",
            )
            .on_fail("/bin/zsh", &["-ilc", "echo $PATH"], 1, "boom")
            .on("/bin/zsh", &["-i", "-c", "exit"], "");
        let (ctx, mut rx) = ctx_with(&tmp, mock);

        ShellEnvScanner.scan(ctx).await.unwrap();
        let findings = drain(&mut rx).await;
        assert!(findings.iter().any(|f| f.title == "Shell startup time"));
        assert!(!findings
            .iter()
            .any(|f| f.title == "Login shell vs process PATH"));
        for f in findings.iter().filter(|f| f.meta.get("entry").is_some()) {
            assert_eq!(f.meta["from_login_shell"], false);
            assert_eq!(f.provenance.as_deref(), Some("process PATH"));
        }
    }
}
