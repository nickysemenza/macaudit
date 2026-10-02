//! Audit inherited process PATH for duplicates, missing directories, and
//! ordering surprises without executing shell startup configuration.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde_json::json;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::global_tools::shellpath::{self, ShellPath};
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

#[async_trait]
impl Scanner for ShellEnvScanner {
    fn id(&self) -> ScannerId {
        ScannerId::ShellEnv
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        let sp = shellpath::detect(&ctx).await;
        scan_path(&ctx, &sp).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanEvent;

    fn ctx_with(
        tmp: &tempfile::TempDir,
        mock: std::sync::Arc<crate::runner::MockCommandRunner>,
    ) -> (ScanCtx, tokio::sync::mpsc::Receiver<ScanEvent>) {
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let ctx = ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: std::sync::Arc::new(crate::config::Config::default()),
            paths: std::sync::Arc::new(crate::config::Paths::from_home(tmp.path())),
            runner: mock,
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

        let mock = std::sync::Arc::new(crate::runner::MockCommandRunner::new());
        let (ctx, mut rx) = ctx_with(&tmp, mock.clone());
        let sp = ShellPath {
            process_path: shellpath::split_path(&path_value),
            source: "process PATH".into(),
            ..Default::default()
        };
        scan_path(&ctx, &sp).await;
        assert!(mock.calls().is_empty());
        let findings = drain(&mut rx).await;

        assert_eq!(findings.len(), 4);

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

        assert_eq!(sys.meta["from_login_shell"], false);
    }

    #[tokio::test]
    async fn automatic_scan_does_not_execute_user_rc() {
        let tmp = tempfile::tempdir().unwrap();
        let sentinel = tmp.path().join("rc-was-executed");
        let rc = format!("printf executed > '{}'\n", sentinel.display());
        for path in [
            ".zshrc",
            ".zprofile",
            ".bashrc",
            ".bash_profile",
            ".config/fish/config.fish",
        ] {
            let path = tmp.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, &rc).unwrap();
        }
        let mock = std::sync::Arc::new(crate::runner::MockCommandRunner::new());
        let (ctx, mut rx) = ctx_with(&tmp, mock.clone());
        ShellEnvScanner.scan(ctx.clone()).await.unwrap();
        let findings = drain(&mut rx).await;
        assert!(mock.calls().is_empty());
        assert!(!sentinel.exists());
        assert!(!findings
            .iter()
            .any(|finding| finding.title == "Shell startup time"));
        for finding in findings
            .iter()
            .filter(|finding| finding.meta.get("entry").is_some())
        {
            assert_eq!(finding.meta["from_login_shell"], false);
            assert_eq!(finding.provenance.as_deref(), Some("process PATH"));
        }
        for path in [
            ".zshrc",
            ".zprofile",
            ".bashrc",
            ".bash_profile",
            ".config/fish/config.fish",
        ] {
            assert_eq!(std::fs::read_to_string(tmp.path().join(path)).unwrap(), rc);
        }
    }
}
