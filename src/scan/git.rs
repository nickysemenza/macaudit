//! GitScanner — drains repo roots discovered by FsScanner and inspects each
//! with `git` (lane S2).
//!
//! It consumes `RepoDiscovery` values off the fs→git pipe until FsScanner drops
//! `repo_tx` and the channel closes (`recv` → `None`) — that is the sole
//! termination signal. Repos are processed with bounded concurrency (~8) via a
//! `Semaphore` + `JoinSet`. Every subprocess goes through `ctx.runner`, so the
//! whole scanner is testable with `MockCommandRunner`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde_json::json;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::{ScanCtx, Scanner};

/// Max repos inspected at once.
const MAX_CONCURRENCY: usize = 8;

#[derive(Default)]
pub struct GitScanner;

#[async_trait]
impl Scanner for GitScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Git
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        // No pipe wired ⇒ Git wasn't part of this run.
        let Some(rx_arc) = ctx.repo_rx.clone() else {
            return Ok(());
        };

        let sem = Arc::new(Semaphore::new(MAX_CONCURRENCY));
        let mut set: JoinSet<()> = JoinSet::new();

        let mut guard = rx_arc.lock().await;
        while let Some(disc) = guard.recv().await {
            if ctx.token.is_cancelled() {
                break;
            }
            // Backpressure: acquire before spawning so at most N run at once.
            let permit = sem.clone().acquire_owned().await?;
            let ctx = ctx.clone();
            set.spawn(async move {
                let _permit = permit;
                if let Some(finding) = inspect_repo(&ctx, disc.root).await {
                    ctx.emit(finding).await;
                }
            });
        }
        // Release the lock so nothing else blocks, then drain in-flight work.
        drop(guard);
        while set.join_next().await.is_some() {}
        Ok(())
    }
}

/// Inspect one repo root. Returns `None` only if the repo can't be queried at
/// all (e.g. `git status` errors) — otherwise emits a best-effort finding.
async fn inspect_repo(ctx: &ScanCtx, root: PathBuf) -> Option<Finding> {
    let root_str = root.to_string_lossy().into_owned();

    let status = ctx
        .runner
        .run(
            "git",
            &["-C", &root_str, "status", "--porcelain=v2", "--branch"],
            &ctx.token,
        )
        .await
        .ok()?;
    if !status.success() {
        return None;
    }
    let st = parse_status(&status.stdout_str());

    // Last-commit time — best effort (empty repos have no commits).
    let last_used = match ctx
        .runner
        .run(
            "git",
            &["-C", &root_str, "log", "-1", "--format=%ct"],
            &ctx.token,
        )
        .await
    {
        Ok(out) if out.success() => out
            .stdout_str()
            .trim()
            .parse::<u64>()
            .ok()
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs)),
        _ => None,
    };

    // Stash count — best effort.
    let stash_count = match ctx
        .runner
        .run("git", &["-C", &root_str, "stash", "list"], &ctx.token)
        .await
    {
        Ok(out) if out.success() => out
            .stdout_str()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count(),
        _ => 0,
    };

    Some(build_finding(&root, &root_str, st, last_used, stash_count))
}

/// Parsed `git status --porcelain=v2 --branch` signals.
#[derive(Default, Debug, PartialEq, Eq)]
struct RepoStatus {
    dirty: bool,
    ahead: u64,
    behind: u64,
    branch: Option<String>,
}

/// Parse porcelain v2 output. Header lines start with `# `; any other non-empty
/// line is a change/untracked entry ⇒ the tree is dirty.
fn parse_status(out: &str) -> RepoStatus {
    let mut st = RepoStatus::default();
    for line in out.lines() {
        if let Some(header) = line.strip_prefix("# ") {
            if let Some(name) = header.strip_prefix("branch.head ") {
                st.branch = Some(name.trim().to_string());
            } else if let Some(ab) = header.strip_prefix("branch.ab ") {
                // Format: "+<ahead> -<behind>"
                for tok in ab.split_whitespace() {
                    if let Some(a) = tok.strip_prefix('+') {
                        st.ahead = a.parse().unwrap_or(0);
                    } else if let Some(b) = tok.strip_prefix('-') {
                        st.behind = b.parse().unwrap_or(0);
                    }
                }
            }
        } else if !line.trim().is_empty() {
            // `1 `, `2 `, `u `, `? ` entries all mean uncommitted/untracked work.
            st.dirty = true;
        }
    }
    st
}

fn build_finding(
    root: &std::path::Path,
    root_str: &str,
    st: RepoStatus,
    last_used: Option<SystemTime>,
    stash_count: usize,
) -> Finding {
    let name = root
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| root_str.to_string());

    let unpushed = st.ahead > 0;
    let severity = if st.dirty || unpushed {
        Severity::Attention
    } else {
        Severity::Info
    };

    let mut bits = Vec::new();
    if st.dirty {
        bits.push("uncommitted changes".to_string());
    }
    if unpushed {
        bits.push(format!("{} unpushed", st.ahead));
    }
    if st.behind > 0 {
        bits.push(format!("{} behind", st.behind));
    }
    if stash_count > 0 {
        bits.push(format!("{stash_count} stash(es)"));
    }
    let detail = if bits.is_empty() {
        "clean".to_string()
    } else {
        bits.join(", ")
    };

    let mut f = Finding::new(FindingKind::GitRepo, root_str, name)
        .path(root.to_path_buf())
        .detail(detail)
        .severity(severity)
        .meta(json!({
            "dirty": st.dirty,
            "ahead": st.ahead,
            "behind": st.behind,
            "stash_count": stash_count,
            "branch": st.branch,
        }))
        .remedy(Remedy {
            label: "Reveal in Finder".into(),
            command: RemedyCommand::RevealInFinder {
                path: root.to_path_buf(),
            },
            reclaims_bytes: None,
            destructive: false,
        });
    if let Some(lu) = last_used {
        f = f.last_used(lu);
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Paths};
    use crate::model::ScanEvent;
    use crate::runner::MockCommandRunner;
    use crate::scan::pipe::{repo_channel, RepoDiscovery};
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    fn ctx_with(
        runner: MockCommandRunner,
    ) -> (
        ScanCtx,
        mpsc::Receiver<ScanEvent>,
        crate::scan::pipe::RepoSender,
    ) {
        let (tx, rx) = mpsc::channel(256);
        let (repo_tx, repo_rx) = repo_channel();
        let ctx = ScanCtx {
            tx,
            token: CancellationToken::new(),
            gen: 1,
            config: Arc::new(Config::default()),
            paths: Arc::new(Paths::from_home("/tmp/none")),
            runner: Arc::new(runner),
            current: ScannerId::Git,
            repo_tx: None,
            repo_rx: Some(Arc::new(tokio::sync::Mutex::new(repo_rx))),
            fs_discovery_only: false,
        };
        (ctx, rx, repo_tx)
    }

    #[test]
    fn parses_dirty_ahead_behind_branch() {
        let out = "\
# branch.oid abcdef
# branch.head main
# branch.upstream origin/main
# branch.ab +2 -1
1 .M N... 100644 100644 100644 aaa bbb file.rs
? untracked.txt
";
        let st = parse_status(out);
        assert!(st.dirty);
        assert_eq!(st.ahead, 2);
        assert_eq!(st.behind, 1);
        assert_eq!(st.branch.as_deref(), Some("main"));
    }

    #[test]
    fn parses_clean_repo() {
        let out = "# branch.head main\n# branch.ab +0 -0\n";
        let st = parse_status(out);
        assert!(!st.dirty);
        assert_eq!(st.ahead, 0);
        assert_eq!(st.behind, 0);
    }

    #[tokio::test]
    async fn no_pipe_returns_ok() {
        let (tx, _rx) = mpsc::channel(4);
        let ctx = ScanCtx {
            tx,
            token: CancellationToken::new(),
            gen: 1,
            config: Arc::new(Config::default()),
            paths: Arc::new(Paths::from_home("/tmp/none")),
            runner: Arc::new(MockCommandRunner::new()),
            current: ScannerId::Git,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        GitScanner.scan(ctx).await.unwrap();
    }

    #[tokio::test]
    async fn emits_finding_with_status_meta() {
        let repo = "/Users/x/code/myrepo";
        let runner = MockCommandRunner::new()
            .on(
                "git",
                &["-C", repo, "status", "--porcelain=v2", "--branch"],
                "# branch.head main\n# branch.ab +3 -0\n1 .M N... 100644 100644 100644 a b f.rs\n",
            )
            .on(
                "git",
                &["-C", repo, "log", "-1", "--format=%ct"],
                "1700000000\n",
            )
            .on(
                "git",
                &["-C", repo, "stash", "list"],
                "stash@{0}: WIP\nstash@{1}: WIP2\n",
            );

        let (ctx, mut rx, repo_tx) = ctx_with(runner);

        // Feed one repo, then drop the sender so the scanner terminates.
        repo_tx
            .send(RepoDiscovery {
                root: PathBuf::from(repo),
            })
            .await
            .unwrap();
        drop(repo_tx);

        GitScanner.scan(ctx).await.unwrap();

        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::GitRepo);
        assert_eq!(f.severity, Severity::Attention); // dirty + ahead
        assert_eq!(f.meta["dirty"], true);
        assert_eq!(f.meta["ahead"], 3);
        assert_eq!(f.meta["behind"], 0);
        assert_eq!(f.meta["stash_count"], 2);
        assert_eq!(f.meta["branch"], "main");
        assert!(f.last_used.is_some());
    }

    #[tokio::test]
    async fn clean_repo_is_info_severity() {
        let repo = "/Users/x/code/clean";
        let runner = MockCommandRunner::new()
            .on(
                "git",
                &["-C", repo, "status", "--porcelain=v2", "--branch"],
                "# branch.head main\n# branch.ab +0 -0\n",
            )
            .on(
                "git",
                &["-C", repo, "log", "-1", "--format=%ct"],
                "1699999999\n",
            )
            .on("git", &["-C", repo, "stash", "list"], "");

        let (ctx, mut rx, repo_tx) = ctx_with(runner);
        repo_tx
            .send(RepoDiscovery {
                root: PathBuf::from(repo),
            })
            .await
            .unwrap();
        drop(repo_tx);

        GitScanner.scan(ctx).await.unwrap();

        let mut f = None;
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                f = Some(*finding);
            }
        }
        let f = f.unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.meta["dirty"], false);
        assert_eq!(f.meta["stash_count"], 0);
    }
}
