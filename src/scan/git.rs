//! GitScanner — drains repo roots discovered by FsScanner and inspects each
//! with `git` (lane S2).
//!
//! It consumes `RepoDiscovery` values off the fs→git pipe until FsScanner drops
//! `repo_tx` and the channel closes (`recv` → `None`) — that is the sole
//! termination signal. Repos are processed with bounded concurrency (~8) via a
//! `Semaphore` + `JoinSet`. Every subprocess goes through `ctx.runner`, so the
//! whole scanner is testable with `MockCommandRunner`.
//!
//! **Vendored repos are skipped.** The walk (deliberately) descends into
//! gitignored territory to find build artifacts, so it also discovers clones
//! that package managers made — SwiftPM `.build`/`SourcePackages/checkouts`,
//! `~/.cargo/git/checkouts`, uv/plugin caches, `node_modules`. Those aren't the
//! user's working repos. Two filters: a path-component denylist for known
//! vendor locations, and a `git check-ignore` probe against the nearest
//! ancestor repo (a repo living inside another repo's gitignored dir — e.g. a
//! checkout under a gitignored `build/` — is vendored by definition).
//!
//! **Sizes**: each surviving repo's working tree is `du`'d through the shared
//! size cache (same mtime+TTL semantics as Disk artifacts), emitted as a
//! deferred size update.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde_json::json;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::sizing::du_blocks;
use crate::scan::{ScanCtx, Scanner};
use crate::size_cache::{self, is_fresh, root_mtime_secs, CachedSize, SizeCache};

/// Max repos inspected at once.
const MAX_CONCURRENCY: usize = 8;

/// Path components that mark a repo as a package-manager/tool checkout rather
/// than a user working repo. Matched against ancestor components only (never
/// the repo directory's own name).
const VENDOR_COMPONENTS: &[&str] = &[
    "node_modules",
    "checkouts",      // cargo/uv/SwiftPM clone caches
    "SourcePackages", // Xcode-managed SwiftPM
    ".build",         // SwiftPM
    "Pods",
    "vendor",
    ".cargo",
    ".cache",
    "Caches",
    "cache",
    "DerivedData",
    "marketplaces", // plugin marketplaces (managed clones)
];

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

        // Shared size cache (same db + staleness semantics as Disk artifacts).
        let paths_load = ctx.paths.clone();
        let cache: Arc<HashMap<PathBuf, CachedSize>> = Arc::new(
            tokio::task::spawn_blocking(move || {
                SizeCache::open(&size_cache::db_path(&paths_load))
                    .and_then(|c| c.load_all())
                    .unwrap_or_default()
            })
            .await
            .unwrap_or_default(),
        );
        let fresh_entries: Arc<Mutex<Vec<(PathBuf, CachedSize)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let ttl_hours = ctx.config.scan.size_cache_ttl_hours;

        let sem = Arc::new(Semaphore::new(MAX_CONCURRENCY));
        let mut set: JoinSet<()> = JoinSet::new();

        let mut guard = rx_arc.lock().await;
        while let Some(disc) = guard.recv().await {
            if ctx.token.is_cancelled() {
                break;
            }
            // Cheap vendored filter first — no subprocess, no task.
            if has_vendor_component(&disc.root) {
                continue;
            }
            // Backpressure: acquire before spawning so at most N run at once.
            let permit = sem.clone().acquire_owned().await?;
            let ctx = ctx.clone();
            let cache = cache.clone();
            let fresh = fresh_entries.clone();
            set.spawn(async move {
                let _permit = permit;
                let root = disc.root;

                // A repo living inside another repo's gitignored directory is a
                // vendored checkout (SwiftPM/pip/etc. clones under a gitignored
                // build dir) — skip it.
                if let Some(ancestor) = nearest_ancestor_repo(&root, &ctx.paths.home) {
                    if is_ignored_by(&ctx, &ancestor, &root).await {
                        return;
                    }
                }

                let Some(finding) = inspect_repo(&ctx, root.clone()).await else {
                    return;
                };

                // Attach the working-tree size: cached when fresh, else emit
                // unsized now and follow up with a measured re-emit (upsert).
                let root_mtime = root_mtime_secs(&root);
                let cached = cache
                    .get(&root)
                    .copied()
                    .filter(|c| is_fresh(c, root_mtime, now_secs, ttl_hours));
                match cached {
                    Some(c) => {
                        let mut f = finding.size(c.size);
                        if let Some(obj) = f.meta.as_object_mut() {
                            obj.insert("size_cached".to_string(), json!(true));
                        }
                        ctx.emit(f).await;
                    }
                    None if root.exists() => {
                        ctx.emit(finding.clone()).await;
                        let du_root = root.clone();
                        let token = ctx.token.clone();
                        let size = tokio::task::spawn_blocking(move || {
                            du_blocks(&du_root, &|| token.is_cancelled())
                        })
                        .await
                        .unwrap_or(0);
                        // Same rule as fs.rs: never emit/record a size measured
                        // under cancellation — it's a partial sum.
                        if ctx.token.is_cancelled() {
                            return;
                        }
                        fresh.lock().unwrap().push((
                            root,
                            CachedSize {
                                size,
                                computed_at: now_secs,
                                root_mtime,
                            },
                        ));
                        ctx.emit(finding.size(size)).await;
                    }
                    None => ctx.emit(finding).await, // path gone (tests/races)
                }
            });
        }
        // Release the lock so nothing else blocks, then drain in-flight work.
        drop(guard);
        while set.join_next().await.is_some() {}

        // Persist freshly measured sizes (best-effort; skipped on cancellation
        // so a partial scan can't poison the cache).
        let entries: Vec<(PathBuf, CachedSize)> = if ctx.token.is_cancelled() {
            Vec::new()
        } else {
            std::mem::take(&mut *fresh_entries.lock().unwrap())
        };
        if !entries.is_empty() {
            let paths_save = ctx.paths.clone();
            let _ = tokio::task::spawn_blocking(move || {
                SizeCache::open(&size_cache::db_path(&paths_save))
                    .and_then(|mut c| c.upsert_batch(&entries))
            })
            .await;
        }
        Ok(())
    }
}

/// Does any ancestor path component (not the repo dir's own name) mark this as
/// a package-manager/tool checkout?
fn has_vendor_component(root: &Path) -> bool {
    let mut components: Vec<&str> = root.iter().filter_map(|c| c.to_str()).collect();
    components.pop(); // the repo directory's own name is exempt
    components.iter().any(|c| VENDOR_COMPONENTS.contains(c))
}

/// Nearest ancestor of `root` (strictly above it, within `home`) that is itself
/// a git repo (`.git` dir or worktree file). `None` when the repo isn't nested.
fn nearest_ancestor_repo(root: &Path, home: &Path) -> Option<PathBuf> {
    let mut cur = root.parent();
    while let Some(dir) = cur {
        if !dir.starts_with(home) {
            return None;
        }
        if dir.join(".git").exists() {
            return Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    None
}

/// Is `path` gitignored from the perspective of `ancestor_repo`? Uses
/// `git check-ignore -q` (exit 0 = ignored, 1 = not, anything else = unknown ⇒
/// treated as not ignored so we never silently drop a real repo).
async fn is_ignored_by(ctx: &ScanCtx, ancestor_repo: &Path, path: &Path) -> bool {
    let repo = ancestor_repo.to_string_lossy().into_owned();
    let target = path.to_string_lossy().into_owned();
    matches!(
        ctx.runner
            .run(
                "git",
                &["-C", &repo, "check-ignore", "-q", "--", &target],
                &ctx.token,
            )
            .await,
        Ok(out) if out.status == 0
    )
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
    /// Whether the branch has an upstream at all. Without one, `branch.ab`
    /// never appears — every local commit is unpushed, but `ahead` reads 0.
    has_upstream: bool,
}

/// Parse porcelain v2 output. Header lines start with `# `; any other non-empty
/// line is a change/untracked entry ⇒ the tree is dirty.
fn parse_status(out: &str) -> RepoStatus {
    let mut st = RepoStatus::default();
    for line in out.lines() {
        if let Some(header) = line.strip_prefix("# ") {
            if let Some(name) = header.strip_prefix("branch.head ") {
                st.branch = Some(name.trim().to_string());
            } else if header.strip_prefix("branch.upstream ").is_some() {
                st.has_upstream = true;
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

    // Commits on a branch with no upstream are unpushed by definition —
    // `branch.ab` never appears for them, so `ahead` alone under-reports.
    let no_upstream = !st.has_upstream && last_used.is_some();
    let unpushed = st.ahead > 0 || no_upstream;
    let severity = if st.dirty || unpushed {
        Severity::Attention
    } else {
        Severity::Info
    };

    let mut bits = Vec::new();
    if st.dirty {
        bits.push("uncommitted changes".to_string());
    }
    if st.ahead > 0 {
        bits.push(format!("{} unpushed", st.ahead));
    } else if no_upstream {
        bits.push("no upstream (nothing pushed)".to_string());
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
            "has_upstream": st.has_upstream,
        }))
        .remedy(Remedy {
            label: "Reveal in Finder".into(),
            command: RemedyCommand::RevealInFinder {
                path: root.to_path_buf(),
            },
            reclaims_bytes: None,
            destructive: false,
            alternative: false,
            guard: None,
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

    #[test]
    fn vendor_components_filter_known_checkout_paths() {
        for p in [
            "/Users/x/dev/paste/build/dogfood/SourcePackages/checkouts/swift-markdown-ui",
            "/Users/x/dev/paste/OverboardKit/.build/checkouts/Highlightr",
            "/Users/x/.cargo/git/checkouts/ingredient-parser-b/badc484",
            "/Users/x/.cache/uv/git-v0/checkouts/fb54253",
            "/Users/x/.claude/plugins/marketplaces/every-marketplace",
            "/Users/x/.cursor/plugins/cache/cursor-public/cloud",
            "/Users/x/code/app/node_modules/leftpad",
        ] {
            assert!(has_vendor_component(Path::new(p)), "should skip: {p}");
        }
        for p in [
            "/Users/x/dev/gourd",
            "/Users/x/Desktop/ansible",
            "/Users/x/.dotfiles", // repo under a hidden dir is NOT vendored
            "/Users/x/dev/cache-server", // own name is exempt from the list
        ] {
            assert!(!has_vendor_component(Path::new(p)), "should keep: {p}");
        }
    }

    #[tokio::test]
    async fn nested_gitignored_repo_is_skipped_and_not_ignored_is_kept() {
        // Real dirs so ancestor discovery works: home/outer is a repo (has
        // .git), home/outer/build/inner is a nested repo.
        let home = tempfile::tempdir().unwrap();
        let outer = home.path().join("outer");
        let inner = outer.join("target-dir/inner");
        std::fs::create_dir_all(outer.join(".git")).unwrap();
        std::fs::create_dir_all(inner.join(".git")).unwrap();
        let outer_s = outer.to_string_lossy().into_owned();
        let inner_s = inner.to_string_lossy().into_owned();

        // First run: check-ignore says IGNORED (exit 0) ⇒ repo skipped entirely.
        let runner = MockCommandRunner::new().on(
            "git",
            &["-C", &outer_s, "check-ignore", "-q", "--", &inner_s],
            "",
        );
        let (mut ctx, mut rx, repo_tx) = ctx_with(runner);
        ctx.paths = Arc::new(Paths::from_home(home.path()));
        repo_tx
            .send(RepoDiscovery {
                root: inner.clone(),
            })
            .await
            .unwrap();
        drop(repo_tx);
        GitScanner.scan(ctx).await.unwrap();
        assert!(
            rx.try_recv().is_err(),
            "gitignored nested repo must be skipped"
        );

        // Second run: check-ignore exits 1 (not ignored) ⇒ repo is inspected.
        let runner = MockCommandRunner::new()
            .on_fail(
                "git",
                &["-C", &outer_s, "check-ignore", "-q", "--", &inner_s],
                1,
                "",
            )
            .on(
                "git",
                &["-C", &inner_s, "status", "--porcelain=v2", "--branch"],
                "# branch.head main\n# branch.ab +0 -0\n",
            )
            .on(
                "git",
                &["-C", &inner_s, "log", "-1", "--format=%ct"],
                "1700000000\n",
            )
            .on("git", &["-C", &inner_s, "stash", "list"], "");
        let (mut ctx, mut rx, repo_tx) = ctx_with(runner);
        ctx.paths = Arc::new(Paths::from_home(home.path()));
        repo_tx.send(RepoDiscovery { root: inner }).await.unwrap();
        drop(repo_tx);
        GitScanner.scan(ctx).await.unwrap();
        let mut names = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                names.push(finding.title.clone());
            }
        }
        assert!(
            names.contains(&"inner".to_string()),
            "non-ignored nested repo must be kept, got {names:?}"
        );
    }

    #[tokio::test]
    async fn real_repo_dir_gets_sized_and_cached() {
        // A repo root that actually exists on disk gets an unsized emit
        // followed by a sized re-emit (same id), and the size lands in the db.
        let home = tempfile::tempdir().unwrap();
        let repo = home.path().join("myrepo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::write(repo.join("README.md"), vec![b'x'; 4096]).unwrap();
        let repo_s = repo.to_string_lossy().into_owned();

        let runner = MockCommandRunner::new()
            .on(
                "git",
                &["-C", &repo_s, "status", "--porcelain=v2", "--branch"],
                "# branch.head main\n# branch.ab +0 -0\n",
            )
            .on(
                "git",
                &["-C", &repo_s, "log", "-1", "--format=%ct"],
                "1700000000\n",
            )
            .on("git", &["-C", &repo_s, "stash", "list"], "");
        let (mut ctx, mut rx, repo_tx) = ctx_with(runner);
        ctx.paths = Arc::new(Paths::from_home(home.path()));
        repo_tx
            .send(RepoDiscovery { root: repo.clone() })
            .await
            .unwrap();
        drop(repo_tx);
        GitScanner.scan(ctx).await.unwrap();

        let mut sized: Option<Finding> = None;
        let mut count = 0;
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                count += 1;
                if finding.size_bytes.is_some() {
                    sized = Some(*finding);
                }
            }
        }
        assert_eq!(count, 2, "unsized emit then sized re-emit");
        let sized = sized.expect("sized re-emit");
        assert!(sized.size_bytes.unwrap() >= 4096);

        let db = size_cache::db_path(&Paths::from_home(home.path()));
        let cache = SizeCache::open(&db).unwrap().load_all().unwrap();
        assert!(cache.contains_key(&repo), "repo size persisted to cache");
    }

    #[tokio::test]
    async fn branch_without_upstream_counts_as_unpushed() {
        // `branch.ab` never appears without an upstream, so ahead reads 0 —
        // but every commit on such a branch is unpushed by definition.
        let repo = "/Users/x/code/local-only";
        let runner = MockCommandRunner::new()
            .on(
                "git",
                &["-C", repo, "status", "--porcelain=v2", "--branch"],
                "# branch.head main\n",
            )
            .on(
                "git",
                &["-C", repo, "log", "-1", "--format=%ct"],
                "1700000000\n",
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
        assert_eq!(f.severity, Severity::Attention);
        assert_eq!(f.meta["has_upstream"], false);
        assert!(f.detail.contains("no upstream"));
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
                "# branch.head main\n# branch.upstream origin/main\n# branch.ab +0 -0\n",
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
