//! FsScanner — the parallel filesystem walk (lane S2).
//!
//! One `ignore::WalkParallel` pass over the configured roots feeds *many* cheap
//! detectors: build-artifact dirs (each gated on a project marker), `.git`
//! roots (piped to GitScanner), and large loose files. Artifact hits are emitted
//! immediately with `size_bytes: None`, then re-emitted (same canonical key ⇒
//! same `FindingId`) once a `rayon` sizing pass has summed their on-disk blocks.
//! A fixed set of well-known cache/backup paths is sized directly, no walk.
//!
//! Concurrency contract (spec §1): the sync `WalkParallel` runs inside
//! `spawn_blocking`; walker/rayon threads bridge back with `blocking_send`. The
//! walk drops `repo_tx` the instant it finishes so GitScanner's channel closes
//! before the (potentially long) sizing pass — the two run concurrently.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use ignore::{WalkBuilder, WalkState};
use rayon::prelude::*;
use serde_json::json;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScanEvent, ScannerId, Severity};
use crate::scan::pipe::{RepoDiscovery, RepoSender};
use crate::scan::sizing::{du_blocks, on_disk_bytes};
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct FsScanner;

/// Project markers that justify treating a generic `build`/`dist` dir as an
/// artifact (rather than a hand-authored source directory).
const PROJECT_MARKERS: &[&str] = &[
    "package.json",
    "Cargo.toml",
    "pyproject.toml",
    "setup.py",
    "go.mod",
    "CMakeLists.txt",
    "Makefile",
    "pom.xml",
    "build.gradle",
];

/// An artifact directory awaiting a size computation + re-emit.
struct Hit {
    path: PathBuf,
    label: String,
    last_used: Option<SystemTime>,
    stale: bool,
}

/// Immutable state shared with every `WalkParallel` visitor closure. Held behind
/// an `Arc` so per-thread visitors are cheap `'static` clones; dropping the last
/// clone (after the walk) releases `repo_tx` and closes the fs→git pipe.
struct WalkShared {
    tx: tokio::sync::mpsc::Sender<ScanEvent>,
    gen: u64,
    token: tokio_util::sync::CancellationToken,
    config: Arc<crate::config::Config>,
    repo_tx: Option<RepoSender>,
    hits: Arc<Mutex<Vec<Hit>>>,
    /// Never descend into these (tilde-expanded ignore list).
    ignore_paths: Vec<PathBuf>,
    /// `~/Library` — skipped wholesale (fixed cache targets are sized directly).
    library: PathBuf,
    large_file_threshold: u64,
    stale_after_days: u64,
    /// git-only scan: feed `repo_tx` but emit no disk findings.
    discovery_only: bool,
}

#[async_trait]
impl Scanner for FsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Fs
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        // Resolve roots (tilde-expanded) or fall back to the home dir.
        let roots: Vec<PathBuf> = if ctx.config.scan.roots.is_empty() {
            ctx.paths.default_roots()
        } else {
            ctx.config
                .scan
                .roots
                .iter()
                .map(|r| ctx.paths.expand(r))
                .collect()
        };

        let ignore_paths: Vec<PathBuf> = ctx
            .config
            .scan
            .ignore
            .iter()
            .map(|p| ctx.paths.expand(p))
            .collect();

        // Handles kept out of `WalkShared` so they survive the drop that closes
        // the fs→git pipe — the sizing pass below still needs them.
        let tx = ctx.tx.clone();
        let token = ctx.token.clone();
        let gen = ctx.gen;
        let paths = ctx.paths.clone();
        let config = ctx.config.clone();
        let discovery_only = ctx.fs_discovery_only;
        let stale_after_days = ctx.config.behavior.stale_after_days;

        // The engine handed us `repo_tx` inside the ctx; move it into the walk.
        let repo_tx = ctx.repo_tx.clone();

        let hits: Arc<Mutex<Vec<Hit>>> = Arc::new(Mutex::new(Vec::new()));

        let shared = Arc::new(WalkShared {
            tx: tx.clone(),
            gen,
            token: token.clone(),
            config: config.clone(),
            repo_tx,
            hits: hits.clone(),
            ignore_paths,
            library: paths.home.join("Library"),
            large_file_threshold: config.large_file_threshold_bytes(),
            stale_after_days,
            discovery_only,
        });

        // Sync WalkParallel must run off the async runtime (spec §1).
        let walk_shared = shared.clone();
        let walk = tokio::task::spawn_blocking(move || run_walk(&walk_shared, &roots));
        walk.await?;

        // The walk task has dropped its `WalkShared` clone; dropping ours releases
        // the last `repo_tx`, closing the pipe so GitScanner terminates while we
        // go on to size artifacts below.
        drop(shared);

        if discovery_only {
            return Ok(());
        }

        // Size artifact subtrees in parallel and re-emit with the same id.
        let hits = std::mem::take(&mut *hits.lock().unwrap());
        if !hits.is_empty() {
            let tx2 = tx.clone();
            let token2 = token.clone();
            tokio::task::spawn_blocking(move || {
                hits.par_iter().for_each(|hit| {
                    let size = du_blocks(&hit.path, &|| token2.is_cancelled());
                    let f = artifact_finding(
                        &hit.path,
                        &hit.label,
                        hit.last_used,
                        hit.stale,
                        Some(size),
                    );
                    let _ = tx2.blocking_send(ScanEvent::Finding {
                        scanner: ScannerId::Fs,
                        gen,
                        finding: Box::new(f),
                    });
                });
            })
            .await?;
        }

        // Fixed cache/backup paths — sized directly, no walk.
        let paths2 = paths.clone();
        let tx3 = tx.clone();
        let token3 = token.clone();
        tokio::task::spawn_blocking(move || size_fixed_paths(&paths2, &tx3, gen, &token3)).await?;

        Ok(())
    }
}

/// Run the parallel walk, emitting unsized artifact findings + large-file
/// findings and pushing artifact hits for later sizing.
fn run_walk(shared: &Arc<WalkShared>, roots: &[PathBuf]) {
    let mut builder: Option<WalkBuilder> = None;
    for root in roots {
        if !root.exists() {
            continue;
        }
        match builder.as_mut() {
            Some(b) => {
                b.add(root);
            }
            None => {
                let mut b = WalkBuilder::new(root);
                // Walk *everything*: node_modules/target are usually gitignored,
                // so all standard filters (hidden, gitignore, parents) are off.
                b.standard_filters(false).follow_links(false);
                builder = Some(b);
            }
        }
    }
    let Some(builder) = builder else {
        return;
    };

    builder.build_parallel().run(|| {
        let shared = shared.clone();
        Box::new(move |result| visit(&shared, result))
    });
}

/// Per-entry visitor. Cheap predicate checks, then either descend, skip, or
/// emit. Returns `Quit` promptly on cancellation (spec §1).
fn visit(shared: &WalkShared, result: Result<ignore::DirEntry, ignore::Error>) -> WalkState {
    if shared.token.is_cancelled() {
        return WalkState::Quit;
    }
    let entry = match result {
        Ok(e) => e,
        Err(_) => return WalkState::Continue,
    };
    let path = entry.path();
    let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);

    if is_dir {
        // Never descend into ~/Library (fixed targets are sized directly).
        if path == shared.library {
            return WalkState::Skip;
        }
        if shared.ignore_paths.iter().any(|ig| path == ig) {
            return WalkState::Skip;
        }

        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => return WalkState::Continue,
        };

        // A repository root — feed GitScanner, then don't descend into .git.
        if name == ".git" {
            if let (Some(tx), Some(parent)) = (shared.repo_tx.as_ref(), path.parent()) {
                let _ = tx.blocking_send(RepoDiscovery {
                    root: parent.to_path_buf(),
                });
            }
            return WalkState::Skip;
        }

        if is_artifact(name, path, &shared.config) {
            if !shared.discovery_only {
                let last_used = path.parent().and_then(parent_max_mtime);
                let stale = is_stale(last_used, shared.stale_after_days);
                let f = artifact_finding(path, name, last_used, stale, None);
                let _ = shared.tx.blocking_send(ScanEvent::Finding {
                    scanner: ScannerId::Fs,
                    gen: shared.gen,
                    finding: Box::new(f),
                });
                shared.hits.lock().unwrap().push(Hit {
                    path: path.to_path_buf(),
                    label: name.to_string(),
                    last_used,
                    stale,
                });
            }
            // Whether or not we emit, do NOT descend into an artifact subtree.
            return WalkState::Skip;
        }
        return WalkState::Continue;
    }

    // Large loose file.
    if !shared.discovery_only {
        if let Ok(meta) = entry.metadata() {
            if meta.is_file() {
                let sz = on_disk_bytes(&meta);
                if sz > shared.large_file_threshold {
                    let f = large_file_finding(path, sz);
                    let _ = shared.tx.blocking_send(ScanEvent::Finding {
                        scanner: ScannerId::Fs,
                        gen: shared.gen,
                        finding: Box::new(f),
                    });
                }
            }
        }
    }
    WalkState::Continue
}

/// Is `name` (a directory) a recognized build artifact, given its marker? The
/// caller guarantees `path` is the directory itself.
fn is_artifact(name: &str, path: &Path, config: &crate::config::Config) -> bool {
    let parent = path.parent();
    let sibling = |file: &str| parent.map(|p| p.join(file).exists()).unwrap_or(false);
    let inside = |file: &str| path.join(file).exists();

    match name {
        "node_modules" => sibling("package.json"),
        "target" => sibling("Cargo.toml"),
        ".venv" | "venv" => inside("pyvenv.cfg"),
        "__pycache__" => true,
        "build" | "dist" => parent
            .map(|p| PROJECT_MARKERS.iter().any(|m| p.join(m).exists()))
            .unwrap_or(false),
        ".next" | ".turbo" | ".wrangler" => sibling("package.json"),
        "Pods" => sibling("Podfile"),
        other => config
            .artifacts
            .extra
            .iter()
            .any(|rule| rule.dir == other && sibling(&rule.marker)),
    }
}

/// Build an artifact finding. `None` size marks the initial (pending) emit; the
/// re-emit passes `Some` — same `(kind, key)` ⇒ same `FindingId`.
fn artifact_finding(
    path: &Path,
    label: &str,
    last_used: Option<SystemTime>,
    stale: bool,
    size: Option<u64>,
) -> Finding {
    let key = path.to_string_lossy();
    let parent_name = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let title = format!("{label} — {parent_name}");

    let mut f = Finding::new(FindingKind::BuildArtifact, &key, title)
        .path(path.to_path_buf())
        .detail(format!("Build artifact ({label})"))
        .severity(Severity::Reclaimable)
        .meta(json!({ "stale": stale, "artifact": label }));
    if let Some(sz) = size {
        f = f.size(sz);
    }
    if let Some(lu) = last_used {
        f = f.last_used(lu);
    }
    f.remedy(Remedy {
        label: "Move to Trash".into(),
        command: RemedyCommand::Trash {
            path: path.to_path_buf(),
        },
        reclaims_bytes: size,
        destructive: true,
    })
}

/// A large loose file: sized inline (we already have its metadata), non
/// destructive (we don't know it's safe to delete), reveal-in-Finder remedy.
fn large_file_finding(path: &Path, size: u64) -> Finding {
    let key = path.to_string_lossy();
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    Finding::new(
        FindingKind::BuildArtifact,
        &key,
        format!("Large file — {name}"),
    )
    .path(path.to_path_buf())
    .detail("Large loose file over the size threshold".to_string())
    .size(size)
    .severity(Severity::Attention)
    .meta(json!({ "large_file": true }))
    .remedy(Remedy {
        label: "Reveal in Finder".into(),
        command: RemedyCommand::RevealInFinder {
            path: path.to_path_buf(),
        },
        reclaims_bytes: None,
        destructive: false,
    })
}

/// Cheap staleness heuristic: max mtime of the *files* directly in `parent`
/// (artifact subdirs, being directories, are naturally excluded).
fn parent_max_mtime(parent: &Path) -> Option<SystemTime> {
    let mut max: Option<SystemTime> = None;
    for entry in std::fs::read_dir(parent).ok()?.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        if let Ok(t) = meta.modified() {
            max = Some(match max {
                Some(cur) if cur >= t => cur,
                _ => t,
            });
        }
    }
    max
}

fn is_stale(last_used: Option<SystemTime>, stale_after_days: u64) -> bool {
    match last_used {
        Some(t) => t
            .elapsed()
            .map(|e| e > Duration::from_secs(stale_after_days.saturating_mul(86_400)))
            .unwrap_or(false),
        None => false,
    }
}

/// A fixed well-known cache/backup path to size directly.
struct FixedTarget {
    rel: &'static str,
    kind: FindingKind,
    /// Emit one finding per immediate subdir instead of one for the whole dir.
    per_subdir: bool,
    /// Offer a destructive Trash remedy (false ⇒ reveal-only, e.g. iOS backups).
    trashable: bool,
}

const FIXED_TARGETS: &[FixedTarget] = &[
    FixedTarget {
        rel: "~/Library/Developer/Xcode/DerivedData",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        trashable: true,
    },
    FixedTarget {
        rel: "~/Library/Developer/Xcode/iOS DeviceSupport",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        trashable: true,
    },
    FixedTarget {
        rel: "~/Library/Developer/CoreSimulator/Caches",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        trashable: true,
    },
    FixedTarget {
        rel: "~/.npm",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        trashable: true,
    },
    FixedTarget {
        rel: "~/.pnpm-store",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        trashable: true,
    },
    FixedTarget {
        rel: "~/.cargo/registry",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        trashable: true,
    },
    FixedTarget {
        rel: "~/.rustup/toolchains",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        trashable: true,
    },
    FixedTarget {
        rel: "~/go/pkg/mod",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        trashable: true,
    },
    FixedTarget {
        rel: "~/Library/Caches",
        kind: FindingKind::CacheDir,
        per_subdir: true,
        trashable: true,
    },
    FixedTarget {
        rel: "~/Library/Application Support/MobileSync/Backup",
        kind: FindingKind::IosBackup,
        per_subdir: true,
        trashable: false,
    },
];

/// Size the fixed cache/backup targets that exist and emit a finding for each.
fn size_fixed_paths(
    paths: &crate::config::Paths,
    tx: &tokio::sync::mpsc::Sender<ScanEvent>,
    gen: u64,
    token: &tokio_util::sync::CancellationToken,
) {
    for target in FIXED_TARGETS {
        if token.is_cancelled() {
            return;
        }
        let root = paths.expand(target.rel);
        if !root.exists() {
            continue;
        }
        if target.per_subdir {
            let Ok(rd) = std::fs::read_dir(&root) else {
                continue;
            };
            for entry in rd.flatten() {
                let p = entry.path();
                if !p.is_dir() {
                    continue;
                }
                let size = du_blocks(&p, &|| token.is_cancelled());
                emit_fixed(tx, gen, &p, target.kind, target.trashable, size);
            }
        } else {
            let size = du_blocks(&root, &|| token.is_cancelled());
            emit_fixed(tx, gen, &root, target.kind, target.trashable, size);
        }
    }
}

fn emit_fixed(
    tx: &tokio::sync::mpsc::Sender<ScanEvent>,
    gen: u64,
    path: &Path,
    kind: FindingKind,
    trashable: bool,
    size: u64,
) {
    let key = path.to_string_lossy();
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| key.to_string());
    let (severity, remedy) = if trashable {
        (
            Severity::Reclaimable,
            Remedy {
                label: "Move to Trash".into(),
                command: RemedyCommand::Trash {
                    path: path.to_path_buf(),
                },
                reclaims_bytes: Some(size),
                destructive: true,
            },
        )
    } else {
        (
            Severity::Attention,
            Remedy {
                label: "Reveal in Finder".into(),
                command: RemedyCommand::RevealInFinder {
                    path: path.to_path_buf(),
                },
                reclaims_bytes: None,
                destructive: false,
            },
        )
    };
    let f = Finding::new(kind, &key, name)
        .path(path.to_path_buf())
        .size(size)
        .severity(severity)
        .remedy(remedy);
    let _ = tx.blocking_send(ScanEvent::Finding {
        scanner: ScannerId::Fs,
        gen,
        finding: Box::new(f),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ArtifactRule, Config, Paths};
    use crate::model::FindingId;
    use crate::runner::MockCommandRunner;
    use crate::scan::pipe::repo_channel;
    use std::collections::HashMap;
    use std::fs;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    /// Build a ctx pointed at `home`, with roots = [home]. Returns the ctx plus
    /// the event receiver. `repo_tx`/`repo_rx` wired if `with_repo`.
    fn ctx_for(
        home: &Path,
        with_repo: bool,
        discovery_only: bool,
        extra: Vec<ArtifactRule>,
    ) -> (
        ScanCtx,
        mpsc::Receiver<ScanEvent>,
        Option<crate::scan::pipe::RepoReceiver>,
    ) {
        let mut config = Config::default();
        config.scan.roots = vec![home.to_string_lossy().into_owned()];
        config.artifacts.extra = extra;
        let (tx, rx) = mpsc::channel(1024);
        let (repo_tx, repo_rx) = if with_repo {
            let (t, r) = repo_channel();
            (Some(t), Some(r))
        } else {
            (None, None)
        };
        let ctx = ScanCtx {
            tx,
            token: CancellationToken::new(),
            gen: 1,
            config: Arc::new(config),
            paths: Arc::new(Paths::from_home(home)),
            runner: Arc::new(MockCommandRunner::new()),
            current: ScannerId::Fs,
            repo_tx,
            repo_rx: None,
            fs_discovery_only: discovery_only,
        };
        (ctx, rx, repo_rx)
    }

    /// Collect all findings from the receiver into path→findings.
    fn drain(mut rx: mpsc::Receiver<ScanEvent>) -> Vec<Finding> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                out.push(*finding);
            }
        }
        out
    }

    #[tokio::test]
    async fn finds_node_modules_next_to_package_json() {
        let home = tempfile::tempdir().unwrap();
        let proj = home.path().join("code/app");
        fs::create_dir_all(proj.join("node_modules/some_pkg")).unwrap();
        fs::write(proj.join("package.json"), "{}").unwrap();
        fs::write(proj.join("node_modules/some_pkg/index.js"), "x").unwrap();

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        let findings = drain(rx);
        assert!(
            findings
                .iter()
                .any(|f| f.path.as_deref() == Some(proj.join("node_modules").as_path())),
            "expected node_modules finding, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn finds_target_next_to_cargo_toml() {
        let home = tempfile::tempdir().unwrap();
        let proj = home.path().join("rustproj");
        fs::create_dir_all(proj.join("target/debug")).unwrap();
        fs::write(proj.join("Cargo.toml"), "[package]").unwrap();
        fs::write(proj.join("target/debug/bin"), "x").unwrap();

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        assert!(drain(rx)
            .iter()
            .any(|f| f.path.as_deref() == Some(proj.join("target").as_path())));
    }

    #[tokio::test]
    async fn decoy_build_without_marker_is_not_flagged() {
        let home = tempfile::tempdir().unwrap();
        let decoy = home.path().join("docs/build");
        fs::create_dir_all(&decoy).unwrap();
        fs::write(decoy.join("page.html"), "x").unwrap();

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        assert!(
            !drain(rx)
                .iter()
                .any(|f| f.path.as_deref() == Some(decoy.as_path())),
            "a build/ with no project marker must not be flagged"
        );
    }

    #[tokio::test]
    async fn build_with_marker_is_flagged() {
        let home = tempfile::tempdir().unwrap();
        let proj = home.path().join("pyproj");
        fs::create_dir_all(proj.join("build/lib")).unwrap();
        fs::write(proj.join("pyproject.toml"), "").unwrap();

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        assert!(drain(rx)
            .iter()
            .any(|f| f.path.as_deref() == Some(proj.join("build").as_path())));
    }

    #[tokio::test]
    async fn does_not_descend_into_artifact_dirs() {
        let home = tempfile::tempdir().unwrap();
        let proj = home.path().join("app");
        // Nested node_modules — only the OUTER one should be reported.
        fs::create_dir_all(proj.join("node_modules/inner/node_modules")).unwrap();
        fs::write(proj.join("package.json"), "{}").unwrap();
        fs::write(proj.join("node_modules/inner/package.json"), "{}").unwrap();

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        let nm: Vec<_> = drain(rx)
            .into_iter()
            .filter(|f| {
                f.path
                    .as_deref()
                    .map(|p| p.ends_with("node_modules"))
                    .unwrap_or(false)
            })
            .collect();
        // Each finding is emitted twice (unsized + sized); dedupe by id.
        let ids: std::collections::HashSet<FindingId> = nm.iter().map(|f| f.id).collect();
        assert_eq!(ids.len(), 1, "only the outer node_modules should be found");
    }

    #[tokio::test]
    async fn git_dir_yields_repo_discovery() {
        let home = tempfile::tempdir().unwrap();
        let repo = home.path().join("myrepo");
        fs::create_dir_all(repo.join(".git")).unwrap();

        let (ctx, _rx, repo_rx) = ctx_for(home.path(), true, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        // The walk dropped repo_tx, so draining to close is clean.
        let mut repo_rx = repo_rx.unwrap();
        let mut roots = Vec::new();
        while let Ok(d) = repo_rx.try_recv() {
            roots.push(d.root);
        }
        assert_eq!(roots, vec![repo]);
    }

    #[tokio::test]
    async fn artifact_emitted_unsized_then_sized_same_id() {
        let home = tempfile::tempdir().unwrap();
        let proj = home.path().join("app");
        fs::create_dir_all(proj.join("node_modules/pkg")).unwrap();
        fs::write(proj.join("package.json"), "{}").unwrap();
        fs::write(proj.join("node_modules/pkg/blob.bin"), vec![7u8; 4096]).unwrap();

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        // Group node_modules emits by id; expect one None then one Some(_).
        let mut by_id: HashMap<FindingId, Vec<Option<u64>>> = HashMap::new();
        for f in drain(rx) {
            if f.path
                .as_deref()
                .map(|p| p.ends_with("node_modules"))
                .unwrap_or(false)
            {
                by_id.entry(f.id).or_default().push(f.size_bytes);
            }
        }
        assert_eq!(by_id.len(), 1);
        let sizes = by_id.into_values().next().unwrap();
        assert!(sizes.contains(&None), "expected an initial unsized emit");
        assert!(
            sizes.iter().any(|s| s.is_some_and(|v| v > 0)),
            "expected a re-emit with a real size, got {sizes:?}"
        );
    }

    #[tokio::test]
    async fn discovery_only_pipes_git_but_emits_nothing() {
        let home = tempfile::tempdir().unwrap();
        let repo = home.path().join("r");
        fs::create_dir_all(repo.join(".git")).unwrap();
        let proj = home.path().join("app");
        fs::create_dir_all(proj.join("node_modules")).unwrap();
        fs::write(proj.join("package.json"), "{}").unwrap();

        let (ctx, rx, repo_rx) = ctx_for(home.path(), true, true, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        assert!(drain(rx).is_empty(), "discovery-only emits no findings");
        let mut repo_rx = repo_rx.unwrap();
        assert!(repo_rx.try_recv().is_ok(), "still feeds the git pipe");
    }

    #[tokio::test]
    async fn extra_artifact_rule_from_config() {
        let home = tempfile::tempdir().unwrap();
        let proj = home.path().join("proj");
        fs::create_dir_all(proj.join("mycache")).unwrap();
        fs::write(proj.join("MARKER"), "").unwrap();

        let rule = ArtifactRule {
            dir: "mycache".into(),
            marker: "MARKER".into(),
        };
        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![rule]);
        FsScanner.scan(ctx).await.unwrap();

        assert!(drain(rx)
            .iter()
            .any(|f| f.path.as_deref() == Some(proj.join("mycache").as_path())));
    }

    #[tokio::test]
    async fn library_is_not_descended() {
        let home = tempfile::tempdir().unwrap();
        // A node_modules buried in ~/Library must be ignored by the walk.
        let lib = home.path().join("Library/weird");
        fs::create_dir_all(lib.join("node_modules")).unwrap();
        fs::write(lib.join("package.json"), "{}").unwrap();

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        assert!(
            !drain(rx)
                .iter()
                .any(|f| f.path.as_deref() == Some(lib.join("node_modules").as_path())),
            "~/Library must be skipped by the walk"
        );
    }
}
