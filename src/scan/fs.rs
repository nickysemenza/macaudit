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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use ignore::{WalkBuilder, WalkState};
use serde_json::json;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScanEvent, ScannerId, Severity};
use crate::scan::pipe::{RepoDiscovery, RepoSender};
use crate::scan::sizing::{du_blocks, du_blocks_bounded, on_disk_bytes};
use crate::scan::{ScanCtx, Scanner};
use crate::size_cache::{self, CachedSize, SizeCache};

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
    /// Discovered artifact hits go here to be sized concurrently with the walk.
    hit_tx: crossbeam_channel::Sender<Hit>,
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

    async fn scan(&self, mut ctx: ScanCtx) -> anyhow::Result<()> {
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

        // The engine handed us `repo_tx` inside the ctx; TAKE it (not clone) so
        // the only surviving senders live in `WalkShared`. Otherwise a leftover
        // sender in `ctx` keeps the fs→git pipe open through the whole sizing
        // pass, delaying GitScanner's completion until this scan returns.
        let repo_tx = ctx.repo_tx.take();

        // Artifacts discovered by the walk are sized CONCURRENTLY with it: the
        // walker sends each hit down this channel and a rayon-backed consumer
        // du's them as they arrive, re-emitting the finding with its size. So
        // sizes start streaming in almost immediately instead of only after the
        // (potentially long) walk finishes.
        let (hit_tx, hit_rx) = crossbeam_channel::unbounded::<Hit>();

        // Sizes computed fresh this scan, accumulated here and flushed to the
        // cache db once (after) the sizing pass finishes.
        let fresh_entries: Arc<Mutex<Vec<(PathBuf, CachedSize)>>> =
            Arc::new(Mutex::new(Vec::new()));

        let sizing = if discovery_only {
            // Discovery-only feeds the git pipe and emits no disk findings.
            None
        } else {
            let tx_sz = tx.clone();
            let token_sz = token.clone();
            let fresh_sz = fresh_entries.clone();
            let ttl_hours = config.scan.size_cache_ttl_hours;

            // Load the on-disk size cache before the walk starts. An
            // unopenable/corrupt db (or any load failure) degrades to an empty
            // cache — a scan must never fail because of it.
            let paths_sz = paths.clone();
            let cache: Arc<HashMap<PathBuf, CachedSize>> = Arc::new(
                tokio::task::spawn_blocking(move || load_cache(&size_cache::db_path(&paths_sz)))
                    .await
                    .unwrap_or_default(),
            );
            let now_secs = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            Some(tokio::task::spawn_blocking(move || {
                use rayon::iter::{ParallelBridge, ParallelIterator};
                hit_rx.into_iter().par_bridge().for_each(|hit| {
                    if token_sz.is_cancelled() {
                        return;
                    }
                    let root_mtime = root_mtime_secs(&hit.path);
                    let cached = cache
                        .get(&hit.path)
                        .copied()
                        .filter(|c| is_fresh(c, root_mtime, now_secs, ttl_hours));

                    let (size, was_cached) = match cached {
                        Some(c) => (c.size, true),
                        None => {
                            let size = du_blocks(&hit.path, &|| token_sz.is_cancelled());
                            // A du interrupted by cancellation returns a PARTIAL
                            // sum. Never record that: with an unchanged root
                            // mtime it would be served as a "fresh" cache hit
                            // (a wrong size) for up to the whole TTL. Skip the
                            // emit too — the run is superseded anyway.
                            if token_sz.is_cancelled() {
                                return;
                            }
                            fresh_sz.lock().unwrap().push((
                                hit.path.clone(),
                                CachedSize {
                                    size,
                                    computed_at: now_secs,
                                    root_mtime,
                                },
                            ));
                            (size, false)
                        }
                    };

                    let f = artifact_finding(
                        &hit.path,
                        &hit.label,
                        hit.last_used,
                        hit.stale,
                        Some(size),
                        was_cached,
                    );
                    let _ = tx_sz.blocking_send(ScanEvent::Finding {
                        scanner: ScannerId::Fs,
                        gen,
                        finding: Box::new(f),
                    });
                });
            }))
        };

        let shared = Arc::new(WalkShared {
            tx: tx.clone(),
            gen,
            token: token.clone(),
            config: config.clone(),
            repo_tx,
            hit_tx,
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

        // Dropping our WalkShared releases the last `repo_tx` (closing the fs→git
        // pipe so GitScanner terminates) AND the last `hit_tx` (closing the
        // sizing channel so the consumer drains and finishes).
        drop(shared);

        if let Some(sizing) = sizing {
            sizing.await?;
        }

        // Persist freshly measured sizes for next time (best-effort — a save
        // failure is silently ignored, the cache is never load-bearing).
        // Belt-and-braces with the per-hit guard above: a cancelled scan
        // persists nothing, so a partial du can never poison the cache.
        let entries: Vec<(PathBuf, CachedSize)> = if token.is_cancelled() {
            Vec::new()
        } else {
            std::mem::take(&mut *fresh_entries.lock().unwrap())
        };
        if !entries.is_empty() {
            let paths_save = paths.clone();
            let _ = tokio::task::spawn_blocking(move || {
                save_cache(&size_cache::db_path(&paths_save), &entries)
            })
            .await;
        }

        if discovery_only {
            return Ok(());
        }

        // Fixed cache/backup paths — sized directly, no walk.
        let paths2 = paths.clone();
        let tx3 = tx.clone();
        let token3 = token.clone();
        tokio::task::spawn_blocking(move || size_fixed_paths(&paths2, &tx3, gen, &token3)).await?;

        // A small, explicitly bounded accounting pass complements artifact
        // discovery. It never walks all of $HOME and labels partial numbers.
        let paths3 = paths.clone();
        let tx4 = tx.clone();
        let token4 = token.clone();
        tokio::task::spawn_blocking(move || size_disk_categories(&paths3, &tx4, gen, &token4))
            .await?;

        Ok(())
    }
}

struct DiskCategory {
    title: &'static str,
    rel: &'static str,
}

const DISK_CATEGORIES: &[DiskCategory] = &[
    DiskCategory {
        title: "Development",
        rel: "~/dev",
    },
    DiskCategory {
        title: "Agent worktrees",
        rel: "~/.codex/worktrees",
    },
    DiskCategory {
        title: "Developer caches",
        rel: "~/.cache",
    },
    DiskCategory {
        title: "App caches",
        rel: "~/Library/Caches",
    },
    DiskCategory {
        title: "Application Support",
        rel: "~/Library/Application Support",
    },
    DiskCategory {
        title: "iCloud Drive",
        rel: "~/Library/Mobile Documents",
    },
    DiskCategory {
        title: "Documents",
        rel: "~/Documents",
    },
    DiskCategory {
        title: "Pictures",
        rel: "~/Pictures",
    },
    DiskCategory {
        title: "Apple developer data",
        rel: "~/Library/Developer",
    },
];

/// Measure a deliberately narrow, non-overlapping set of roots with one shared
/// five-second budget. Missing/unreadable roots are omitted; unfinished roots
/// are still emitted with a coverage warning so their partial number is never
/// mistaken for a whole-disk answer.
fn size_disk_categories(
    paths: &crate::config::Paths,
    tx: &tokio::sync::mpsc::Sender<ScanEvent>,
    gen: u64,
    token: &tokio_util::sync::CancellationToken,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    for category in DISK_CATEGORIES {
        if token.is_cancelled() {
            return;
        }
        let root = paths.expand(category.rel);
        if !root.is_dir() {
            continue;
        }
        let result = du_blocks_bounded(&root, 25_000, deadline, &|| token.is_cancelled());
        let coverage = if result.complete {
            format!("Measured {} entries in the selected root.", result.entries)
        } else {
            format!(
                "Partial: measured {} entries before the shared 5s / 25,000-entry budget ended.",
                result.entries
            )
        };
        let f = Finding::new(FindingKind::DiskCategory, category.rel, category.title)
            .path(root)
            .size(result.bytes)
            .detail(format!("{} on disk", humansize::format_size(result.bytes, humansize::BINARY)))
            .severity(if result.complete { Severity::Info } else { Severity::Attention })
            .provenance("bounded local directory walk; symlinks skipped, hard links deduplicated per category")
            .coverage(coverage.clone())
            .meta(json!({ "group": "Disk allocation", "category": category.title, "entries": result.entries, "complete": result.complete, "coverage": coverage }));
        let _ = tx.blocking_send(ScanEvent::Finding {
            scanner: ScannerId::Fs,
            gen,
            finding: Box::new(f),
        });
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
        // Never descend into Trash: everything in it is already slated for
        // deletion — re-reporting trashed node_modules (or piping trashed
        // repos to GitScanner) is noise, and a Trash remedy would be absurd.
        if path.file_name().and_then(|n| n.to_str()) == Some(".Trash") {
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
                let f = artifact_finding(path, name, last_used, stale, None, false);
                let _ = shared.tx.blocking_send(ScanEvent::Finding {
                    scanner: ScannerId::Fs,
                    gen: shared.gen,
                    finding: Box::new(f),
                });
                // Hand the hit to the concurrent sizing consumer immediately so
                // its size is computed while the walk continues.
                let _ = shared.hit_tx.send(Hit {
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
/// re-emit passes `Some` — same `(kind, key)` ⇒ same `FindingId`. `cached`
/// marks a re-emit whose size came from the size cache rather than a fresh
/// `du_blocks` (surfaced to the UI via `meta.size_cached`).
fn artifact_finding(
    path: &Path,
    label: &str,
    last_used: Option<SystemTime>,
    stale: bool,
    size: Option<u64>,
    cached: bool,
) -> Finding {
    let key = path.to_string_lossy();
    let parent_name = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let title = format!("{label} — {parent_name}");

    let mut meta = json!({ "stale": stale, "artifact": label, "group": label });
    if cached {
        meta["size_cached"] = json!(true);
    }

    let mut f = Finding::new(FindingKind::BuildArtifact, &key, title)
        .path(path.to_path_buf())
        .detail(format!("Build artifact ({label})"))
        .severity(Severity::Reclaimable)
        .meta(meta);
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

/// A large loose file: sized inline (we already have its metadata). Severity
/// stays `Attention` rather than `Reclaimable` — a big file may well be wanted
/// (a Photos library, a video) — but we offer a reversible Trash remedy so the
/// user can act, plus reveal-in-Finder to inspect first.
fn large_file_finding(path: &Path, size: u64) -> Finding {
    let key = path.to_string_lossy();
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    Finding::new(FindingKind::LargeFile, &key, format!("Large file — {name}"))
        .path(path.to_path_buf())
        .detail("Large loose file over the size threshold".to_string())
        .size(size)
        .severity(Severity::Attention)
        .meta(json!({ "group": "Large files" }))
        .remedy(Remedy {
            label: "Move to Trash".into(),
            command: RemedyCommand::Trash {
                path: path.to_path_buf(),
            },
            reclaims_bytes: Some(size),
            destructive: true,
        })
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
    /// What action to offer for this target.
    remedy: FixedRemedy,
}

/// Remedy shape for a fixed target. Most caches are safely trashable; some
/// need a tool-specific cleanup command instead (trashing `~/Library/pnpm`
/// would also nuke pnpm's global bin shims, so `pnpm store prune` is the
/// correct action there); backups get reveal-only.
enum FixedRemedy {
    Trash,
    Reveal,
    Shell {
        label: &'static str,
        program: &'static str,
        args: &'static [&'static str],
    },
}

const FIXED_TARGETS: &[FixedTarget] = &[
    FixedTarget {
        rel: "~/Library/Developer/Xcode/DerivedData",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        remedy: FixedRemedy::Trash,
    },
    FixedTarget {
        rel: "~/Library/Developer/Xcode/iOS DeviceSupport",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        remedy: FixedRemedy::Trash,
    },
    FixedTarget {
        rel: "~/Library/Developer/CoreSimulator/Caches",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        remedy: FixedRemedy::Trash,
    },
    FixedTarget {
        rel: "~/.npm",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        remedy: FixedRemedy::Trash,
    },
    FixedTarget {
        rel: "~/.pnpm-store",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        remedy: FixedRemedy::Trash,
    },
    FixedTarget {
        // Modern pnpm's default home on macOS: content-addressable store plus
        // global bin shims — do NOT offer Trash; prune is the correct cleanup.
        rel: "~/Library/pnpm",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        remedy: FixedRemedy::Shell {
            label: "Prune unreferenced packages (pnpm store prune)",
            program: "pnpm",
            args: &["store", "prune"],
        },
    },
    FixedTarget {
        rel: "~/.cargo/registry",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        remedy: FixedRemedy::Trash,
    },
    FixedTarget {
        // Trashing this wholesale would delete the ACTIVE toolchain and break
        // the user's Rust install. The Runtimes section lists toolchains
        // individually with `rustup toolchain uninstall` as the safe path.
        rel: "~/.rustup/toolchains",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        remedy: FixedRemedy::Reveal,
    },
    FixedTarget {
        rel: "~/go/pkg/mod",
        kind: FindingKind::CacheDir,
        per_subdir: false,
        remedy: FixedRemedy::Trash,
    },
    FixedTarget {
        rel: "~/Library/Caches",
        kind: FindingKind::CacheDir,
        per_subdir: true,
        remedy: FixedRemedy::Trash,
    },
    FixedTarget {
        rel: "~/Library/Application Support/MobileSync/Backup",
        kind: FindingKind::IosBackup,
        per_subdir: true,
        remedy: FixedRemedy::Reveal,
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
                emit_fixed(tx, gen, &p, target.kind, &target.remedy, size);
            }
        } else {
            let size = du_blocks(&root, &|| token.is_cancelled());
            emit_fixed(tx, gen, &root, target.kind, &target.remedy, size);
        }
    }
}

fn emit_fixed(
    tx: &tokio::sync::mpsc::Sender<ScanEvent>,
    gen: u64,
    path: &Path,
    kind: FindingKind,
    fixed_remedy: &FixedRemedy,
    size: u64,
) {
    let key = path.to_string_lossy();
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| key.to_string());
    let (severity, remedy) = match fixed_remedy {
        FixedRemedy::Trash => (
            Severity::Reclaimable,
            Remedy {
                label: "Move to Trash".into(),
                command: RemedyCommand::Trash {
                    path: path.to_path_buf(),
                },
                reclaims_bytes: Some(size),
                destructive: true,
            },
        ),
        FixedRemedy::Reveal => (
            Severity::Attention,
            Remedy {
                label: "Reveal in Finder".into(),
                command: RemedyCommand::RevealInFinder {
                    path: path.to_path_buf(),
                },
                reclaims_bytes: None,
                destructive: false,
            },
        ),
        FixedRemedy::Shell {
            label,
            program,
            args,
        } => (
            Severity::Reclaimable,
            Remedy {
                label: (*label).into(),
                command: RemedyCommand::Shell {
                    program: (*program).into(),
                    args: args.iter().map(|a| (*a).to_string()).collect(),
                },
                // The tool decides what's actually reclaimable (e.g. prune only
                // removes unreferenced packages) — don't promise the full size.
                reclaims_bytes: None,
                destructive: true,
            },
        ),
    };
    let group = match kind {
        FindingKind::IosBackup => "iOS Backups",
        _ => "Caches",
    };
    let f = Finding::new(kind, &key, name)
        .path(path.to_path_buf())
        .size(size)
        .severity(severity)
        .meta(json!({ "group": group }))
        .remedy(remedy);
    let _ = tx.blocking_send(ScanEvent::Finding {
        scanner: ScannerId::Fs,
        gen,
        finding: Box::new(f),
    });
}

// --- Artifact size cache integration -------------------------------------
//
// The cache is consulted per-`Hit` in the sizing consumer above: a hit is
// re-used (no `du_blocks`) when its cached entry is both within the TTL and
// keyed to the artifact root's current mtime; otherwise it's measured fresh
// and queued for a single batched `upsert_batch` after the sizing pass ends.

/// Best-effort cache open + load. An unopenable or corrupt db degrades to an
/// empty cache rather than failing the scan.
fn load_cache(path: &Path) -> HashMap<PathBuf, CachedSize> {
    SizeCache::open(path)
        .and_then(|c| c.load_all())
        .unwrap_or_default()
}

/// Best-effort persistence of freshly measured sizes. Failure is silently
/// ignored — the cache is a performance optimization, never load-bearing.
fn save_cache(path: &Path, entries: &[(PathBuf, CachedSize)]) {
    if let Ok(mut cache) = SizeCache::open(path) {
        let _ = cache.upsert_batch(entries);
    }
}

// Freshness/mtime helpers live in `size_cache` so GitScanner's repo sizing can
// share the exact same staleness semantics.
use crate::size_cache::{is_fresh, root_mtime_secs};

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

    fn unix_secs(t: SystemTime) -> i64 {
        t.duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
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

    /// Regression: trashed projects were being re-reported — a node_modules
    /// sitting in ~/.Trash is already slated for deletion and must be ignored
    /// (and its .git must not be piped to GitScanner).
    #[tokio::test]
    async fn trash_is_not_descended() {
        let home = tempfile::tempdir().unwrap();
        let trashed = home.path().join(".Trash/old-project");
        fs::create_dir_all(trashed.join("node_modules/x")).unwrap();
        fs::write(trashed.join("package.json"), "{}").unwrap();
        fs::create_dir_all(trashed.join(".git")).unwrap();

        let (ctx, rx, repo_rx) = ctx_for(home.path(), true, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        assert!(
            drain(rx).is_empty(),
            "nothing inside ~/.Trash may produce findings"
        );
        let mut repo_rx = repo_rx.unwrap();
        assert!(
            repo_rx.try_recv().is_err(),
            "trashed repos must not reach GitScanner"
        );
    }

    /// Build a fixture tree with one sizeable `node_modules` artifact. Returns
    /// its path.
    fn fixture_node_modules(home: &Path) -> PathBuf {
        let proj = home.join("app");
        fs::create_dir_all(proj.join("node_modules/pkg")).unwrap();
        fs::write(proj.join("package.json"), "{}").unwrap();
        fs::write(proj.join("node_modules/pkg/blob.bin"), vec![7u8; 4096]).unwrap();
        proj.join("node_modules")
    }

    #[tokio::test]
    async fn cold_scan_populates_size_cache_db() {
        let home = tempfile::tempdir().unwrap();
        let nm = fixture_node_modules(home.path());

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        let findings = drain(rx);
        let sized = findings
            .iter()
            .find(|f| {
                f.path.as_deref() == Some(nm.as_path()) && f.size_bytes.is_some_and(|v| v > 0)
            })
            .expect("expected a sized node_modules finding");
        assert!(
            sized.meta.get("size_cached").is_none(),
            "a cold scan must not claim a cached size"
        );

        // The size we just computed should now be persisted in the cache db.
        let db = size_cache::db_path(&Paths::from_home(home.path()));
        let cache = SizeCache::open(&db).unwrap();
        let all = cache.load_all().unwrap();
        let entry = all
            .get(&nm)
            .expect("expected a node_modules row in the size cache db");
        assert!(entry.size > 0);
        assert_eq!(entry.size, sized.size_bytes.unwrap());
    }

    /// Regression: a scan cancelled mid-sizing must not persist anything — a
    /// du interrupted by cancellation returns a PARTIAL sum, and with the root
    /// mtime unchanged it would be served as a "fresh" (wrong) cached size for
    /// up to the whole TTL on subsequent scans.
    #[tokio::test]
    async fn cancelled_scan_never_persists_sizes() {
        let home = tempfile::tempdir().unwrap();
        let _nm = fixture_node_modules(home.path());

        let (ctx, _rx, _) = ctx_for(home.path(), false, false, vec![]);
        // Cancel before the scan even starts sizing — every du is "interrupted".
        ctx.token.cancel();
        FsScanner.scan(ctx).await.unwrap();

        let db = size_cache::db_path(&Paths::from_home(home.path()));
        // Either no db was created, or it contains no rows — never a partial size.
        if let Ok(cache) = SizeCache::open(&db) {
            assert!(
                cache.load_all().unwrap().is_empty(),
                "cancelled scan must not write size-cache rows"
            );
        }
    }

    #[tokio::test]
    async fn warm_cache_within_ttl_and_matching_mtime_is_reused() {
        let home = tempfile::tempdir().unwrap();
        let nm = fixture_node_modules(home.path());
        let root_mtime = root_mtime_secs(&nm);
        let now = unix_secs(SystemTime::now());

        let db = size_cache::db_path(&Paths::from_home(home.path()));
        {
            let mut cache = SizeCache::open(&db).unwrap();
            cache
                .upsert_batch(&[(
                    nm.clone(),
                    CachedSize {
                        size: 999_999,
                        computed_at: now,
                        root_mtime,
                    },
                )])
                .unwrap();
        }

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        let findings = drain(rx);
        let hit = findings
            .iter()
            .find(|f| f.path.as_deref() == Some(nm.as_path()) && f.size_bytes == Some(999_999))
            .expect("expected the cached size to be reused verbatim");
        assert_eq!(hit.meta["size_cached"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn cache_entry_with_wrong_root_mtime_is_ignored() {
        let home = tempfile::tempdir().unwrap();
        let nm = fixture_node_modules(home.path());
        let now = unix_secs(SystemTime::now());

        let db = size_cache::db_path(&Paths::from_home(home.path()));
        {
            let mut cache = SizeCache::open(&db).unwrap();
            cache
                .upsert_batch(&[(
                    nm.clone(),
                    CachedSize {
                        size: 999_999,
                        computed_at: now,
                        root_mtime: 1, // deliberately wrong — the tree "changed"
                    },
                )])
                .unwrap();
        }

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        let findings = drain(rx);
        let hit = findings
            .iter()
            .find(|f| {
                f.path.as_deref() == Some(nm.as_path()) && f.size_bytes.is_some_and(|v| v > 0)
            })
            .expect("expected a re-measured sized finding");
        assert_ne!(
            hit.size_bytes,
            Some(999_999),
            "a cache entry with a stale root_mtime must be re-du'd"
        );
        assert!(hit.meta.get("size_cached").is_none());
    }

    #[tokio::test]
    async fn cache_entry_older_than_ttl_is_ignored() {
        let home = tempfile::tempdir().unwrap();
        let nm = fixture_node_modules(home.path());
        let root_mtime = root_mtime_secs(&nm);

        let db = size_cache::db_path(&Paths::from_home(home.path()));
        {
            let mut cache = SizeCache::open(&db).unwrap();
            cache
                .upsert_batch(&[(
                    nm.clone(),
                    CachedSize {
                        size: 999_999,
                        computed_at: 0, // unix epoch — far past the default 24h TTL
                        root_mtime,
                    },
                )])
                .unwrap();
        }

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        let findings = drain(rx);
        let hit = findings
            .iter()
            .find(|f| {
                f.path.as_deref() == Some(nm.as_path()) && f.size_bytes.is_some_and(|v| v > 0)
            })
            .expect("expected a re-measured sized finding");
        assert_ne!(
            hit.size_bytes,
            Some(999_999),
            "an expired cache entry must be re-du'd"
        );
        assert!(hit.meta.get("size_cached").is_none());
    }

    #[test]
    fn large_file_offers_trash_then_reveal() {
        let f = large_file_finding(Path::new("/Users/x/Movies/huge.mkv"), 5_000_000_000);
        assert_eq!(f.kind, FindingKind::LargeFile);
        // A big file may be wanted, so it's flagged for attention, not auto-reclaimable.
        assert_eq!(f.severity, Severity::Attention);
        // Primary remedy: a reversible Trash that reclaims the file's size.
        assert!(matches!(
            &f.remedies[0].command,
            RemedyCommand::Trash { path } if path == Path::new("/Users/x/Movies/huge.mkv")
        ));
        assert!(f.remedies[0].destructive);
        assert_eq!(f.remedies[0].reclaims_bytes, Some(5_000_000_000));
        // Secondary: inspect before deleting.
        assert!(matches!(
            f.remedies[1].command,
            RemedyCommand::RevealInFinder { .. }
        ));
    }
}
