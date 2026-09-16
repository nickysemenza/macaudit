//! FsScanner — the single-pass filesystem index (lane S2).
//!
//! One `walk::walk` over the configured roots (getattrlistbulk listing,
//! rayon recursion) builds a bounded-memory directory tree and feeds *many*
//! cheap detectors on the way: build-artifact dirs (each gated on a project
//! marker), `.git` roots (piped to GitScanner), data-library packages, large
//! loose files. Artifact hits are emitted immediately with `size_bytes: None`
//! and re-emitted (same canonical key ⇒ same `FindingId`) the moment their
//! subtree is rolled up. Disk categories and the fixed cache/backup targets
//! are read off the finished tree, so they are exact, and the tree itself is
//! published as `ScanEvent::DirTree` for drill-down views.
//!
//! Concurrency contract (spec §1): the sync walk runs inside
//! `spawn_blocking`; rayon threads bridge back with `blocking_send`. The
//! visitor (and with it `repo_tx`) is dropped the instant the walk finishes
//! so GitScanner's channel closes before the post-walk derivations.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde_json::json;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScanEvent, ScannerId, Severity};
use crate::scan::pipe::{RepoDiscovery, RepoSender};
use crate::scan::sizing::{du_blocks, du_blocks_bounded, du_blocks_shared};
use crate::scan::walk::{
    self, DirAction, DirNode, DirTree, Entry, Flags, Kind, Visitor, WalkOptions, WalkStats,
};
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

/// How often the walk reports its live counters.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);
/// The "Largest files" group: this many, regardless of the threshold.
const LARGEST_FILES: usize = 25;
/// Budget for sizing an opaque subtree such as `~/Library/CloudStorage`.
const OPAQUE_BUDGET: Duration = Duration::from_secs(3);
const OPAQUE_MAX_ENTRIES: u64 = 200_000;

/// An artifact directory awaiting its rolled-up size.
struct Hit {
    label: String,
    last_used: Option<SystemTime>,
    stale: bool,
    ctx: ArtifactCtx,
}

/// What we know about an artifact beyond its path: which marker justified
/// it, the git worktree it lives in, and (pnpm) the store it shares files
/// with.
#[derive(Clone, Debug, Default, PartialEq)]
struct ArtifactCtx {
    marker: Option<String>,
    /// `(main repo root, worktree name)` when the enclosing repo is a linked
    /// worktree (`.git` is a file pointing into `<main>/.git/worktrees/<name>`).
    worktree: Option<(PathBuf, String)>,
    /// Nearest enclosing repository root (worktree or main).
    repo_root: Option<PathBuf>,
    /// pnpm-linked `node_modules`: the store dir from `.modules.yaml`.
    pnpm_store: Option<PathBuf>,
    pnpm_import_method: Option<String>,
}

/// Inspect an artifact's surroundings (cheap: a few `exists`/reads).
fn artifact_ctx(name: &str, path: &Path, siblings: &[Entry]) -> ArtifactCtx {
    let sibling = |file: &str| has_sibling(siblings, file);
    let inside = |file: &str| path.join(file).exists();
    let marker = match name {
        "target" if sibling("Cargo.toml") => Some("Cargo.toml".to_string()),
        "target" if inside(".rustc_info.json") => Some("target/.rustc_info.json".to_string()),
        "target" if inside("CACHEDIR.TAG") => Some("target/CACHEDIR.TAG".to_string()),
        "node_modules" => Some("package.json".to_string()),
        _ => None,
    };
    let (repo_root, worktree) = enclosing_repo(path);
    let (pnpm_store, pnpm_import_method) = if name == "node_modules" && path.join(".pnpm").is_dir()
    {
        let scalars = std::fs::read_to_string(path.join(".modules.yaml"))
            .map(|t| crate::scan::global_tools::flatyaml::top_level_scalars(&t))
            .unwrap_or_default();
        (
            Some(
                scalars
                    .get("storeDir")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("(pnpm store)")),
            ),
            scalars
                .get("packageImportMethod")
                .cloned()
                .or(Some("auto (clone/hardlink)".into())),
        )
    } else {
        (None, None)
    };
    ArtifactCtx {
        marker,
        worktree,
        repo_root,
        pnpm_store,
        pnpm_import_method,
    }
}

/// Is there a non-directory entry called `file` in this listing?
fn has_sibling(siblings: &[Entry], file: &str) -> bool {
    siblings
        .iter()
        .any(|e| e.kind != Kind::Dir && e.name == file)
}

/// Walk up from `path` to the nearest `.git`; a `.git` *file* names a linked
/// worktree (`gitdir: <main>/.git/worktrees/<name>`).
fn enclosing_repo(path: &Path) -> (Option<PathBuf>, Option<(PathBuf, String)>) {
    let mut cur = path.parent();
    while let Some(dir) = cur {
        let git = dir.join(".git");
        if git.is_dir() {
            return (Some(dir.to_path_buf()), None);
        }
        if git.is_file() {
            let worktree = std::fs::read_to_string(&git).ok().and_then(|t| {
                let gitdir = t.lines().find_map(|l| l.strip_prefix("gitdir:"))?.trim();
                let gitdir = if Path::new(gitdir).is_absolute() {
                    PathBuf::from(gitdir)
                } else {
                    dir.join(gitdir)
                };
                let s = gitdir.to_string_lossy();
                let idx = s.find("/.git/worktrees/")?;
                let main = PathBuf::from(&s[..idx]);
                let name = s[idx + "/.git/worktrees/".len()..]
                    .trim_end_matches('/')
                    .to_string();
                Some((main, name))
            });
            return (Some(dir.to_path_buf()), worktree);
        }
        cur = dir.parent();
    }
    (None, None)
}

/// Private walk flags: what kind of subtree we are inside. Below any of
/// these no artifact, package or repository classification happens.
const IN_LIBRARY: Flags = Flags(1 << 8);
const IN_PACKAGE: Flags = Flags(1 << 9);
const IN_GIT: Flags = Flags(1 << 10);
const IN_ARTIFACT: Flags = Flags(1 << 11);
const IN_TRASH: Flags = Flags(1 << 12);
const CLASSIFIED: Flags =
    Flags(IN_LIBRARY.0 | IN_PACKAGE.0 | IN_GIT.0 | IN_ARTIFACT.0 | IN_TRASH.0);

/// Subtrees under `~/Library` that are listed opaquely: File Provider
/// domains (Dropbox, Drive, OneDrive) enumerate on `opendir`, which can be
/// slow and network-bound, so they get a bounded measurement instead.
const OPAQUE_UNDER_LIBRARY: &[&str] = &["CloudStorage"];

/// The walk's per-directory classifier. Shared by every rayon worker; the
/// last clone to drop releases `repo_tx` and closes the fs→git pipe.
struct FsVisitor {
    tx: tokio::sync::mpsc::Sender<ScanEvent>,
    gen: u64,
    token: tokio_util::sync::CancellationToken,
    config: Arc<crate::config::Config>,
    repo_tx: Option<RepoSender>,
    /// `~/Library` — sized into the tree, never classified.
    library: PathBuf,
    large_file_threshold: u64,
    stale_after_days: u64,
    /// git-only scan: feed `repo_tx`, walk nothing else, emit no findings.
    discovery_only: bool,
    /// Artifacts found so far, awaiting their rolled-up size.
    hits: Mutex<HashMap<PathBuf, Hit>>,
    /// Data-library packages found so far (path → label).
    packages: Mutex<HashMap<PathBuf, &'static str>>,
}

impl FsVisitor {
    fn emit(&self, f: Finding) {
        let _ = self.tx.blocking_send(ScanEvent::Finding {
            scanner: ScannerId::Fs,
            gen: self.gen,
            finding: Box::new(f),
        });
    }
}

impl Visitor for FsVisitor {
    fn on_child_dir(
        &self,
        parent: &Path,
        child: &Entry,
        siblings: &[Entry],
        flags: Flags,
    ) -> DirAction {
        let Some(name) = child.name.to_str() else {
            return DirAction::Descend(flags);
        };
        if flags.contains(IN_LIBRARY)
            && parent == self.library
            && OPAQUE_UNDER_LIBRARY.contains(&name)
        {
            let r = du_blocks_bounded(
                &parent.join(name),
                OPAQUE_MAX_ENTRIES,
                Instant::now() + OPAQUE_BUDGET,
                &|| self.token.is_cancelled(),
            );
            return DirAction::Opaque {
                alloc: r.bytes,
                files: r.entries,
                dirs: 0,
            };
        }
        // Inside a classified subtree nothing below is a project of ours.
        if flags.0 & CLASSIFIED.0 != 0 {
            return DirAction::Descend(flags);
        }
        let path = parent.join(name);
        // ~/Library is measured (categories live there) but never mined for
        // artifacts or repositories.
        if path == self.library {
            return if self.discovery_only {
                DirAction::Skip
            } else {
                DirAction::Descend(flags | IN_LIBRARY | Flags::NOT_LOOSE)
            };
        }
        // Trash is already slated for deletion: measure it, report nothing
        // in it, pipe none of its repos to GitScanner.
        if name == ".Trash" {
            return if self.discovery_only {
                DirAction::Skip
            } else {
                DirAction::Descend(flags | IN_TRASH | Flags::NOT_LOOSE | Flags::NO_TOP)
            };
        }
        // A repository root — feed GitScanner. Its internals count toward
        // sizes (packfiles are real bytes) but are never loose large files.
        if name == ".git" {
            if let Some(tx) = self.repo_tx.as_ref() {
                let _ = tx.blocking_send(RepoDiscovery {
                    root: parent.to_path_buf(),
                });
            }
            return if self.discovery_only {
                DirAction::Skip
            } else {
                DirAction::Descend(flags | IN_GIT | Flags::NOT_LOOSE)
            };
        }
        // A macOS package (app, project, Photos/Music library, VM bundle) is
        // opaque: nothing inside it is a loose file or a project of its own.
        // Data libraries are surfaced as one large item once sized.
        if let Some(ext) = package_extension(name) {
            if self.discovery_only {
                return DirAction::Skip;
            }
            if let Some(label) = data_library_label(ext) {
                self.packages.lock().unwrap().insert(path, label);
            }
            return DirAction::Descend(flags | IN_PACKAGE | Flags::NOT_LOOSE | Flags::NO_TOP);
        }
        if is_artifact(name, &path, siblings, &self.config) {
            if self.discovery_only {
                return DirAction::Skip;
            }
            let last_used = siblings_max_mtime(siblings);
            let stale = is_stale(last_used, self.stale_after_days);
            let ctx = artifact_ctx(name, &path, siblings);
            self.emit(artifact_finding(
                &path, name, last_used, stale, None, &ctx, None,
            ));
            self.hits.lock().unwrap().insert(
                path,
                Hit {
                    label: name.to_string(),
                    last_used,
                    stale,
                    ctx,
                },
            );
            return DirAction::Descend(flags | IN_ARTIFACT | Flags::NOT_LOOSE | Flags::NO_TOP);
        }
        DirAction::Descend(flags)
    }

    fn on_dir_done(&self, dir: &Path, node: &DirNode, _flags: Flags) {
        if self.token.is_cancelled() {
            return;
        }
        // pnpm-linked node_modules are re-measured after the walk (per-tree
        // hard-link accounting); everything else streams out right here.
        let hit = self.hits.lock().unwrap();
        if let Some(h) = hit.get(dir) {
            if h.ctx.pnpm_store.is_none() {
                self.emit(artifact_finding(
                    dir,
                    &h.label,
                    h.last_used,
                    h.stale,
                    Some(node.alloc),
                    &h.ctx,
                    None,
                ));
            }
            return;
        }
        drop(hit);
        if let Some(label) = self.packages.lock().unwrap().get(dir) {
            // TCC-protected libraries look empty to a process without access;
            // an empty package is simply not reported.
            if node.alloc > self.large_file_threshold {
                self.emit(large_package_finding(dir, label, node.alloc));
            }
        }
    }
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

        let tx = ctx.tx.clone();
        let token = ctx.token.clone();
        let gen = ctx.gen;
        let paths = ctx.paths.clone();
        let config = ctx.config.clone();
        let discovery_only = ctx.fs_discovery_only;

        // The engine handed us `repo_tx` inside the ctx; TAKE it (not clone) so
        // the only surviving sender lives in the visitor. Otherwise a leftover
        // sender in `ctx` keeps the fs→git pipe open through the post-walk
        // work, delaying GitScanner's completion until this scan returns.
        let repo_tx = ctx.repo_tx.take();

        let visitor = Arc::new(FsVisitor {
            tx: tx.clone(),
            gen,
            token: token.clone(),
            config: config.clone(),
            repo_tx,
            library: paths.home.join("Library"),
            large_file_threshold: config.large_file_threshold_bytes(),
            stale_after_days: config.behavior.stale_after_days,
            discovery_only,
            hits: Mutex::new(HashMap::new()),
            packages: Mutex::new(HashMap::new()),
        });
        let stats = Arc::new(WalkStats::default());

        // Live progress from the walk's counters, until the walk is done.
        let progress_stop = token.child_token();
        let progress = if discovery_only {
            None
        } else {
            Some(tokio::spawn(report_progress(
                tx.clone(),
                gen,
                stats.clone(),
                progress_stop.clone(),
                roots.first().cloned().unwrap_or_default(),
            )))
        };

        // The sync walk must run off the async runtime (spec §1).
        let walk_visitor = visitor.clone();
        let walk_stats = stats.clone();
        let walk_token = token.clone();
        let opts = WalkOptions {
            excludes: ignore_paths,
            same_device: true,
            deadline: None,
            max_entries: None,
            // Discovery-only reproduces the cheap git-root sweep: no tree, no
            // largest-file bookkeeping, and the visitor skips everything else.
            keep_tree: !discovery_only,
            per_dir_top: if discovery_only { 0 } else { 3 },
            top_n: if discovery_only { 0 } else { LARGEST_FILES * 4 },
            threshold: if discovery_only {
                None
            } else {
                Some(config.large_file_threshold_bytes())
            },
        };
        let results = tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            for root in roots {
                if walk_token.is_cancelled() {
                    break;
                }
                if !root.exists() {
                    continue;
                }
                let started = Instant::now();
                let r = walk::walk(
                    &root,
                    opts.clone(),
                    walk_visitor.as_ref(),
                    Some(&walk_stats),
                    &|| walk_token.is_cancelled(),
                );
                out.push((root, r, started));
            }
            out
        })
        .await?;

        progress_stop.cancel();
        if let Some(p) = progress {
            let _ = p.await;
        }

        // The walk is over: hand the remaining state to the post-walk pass
        // and drop the visitor so `repo_tx` closes and GitScanner can finish.
        let hits: Vec<(PathBuf, Hit)> = std::mem::take(&mut *visitor.hits.lock().unwrap())
            .into_iter()
            .collect();
        drop(visitor);

        if discovery_only || token.is_cancelled() {
            return Ok(());
        }

        let files: u64 = stats.files.load(std::sync::atomic::Ordering::Relaxed);
        let dirs: u64 = stats.dirs.load(std::sync::atomic::Ordering::Relaxed);
        let bytes: u64 = stats.bytes.load(std::sync::atomic::Ordering::Relaxed);
        let elapsed: Duration = results
            .iter()
            .map(|(_, _, s)| s.elapsed())
            .max()
            .unwrap_or_default();
        let _ = tx
            .send(ScanEvent::Progress {
                scanner: ScannerId::Fs,
                gen,
                msg: format!(
                    "Indexed {} files in {} folders ({}) in {:.1}s",
                    files,
                    dirs,
                    humansize::format_size(bytes, humansize::BINARY),
                    elapsed.as_secs_f64()
                ),
                done: files,
                total: None,
            })
            .await;

        let tx2 = tx.clone();
        let token2 = token.clone();
        let paths2 = paths.clone();
        let threshold = config.large_file_threshold_bytes();
        tokio::task::spawn_blocking(move || {
            derive_from_trees(&paths2, &tx2, gen, &token2, results, hits, threshold)
        })
        .await?;
        Ok(())
    }
}

/// Emit `Progress` from the live counters every `PROGRESS_INTERVAL`.
async fn report_progress(
    tx: tokio::sync::mpsc::Sender<ScanEvent>,
    gen: u64,
    stats: Arc<WalkStats>,
    stop: tokio_util::sync::CancellationToken,
    root: PathBuf,
) {
    use std::sync::atomic::Ordering::Relaxed;
    let label = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| root.display().to_string());
    loop {
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = tokio::time::sleep(PROGRESS_INTERVAL) => {}
        }
        let files = stats.files.load(Relaxed);
        let msg = format!(
            "Indexing {label} — {} files, {} folders, {}",
            files,
            stats.dirs.load(Relaxed),
            humansize::format_size(stats.bytes.load(Relaxed), humansize::BINARY)
        );
        if tx
            .send(ScanEvent::Progress {
                scanner: ScannerId::Fs,
                gen,
                msg,
                done: files,
                total: None,
            })
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Everything that reads off the finished trees: pnpm re-measurement, large
/// and largest files, the fixed cache/backup targets, the disk categories,
/// and finally the trees themselves.
fn derive_from_trees(
    paths: &crate::config::Paths,
    tx: &tokio::sync::mpsc::Sender<ScanEvent>,
    gen: u64,
    token: &tokio_util::sync::CancellationToken,
    results: Vec<(PathBuf, walk::WalkResult, Instant)>,
    hits: Vec<(PathBuf, Hit)>,
    threshold: u64,
) {
    let send = |f: Finding| {
        let _ = tx.blocking_send(ScanEvent::Finding {
            scanner: ScannerId::Fs,
            gen,
            finding: Box::new(f),
        });
    };
    let cancelled = || token.is_cancelled();

    // pnpm-linked node_modules: how much is hard-linked from the store is a
    // per-tree question, so it gets its own bounded walk.
    for (path, hit) in hits.iter().filter(|(_, h)| h.ctx.pnpm_store.is_some()) {
        if cancelled() {
            return;
        }
        let s = du_blocks_shared(path, &cancelled);
        if cancelled() {
            return;
        }
        send(artifact_finding(
            path,
            &hit.label,
            hit.last_used,
            hit.stale,
            Some(s.bytes),
            &hit.ctx,
            Some(s.externally_linked),
        ));
    }

    let trees: Vec<Arc<DirTree>> = results
        .into_iter()
        .map(|(root, r, started)| {
            let mut threshold_files = r.threshold_files.clone();
            let mut top_files = r.top_files.clone();
            let tree = Arc::new(DirTree::from_result(root, r, started));
            // Loose files over the threshold: Attention, trashable.
            threshold_files.sort_by_key(|f| std::cmp::Reverse(f.alloc));
            let over: HashSet<&Path> = threshold_files.iter().map(|f| f.path.as_path()).collect();
            for f in &threshold_files {
                if f.alloc > threshold {
                    send(large_file_finding(&f.path, f.alloc));
                }
            }
            // The largest files regardless of threshold: context only.
            top_files.retain(|f| !over.contains(f.path.as_path()));
            for (rank, f) in top_files.iter().take(LARGEST_FILES).enumerate() {
                send(largest_file_finding(&f.path, f.alloc, rank + 1));
            }
            tree
        })
        .collect();
    if cancelled() {
        return;
    }

    size_fixed_paths(paths, &send, &cancelled, &trees);
    size_disk_categories(paths, &send, &cancelled, &trees);

    for tree in trees {
        let _ = tx.blocking_send(ScanEvent::DirTree {
            scanner: ScannerId::Fs,
            gen,
            tree,
        });
    }
}

/// The node for `path` in whichever tree contains it.
fn find_node<'a>(trees: &'a [Arc<DirTree>], path: &Path) -> Option<&'a DirNode> {
    trees
        .iter()
        .find(|t| path.starts_with(&t.root))
        .and_then(|t| t.node.find(&t.root, path))
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

/// Unreadable directories a category may contain before it is flagged
/// `Attention`. Every Mac without Full Disk Access has a handful of
/// TCC-protected folders under `~/Library` (Mail, Messages, Safari…); that
/// is a coverage note, not a warning.
const PARTIAL_ATTENTION_DIRS: u64 = 25;

/// Measure a deliberately narrow, non-overlapping set of roots, exactly,
/// off the finished tree. A root outside every walked tree (custom
/// `scan.roots`) falls back to a direct walk.
fn size_disk_categories(
    paths: &crate::config::Paths,
    send: &dyn Fn(Finding),
    cancelled: &(dyn Fn() -> bool + Sync),
    trees: &[Arc<DirTree>],
) {
    for category in DISK_CATEGORIES {
        if cancelled() {
            return;
        }
        let root = paths.expand(category.rel);
        if !root.is_dir() {
            continue;
        }
        let (bytes, files, dirs, errors) = match find_node(trees, &root) {
            Some(n) => (n.alloc, n.files, n.dirs, n.errors),
            None => (du_blocks(&root, cancelled), 0, 0, 0),
        };
        let entries = files + dirs;
        let complete = errors == 0;
        let coverage = if complete {
            format!("Measured exactly: {files} files in {dirs} folders.")
        } else {
            format!(
                "{errors} folders could not be read — grant Full Disk Access to include them. Measured {files} files in {dirs} folders."
            )
        };
        let attention = errors > PARTIAL_ATTENTION_DIRS || errors.saturating_mul(100) > entries;
        let f = Finding::new(FindingKind::DiskCategory, category.rel, category.title)
            .path(root)
            .size(bytes)
            .detail(format!("{} on disk", humansize::format_size(bytes, humansize::BINARY)))
            .severity(if attention { Severity::Attention } else { Severity::Info })
            .provenance("exact directory walk; symlinks skipped, hard links deduplicated, mount points not crossed")
            .coverage(coverage.clone())
            .meta(json!({ "group": "Disk allocation", "category": category.title, "entries": entries, "files": files, "dirs": dirs, "errors": errors, "complete": complete, "coverage": coverage }));
        send(f);
    }
}

/// Directory extensions macOS treats as packages. The walk never descends
/// into one: a file inside a package is part of the package, never a "loose"
/// large file (deleting `Photos.sqlite` out of a Photos library corrupts it),
/// and a project inside an `.xcodeproj` or `.app` is not a project of ours.
const PACKAGE_EXTENSIONS: &[&str] = &[
    // apps & code
    "app",
    "appex",
    "framework",
    "bundle",
    "plugin",
    "kext",
    "xpc",
    "prefpane",
    "qlgenerator",
    "mdimporter",
    "saver",
    "xcodeproj",
    "xcworkspace",
    "playground",
    "docset",
    "dsym",
    "pkg",
    "mpkg",
    // user data libraries — see `data_library_label`
    "photoslibrary",
    "migratedphotolibrary",
    "aplibrary",
    "musiclibrary",
    "tvlibrary",
    "imovielibrary",
    "fcpbundle",
    "logicx",
    "band",
    "abbu",
    "lrlibrary",
    "vmwarevm",
    "pvm",
    "utm",
    "sparsebundle",
    "rtfd",
    "scriv",
    "keynote",
    "pages",
    "numbers",
];

/// The package extension of a directory name (lower-cased), if it is one.
fn package_extension(name: &str) -> Option<&'static str> {
    let (_, ext) = name.rsplit_once('.')?;
    let ext = ext.to_ascii_lowercase();
    PACKAGE_EXTENSIONS.iter().copied().find(|e| *e == ext)
}

/// Packages worth surfacing as one opaque large item: user data that grows
/// (the Storage pane's "Photos 63 GB"), as opposed to apps and projects.
fn data_library_label(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "photoslibrary" | "migratedphotolibrary" => "Photos library",
        "aplibrary" => "Aperture library",
        "musiclibrary" => "Music library",
        "tvlibrary" => "TV library",
        "imovielibrary" => "iMovie library",
        "fcpbundle" => "Final Cut Pro library",
        "logicx" => "Logic Pro project",
        "band" => "GarageBand project",
        "lrlibrary" => "Lightroom library",
        "vmwarevm" => "VMware virtual machine",
        "pvm" => "Parallels virtual machine",
        "utm" => "UTM virtual machine",
        "sparsebundle" => "sparse bundle disk image",
        _ => return None,
    })
}

/// A large data-library package, sized whole by the sizing pool. `Info`, in
/// its own group, Reveal only: it is context for where the disk went, never
/// a cleanup candidate — a library is managed by its app.
fn large_package_finding(path: &Path, label: &str, size: u64) -> Finding {
    let key = path.to_string_lossy();
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = package_extension(&name).unwrap_or("");
    Finding::new(
        FindingKind::LargeFile,
        &key,
        format!("Large package — {name}"),
    )
    .path(path.to_path_buf())
    .detail(format!(
        "{label} ({}); a macOS package managed by its app — shown for size only, not a cleanup candidate",
        humansize::format_size(size, humansize::BINARY)
    ))
    .size(size)
    .severity(Severity::Info)
    .provenance("du over the whole package; contents never listed individually")
    .meta(json!({ "group": "Data libraries", "package": ext, "package_label": label }))
    .remedy(Remedy {
        label: "Reveal in Finder".into(),
        command: RemedyCommand::RevealInFinder {
            path: path.to_path_buf(),
        },
        reclaims_bytes: None,
        destructive: false,
        alternative: false,
        guard: None,
    })
}

/// Is `name` (a directory) a recognized build artifact, given its marker?
/// `siblings` is the parent's listing, so marker files next to the candidate
/// cost no syscall; only the probes *inside* `target`/`.venv` still touch
/// the disk, and only for directories with exactly those names.
fn is_artifact(
    name: &str,
    path: &Path,
    siblings: &[Entry],
    config: &crate::config::Config,
) -> bool {
    let sibling = |file: &str| has_sibling(siblings, file);
    let inside = |file: &str| path.join(file).exists();

    match name {
        "node_modules" => sibling("package.json"),
        // A cargo target dir is recognised by its parent manifest or, when
        // CARGO_TARGET_DIR points elsewhere / the manifest is a workspace
        // level up, by what cargo itself writes into it.
        "target" => sibling("Cargo.toml") || inside(".rustc_info.json") || inside("CACHEDIR.TAG"),
        ".venv" | "venv" => inside("pyvenv.cfg"),
        "__pycache__" => true,
        "build" | "dist" => PROJECT_MARKERS.iter().any(|m| sibling(m)),
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
    ctx: &ArtifactCtx,
    shared_bytes: Option<u64>,
) -> Finding {
    let key = path.to_string_lossy();
    let parent_name = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let title = match &ctx.worktree {
        Some((_, wt)) => format!("{label} — {parent_name} (worktree {wt})"),
        None => format!("{label} — {parent_name}"),
    };

    let mut meta = json!({
        "stale": stale,
        "artifact": label,
        "group": label,
        "marker": ctx.marker,
        "repo_root": ctx.repo_root,
        "worktree_of": ctx.worktree.as_ref().map(|(m, _)| m.clone()),
        "worktree_name": ctx.worktree.as_ref().map(|(_, n)| n.clone()),
    });
    // What trashing actually reclaims: pnpm links package files from its
    // store, so the store keeps most of these bytes alive.
    let reclaim = match (size, shared_bytes) {
        (Some(s), Some(shared)) => Some(s.saturating_sub(shared)),
        (s, _) => s,
    };
    let mut coverage: Option<String> = None;
    if let Some(store) = &ctx.pnpm_store {
        meta["layout"] = json!("pnpm");
        meta["store_dir"] = json!(store);
        meta["import_method"] = json!(ctx.pnpm_import_method);
        meta["shared_hardlink_bytes"] = json!(shared_bytes);
        meta["estimated_reclaim_bytes"] = json!(reclaim);
        coverage = Some(match shared_bytes {
            Some(b) => format!(
                "pnpm links package files from {}: {} of this size is hard-linked from the store and reclaims nothing while the store keeps it; APFS clones (pnpm's default import method) are not detectable and may make the real reclaim smaller still. Run `pnpm store prune` afterwards.",
                store.display(),
                humansize::format_size(b, humansize::BINARY)
            ),
            None => format!(
                "pnpm links package files from {}; the hard-linked and cloned share is not measured yet, so the real reclaim is at most this size.",
                store.display()
            ),
        });
    }

    let mut f = Finding::new(FindingKind::BuildArtifact, &key, title)
        .path(path.to_path_buf())
        .detail(match (&ctx.worktree, &ctx.pnpm_store) {
            (Some((main, _)), _) => format!(
                "Build artifact ({label}) in a worktree of {}",
                main.display()
            ),
            (_, Some(_)) => format!("Build artifact ({label}, pnpm-linked)"),
            _ => format!("Build artifact ({label})"),
        })
        .severity(Severity::Reclaimable)
        .meta(meta);
    if let Some(sz) = size {
        f = f.size(sz);
    }
    if let Some(lu) = last_used {
        f = f.last_used(lu);
    }
    if let Some(c) = coverage {
        f = f.coverage(c);
    }
    let trash = Remedy::new(
        "Move to Trash",
        RemedyCommand::Trash {
            path: path.to_path_buf(),
        },
    )
    .destructive()
    .reclaims(reclaim);
    // cargo's own cleanup respects its layout and reclaims immediately; Trash
    // stays available as the alternative (and is the primary action when the
    // manifest is missing).
    let manifest = path
        .parent()
        .map(|p| p.join("Cargo.toml"))
        .filter(|m| m.exists());
    match (label, manifest) {
        ("target", Some(manifest)) => {
            f = f
                .remedy(
                    Remedy::new(
                        "cargo clean",
                        RemedyCommand::Shell {
                            program: "cargo".into(),
                            args: vec![
                                "clean".into(),
                                "--manifest-path".into(),
                                manifest.display().to_string(),
                            ],
                        },
                    )
                    .destructive()
                    .reclaims(reclaim),
                )
                .remedy(trash.alternative());
        }
        _ => f = f.remedy(trash),
    }
    if ctx.pnpm_store.is_some() {
        f = f.remedy(
            Remedy::new(
                "pnpm store prune (after trashing)",
                RemedyCommand::Shell {
                    program: "pnpm".into(),
                    args: vec!["store".into(), "prune".into()],
                },
            )
            .destructive()
            .alternative(),
        );
    }
    f
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
            alternative: false,
            guard: None,
        })
        .remedy(Remedy {
            label: "Reveal in Finder".into(),
            command: RemedyCommand::RevealInFinder {
                path: path.to_path_buf(),
            },
            reclaims_bytes: None,
            destructive: false,
            alternative: false,
            guard: None,
        })
}

/// One of the largest files on the walked roots, threshold or not. `Info`,
/// in its own group, Reveal only: context for where the disk went, not a
/// cleanup candidate (files over the threshold are reported separately as
/// trashable "Large files" and excluded from this group).
fn largest_file_finding(path: &Path, size: u64, rank: usize) -> Finding {
    let key = format!("top:{}", path.to_string_lossy());
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    Finding::new(FindingKind::LargeFile, &key, format!("Largest — {name}"))
        .path(path.to_path_buf())
        .detail(format!("#{rank} largest file on the scanned roots"))
        .size(size)
        .severity(Severity::Info)
        .meta(json!({ "group": "Largest files", "rank": rank }))
        .remedy(Remedy {
            label: "Reveal in Finder".into(),
            command: RemedyCommand::RevealInFinder {
                path: path.to_path_buf(),
            },
            reclaims_bytes: None,
            destructive: false,
            alternative: false,
            guard: None,
        })
}

/// Cheap staleness heuristic: max mtime of the *files* directly next to an
/// artifact, straight from the parent's listing.
fn siblings_max_mtime(siblings: &[Entry]) -> Option<SystemTime> {
    siblings
        .iter()
        .filter(|e| e.kind == Kind::File)
        .map(|e| e.mtime_secs)
        .max()
        .map(|secs| UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64))
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

/// Size the fixed cache/backup targets that exist and emit a finding for each,
/// from the tree where possible (a target outside every walked root is
/// walked directly).
fn size_fixed_paths(
    paths: &crate::config::Paths,
    send: &dyn Fn(Finding),
    cancelled: &(dyn Fn() -> bool + Sync),
    trees: &[Arc<DirTree>],
) {
    for target in FIXED_TARGETS {
        if cancelled() {
            return;
        }
        let root = paths.expand(target.rel);
        if !root.exists() {
            continue;
        }
        if target.per_subdir {
            match find_node(trees, &root) {
                Some(node) => {
                    for child in &node.children {
                        let p = root.join(&child.name);
                        send(fixed_finding(&p, target.kind, &target.remedy, child.alloc));
                    }
                }
                None => {
                    let Ok(rd) = std::fs::read_dir(&root) else {
                        continue;
                    };
                    for entry in rd.flatten() {
                        let p = entry.path();
                        if !p.is_dir() {
                            continue;
                        }
                        let size = du_blocks(&p, cancelled);
                        send(fixed_finding(&p, target.kind, &target.remedy, size));
                    }
                }
            }
        } else {
            let size = match find_node(trees, &root) {
                Some(node) => node.alloc,
                None => du_blocks(&root, cancelled),
            };
            send(fixed_finding(&root, target.kind, &target.remedy, size));
        }
    }
}

fn fixed_finding(path: &Path, kind: FindingKind, fixed_remedy: &FixedRemedy, size: u64) -> Finding {
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
                alternative: false,
                guard: None,
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
                alternative: false,
                guard: None,
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
                alternative: false,
                guard: None,
            },
        ),
    };
    let group = match kind {
        FindingKind::IosBackup => "iOS Backups",
        _ => "Caches",
    };
    Finding::new(kind, &key, name)
        .path(path.to_path_buf())
        .size(size)
        .severity(severity)
        .meta(json!({ "group": group }))
        .remedy(remedy)
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
    async fn target_recognised_by_contents_without_manifest_and_cargo_clean_primary() {
        let home = tempfile::tempdir().unwrap();
        // A workspace: manifest at the root, target beside it → cargo clean
        // with that manifest is primary, Trash the alternative.
        let ws = home.path().join("ws");
        fs::create_dir_all(ws.join("target/debug")).unwrap();
        fs::write(ws.join("Cargo.toml"), "[workspace]").unwrap();
        fs::write(ws.join("target/debug/bin"), "x").unwrap();
        // A relocated target dir with only cargo's own markers inside.
        let reloc = home.path().join("cache/target");
        fs::create_dir_all(reloc.join("release")).unwrap();
        fs::write(reloc.join(".rustc_info.json"), "{}").unwrap();
        fs::write(reloc.join("release/bin"), "x").unwrap();
        // A plain dir named target with neither: not an artifact.
        let decoy = home.path().join("docs/target");
        fs::create_dir_all(&decoy).unwrap();
        fs::write(decoy.join("goal.md"), "x").unwrap();

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();
        let findings = drain(rx);
        let by_path = |p: &Path| {
            findings
                .iter()
                .rfind(|f| f.path.as_deref() == Some(p))
                .cloned()
        };
        let ws_target = by_path(&ws.join("target")).expect("workspace target");
        assert_eq!(ws_target.meta["marker"], "Cargo.toml");
        assert_eq!(
            ws_target.remedies[0].command.rendered(),
            format!(
                "cargo clean --manifest-path {}",
                ws.join("Cargo.toml").display()
            )
        );
        assert!(!ws_target.remedies[0].alternative);
        assert!(matches!(
            ws_target.remedies[1].command,
            RemedyCommand::Trash { .. }
        ));
        assert!(ws_target.remedies[1].alternative);
        let reloc_target = by_path(&reloc).expect("relocated target");
        assert_eq!(reloc_target.meta["marker"], "target/.rustc_info.json");
        assert!(matches!(
            reloc_target.remedies[0].command,
            RemedyCommand::Trash { .. }
        ));
        assert!(by_path(&decoy).is_none());
    }

    #[tokio::test]
    async fn worktree_artifacts_name_their_main_repo() {
        let home = tempfile::tempdir().unwrap();
        let main = home.path().join("dev/cubby");
        fs::create_dir_all(main.join(".git/worktrees/native-api")).unwrap();
        let wt = main.join(".claude/worktrees/native-api/cubby-ffi");
        fs::create_dir_all(wt.join("target/debug")).unwrap();
        fs::write(wt.join("Cargo.toml"), "[package]").unwrap();
        fs::write(wt.join("target/debug/bin"), "x").unwrap();
        fs::write(
            main.join(".claude/worktrees/native-api/.git"),
            format!(
                "gitdir: {}\n",
                main.join(".git/worktrees/native-api").display()
            ),
        )
        .unwrap();
        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();
        let f = drain(rx)
            .into_iter()
            .rfind(|f| f.path.as_deref() == Some(wt.join("target").as_path()))
            .expect("worktree target");
        assert_eq!(f.meta["worktree_of"], main.display().to_string());
        assert_eq!(f.meta["worktree_name"], "native-api");
        assert!(f.title.contains("(worktree native-api)"));
        assert_eq!(
            f.meta["repo_root"],
            main.join(".claude/worktrees/native-api")
                .display()
                .to_string()
        );
    }

    #[tokio::test]
    async fn pnpm_node_modules_reports_store_shared_bytes_honestly() {
        let home = tempfile::tempdir().unwrap();
        let proj = home.path().join("code/app");
        let nm = proj.join("node_modules");
        fs::create_dir_all(nm.join(".pnpm/pkg@1/node_modules/pkg")).unwrap();
        fs::write(proj.join("package.json"), "{}").unwrap();
        let store = home.path().join("store/v10/files");
        fs::create_dir_all(&store).unwrap();
        fs::write(store.join("blob"), vec![b'x'; 8192]).unwrap();
        fs::hard_link(
            store.join("blob"),
            nm.join(".pnpm/pkg@1/node_modules/pkg/index.js"),
        )
        .unwrap();
        fs::write(
            nm.join(".pnpm/pkg@1/node_modules/pkg/own.js"),
            vec![b'y'; 4096],
        )
        .unwrap();
        fs::write(
            nm.join(".modules.yaml"),
            format!(
                "layoutVersion: 5\nstoreDir: {}\npackageImportMethod: clone-or-copy\n",
                home.path().join("store/v10").display()
            ),
        )
        .unwrap();

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();
        let f = drain(rx)
            .into_iter()
            .rfind(|f| f.path.as_deref() == Some(nm.as_path()) && f.size_bytes.is_some())
            .expect("sized node_modules");
        assert_eq!(f.meta["layout"], "pnpm");
        let shared = f.meta["shared_hardlink_bytes"].as_u64().unwrap();
        let size = f.size_bytes.unwrap();
        assert!(shared > 0 && shared < size, "shared={shared} size={size}");
        assert_eq!(
            f.meta["estimated_reclaim_bytes"].as_u64().unwrap(),
            size - shared
        );
        assert_eq!(f.remedies[0].reclaims_bytes, Some(size - shared));
        assert!(f.coverage.as_deref().unwrap().contains("pnpm store prune"));
        assert!(f
            .remedies
            .iter()
            .any(|r| r.command.rendered() == "pnpm store prune" && r.alternative));
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
    async fn library_yields_no_artifact_findings() {
        let home = tempfile::tempdir().unwrap();
        // A node_modules buried in ~/Library is sized but never classified.
        let lib = home.path().join("Library/weird");
        fs::create_dir_all(lib.join("node_modules")).unwrap();
        fs::write(lib.join("package.json"), "{}").unwrap();

        let (ctx, rx, _) = ctx_for(home.path(), false, false, vec![]);
        FsScanner.scan(ctx).await.unwrap();

        assert!(
            !drain(rx)
                .iter()
                .any(|f| f.path.as_deref() == Some(lib.join("node_modules").as_path())),
            "nothing under ~/Library may become an artifact finding"
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

    /// `ctx_for` with a ~100-byte large-file threshold so small fixtures count.
    fn ctx_tiny_threshold(home: &Path) -> (ScanCtx, mpsc::Receiver<ScanEvent>) {
        let (mut ctx, rx, _) = ctx_for(home, false, false, vec![]);
        let mut config = (*ctx.config).clone();
        config.scan.large_file_threshold_gb = 1e-7;
        ctx.config = Arc::new(config);
        (ctx, rx)
    }

    fn big_file(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, vec![0u8; 64 * 1024]).unwrap();
    }

    #[tokio::test]
    async fn files_inside_packages_are_never_loose_large_files() {
        let home = tempfile::tempdir().unwrap();
        let sqlite = home
            .path()
            .join("Pictures/Photos Library.photoslibrary/database/Photos.sqlite");
        big_file(&sqlite);
        let app_bin = home.path().join("Applications/Foo.app/Contents/MacOS/Foo");
        big_file(&app_bin);
        let loose = home.path().join("Movies/huge.mkv");
        big_file(&loose);

        let (ctx, rx) = ctx_tiny_threshold(home.path());
        FsScanner.scan(ctx).await.unwrap();
        let findings = drain(rx);
        let large: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::LargeFile)
            .collect();
        assert!(
            !large
                .iter()
                .any(|f| f.path.as_deref() == Some(sqlite.as_path())),
            "Photos.sqlite must not be a loose large file: {large:?}"
        );
        assert!(!large
            .iter()
            .any(|f| f.path.as_deref() == Some(app_bin.as_path())));
        assert!(large
            .iter()
            .any(|f| f.path.as_deref() == Some(loose.as_path())));
    }

    #[tokio::test]
    async fn data_library_package_is_one_opaque_reveal_only_item() {
        let home = tempfile::tempdir().unwrap();
        let lib = home.path().join("Pictures/Photos Library.photoslibrary");
        big_file(&lib.join("database/Photos.sqlite"));
        big_file(&lib.join("originals/1/IMG_0001.HEIC"));

        let (ctx, rx) = ctx_tiny_threshold(home.path());
        FsScanner.scan(ctx).await.unwrap();
        let findings = drain(rx);
        // (The tiny threshold also catches the scanner's own size cache under
        // the temp home; only Pictures matters here.)
        let pictures = home.path().join("Pictures");
        let pkgs: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::LargeFile)
            .filter(|f| f.path.as_ref().unwrap().starts_with(&pictures))
            .collect();
        assert_eq!(pkgs.len(), 1, "{pkgs:?}");
        let f = pkgs[0];
        assert_eq!(f.path.as_deref(), Some(lib.as_path()));
        assert_eq!(f.title, "Large package — Photos Library.photoslibrary");
        assert_eq!(f.meta["package_label"], "Photos library");
        assert_eq!(f.meta["group"], "Data libraries");
        // Context, not a cleanup candidate.
        assert_eq!(f.severity, Severity::Info);
        assert!(f.size_bytes.unwrap() >= 2 * 64 * 1024);
        assert_eq!(f.remedies.len(), 1);
        assert!(matches!(
            f.remedies[0].command,
            RemedyCommand::RevealInFinder { .. }
        ));
        assert!(!f.remedies[0].destructive);
    }

    #[tokio::test]
    async fn code_packages_are_skipped_silently() {
        let home = tempfile::tempdir().unwrap();
        let app = home.path().join("Applications/Foo.APP");
        big_file(&app.join("Contents/MacOS/Foo"));
        let proj = home.path().join("code/Foo.xcodeproj");
        fs::create_dir_all(proj.join("node_modules/x")).unwrap();
        fs::write(proj.join("package.json"), "{}").unwrap();

        let (ctx, rx) = ctx_tiny_threshold(home.path());
        FsScanner.scan(ctx).await.unwrap();
        let findings = drain(rx);
        assert!(
            findings
                .iter()
                .all(|f| !f.path.as_ref().unwrap().starts_with(&app)
                    && !f.path.as_ref().unwrap().starts_with(&proj)),
            "nothing inside a code package may be reported: {findings:?}"
        );
    }

    #[test]
    fn package_extension_matches_case_insensitively_and_exactly() {
        assert_eq!(package_extension("Foo.app"), Some("app"));
        assert_eq!(package_extension("Foo.APP"), Some("app"));
        assert_eq!(
            package_extension("Photos Library.photoslibrary"),
            Some("photoslibrary")
        );
        assert_eq!(package_extension("foo.appdata"), None);
        assert_eq!(package_extension("app"), None);
        assert_eq!(data_library_label("app"), None);
        assert_eq!(
            data_library_label("vmwarevm"),
            Some("VMware virtual machine")
        );
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
