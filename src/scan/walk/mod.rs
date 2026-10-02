//! The parallel walk, and the accounting rules that make its numbers honest.
//!
//! Four decisions distinguish the totals here from `du`-style ones:
//!
//! 1. **Allocated, not apparent.** A size is `st_blocks * 512`. A 10 GB
//!    sparse disk image holding 200 MB counts as 200 MB, because that is what
//!    deleting it gives back. APFS clones are the known blind spot: two clones
//!    each report their full allocation.
//! 2. **Hard links once.** A file with `nlink > 1` is counted the first time
//!    its `(dev, ino)` is seen and skipped afterwards. Links the walk never
//!    reached (`seen < nlink`) are summed into `externally_linked`, which is
//!    how a pnpm `node_modules` reports how much of it is really the store's.
//! 3. **Directories once, too.** The same `(dev, ino)` rule applied to
//!    directories is what stops APFS *firmlinks* — `/Users` and
//!    `/System/Volumes/Data/Users` are the same directory — from doubling an
//!    entire home folder. Mount points are not entered at all.
//! 4. **Symlinks are never followed.** They are counted at their own size.
//!
//! Memory is bounded on purpose: only the directory tree survives the walk
//! (and only when the caller asks for it). Individual files contribute to
//! their parent's totals, to a small per-directory "largest" list, and to one
//! global bounded heap of the biggest files in the scan.

pub mod listing;

pub use listing::{Entry, Kind, Listing};

use crate::inventory::{DirId, DiskInventory, MemoryBudget, Reservation};
use rayon::prelude::*;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fs;
use std::ops::BitOr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// One directory and the totals for everything beneath it.
///
/// Kept for every directory of the walked roots (~750 k on a full disk), so
/// the layout is deliberately lean: boxed name and children (no `Vec`
/// capacity slack) and no per-directory file list — the largest files in a
/// directory are listed live by [`top_files_in`] when a view asks.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DirNode {
    /// The directory's own name — for the root, its full path.
    pub name: Box<str>,
    /// Allocated bytes of the whole subtree.
    pub alloc: u64,
    /// Apparent (logical) bytes of the whole subtree.
    pub apparent: u64,
    /// Files (and other non-directory entries) in the whole subtree.
    pub files: u64,
    /// Directories in the subtree, excluding this one.
    pub dirs: u64,
    /// Directories in the subtree that could not be read, plus entries the
    /// kernel could not stat — usually a missing Full Disk Access grant.
    pub errors: u64,
    /// Subdirectories, sorted by `alloc` descending then name. Empty when the
    /// walk ran with `keep_tree: false`.
    pub children: Box<[DirNode]>,
}

impl DirNode {
    /// Resolve `target` (an absolute path under `root`) inside this tree,
    /// which is rooted at `root`.
    pub fn find(&self, root: &Path, target: &Path) -> Option<&DirNode> {
        let rel = target.strip_prefix(root).ok()?;
        let mut node = self;
        for component in rel.components() {
            let name = component.as_os_str().to_string_lossy();
            node = node.children.iter().find(|c| *c.name == *name)?;
        }
        Some(node)
    }
}

/// One of the largest files in the scan, kept with its absolute path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BigFile {
    pub path: PathBuf,
    pub alloc: u64,
}

/// A query result: one directory with absolute paths filled in and children
/// expanded to a requested depth.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DirNodeSummary {
    pub name: String,
    pub path: PathBuf,
    pub alloc: u64,
    pub apparent: u64,
    pub files: u64,
    pub dirs: u64,
    pub errors: u64,
    /// Number of subdirectories, even when `children` is not expanded.
    pub child_count: u64,
    /// Expanded to the requested depth; empty beyond it.
    pub children: Vec<DirNodeSummary>,
}

/// The complete result of walking one root with the tree kept.
#[derive(Debug)]
pub struct DirTree {
    pub root: PathBuf,
    pub node: DiskInventory,
    /// Largest files anywhere under the root, largest first.
    pub top_files: Vec<BigFile>,
    /// False if the walk was cancelled or hit a deadline / entry cap.
    pub complete: bool,
    pub coverage: WalkCoverage,
    pub memory: Option<Arc<Reservation>>,
    pub files: u64,
    pub entries: Option<u64>,
    pub externally_linked: Option<u64>,
    pub dirs: u64,
    pub bytes: u64,
    pub errors: u64,
    pub scanned_at: SystemTime,
    pub elapsed: Duration,
}

impl DirTree {
    pub fn from_result(root: PathBuf, result: WalkResult, started: Instant) -> Self {
        let mut coverage = result.coverage;
        let inventory = result.inventory.unwrap_or_else(|| {
            DiskInventory::from_node(&result.root, MemoryBudget::shared()).unwrap_or_else(|_| {
                coverage.resource_limited = true;
                DiskInventory::new(MemoryBudget::shared()).expect("zero-byte reservation")
            })
        });
        DirTree {
            root,
            files: result.root.files,
            entries: Some(result.entries),
            externally_linked: Some(result.externally_linked),
            dirs: result.root.dirs,
            bytes: result.root.alloc,
            errors: result.root.errors,
            node: inventory,
            top_files: result.top_files,
            complete: result.complete && !coverage.resource_limited,
            coverage,
            memory: result.memory,
            scanned_at: SystemTime::now(),
            elapsed: started.elapsed(),
        }
    }

    /// The subtree at `path` (which must be the root or under it), children
    /// expanded `depth` levels (0 = the node alone).
    pub fn summary_at(&self, path: &Path, depth: usize) -> Option<DirNodeSummary> {
        self.summary_at_bounded(path, depth, 500)
    }

    pub fn summary_at_bounded(
        &self,
        path: &Path,
        depth: usize,
        max_nodes: usize,
    ) -> Option<DirNodeSummary> {
        self.node
            .summary_at_bounded(&self.root, path, depth, max_nodes)
    }

    pub fn largest_files(&self, n: usize) -> Vec<BigFile> {
        self.top_files.iter().take(n).cloned().collect()
    }
}

/// Bits the walker interprets; visitors may use the high half privately.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags(pub u32);

impl Flags {
    pub const NONE: Flags = Flags(0);
    /// Files below are never "loose": they do not enter the threshold list.
    pub const NOT_LOOSE: Flags = Flags(1);
    /// Files below never enter the global top-N heap.
    pub const NO_TOP: Flags = Flags(2);

    pub fn contains(self, other: Flags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for Flags {
    type Output = Flags;
    fn bitor(self, rhs: Flags) -> Flags {
        Flags(self.0 | rhs.0)
    }
}

/// What to do with a child directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirAction {
    /// List it and recurse; `flags` are inherited by the subtree.
    Descend(Flags),
    /// Do not list it; it contributes nothing.
    Skip,
}

/// Per-directory hooks. Every rayon worker calls these concurrently.
pub trait Visitor: Sync {
    fn inventory_publisher(&self, _root: &Path) -> Option<InventoryPublisher> {
        None
    }
    /// Whether to enter `child` (a directory entry of `parent`). `siblings`
    /// is the whole listing of `parent`, so a classifier can look for marker
    /// files by name without extra syscalls.
    fn on_child_dir(
        &self,
        parent: &Path,
        child: &Entry,
        siblings: &[Entry],
        flags: Flags,
    ) -> DirAction {
        let _ = (parent, child, siblings);
        DirAction::Descend(flags)
    }

    /// After the subtree under `dir` is complete and rolled up.
    fn on_dir_done(&self, dir: &Path, node: &DirNode, flags: Flags) {
        let _ = (dir, node, flags);
    }
}

pub type InventoryPublisher = Arc<dyn Fn(&DiskInventory) + Send + Sync>;

/// A visitor that descends everywhere and reports nothing.
pub struct NoVisitor;
impl Visitor for NoVisitor {}

#[derive(Debug, Clone)]
pub struct WalkOptions {
    /// Exact paths never entered.
    pub excludes: Vec<PathBuf>,
    /// Do not cross mount points (default true).
    pub same_device: bool,
    pub deadline: Option<Instant>,
    /// Stop (incomplete) once this many entries have been listed.
    pub max_entries: Option<u64>,
    /// Keep `DirNode::children`; false rolls them up and drops them.
    pub keep_tree: bool,
    pub keep_inventory: bool,
    /// Flags the root's own children are visited with — what the visitor
    /// would have chosen for the root had it been a child of something.
    pub root_flags: Flags,
    /// Size of the global largest-files heap; 0 disables.
    pub top_n: usize,
    /// Collect every loose file at least this large.
    pub threshold: Option<u64>,
}

impl Default for WalkOptions {
    fn default() -> Self {
        WalkOptions {
            excludes: Vec::new(),
            same_device: true,
            deadline: None,
            max_entries: None,
            keep_tree: true,
            keep_inventory: false,
            root_flags: Flags::NONE,
            top_n: 0,
            threshold: None,
        }
    }
}

/// Live counters for progress reporting; approximate by design.
#[derive(Debug, Default)]
pub struct WalkStats {
    pub files: AtomicU64,
    pub dirs: AtomicU64,
    pub bytes: AtomicU64,
    pub errors: AtomicU64,
    pub entries: AtomicU64,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct WalkCoverage {
    pub unreadable: u64,
    pub excluded: u64,
    pub dataless: u64,
    pub aliases: u64,
    pub mounts: u64,
    pub cancelled: bool,
    pub resource_limited: bool,
    pub summaries_truncated: bool,
    pub deadline: bool,
    pub entry_limit: bool,
}

#[derive(Debug)]
pub struct WalkResult {
    /// The root's node; `name` is the root path.
    pub root: DirNode,
    pub inventory: Option<DiskInventory>,
    pub resource_limited: bool,
    pub coverage: WalkCoverage,
    pub memory: Option<Arc<Reservation>>,
    /// False if cancelled, past the deadline, or over `max_entries`.
    pub complete: bool,
    /// Every listed entry, files and directories alike.
    pub entries: u64,
    /// Bytes of hard-linked files that also have links outside the walk.
    pub externally_linked: u64,
    /// Global largest files, largest first.
    pub top_files: Vec<BigFile>,
    /// Loose files at or above `threshold`, largest first.
    pub threshold_files: Vec<BigFile>,
    /// Unreadable directories plus unstat-able entries.
    pub errors: u64,
}

impl WalkResult {
    fn empty(root: &Path, errors: u64) -> Self {
        WalkResult {
            inventory: None,
            resource_limited: false,
            coverage: WalkCoverage {
                unreadable: errors,
                ..WalkCoverage::default()
            },
            memory: None,
            root: DirNode {
                name: root.to_string_lossy().into(),
                errors,
                ..DirNode::default()
            },
            complete: errors == 0,
            entries: 0,
            externally_linked: 0,
            top_files: Vec::new(),
            threshold_files: Vec::new(),
            errors,
        }
    }
}

struct LinkRec {
    nlink: u32,
    seen: u32,
    alloc: u64,
    apparent: u64,
    charged_owner: PathBuf,
    owner: PathBuf,
    top_owner: Option<PathBuf>,
    loose_owner: Option<PathBuf>,
    _memory: Reservation,
}

/// Shared state for one walk. Every rayon worker holds the same `&Walk`.
struct Walk<'a> {
    opts: &'a WalkOptions,
    visitor: &'a dyn Visitor,
    stats: Option<&'a WalkStats>,
    cancelled: &'a (dyn Fn() -> bool + Sync),
    root_dev: u64,
    /// `(dev, ino)` of directories already entered — the firmlink guard.
    seen_dirs: Mutex<HashSet<(u64, u64)>>,
    /// `nlink > 1` files: how many links exist, how many the walk saw.
    links: Mutex<HashMap<(u64, u64), LinkRec>>,
    top: Mutex<BinaryHeap<Reverse<(u64, PathBuf)>>>,
    /// Lock-free pre-filter: the smallest size in a full `top` heap, else 0.
    top_min: AtomicU64,
    threshold_files: Mutex<Vec<BigFile>>,
    stopped: AtomicBool,
    entries: AtomicU64,
    errors: AtomicU64,
    inventory: Option<InventoryCollector>,
    resource_limited: AtomicBool,
    excluded: AtomicU64,
    aliases: AtomicU64,
    mounts: AtomicU64,
    dataless: AtomicU64,
    summaries_truncated: AtomicBool,
    bookkeeping: Mutex<Reservation>,
}

struct InventoryCollector {
    arena: Arc<Mutex<DiskInventory>>,
    updates: crossbeam_channel::Sender<(DirId, DirNode, Reservation)>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl InventoryCollector {
    fn new(
        root: &Path,
        publisher: Option<InventoryPublisher>,
    ) -> Result<Self, crate::inventory::InventoryError> {
        let mut inventory = DiskInventory::new(MemoryBudget::shared())?;
        inventory.add_directory(None, root.as_os_str())?;
        let arena = Arc::new(Mutex::new(inventory));
        let (updates, receiver) = crossbeam_channel::bounded::<(DirId, DirNode, Reservation)>(32);
        let consumer = arena.clone();
        let worker = std::thread::spawn(move || {
            let interval = Duration::from_millis(100);
            let mut deadline = Instant::now() + interval;
            let mut dirty = false;
            loop {
                match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Ok((id, totals, _reservation)) => {
                        consumer.lock().unwrap().update_rollup(id, &totals);
                        dirty = true;
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
                if Instant::now() >= deadline {
                    if dirty {
                        if let Some(publisher) = &publisher {
                            let inventory = consumer.lock().unwrap();
                            let started = Instant::now();
                            publisher(&inventory);
                            tracing::debug!(
                                directories = inventory.len(),
                                inventory_bytes = inventory.retained_bytes(),
                                publish_micros = started.elapsed().as_micros() as u64,
                                "partial inventory published"
                            );
                        }
                    }
                    dirty = false;
                    deadline += interval;
                    if deadline <= Instant::now() {
                        deadline = Instant::now() + interval;
                    }
                }
            }
        });
        Ok(Self {
            arena,
            updates,
            worker: Some(worker),
        })
    }

    fn complete(mut self) -> DiskInventory {
        drop(self.updates);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("inventory aggregator panicked");
        }
        Arc::try_unwrap(self.arena)
            .expect("inventory still borrowed")
            .into_inner()
            .unwrap()
    }

    fn publish(&self, id: DirId, node: &DirNode) -> Result<(), crate::inventory::InventoryError> {
        let reservation = MemoryBudget::shared().reserve(std::mem::size_of::<DirNode>())?;
        let totals = DirNode {
            alloc: node.alloc,
            apparent: node.apparent,
            files: node.files,
            dirs: node.dirs,
            errors: node.errors,
            ..DirNode::default()
        };
        let started = Instant::now();
        let result = self
            .updates
            .send((id, totals, reservation))
            .map_err(|_| crate::inventory::InventoryError::ResourceLimit);
        tracing::trace!(
            directory_id = id.0,
            queue_depth = self.updates.len(),
            send_micros = started.elapsed().as_micros() as u64,
            "inventory batch enqueued"
        );
        result
    }
}

/// Walk `root` and return its totals (and tree, if `keep_tree`).
///
/// A symlinked root is resolved first (matching `read_dir`'s behaviour for
/// callers that size a path that happens to be a symlink); symlinks below
/// the root are never followed.
pub fn walk(
    root: &Path,
    opts: WalkOptions,
    visitor: &dyn Visitor,
    stats: Option<&Arc<WalkStats>>,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> WalkResult {
    let started = Instant::now();
    static FILESYSTEM_POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
    let result = FILESYSTEM_POOL
        .get_or_init(|| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(8)
                .thread_name(|index| format!("macaudit-fs-{index}"))
                .build()
                .expect("filesystem pool")
        })
        .install(|| walk_impl(root, opts, visitor, stats, cancelled));
    tracing::debug!(
        root = %root.display(),
        elapsed_micros = started.elapsed().as_micros() as u64,
        entries = result.entries,
        allocated_bytes = result.root.alloc,
        complete = result.complete,
        coverage = ?result.coverage,
        "filesystem walk finished"
    );
    result
}

fn walk_impl(
    root: &Path,
    opts: WalkOptions,
    visitor: &dyn Visitor,
    stats: Option<&Arc<WalkStats>>,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> WalkResult {
    let Ok(_materialization) = listing::MaterializationGuard::enter() else {
        return WalkResult::empty(root, 1);
    };
    let resolved = match fs::symlink_metadata(root) {
        Ok(md) if md.file_type().is_symlink() => match fs::canonicalize(root) {
            Ok(p) => p,
            Err(_) => return WalkResult::empty(root, 1),
        },
        Ok(_) => root.to_path_buf(),
        Err(_) => return WalkResult::empty(root, 1),
    };
    let first = match listing::list(&resolved) {
        Ok(l) => l,
        Err(error) => {
            if let Some(s) = stats {
                s.errors.fetch_add(1, Ordering::Relaxed);
            }
            let mut result = WalkResult::empty(root, 1);
            result.resource_limited = error.raw_os_error() == Some(libc::ENOMEM);
            result.coverage.resource_limited = result.resource_limited;
            result.coverage.dataless = u64::from(error.raw_os_error() == Some(libc::EDEADLK));
            return result;
        }
    };

    let inventory = if opts.keep_inventory {
        match InventoryCollector::new(&resolved, visitor.inventory_publisher(root)) {
            Ok(inventory) => Some(inventory),
            Err(_) => {
                let mut result = WalkResult::empty(root, 1);
                result.resource_limited = true;
                result.coverage.resource_limited = true;
                return result;
            }
        }
    } else {
        None
    };
    let summary_capacity = opts.top_n.min(crate::inventory::MAX_SEARCH_MATCHES);
    let threshold_capacity = if opts.threshold.is_some() {
        crate::inventory::MAX_SEARCH_MATCHES
    } else {
        0
    };
    let bookkeeping = match MemoryBudget::shared().reserve(
        std::mem::size_of::<DirNode>()
            + root.as_os_str().len() * 2
            + summary_capacity * std::mem::size_of::<Reverse<(u64, PathBuf)>>()
            + threshold_capacity * std::mem::size_of::<BigFile>(),
    ) {
        Ok(memory) => memory,
        Err(_) => {
            let mut result = WalkResult::empty(root, 1);
            result.resource_limited = true;
            result.coverage.resource_limited = true;
            return result;
        }
    };
    let mut walk = Walk {
        opts: &opts,
        visitor,
        stats: stats.map(Arc::as_ref),
        cancelled,
        root_dev: first.dev,
        seen_dirs: Mutex::new(HashSet::from([(first.dev, first.ino)])),
        links: Mutex::new(HashMap::new()),
        top: Mutex::new(BinaryHeap::with_capacity(summary_capacity)),
        top_min: AtomicU64::new(0),
        threshold_files: Mutex::new(Vec::with_capacity(threshold_capacity)),
        stopped: AtomicBool::new(false),
        entries: AtomicU64::new(0),
        errors: AtomicU64::new(0),
        inventory,
        resource_limited: AtomicBool::new(false),
        excluded: AtomicU64::new(0),
        aliases: AtomicU64::new(0),
        mounts: AtomicU64::new(0),
        dataless: AtomicU64::new(0),
        summaries_truncated: AtomicBool::new(false),
        bookkeeping: Mutex::new(bookkeeping),
    };

    let mut node = walk.scan_listed(&resolved, first, walk.opts.root_flags, DirId(0));
    node.name = root.to_string_lossy().into();

    let externally_linked = walk
        .links
        .lock()
        .expect("links poisoned")
        .values()
        .filter(|r| r.seen < r.nlink)
        .map(|r| r.alloc)
        .sum();
    for record in walk.links.lock().unwrap().values() {
        if let Some(path) = &record.top_owner {
            walk.offer_top(record.alloc, path.clone());
        }
        if let Some(path) = &record.loose_owner {
            walk.offer_threshold(record.alloc, path.clone());
        }
    }
    let mut top_files: Vec<BigFile> = walk
        .top
        .lock()
        .expect("top heap poisoned")
        .iter()
        .map(|Reverse((alloc, path))| BigFile {
            path: path.clone(),
            alloc: *alloc,
        })
        .collect();
    top_files.sort_by(|a, b| b.alloc.cmp(&a.alloc).then_with(|| a.path.cmp(&b.path)));
    let mut threshold_files =
        std::mem::take(&mut *walk.threshold_files.lock().expect("threshold poisoned"));
    threshold_files.sort_by(|a, b| b.alloc.cmp(&a.alloc).then_with(|| a.path.cmp(&b.path)));

    let mut inventory = walk.inventory.take().map(InventoryCollector::complete);
    if let Some(inventory) = inventory.as_mut() {
        for record in walk.links.lock().unwrap().values() {
            if record.owner != record.charged_owner {
                if let (Some(from), Some(to)) =
                    (record.charged_owner.parent(), record.owner.parent())
                {
                    inventory.transfer_file_charge(
                        &resolved,
                        from,
                        to,
                        record.alloc,
                        record.apparent,
                    );
                }
            }
        }
    }
    top_files.sort_by(|left, right| {
        right
            .alloc
            .cmp(&left.alloc)
            .then_with(|| left.path.cmp(&right.path))
    });
    threshold_files.sort_by(|left, right| {
        right
            .alloc
            .cmp(&left.alloc)
            .then_with(|| left.path.cmp(&right.path))
    });
    let coverage = WalkCoverage {
        unreadable: node.errors,
        excluded: walk.excluded.load(Ordering::Relaxed),
        aliases: walk.aliases.load(Ordering::Relaxed),
        mounts: walk.mounts.load(Ordering::Relaxed),
        dataless: walk.dataless.load(Ordering::Relaxed),
        cancelled: cancelled(),
        resource_limited: walk.resource_limited.load(Ordering::Relaxed),
        summaries_truncated: walk.summaries_truncated.load(Ordering::Relaxed),
        deadline: opts
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline),
        entry_limit: opts
            .max_entries
            .is_some_and(|limit| walk.entries.load(Ordering::Relaxed) > limit),
    };
    let complete = !walk.stopped.load(Ordering::Relaxed)
        && node.errors == 0
        && coverage.dataless == 0
        && coverage.excluded == 0;
    WalkResult {
        inventory,
        coverage,
        memory: Some(Arc::new(walk.bookkeeping.into_inner().unwrap())),
        resource_limited: walk.resource_limited.load(Ordering::Relaxed),
        errors: node.errors,
        root: node,
        complete,
        entries: walk.entries.load(Ordering::Relaxed),
        externally_linked,
        top_files,
        threshold_files,
    }
}

impl Walk<'_> {
    fn stop_requested(&self) -> bool {
        if self.stopped.load(Ordering::Relaxed) {
            return true;
        }
        let stop = (self.cancelled)() || self.opts.deadline.is_some_and(|d| Instant::now() >= d);
        if stop {
            self.stopped.store(true, Ordering::Relaxed);
        }
        stop
    }

    fn scan_dir(&self, path: &Path, flags: Flags, id: DirId) -> DirNode {
        let mut node = DirNode {
            name: name_of(path),
            ..DirNode::default()
        };
        if self.stop_requested() {
            return node;
        }
        let Ok(_materialization) = listing::MaterializationGuard::enter() else {
            node.errors = 1;
            return node;
        };
        if path.components().count() > 256 {
            self.resource_limited.store(true, Ordering::Relaxed);
            self.stopped.store(true, Ordering::Relaxed);
            return node;
        }
        let listing = match listing::list(path) {
            Ok(l) => l,
            Err(error) => {
                node.errors = 1;
                if error.raw_os_error() == Some(libc::ENOMEM) {
                    self.resource_limited.store(true, Ordering::Relaxed);
                    self.stopped.store(true, Ordering::Relaxed);
                }
                if error.raw_os_error() == Some(libc::EDEADLK) {
                    self.dataless.fetch_add(1, Ordering::Relaxed);
                }
                self.errors.fetch_add(1, Ordering::Relaxed);
                if let Some(s) = self.stats {
                    s.errors.fetch_add(1, Ordering::Relaxed);
                }
                if let Some(inventory) = &self.inventory {
                    let _ = inventory.publish(id, &node);
                }
                return node;
            }
        };
        // Second layer of the mount guard: the parent's listing reports the
        // covered vnode, so only the opened directory's own `st_dev` is
        // authoritative.
        if self.opts.same_device && listing.dev != self.root_dev {
            self.mounts.fetch_add(1, Ordering::Relaxed);
            return node;
        }
        self.scan_listed(path, listing, flags, id)
    }

    fn scan_listed(&self, path: &Path, listing: Listing, flags: Flags, id: DirId) -> DirNode {
        let mut node = DirNode {
            name: name_of(path),
            errors: listing.errors,
            ..DirNode::default()
        };
        // Also covers the root, which is listed before `scan_dir`'s check.
        if self.stop_requested() {
            return node;
        }
        self.errors.fetch_add(listing.errors, Ordering::Relaxed);
        let listed = listing.entries.len() as u64;
        let seen = self.entries.fetch_add(listed, Ordering::Relaxed) + listed;
        if self.opts.max_entries.is_some_and(|max| seen > max) {
            self.stopped.store(true, Ordering::Relaxed);
        }

        let transient_bytes = listing
            .entries
            .iter()
            .filter(|entry| entry.kind == Kind::Dir)
            .map(|entry| {
                path.as_os_str().len()
                    + entry.name.len() * 2
                    + std::mem::size_of::<DirNode>() * 3
                    + 64
            })
            .sum();
        let Ok(transient_memory) = MemoryBudget::shared().reserve(transient_bytes) else {
            self.resource_limited.store(true, Ordering::Relaxed);
            self.stopped.store(true, Ordering::Relaxed);
            node.errors += 1;
            return node;
        };
        let entries = listing.entries;
        let mut subdirs: Vec<(PathBuf, Flags, DirId)> = Vec::new();
        let mut own_files = 0u64;
        let mut own_bytes = 0u64;

        for e in &entries {
            if e.dataless {
                self.dataless.fetch_add(1, Ordering::Relaxed);
            }
            match e.kind {
                Kind::Dir => {
                    let child = path.join(&e.name);
                    if self.opts.excludes.iter().any(|x| x == &child) {
                        self.excluded.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if self.opts.same_device && e.mount_point {
                        self.mounts.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    // Firmlink / already-visited guard.
                    let mut seen_dirs = self.seen_dirs.lock().expect("seen_dirs poisoned");
                    if seen_dirs.contains(&(e.dev, e.ino)) {
                        self.aliases.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if self.bookkeeping.lock().unwrap().grow(64).is_err() {
                        self.resource_limited.store(true, Ordering::Relaxed);
                        self.stopped.store(true, Ordering::Relaxed);
                        break;
                    }
                    seen_dirs.insert((e.dev, e.ino));
                    drop(seen_dirs);
                    match self.visitor.on_child_dir(path, e, &entries, flags) {
                        DirAction::Descend(f) => {
                            let child_id = if let Some(inventory) = &self.inventory {
                                match inventory
                                    .arena
                                    .lock()
                                    .unwrap()
                                    .add_directory(Some(id), &e.name)
                                {
                                    Ok(child_id) => child_id,
                                    Err(_) => {
                                        self.resource_limited.store(true, Ordering::Relaxed);
                                        self.stopped.store(true, Ordering::Relaxed);
                                        break;
                                    }
                                }
                            } else {
                                DirId(0)
                            };
                            subdirs.push((child, f, child_id));
                        }
                        DirAction::Skip => {}
                    }
                }
                Kind::File | Kind::Other => {
                    if e.nlink > 1 {
                        let mut links = self.links.lock().expect("links poisoned");
                        match links.get_mut(&(e.dev, e.ino)) {
                            Some(rec) => {
                                rec.seen += 1;
                                let candidate = path.join(&e.name);
                                let extra_bytes = candidate
                                    .capacity()
                                    .saturating_sub(rec.owner.capacity())
                                    + rec.top_owner.as_ref().map_or(
                                        candidate.capacity(),
                                        |owner| {
                                            candidate.capacity().saturating_sub(owner.capacity())
                                        },
                                    )
                                    + rec.loose_owner.as_ref().map_or(
                                        candidate.capacity(),
                                        |owner| {
                                            candidate.capacity().saturating_sub(owner.capacity())
                                        },
                                    );
                                if rec._memory.grow(extra_bytes).is_err() {
                                    self.resource_limited.store(true, Ordering::Relaxed);
                                    self.stopped.store(true, Ordering::Relaxed);
                                    break;
                                }
                                if candidate < rec.owner {
                                    rec.owner.clone_from(&candidate);
                                }
                                if e.kind == Kind::File {
                                    if self.opts.top_n > 0
                                        && !flags.contains(Flags::NO_TOP)
                                        && rec
                                            .top_owner
                                            .as_ref()
                                            .is_none_or(|owner| candidate < *owner)
                                    {
                                        rec.top_owner = Some(candidate.clone());
                                    }
                                    if !flags.contains(Flags::NOT_LOOSE)
                                        && self.opts.threshold.is_some_and(|threshold| {
                                            e.alloc > 0 && e.alloc >= threshold
                                        })
                                        && rec
                                            .loose_owner
                                            .as_ref()
                                            .is_none_or(|owner| candidate < *owner)
                                    {
                                        rec.loose_owner = Some(candidate);
                                    }
                                }
                                continue; // this hard link's bytes are already counted
                            }
                            None => {
                                let owner = path.join(&e.name);
                                let Ok(memory) = MemoryBudget::shared().reserve(
                                    std::mem::size_of::<LinkRec>() * 3 + owner.capacity() * 4,
                                ) else {
                                    self.resource_limited.store(true, Ordering::Relaxed);
                                    self.stopped.store(true, Ordering::Relaxed);
                                    break;
                                };
                                links.insert(
                                    (e.dev, e.ino),
                                    LinkRec {
                                        nlink: e.nlink,
                                        seen: 1,
                                        alloc: e.alloc,
                                        apparent: e.apparent,
                                        charged_owner: owner.clone(),
                                        top_owner: (e.kind == Kind::File
                                            && self.opts.top_n > 0
                                            && !flags.contains(Flags::NO_TOP))
                                        .then(|| owner.clone()),
                                        loose_owner: (e.kind == Kind::File
                                            && !flags.contains(Flags::NOT_LOOSE)
                                            && self.opts.threshold.is_some_and(|threshold| {
                                                e.alloc > 0 && e.alloc >= threshold
                                            }))
                                        .then(|| owner.clone()),
                                        owner,
                                        _memory: memory,
                                    },
                                );
                            }
                        }
                    }
                    own_files += 1;
                    own_bytes += e.alloc;
                    node.apparent += e.apparent;
                    if e.kind == Kind::File && e.nlink <= 1 {
                        if self.opts.top_n > 0
                            && !flags.contains(Flags::NO_TOP)
                            && e.alloc >= self.top_min.load(Ordering::Relaxed)
                        {
                            self.offer_top(e.alloc, path.join(&e.name));
                        }
                        if let Some(threshold) = self.opts.threshold {
                            if !flags.contains(Flags::NOT_LOOSE)
                                && e.alloc > 0
                                && e.alloc >= threshold
                                && !self.offer_threshold(e.alloc, path.join(&e.name))
                            {
                                break;
                            }
                        }
                    }
                }
            }
        }

        if let Some(s) = self.stats {
            s.files.fetch_add(own_files, Ordering::Relaxed);
            s.bytes.fetch_add(own_bytes, Ordering::Relaxed);
            s.dirs.fetch_add(1, Ordering::Relaxed);
            s.entries.fetch_add(listed, Ordering::Relaxed);
            s.errors.fetch_add(listing.errors, Ordering::Relaxed);
        }

        node.files = own_files;
        node.alloc = own_bytes;
        if let Some(inventory) = &self.inventory {
            if inventory.publish(id, &node).is_err() {
                self.resource_limited.store(true, Ordering::Relaxed);
                self.stopped.store(true, Ordering::Relaxed);
            }
        }

        // rayon's work stealing is what keeps every core busy on a tree whose
        // branches differ in size by four orders of magnitude.
        let mut children: Vec<DirNode> = subdirs
            .into_par_iter()
            .map(|(path, flags, child_id)| self.scan_dir(&path, flags, child_id))
            .collect();
        for c in &children {
            node.alloc += c.alloc;
            node.apparent += c.apparent;
            node.files += c.files;
            node.dirs += 1 + c.dirs;
            node.errors += c.errors;
        }
        children.sort_by(|a, b| b.alloc.cmp(&a.alloc).then_with(|| a.name.cmp(&b.name)));
        node.children = children.into_boxed_slice();

        self.visitor.on_dir_done(path, &node, flags);
        if let Some(inventory) = &self.inventory {
            if inventory.publish(id, &node).is_err() {
                self.resource_limited.store(true, Ordering::Relaxed);
                self.stopped.store(true, Ordering::Relaxed);
            }
        }
        if !self.opts.keep_tree {
            node.children = Box::default();
        } else if self
            .bookkeeping
            .lock()
            .unwrap()
            .absorb(transient_memory)
            .is_err()
        {
            self.resource_limited.store(true, Ordering::Relaxed);
            self.stopped.store(true, Ordering::Relaxed);
        }
        node
    }

    fn offer_threshold(&self, alloc: u64, path: PathBuf) -> bool {
        let mut files = self.threshold_files.lock().expect("threshold poisoned");
        if files.len() >= crate::inventory::MAX_SEARCH_MATCHES {
            self.summaries_truncated.store(true, Ordering::Relaxed);
            return true;
        }
        if self
            .bookkeeping
            .lock()
            .unwrap()
            .grow(std::mem::size_of::<BigFile>() * 2 + path.capacity())
            .is_err()
        {
            self.resource_limited.store(true, Ordering::Relaxed);
            self.stopped.store(true, Ordering::Relaxed);
            return false;
        }
        files.push(BigFile { alloc, path });
        true
    }

    /// Offer a file to the global top-N heap.
    fn offer_top(&self, alloc: u64, path: PathBuf) {
        if alloc == 0 {
            return;
        }
        let mut heap = self.top.lock().expect("top heap poisoned");
        let limit = self.opts.top_n.min(crate::inventory::MAX_SEARCH_MATCHES);
        if heap.len() < limit {
            if self
                .bookkeeping
                .lock()
                .unwrap()
                .grow(std::mem::size_of::<BigFile>() * 3 + 16 * 1024)
                .is_err()
            {
                self.resource_limited.store(true, Ordering::Relaxed);
                self.stopped.store(true, Ordering::Relaxed);
                return;
            }
            heap.push(Reverse((alloc, path)));
            if heap.len() == limit {
                self.publish_min(&heap);
            }
        } else if heap.peek().is_some_and(|Reverse((min, _))| alloc > *min) {
            heap.pop();
            heap.push(Reverse((alloc, path)));
            self.publish_min(&heap);
        }
    }

    fn publish_min(&self, heap: &BinaryHeap<Reverse<(u64, PathBuf)>>) {
        if let Some(Reverse((min, _))) = heap.peek() {
            self.top_min.store(*min, Ordering::Relaxed);
        }
    }
}

/// Keep the `k` largest `(name, size)` pairs seen so far, largest first.
/// The `n` largest files directly inside `dir`, largest first (ties by name),
/// from a live listing: one `getattrlistbulk` pass, no recursion. Zero-byte
/// files are left out. An unreadable or missing directory yields an empty
/// list — the caller already knows about it from the tree's `errors`.
pub fn top_files_in(dir: &Path, n: usize) -> Vec<BigFile> {
    let limit = n.min(crate::inventory::MAX_PAGE_ROWS);
    if limit == 0 {
        return Vec::new();
    }
    let Ok(listing) = listing::list(dir) else {
        return Vec::new();
    };
    let mut heap = BinaryHeap::with_capacity(limit);
    for entry in &listing.entries {
        if entry.kind != Kind::File || entry.alloc == 0 {
            continue;
        }
        let candidate = Reverse((entry.alloc, dir.join(&entry.name)));
        if heap.len() < limit {
            heap.push(candidate);
        } else if heap.peek().is_some_and(|smallest| candidate < *smallest) {
            heap.pop();
            heap.push(candidate);
        }
    }
    let mut files: Vec<BigFile> = heap
        .into_iter()
        .map(|Reverse((alloc, path))| BigFile { alloc, path })
        .collect();
    files.sort_by(|a, b| b.alloc.cmp(&a.alloc).then_with(|| a.path.cmp(&b.path)));
    files
}

fn name_of(p: &Path) -> Box<str> {
    p.file_name()
        .map_or_else(|| p.to_string_lossy(), |n| n.to_string_lossy())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    fn write_file(path: &Path, size: usize) {
        std::fs::write(path, vec![0u8; size]).unwrap();
    }

    /// Mirrors `sizing::tests::shared_size_counts_external_hard_links_but_not_internal_ones`,
    /// but exercised directly against `walk` rather than through the `du_blocks_shared`
    /// wrapper.
    #[test]
    fn hardlinks_count_once_and_external_links_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("store");
        let nm = tmp.path().join("node_modules/.pnpm/pkg");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::create_dir_all(&nm).unwrap();
        // A file hard-linked from outside the walked root …
        let ext = store.join("big");
        write_file(&ext, 4096);
        std::fs::hard_link(&ext, nm.join("big")).unwrap();
        // … a file hard-linked twice *inside* the root (internal only) …
        let inner = nm.join("a");
        write_file(&inner, 4096);
        std::fs::hard_link(&inner, nm.join("b")).unwrap();
        // … and a plain file.
        write_file(&nm.join("plain"), 4096);

        let result = walk(&nm, WalkOptions::default(), &NoVisitor, None, &|| false);
        let ext_bytes = std::fs::metadata(&ext).unwrap().blocks() * 512;

        assert_eq!(result.externally_linked, ext_bytes);
        // Internal double link counted once: total = big + a + plain.
        assert_eq!(result.root.alloc, ext_bytes * 3);
        let tree = DirTree::from_result(nm, result, Instant::now());
        assert_eq!(tree.entries, Some(4));
        assert_eq!(tree.files, 3);
        assert_eq!(tree.externally_linked, Some(ext_bytes));
    }

    #[test]
    fn arena_assigns_shared_allocation_to_lexical_owner() {
        let fixture = tempfile::tempdir().unwrap();
        let first = fixture.path().join("a");
        let second = fixture.path().join("z");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        write_file(&second.join("shared"), 8192);
        std::fs::hard_link(second.join("shared"), first.join("shared")).unwrap();
        let allocation = std::fs::metadata(first.join("shared")).unwrap().blocks() * 512;
        for _ in 0..16 {
            let result = walk(
                fixture.path(),
                WalkOptions {
                    keep_tree: false,
                    keep_inventory: true,
                    top_n: 10,
                    ..WalkOptions::default()
                },
                &NoVisitor,
                None,
                &|| false,
            );
            let arena = result.inventory.as_ref().unwrap();
            assert_eq!(arena.alloc, allocation);
            assert_eq!(arena.files, 1);
            assert_eq!(
                arena.find(fixture.path(), &first).unwrap().alloc,
                allocation
            );
            assert_eq!(arena.find(fixture.path(), &second).unwrap().alloc, 0);
            assert_eq!(result.top_files[0].path, first.join("shared"));
            assert!(result.complete);
        }
    }

    #[test]
    fn hardlink_summary_owners_never_cross_protected_aliases() {
        struct ProtectedAliases;
        impl Visitor for ProtectedAliases {
            fn on_child_dir(
                &self,
                _parent: &Path,
                child: &Entry,
                _siblings: &[Entry],
                flags: Flags,
            ) -> DirAction {
                if child.name.to_string_lossy().contains("protected") {
                    DirAction::Descend(flags | Flags::NOT_LOOSE | Flags::NO_TOP)
                } else {
                    DirAction::Descend(flags)
                }
            }
        }
        for (protected, loose) in [
            ("a-protected.photoslibrary", "z-loose"),
            ("z-protected.artifact", "a-loose"),
            ("a-protected.Trash", "z-loose"),
        ] {
            let fixture = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(fixture.path().join(protected)).unwrap();
            std::fs::create_dir_all(fixture.path().join(loose)).unwrap();
            let protected_path = fixture.path().join(protected).join("shared");
            let loose_path = fixture.path().join(loose).join("shared");
            write_file(&protected_path, 8192);
            std::fs::hard_link(&protected_path, &loose_path).unwrap();
            for _ in 0..16 {
                let result = walk(
                    fixture.path(),
                    WalkOptions {
                        keep_tree: false,
                        keep_inventory: true,
                        top_n: 10,
                        threshold: Some(1),
                        ..WalkOptions::default()
                    },
                    &ProtectedAliases,
                    None,
                    &|| false,
                );
                assert_eq!(result.root.files, 1);
                assert_eq!(result.top_files.len(), 1);
                assert_eq!(result.threshold_files.len(), 1);
                assert_eq!(result.top_files[0].path, loose_path);
                assert_eq!(result.threshold_files[0].path, loose_path);
            }
        }
    }

    #[test]
    fn retained_tree_credits_survive_recursion_and_multiple_results() {
        fn retained_bytes(node: &DirNode) -> usize {
            node.name.len()
                + std::mem::size_of_val(&*node.children)
                + node.children.iter().map(retained_bytes).sum::<usize>()
        }
        let fixture = tempfile::tempdir().unwrap();
        for index in 0..1000 {
            std::fs::create_dir_all(fixture.path().join(format!("directory-{index}/nested")))
                .unwrap();
        }
        let first = walk(
            fixture.path(),
            WalkOptions::default(),
            &NoVisitor,
            None,
            &|| false,
        );
        let second = walk(
            fixture.path(),
            WalkOptions::default(),
            &NoVisitor,
            None,
            &|| false,
        );
        for result in [&first, &second] {
            assert_eq!(result.root.dirs, 2000);
            assert!(result.memory.as_ref().unwrap().bytes() >= retained_bytes(&result.root));
        }
        let first_memory = Arc::downgrade(first.memory.as_ref().unwrap());
        let second_memory = Arc::downgrade(second.memory.as_ref().unwrap());
        drop(first);
        assert!(first_memory.upgrade().is_none());
        assert!(second_memory.upgrade().is_some());
        drop(second);
        assert!(second_memory.upgrade().is_none());
    }

    #[test]
    fn bounded_summary_preserves_omitted_mass() {
        let fixture = tempfile::tempdir().unwrap();
        for index in 0..12 {
            let directory = fixture.path().join(format!("directory-{index}"));
            std::fs::create_dir_all(&directory).unwrap();
            write_file(&directory.join("file"), 4096);
        }
        let result = walk(
            fixture.path(),
            WalkOptions {
                keep_tree: false,
                keep_inventory: true,
                ..WalkOptions::default()
            },
            &NoVisitor,
            None,
            &|| false,
        );
        let total = result.root.alloc;
        let tree = DirTree::from_result(fixture.path().to_path_buf(), result, Instant::now());
        let summary = tree.summary_at_bounded(fixture.path(), 1, 4).unwrap();
        assert_eq!(summary.alloc, total);
        assert_eq!(summary.child_count, 12);
        assert_eq!(summary.children.len(), 3);
        assert!(
            summary
                .children
                .iter()
                .map(|child| child.alloc)
                .sum::<u64>()
                < summary.alloc
        );
    }

    #[test]
    fn cancellation_returns_zero_and_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("f"), 4096);

        let result = walk(
            dir.path(),
            WalkOptions::default(),
            &NoVisitor,
            None,
            &|| true,
        );

        assert_eq!(result.root.alloc, 0);
        assert!(!result.complete);
    }

    #[test]
    fn deadline_marks_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("f"), 4096);
        let opts = WalkOptions {
            deadline: Some(Instant::now() - Duration::from_secs(1)),
            ..WalkOptions::default()
        };

        let result = walk(dir.path(), opts, &NoVisitor, None, &|| false);

        assert!(!result.complete);
    }

    #[test]
    fn max_entries_marks_incomplete_but_reports_entries() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..10 {
            write_file(&dir.path().join(format!("{n}.bin")), 4096);
        }
        let opts = WalkOptions {
            max_entries: Some(3),
            ..WalkOptions::default()
        };

        let result = walk(dir.path(), opts, &NoVisitor, None, &|| false);

        assert!(!result.complete);
        // The directory that pushed the count over the cap is still counted
        // whole: the walker checks the cap between directories, not entries.
        assert!(result.entries >= 10, "got {}", result.entries);
    }

    #[test]
    fn excludes_skip_subtree_by_exact_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("excluded")).unwrap();
        write_file(&root.join("excluded/file"), 4096);
        // Same name, one level deeper: only the exact path is excluded.
        std::fs::create_dir_all(root.join("keep/excluded")).unwrap();
        write_file(&root.join("keep/excluded/file2"), 4096);

        let opts = WalkOptions {
            excludes: vec![root.join("excluded")],
            ..WalkOptions::default()
        };
        let result = walk(root, opts, &NoVisitor, None, &|| false);

        assert!(!result.root.children.iter().any(|c| &*c.name == "excluded"));
        let keep = result
            .root
            .children
            .iter()
            .find(|c| &*c.name == "keep")
            .expect("keep present");
        assert!(
            keep.children.iter().any(|c| &*c.name == "excluded"),
            "nested directory with the same name must not be excluded"
        );
        // Only keep/excluded/file2 is counted; excluded/file is not.
        assert_eq!(result.root.files, 1);
    }

    #[test]
    fn keep_tree_false_drops_children_but_keeps_totals() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        write_file(&root.join("a/b/f"), 4096);
        write_file(&root.join("top"), 4096);

        let with_tree = walk(
            root,
            WalkOptions {
                keep_tree: true,
                ..WalkOptions::default()
            },
            &NoVisitor,
            None,
            &|| false,
        );
        let without_tree = walk(
            root,
            WalkOptions {
                keep_tree: false,
                ..WalkOptions::default()
            },
            &NoVisitor,
            None,
            &|| false,
        );

        assert_eq!(with_tree.root.alloc, without_tree.root.alloc);
        assert_eq!(with_tree.root.files, without_tree.root.files);
        assert_eq!(with_tree.root.dirs, without_tree.root.dirs);
        assert!(!with_tree.root.children.is_empty());
        assert!(without_tree.root.children.is_empty());
    }

    #[test]
    fn top_files_in_lists_one_directory_live() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let sizes = [4096, 8192, 12288, 16384, 20480];
        for (i, sz) in sizes.iter().enumerate() {
            write_file(&root.join(format!("f{i}")), *sz);
        }
        write_file(&root.join("empty"), 0);
        // Files in subdirectories are not this directory's own files.
        std::fs::create_dir_all(root.join("sub")).unwrap();
        write_file(&root.join("sub/bigger"), 1 << 20);

        let top = top_files_in(root, 3);
        let names: Vec<_> = top
            .iter()
            .map(|f| f.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["f4", "f3", "f2"]);
        assert!(top.windows(2).all(|w| w[0].alloc >= w[1].alloc));
        assert!(top_files_in(root, 0).is_empty());
        assert!(top_files_in(&root.join("missing"), 3).is_empty());
    }

    #[test]
    fn global_top_n_and_threshold_lists() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        write_file(&root.join("a"), 4096);
        write_file(&root.join("sub/b"), 8192);
        write_file(&root.join("sub/c"), 12288);
        write_file(&root.join("zero"), 0);

        let opts = WalkOptions {
            top_n: 2,
            threshold: Some(8192),
            ..WalkOptions::default()
        };
        let result = walk(root, opts, &NoVisitor, None, &|| false);

        let top_paths: Vec<_> = result.top_files.iter().map(|f| f.path.clone()).collect();
        assert_eq!(top_paths, vec![root.join("sub/c"), root.join("sub/b")]);
        let threshold_paths: Vec<_> = result
            .threshold_files
            .iter()
            .map(|f| f.path.clone())
            .collect();
        assert_eq!(
            threshold_paths,
            vec![root.join("sub/c"), root.join("sub/b")]
        );

        // Even with room for everything, a zero-byte file never enters the
        // global top-N heap (`offer_top` refuses `alloc == 0` explicitly).
        let generous = WalkOptions {
            top_n: 10,
            ..WalkOptions::default()
        };
        let result2 = walk(root, generous, &NoVisitor, None, &|| false);
        assert_eq!(result2.top_files.len(), 3);
        assert!(!result2.top_files.iter().any(|f| f.path.ends_with("zero")));
    }

    #[test]
    fn visitor_flags_gate_top_and_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("hidden")).unwrap();
        write_file(&root.join("hidden/big"), 20480);
        write_file(&root.join("visible"), 4096);

        struct HiddenGate;
        impl Visitor for HiddenGate {
            fn on_child_dir(
                &self,
                _parent: &Path,
                child: &Entry,
                _siblings: &[Entry],
                flags: Flags,
            ) -> DirAction {
                if child.name.to_string_lossy() == "hidden" {
                    DirAction::Descend(Flags::NOT_LOOSE | Flags::NO_TOP)
                } else {
                    DirAction::Descend(flags)
                }
            }
        }

        let opts = WalkOptions {
            top_n: 10,
            threshold: Some(1),
            ..WalkOptions::default()
        };
        let result = walk(root, opts, &HiddenGate, None, &|| false);

        assert!(result.root.alloc >= 20480 + 4096);
        assert!(!result.top_files.iter().any(|f| f.path.ends_with("big")));
        assert!(!result
            .threshold_files
            .iter()
            .any(|f| f.path.ends_with("big")));
        assert!(result.top_files.iter().any(|f| f.path.ends_with("visible")));
        assert!(result
            .threshold_files
            .iter()
            .any(|f| f.path.ends_with("visible")));
    }

    #[test]
    fn visitor_skip_omits_the_subtree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("skipme")).unwrap();
        // Deliberately large: if the walker ever descended into `skipme`
        // despite the visitor's answer, this would show up in `root.alloc`.
        write_file(&root.join("skipme/huge"), 1_000_000);
        write_file(&root.join("kept"), 4096);

        struct SkipOne;
        impl Visitor for SkipOne {
            fn on_child_dir(
                &self,
                _parent: &Path,
                child: &Entry,
                _siblings: &[Entry],
                flags: Flags,
            ) -> DirAction {
                if child.name == "skipme" {
                    DirAction::Skip
                } else {
                    DirAction::Descend(flags)
                }
            }
        }

        let result = walk(root, WalkOptions::default(), &SkipOne, None, &|| false);

        assert!(!result.root.children.iter().any(|c| &*c.name == "skipme"));
        assert_eq!(result.root.alloc, 4096);
        assert_eq!(result.root.files, 1);
        assert_eq!(result.root.dirs, 0);
    }

    #[test]
    fn root_flags_reach_root_children() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("child/grandchild")).unwrap();

        struct Recorder(Mutex<Vec<(PathBuf, Flags)>>);
        impl Visitor for Recorder {
            fn on_child_dir(
                &self,
                parent: &Path,
                child: &Entry,
                _siblings: &[Entry],
                flags: Flags,
            ) -> DirAction {
                self.0
                    .lock()
                    .unwrap()
                    .push((parent.join(&child.name), flags));
                DirAction::Descend(flags)
            }
        }

        let marker = Flags(1 << 20);
        let recorder = Recorder(Mutex::new(Vec::new()));
        let opts = WalkOptions {
            root_flags: marker,
            ..WalkOptions::default()
        };
        walk(root, opts, &recorder, None, &|| false);

        let seen = recorder.0.into_inner().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(
            seen.iter().all(|(_, f)| f.contains(marker)),
            "root children and their descendants inherit root_flags: {seen:?}"
        );
    }

    #[test]
    fn on_dir_done_fires_per_directory_with_rolled_up_totals() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        write_file(&root.join("a/b/f"), 4096);
        write_file(&root.join("top"), 4096);

        struct Recorder(Mutex<Vec<(PathBuf, u64)>>);
        impl Visitor for Recorder {
            fn on_dir_done(&self, dir: &Path, node: &DirNode, _flags: Flags) {
                self.0
                    .lock()
                    .expect("recorder poisoned")
                    .push((dir.to_path_buf(), node.alloc));
            }
        }

        let recorder = Recorder(Mutex::new(Vec::new()));
        let result = walk(root, WalkOptions::default(), &recorder, None, &|| false);

        let seen = recorder.0.into_inner().expect("recorder poisoned");
        let root_entry = seen
            .iter()
            .find(|(p, _)| p == root)
            .expect("root directory reported");
        assert_eq!(root_entry.1, result.root.alloc);
        assert!(seen.iter().any(|(p, _)| p == &root.join("a")));
        assert!(seen.iter().any(|(p, _)| p == &root.join("a/b")));
    }

    #[test]
    fn unreadable_dir_is_counted_as_error() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root reads everything; the permission bits are moot.
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("locked")).unwrap();
        write_file(&root.join("locked/secret"), 4096);
        write_file(&root.join("visible"), 4096);
        std::fs::set_permissions(root.join("locked"), std::fs::Permissions::from_mode(0o000))
            .unwrap();

        let result = walk(root, WalkOptions::default(), &NoVisitor, None, &|| false);

        std::fs::set_permissions(root.join("locked"), std::fs::Permissions::from_mode(0o755))
            .unwrap();

        assert_eq!(result.root.errors, 1);
        assert_eq!(result.errors, 1);
        assert_eq!(result.root.files, 1, "only the visible file is counted");
        assert!(result.root.alloc >= 4096);
    }

    #[test]
    fn symlinks_are_counted_but_never_followed() {
        let outside = tempfile::tempdir().unwrap();
        let big = outside.path().join("big.bin");
        write_file(&big, 1_000_000);
        std::fs::create_dir_all(outside.path().join("otherdir")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_file(&root.join("small.bin"), 4096);
        symlink(&big, root.join("link-to-big")).unwrap();
        symlink(outside.path().join("otherdir"), root.join("link-to-dir")).unwrap();

        let result = walk(root, WalkOptions::default(), &NoVisitor, None, &|| false);

        assert!(result.root.alloc >= 4096);
        assert!(
            result.root.alloc < 1_000_000,
            "symlink target was counted/traversed: {}",
            result.root.alloc
        );
        assert_eq!(
            result.root.dirs, 0,
            "the symlinked directory must not be entered"
        );
    }

    #[test]
    fn partial_inventory_is_published_on_deadline_before_walk_completion() {
        struct SlowVisitor {
            observations: Arc<Mutex<Vec<(Duration, u64)>>>,
            started: Instant,
        }
        impl Visitor for SlowVisitor {
            fn inventory_publisher(&self, _root: &Path) -> Option<InventoryPublisher> {
                let observations = self.observations.clone();
                let started = self.started;
                Some(Arc::new(move |inventory| {
                    observations
                        .lock()
                        .unwrap()
                        .push((started.elapsed(), inventory.files));
                }))
            }
            fn on_dir_done(&self, _dir: &Path, _node: &DirNode, _flags: Flags) {
                std::thread::sleep(Duration::from_millis(350));
            }
        }
        let root = tempfile::tempdir().unwrap();
        write_file(&root.path().join("file"), 4096);
        let observations = Arc::new(Mutex::new(Vec::new()));
        let visitor = SlowVisitor {
            observations: observations.clone(),
            started: Instant::now(),
        };
        let result = walk(
            root.path(),
            WalkOptions {
                keep_tree: false,
                keep_inventory: true,
                ..WalkOptions::default()
            },
            &visitor,
            None,
            &|| false,
        );
        assert_eq!(result.inventory.unwrap().files, 1);
        let observations = observations.lock().unwrap();
        assert!(!observations.is_empty());
        assert_eq!(observations[0].1, 1);
        assert!(observations[0].0 < Duration::from_millis(300));
    }

    #[test]
    fn stats_counters_match_result() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("a")).unwrap();
        write_file(&root.join("a/f1"), 4096);
        write_file(&root.join("f2"), 4096);

        let stats = Arc::new(WalkStats::default());
        let result = walk(
            root,
            WalkOptions::default(),
            &NoVisitor,
            Some(&stats),
            &|| false,
        );

        assert_eq!(stats.files.load(Ordering::Relaxed), result.root.files);
        // `stats.dirs` is incremented once per directory *visited* (root
        // included), while `root.dirs` counts subdirectories excluding the
        // root itself — hence the off-by-one.
        assert_eq!(stats.dirs.load(Ordering::Relaxed), result.root.dirs + 1);
        assert_eq!(stats.bytes.load(Ordering::Relaxed), result.root.alloc);
    }

    #[test]
    fn find_and_summary_at() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::create_dir_all(root.join("b")).unwrap();
        write_file(&root.join("a/small"), 4096);
        write_file(&root.join("b/big"), 40960);

        let started = Instant::now();
        let opts = WalkOptions {
            top_n: 5,
            ..WalkOptions::default()
        };
        let result = walk(&root, opts, &NoVisitor, None, &|| false);
        let tree = DirTree::from_result(root.clone(), result, started);

        let s0 = tree.summary_at(&root, 0).expect("root resolves");
        assert_eq!(s0.child_count, 2);
        assert!(s0.children.is_empty());

        let s1 = tree.summary_at(&root, 1).expect("root at depth 1");
        assert_eq!(s1.children.len(), 2);
        for c in &s1.children {
            assert!(c.path.starts_with(&root));
        }

        let nested = root.join("b");
        let sn = tree.summary_at(&nested, 0).expect("nested path resolves");
        assert_eq!(sn.path, nested);

        let outside = tempfile::tempdir().unwrap();
        assert!(tree.summary_at(outside.path(), 0).is_none());

        let biggest = tree.largest_files(1);
        assert_eq!(biggest.len(), 1);
        assert_eq!(biggest[0].path, root.join("b/big"));
    }

    /// Mount points must never be entered, even for a real one. This needs a
    /// live macOS mount to assert against, so it is not portable to other
    /// platforms or to a filesystem fixture.
    #[cfg(target_os = "macos")]
    #[test]
    fn same_device_guard_predicate() {
        let root = Path::new("/System/Volumes");
        let result = walk(root, WalkOptions::default(), &NoVisitor, None, &|| false);
        assert!(
            !result.root.children.iter().any(|c| &*c.name == "Data"),
            "/System/Volumes/Data is a mount point and must be skipped"
        );
    }
}
