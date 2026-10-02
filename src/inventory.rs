use std::borrow::Cow;
use std::ffi::OsStr;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::scan::walk::{DirNode, DirNodeSummary};

pub const DEFAULT_MEMORY_LIMIT: usize = 1024 * 1024 * 1024;
pub const MAX_PAGE_ROWS: usize = 500;
pub const MAX_SEARCH_MATCHES: usize = 1000;
const NONE: u32 = u32::MAX;
const MAX_RETAINED_QUERIES: usize = 8;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InventoryError {
    #[error("engine memory budget exhausted")]
    ResourceLimit,
    #[error("query belongs to a retired run")]
    StaleRun,
    #[error("query handle or cursor has expired")]
    StaleQuery,
    #[error("invalid query page")]
    InvalidPage,
}

pub struct MemoryBudget {
    limit: usize,
    used: AtomicUsize,
    peak: AtomicUsize,
    reclaimers: Mutex<Vec<Weak<MemoryReclaimer>>>,
}

pub type MemoryReclaimer = dyn Fn() + Send + Sync;

impl std::fmt::Debug for MemoryBudget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemoryBudget")
            .field("limit", &self.limit)
            .field("used", &self.used())
            .field("peak", &self.peak())
            .finish()
    }
}

impl MemoryBudget {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            reclaimers: Mutex::new(Vec::new()),
        })
    }

    pub fn shared() -> Arc<Self> {
        static BUDGET: OnceLock<Arc<MemoryBudget>> = OnceLock::new();
        BUDGET
            .get_or_init(|| Self::new(DEFAULT_MEMORY_LIMIT))
            .clone()
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Acquire)
    }
    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn register_reclaimer(&self, reclaimer: &Arc<MemoryReclaimer>) {
        let mut reclaimers = self.reclaimers.lock().unwrap();
        reclaimers.retain(|reclaimer| reclaimer.strong_count() > 0);
        if reclaimers.len() < 64 {
            reclaimers.push(Arc::downgrade(reclaimer));
        }
    }

    pub fn reserve(self: &Arc<Self>, bytes: usize) -> Result<Reservation, InventoryError> {
        self.charge(bytes)?;
        Ok(Reservation {
            budget: self.clone(),
            bytes,
        })
    }

    fn charge(&self, bytes: usize) -> Result<(), InventoryError> {
        if self.try_charge(bytes).is_ok() {
            return Ok(());
        }
        if bytes > self.limit {
            return Err(InventoryError::ResourceLimit);
        }
        let reclaimers: Vec<_> = self
            .reclaimers
            .lock()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for reclaimer in reclaimers {
            reclaimer();
        }
        let result = self.try_charge(bytes);
        tracing::debug!(
            requested_bytes = bytes,
            used_bytes = self.used(),
            limit_bytes = self.limit,
            refused = result.is_err(),
            "memory pressure reclamation finished"
        );
        result
    }

    fn try_charge(&self, bytes: usize) -> Result<(), InventoryError> {
        let previous = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.limit)
            })
            .map_err(|_| InventoryError::ResourceLimit)?;
        self.peak.fetch_max(previous + bytes, Ordering::Relaxed);
        Ok(())
    }
}

#[derive(Debug)]
pub struct Reservation {
    budget: Arc<MemoryBudget>,
    bytes: usize,
}

impl Reservation {
    pub fn grow(&mut self, bytes: usize) -> Result<(), InventoryError> {
        let next = self
            .bytes
            .checked_add(bytes)
            .ok_or(InventoryError::ResourceLimit)?;
        self.budget.charge(bytes)?;
        self.bytes = next;
        Ok(())
    }

    pub fn resize(&mut self, bytes: usize) -> Result<(), InventoryError> {
        if bytes > self.bytes {
            self.grow(bytes - self.bytes)?;
        } else {
            let released = self.bytes - bytes;
            self.bytes = bytes;
            self.budget.used.fetch_sub(released, Ordering::AcqRel);
        }
        Ok(())
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn absorb(&mut self, mut other: Self) -> Result<(), InventoryError> {
        if !Arc::ptr_eq(&self.budget, &other.budget) {
            return Err(InventoryError::ResourceLimit);
        }
        self.bytes = self
            .bytes
            .checked_add(other.bytes)
            .ok_or(InventoryError::ResourceLimit)?;
        other.bytes = 0;
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

fn grow_arena<T>(
    values: &mut Vec<T>,
    additional: usize,
    memory: &mut Reservation,
) -> Result<(), InventoryError> {
    let capacity = values
        .capacity()
        .checked_add(additional)
        .ok_or(InventoryError::ResourceLimit)?;
    let bytes = capacity
        .checked_mul(std::mem::size_of::<T>())
        .ok_or(InventoryError::ResourceLimit)?;
    let previous_bytes = values.capacity() * std::mem::size_of::<T>();
    let mut replacement_memory = memory.budget.reserve(bytes)?;
    let mut replacement = Vec::new();
    replacement
        .try_reserve_exact(capacity)
        .map_err(|_| InventoryError::ResourceLimit)?;
    replacement_memory.resize(
        replacement
            .capacity()
            .checked_mul(std::mem::size_of::<T>())
            .ok_or(InventoryError::ResourceLimit)?,
    )?;
    replacement.append(values);
    drop(std::mem::replace(values, replacement));
    memory.resize(memory.bytes() - previous_bytes)?;
    memory.absorb(replacement_memory)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirId(pub u32);

#[derive(Debug, Default, Clone)]
pub struct DirectoryRecord {
    pub revision: u64,
    pub alloc: u64,
    pub apparent: u64,
    pub files: u64,
    pub dirs: u64,
    pub errors: u64,
    parent: u32,
    first_child: u32,
    next_sibling: u32,
    name_start: u32,
    name_len: u32,
}

#[derive(Debug)]
pub struct DiskInventory {
    nodes: Vec<DirectoryRecord>,
    names: Vec<u8>,
    memory: Reservation,
}

impl DiskInventory {
    pub fn new(budget: Arc<MemoryBudget>) -> Result<Self, InventoryError> {
        Ok(Self {
            nodes: Vec::new(),
            names: Vec::new(),
            memory: budget.reserve(0)?,
        })
    }

    pub fn from_node(root: &DirNode, budget: Arc<MemoryBudget>) -> Result<Self, InventoryError> {
        let mut arena = Self::new(budget)?;
        let mut pending = vec![(None, root)];
        while let Some((parent, node)) = pending.pop() {
            let id = arena.add_directory(parent, OsStr::new(node.name.as_ref()))?;
            arena.update(id, node);
            for child in node.children.iter().rev() {
                pending.push((Some(id), child));
            }
        }
        Ok(arena)
    }

    pub fn add_directory(
        &mut self,
        parent: Option<DirId>,
        name: &OsStr,
    ) -> Result<DirId, InventoryError> {
        let raw = name.as_bytes();
        let id = u32::try_from(self.nodes.len()).map_err(|_| InventoryError::ResourceLimit)?;
        let name_start =
            u32::try_from(self.names.len()).map_err(|_| InventoryError::ResourceLimit)?;
        let name_len = u32::try_from(raw.len()).map_err(|_| InventoryError::ResourceLimit)?;
        if id == NONE
            || self
                .names
                .len()
                .checked_add(raw.len())
                .is_none_or(|len| len > u32::MAX as usize)
        {
            return Err(InventoryError::ResourceLimit);
        }
        if self.nodes.len() == self.nodes.capacity() {
            grow_arena(&mut self.nodes, 4096, &mut self.memory)?;
        }
        let missing = raw
            .len()
            .saturating_sub(self.names.capacity() - self.names.len());
        if missing > 0 {
            let additional = missing.max(64 * 1024);
            grow_arena(&mut self.names, additional, &mut self.memory)?;
        }
        let next_sibling = parent
            .map(|parent| self.nodes[parent.0 as usize].first_child)
            .unwrap_or(NONE);
        self.names.extend_from_slice(raw);
        self.nodes.push(DirectoryRecord {
            parent: parent.map(|parent| parent.0).unwrap_or(NONE),
            first_child: NONE,
            next_sibling,
            name_start,
            name_len,
            ..DirectoryRecord::default()
        });
        if let Some(parent) = parent {
            self.nodes[parent.0 as usize].first_child = id;
            self.nodes[parent.0 as usize].revision =
                self.nodes[parent.0 as usize].revision.wrapping_add(1);
        }
        Ok(DirId(id))
    }

    pub fn update(&mut self, id: DirId, node: &DirNode) {
        let record = &mut self.nodes[id.0 as usize];
        if (
            record.alloc,
            record.apparent,
            record.files,
            record.dirs,
            record.errors,
        ) != (
            node.alloc,
            node.apparent,
            node.files,
            node.dirs,
            node.errors,
        ) {
            record.revision = record.revision.wrapping_add(1);
        }
        record.alloc = node.alloc;
        record.apparent = node.apparent;
        record.files = node.files;
        record.dirs = node.dirs;
        record.errors = node.errors;
    }

    pub fn update_rollup(&mut self, id: DirId, node: &DirNode) {
        let previous = self.nodes[id.0 as usize].clone();
        self.update(id, node);
        let mut parent = previous.parent;
        let changed = (
            previous.alloc,
            previous.apparent,
            previous.files,
            previous.dirs,
            previous.errors,
        ) != (
            node.alloc,
            node.apparent,
            node.files,
            node.dirs,
            node.errors,
        );
        while parent != NONE {
            let record = &mut self.nodes[parent as usize];
            record.alloc = record
                .alloc
                .saturating_sub(previous.alloc)
                .saturating_add(node.alloc);
            record.apparent = record
                .apparent
                .saturating_sub(previous.apparent)
                .saturating_add(node.apparent);
            record.files = record
                .files
                .saturating_sub(previous.files)
                .saturating_add(node.files);
            record.dirs = record
                .dirs
                .saturating_sub(previous.dirs)
                .saturating_add(node.dirs);
            record.errors = record
                .errors
                .saturating_sub(previous.errors)
                .saturating_add(node.errors);
            if changed {
                record.revision = record.revision.wrapping_add(1);
            }
            parent = record.parent;
        }
    }

    pub fn bounded_copy(&self, max_nodes: usize) -> Result<Self, InventoryError> {
        let max_nodes = max_nodes.min(2048);
        let _workspace = self.memory.budget.reserve(max_nodes * 128)?;
        let mut copy = Self::new(self.memory.budget.clone())?;
        let mut pending = Vec::with_capacity(max_nodes);
        if max_nodes > 0 && !self.is_empty() {
            pending.push((DirId(0), None, 0usize));
        }
        while let Some((source, parent, depth)) = pending.pop() {
            let source = self.directory(source).ok_or(InventoryError::InvalidPage)?;
            let destination = copy.add_directory(parent, OsStr::from_bytes(source.raw_name()))?;
            copy.update(
                destination,
                &DirNode {
                    alloc: source.alloc,
                    apparent: source.apparent,
                    files: source.files,
                    dirs: source.dirs,
                    errors: source.errors,
                    ..DirNode::default()
                },
            );
            copy.nodes[destination.0 as usize].revision = source.revision;
            let available = max_nodes.saturating_sub(copy.len() + pending.len());
            if available == 0 || depth >= 64 {
                continue;
            }
            let mut children = std::collections::BinaryHeap::with_capacity(available);
            for child in source.children() {
                let candidate = std::cmp::Reverse((
                    child.alloc,
                    std::cmp::Reverse(child.raw_name()),
                    child.id.0,
                ));
                if children.len() < available {
                    children.push(candidate);
                } else if children
                    .peek()
                    .is_some_and(|smallest| candidate < *smallest)
                {
                    children.pop();
                    children.push(candidate);
                }
            }
            let mut children = children.into_sorted_vec();
            children.reverse();
            pending.extend(
                children
                    .into_iter()
                    .map(|child| (DirId(child.0 .2), Some(destination), depth + 1)),
            );
        }
        Ok(copy)
    }

    pub fn transfer_file_charge(
        &mut self,
        root: &Path,
        from: &Path,
        to: &Path,
        alloc: u64,
        apparent: u64,
    ) {
        let source = self.find(root, from).map(|node| node.id);
        let destination = self.find(root, to).map(|node| node.id);
        let (Some(mut source), Some(mut destination)) = (source, destination) else {
            return;
        };
        loop {
            let node = &mut self.nodes[source.0 as usize];
            node.alloc = node.alloc.saturating_sub(alloc);
            node.apparent = node.apparent.saturating_sub(apparent);
            node.files = node.files.saturating_sub(1);
            node.revision = node.revision.wrapping_add(1);
            if node.parent == NONE {
                break;
            }
            source = DirId(node.parent);
        }
        loop {
            let node = &mut self.nodes[destination.0 as usize];
            node.alloc = node.alloc.saturating_add(alloc);
            node.apparent = node.apparent.saturating_add(apparent);
            node.files = node.files.saturating_add(1);
            node.revision = node.revision.wrapping_add(1);
            if node.parent == NONE {
                break;
            }
            destination = DirId(node.parent);
        }
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
    pub fn retained_bytes(&self) -> usize {
        self.memory.bytes()
    }
    pub fn directory(&self, id: DirId) -> Option<DirectoryRef<'_>> {
        self.nodes
            .get(id.0 as usize)
            .map(|_| DirectoryRef { arena: self, id })
    }

    pub fn find(&self, root: &Path, target: &Path) -> Option<DirectoryRef<'_>> {
        let mut current = self.directory(DirId(0))?;
        for component in target.strip_prefix(root).ok()?.components() {
            match component {
                Component::CurDir => {}
                Component::Normal(name) => {
                    current = current
                        .children()
                        .find(|child| child.raw_name() == name.as_bytes())?
                }
                _ => return None,
            }
        }
        Some(current)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(root = %root.display(), path = %path.display(), depth, max_nodes))]
    pub fn summary_at_bounded(
        &self,
        root: &Path,
        path: &Path,
        depth: usize,
        max_nodes: usize,
    ) -> Option<DirNodeSummary> {
        if max_nodes == 0 {
            return None;
        }
        let mut remaining = max_nodes.min(2048);
        let current = self.find(root, path)?;
        Some(current.summary(path, depth.min(64), &mut remaining))
    }
}

impl Deref for DiskInventory {
    type Target = DirectoryRecord;
    fn deref(&self) -> &Self::Target {
        static EMPTY: DirectoryRecord = DirectoryRecord {
            revision: 0,
            alloc: 0,
            apparent: 0,
            files: 0,
            dirs: 0,
            errors: 1,
            parent: NONE,
            first_child: NONE,
            next_sibling: NONE,
            name_start: 0,
            name_len: 0,
        };
        self.nodes.first().unwrap_or(&EMPTY)
    }
}

#[derive(Clone, Copy)]
pub struct DirectoryRef<'arena> {
    arena: &'arena DiskInventory,
    pub id: DirId,
}

impl<'arena> DirectoryRef<'arena> {
    pub fn name(self) -> Cow<'arena, str> {
        String::from_utf8_lossy(self.raw_name())
    }
    pub fn raw_name(self) -> &'arena [u8] {
        let record = &self.arena.nodes[self.id.0 as usize];
        &self.arena.names
            [record.name_start as usize..(record.name_start + record.name_len) as usize]
    }
    pub fn parent(self) -> Option<Self> {
        self.arena.directory(DirId(self.parent))
    }
    pub fn children(self) -> Children<'arena> {
        Children {
            arena: self.arena,
            next: self.first_child,
        }
    }
    fn summary(self, path: &Path, depth: usize, remaining: &mut usize) -> DirNodeSummary {
        *remaining -= 1;
        let mut children = Vec::new();
        let child_count = self.children().count() as u64;
        if depth > 0 {
            let mut candidates = std::collections::BinaryHeap::new();
            for child in self.children() {
                let candidate = std::cmp::Reverse((
                    child.alloc,
                    std::cmp::Reverse(child.raw_name()),
                    child.id.0,
                ));
                if candidates.len() < *remaining {
                    candidates.push(candidate);
                } else if candidates
                    .peek()
                    .is_some_and(|smallest| candidate < *smallest)
                {
                    candidates.pop();
                    candidates.push(candidate);
                }
            }
            let mut ids: Vec<_> = candidates.into_iter().map(|item| item.0).collect();
            ids.sort_unstable_by(|left, right| {
                right.0.cmp(&left.0).then_with(|| left.1 .0.cmp(right.1 .0))
            });
            for (_, _, id) in ids {
                if *remaining == 0 {
                    break;
                }
                let child = self.arena.directory(DirId(id)).unwrap();
                let child_path = path.join(OsStr::from_bytes(child.raw_name()));
                children.push(child.summary(&child_path, depth - 1, remaining));
            }
        }
        DirNodeSummary {
            name: self.name().into_owned(),
            path: path.to_path_buf(),
            alloc: self.alloc,
            apparent: self.apparent,
            files: self.files,
            dirs: self.dirs,
            errors: self.errors,
            child_count,
            children,
        }
    }
}

impl Deref for DirectoryRef<'_> {
    type Target = DirectoryRecord;
    fn deref(&self) -> &Self::Target {
        &self.arena.nodes[self.id.0 as usize]
    }
}

pub struct Children<'arena> {
    arena: &'arena DiskInventory,
    next: u32,
}
impl<'arena> Iterator for Children<'arena> {
    type Item = DirectoryRef<'arena>;
    fn next(&mut self) -> Option<Self::Item> {
        let child = self.arena.directory(DirId(self.next))?;
        self.next = child.next_sibling;
        Some(child)
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Complete,
    Partial,
    Cancelled,
    ResourceLimit,
    Unavailable,
    Truncated,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryMetadata {
    pub run_id: u64,
    pub request_id: u64,
    pub revision: u64,
    pub observed_unix_millis: u64,
    pub coverage: Coverage,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryCursor {
    pub handle: u64,
    pub run_id: u64,
    pub revision: u64,
    pub offset: usize,
}

#[derive(Debug, Serialize)]
pub struct QueryPage<T> {
    pub metadata: QueryMetadata,
    pub rows: Vec<T>,
    pub next_cursor: Option<QueryCursor>,
    #[serde(skip)]
    _memory: Reservation,
}

pub fn serialized_size<T: Serialize + ?Sized>(value: &T) -> Result<usize, InventoryError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or(std::io::ErrorKind::OutOfMemory)?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).map_err(|_| InventoryError::ResourceLimit)?;
    Ok(counter.0)
}

/// Accounts for owned heap allocations, excluding the inline size of `Self`.
pub trait QueryRow: Clone {
    fn retained_heap_bytes(&self) -> Result<usize, InventoryError>;

    /// Bounds peak heap allocations made by `Clone`, not the serialized size.
    fn clone_heap_bytes(&self) -> Result<usize, InventoryError>;
}

impl QueryRow for String {
    fn retained_heap_bytes(&self) -> Result<usize, InventoryError> {
        Ok(self.capacity())
    }

    fn clone_heap_bytes(&self) -> Result<usize, InventoryError> {
        Ok(self.len())
    }
}

impl QueryRow for Cow<'_, str> {
    fn retained_heap_bytes(&self) -> Result<usize, InventoryError> {
        match self {
            Cow::Borrowed(_) => Ok(0),
            Cow::Owned(value) => value.retained_heap_bytes(),
        }
    }

    fn clone_heap_bytes(&self) -> Result<usize, InventoryError> {
        match self {
            Cow::Borrowed(_) => Ok(0),
            Cow::Owned(value) => value.clone_heap_bytes(),
        }
    }
}

impl<T: QueryRow> QueryRow for Vec<T> {
    fn retained_heap_bytes(&self) -> Result<usize, InventoryError> {
        let inline = self
            .capacity()
            .checked_mul(std::mem::size_of::<T>())
            .ok_or(InventoryError::ResourceLimit)?;
        self.iter().try_fold(inline, |bytes, row| {
            bytes
                .checked_add(row.retained_heap_bytes()?)
                .ok_or(InventoryError::ResourceLimit)
        })
    }

    fn clone_heap_bytes(&self) -> Result<usize, InventoryError> {
        clone_rows_bytes(self)
    }
}

impl<T: QueryRow> QueryRow for Option<T> {
    fn retained_heap_bytes(&self) -> Result<usize, InventoryError> {
        self.as_ref().map_or(Ok(0), QueryRow::retained_heap_bytes)
    }

    fn clone_heap_bytes(&self) -> Result<usize, InventoryError> {
        self.as_ref().map_or(Ok(0), QueryRow::clone_heap_bytes)
    }
}

impl<T: QueryRow> QueryRow for Box<T> {
    fn retained_heap_bytes(&self) -> Result<usize, InventoryError> {
        std::mem::size_of::<T>()
            .checked_add(self.as_ref().retained_heap_bytes()?)
            .ok_or(InventoryError::ResourceLimit)
    }

    fn clone_heap_bytes(&self) -> Result<usize, InventoryError> {
        std::mem::size_of::<T>()
            .checked_add(self.as_ref().clone_heap_bytes()?)
            .ok_or(InventoryError::ResourceLimit)
    }
}

macro_rules! inline_query_rows {
    ($($type:ty),* $(,)?) => {
        $(impl QueryRow for $type {
            fn retained_heap_bytes(&self) -> Result<usize, InventoryError> {
                Ok(0)
            }

            fn clone_heap_bytes(&self) -> Result<usize, InventoryError> {
                Ok(0)
            }
        })*
    };
}

inline_query_rows!(
    (),
    bool,
    char,
    u8,
    u16,
    u32,
    u64,
    u128,
    usize,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    f32,
    f64
);

fn clone_rows_bytes<T: QueryRow>(rows: &[T]) -> Result<usize, InventoryError> {
    let inline = rows
        .len()
        .checked_mul(std::mem::size_of::<T>())
        .ok_or(InventoryError::ResourceLimit)?;
    rows.iter().try_fold(inline, |bytes, row| {
        bytes
            .checked_add(row.clone_heap_bytes()?)
            .ok_or(InventoryError::ResourceLimit)
    })
}

struct Query<T> {
    handle: u64,
    metadata: QueryMetadata,
    rows: Vec<T>,
    _memory: Reservation,
}
pub struct QueryRegistry<T> {
    run_id: u64,
    budget: Arc<MemoryBudget>,
    queries: [Option<Query<T>>; MAX_RETAINED_QUERIES],
    next_handle: u64,
}

impl<T: QueryRow> QueryRegistry<T> {
    pub fn new(run_id: u64, budget: Arc<MemoryBudget>) -> Self {
        Self {
            run_id,
            budget,
            queries: std::array::from_fn(|_| None),
            next_handle: 1,
        }
    }

    /// Adopts a same-budget lease held throughout row construction. Scratch must
    /// already be freed or covered by a separate lease before insertion.
    #[tracing::instrument(level = "debug", skip_all, fields(run_id = self.run_id, request_id, revision, rows = rows.len()))]
    pub fn insert(
        &mut self,
        request_id: u64,
        revision: u64,
        coverage: Coverage,
        rows: Vec<T>,
        memory: Reservation,
    ) -> Result<u64, InventoryError> {
        let mut query = Query {
            handle: self.next_handle,
            metadata: QueryMetadata {
                run_id: self.run_id,
                request_id,
                revision,
                coverage,
                observed_unix_millis: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            },
            rows,
            _memory: memory,
        };
        let retained = query.rows.retained_heap_bytes()?;
        if !Arc::ptr_eq(&query._memory.budget, &self.budget) || query._memory.bytes() < retained {
            return Err(InventoryError::ResourceLimit);
        }
        query._memory.resize(retained)?;
        let next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or(InventoryError::ResourceLimit)?;
        let slot = self
            .queries
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.queries
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, query)| query.as_ref().unwrap().handle)
                    .unwrap()
                    .0
            });
        self.queries[slot] = Some(query);
        let handle = self.next_handle;
        self.next_handle = next_handle;
        Ok(handle)
    }
    #[tracing::instrument(level = "debug", skip_all, fields(run_id = cursor.run_id, handle = cursor.handle, offset = cursor.offset, limit))]
    pub fn page(&self, cursor: QueryCursor, limit: usize) -> Result<QueryPage<T>, InventoryError> {
        if cursor.run_id != self.run_id {
            return Err(InventoryError::StaleRun);
        }
        let query = self
            .queries
            .iter()
            .flatten()
            .find(|query| query.handle == cursor.handle)
            .ok_or(InventoryError::StaleQuery)?;
        if cursor.revision != query.metadata.revision {
            return Err(InventoryError::StaleQuery);
        }
        if limit == 0 || limit > MAX_PAGE_ROWS || cursor.offset > query.rows.len() {
            return Err(InventoryError::InvalidPage);
        }
        let end = cursor.offset + limit.min(query.rows.len() - cursor.offset);
        let source = &query.rows[cursor.offset..end];
        let mut memory = self.budget.reserve(clone_rows_bytes(source)?)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(source.len())
            .map_err(|_| InventoryError::ResourceLimit)?;
        rows.extend(source.iter().cloned());
        let retained = rows.retained_heap_bytes()?;
        if retained > memory.bytes() {
            return Err(InventoryError::ResourceLimit);
        }
        memory.resize(retained)?;
        Ok(QueryPage {
            metadata: query.metadata.clone(),
            rows,
            next_cursor: (end < query.rows.len()).then_some(QueryCursor {
                offset: end,
                ..cursor
            }),
            _memory: memory,
        })
    }
    pub fn remove(&mut self, handle: u64) {
        if let Some(query) = self
            .queries
            .iter_mut()
            .find(|query| query.as_ref().is_some_and(|query| query.handle == handle))
        {
            *query = None;
        }
    }

    pub fn clear(&mut self) {
        for query in &mut self.queries {
            *query = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn reservations_include_retiring_owners() {
        let budget = MemoryBudget::new(16);
        let first = budget.reserve(10).unwrap();
        assert_eq!(
            budget.reserve(7).unwrap_err(),
            InventoryError::ResourceLimit
        );
        let second = budget.reserve(6).unwrap();
        drop(first);
        assert_eq!(budget.used(), 6);
        drop(second);
        assert_eq!(budget.used(), 0);
        assert_eq!(budget.peak(), 16);
    }

    #[test]
    fn pressure_reclaims_disposable_memory_before_refusing_inventory() {
        let budget = MemoryBudget::new(1024 * 1024);
        let cache = Arc::new(Mutex::new(Some(budget.reserve(900 * 1024).unwrap())));
        let weak_cache = Arc::downgrade(&cache);
        let reclaimer: Arc<MemoryReclaimer> = Arc::new(move || {
            if let Some(cache) = weak_cache.upgrade() {
                if let Ok(mut cache) = cache.try_lock() {
                    cache.take();
                }
            }
        });
        budget.register_reclaimer(&reclaimer);
        let mut inventory = DiskInventory::new(budget.clone()).unwrap();
        inventory.add_directory(None, OsStr::new("root")).unwrap();
        assert!(cache.lock().unwrap().is_none());
        assert!(budget.peak() <= budget.limit());
    }

    #[test]
    fn pressure_never_waits_for_a_busy_cache_or_drops_retained_memory() {
        let budget = MemoryBudget::new(16);
        let cache = Arc::new(Mutex::new(Some(budget.reserve(10).unwrap())));
        let retained = budget.reserve(6).unwrap();
        let weak_cache = Arc::downgrade(&cache);
        let reclaimer: Arc<MemoryReclaimer> = Arc::new(move || {
            if let Some(cache) = weak_cache.upgrade() {
                if let Ok(mut cache) = cache.try_lock() {
                    cache.take();
                }
            }
        });
        budget.register_reclaimer(&reclaimer);
        let guard = cache.lock().unwrap();
        assert_eq!(
            budget.reserve(1).unwrap_err(),
            InventoryError::ResourceLimit
        );
        assert_eq!(budget.used(), 16);
        drop(guard);
        drop(reclaimer);
        assert_eq!(
            budget.reserve(1).unwrap_err(),
            InventoryError::ResourceLimit
        );
        assert_eq!(retained.bytes(), 6);
    }

    #[test]
    fn clearing_queries_expires_handles_without_reusing_their_generation() {
        let budget = MemoryBudget::new(4096);
        let mut queries = QueryRegistry::new(1, budget.clone());
        let memory = budget.reserve(std::mem::size_of::<i32>()).unwrap();
        let handle = queries
            .insert(1, 1, Coverage::Complete, vec![1], memory)
            .unwrap();
        queries.clear();
        let memory = budget.reserve(std::mem::size_of::<i32>()).unwrap();
        let replacement = queries
            .insert(1, 1, Coverage::Complete, vec![2], memory)
            .unwrap();
        assert_ne!(handle, replacement);
        assert!(matches!(
            queries.page(
                QueryCursor {
                    handle,
                    run_id: 1,
                    revision: 1,
                    offset: 0
                },
                1
            ),
            Err(InventoryError::StaleQuery)
        ));
    }

    #[test]
    fn expired_handles_and_retired_runs_are_rejected() {
        let budget = MemoryBudget::new(1024);
        let mut queries = QueryRegistry::new(3, budget.clone());
        let memory = budget.reserve(3 * std::mem::size_of::<i32>()).unwrap();
        let handle = queries
            .insert(7, 1, Coverage::Complete, vec![1, 2, 3], memory)
            .unwrap();
        let cursor = QueryCursor {
            handle,
            run_id: 3,
            revision: 1,
            offset: 0,
        };
        assert_eq!(
            queries
                .page(cursor.clone(), 2)
                .unwrap()
                .next_cursor
                .unwrap()
                .offset,
            2
        );
        assert!(matches!(
            queries.page(
                QueryCursor {
                    run_id: 2,
                    ..cursor.clone()
                },
                2
            ),
            Err(InventoryError::StaleRun)
        ));
        queries.remove(handle);
        assert!(matches!(
            queries.page(cursor, 2),
            Err(InventoryError::StaleQuery)
        ));
    }

    #[test]
    fn pooled_names_preserve_non_utf8_paths() {
        let mut arena = DiskInventory::new(MemoryBudget::new(1024 * 1024)).unwrap();
        let root = arena.add_directory(None, OsStr::new("/root")).unwrap();
        let raw = OsStr::from_bytes(b"odd\xff");
        let child = arena.add_directory(Some(root), raw).unwrap();
        assert_eq!(
            arena
                .find(Path::new("/root"), &Path::new("/root").join(raw))
                .unwrap()
                .id,
            child
        );
        assert!(arena
            .find(Path::new("/root"), Path::new("/root/../other"))
            .is_none());
    }

    #[test]
    fn arena_refuses_growth_before_exceeding_budget() {
        let budget = MemoryBudget::new(1024);
        let mut arena = DiskInventory::new(budget.clone()).unwrap();
        assert_eq!(
            arena.add_directory(None, OsStr::new("root")),
            Err(InventoryError::ResourceLimit)
        );
        assert_eq!(arena.len(), 0);
        assert_eq!(budget.used(), 0);
        assert!(budget.peak() <= budget.limit());
    }

    #[test]
    fn paged_copies_remain_budgeted_until_consumed() {
        let budget = MemoryBudget::new(4096);
        let mut queries = QueryRegistry::new(1, budget.clone());
        let memory = budget
            .reserve(std::mem::size_of::<String>() + "a filename".len())
            .unwrap();
        let handle = queries
            .insert(
                1,
                1,
                Coverage::Complete,
                vec![String::from("a filename")],
                memory,
            )
            .unwrap();
        let retained = budget.used();
        let page = queries
            .page(
                QueryCursor {
                    handle,
                    run_id: 1,
                    revision: 1,
                    offset: 0,
                },
                1,
            )
            .unwrap();
        assert!(budget.used() > retained);
        queries.remove(handle);
        assert!(budget.used() > 0);
        drop(page);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn absorbing_reservations_transfers_without_recharging() {
        let budget = MemoryBudget::new(16);
        let mut retained = budget.reserve(6).unwrap();
        let transient = budget.reserve(10).unwrap();
        retained.absorb(transient).unwrap();
        assert_eq!(retained.bytes(), 16);
        assert_eq!(budget.used(), 16);
        assert_eq!(budget.peak(), 16);
        assert_eq!(
            budget.reserve(1).unwrap_err(),
            InventoryError::ResourceLimit
        );
        drop(retained);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn absorbing_reservations_rejects_different_budgets() {
        let budget = MemoryBudget::new(16);
        let other_budget = MemoryBudget::new(16);
        let mut retained = budget.reserve(6).unwrap();
        let other = other_budget.reserve(10).unwrap();
        assert_eq!(retained.absorb(other), Err(InventoryError::ResourceLimit));
        assert_eq!(retained.bytes(), 6);
        assert_eq!(budget.used(), 6);
        assert_eq!(other_budget.used(), 0);
    }

    #[test]
    fn node_growth_refuses_when_only_final_capacity_fits() {
        let chunk = 4096 * std::mem::size_of::<DirectoryRecord>();
        let budget = MemoryBudget::new(2 * chunk);
        let mut arena = DiskInventory::new(budget.clone()).unwrap();
        for _ in 0..4096 {
            arena.add_directory(None, OsStr::new("")).unwrap();
        }
        assert_eq!(budget.used(), chunk);
        assert_eq!(
            arena.add_directory(None, OsStr::new("")),
            Err(InventoryError::ResourceLimit)
        );
        assert_eq!(arena.len(), 4096);
        assert_eq!(arena.nodes.capacity(), 4096);
        assert_eq!(arena.retained_bytes(), chunk);
        assert_eq!(budget.used(), chunk);
        assert!(budget.peak() <= budget.limit());
    }

    #[test]
    fn node_growth_reserves_old_and_new_buffers_then_releases_old() {
        let chunk = 4096 * std::mem::size_of::<DirectoryRecord>();
        let budget = MemoryBudget::new(3 * chunk);
        let mut arena = DiskInventory::new(budget.clone()).unwrap();
        for _ in 0..4097 {
            arena.add_directory(None, OsStr::new("")).unwrap();
        }
        assert_eq!(arena.nodes.capacity(), 8192);
        assert_eq!(arena.retained_bytes(), 2 * chunk);
        assert_eq!(budget.used(), 2 * chunk);
        assert_eq!(budget.peak(), 3 * chunk);
        drop(arena);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn name_growth_refuses_when_only_final_capacity_fits() {
        let nodes = 4096 * std::mem::size_of::<DirectoryRecord>();
        let chunk = 64 * 1024;
        let budget = MemoryBudget::new(nodes + 2 * chunk);
        let mut arena = DiskInventory::new(budget.clone()).unwrap();
        let name = vec![b'a'; chunk];
        let root = arena.add_directory(None, OsStr::from_bytes(&name)).unwrap();
        assert_eq!(
            arena.add_directory(Some(root), OsStr::new("b")),
            Err(InventoryError::ResourceLimit)
        );
        assert_eq!(arena.len(), 1);
        assert_eq!(arena.names.len(), chunk);
        assert_eq!(arena.names.capacity(), chunk);
        assert_eq!(budget.used(), nodes + chunk);
    }

    #[test]
    fn name_growth_reserves_old_and_new_buffers_then_releases_old() {
        let nodes = 4096 * std::mem::size_of::<DirectoryRecord>();
        let chunk = 64 * 1024;
        let budget = MemoryBudget::new(nodes + 3 * chunk);
        let mut arena = DiskInventory::new(budget.clone()).unwrap();
        let name = vec![b'a'; chunk];
        let root = arena.add_directory(None, OsStr::from_bytes(&name)).unwrap();
        arena.add_directory(Some(root), OsStr::new("b")).unwrap();
        assert_eq!(arena.names.capacity(), 2 * chunk);
        assert_eq!(arena.retained_bytes(), nodes + 2 * chunk);
        assert_eq!(budget.used(), nodes + 2 * chunk);
        assert_eq!(budget.peak(), nodes + 3 * chunk);
    }

    #[test]
    fn failed_arena_allocation_releases_tentative_reservation() {
        let budget = MemoryBudget::new(usize::MAX);
        let mut memory = budget.reserve(0).unwrap();
        let mut values = Vec::<u64>::new();
        assert_eq!(
            grow_arena(
                &mut values,
                usize::MAX / std::mem::size_of::<u64>(),
                &mut memory
            ),
            Err(InventoryError::ResourceLimit)
        );
        assert_eq!(values.capacity(), 0);
        assert_eq!(memory.bytes(), 0);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn tiny_serialized_string_cannot_hide_large_retained_capacity() {
        let budget = MemoryBudget::new(4096);
        let mut queries = QueryRegistry::new(1, budget.clone());
        let memory = budget.reserve(4096).unwrap();
        let mut value = String::with_capacity(1024 * 1024);
        value.push('x');
        let rows = vec![value];
        assert_eq!(serialized_size(&rows).unwrap(), 5);
        assert!(rows.retained_heap_bytes().unwrap() > budget.limit());
        assert_eq!(
            queries.insert(1, 1, Coverage::Complete, rows, memory),
            Err(InventoryError::ResourceLimit)
        );
        assert_eq!(budget.used(), 0);
        assert!(budget.peak() <= budget.limit());
    }

    #[test]
    fn query_adopts_construction_lease_and_retains_exact_nested_capacities() {
        let budget = MemoryBudget::new(4096);
        let mut queries = QueryRegistry::new(1, budget.clone());
        let memory = budget.reserve(4096).unwrap();
        let mut rows = Vec::with_capacity(3);
        let mut row = Vec::with_capacity(10);
        let mut value = String::with_capacity(100);
        value.push('x');
        row.push(Some(Box::new(value)));
        rows.push(row);
        let retained = 3 * std::mem::size_of::<Vec<Option<Box<String>>>>()
            + 10 * std::mem::size_of::<Option<Box<String>>>()
            + std::mem::size_of::<String>()
            + 100;
        assert_eq!(rows.retained_heap_bytes().unwrap(), retained);
        let handle = queries
            .insert(1, 1, Coverage::Complete, rows, memory)
            .unwrap();
        assert_eq!(budget.used(), retained);
        assert_eq!(budget.peak(), 4096);
        queries.remove(handle);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn query_rejects_construction_lease_from_another_budget() {
        let budget = MemoryBudget::new(4096);
        let other_budget = MemoryBudget::new(4096);
        let mut queries = QueryRegistry::new(1, budget.clone());
        let memory = other_budget.reserve(std::mem::size_of::<i32>()).unwrap();
        assert_eq!(
            queries.insert(1, 1, Coverage::Complete, vec![1], memory),
            Err(InventoryError::ResourceLimit)
        );
        assert_eq!(budget.used(), 0);
        assert_eq!(other_budget.used(), 0);
    }

    #[test]
    fn overflowing_row_accounting_is_rejected_without_charging() {
        #[derive(Clone)]
        struct OverflowRow;

        impl QueryRow for OverflowRow {
            fn retained_heap_bytes(&self) -> Result<usize, InventoryError> {
                Ok(usize::MAX)
            }

            fn clone_heap_bytes(&self) -> Result<usize, InventoryError> {
                Ok(0)
            }
        }

        let budget = MemoryBudget::new(1024);
        let mut queries = QueryRegistry::new(1, budget.clone());
        let memory = budget.reserve(0).unwrap();
        assert_eq!(
            queries.insert(
                1,
                1,
                Coverage::Complete,
                vec![OverflowRow, OverflowRow],
                memory
            ),
            Err(InventoryError::ResourceLimit)
        );
        assert_eq!(budget.used(), 0);
        assert_eq!(budget.peak(), 0);
    }

    #[test]
    fn overflowing_clone_accounting_fails_before_clone_or_allocation() {
        struct OverflowClone(u8);

        impl Clone for OverflowClone {
            fn clone(&self) -> Self {
                panic!("clone must not run without its peak reservation")
            }
        }

        impl QueryRow for OverflowClone {
            fn retained_heap_bytes(&self) -> Result<usize, InventoryError> {
                Ok(usize::from(self.0))
            }

            fn clone_heap_bytes(&self) -> Result<usize, InventoryError> {
                Ok(usize::MAX)
            }
        }

        let budget = MemoryBudget::new(1024);
        let mut queries = QueryRegistry::new(1, budget.clone());
        let memory = budget
            .reserve(std::mem::size_of::<OverflowClone>())
            .unwrap();
        let handle = queries
            .insert(1, 1, Coverage::Complete, vec![OverflowClone(0)], memory)
            .unwrap();
        assert!(matches!(
            queries.page(
                QueryCursor {
                    handle,
                    run_id: 1,
                    revision: 1,
                    offset: 0
                },
                1
            ),
            Err(InventoryError::ResourceLimit)
        ));
        assert_eq!(budget.used(), std::mem::size_of::<OverflowClone>());
        assert_eq!(budget.peak(), std::mem::size_of::<OverflowClone>());
    }

    #[test]
    fn rejected_query_drops_rows_before_releasing_construction_lease() {
        #[derive(Clone)]
        struct DropProbe {
            budget: Arc<MemoryBudget>,
            observed: Arc<AtomicUsize>,
        }

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.observed.store(self.budget.used(), Ordering::Relaxed);
            }
        }

        impl QueryRow for DropProbe {
            fn retained_heap_bytes(&self) -> Result<usize, InventoryError> {
                Err(InventoryError::ResourceLimit)
            }

            fn clone_heap_bytes(&self) -> Result<usize, InventoryError> {
                Ok(0)
            }
        }

        let budget = MemoryBudget::new(1024);
        let mut queries = QueryRegistry::new(1, budget.clone());
        let memory = budget.reserve(1024).unwrap();
        let observed = Arc::new(AtomicUsize::new(0));
        let rows = vec![DropProbe {
            budget: budget.clone(),
            observed: observed.clone(),
        }];
        assert_eq!(
            queries.insert(1, 1, Coverage::Complete, rows, memory),
            Err(InventoryError::ResourceLimit)
        );
        assert_eq!(observed.load(Ordering::Relaxed), 1024);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn page_clone_observes_original_and_copy_peak_reserved() {
        struct CloneProbe {
            value: String,
            budget: Arc<MemoryBudget>,
        }

        impl Clone for CloneProbe {
            fn clone(&self) -> Self {
                assert_eq!(self.budget.used(), self.budget.limit());
                Self {
                    value: self.value.clone(),
                    budget: self.budget.clone(),
                }
            }
        }

        impl QueryRow for CloneProbe {
            fn retained_heap_bytes(&self) -> Result<usize, InventoryError> {
                self.value.retained_heap_bytes()
            }

            fn clone_heap_bytes(&self) -> Result<usize, InventoryError> {
                self.value.clone_heap_bytes()
            }
        }

        let retained = std::mem::size_of::<CloneProbe>() + 512;
        let copied = std::mem::size_of::<CloneProbe>() + 200;
        let budget = MemoryBudget::new(retained + copied);
        let mut queries = QueryRegistry::new(1, budget.clone());
        let memory = budget.reserve(retained).unwrap();
        let mut value = String::with_capacity(512);
        value.extend(std::iter::repeat_n('a', 200));
        let handle = queries
            .insert(
                1,
                1,
                Coverage::Complete,
                vec![CloneProbe {
                    value,
                    budget: budget.clone(),
                }],
                memory,
            )
            .unwrap();
        let page = queries
            .page(
                QueryCursor {
                    handle,
                    run_id: 1,
                    revision: 1,
                    offset: 0,
                },
                1,
            )
            .unwrap();
        assert_eq!(budget.used(), retained + copied);
        drop(queries);
        assert_eq!(budget.used(), copied);
        drop(page);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn concurrent_pages_keep_retiring_query_copies_reserved() {
        let retained = std::mem::size_of::<String>() + 512;
        let copied = std::mem::size_of::<String>() + 300;
        let budget = MemoryBudget::new(retained + 2 * copied);
        let mut queries = QueryRegistry::new(1, budget.clone());
        let memory = budget.reserve(retained).unwrap();
        let mut value = String::with_capacity(512);
        value.extend(std::iter::repeat_n('a', 300));
        let handle = queries
            .insert(1, 1, Coverage::ResourceLimit, vec![value], memory)
            .unwrap();
        let cursor = QueryCursor {
            handle,
            run_id: 1,
            revision: 1,
            offset: 0,
        };
        let first = queries.page(cursor.clone(), 1).unwrap();
        let second = queries.page(cursor.clone(), 1).unwrap();
        assert_eq!(first.metadata.coverage, Coverage::ResourceLimit);
        assert_eq!(budget.used(), retained + 2 * copied);
        assert!(matches!(
            queries.page(cursor, 1),
            Err(InventoryError::ResourceLimit)
        ));
        drop(queries);
        assert_eq!(budget.used(), 2 * copied);
        assert_eq!(budget.peak(), budget.limit());
        assert_eq!(
            budget.reserve(retained + 1).unwrap_err(),
            InventoryError::ResourceLimit
        );
        drop(first);
        assert_eq!(budget.used(), copied);
        drop(second);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn failed_query_insert_does_not_evict_existing_handles() {
        let budget = MemoryBudget::new(64);
        let mut queries = QueryRegistry::new(1, budget.clone());
        let mut oldest = 0;
        for request_id in 1..=8 {
            let memory = budget.reserve(std::mem::size_of::<i32>()).unwrap();
            let handle = queries
                .insert(request_id, 1, Coverage::Complete, vec![1], memory)
                .unwrap();
            if request_id == 1 {
                oldest = handle;
            }
        }
        let memory = budget.reserve(0).unwrap();
        assert_eq!(
            queries.insert(9, 1, Coverage::Complete, vec![1], memory),
            Err(InventoryError::ResourceLimit)
        );
        assert_eq!(budget.used(), 8 * std::mem::size_of::<i32>());
        assert!(queries
            .page(
                QueryCursor {
                    handle: oldest,
                    run_id: 1,
                    revision: 1,
                    offset: 0
                },
                1
            )
            .is_ok());
    }

    #[test]
    fn incremental_rollups_do_not_double_charge_completed_ancestors() {
        let mut arena = DiskInventory::new(MemoryBudget::new(1024 * 1024)).unwrap();
        let root = arena.add_directory(None, OsStr::new("/root")).unwrap();
        let parent = arena
            .add_directory(Some(root), OsStr::new("parent"))
            .unwrap();
        let child = arena
            .add_directory(Some(parent), OsStr::new("child"))
            .unwrap();
        arena.update_rollup(
            root,
            &DirNode {
                alloc: 10,
                files: 1,
                ..DirNode::default()
            },
        );
        arena.update_rollup(
            parent,
            &DirNode {
                alloc: 20,
                files: 1,
                ..DirNode::default()
            },
        );
        arena.update_rollup(
            child,
            &DirNode {
                alloc: 30,
                files: 1,
                ..DirNode::default()
            },
        );
        assert_eq!(arena.alloc, 60);
        assert_eq!(arena.directory(parent).unwrap().alloc, 50);
        arena.update_rollup(
            parent,
            &DirNode {
                alloc: 50,
                files: 2,
                dirs: 1,
                ..DirNode::default()
            },
        );
        arena.update_rollup(
            root,
            &DirNode {
                alloc: 60,
                files: 3,
                dirs: 2,
                ..DirNode::default()
            },
        );
        assert_eq!(arena.alloc, 60);
        assert_eq!(arena.files, 3);
    }

    #[test]
    fn bounded_partial_copy_preserves_raw_names_totals_and_budget() {
        let budget = MemoryBudget::new(2 * 1024 * 1024);
        let mut arena = DiskInventory::new(budget.clone()).unwrap();
        let root = arena.add_directory(None, OsStr::new("/root")).unwrap();
        for index in 0..100 {
            let raw = vec![0xff, index];
            let child = arena
                .add_directory(Some(root), OsStr::from_bytes(&raw))
                .unwrap();
            arena.update_rollup(
                child,
                &DirNode {
                    alloc: index as u64,
                    ..DirNode::default()
                },
            );
        }
        let retained = budget.used();
        let copy = arena.bounded_copy(10).unwrap();
        assert_eq!(copy.len(), 10);
        assert_eq!(copy.alloc, arena.alloc);
        assert!(copy
            .directory(DirId(0))
            .unwrap()
            .children()
            .all(|child| child.raw_name()[0] == 0xff));
        assert!(budget.used() > retained);
        drop(copy);
        assert_eq!(budget.used(), retained);
    }

    proptest! {
        #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]
        #[test]
        fn summaries_never_exceed_the_requested_cap(count in 1usize..100, cap in 1usize..40) {
            let node = DirNode { name: "/root".into(), children: (0..count).map(|index| DirNode {
                name: format!("child-{index}").into(), alloc: index as u64, ..DirNode::default()
            }).collect::<Vec<_>>().into_boxed_slice(), ..DirNode::default() };
            let arena = DiskInventory::from_node(&node, MemoryBudget::new(1024 * 1024)).unwrap();
            let summary = arena.summary_at_bounded(Path::new("/root"), Path::new("/root"), 10, cap).unwrap();
            prop_assert!(summary.children.len() < cap);
            prop_assert_eq!(summary.child_count, count as u64);
        }
    }
}
