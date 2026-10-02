//! Bounded, run-owned artifact measurements.
//!
//! Clones share measurements within one run; timestamps never establish validity.

use std::collections::BTreeMap;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::inventory::{MemoryBudget, Reservation};

const MAX_ENTRIES: usize = 4096;
const MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CachedSize {
    pub size: u64,
}

#[derive(Debug)]
struct Measurement {
    size: CachedSize,
    sequence: u64,
    memory: Reservation,
}

#[derive(Debug, Default)]
struct Measurements {
    sizes: BTreeMap<PathBuf, Measurement>,
    entitlements: BTreeMap<PathBuf, (CachedEntitlements, u64, usize)>,
    bytes: usize,
    sequence: u64,
}

impl Measurements {
    fn evict_oldest(&mut self) -> bool {
        let size_sequence = self.sizes.values().map(|entry| entry.sequence).min();
        let group_sequence = self
            .entitlements
            .values()
            .map(|(_, sequence, _)| *sequence)
            .min();
        if group_sequence.is_some_and(|sequence| size_sequence.is_none_or(|size| sequence < size)) {
            self.entitlements.retain(|_, (_, sequence, bytes)| {
                if Some(*sequence) == group_sequence {
                    self.bytes -= *bytes;
                    false
                } else {
                    true
                }
            });
            if self.entitlements.is_empty() {
                self.entitlements = BTreeMap::new();
            }
            return true;
        }
        let Some(sequence) = size_sequence else {
            return false;
        };
        self.sizes.retain(|_, entry| {
            if entry.sequence == sequence {
                self.bytes -= entry.memory.bytes();
                false
            } else {
                true
            }
        });
        if self.sizes.is_empty() {
            self.sizes = BTreeMap::new();
        }
        true
    }
}

#[derive(Debug, Default)]
struct SnapshotData {
    sizes: BTreeMap<PathBuf, CachedSize>,
    _memory: Option<Reservation>,
}

/// Immutable measurements whose reservation follows every shared snapshot.
#[derive(Clone, Debug, Default)]
pub struct SizeSnapshot {
    data: Option<Arc<SnapshotData>>,
}

impl Deref for SizeSnapshot {
    type Target = BTreeMap<PathBuf, CachedSize>;

    fn deref(&self) -> &Self::Target {
        static EMPTY: BTreeMap<PathBuf, CachedSize> = BTreeMap::new();
        self.data.as_ref().map(|data| &data.sizes).unwrap_or(&EMPTY)
    }
}

#[derive(Clone, Debug)]
pub struct SizeCache {
    measurements: Option<Arc<Mutex<Measurements>>>,
    budget: Arc<MemoryBudget>,
    _memory: Option<Arc<Reservation>>,
}

impl Default for SizeCache {
    fn default() -> Self {
        Self::with_budget(MemoryBudget::shared())
    }
}

impl SizeCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_budget(budget: Arc<MemoryBudget>) -> Self {
        let memory = budget
            .reserve(
                std::mem::size_of::<Mutex<Measurements>>()
                    + std::mem::size_of::<Reservation>()
                    + 128,
            )
            .ok()
            .map(Arc::new);
        let measurements = memory
            .as_ref()
            .map(|_| Arc::new(Mutex::new(Measurements::default())));
        Self {
            measurements,
            budget,
            _memory: memory,
        }
    }

    pub fn memory_budget(&self) -> Arc<MemoryBudget> {
        self.budget.clone()
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        Ok(Self::new())
    }

    pub fn load_all(&self) -> anyhow::Result<SizeSnapshot> {
        let Some(store) = &self.measurements else {
            return Ok(SizeSnapshot::default());
        };
        let mut measurements = store
            .lock()
            .map_err(|_| anyhow::anyhow!("measurement store poisoned"))?;
        loop {
            if measurements.sizes.is_empty() {
                return Ok(SizeSnapshot::default());
            }
            let bytes = measurements
                .sizes
                .keys()
                .try_fold(128usize, |bytes, path| bytes.checked_add(entry_bytes(path)))
                .ok_or(crate::inventory::InventoryError::ResourceLimit)?;
            if let Ok(memory) = self.budget.reserve(bytes) {
                let sizes = measurements
                    .sizes
                    .iter()
                    .map(|(path, entry)| (path.clone(), entry.size))
                    .collect();
                return Ok(SizeSnapshot {
                    data: Some(Arc::new(SnapshotData {
                        sizes,
                        _memory: Some(memory),
                    })),
                });
            }
            if !measurements.evict_oldest() {
                return Ok(SizeSnapshot::default());
            }
        }
    }

    pub fn upsert_batch(&mut self, entries: &[(PathBuf, CachedSize)]) -> anyhow::Result<()> {
        let Some(store) = &self.measurements else {
            return Ok(());
        };
        let mut measurements = store
            .lock()
            .map_err(|_| anyhow::anyhow!("measurement store poisoned"))?;
        for (path, size) in entries {
            if let Some(previous) = measurements.sizes.remove(path.as_path()) {
                measurements.bytes -= previous.memory.bytes();
            }
            if measurements.sizes.is_empty() {
                measurements.sizes = BTreeMap::new();
            }
            let bytes = entry_bytes(path);
            if bytes > MAX_BYTES {
                continue;
            }
            while measurements.sizes.len() + measurements.entitlements.len() >= MAX_ENTRIES
                || measurements.bytes.saturating_add(bytes) > MAX_BYTES
            {
                if !measurements.evict_oldest() {
                    break;
                }
            }
            let memory = loop {
                if let Ok(memory) = self.budget.reserve(bytes) {
                    break Some(memory);
                }
                if !measurements.evict_oldest() {
                    break None;
                }
            };
            let Some(memory) = memory else {
                continue;
            };
            measurements.sequence = measurements.sequence.saturating_add(1);
            let sequence = measurements.sequence;
            measurements.sizes.insert(
                path.clone(),
                Measurement {
                    size: *size,
                    sequence,
                    memory,
                },
            );
            measurements.bytes += bytes;
        }
        Ok(())
    }

    pub fn get_entitlements(
        &self,
        app_path: &Path,
        _mtime: i64,
    ) -> anyhow::Result<Option<CachedEntitlements>> {
        let Some(store) = &self.measurements else {
            return Ok(None);
        };
        let measurements = store
            .lock()
            .map_err(|_| anyhow::anyhow!("measurement store poisoned"))?;
        Ok(measurements
            .entitlements
            .get(app_path)
            .map(|(groups, _, _)| groups.clone()))
    }

    pub fn put_entitlements(
        &self,
        app_path: &Path,
        _mtime: i64,
        app_groups: &[String],
    ) -> anyhow::Result<()> {
        let Some(store) = &self.measurements else {
            return Ok(());
        };
        let bytes = crate::inventory::serialized_size(app_groups)?
            .checked_add(
                app_groups
                    .len()
                    .saturating_mul(std::mem::size_of::<String>()),
            )
            .and_then(|bytes| bytes.checked_add(entry_bytes(app_path)))
            .unwrap_or(usize::MAX);
        if bytes > MAX_BYTES {
            return Ok(());
        }
        let mut measurements = store
            .lock()
            .map_err(|_| anyhow::anyhow!("measurement store poisoned"))?;
        if let Some((_, _, bytes)) = measurements.entitlements.remove(app_path) {
            measurements.bytes -= bytes;
        }
        if measurements.entitlements.is_empty() {
            measurements.entitlements = BTreeMap::new();
        }
        while measurements.sizes.len() + measurements.entitlements.len() >= MAX_ENTRIES
            || measurements.bytes.saturating_add(bytes) > MAX_BYTES
        {
            if !measurements.evict_oldest() {
                break;
            }
        }
        let memory = loop {
            if let Ok(memory) = self.budget.reserve(bytes) {
                break Some(memory);
            }
            if !measurements.evict_oldest() {
                break None;
            }
        };
        let Some(memory) = memory else {
            return Ok(());
        };
        let app_groups = SharedGroups(Arc::new(GroupData {
            groups: app_groups.to_vec(),
            _memory: memory,
        }));
        measurements.sequence = measurements.sequence.saturating_add(1);
        let sequence = measurements.sequence;
        measurements.entitlements.insert(
            app_path.to_path_buf(),
            (CachedEntitlements { app_groups }, sequence, bytes),
        );
        measurements.bytes += bytes;
        Ok(())
    }
}

fn entry_bytes(path: &Path) -> usize {
    path.as_os_str()
        .len()
        .saturating_add(std::mem::size_of::<(PathBuf, Measurement)>().saturating_mul(16))
        .saturating_add(256)
}

#[derive(Clone, Debug)]
pub struct CachedEntitlements {
    pub app_groups: SharedGroups,
}

#[derive(Debug)]
struct GroupData {
    groups: Vec<String>,
    _memory: Reservation,
}

#[derive(Clone, Debug)]
pub struct SharedGroups(Arc<GroupData>);

impl Deref for SharedGroups {
    type Target = [String];
    fn deref(&self) -> &[String] {
        &self.0.groups
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Paths;

    fn sized(size: u64) -> CachedSize {
        CachedSize { size }
    }

    #[test]
    fn snapshots_and_cache_clones_retain_their_own_reservations() {
        let budget = MemoryBudget::new(MAX_BYTES);
        let mut cache = SizeCache::with_budget(budget.clone());
        cache
            .upsert_batch(&[(PathBuf::from("/a"), sized(3))])
            .unwrap();
        let cache_clone = cache.clone();
        let snapshot = cache.load_all().unwrap();
        let used = budget.used();
        let snapshot_clone = snapshot.clone();
        assert_eq!(budget.used(), used);
        drop(cache);
        assert_eq!(budget.used(), used);
        drop(cache_clone);
        assert!(budget.used() > 0);
        assert_eq!(snapshot_clone.get(Path::new("/a")), Some(&sized(3)));
        drop(snapshot);
        assert!(budget.used() > 0);
        drop(snapshot_clone);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn exhausted_budget_skips_allocations_and_evicts_old_measurements() {
        let empty_budget = MemoryBudget::new(0);
        let mut disabled = SizeCache::with_budget(empty_budget.clone());
        disabled
            .upsert_batch(&[(PathBuf::from("/a"), sized(1))])
            .unwrap();
        assert!(disabled.load_all().unwrap().is_empty());
        assert_eq!(empty_budget.used(), 0);

        let budget = MemoryBudget::new(16 * 1024);
        let mut cache = SizeCache::with_budget(budget.clone());
        cache
            .upsert_batch(&[(PathBuf::from("/a"), sized(1))])
            .unwrap();
        let pressure = budget.reserve(budget.limit() - budget.used()).unwrap();
        cache
            .upsert_batch(&[(PathBuf::from("/b"), sized(2))])
            .unwrap();
        let measurements = cache.measurements.as_ref().unwrap().lock().unwrap();
        assert!(!measurements.sizes.contains_key(Path::new("/a")));
        assert!(measurements.sizes.contains_key(Path::new("/b")));
        assert!(budget.peak() <= budget.limit());
        drop(measurements);
        assert!(cache.load_all().unwrap().is_empty());
        drop(cache);
        drop(pressure);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn clones_share_same_run_measurements_and_last_write_wins() {
        let mut cache = SizeCache::new();
        let shared = cache.clone();
        let artifact = PathBuf::from("/a/node_modules");
        cache
            .upsert_batch(&[
                (artifact.clone(), sized(100)),
                (artifact.clone(), sized(200)),
            ])
            .unwrap();
        assert_eq!(shared.load_all().unwrap().get(&artifact), Some(&sized(200)));
        assert!(SizeCache::new().load_all().unwrap().is_empty());
    }

    #[test]
    fn measurements_never_read_or_modify_existing_artifacts() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        let database = paths.state_dir.join("sizes.db");
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        std::fs::write(&database, b"legacy database must remain untouched").unwrap();
        let mut cache = paths.size_cache.clone();
        assert!(cache.load_all().unwrap().is_empty());
        cache
            .upsert_batch(&[(PathBuf::from("/artifact"), sized(u64::MAX))])
            .unwrap();
        cache.put_entitlements(Path::new("/app"), 0, &[]).unwrap();
        assert_eq!(
            std::fs::read(&database).unwrap(),
            b"legacy database must remain untouched"
        );
        assert!(paths
            .with_fresh_measurements()
            .size_cache
            .load_all()
            .unwrap()
            .is_empty());
        assert_eq!(std::fs::read_dir(&paths.state_dir).unwrap().count(), 1);
    }

    #[test]
    fn measurements_do_not_create_directories_or_files() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().join("missing"));
        let mut cache = paths.size_cache.clone();
        cache
            .upsert_batch(&[(PathBuf::from("/a"), sized(1))])
            .unwrap();
        assert!(!home.path().join("missing").exists());
        let blocked = home.path().join("not-a-directory");
        std::fs::write(&blocked, b"untouched").unwrap();
        let blocked_paths = Paths::from_home(&blocked);
        assert!(blocked_paths.size_cache.load_all().unwrap().is_empty());
        assert_eq!(std::fs::read(&blocked).unwrap(), b"untouched");
    }

    #[test]
    fn run_isolation_does_not_depend_on_ttl_or_root_mtime() {
        let paths = Paths::from_home("/unused");
        let first = paths.with_fresh_measurements();
        let second = first.with_fresh_measurements();
        let mut cache = first.size_cache.clone();
        cache
            .upsert_batch(&[(PathBuf::from("/a"), sized(5))])
            .unwrap();
        assert!(second.size_cache.load_all().unwrap().is_empty());
    }

    #[test]
    fn size_entries_are_bounded_and_oldest_is_evicted() {
        let mut cache = SizeCache::new();
        let entries: Vec<_> = (0..=MAX_ENTRIES)
            .map(|index| {
                (
                    PathBuf::from(format!("/artifact/{index}")),
                    sized(index as u64),
                )
            })
            .collect();
        cache.upsert_batch(&entries).unwrap();
        let loaded = cache.load_all().unwrap();
        assert!(loaded.len() <= MAX_ENTRIES);
        assert!(!loaded.is_empty());
        assert!(!loaded.contains_key(Path::new("/artifact/0")));
        assert!(cache.measurements.as_ref().unwrap().lock().unwrap().bytes <= MAX_BYTES);
    }

    #[test]
    fn entitlements_are_run_owned_immutable_and_payload_bounded() {
        let cache = SizeCache::new();
        let app = Path::new("/app");
        cache
            .put_entitlements(app, 1, &["group.test".into()])
            .unwrap();
        let groups = cache.get_entitlements(app, 2).unwrap().unwrap().app_groups;
        assert_eq!(&*groups, &["group.test".to_string()]);
        assert!(SizeCache::new().get_entitlements(app, 1).unwrap().is_none());
        for index in 0..10 {
            cache
                .put_entitlements(
                    Path::new(&format!("/app/{index}")),
                    0,
                    &["x".repeat(MAX_BYTES / 3)],
                )
                .unwrap();
        }
        cache
            .put_entitlements(Path::new("/oversized"), 0, &["x".repeat(MAX_BYTES)])
            .unwrap();
        assert!(cache
            .get_entitlements(Path::new("/oversized"), 0)
            .unwrap()
            .is_none());
        let measurements = cache.measurements.as_ref().unwrap().lock().unwrap();
        assert!(measurements.sizes.is_empty());
        assert!(measurements.bytes <= MAX_BYTES);
        assert!(measurements.entitlements.len() < 10);
        assert_eq!(&*groups, &["group.test".to_string()]);
    }

    #[test]
    fn returned_entitlement_groups_keep_their_reservation_after_cache_drop() {
        let budget = MemoryBudget::new(1 << 20);
        let cache = SizeCache::with_budget(budget.clone());
        cache
            .put_entitlements(Path::new("/app"), 0, &["group.test".into()])
            .unwrap();
        let groups = cache
            .get_entitlements(Path::new("/app"), 0)
            .unwrap()
            .unwrap()
            .app_groups;
        let charged = budget.used();
        let clone = groups.clone();
        assert_eq!(budget.used(), charged);
        drop(cache);
        assert!(budget.used() > 0);
        drop(groups);
        assert_eq!(clone[0], "group.test");
        drop(clone);
        assert_eq!(budget.used(), 0);
    }
}
