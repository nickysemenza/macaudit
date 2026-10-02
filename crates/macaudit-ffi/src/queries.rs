use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use macaudit::inventory::{InventoryError, MemoryBudget, QueryPage, QueryRow, Reservation};

use crate::{DirEntry, MacAuditError, QueryCancellation};

const QUERY_SLOTS: usize = 2;
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(2);
const CANCELLATION_POLL: Duration = Duration::from_millis(10);

#[derive(Default)]
pub struct QueryAdmission {
    active: Mutex<usize>,
    available: Condvar,
}

impl QueryAdmission {
    pub fn acquire(
        &self,
        cancellation: Option<&QueryCancellation>,
    ) -> Result<QueryPermit<'_>, MacAuditError> {
        self.acquire_until(cancellation, Instant::now() + ADMISSION_TIMEOUT)
    }

    fn acquire_until(
        &self,
        cancellation: Option<&QueryCancellation>,
        deadline: Instant,
    ) -> Result<QueryPermit<'_>, MacAuditError> {
        let mut active = self.active.lock().unwrap();
        loop {
            if cancellation.is_some_and(QueryCancellation::is_cancelled) {
                return Err(MacAuditError::Invalid(
                    "query cancelled during admission".into(),
                ));
            }
            if *active < QUERY_SLOTS {
                *active += 1;
                return Ok(QueryPermit(self));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(MacAuditError::Busy(
                    "heavy query slots are occupied; retry".into(),
                ));
            }
            active = self
                .available
                .wait_timeout(active, remaining.min(CANCELLATION_POLL))
                .unwrap()
                .0;
        }
    }
}

pub struct QueryPermit<'admission>(&'admission QueryAdmission);

impl Drop for QueryPermit<'_> {
    fn drop(&mut self) {
        *self.0.active.lock().unwrap() -= 1;
        self.0.available.notify_one();
    }
}

#[derive(Debug, uniffi::Object)]
pub struct QueryMemory {
    _memory: Reservation,
    _page: Option<QueryPage<DirEntry>>,
}

impl PartialEq for QueryMemory {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Eq for QueryMemory {}

impl QueryMemory {
    pub fn keep(memory: Reservation) -> Arc<Self> {
        Arc::new(Self {
            _memory: memory,
            _page: None,
        })
    }

    pub fn keep_page(page: QueryPage<DirEntry>, memory: Reservation) -> Arc<Self> {
        Arc::new(Self {
            _memory: memory,
            _page: Some(page),
        })
    }

    pub fn into_reservation(memory: Arc<Self>) -> Result<Reservation, MacAuditError> {
        Arc::try_unwrap(memory)
            .map(|memory| memory._memory)
            .map_err(|_| MacAuditError::Invalid("query construction lease is shared".into()))
    }
}

impl QueryRow for DirEntry {
    fn retained_heap_bytes(&self) -> Result<usize, InventoryError> {
        self.path
            .retained_heap_bytes()?
            .checked_add(self.name.retained_heap_bytes()?)
            .ok_or(InventoryError::ResourceLimit)
    }

    fn clone_heap_bytes(&self) -> Result<usize, InventoryError> {
        self.path
            .clone_heap_bytes()?
            .checked_add(self.name.clone_heap_bytes()?)
            .ok_or(InventoryError::ResourceLimit)
    }
}

pub fn reserve(
    budget: &Arc<MemoryBudget>,
    rows: usize,
    row_bytes: usize,
    string_bytes: usize,
) -> Result<Reservation, MacAuditError> {
    budget
        .reserve(
            rows.saturating_mul(row_bytes)
                .saturating_mul(2)
                .saturating_add(string_bytes.saturating_mul(16))
                .saturating_add(1024),
        )
        .map_err(|error| MacAuditError::Invalid(format!("query memory: {error}")))
}

pub fn grow(memory: &mut Reservation, string_bytes: usize) -> Result<(), MacAuditError> {
    memory
        .grow(string_bytes.saturating_mul(16).saturating_add(128))
        .map_err(|error| MacAuditError::Invalid(format!("query memory: {error}")))
}

pub fn entry_bytes(entry: &macaudit::attribution::model::FootprintEntry) -> usize {
    entry
        .path
        .as_os_str()
        .len()
        .saturating_add(entry.evidence.len())
        .saturating_add(entry.label.len())
        .saturating_add(entry.reason.as_ref().map_or(0, String::len))
        .saturating_add(
            entry
                .owners
                .iter()
                .take(500)
                .map(|owner| owner.len().saturating_add(std::mem::size_of::<String>()))
                .sum::<usize>(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn concurrent_queries_never_exceed_two_slots() {
        let admission = QueryAdmission::default();
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..12 {
                scope.spawn(|| {
                    let _permit = admission.acquire(None).unwrap();
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(current, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(20));
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        assert_eq!(peak.load(Ordering::SeqCst), QUERY_SLOTS);
        assert_eq!(*admission.active.lock().unwrap(), 0);
    }

    #[test]
    fn admission_waits_are_cancellable_and_time_bounded() {
        let admission = QueryAdmission::default();
        let _first = admission.acquire(None).unwrap();
        let _second = admission.acquire(None).unwrap();
        let cancellation = QueryCancellation::new();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(20));
                cancellation.cancel();
            });
            let started = Instant::now();
            assert!(admission.acquire(Some(&cancellation)).is_err());
            assert!(started.elapsed() < Duration::from_millis(250));
        });
        let deadline = Instant::now() + Duration::from_millis(20);
        assert!(matches!(
            admission.acquire_until(None, deadline),
            Err(MacAuditError::Busy(_))
        ));
    }

    #[test]
    fn returned_result_credit_survives_clones_and_releases_on_last_drop() {
        let budget = MemoryBudget::new(8192);
        let memory = reserve(&budget, 1, std::mem::size_of::<DirEntry>(), 20).unwrap();
        let credit = QueryMemory::keep(memory);
        let clone = credit.clone();
        assert!(budget.used() > 0);
        drop(credit);
        assert!(budget.used() > 0);
        drop(clone);
        assert_eq!(budget.used(), 0);
        assert!(reserve(&MemoryBudget::new(100), 500, 80, 100).is_err());
    }

    #[test]
    fn directory_rows_charge_retained_capacities_and_clone_lengths() {
        let budget = MemoryBudget::new(2 * 1024 * 1024);
        let memory = budget.reserve(1024 * 1024 + 256).unwrap();
        let mut path = String::with_capacity(1024 * 1024);
        path.push('/');
        let row = DirEntry {
            path,
            name: "x".into(),
            node_revision: 1,
            alloc: 0,
            apparent: 0,
            files: 0,
            dirs: 0,
            errors: 0,
            has_children: false,
        };
        assert_eq!(
            row.retained_heap_bytes().unwrap(),
            1024 * 1024 + row.name.capacity()
        );
        assert_eq!(row.clone_heap_bytes().unwrap(), 2);
        drop(row);
        drop(memory);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn query_cache_transfers_existing_construction_credit_without_double_charge() {
        let budget = MemoryBudget::new(8192);
        let memory = budget.reserve(4096).unwrap();
        let rows = vec![DirEntry {
            path: "/synthetic".into(),
            name: "synthetic".into(),
            node_revision: 1,
            alloc: 0,
            apparent: 0,
            files: 0,
            dirs: 0,
            errors: 0,
            has_children: false,
        }];
        let retained = rows.retained_heap_bytes().unwrap();
        let credit = QueryMemory::keep(memory);
        let memory = QueryMemory::into_reservation(credit).unwrap();
        let mut registry = macaudit::inventory::QueryRegistry::new(1, budget.clone());
        registry
            .insert(1, 1, macaudit::inventory::Coverage::Partial, rows, memory)
            .unwrap();
        assert_eq!(budget.used(), retained);
        assert_eq!(budget.peak(), 4096);
        registry.clear();
        assert_eq!(budget.used(), 0);
    }
}
