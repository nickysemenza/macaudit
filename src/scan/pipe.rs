//! The internal FsScanner → GitScanner channel.
//!
//! The engine creates the pair and injects the ends via `ScanCtx` (FsScanner
//! gets `repo_tx`, GitScanner gets `repo_rx`) so neither scanner invents its own
//! type. Semantics:
//!
//! - FsScanner sends one `RepoDiscovery` per `.git` directory it finds, then
//!   drops `repo_tx` when its walk completes.
//! - GitScanner loops `recv().await` until the channel closes (`None`), which is
//!   guaranteed once FsScanner finishes (or if FsScanner isn't running this scan,
//!   the engine drops the sender immediately so GitScanner sees an empty stream).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::inventory::{MemoryBudget, Reservation};

const MAX_QUEUED_REPOS: usize = 2048;
const MAX_PIPE_BYTES: usize = 32 * 1024 * 1024;
const QUEUE_CONTROL_BYTES: usize = 4096;
const QUEUE_SPARE_SLOTS: usize = 64;
const QUEUE_SLOT_BYTES: usize =
    std::mem::size_of::<RepoDiscovery>() + 4 * std::mem::size_of::<usize>();

/// A git repository discovered by the filesystem walk. `root` is the repo's
/// working-directory root (the parent of `.git`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoDiscovery {
    pub root: PathBuf,
}

#[derive(Debug)]
struct PipelineMemory {
    reservation: Mutex<Reservation>,
    limit: usize,
}

#[derive(Clone, Debug)]
pub struct RepoSender {
    inner: Option<mpsc::Sender<RepoDiscovery>>,
    memory: Option<Arc<PipelineMemory>>,
}

#[derive(Debug)]
pub struct RepoReceiver {
    inner: Option<mpsc::Receiver<RepoDiscovery>>,
    _memory: Option<Arc<PipelineMemory>>,
}

impl RepoSender {
    /// Send without parking a Rayon worker. A full queue, unavailable memory,
    /// or contended reservation returns the original discovery in `SendError`.
    pub fn send(
        &self,
        discovery: RepoDiscovery,
    ) -> Result<(), mpsc::error::SendError<RepoDiscovery>> {
        let (Some(inner), Some(memory)) = (&self.inner, &self.memory) else {
            return Err(mpsc::error::SendError(discovery));
        };
        let Ok(permit) = inner.try_reserve() else {
            return Err(mpsc::error::SendError(discovery));
        };
        let Some(bytes) = discovery
            .root
            .capacity()
            .checked_add(std::mem::size_of::<RepoDiscovery>())
        else {
            return Err(mpsc::error::SendError(discovery));
        };
        let Ok(mut reservation) = memory.reservation.try_lock() else {
            return Err(mpsc::error::SendError(discovery));
        };
        if reservation
            .bytes()
            .checked_add(bytes)
            .is_none_or(|total| total > memory.limit)
            || reservation.grow(bytes).is_err()
        {
            return Err(mpsc::error::SendError(discovery));
        }
        drop(reservation);
        permit.send(discovery);
        Ok(())
    }
}

impl RepoReceiver {
    pub async fn recv(&mut self) -> Option<RepoDiscovery> {
        match self.inner.as_mut() {
            Some(inner) => inner.recv().await,
            None => None,
        }
    }

    pub fn try_recv(&mut self) -> Result<RepoDiscovery, mpsc::error::TryRecvError> {
        match self.inner.as_mut() {
            Some(inner) => inner.try_recv(),
            None => Err(mpsc::error::TryRecvError::Disconnected),
        }
    }
}

/// Create a nonblocking, bounded discovery pipe using the shared memory budget.
/// Conservative queue storage and all accepted paths remain charged until both
/// endpoints (including sender clones) drop, covering queued and active repos.
/// Budget exhaustion creates a closed pipe rather than an unaccounted queue.
pub fn repo_channel() -> (RepoSender, RepoReceiver) {
    repo_channel_with_budget(MemoryBudget::shared(), MAX_QUEUED_REPOS, MAX_PIPE_BYTES)
}

fn queue_bytes(capacity: usize) -> Option<usize> {
    capacity
        .checked_add(QUEUE_SPARE_SLOTS)?
        .checked_mul(QUEUE_SLOT_BYTES)?
        .checked_add(QUEUE_CONTROL_BYTES)
}

fn repo_channel_with_budget(
    budget: Arc<MemoryBudget>,
    capacity: usize,
    byte_limit: usize,
) -> (RepoSender, RepoReceiver) {
    let reservation = queue_bytes(capacity)
        .filter(|bytes| capacity > 0 && *bytes <= byte_limit)
        .and_then(|bytes| budget.reserve(bytes).ok());
    let Some(reservation) = reservation else {
        return (
            RepoSender {
                inner: None,
                memory: None,
            },
            RepoReceiver {
                inner: None,
                _memory: None,
            },
        );
    };
    let memory = Arc::new(PipelineMemory {
        reservation: Mutex::new(reservation),
        limit: byte_limit,
    });
    let (sender, receiver) = mpsc::channel(capacity);
    (
        RepoSender {
            inner: Some(sender),
            memory: Some(memory.clone()),
        },
        RepoReceiver {
            inner: Some(receiver),
            _memory: Some(memory),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn discovery(capacity: usize) -> RepoDiscovery {
        let mut root = PathBuf::with_capacity(capacity);
        root.push("repo");
        RepoDiscovery { root }
    }

    fn discovery_bytes(discovery: &RepoDiscovery) -> usize {
        discovery.root.capacity() + std::mem::size_of::<RepoDiscovery>()
    }

    #[tokio::test]
    async fn receiver_contract_and_sender_clones_are_preserved() {
        let budget = MemoryBudget::new(MAX_PIPE_BYTES);
        let (sender, mut receiver) = repo_channel_with_budget(budget.clone(), 2, MAX_PIPE_BYTES);
        let clone = sender.clone();
        assert_eq!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty));
        let first = discovery(32);
        let second = discovery(64);
        sender.send(first.clone()).unwrap();
        clone.send(second.clone()).unwrap();
        drop(sender);
        assert_eq!(receiver.recv().await, Some(first));
        assert_eq!(receiver.try_recv(), Ok(second));
        assert_eq!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty));
        drop(clone);
        assert_eq!(receiver.recv().await, None);
        assert_eq!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        );
        assert!(budget.used() > 0);
        drop(receiver);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn stalled_consumer_does_not_park_rayon_workers() {
        let budget = MemoryBudget::new(MAX_PIPE_BYTES);
        let (sender, mut receiver) =
            repo_channel_with_budget(budget.clone(), MAX_QUEUED_REPOS, MAX_PIPE_BYTES);
        for _ in 0..MAX_QUEUED_REPOS {
            sender.send(discovery(8)).unwrap();
        }
        let used = budget.used();
        let rejected = discovery(1024);
        let expected = rejected.clone();
        let (done_sender, done_receiver) = std::sync::mpsc::channel();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        pool.spawn(move || {
            let result = sender.send(rejected);
            drop(sender);
            done_sender.send(result).unwrap();
        });
        let result = done_receiver.recv_timeout(Duration::from_secs(2));
        assert!(result.is_ok(), "sending into a full pipe parked the worker");
        assert_eq!(result.unwrap().unwrap_err().0, expected);
        assert_eq!(budget.used(), used);
        for _ in 0..MAX_QUEUED_REPOS {
            receiver.try_recv().unwrap();
        }
        assert_eq!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        );
        assert_eq!(budget.used(), used);
        drop(receiver);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn slow_consumer_retains_active_path_budget() {
        let first = discovery(4096);
        let first_bytes = discovery_bytes(&first);
        let limit = queue_bytes(2).unwrap() + first_bytes;
        let budget = MemoryBudget::new(MAX_PIPE_BYTES);
        let (sender, mut receiver) = repo_channel_with_budget(budget.clone(), 2, limit);
        let (active_sender, active_receiver) = tokio::sync::oneshot::channel();
        let (finish_sender, finish_receiver) = tokio::sync::oneshot::channel();
        let consumer = tokio::spawn(async move {
            let active = receiver.recv().await.unwrap();
            active_sender.send(()).unwrap();
            finish_receiver.await.unwrap();
            assert_eq!(active.root, PathBuf::from("repo"));
            receiver
        });
        sender.send(first).unwrap();
        active_receiver.await.unwrap();
        assert_eq!(budget.used(), limit);
        let rejected = discovery(8);
        let error = sender.send(rejected).unwrap_err();
        assert_eq!(error.0.root, PathBuf::from("repo"));
        assert_eq!(budget.used(), limit);
        finish_sender.send(()).unwrap();
        let mut receiver = consumer.await.unwrap();
        assert_eq!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty));
        drop(sender);
        assert_eq!(receiver.recv().await, None);
        assert_eq!(budget.used(), limit);
        drop(receiver);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn shared_budget_rejection_preserves_message_and_queue_capacity() {
        let first = discovery(4096);
        let limit = queue_bytes(2).unwrap() + discovery_bytes(&first);
        let budget = MemoryBudget::new(limit);
        let (sender, mut receiver) = repo_channel_with_budget(budget.clone(), 2, MAX_PIPE_BYTES);
        sender.send(first).unwrap();
        let rejected = discovery(1);
        let error = sender.send(rejected.clone()).unwrap_err();
        assert_eq!(error.0, rejected);
        assert_eq!(budget.used(), limit);
        assert_eq!(sender.inner.as_ref().unwrap().capacity(), 1);
        receiver.try_recv().unwrap();
        assert_eq!(budget.used(), limit);
        drop(receiver);
        assert_eq!(budget.used(), limit);
        drop(sender);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn insufficient_queue_budget_produces_closed_pipe() {
        let budget = MemoryBudget::new(queue_bytes(2).unwrap() - 1);
        let (sender, mut receiver) = repo_channel_with_budget(budget.clone(), 2, MAX_PIPE_BYTES);
        assert_eq!(budget.used(), 0);
        let rejected = discovery(8);
        assert_eq!(sender.send(rejected.clone()).unwrap_err().0, rejected);
        assert_eq!(receiver.recv().await, None);
        assert_eq!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        );
    }

    #[test]
    fn path_capacity_not_length_is_charged() {
        let budget = MemoryBudget::new(MAX_PIPE_BYTES);
        let (sender, mut receiver) = repo_channel_with_budget(budget.clone(), 2, MAX_PIPE_BYTES);
        let discovery = discovery(8192);
        let expected = budget.used() + discovery_bytes(&discovery);
        sender.send(discovery).unwrap();
        assert_eq!(budget.used(), expected);
        receiver.try_recv().unwrap();
        assert_eq!(budget.used(), expected);
    }

    #[test]
    fn contended_reservation_is_nonblocking() {
        let budget = MemoryBudget::new(MAX_PIPE_BYTES);
        let (sender, _receiver) = repo_channel_with_budget(budget.clone(), 2, MAX_PIPE_BYTES);
        let memory = sender.memory.as_ref().unwrap();
        let reservation = memory.reservation.lock().unwrap();
        let used = budget.used();
        assert!(sender.send(discovery(8)).is_err());
        assert_eq!(budget.used(), used);
        assert_eq!(sender.inner.as_ref().unwrap().capacity(), 2);
        drop(reservation);
    }

    #[test]
    fn closed_receiver_rejects_without_charging() {
        let budget = MemoryBudget::new(MAX_PIPE_BYTES);
        let (sender, receiver) = repo_channel_with_budget(budget.clone(), 2, MAX_PIPE_BYTES);
        drop(receiver);
        let used = budget.used();
        assert!(sender.send(discovery(8192)).is_err());
        assert_eq!(budget.used(), used);
        drop(sender);
        assert_eq!(budget.used(), 0);
    }
}
