//! `ScanBus`: the coordination point that lets the two attribution scanners
//! (Projects, App Storage) wait on other sections' *latest valid* results
//! without the engine's `plan()` having to know they depend on anything.
//!
//! Every planned section is `begin()`-registered synchronously, before any
//! scanner task is spawned (`engine.rs::spawn_set`), so there is no race
//! where a dependency's `Started` event could arrive before a waiter starts
//! watching for it. A forwarder task then feeds every `ScanEvent` for every
//! section through `observe()` on its way to the UI/headless channel, so the
//! bus always has a complete, ordered view of one generation's events for a
//! section — the attribution scanners never see raw events themselves.
//!
//! A dependency's run can finish two ways that must NOT publish a new
//! snapshot: its token was cancelled (superseded by a fresher rescan of that
//! section) or a newer generation was already registered for it before this
//! one's `Finished` arrived (the event is simply stale). Either way the
//! run never publishes an attribution snapshot. Starting a new run clears
//! prior snapshots so selected-root data cannot leak across run boundaries.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::inventory::{InventoryError, MemoryBudget, Reservation};
use crate::model::{Finding, FindingId, ScanEvent, ScannerId};
use crate::scan::walk::DirTree;

/// One section's accumulated output for one generation, published only once
/// that generation finished validly (see the module doc).
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub gen: u64,
    pub findings: Arc<Vec<Finding>>,
    pub dir_trees: Vec<Arc<DirTree>>,
    pub memory: Option<Arc<Vec<Arc<Reservation>>>>,
}

/// Per-section bookkeeping. Not `pub`: only `ScanBus`'s methods touch it, so
/// the invariants above (registration precedes events, terminal states never
/// go backwards) are enforced in one place.
struct SectionState {
    /// The generation `begin()` most recently registered for this section.
    /// An event whose gen doesn't match is either stale (an older run still
    /// draining) or foreign; both are ignored by `observe`.
    registered_gen: u64,
    token: CancellationToken,
    /// Whether `registered_gen` has reached `Finished`/`Failed`.
    terminal: bool,
    acc_findings: BTreeMap<FindingId, Finding>,
    memory: BTreeMap<FindingId, Arc<Reservation>>,
    acc_trees: Vec<Arc<DirTree>>,
    /// The snapshot published for this registered generation, if complete.
    last_valid: Option<Snapshot>,
}

/// Shared handle, owned by `ScannerManager` and injected into the two
/// attribution scanners at construction (never threaded through `ScanCtx` —
/// see `engine.rs`'s module doc for why).
pub struct ScanBus {
    state: Mutex<HashMap<ScannerId, SectionState>>,
    notify: Notify,
    budget: Arc<MemoryBudget>,
}

impl ScanBus {
    pub fn new() -> Arc<Self> {
        Self::with_budget(MemoryBudget::shared())
    }

    pub fn with_budget(budget: Arc<MemoryBudget>) -> Arc<Self> {
        Arc::new(ScanBus {
            state: Mutex::new(HashMap::new()),
            notify: Notify::new(),
            budget,
        })
    }

    /// A bus with nothing ever registered on it. Used where a scanner must
    /// be constructible with no engine in hand at all — `registry::REGISTRY`'s
    /// `build: fn() -> Box<dyn Scanner>` has no way to pass the engine's real
    /// bus in. Every dependency then reads as "never registered", so
    /// `wait_for` returns instantly with an empty snapshot map and the
    /// scanner emits only its missing-deps coverage row.
    pub fn detached() -> Arc<Self> {
        Self::new()
    }

    /// Register a fresh generation for every listed section, synchronously,
    /// before any of their tasks are spawned. Clears all prior-run snapshots.
    pub fn begin(&self, gen: u64, sections: &[(ScannerId, CancellationToken)]) {
        let mut state = self.state.lock().unwrap();
        for (id, token) in sections {
            state.insert(
                *id,
                SectionState {
                    registered_gen: gen,
                    token: token.clone(),
                    terminal: false,
                    acc_findings: BTreeMap::new(),
                    memory: BTreeMap::new(),
                    acc_trees: Vec::new(),
                    last_valid: None,
                },
            );
        }
        drop(state);
        self.notify.notify_waiters();
    }

    /// Feed one event from the forwarder. Findings/trees accumulate;
    /// `Finished` publishes a snapshot unless the section's token was
    /// cancelled; `Failed` never publishes. Both mark the section terminal
    /// and wake waiters. Events for an unregistered section, or whose gen
    /// doesn't match what's registered, are ignored (stale or foreign).
    pub fn observe(&self, ev: &ScanEvent) {
        let _ = self.observe_checked(ev);
    }

    pub fn observe_checked(&self, ev: &ScanEvent) -> Result<(), InventoryError> {
        let id = ev.scanner();
        let gen = ev.generation();
        let mut state = self.state.lock().unwrap();
        let Some(entry) = state.get_mut(&id) else {
            return Ok(());
        };
        if gen != entry.registered_gen {
            return Ok(());
        }
        if (entry.terminal || entry.token.is_cancelled())
            && matches!(ev, ScanEvent::Finding { .. } | ScanEvent::DirTree { .. })
        {
            return Ok(());
        }
        let mut wake = false;
        match ev {
            ScanEvent::Finding { finding, .. } => {
                let memory = match crate::engine::finding_reservation(finding, &self.budget) {
                    Ok(memory) => memory,
                    Err(error) => {
                        entry.token.cancel();
                        entry.terminal = true;
                        drop(state);
                        self.notify.notify_waiters();
                        return Err(error);
                    }
                };
                let retained = (**finding).clone();
                entry.acc_findings.insert(finding.id, retained);
                entry.memory.insert(finding.id, Arc::new(memory));
            }
            ScanEvent::DirTree { tree, .. } => {
                crate::engine::upsert_tree(&mut entry.acc_trees, tree.clone());
            }
            ScanEvent::Finished { .. } => {
                if entry.token.is_cancelled() {
                    entry.acc_findings.clear();
                    entry.acc_trees.clear();
                    entry.memory.clear();
                } else {
                    entry.last_valid = Some(Snapshot {
                        gen,
                        findings: Arc::new(
                            std::mem::take(&mut entry.acc_findings)
                                .into_values()
                                .collect(),
                        ),
                        dir_trees: std::mem::take(&mut entry.acc_trees),
                        memory: Some(Arc::new(
                            std::mem::take(&mut entry.memory).into_values().collect(),
                        )),
                    });
                }
                entry.terminal = true;
                wake = true;
            }
            ScanEvent::Failed { .. } => {
                entry.acc_findings.clear();
                entry.acc_trees.clear();
                entry.memory.clear();
                entry.terminal = true;
                wake = true;
            }
            ScanEvent::Started { .. }
            | ScanEvent::Progress { .. }
            | ScanEvent::Footprints { .. } => {}
        }
        drop(state);
        if wake {
            self.notify.notify_waiters();
        }
        Ok(())
    }

    /// Mark every in-flight section terminal without publishing (shutdown
    /// semantics — mirrors `ScannerManager::cancel()`, which owns actually
    /// cancelling the tokens; this just stops anyone waiting on the bus from
    /// hanging once that happens).
    pub fn cancel_all(&self) {
        let mut state = self.state.lock().unwrap();
        for entry in state.values_mut() {
            entry.terminal = true;
            entry.acc_findings.clear();
            entry.acc_trees.clear();
            entry.memory.clear();
        }
        drop(state);
        self.notify.notify_waiters();
    }

    /// Mark only sections registered for this generation terminal without
    /// publishing. Run owners remain responsible for cancelling their tokens.
    pub fn cancel_generation(&self, gen: u64) {
        let mut state = self.state.lock().unwrap();
        for entry in state
            .values_mut()
            .filter(|entry| entry.registered_gen == gen)
        {
            entry.terminal = true;
            entry.acc_findings.clear();
            entry.acc_trees.clear();
            entry.memory.clear();
        }
        drop(state);
        self.notify.notify_waiters();
    }

    /// Wait until every listed section that is in flight for `gen` is
    /// terminal (a section never registered, or registered for a different
    /// gen, counts as immediately resolved — it isn't "in flight in gen").
    /// Returns the latest valid snapshot for each listed section that has
    /// one; a section with no snapshot yet (or never registered at all) is
    /// simply absent from the map. Also returns early if `token` cancels.
    pub async fn wait_for(
        &self,
        sections: &[ScannerId],
        gen: u64,
        token: &CancellationToken,
    ) -> HashMap<ScannerId, Snapshot> {
        loop {
            // Register interest in a notification BEFORE checking state, so a
            // notify_waiters() racing with the check below is never missed.
            let notified = self.notify.notified();
            {
                let state = self.state.lock().unwrap();
                let ready = sections.iter().all(|id| match state.get(id) {
                    None => true,
                    Some(entry) => entry.registered_gen != gen || entry.terminal,
                });
                if ready || token.is_cancelled() {
                    let mut out = HashMap::new();
                    for id in sections {
                        if let Some(snap) = state
                            .get(id)
                            .and_then(|entry| entry.last_valid.clone())
                            .filter(|snapshot| snapshot.gen == gen)
                        {
                            out.insert(*id, snap);
                        }
                    }
                    return out;
                }
            }
            tokio::select! {
                _ = notified => {}
                _ = token.cancelled() => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::model::FindingKind;

    fn finding_event(scanner: ScannerId, gen: u64, path: &str) -> ScanEvent {
        ScanEvent::Finding {
            scanner,
            gen,
            finding: Box::new(Finding::new(FindingKind::DiskCategory, path, path)),
        }
    }

    fn finished_event(scanner: ScannerId, gen: u64) -> ScanEvent {
        ScanEvent::Finished {
            scanner,
            gen,
            duration: Duration::from_millis(1),
        }
    }

    #[tokio::test]
    async fn incremental_tree_snapshot_keeps_only_latest_root_and_releases_memory() {
        let budget = MemoryBudget::new(4096);
        let bus = ScanBus::with_budget(budget.clone());
        bus.begin(1, &[(ScannerId::Fs, CancellationToken::new())]);
        let mut partial = crate::fake::dir_tree();
        partial.complete = false;
        partial.memory = Some(Arc::new(budget.reserve(2048).unwrap()));
        let partial = Arc::new(partial);
        let weak = Arc::downgrade(&partial);
        bus.observe_checked(&ScanEvent::DirTree {
            scanner: ScannerId::Fs,
            gen: 1,
            tree: partial,
        })
        .unwrap();
        assert_eq!(budget.used(), 2048);
        let mut final_tree = crate::fake::dir_tree();
        final_tree.complete = true;
        bus.observe_checked(&ScanEvent::DirTree {
            scanner: ScannerId::Fs,
            gen: 1,
            tree: Arc::new(final_tree),
        })
        .unwrap();
        assert!(weak.upgrade().is_none());
        assert_eq!(budget.used(), 0);
        bus.observe_checked(&finished_event(ScannerId::Fs, 1))
            .unwrap();
        let snapshots = bus
            .wait_for(&[ScannerId::Fs], 1, &CancellationToken::new())
            .await;
        assert_eq!(snapshots[&ScannerId::Fs].dir_trees.len(), 1);
        assert!(snapshots[&ScannerId::Fs].dir_trees[0].complete);
    }

    #[tokio::test]
    async fn snapshots_share_budgeted_payload_and_hold_retiring_memory() {
        let budget = MemoryBudget::new(16 * 1024);
        let bus = ScanBus::with_budget(budget.clone());
        bus.begin(1, &[(ScannerId::Fs, CancellationToken::new())]);
        bus.observe_checked(&finding_event(ScannerId::Fs, 1, "/first"))
            .unwrap();
        bus.observe_checked(&finished_event(ScannerId::Fs, 1))
            .unwrap();
        let first = bus
            .wait_for(&[ScannerId::Fs], 1, &CancellationToken::new())
            .await;
        let second = first.clone();
        assert!(Arc::ptr_eq(
            &first[&ScannerId::Fs].findings,
            &second[&ScannerId::Fs].findings
        ));
        let bytes = budget.used();
        assert!(bytes > 0);
        bus.begin(2, &[(ScannerId::Fs, CancellationToken::new())]);
        assert_eq!(budget.used(), bytes);
        drop(first);
        assert_eq!(budget.used(), bytes);
        drop(second);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn storage_pressure_fails_before_cloning_and_cancels_token() {
        let budget = MemoryBudget::new(1);
        let bus = ScanBus::with_budget(budget.clone());
        let token = CancellationToken::new();
        bus.begin(1, &[(ScannerId::Fs, token.clone())]);
        assert_eq!(
            bus.observe_checked(&finding_event(ScannerId::Fs, 1, "/too-big")),
            Err(InventoryError::ResourceLimit)
        );
        assert!(token.is_cancelled());
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn waiter_registered_before_started_still_waits_for_finished() {
        let bus = ScanBus::new();
        let token = CancellationToken::new();
        bus.begin(1, &[(ScannerId::Fs, token.clone())]);

        let waiter_bus = bus.clone();
        let waiter = tokio::spawn(async move {
            waiter_bus
                .wait_for(&[ScannerId::Fs], 1, &CancellationToken::new())
                .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;

        bus.observe(&ScanEvent::Started {
            scanner: ScannerId::Fs,
            gen: 1,
        });
        assert!(
            !waiter.is_finished(),
            "Started alone must not resolve the wait"
        );

        bus.observe(&finding_event(ScannerId::Fs, 1, "/a"));
        bus.observe(&finished_event(ScannerId::Fs, 1));

        let result = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("wait_for should resolve after Finished")
            .unwrap();
        assert_eq!(result[&ScannerId::Fs].findings.len(), 1);
    }

    #[tokio::test]
    async fn cancelled_finished_is_not_published_but_still_wakes_waiters() {
        let bus = ScanBus::new();
        let token1 = CancellationToken::new();
        bus.begin(1, &[(ScannerId::Fs, token1.clone())]);
        bus.observe(&finding_event(ScannerId::Fs, 1, "/a"));
        bus.observe(&finished_event(ScannerId::Fs, 1));
        let first = bus
            .wait_for(&[ScannerId::Fs], 1, &CancellationToken::new())
            .await;
        assert_eq!(first[&ScannerId::Fs].findings.len(), 1);

        let token2 = CancellationToken::new();
        bus.begin(2, &[(ScannerId::Fs, token2.clone())]);
        bus.observe(&finding_event(ScannerId::Fs, 2, "/b"));
        token2.cancel();

        let waiter_bus = bus.clone();
        let waiter = tokio::spawn(async move {
            waiter_bus
                .wait_for(&[ScannerId::Fs], 2, &CancellationToken::new())
                .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        bus.observe(&finished_event(ScannerId::Fs, 2));

        let second = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("cancelled Finished must still wake waiters")
            .unwrap();
        assert!(
            !second.contains_key(&ScannerId::Fs),
            "a new root must never reuse previous-run snapshots"
        );
    }

    #[tokio::test]
    async fn deferred_findings_upsert_before_attribution_snapshot() {
        let bus = ScanBus::new();
        bus.begin(1, &[(ScannerId::Fs, CancellationToken::new())]);
        let initial = finding_event(ScannerId::Fs, 1, "/artifact");
        let mut sized = initial.clone();
        if let ScanEvent::Finding { finding, .. } = &mut sized {
            finding.size_bytes = Some(999);
        }
        bus.observe(&initial);
        bus.observe(&sized);
        bus.observe(&finished_event(ScannerId::Fs, 1));
        let snapshots = bus
            .wait_for(&[ScannerId::Fs], 1, &CancellationToken::new())
            .await;
        assert_eq!(snapshots[&ScannerId::Fs].findings.len(), 1);
        assert_eq!(snapshots[&ScannerId::Fs].findings[0].size_bytes, Some(999));
    }

    #[tokio::test]
    async fn finished_with_stale_gen_is_ignored() {
        let bus = ScanBus::new();
        let token1 = CancellationToken::new();
        bus.begin(1, &[(ScannerId::Fs, token1.clone())]);
        let token2 = CancellationToken::new();
        bus.begin(2, &[(ScannerId::Fs, token2.clone())]); // supersedes gen 1

        bus.observe(&finished_event(ScannerId::Fs, 1)); // stale — must be ignored
        let still_waiting = tokio::time::timeout(
            Duration::from_millis(100),
            bus.wait_for(&[ScannerId::Fs], 2, &CancellationToken::new()),
        )
        .await;
        assert!(
            still_waiting.is_err(),
            "stale gen 1 Finished must not satisfy gen 2's wait"
        );

        bus.observe(&finished_event(ScannerId::Fs, 2));
        let resolved = tokio::time::timeout(
            Duration::from_secs(2),
            bus.wait_for(&[ScannerId::Fs], 2, &CancellationToken::new()),
        )
        .await;
        assert!(
            resolved.is_ok(),
            "the correct-gen Finished must resolve the wait"
        );
    }

    #[tokio::test]
    async fn wait_for_never_registered_section_returns_immediately_without_it() {
        let bus = ScanBus::new();
        let token = CancellationToken::new();
        bus.begin(1, &[(ScannerId::Fs, token.clone())]);

        let result = tokio::time::timeout(
            Duration::from_millis(200),
            bus.wait_for(&[ScannerId::Docker], 1, &CancellationToken::new()),
        )
        .await
        .expect("an unregistered section must resolve immediately");
        assert!(!result.contains_key(&ScannerId::Docker));
    }

    #[tokio::test]
    async fn cancel_generation_preserves_newer_accumulation() {
        let budget = MemoryBudget::new(64 * 1024);
        let bus = ScanBus::with_budget(budget.clone());
        bus.begin(
            1,
            &[
                (ScannerId::Fs, CancellationToken::new()),
                (ScannerId::Git, CancellationToken::new()),
            ],
        );
        bus.observe_checked(&finding_event(ScannerId::Git, 1, "/retired"))
            .unwrap();
        let retired_bytes = budget.used();
        let current_token = CancellationToken::new();
        bus.begin(2, &[(ScannerId::Fs, current_token.clone())]);
        bus.observe_checked(&finding_event(ScannerId::Fs, 2, "/before"))
            .unwrap();
        let tree = Arc::new(crate::fake::dir_tree());
        bus.observe_checked(&ScanEvent::DirTree {
            scanner: ScannerId::Fs,
            gen: 2,
            tree: tree.clone(),
        })
        .unwrap();
        let current_bytes = budget.used() - retired_bytes;

        bus.cancel_generation(1);

        assert_eq!(budget.used(), current_bytes);
        assert!(!current_token.is_cancelled());
        let retired = tokio::time::timeout(
            Duration::from_secs(2),
            bus.wait_for(&[ScannerId::Git], 1, &CancellationToken::new()),
        )
        .await
        .expect("matching retired generation must resolve");
        assert!(retired.is_empty());
        assert!(tokio::time::timeout(
            Duration::from_millis(25),
            bus.wait_for(&[ScannerId::Fs], 2, &CancellationToken::new()),
        )
        .await
        .is_err());

        bus.observe_checked(&finding_event(ScannerId::Fs, 2, "/after"))
            .unwrap();
        bus.observe_checked(&finished_event(ScannerId::Fs, 2))
            .unwrap();
        let snapshots = tokio::time::timeout(
            Duration::from_secs(2),
            bus.wait_for(&[ScannerId::Fs], 2, &CancellationToken::new()),
        )
        .await
        .expect("current generation must finish normally");
        let snapshot = &snapshots[&ScannerId::Fs];
        assert_eq!(snapshot.gen, 2);
        let mut titles: Vec<_> = snapshot
            .findings
            .iter()
            .map(|finding| finding.title.as_str())
            .collect();
        titles.sort_unstable();
        assert_eq!(titles, ["/after", "/before"]);
        assert_eq!(snapshot.dir_trees.len(), 1);
        assert!(Arc::ptr_eq(&snapshot.dir_trees[0], &tree));
    }

    #[tokio::test]
    async fn cancel_generation_preserves_newer_snapshot() {
        let budget = MemoryBudget::new(64 * 1024);
        let bus = ScanBus::with_budget(budget.clone());
        bus.begin(1, &[(ScannerId::Fs, CancellationToken::new())]);
        let current_token = CancellationToken::new();
        bus.begin(2, &[(ScannerId::Fs, current_token.clone())]);
        bus.observe_checked(&finding_event(ScannerId::Fs, 2, "/current"))
            .unwrap();
        let tree = Arc::new(crate::fake::dir_tree());
        bus.observe_checked(&ScanEvent::DirTree {
            scanner: ScannerId::Fs,
            gen: 2,
            tree: tree.clone(),
        })
        .unwrap();
        bus.observe_checked(&finished_event(ScannerId::Fs, 2))
            .unwrap();
        let snapshots = bus
            .wait_for(&[ScannerId::Fs], 2, &CancellationToken::new())
            .await;
        let retained_bytes = budget.used();
        assert!(retained_bytes > 0);

        bus.cancel_generation(1);

        let current = tokio::time::timeout(
            Duration::from_secs(2),
            bus.wait_for(&[ScannerId::Fs], 2, &CancellationToken::new()),
        )
        .await
        .expect("current snapshot must remain available");
        let snapshot = &current[&ScannerId::Fs];
        assert_eq!(snapshot.gen, 2);
        assert_eq!(snapshot.findings.len(), 1);
        assert_eq!(snapshot.findings[0].title, "/current");
        assert!(Arc::ptr_eq(
            &snapshot.findings,
            &snapshots[&ScannerId::Fs].findings
        ));
        assert_eq!(snapshot.dir_trees.len(), 1);
        assert!(Arc::ptr_eq(&snapshot.dir_trees[0], &tree));
        assert_eq!(budget.used(), retained_bytes);
        assert!(!current_token.is_cancelled());
    }

    #[tokio::test]
    async fn cancel_generation_wakes_matching_waiters_and_releases_accumulation() {
        let budget = MemoryBudget::new(64 * 1024);
        let bus = ScanBus::with_budget(budget.clone());
        let token = CancellationToken::new();
        bus.begin(
            7,
            &[
                (ScannerId::Fs, token.clone()),
                (ScannerId::Git, token.clone()),
            ],
        );
        bus.observe_checked(&finding_event(ScannerId::Fs, 7, "/disk"))
            .unwrap();
        bus.observe_checked(&finding_event(ScannerId::Git, 7, "/project"))
            .unwrap();
        let mut tree = crate::fake::dir_tree();
        tree.memory = Some(Arc::new(budget.reserve(2048).unwrap()));
        let tree = Arc::new(tree);
        let weak_tree = Arc::downgrade(&tree);
        bus.observe_checked(&ScanEvent::DirTree {
            scanner: ScannerId::Fs,
            gen: 7,
            tree,
        })
        .unwrap();
        assert!(budget.used() > 2048);

        let fs_waiter = bus.wait_for(&[ScannerId::Fs], 7, &token);
        let git_waiter = bus.wait_for(&[ScannerId::Git], 7, &token);
        tokio::pin!(fs_waiter, git_waiter);
        tokio::select! {
            biased;
            _ = &mut fs_waiter => panic!("unfinished disk must keep its waiter pending"),
            _ = &mut git_waiter => panic!("unfinished Git must keep its waiter pending"),
            _ = std::future::ready(()) => {}
        }

        bus.cancel_generation(7);

        assert!(!token.is_cancelled());
        assert_eq!(budget.used(), 0);
        assert!(weak_tree.upgrade().is_none());
        let snapshots = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(fs_waiter, git_waiter)
        })
        .await
        .expect("matching-generation cancellation must notify every waiter");
        assert!(snapshots.0.is_empty());
        assert!(snapshots.1.is_empty());
    }

    #[tokio::test]
    async fn cancel_all_wakes_waiters() {
        let bus = ScanBus::new();
        let token = CancellationToken::new();
        bus.begin(1, &[(ScannerId::Fs, token.clone())]);

        let waiter_bus = bus.clone();
        let waiter = tokio::spawn(async move {
            waiter_bus
                .wait_for(&[ScannerId::Fs], 1, &CancellationToken::new())
                .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        bus.cancel_all();

        let result = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("cancel_all must wake waiters")
            .unwrap();
        assert!(
            !result.contains_key(&ScannerId::Fs),
            "no Finished ever arrived — no snapshot"
        );
    }

    #[tokio::test]
    async fn detached_bus_resolves_every_wait_immediately_and_empty() {
        let bus = ScanBus::detached();
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            bus.wait_for(
                &[ScannerId::Fs, ScannerId::Git],
                1,
                &CancellationToken::new(),
            ),
        )
        .await
        .expect("a detached bus must never block a waiter");
        assert!(result.is_empty());
    }
}
