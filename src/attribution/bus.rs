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
//! previous valid snapshot — however old — stays available, because a
//! partial/aborted run publishing a snapshot would make `missing_deps`
//! meaningless (attribution numbers would silently flicker to "unlinked").

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::model::{Finding, ScanEvent, ScannerId};
use crate::scan::walk::DirTree;

/// One section's accumulated output for one generation, published only once
/// that generation finished validly (see the module doc).
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub gen: u64,
    pub findings: Vec<Finding>,
    pub dir_trees: Vec<Arc<DirTree>>,
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
    acc_findings: Vec<Finding>,
    acc_trees: Vec<Arc<DirTree>>,
    /// The most recent snapshot that was actually published (possibly from
    /// an older generation than `registered_gen` — see the module doc).
    last_valid: Option<Snapshot>,
}

/// Shared handle, owned by `ScannerManager` and injected into the two
/// attribution scanners at construction (never threaded through `ScanCtx` —
/// see `engine.rs`'s module doc for why).
pub struct ScanBus {
    state: Mutex<HashMap<ScannerId, SectionState>>,
    notify: Notify,
}

impl ScanBus {
    pub fn new() -> Arc<Self> {
        Arc::new(ScanBus {
            state: Mutex::new(HashMap::new()),
            notify: Notify::new(),
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
    /// before any of their tasks are spawned. Carries forward each section's
    /// last published snapshot (if any) so a superseded run never regresses
    /// a waiter to "nothing published yet".
    pub fn begin(&self, gen: u64, sections: &[(ScannerId, CancellationToken)]) {
        let mut state = self.state.lock().unwrap();
        for (id, token) in sections {
            let last_valid = state.get(id).and_then(|s| s.last_valid.clone());
            state.insert(
                *id,
                SectionState {
                    registered_gen: gen,
                    token: token.clone(),
                    terminal: false,
                    acc_findings: Vec::new(),
                    acc_trees: Vec::new(),
                    last_valid,
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
        let id = ev.scanner();
        let gen = ev.generation();
        let mut state = self.state.lock().unwrap();
        let Some(entry) = state.get_mut(&id) else {
            return;
        };
        if gen != entry.registered_gen {
            return;
        }
        let mut wake = false;
        match ev {
            ScanEvent::Finding { finding, .. } => entry.acc_findings.push((**finding).clone()),
            ScanEvent::DirTree { tree, .. } => entry.acc_trees.push(tree.clone()),
            ScanEvent::Finished { .. } => {
                if entry.token.is_cancelled() {
                    entry.acc_findings.clear();
                    entry.acc_trees.clear();
                } else {
                    entry.last_valid = Some(Snapshot {
                        gen,
                        findings: std::mem::take(&mut entry.acc_findings),
                        dir_trees: std::mem::take(&mut entry.acc_trees),
                    });
                }
                entry.terminal = true;
                wake = true;
            }
            ScanEvent::Failed { .. } => {
                entry.acc_findings.clear();
                entry.acc_trees.clear();
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
                        if let Some(snap) = state.get(id).and_then(|e| e.last_valid.clone()) {
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
        let snap = &second[&ScannerId::Fs];
        assert_eq!(
            snap.gen, 1,
            "cancelled run must not publish; previous snapshot kept"
        );
        assert_eq!(snap.findings.len(), 1);
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
