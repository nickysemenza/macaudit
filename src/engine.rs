//! `ScannerManager`: owns scan generations, cancellation, and the lifecycle
//! bookkeeping that scanners are deliberately kept out of.
//!
//! - **Generations**: every scan run gets a monotonic `gen`. Starting a new run
//!   cancels the previous generation's `CancellationToken` and bumps the counter.
//!   Events carry their `gen`; consumers drop stale-generation events.
//! - **Lifecycle**: the manager wraps each scanner, sending `Started` before and
//!   `Finished`/`Failed` after. Scanners only ever send `Progress`/`Finding`.
//! - **fs→git pipe**: if `Git` is in the run, the manager wires the discovery
//!   channel (auto-adding a discovery-only `Fs` pass if disk wasn't requested).
//! - **Headless**: `run_to_completion` drains findings into an upserting map for
//!   `scan --json`, `snapshot save`, and `clean --dry-run` — the same engine the
//!   TUI drives.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, Paths};
use crate::fake::FakeScanner;
use crate::model::{Finding, FindingId, ScanEvent, ScannerId};
use crate::registry;
use crate::runner::CommandRunner;
use crate::scan::pipe::repo_channel;
use crate::scan::{ScanCtx, Scanner};

/// Which scanner implementation to build for a section.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Real scanners from the registry.
    Real,
    /// Synthetic findings via `FakeScanner` (`--fake`).
    Fake,
}

pub struct ScannerManager {
    config: Arc<Config>,
    paths: Arc<Paths>,
    runner: Arc<dyn CommandRunner>,
    mode: Mode,
    gen: AtomicU64,
    token: Mutex<CancellationToken>,
}

impl ScannerManager {
    pub fn new(
        config: Arc<Config>,
        paths: Arc<Paths>,
        runner: Arc<dyn CommandRunner>,
        mode: Mode,
    ) -> Self {
        ScannerManager {
            config,
            paths,
            runner,
            mode,
            gen: AtomicU64::new(0),
            token: Mutex::new(CancellationToken::new()),
        }
    }

    /// The generation currently in flight (0 before any scan).
    pub fn current_generation(&self) -> u64 {
        self.gen.load(Ordering::SeqCst)
    }

    /// Cancel the in-flight generation without starting a new one.
    pub fn cancel(&self) {
        self.token.lock().unwrap().cancel();
    }

    /// Begin a new generation: cancel the old token, mint a fresh one, bump the
    /// counter. Returns the new `(gen, token)`.
    fn begin_generation(&self) -> (u64, CancellationToken) {
        let mut guard = self.token.lock().unwrap();
        guard.cancel();
        let fresh = CancellationToken::new();
        *guard = fresh.clone();
        let g = self.gen.fetch_add(1, Ordering::SeqCst) + 1;
        (g, fresh)
    }

    /// Resolve which sections actually run, plus the fs-discovery-only flag.
    /// If `Git` is requested but `Fs` isn't, we still need a walk to feed the
    /// pipe, so `Fs` is added in discovery-only mode.
    fn plan(requested: &[ScannerId]) -> (Vec<ScannerId>, bool) {
        let mut sections: Vec<ScannerId> = requested.to_vec();
        let has_git = sections.contains(&ScannerId::Git);
        let has_fs = sections.contains(&ScannerId::Fs);
        let discovery_only = has_git && !has_fs;
        if discovery_only {
            sections.push(ScannerId::Fs);
        }
        (sections, discovery_only)
    }

    /// Build a scanner instance for a section per the manager's mode.
    fn build_scanner(&self, id: ScannerId) -> Box<dyn Scanner> {
        match self.mode {
            Mode::Real => (registry::section(id).build)(),
            Mode::Fake => Box::new(FakeScanner::for_section(id)),
        }
    }

    /// Spawn every scanner in `sections` for generation `gen`, wiring the fs→git
    /// pipe. Each task sends its own lifecycle events. Returns the join handles.
    fn spawn_set(
        &self,
        tx: &mpsc::Sender<ScanEvent>,
        sections: &[ScannerId],
        discovery_only: bool,
        gen: u64,
        token: CancellationToken,
    ) -> Vec<JoinHandle<()>> {
        // Wire the repo-discovery pipe only when Git participates.
        let git_present = sections.contains(&ScannerId::Git);
        let (repo_tx, repo_rx) = if git_present {
            let (t, r) = repo_channel();
            (Some(t), Some(Arc::new(tokio::sync::Mutex::new(r))))
        } else {
            (None, None)
        };

        let base = ScanCtx {
            tx: tx.clone(),
            token: token.clone(),
            gen,
            config: self.config.clone(),
            paths: self.paths.clone(),
            runner: self.runner.clone(),
            current: ScannerId::Apps, // placeholder; stamped per-scanner below
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };

        let mut handles = Vec::with_capacity(sections.len());
        for &id in sections {
            let scanner = self.build_scanner(id);
            let mut ctx = base.clone().with_current(id);
            match id {
                ScannerId::Fs => {
                    ctx.repo_tx = repo_tx.clone();
                    ctx.fs_discovery_only = discovery_only;
                }
                ScannerId::Git => {
                    ctx.repo_rx = repo_rx.clone();
                }
                _ => {}
            }
            handles.push(spawn_one(scanner, ctx, tx.clone()));
        }
        // Drop our copies so the pipe closes once Fs finishes.
        drop(repo_tx);
        drop(repo_rx);
        handles
    }

    /// Start a scan for the TUI: spawns detached tasks that report over `tx`
    /// (which the caller keeps alive across rescans). Returns the new generation.
    pub fn start(&self, tx: &mpsc::Sender<ScanEvent>, requested: &[ScannerId]) -> u64 {
        let (gen, token) = self.begin_generation();
        let (sections, discovery_only) = Self::plan(requested);
        self.spawn_set(tx, &sections, discovery_only, gen, token);
        gen
    }

    /// Run a scan to completion and collect findings into an upserting map keyed
    /// by stable `FindingId` (last write wins — deferred size updates replace the
    /// earlier unsized finding). Used by all headless commands.
    pub async fn run_to_completion(&self, requested: &[ScannerId]) -> BTreeMap<FindingId, Finding> {
        let (tx, mut rx) = mpsc::channel::<ScanEvent>(1024);
        let (gen, token) = self.begin_generation();
        let (sections, discovery_only) = Self::plan(requested);
        self.spawn_set(&tx, &sections, discovery_only, gen, token);
        drop(tx); // channel closes once all tasks finish

        let mut map: BTreeMap<FindingId, Finding> = BTreeMap::new();
        while let Some(ev) = rx.recv().await {
            if let ScanEvent::Finding {
                finding, gen: g, ..
            } = ev
            {
                if g == gen {
                    map.insert(finding.id, *finding);
                }
            }
        }
        crate::correlate::correlate(&mut map);
        map
    }
}

/// Wrap one scanner: emit `Started`, run, emit `Finished`/`Failed`.
fn spawn_one(
    scanner: Box<dyn Scanner>,
    ctx: ScanCtx,
    tx: mpsc::Sender<ScanEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let id = scanner.id();
        let gen = ctx.gen;
        let _ = tx.send(ScanEvent::Started { scanner: id, gen }).await;
        let start = Instant::now();
        match scanner.scan(ctx).await {
            Ok(()) => {
                let _ = tx
                    .send(ScanEvent::Finished {
                        scanner: id,
                        gen,
                        duration: start.elapsed(),
                    })
                    .await;
            }
            Err(e) => {
                let _ = tx
                    .send(ScanEvent::Failed {
                        scanner: id,
                        gen,
                        error: e.to_string(),
                    })
                    .await;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockCommandRunner;

    fn mgr(mode: Mode) -> ScannerManager {
        ScannerManager::new(
            Arc::new(Config::default()),
            Arc::new(Paths::from_home("/tmp/none")),
            Arc::new(MockCommandRunner::new()),
            mode,
        )
    }

    #[tokio::test]
    async fn fake_run_produces_findings() {
        let m = mgr(Mode::Fake);
        let map = m.run_to_completion(&[ScannerId::Apps]).await;
        // 3 distinct ids (item 1 upserted, not duplicated).
        assert_eq!(map.len(), 3);
        // Item 1's size was set by the deferred update.
        let sized = map.values().filter(|f| f.size_bytes.is_some()).count();
        assert!(sized >= 2, "expected deferred size to land");
    }

    #[tokio::test]
    async fn real_run_completes_with_blank_runner() {
        // With a MockCommandRunner that has no registered responses, every real
        // scanner's subprocess call errors — scanners must degrade gracefully
        // (emit an Info fallback or nothing) rather than hang or panic. This
        // asserts the engine drives a real scanner end-to-end and terminates,
        // and that anything emitted is a non-actionable Info fallback.
        let m = mgr(Mode::Real);
        let map = m.run_to_completion(&[ScannerId::Ports]).await;
        assert!(m.current_generation() >= 1);
        assert!(
            map.values().all(|f| f.severity == crate::model::Severity::Info),
            "a blank-runner real scan should only yield Info fallbacks"
        );
    }

    #[tokio::test]
    async fn generations_increase() {
        let m = mgr(Mode::Fake);
        let _ = m.run_to_completion(&[ScannerId::Apps]).await;
        let g1 = m.current_generation();
        let _ = m.run_to_completion(&[ScannerId::Apps]).await;
        let g2 = m.current_generation();
        assert!(g2 > g1);
    }

    #[tokio::test]
    async fn git_request_adds_fs_discovery() {
        let (sections, discovery_only) = ScannerManager::plan(&[ScannerId::Git]);
        assert!(sections.contains(&ScannerId::Fs));
        assert!(discovery_only);
    }
}
