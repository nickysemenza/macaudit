//! `ScannerManager`: owns scan generations, cancellation, and the lifecycle
//! bookkeeping that scanners are deliberately kept out of.
//!
//! - **Generations are per-section.** Every `start()` mints one globally-unique
//!   monotonic `gen` shared by that request, and registers a fresh
//!   `CancellationToken` for each *requested* section — cancelling only those
//!   sections' previous runs. Rescanning Ports never disturbs an in-flight Disk
//!   scan. Events carry `(scanner, gen)`; the UI accepts an event only when its
//!   gen exactly matches the section's expected gen.
//! - The discovery-only `Fs` helper spawned by a git-only request borrows Git's
//!   token and is NOT registered in the runs map: it dies with Git's run, never
//!   displaces a real in-flight Fs run, and its lifecycle events are dropped by
//!   the UI (Fs's expected gen never points at it).
//! - Known coupling: rescanning Disk mid-run closes the fs→git pipe early, so a
//!   concurrently-running Git scan finishes normally but may report fewer repos
//!   than a full walk would find. Inherent to the pipe; accepted.
//! - **Lifecycle**: the manager wraps each scanner, sending `Started` before and
//!   `Finished`/`Failed` after. Scanners only ever send `Progress`/`Finding`.
//! - **fs→git pipe**: if `Git` is in the run, the manager wires the discovery
//!   channel (auto-adding a discovery-only `Fs` pass if disk wasn't requested).
//! - **Headless**: `run_to_completion` drains findings into an upserting map for
//!   `scan --json` and `clean --dry-run` — the same engine the TUI drives.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::attribution::bus::ScanBus;
use crate::attribution::model::FootprintSet;
use crate::attribution::{AppStorageScanner, ProjectsScanner};
use crate::config::{Config, Paths};
use crate::fake::FakeScanner;
use crate::model::{Finding, FindingId, ScanEvent, ScannerId};
use crate::net::HttpFetcher;
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

/// One registered in-flight run for a section.
struct SectionRun {
    /// The run's generation — read by tests to assert slot identity; runtime
    /// supersession is purely token-based (insert replaces + cancels).
    #[cfg_attr(not(test), allow(dead_code))]
    gen: u64,
    token: CancellationToken,
}

pub struct ScannerManager {
    config: Arc<Config>,
    paths: Arc<Paths>,
    runner: Arc<dyn CommandRunner>,
    mode: Mode,
    /// Global monotonic generation counter — every `start()` mints one unique
    /// gen; global uniqueness is what makes the UI's exact-match rule unambiguous.
    gen: AtomicU64,
    /// Per-section in-flight run registry. Cancelling/rescanning section X
    /// touches only X's slot.
    runs: Mutex<HashMap<ScannerId, SectionRun>>,
    /// HTTP access for network enrichment. `None` = offline: enrichment
    /// degrades to a no-op and every existing test stays network-free.
    fetcher: Option<Arc<dyn HttpFetcher>>,
    /// Shared with the two attribution scanners (constructed with it at
    /// `build_scanner` time) so they can wait on other sections' latest
    /// results without `plan()` needing to know they depend on anything.
    bus: Arc<ScanBus>,
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
            runs: Mutex::new(HashMap::new()),
            fetcher: None,
            bus: ScanBus::new(),
        }
    }

    /// The generation currently in flight (0 before any scan).
    pub fn current_generation(&self) -> u64 {
        self.gen.load(Ordering::SeqCst)
    }

    /// The configured delete mode (Trash vs rm) — the UI needs it to plan remedies.
    pub fn delete_mode(&self) -> crate::config::DeleteMode {
        self.config.behavior.delete_mode
    }

    /// A shared handle to the command runner, for executing remedies.
    pub fn runner(&self) -> Arc<dyn CommandRunner> {
        self.runner.clone()
    }

    /// Resolved paths.
    pub fn paths(&self) -> Arc<Paths> {
        self.paths.clone()
    }

    /// The loaded configuration (the TUI's enrichment task needs NetworkConfig).
    pub fn config(&self) -> Arc<Config> {
        self.config.clone()
    }

    /// Attach an HTTP fetcher, enabling network enrichment (cask catalog +
    /// release checks). Without it the manager is fully offline.
    pub fn with_fetcher(mut self, fetcher: Arc<dyn HttpFetcher>) -> Self {
        self.fetcher = Some(fetcher);
        self
    }

    /// The attached fetcher, if any — the TUI needs it for its enrichment task.
    pub fn fetcher(&self) -> Option<Arc<dyn HttpFetcher>> {
        self.fetcher.clone()
    }

    /// Cancel every in-flight section run (shutdown semantics).
    pub fn cancel(&self) {
        for run in self.runs.lock().unwrap().values() {
            run.token.cancel();
        }
        self.bus.cancel_all();
    }

    /// Begin a run: cancel the in-flight run of each section in `requested`
    /// (ONLY those), mint one fresh generation shared by this request, and
    /// register a fresh per-section token for every requested section.
    ///
    /// Returns the gen plus a token for every section in `planned`. The
    /// discovery-only Fs helper (present in `planned` but not `requested`, only
    /// ever for git-only requests) borrows Git's token and is NOT registered in
    /// the runs map: it must die with Git's run, must not displace a real
    /// in-flight Fs run, and its lifecycle events are dropped by the UI's
    /// exact-match rule.
    ///
    /// Tokens are per-section, not per-request — a shared per-request token
    /// would recreate the everything-cancelled bug one level down after an `R`.
    fn begin_sections(
        &self,
        requested: &[ScannerId],
        planned: &[ScannerId],
    ) -> (u64, HashMap<ScannerId, CancellationToken>) {
        let mut runs = self.runs.lock().unwrap();
        let gen = self.gen.fetch_add(1, Ordering::SeqCst) + 1;

        let mut tokens: HashMap<ScannerId, CancellationToken> = HashMap::new();
        for &id in requested {
            if let Some(old) = runs.get(&id) {
                old.token.cancel();
            }
            let token = CancellationToken::new();
            runs.insert(
                id,
                SectionRun {
                    gen,
                    token: token.clone(),
                },
            );
            tokens.insert(id, token);
        }
        // Unrequested-but-planned section (the discovery-only Fs): borrow Git's
        // token; leave the runs map alone.
        for &id in planned {
            if !tokens.contains_key(&id) {
                let git_token = tokens
                    .get(&ScannerId::Git)
                    .cloned()
                    .unwrap_or_else(CancellationToken::new);
                tokens.insert(id, git_token);
            }
        }
        (gen, tokens)
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

    /// Test-only view of a section's registered run.
    #[cfg(test)]
    fn section_run(&self, id: ScannerId) -> Option<(u64, CancellationToken)> {
        self.runs
            .lock()
            .unwrap()
            .get(&id)
            .map(|r| (r.gen, r.token.clone()))
    }

    /// Build a scanner instance for a section per the manager's mode. The two
    /// attribution scanners are the one case the registry's `build: fn() ->
    /// Box<dyn Scanner>` can't cover in `Mode::Real` (they need the engine's
    /// shared `ScanBus`, not a detached one) — everything else still goes
    /// through `registry::section(id).build`.
    fn build_scanner(&self, id: ScannerId) -> Box<dyn Scanner> {
        match self.mode {
            Mode::Real => match id {
                ScannerId::Projects => Box::new(ProjectsScanner::new(self.bus.clone())),
                ScannerId::AppStorage => Box::new(AppStorageScanner::new(self.bus.clone())),
                _ => (registry::section(id).build)(),
            },
            Mode::Fake => Box::new(FakeScanner::for_section(id)),
        }
    }

    /// Spawn every scanner in `sections` for generation `gen`, wiring the fs→git
    /// pipe. Each task sends its own lifecycle events, into an internal
    /// channel; one forwarder task per call feeds every event through
    /// `bus.observe` on its way to the caller's `tx`, so the two attribution
    /// scanners always see a complete, ordered view of a dependency's run
    /// without the engine's `plan()` needing to know about the dependency.
    /// Returns the join handles for the scanner tasks (not the forwarder,
    /// which outlives them only as long as it takes to drain).
    fn spawn_set(
        &self,
        tx: &mpsc::Sender<ScanEvent>,
        sections: &[ScannerId],
        discovery_only: bool,
        gen: u64,
        tokens: &HashMap<ScannerId, CancellationToken>,
    ) -> Vec<JoinHandle<()>> {
        // Register every planned section on the bus BEFORE spawning anything,
        // so a dependency's `Started` can never race a waiter that starts
        // watching for it later (see `ScanBus`'s module doc). The
        // discovery-only Fs helper is deliberately NOT registered: it emits no
        // findings and no tree, so letting it "finish validly" would replace
        // the last real Disk snapshot with an empty one.
        let registrations: Vec<(ScannerId, CancellationToken)> = sections
            .iter()
            .filter(|&&id| !(discovery_only && id == ScannerId::Fs))
            .map(|&id| {
                (
                    id,
                    tokens
                        .get(&id)
                        .cloned()
                        .unwrap_or_else(CancellationToken::new),
                )
            })
            .collect();
        self.bus.begin(gen, &registrations);

        // Wire the repo-discovery pipe only when Git participates.
        let git_present = sections.contains(&ScannerId::Git);
        let (repo_tx, repo_rx) = if git_present {
            let (t, r) = repo_channel();
            (Some(t), Some(Arc::new(tokio::sync::Mutex::new(r))))
        } else {
            (None, None)
        };

        let (internal_tx, mut internal_rx) = mpsc::channel::<ScanEvent>(1024);

        let base = ScanCtx {
            tx: internal_tx.clone(),
            token: CancellationToken::new(), // placeholder; stamped per-scanner below
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
            ctx.token = tokens
                .get(&id)
                .cloned()
                .unwrap_or_else(CancellationToken::new);
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
            handles.push(spawn_one(scanner, ctx, internal_tx.clone()));
        }
        // Drop our copies so the pipe (and, below, the internal channel)
        // close once their producers finish.
        drop(repo_tx);
        drop(repo_rx);
        drop(internal_tx);

        let bus = self.bus.clone();
        let external_tx = tx.clone();
        tokio::spawn(async move {
            while let Some(ev) = internal_rx.recv().await {
                bus.observe(&ev);
                if external_tx.send(ev).await.is_err() {
                    break;
                }
            }
        });

        handles
    }

    /// Start a scan for the TUI: spawns detached tasks that report over `tx`
    /// (which the caller keeps alive across rescans). Returns the new generation.
    pub fn start(&self, tx: &mpsc::Sender<ScanEvent>, requested: &[ScannerId]) -> u64 {
        let (sections, discovery_only) = Self::plan(requested);
        let (gen, tokens) = self.begin_sections(requested, &sections);
        self.spawn_set(tx, &sections, discovery_only, gen, &tokens);
        gen
    }

    /// Run a scan to completion, collecting findings into an upserting map keyed
    /// by stable `FindingId` plus the list of sections that FAILED (scanner
    /// returned an error). Callers should check `failures` before treating the
    /// result as a complete picture. Used by all headless commands.
    ///
    /// `requested` is expanded with `expand_deps` before planning, so asking
    /// for just `Projects`/`AppStorage` still scans (and returns findings
    /// for) their dependency sections — callers that want output scoped to
    /// exactly what the user asked for filter `findings` themselves against
    /// their own unexpanded `requested` list (`main.rs::run_scan` does this).
    pub async fn run_to_completion(&self, requested: &[ScannerId]) -> ScanOutcome {
        let requested = expand_deps(requested);
        let (tx, mut rx) = mpsc::channel::<ScanEvent>(1024);
        let (sections, discovery_only) = Self::plan(&requested);
        let (gen, tokens) = self.begin_sections(&requested, &sections);
        self.spawn_set(&tx, &sections, discovery_only, gen, &tokens);
        drop(tx); // channel closes once all tasks finish

        let mut map: BTreeMap<FindingId, Finding> = BTreeMap::new();
        let mut failures: Vec<(ScannerId, String)> = Vec::new();
        let mut dir_trees: Vec<Arc<crate::scan::walk::DirTree>> = Vec::new();
        let mut footprints: Vec<Arc<FootprintSet>> = Vec::new();
        while let Some(ev) = rx.recv().await {
            match ev {
                ScanEvent::Finding {
                    finding, gen: g, ..
                } if g == gen => {
                    map.insert(finding.id, *finding);
                }
                ScanEvent::DirTree { tree, gen: g, .. } if g == gen => {
                    dir_trees.push(tree);
                }
                ScanEvent::Footprints { set, gen: g, .. } if g == gen => {
                    footprints.push(set);
                }
                ScanEvent::Failed {
                    scanner,
                    gen: g,
                    error,
                } if g == gen => {
                    failures.push((scanner, error));
                }
                _ => {}
            }
        }
        // Sync correlation first (installed-cask marking must precede catalog
        // matching), then optional network enrichment. The Apps-section token is
        // representative for cancellation; if Apps wasn't in the run, enrich
        // early-returns anyway (no unmanaged apps).
        crate::correlate::correlate(&mut map);
        let enrich_token = tokens
            .get(&ScannerId::Apps)
            .cloned()
            .unwrap_or_else(CancellationToken::new);
        crate::net::enrich(
            &mut map,
            self.fetcher.clone(),
            &self.paths,
            &self.config,
            &enrich_token,
        )
        .await;
        ScanOutcome {
            findings: map,
            failures,
            dir_trees,
            footprints,
        }
    }
}

/// The result of a headless scan: everything found, plus which sections failed.
pub struct ScanOutcome {
    pub findings: BTreeMap<FindingId, Finding>,
    /// Sections whose scanner returned an error, with the error text.
    pub failures: Vec<(ScannerId, String)>,
    /// One tree per walked Disk root (empty unless Disk was scanned).
    pub dir_trees: Vec<Arc<crate::scan::walk::DirTree>>,
    /// One set per attribution axis actually scanned (empty unless
    /// Projects/AppStorage were requested, directly or via `expand_deps`).
    pub footprints: Vec<Arc<FootprintSet>>,
}

/// Expand `requested` with each section's attribution dependencies
/// (`attribution::deps_of`), transitively, deduplicated, keeping first-seen
/// order — `requested`'s own sections first (in their given order), each
/// followed immediately by its own deps. Sections with no deps (everything
/// but `Projects`/`AppStorage`) pass through unchanged.
pub fn expand_deps(requested: &[ScannerId]) -> Vec<ScannerId> {
    let mut out = Vec::new();
    fn add(id: ScannerId, out: &mut Vec<ScannerId>) {
        if out.contains(&id) {
            return;
        }
        out.push(id);
        for &dep in crate::attribution::deps_of(id) {
            add(dep, out);
        }
    }
    for &id in requested {
        add(id, &mut out);
    }
    out
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
        // Disk has sized fixtures, so the deferred-size re-emit is exercised.
        let outcome = m.run_to_completion(&[ScannerId::Fs]).await;
        let expected = crate::fake::fixtures(ScannerId::Fs);
        // Distinct ids: the deferred re-emit upserts rather than duplicates.
        assert_eq!(outcome.findings.len(), expected.len());
        assert!(outcome.failures.is_empty());
        // Every fixture that carries a size ends up sized — including the one
        // that was first emitted unsized.
        let expect_sized = expected.iter().filter(|f| f.size_bytes.is_some()).count();
        let sized = outcome
            .findings
            .values()
            .filter(|f| f.size_bytes.is_some())
            .count();
        assert_eq!(sized, expect_sized, "expected deferred size to land");
    }

    #[tokio::test]
    async fn real_run_completes_with_blank_runner() {
        // With a MockCommandRunner that has no registered responses, every real
        // scanner's subprocess call errors — scanners must degrade gracefully
        // (emit an Info fallback or nothing) rather than hang or panic. This
        // asserts the engine drives a real scanner end-to-end and terminates,
        // and that anything emitted is a non-actionable Info fallback.
        let m = mgr(Mode::Real);
        let outcome = m.run_to_completion(&[ScannerId::Ports]).await;
        assert!(m.current_generation() >= 1);
        assert!(
            outcome
                .findings
                .values()
                .all(|f| f.severity == crate::model::Severity::Info),
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

    #[tokio::test]
    async fn targeted_start_cancels_only_requested() {
        let m = mgr(Mode::Fake);
        let (tx, _rx) = mpsc::channel(1024);
        m.start(&tx, &[ScannerId::Apps, ScannerId::Ports]);
        let (apps_gen, apps_token) = m.section_run(ScannerId::Apps).unwrap();
        let (_, old_ports_token) = m.section_run(ScannerId::Ports).unwrap();

        m.start(&tx, &[ScannerId::Ports]);

        // Apps untouched: same slot gen, token not cancelled.
        let (apps_gen2, _) = m.section_run(ScannerId::Apps).unwrap();
        assert_eq!(apps_gen, apps_gen2);
        assert!(!apps_token.is_cancelled(), "Apps must keep running");
        // Ports superseded: old token cancelled, slot on a newer gen.
        assert!(old_ports_token.is_cancelled());
        let (ports_gen2, _) = m.section_run(ScannerId::Ports).unwrap();
        assert!(ports_gen2 > apps_gen);
    }

    #[tokio::test]
    async fn start_all_cancels_everything() {
        let m = mgr(Mode::Fake);
        let (tx, _rx) = mpsc::channel(1024);
        m.start(&tx, ScannerId::ALL);
        let old_tokens: Vec<_> = ScannerId::ALL
            .iter()
            .map(|id| m.section_run(*id).unwrap().1)
            .collect();

        let gen2 = m.start(&tx, ScannerId::ALL);

        for t in &old_tokens {
            assert!(t.is_cancelled(), "R must cancel every previous run");
        }
        for id in ScannerId::ALL {
            assert_eq!(m.section_run(*id).unwrap().0, gen2);
        }
    }

    #[tokio::test]
    async fn git_only_start_leaves_fs_slot_alone() {
        let m = mgr(Mode::Fake);
        let (tx, _rx) = mpsc::channel(1024);
        m.start(&tx, &[ScannerId::Fs]);
        let (fs_gen, fs_token) = m.section_run(ScannerId::Fs).unwrap();

        let git_gen = m.start(&tx, &[ScannerId::Git]);

        // The discovery-only Fs helper must not displace the real Fs run.
        let (fs_gen2, _) = m.section_run(ScannerId::Fs).unwrap();
        assert_eq!(fs_gen, fs_gen2, "Fs slot displaced by discovery helper");
        assert!(!fs_token.is_cancelled());
        assert_eq!(m.section_run(ScannerId::Git).unwrap().0, git_gen);
    }

    #[test]
    fn expand_deps_pulls_in_attribution_dependencies() {
        let expanded = expand_deps(&[ScannerId::AppStorage]);
        assert_eq!(
            expanded[0],
            ScannerId::AppStorage,
            "requested section stays first"
        );
        for dep in crate::attribution::APP_STORAGE_DEPS {
            assert!(expanded.contains(dep), "missing dep {dep:?}");
        }
    }

    #[test]
    fn expand_deps_is_a_no_op_for_sections_without_deps() {
        assert_eq!(
            expand_deps(&[ScannerId::Fs, ScannerId::Ports]),
            vec![ScannerId::Fs, ScannerId::Ports]
        );
    }

    #[test]
    fn expand_deps_dedups_when_a_dependency_is_also_requested() {
        let expanded = expand_deps(&[ScannerId::Fs, ScannerId::Projects]);
        assert_eq!(
            expanded.iter().filter(|id| **id == ScannerId::Fs).count(),
            1,
            "Fs is both explicitly requested and a Projects dependency"
        );
    }

    #[tokio::test]
    async fn run_to_completion_expands_deps_and_collects_footprints() {
        let m = mgr(Mode::Fake);
        let outcome = m.run_to_completion(&[ScannerId::AppStorage]).await;
        assert_eq!(
            outcome.footprints.len(),
            1,
            "AppStorage's fake footprints event should land"
        );
        assert_eq!(
            outcome.footprints[0].axis,
            crate::attribution::model::Axis::AppStorage
        );
        // Dependency sections' findings are present too (not filtered here —
        // that's main.rs::run_scan's job).
        assert!(outcome
            .findings
            .values()
            .any(|f| f.kind.scanner() == ScannerId::Apps));
    }
}
