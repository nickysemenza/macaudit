//! UniFFI surface over the macaudit engine for the SwiftUI app.
//!
//! Shape: one `Engine` object per app, created once. Long-running work
//! (scans, cleanup batches) is "spawn, return immediately, report through a
//! listener" — every exported function is synchronous and fast, and every
//! callback arrives on a tokio worker thread. Swift must hop to its main
//! actor before touching UI state and must never call back into the engine
//! synchronously from inside a callback.
//!
//! Types that Swift only reads (findings, plan summaries, events) cross as
//! typed records (`mapping`). Anything the engine needs back — which finding,
//! which remedy, which plan — is an id or an opaque object, so the engine's
//! guards and preflight rules never round-trip through the app.

mod mapping;
mod runtime;
mod session;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use macaudit::cleanup::{self, ExecDeps};
use macaudit::config::{Config, DeleteMode as CoreDeleteMode, Paths};
use macaudit::engine::{Mode, ScannerManager};
use macaudit::model::{Finding as CoreFinding, FindingId, Remedy as CoreRemedy, ScannerId};
use macaudit::remedy::{execution_remedies, PlannedAction, RealClipboard, RealTrash, RemedyEngine};
use macaudit::runner::{CommandRunner, RealCommandRunner};
use macaudit::snapshot::SnapshotStore;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub use mapping::*;
use runtime::runtime;
use session::{Session, Shared};

uniffi::setup_scaffolding!("macaudit");

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum MacAuditError {
    /// Config or paths could not be loaded.
    #[error("config: {0}")]
    Config(String),
    #[error("snapshot: {0}")]
    Snapshot(String),
    /// A cleanup batch is already running.
    #[error("busy: {0}")]
    Busy(String),
    /// The request referenced something the engine does not have.
    #[error("invalid: {0}")]
    Invalid(String),
}

/// Receives scan progress. Called on engine threads.
#[uniffi::export(foreign)]
pub trait ScanListener: Send + Sync {
    fn on_event(&self, event: ScanEvent);
}

/// Receives cleanup progress. Called on engine threads.
#[uniffi::export(foreign)]
pub trait ExecListener: Send + Sync {
    fn on_event(&self, event: ExecEvent);
}

#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct EngineOptions {
    /// Use this directory as `$HOME` (config, state, scan roots) instead of
    /// the real one — the `MACAUDIT_HOME` fixture mechanism.
    pub home_override: Option<String>,
    /// Synthetic findings instead of real scanners (`--fake`).
    pub fake: bool,
    /// Skip network enrichment (`--offline`).
    pub offline: bool,
    /// Really delete instead of moving to the Trash (`--rm`).
    pub rm_mode: bool,
}

/// A planned, statically preflighted batch. Opaque to Swift: it reads the
/// summary and hands the object back to `execute`.
#[derive(uniffi::Object)]
pub struct Plan {
    actions: Vec<PlannedAction>,
    affected: Vec<ScannerId>,
    summary: PlanSummary,
}

#[uniffi::export]
impl Plan {
    pub fn summary(&self) -> PlanSummary {
        self.summary.clone()
    }
}

#[derive(uniffi::Object)]
pub struct Engine {
    shared: Arc<Shared>,
    /// The running batch's stop token; `None` between batches. Shared with
    /// the event forwarder so it can clear the slot when the batch finishes.
    cleanup_stop: Arc<Mutex<Option<CancellationToken>>>,
}

#[uniffi::export]
impl Engine {
    #[uniffi::constructor]
    pub fn new(opts: EngineOptions) -> Result<Arc<Self>, MacAuditError> {
        // A scan must never mutate Homebrew state (mirrors the CLI's main).
        std::env::set_var("HOMEBREW_NO_AUTO_UPDATE", "1");

        let paths = match &opts.home_override {
            Some(home) => Paths::from_home(home),
            None => Paths::resolve().map_err(|e| MacAuditError::Config(e.to_string()))?,
        };
        let paths = Arc::new(paths);
        let mut config =
            Config::load(&paths.config_file()).map_err(|e| MacAuditError::Config(e.to_string()))?;
        if opts.rm_mode {
            config.behavior.delete_mode = CoreDeleteMode::Rm;
        }
        if opts.offline {
            config.network.offline = true;
        }
        let config = Arc::new(config);
        let mode = if opts.fake { Mode::Fake } else { Mode::Real };
        if mode == Mode::Real {
            // A Finder-launched app inherits launchd's minimal PATH.
            paths.adopt_login_shell_path();
        }

        let runner: Arc<dyn CommandRunner> = Arc::new(RealCommandRunner);
        let _guard = runtime().enter();
        let mut manager = ScannerManager::new(config.clone(), paths.clone(), runner, mode);
        if !config.network.offline && mode == Mode::Real {
            manager = manager.with_fetcher(Arc::new(macaudit::net::ReqwestFetcher::new()));
        }
        let manager = Arc::new(manager);

        let (tx, rx) = mpsc::channel(1024);
        let shared = Arc::new(Shared {
            manager,
            session: Mutex::new(Session::default()),
            listener: Mutex::new(None),
            tx,
        });
        runtime().spawn(session::pump(rx, shared.clone()));

        Ok(Arc::new(Engine {
            shared,
            cleanup_stop: Arc::new(Mutex::new(None)),
        }))
    }

    /// Section metadata in sidebar order.
    pub fn sections(&self) -> Vec<SectionMeta> {
        mapping::sections()
    }

    pub fn delete_mode(&self) -> DeleteMode {
        self.shared.manager.delete_mode().into()
    }

    /// Start scanning `sections` (all of them for a full scan), reporting to
    /// `listener` — which replaces any previous listener. Returns the new
    /// generation; events from older generations are dropped. A section
    /// already scanning is cancelled and restarted; others keep running.
    pub fn start_scan(&self, sections: Vec<SectionId>, listener: Arc<dyn ScanListener>) -> u64 {
        *self.shared.listener.lock().unwrap() = Some(listener);
        let ids: Vec<ScannerId> = sections.into_iter().map(ScannerId::from).collect();
        self.shared.start_scan(&ids)
    }

    pub fn cancel_scan(&self) {
        self.shared.manager.cancel();
    }

    /// The current findings of one section (what the listener has been told,
    /// plus any correlation/enrichment rewrites).
    pub fn findings(&self, section: SectionId) -> Vec<Finding> {
        let session = self.shared.session.lock().unwrap();
        mapping::findings(session.section_findings(section.into()))
    }

    /// Plan a batch for `selection` and run the in-memory preflight. The plan
    /// may contain zero runnable actions (everything refused) — the summary
    /// says why, so the user can still see it.
    pub fn plan(&self, selection: Vec<Selection>) -> Result<Arc<Plan>, MacAuditError> {
        let current = self.shared.session.lock().unwrap().all_findings();
        let mut items: Vec<(FindingId, CoreRemedy)> = Vec::new();
        for sel in &selection {
            let id = mapping::finding_id(sel.finding_id);
            let f: &CoreFinding = current
                .get(&id)
                .ok_or_else(|| MacAuditError::Invalid(format!("no finding {id}")))?;
            let choice = match sel.remedy_index {
                Some(i) if (i as usize) < f.remedies.len() => Some(i as usize),
                Some(i) => {
                    return Err(MacAuditError::Invalid(format!(
                        "finding {id} has no remedy #{i}"
                    )))
                }
                None => None,
            };
            for r in execution_remedies(f, choice) {
                items.push((f.id, r.clone()));
            }
        }
        if items.is_empty() {
            return Err(MacAuditError::Invalid(
                "selection has no runnable remedies".to_string(),
            ));
        }
        let delete_mode = self.shared.manager.delete_mode();
        let planned = RemedyEngine::new(delete_mode).plan(&items);
        let report = cleanup::preflight_static(&planned, &current);
        let affected = cleanup::affected_sections(&report.ok, &current);
        let summary = mapping::plan_summary(&report, delete_mode, &affected);
        Ok(Arc::new(Plan {
            actions: report.ok,
            affected,
            summary,
        }))
    }

    /// Run a confirmed plan: refreshed preflight, the exact commands in
    /// dependency order, verification, audit report. Progress goes to
    /// `listener`; once the actions have run, the affected sections are
    /// rescanned through the scan listener. One batch at a time.
    pub fn execute(
        &self,
        plan: Arc<Plan>,
        listener: Arc<dyn ExecListener>,
    ) -> Result<(), MacAuditError> {
        if plan.actions.is_empty() {
            return Err(MacAuditError::Invalid(
                "plan has no runnable actions".to_string(),
            ));
        }
        let mut slot = self.cleanup_stop.lock().unwrap();
        if slot.is_some() {
            return Err(MacAuditError::Busy(
                "a cleanup batch is already running".to_string(),
            ));
        }
        let stop = CancellationToken::new();
        *slot = Some(stop.clone());
        drop(slot);

        let manager = self.shared.manager.clone();
        let deps = ExecDeps {
            runner: manager.runner(),
            trash: Arc::new(RealTrash),
            clipboard: Arc::new(RealClipboard),
            paths: manager.paths(),
            config: manager.config(),
            delete_mode: manager.delete_mode(),
        };
        let current: BTreeMap<FindingId, CoreFinding> =
            self.shared.session.lock().unwrap().all_findings();
        let (etx, mut erx) = mpsc::channel::<cleanup::ExecEvent>(64);
        let actions = plan.actions.clone();
        let affected = plan.affected.clone();
        let shared = self.shared.clone();
        let stop_slot = self.cleanup_stop.clone();

        runtime().spawn(async move {
            cleanup::run_batch(actions, current, deps, etx, stop).await;
        });
        runtime().spawn(async move {
            while let Some(ev) = erx.recv().await {
                let finished = matches!(ev, cleanup::ExecEvent::Finished(_));
                let mut ffi = ExecEvent::from(ev);
                if let ExecEvent::Executed { rescanning, .. } = &mut ffi {
                    if !affected.is_empty() {
                        shared.start_scan(&affected);
                        *rescanning = affected.iter().map(|s| SectionId::from(*s)).collect();
                    }
                }
                listener.on_event(ffi);
                if finished {
                    *stop_slot.lock().unwrap() = None;
                }
            }
        });
        Ok(())
    }

    /// Stop the running batch between actions (the current action finishes).
    pub fn cancel_cleanup(&self) {
        if let Some(stop) = self.cleanup_stop.lock().unwrap().as_ref() {
            stop.cancel();
        }
    }

    pub fn snapshots(&self) -> Result<Vec<SnapshotMeta>, MacAuditError> {
        let store = self.store()?;
        let list = store.list().map_err(snapshot_err)?;
        Ok(list.iter().map(SnapshotMeta::from).collect())
    }

    /// Persist the current findings. Refused while any section of the last
    /// scan failed — a partial snapshot would diff as wholesale removals.
    pub fn save_snapshot(&self) -> Result<i64, MacAuditError> {
        let (findings, failed) = {
            let session = self.shared.session.lock().unwrap();
            (
                session.all_findings(),
                session.failed_sections(ScannerId::ALL),
            )
        };
        if !failed.is_empty() {
            let names: Vec<&str> = failed.iter().map(|id| id.slug()).collect();
            return Err(MacAuditError::Snapshot(format!(
                "{} section(s) failed ({})",
                failed.len(),
                names.join(", ")
            )));
        }
        session::save_snapshot(&self.shared.manager, &findings).map_err(snapshot_err)
    }

    pub fn diff_snapshots(&self, a: i64, b: i64) -> Result<SnapshotDiff, MacAuditError> {
        let store = self.store()?;
        store
            .diff(a, b)
            .map(SnapshotDiff::from)
            .map_err(snapshot_err)
    }

    /// Per-section counts from the latest snapshot, for Δ badges.
    pub fn baseline_counts(&self) -> Vec<SectionBaseline> {
        session::baseline(&self.shared.manager)
    }

    /// Where the user's config file lives (for the Settings pane).
    pub fn config_path(&self) -> String {
        self.shared
            .manager
            .paths()
            .config_file()
            .to_string_lossy()
            .into_owned()
    }
}

impl Engine {
    fn store(&self) -> Result<SnapshotStore, MacAuditError> {
        SnapshotStore::open(&self.shared.manager.paths().history_db()).map_err(snapshot_err)
    }
}

fn snapshot_err(e: anyhow::Error) -> MacAuditError {
    MacAuditError::Snapshot(e.to_string())
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shared.manager.cancel();
        self.cancel_cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    struct Collector(Mutex<Vec<ScanEvent>>);

    impl ScanListener for Collector {
        fn on_event(&self, event: ScanEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    impl Collector {
        fn terminal_count(&self) -> usize {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|e| {
                    matches!(
                        e,
                        ScanEvent::SectionFinished { .. } | ScanEvent::SectionFailed { .. }
                    )
                })
                .count()
        }

        fn wait_for_terminal(&self, n: usize) {
            let deadline = Instant::now() + Duration::from_secs(30);
            while self.terminal_count() < n {
                assert!(Instant::now() < deadline, "scan did not finish in time");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    fn fake_engine() -> (Arc<Engine>, tempfile::TempDir) {
        let home = tempfile::tempdir().unwrap();
        let engine = Engine::new(EngineOptions {
            home_override: Some(home.path().to_string_lossy().into_owned()),
            fake: true,
            offline: true,
            rm_mode: false,
        })
        .unwrap();
        (engine, home)
    }

    fn scan_all(engine: &Engine) -> Arc<Collector> {
        let collector = Arc::new(Collector(Mutex::new(Vec::new())));
        let all: Vec<SectionId> = ScannerId::ALL.iter().map(|s| SectionId::from(*s)).collect();
        let listener: Arc<dyn ScanListener> = collector.clone();
        engine.start_scan(all, listener);
        collector.wait_for_terminal(ScannerId::ALL.len());
        collector
    }

    #[test]
    fn fake_scan_streams_every_section_and_matches_pull() {
        let (engine, _home) = fake_engine();
        let collector = scan_all(&engine);
        // Auto-snapshot lands after the last terminal event; wait for it so
        // the assertion below sees the full event stream.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !collector
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, ScanEvent::SnapshotSaved { .. }))
        {
            assert!(Instant::now() < deadline, "no auto-snapshot");
            std::thread::sleep(Duration::from_millis(20));
        }
        let events = collector.0.lock().unwrap().clone();

        for id in ScannerId::ALL {
            let section = SectionId::from(*id);
            let streamed: std::collections::BTreeSet<u64> = events
                .iter()
                .filter_map(|e| match e {
                    ScanEvent::Findings {
                        section: s,
                        findings,
                        ..
                    } if *s == section => Some(findings.iter().map(|f| f.id)),
                    _ => None,
                })
                .flatten()
                .collect();
            let expected: std::collections::BTreeSet<u64> = macaudit::fake::fixtures(*id)
                .iter()
                .map(|f| f.id.0)
                .collect();
            assert_eq!(streamed, expected, "section {}", id.slug());
            let pulled: std::collections::BTreeSet<u64> =
                engine.findings(section).iter().map(|f| f.id).collect();
            assert_eq!(pulled, expected, "pull for {}", id.slug());
        }
        assert!(events
            .iter()
            .any(|e| matches!(e, ScanEvent::SnapshotSaved { id: Some(_), .. })));
        assert_eq!(engine.snapshots().unwrap().len(), 1);
        assert_eq!(engine.sections().len(), ScannerId::ALL.len());
    }

    #[test]
    fn plan_uses_engine_rules_and_rejects_unknown_ids() {
        let (engine, _home) = fake_engine();
        scan_all(&engine);
        let destructive = engine
            .findings(SectionId::Fs)
            .into_iter()
            .find(|f| f.remedies.iter().any(|r| r.destructive && !r.alternative))
            .expect("a destructive Disk fixture");
        let plan = engine
            .plan(vec![Selection {
                finding_id: destructive.id,
                remedy_index: None,
            }])
            .unwrap();
        let summary = plan.summary();
        assert_eq!(summary.actions.len(), 1);
        assert_eq!(summary.actions[0].finding_id, destructive.id);
        let primary = destructive
            .remedies
            .iter()
            .find(|r| r.destructive && !r.alternative)
            .unwrap();
        assert_eq!(summary.actions[0].rendered, primary.rendered);
        assert_eq!(summary.affected, vec![SectionId::Fs]);

        let err = engine
            .plan(vec![Selection {
                finding_id: 42,
                remedy_index: None,
            }])
            .err()
            .unwrap();
        assert!(matches!(err, MacAuditError::Invalid(_)));
        let err = engine
            .plan(vec![Selection {
                finding_id: destructive.id,
                remedy_index: Some(99),
            }])
            .err()
            .unwrap();
        assert!(matches!(err, MacAuditError::Invalid(_)));
    }

    #[test]
    fn execute_refuses_empty_plans_and_concurrent_batches() {
        let (engine, _home) = fake_engine();
        scan_all(&engine);
        struct Sink;
        impl ExecListener for Sink {
            fn on_event(&self, _: ExecEvent) {}
        }
        let empty = Arc::new(Plan {
            actions: Vec::new(),
            affected: Vec::new(),
            summary: PlanSummary {
                actions: Vec::new(),
                refused: Vec::new(),
                removed: Vec::new(),
                remaining: Vec::new(),
                follow_up: Vec::new(),
                impact: None,
                delete_mode: DeleteMode::Trash,
                affected: Vec::new(),
            },
        });
        assert!(matches!(
            engine.execute(empty, Arc::new(Sink)),
            Err(MacAuditError::Invalid(_))
        ));

        // Occupy the slot as a running batch would and check the guard.
        *engine.cleanup_stop.lock().unwrap() = Some(CancellationToken::new());
        let reveal = engine
            .findings(SectionId::Fs)
            .into_iter()
            .find(|f| !f.remedies.is_empty())
            .unwrap();
        let plan = engine
            .plan(vec![Selection {
                finding_id: reveal.id,
                remedy_index: None,
            }])
            .unwrap();
        assert!(matches!(
            engine.execute(plan, Arc::new(Sink)),
            Err(MacAuditError::Busy(_))
        ));
    }
}
