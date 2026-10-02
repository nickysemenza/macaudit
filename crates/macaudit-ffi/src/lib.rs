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

mod diagnostics;
mod fake_effects;
mod mapping;
mod name_search;
mod queries;
mod runtime;
mod session;

use std::os::unix::ffi::OsStrExt;
use std::sync::{Arc, Mutex};

use macaudit::cleanup::{self, ExecDeps};
use macaudit::config::{Config, DeleteMode as CoreDeleteMode, Paths};
use macaudit::engine::{Mode, RunRequest, ScannerManager};
use macaudit::inventory::{
    Coverage, DirId, DirectoryRef, MemoryBudget, QueryCursor, QueryRegistry,
};
use macaudit::model::{Finding as CoreFinding, FindingId, Remedy as CoreRemedy, ScannerId};
use macaudit::remedy::{execution_remedies, RealClipboard, RealTrash, RemedyEngine};
use macaudit::runner::{CommandRunner, RealCommandRunner};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use fake_effects::FakeEffects;
pub use mapping::*;
pub use queries::QueryMemory;
use runtime::runtime;
use session::{Session, Shared};

uniffi::setup_scaffolding!("macaudit");

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum MacAuditError {
    /// Config or paths could not be loaded.
    #[error("config: {0}")]
    Config(String),
    /// A cleanup batch is already running.
    #[error("busy: {0}")]
    Busy(String),
    /// The request referenced something the engine does not have.
    #[error("invalid: {0}")]
    Invalid(String),
}

impl Engine {
    fn metadata_locked(&self) -> SessionMetadata {
        let mut session = self.shared.session.lock().unwrap();
        let run = self.shared.manager.current_run();
        if let Some(run) = run.as_ref() {
            session.reconcile_retired(run);
        }
        let trees = self.shared.dir_trees.read().unwrap();
        let disk = trees.first();
        let resource_limited = session.resource_limited();
        let mut coverage = run
            .as_ref()
            .and_then(|run| run.disk.coverage.as_ref())
            .map(WalkCoverage::from)
            .unwrap_or_else(|| {
                disk.map(|tree| WalkCoverage::from(&tree.coverage))
                    .unwrap_or_default()
            });
        coverage.resource_limited |= resource_limited;
        let mut disk_stop_reasons = run
            .as_ref()
            .map(|run| {
                run.disk
                    .stop_reasons
                    .iter()
                    .map(stop_reason)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut audit_stop_reasons = run
            .as_ref()
            .map(|run| {
                run.audit_host
                    .stop_reasons
                    .iter()
                    .map(stop_reason)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if resource_limited {
            if !disk_stop_reasons
                .iter()
                .any(|reason| reason == "resource_limited")
            {
                disk_stop_reasons.push("resource_limited".into());
            }
            if !audit_stop_reasons
                .iter()
                .any(|reason| reason == "resource_limited")
            {
                audit_stop_reasons.push("resource_limited".into());
            }
        }
        if coverage.deadline && !disk_stop_reasons.iter().any(|reason| reason == "deadline") {
            disk_stop_reasons.push("deadline".into());
        }
        if coverage.entry_limit
            && !disk_stop_reasons
                .iter()
                .any(|reason| reason == "entry_limit")
        {
            disk_stop_reasons.push("entry_limit".into());
        }
        SessionMetadata {
            run_id: session.run_id,
            revision: session.query_revision,
            selected_root: run
                .as_ref()
                .map(|run| run.request.selected_root.to_string_lossy().into_owned())
                .unwrap_or_else(|| self.selected_root()),
            started_at_ms: session.started_at_ms,
            queried_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            disk_complete: !resource_limited
                && run.as_ref().is_some_and(|run| {
                    run.disk.completeness == macaudit::engine::Completeness::Complete
                }),
            disk_errors: disk.map(|tree| tree.errors).unwrap_or_default(),
            disk_elapsed_ms: disk
                .map(|tree| tree.elapsed.as_millis() as u64)
                .unwrap_or_default(),
            audit_complete: !resource_limited
                && run.as_ref().is_some_and(|run| {
                    run.audit_host.completeness == macaudit::engine::Completeness::Complete
                }),
            cancelled: run.as_ref().is_some_and(|run| {
                run.disk.completeness == macaudit::engine::Completeness::Cancelled
            }),
            disk_coverage: if resource_limited {
                "resource_limited".into()
            } else {
                run.as_ref()
                    .map(|run| format!("{:?}", run.disk.completeness).to_lowercase())
                    .unwrap_or_else(|| "unavailable".into())
            },
            audit_coverage: if resource_limited {
                "resource_limited".into()
            } else {
                run.as_ref()
                    .map(|run| format!("{:?}", run.audit_host.completeness).to_lowercase())
                    .unwrap_or_else(|| "unavailable".into())
            },
            walk_coverage: coverage,
            disk_stop_reasons,
            audit_stop_reasons,
            active_scanners: run
                .as_ref()
                .map(|run| run.active_scanners as u64)
                .unwrap_or_default(),
            retiring_count: run
                .as_ref()
                .map(|run| run.retiring_count as u64)
                .unwrap_or_default(),
            retiring_runs: run
                .as_ref()
                .map(|run| {
                    run.retiring_runs
                        .iter()
                        .map(|retiring| RetiringRun {
                            run_id: retiring.run_id.0,
                            active_scanners: retiring.active_scanners as u64,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            query_memory: None,
        }
    }
}

fn stop_reason(reason: &macaudit::engine::RunStopReason) -> String {
    use macaudit::engine::RunStopReason;
    match reason {
        RunStopReason::Unreadable => "unreadable".into(),
        RunStopReason::Excluded => "excluded".into(),
        RunStopReason::Dataless => "dataless".into(),
        RunStopReason::Aliases => "aliases".into(),
        RunStopReason::Mounts => "mounts".into(),
        RunStopReason::Cancelled => "cancelled".into(),
        RunStopReason::ResourceLimited => "resource_limited".into(),
        RunStopReason::SummariesTruncated => "summaries_truncated".into(),
        RunStopReason::Deadline => "deadline".into(),
        RunStopReason::EntryLimit => "entry_limit".into(),
        RunStopReason::ScannerFailed { scanner } => format!("scanner_failed:{}", scanner.slug()),
    }
}

fn page_limit(limit: u32) -> Result<usize, MacAuditError> {
    if limit == 0 || limit > 500 {
        return Err(MacAuditError::Invalid("page limit must be 1...500".into()));
    }
    Ok(limit as usize)
}

fn next_request_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn supported_path(path: &std::path::Path) -> Result<&str, MacAuditError> {
    path.to_str().ok_or_else(|| {
        MacAuditError::Invalid("path has an unsupported non-UTF-8 representation".into())
    })
}

struct LiveSelection {
    files: Vec<TopFile>,
    dataless: u64,
    candidates: usize,
    unsupported: u64,
}

fn select_live_files(
    path: &std::path::Path,
    entries: &[macaudit::scan::walk::listing::Entry],
    limit: usize,
) -> LiveSelection {
    let mut files = std::collections::BinaryHeap::with_capacity(limit);
    let mut dataless = 0;
    let mut candidates = 0;
    let mut unsupported = 0;
    for entry in entries {
        if entry.name.to_str().is_none() {
            unsupported += 1;
            continue;
        }
        if entry.dataless {
            dataless += 1;
            continue;
        }
        if entry.kind != macaudit::scan::walk::listing::Kind::File {
            continue;
        }
        candidates += 1;
        let candidate = std::cmp::Reverse((entry.alloc, path.join(&entry.name)));
        if files.len() < limit {
            files.push(candidate);
        } else if files.peek().is_some_and(|smallest| candidate < *smallest) {
            files.pop();
            files.push(candidate);
        }
    }
    let mut files: Vec<_> = files
        .into_iter()
        .filter_map(|std::cmp::Reverse((alloc, path))| {
            path.to_str().map(|path| TopFile {
                path: path.to_owned(),
                alloc,
            })
        })
        .collect();
    files.sort_by(|left, right| {
        right
            .alloc
            .cmp(&left.alloc)
            .then_with(|| left.path.cmp(&right.path))
    });
    LiveSelection {
        files,
        dataless,
        candidates,
        unsupported,
    }
}

fn directory_entry(directory: DirectoryRef<'_>, path: std::path::PathBuf) -> Option<DirEntry> {
    Some(DirEntry {
        path: path.to_str()?.to_owned(),
        name: directory.name().into_owned(),
        node_revision: directory.revision,
        alloc: directory.alloc,
        apparent: directory.apparent,
        files: directory.files,
        dirs: directory.dirs,
        errors: directory.errors,
        has_children: directory.children().next().is_some(),
    })
}

fn unsupported_paths(metadata: &mut SessionMetadata, count: u64) {
    if count == 0 {
        return;
    }
    metadata.walk_coverage.unsupported_paths = metadata
        .walk_coverage
        .unsupported_paths
        .saturating_add(count);
    metadata.disk_coverage = "partial".into();
    if !metadata
        .disk_stop_reasons
        .iter()
        .any(|reason| reason == "unsupported_paths")
    {
        metadata.disk_stop_reasons.push("unsupported_paths".into());
    }
}

#[derive(Default, uniffi::Object)]
pub struct QueryCancellation {
    cancelled: std::sync::atomic::AtomicBool,
}

#[uniffi::export]
impl QueryCancellation {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Acquire)
    }
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
    run_id: u64,
    session: std::sync::Weak<Shared>,
    confirmed: cleanup::PreflightReport,
    affected: Vec<ScannerId>,
    summary: PlanSummary,
    _memory: Option<macaudit::inventory::Reservation>,
}

#[uniffi::export]
impl Plan {
    pub fn run_id(&self) -> u64 {
        self.run_id
    }
    pub fn summary(&self) -> PlanSummary {
        self.summary.clone()
    }
}

#[derive(uniffi::Object)]
pub struct Engine {
    fake: bool,
    shared: Arc<Shared>,
    /// The running batch's stop token; `None` between batches. Shared with
    /// the event forwarder so it can clear the slot when the batch finishes.
    cleanup_stop: Arc<Mutex<Option<CancellationToken>>>,
}

#[uniffi::export]
impl Engine {
    #[uniffi::constructor]
    pub fn new(opts: EngineOptions) -> Result<Arc<Self>, MacAuditError> {
        diagnostics::initialize();
        // A scan must never mutate Homebrew state (mirrors the CLI's main).
        std::env::set_var("HOMEBREW_NO_AUTO_UPDATE", "1");

        let paths = match &opts.home_override {
            Some(home) => Paths::from_home(home),
            None => Paths::resolve().map_err(|e| MacAuditError::Config(e.to_string()))?,
        };
        if paths.home.to_str().is_none() {
            return Err(MacAuditError::Config("Home path is not UTF-8".into()));
        }
        let paths = Arc::new(paths);
        let mut config = Config::default();
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

        let (tx, rx) = mpsc::channel(32);
        let (publish, callbacks) = std::sync::mpsc::sync_channel(1);
        let query_budget = MemoryBudget::shared();
        let shared = Arc::new(Shared {
            run_gate: Mutex::new(()),
            selected_root: Mutex::new(paths.home.to_string_lossy().into_owned()),
            publish,
            queries: Mutex::new(QueryRegistry::new(0, query_budget.clone())),
            query_budget,
            query_reclaimer: std::sync::OnceLock::new(),
            query_slots: queries::QueryAdmission::default(),
            manager,
            session: Mutex::new(Session::default()),
            listener: Mutex::new(None),
            tx,
            dir_trees: std::sync::RwLock::new(Vec::new()),
            footprints: std::sync::RwLock::new(std::collections::HashMap::new()),
        });
        shared.register_query_reclaimer();
        runtime().spawn(session::pump(rx, Arc::downgrade(&shared)));
        let weak = Arc::downgrade(&shared);
        std::thread::spawn(move || session::dispatch(callbacks, weak));

        Ok(Arc::new(Engine {
            fake: opts.fake,
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

    /// Compatibility entry point: every refresh starts a unified run.
    pub fn start_scan(&self, sections: Vec<SectionId>, listener: Arc<dyn ScanListener>) -> u64 {
        let _ = sections;
        self.start_run(self.selected_root(), listener)
            .unwrap_or_else(|_| self.shared.session.lock().unwrap().run_id)
    }

    pub fn selected_root(&self) -> String {
        self.shared.selected_root.lock().unwrap().clone()
    }

    pub fn set_root(&self, root: String) -> Result<(), MacAuditError> {
        let _gate = self.shared.run_gate.lock().unwrap();
        if self.cleanup_stop.lock().unwrap().is_some() {
            return Err(MacAuditError::Busy(
                "cleanup locks the selected root".into(),
            ));
        }
        let root = RunRequest::resolve_root(
            std::path::Path::new(&root),
            &self.shared.manager.paths().home,
            &self.shared.manager.paths().home,
        )
        .map_err(|error| MacAuditError::Invalid(error.to_string()))?;
        let root = supported_path(&root)?;
        *self.shared.selected_root.lock().unwrap() = root.to_owned();
        Ok(())
    }

    pub fn start_run(
        &self,
        root: String,
        listener: Arc<dyn ScanListener>,
    ) -> Result<u64, MacAuditError> {
        let _gate = self.shared.run_gate.lock().unwrap();
        if self.cleanup_stop.lock().unwrap().is_some() {
            return Err(MacAuditError::Busy("cleanup locks the current run".into()));
        }
        self.shared.start_run(root, Some(listener))
    }

    pub fn cancel_scan(&self) {
        let _gate = self.shared.run_gate.lock().unwrap();
        self.shared.manager.cancel();
        self.shared.session.lock().unwrap().cancel();
        let _ = self.shared.publish.try_send(());
    }

    /// The current findings of one section (what the listener has been told,
    /// plus any correlation/enrichment rewrites).
    pub fn findings(&self, section: SectionId) -> Vec<Finding> {
        let Ok(_permit) = self.shared.query_slots.acquire(None) else {
            return Vec::new();
        };
        let session = self.shared.session.lock().unwrap();
        let timing = diagnostics::query(
            "legacy_findings",
            session.run_id,
            next_request_id(),
            session.query_revision,
        );
        let _timing = timing.enter();
        let Ok((rows, _memory)) =
            session.budgeted_findings_page(section.into(), 0, 500, &self.shared.query_budget)
        else {
            return Vec::new();
        };
        diagnostics::query_rows(&timing, &rows);
        mapping::findings(rows)
    }

    pub fn session_metadata(&self) -> SessionMetadata {
        let _gate = self.shared.run_gate.lock().unwrap();
        self.metadata_locked()
    }

    pub fn findings_page(
        &self,
        section: SectionId,
        offset: u64,
        limit: u32,
    ) -> Result<FindingsPage, MacAuditError> {
        self.findings_page_for_run(
            section,
            self.session_metadata().run_id,
            None,
            None,
            offset,
            limit,
        )
    }

    pub fn findings_cursor_page(
        &self,
        cursor: FindingsCursor,
        limit: u32,
    ) -> Result<FindingsPage, MacAuditError> {
        self.findings_page_for_run(
            cursor.section,
            cursor.run_id,
            Some(cursor.revision),
            Some(cursor.request_id),
            cursor.offset,
            limit,
        )
    }

    pub fn findings_page_for_run(
        &self,
        section: SectionId,
        run_id: u64,
        revision: Option<u64>,
        request_id: Option<u64>,
        offset: u64,
        limit: u32,
    ) -> Result<FindingsPage, MacAuditError> {
        if offset != 0 && (revision.is_none() || request_id.is_none()) {
            return Err(MacAuditError::Invalid(
                "continuation requires a run-stamped cursor".into(),
            ));
        }
        let limit = page_limit(limit)?;
        let offset = usize::try_from(offset)
            .map_err(|_| MacAuditError::Invalid("page offset is too large".into()))?;
        let _permit = self.shared.query_slots.acquire(None)?;
        let _gate = self.shared.run_gate.lock().unwrap();
        let mut metadata = self.metadata_locked();
        if metadata.run_id != run_id
            || revision.is_some_and(|revision| revision != metadata.revision)
        {
            return Err(MacAuditError::Invalid(
                "findings page belongs to a retired run or revision".into(),
            ));
        }
        let session = self.shared.session.lock().unwrap();
        let revision = session.query_revision;
        let request_id = request_id.unwrap_or_else(next_request_id);
        let timing = diagnostics::query("findings_page", run_id, request_id, revision);
        let _timing = timing.enter();
        let total = session.finding_count(section.into());
        let (mut rows, memory) = session
            .budgeted_findings_page(section.into(), offset, limit + 1, &self.shared.query_budget)
            .map_err(|error| MacAuditError::Invalid(error.to_string()))?;
        let more = rows.len() > limit;
        rows.truncate(limit);
        diagnostics::query_rows(&timing, &rows);
        metadata.query_memory = Some(QueryMemory::keep(memory));
        Ok(FindingsPage {
            next_cursor: more.then_some(FindingsCursor {
                section,
                run_id,
                revision,
                request_id,
                offset: offset as u64 + rows.len() as u64,
            }),
            request_id,
            revision,
            total,
            metadata,
            next_offset: more.then_some(offset as u64 + rows.len() as u64),
            findings: mapping::findings(rows),
        })
    }

    pub fn section_summary(
        &self,
        section: SectionId,
        run_id: u64,
    ) -> Result<SectionSummary, MacAuditError> {
        let _gate = self.shared.run_gate.lock().unwrap();
        let metadata = self.metadata_locked();
        if metadata.run_id != run_id {
            return Err(MacAuditError::Invalid(
                "summary belongs to a retired run".into(),
            ));
        }
        let session = self.shared.session.lock().unwrap();
        let status = session.status_of(section.into());
        Ok(SectionSummary {
            metadata,
            section,
            total: session.finding_count(section.into()),
            reported_bytes: session.reported_bytes(section.into()),
            terminal: matches!(status, session::Status::Done | session::Status::Failed(_)),
            error: match status {
                session::Status::Failed(error) => Some(error),
                _ => None,
            },
        })
    }

    pub fn dir_children_page(
        &self,
        path: String,
        offset: u64,
        limit: u32,
    ) -> Result<DirectoryPage, MacAuditError> {
        let limit = page_limit(limit)?;
        let offset = usize::try_from(offset)
            .map_err(|_| MacAuditError::Invalid("page offset is too large".into()))?;
        let _permit = self.shared.query_slots.acquire(None)?;
        let mut memory = queries::reserve(
            &self.shared.query_budget,
            limit + 1,
            std::mem::size_of::<DirEntry>(),
            path.len(),
        )?;
        let _gate = self.shared.run_gate.lock().unwrap();
        let mut metadata = self.metadata_locked();
        let request_id = next_request_id();
        let path = std::path::PathBuf::from(path);
        let timing = diagnostics::query(
            "directory_children",
            metadata.run_id,
            request_id,
            metadata.revision,
        );
        let _timing = timing.enter();
        let trees = self.shared.dir_trees.read().unwrap();
        let tree = trees
            .iter()
            .find(|tree| path.starts_with(&tree.root))
            .ok_or_else(|| {
                MacAuditError::Invalid("directory is unavailable in the current inventory".into())
            })?;
        let directory = tree.node.find(&tree.root, &path).ok_or_else(|| {
            MacAuditError::Invalid(
                "directory is unavailable in the current inventory projection".into(),
            )
        })?;
        unsupported_paths(
            &mut metadata,
            directory
                .children()
                .filter(|child| std::str::from_utf8(child.raw_name()).is_err())
                .count() as u64,
        );
        let mut entries = Vec::with_capacity(limit + 1);
        for child in directory
            .children()
            .filter(|child| std::str::from_utf8(child.raw_name()).is_ok())
            .skip(offset)
            .take(limit + 1)
        {
            queries::grow(
                &mut memory,
                path.as_os_str().len() + child.raw_name().len() * 2 + 1,
            )?;
            if let Some(entry) = directory_entry(
                child,
                path.join(std::ffi::OsStr::from_bytes(child.raw_name())),
            ) {
                entries.push(entry);
            }
        }
        let more = entries.len() > limit;
        entries.truncate(limit);
        diagnostics::query_rows(&timing, &entries);
        metadata.query_memory = Some(QueryMemory::keep(memory));
        Ok(DirectoryPage {
            request_id,
            subject_path: supported_path(&path)?.to_owned(),
            metadata,
            next_offset: more.then_some(offset as u64 + entries.len() as u64),
            entries,
            truncated: more,
        })
    }

    pub fn dir_ancestors(&self, path: String) -> Vec<DirEntry> {
        let Ok(_permit) = self.shared.query_slots.acquire(None) else {
            return Vec::new();
        };
        let Ok(_memory) = queries::reserve(
            &self.shared.query_budget,
            500,
            std::mem::size_of::<DirEntry>(),
            path.len().saturating_mul(500),
        ) else {
            return Vec::new();
        };
        let _gate = self.shared.run_gate.lock().unwrap();
        let path = std::path::PathBuf::from(path);
        let trees = self.shared.dir_trees.read().unwrap();
        let Some(tree) = trees
            .iter()
            .find(|tree| tree.node.find(&tree.root, &path).is_some())
        else {
            return Vec::new();
        };
        let mut entries: Vec<_> = path
            .ancestors()
            .take_while(|ancestor| ancestor.starts_with(&tree.root))
            .take(500)
            .filter_map(|ancestor| {
                tree.node
                    .find(&tree.root, ancestor)
                    .and_then(|directory| directory_entry(directory, ancestor.to_path_buf()))
            })
            .collect();
        entries.reverse();
        entries
    }

    pub fn name_search(
        &self,
        query: String,
        limit: u32,
        cancellation: Arc<QueryCancellation>,
    ) -> Result<DirectorySearchPage, MacAuditError> {
        if limit == 0 || limit > 1000 {
            return Err(MacAuditError::Invalid(
                "name search limit must be 1...1000".into(),
            ));
        }
        let _permit = self.shared.query_slots.acquire(Some(&cancellation))?;
        let mut memory = queries::reserve(
            &self.shared.query_budget,
            limit as usize,
            std::mem::size_of::<DirEntry>() + std::mem::size_of::<TopFile>(),
            query.len(),
        )?;
        let (mut metadata, trees) = {
            let _gate = self.shared.run_gate.lock().unwrap();
            (
                self.metadata_locked(),
                self.shared.dir_trees.read().unwrap().clone(),
            )
        };
        let subject_query = query;
        let query = subject_query.trim().to_lowercase();
        let request_id = next_request_id();
        let timing = diagnostics::query(
            "name_search",
            metadata.run_id,
            request_id,
            metadata.revision,
        );
        let _timing = timing.enter();
        let mut entries = Vec::with_capacity(limit as usize);
        let mut truncated = false;
        let mut unsupported = 0;
        if !query.is_empty() {
            'trees: for tree in trees {
                for index in 0..tree.node.len() {
                    if cancellation.is_cancelled() {
                        break 'trees;
                    }
                    let Some(directory) = tree.node.directory(DirId(index as u32)) else {
                        continue;
                    };
                    let _name_memory = queries::reserve(
                        &self.shared.query_budget,
                        0,
                        0,
                        directory.raw_name().len(),
                    )?;
                    let mut depth = 0;
                    let mut path_bytes = tree.root.as_os_str().len();
                    let mut current = directory;
                    while let Some(parent) = current.parent() {
                        if cancellation.is_cancelled() {
                            break 'trees;
                        }
                        depth += 1;
                        path_bytes += current.raw_name().len() + 1;
                        current = parent;
                    }
                    let _path_memory = queries::reserve(
                        &self.shared.query_budget,
                        depth,
                        std::mem::size_of::<&std::ffi::OsStr>(),
                        path_bytes,
                    )?;
                    let mut components = Vec::with_capacity(depth);
                    let mut current = directory;
                    while let Some(parent) = current.parent() {
                        components.push(std::ffi::OsStr::from_bytes(current.raw_name()));
                        current = parent;
                    }
                    let mut path = tree.root.clone();
                    for component in components.into_iter().rev() {
                        path.push(component);
                    }
                    if path.to_str().is_none() {
                        unsupported += 1;
                        continue;
                    }
                    let relative = path.strip_prefix(&tree.root).unwrap_or(&path);
                    let _match_memory = queries::reserve(
                        &self.shared.query_budget,
                        0,
                        0,
                        path_bytes.saturating_mul(4),
                    )?;
                    if !relative.to_str().unwrap().to_lowercase().contains(&query)
                        && !directory.name().to_lowercase().contains(&query)
                    {
                        continue;
                    }
                    if entries.len() == limit as usize {
                        truncated = true;
                        break 'trees;
                    }
                    queries::grow(&mut memory, path_bytes + directory.raw_name().len())?;
                    if let Some(entry) = directory_entry(directory, path) {
                        entries.push(entry);
                    }
                }
            }
        }
        let observed_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let config = self.shared.manager.config();
        let paths = self.shared.manager.paths();
        let _exclude_memory = queries::reserve(
            &self.shared.query_budget,
            config.scan.ignore.len(),
            std::mem::size_of::<std::path::PathBuf>(),
            config.scan.ignore.iter().map(String::len).sum::<usize>()
                + paths
                    .home
                    .as_os_str()
                    .len()
                    .saturating_mul(config.scan.ignore.len()),
        )?;
        let excludes: Vec<_> = config
            .scan
            .ignore
            .iter()
            .map(|path| paths.expand(path))
            .collect();
        let files = if truncated {
            name_search::FileMatches {
                files: Vec::new(),
                stop_reasons: vec!["truncated".into()],
                truncated: true,
            }
        } else {
            name_search::files(
                std::path::Path::new(&metadata.selected_root),
                &query,
                limit as usize - entries.len(),
                &self.shared.query_budget,
                &mut memory,
                &excludes,
                &|| {
                    cancellation.is_cancelled()
                        || self.shared.session.lock().unwrap().run_id != metadata.run_id
                },
            )
        };
        truncated |= files.truncated;
        let mut stop_reasons = files.stop_reasons;
        if unsupported > 0
            && !stop_reasons
                .iter()
                .any(|reason| reason == "unsupported_paths")
        {
            stop_reasons.push("unsupported_paths".into());
        }
        let coverage = if cancellation.is_cancelled() {
            "cancelled"
        } else if truncated {
            "truncated"
        } else if stop_reasons.is_empty() {
            "complete"
        } else {
            "partial"
        }
        .to_owned();
        diagnostics::query_rows(&timing, &files.files);
        unsupported_paths(&mut metadata, unsupported);
        let _gate = self.shared.run_gate.lock().unwrap();
        if metadata.run_id != self.shared.session.lock().unwrap().run_id {
            return Err(MacAuditError::Invalid(
                "name search belongs to a retired run".into(),
            ));
        }
        diagnostics::query_rows(&timing, &entries);
        metadata.query_memory = Some(QueryMemory::keep(memory));
        Ok(DirectorySearchPage {
            request_id,
            query: subject_query,
            metadata,
            entries,
            files: files.files,
            observed_at_ms,
            coverage,
            stop_reasons,
            truncated,
            cancelled: cancellation.is_cancelled(),
        })
    }

    pub fn open_name_query(
        &self,
        query: String,
        limit: u32,
        cancellation: Arc<QueryCancellation>,
    ) -> Result<DirectoryCursor, MacAuditError> {
        let mut result = self.name_search(query, limit, cancellation.clone())?;
        let _permit = self.shared.query_slots.acquire(Some(&cancellation))?;
        if result.cancelled {
            return Err(MacAuditError::Invalid("name query was cancelled".into()));
        }
        let _gate = self.shared.run_gate.lock().unwrap();
        let session = self.shared.session.lock().unwrap();
        if result.metadata.run_id != session.run_id
            || result.metadata.revision != session.query_revision
        {
            return Err(MacAuditError::Invalid(
                "query belongs to a retired run".into(),
            ));
        }
        drop(session);
        let coverage = if result.cancelled {
            Coverage::Cancelled
        } else if result.truncated {
            Coverage::Truncated
        } else if result.metadata.disk_complete
            && result.metadata.walk_coverage.unsupported_paths == 0
        {
            Coverage::Complete
        } else {
            Coverage::Partial
        };
        let revision = result.metadata.revision;
        let request_id = result.request_id;
        let run_id = result.metadata.run_id;
        let unsupported_paths = result.metadata.walk_coverage.unsupported_paths;
        let timing = diagnostics::query(
            "name_query_cache",
            result.metadata.run_id,
            request_id,
            revision,
        );
        let _timing = timing.enter();
        diagnostics::query_rows(&timing, &result.entries);
        let memory =
            QueryMemory::into_reservation(result.metadata.query_memory.take().ok_or_else(
                || MacAuditError::Invalid("name query has no construction lease".into()),
            )?)?;
        let entries = std::mem::take(&mut result.entries);
        drop(result);
        let handle = self
            .shared
            .queries
            .lock()
            .unwrap()
            .insert(request_id, revision, coverage, entries, memory)
            .map_err(|error| MacAuditError::Invalid(error.to_string()))?;
        Ok(DirectoryCursor {
            handle,
            run_id,
            revision,
            offset: 0,
            unsupported_paths,
        })
    }

    pub fn directory_query_page(
        &self,
        cursor: DirectoryCursor,
        limit: u32,
    ) -> Result<DirectoryQueryPage, MacAuditError> {
        let limit = page_limit(limit)?;
        let _permit = self.shared.query_slots.acquire(None)?;
        let mut memory = queries::reserve(&self.shared.query_budget, 0, 0, 0)?;
        let _gate = self.shared.run_gate.lock().unwrap();
        let mut metadata = self.metadata_locked();
        let timing = diagnostics::query("directory_page", cursor.run_id, 0, cursor.revision);
        let _timing = timing.enter();
        if cursor.run_id != metadata.run_id || cursor.revision != metadata.revision {
            return Err(MacAuditError::Invalid(
                "query belongs to a retired run or revision".into(),
            ));
        }
        unsupported_paths(&mut metadata, cursor.unsupported_paths);
        let mut page = self
            .shared
            .queries
            .lock()
            .unwrap()
            .page(
                QueryCursor {
                    handle: cursor.handle,
                    run_id: cursor.run_id,
                    revision: cursor.revision,
                    offset: usize::try_from(cursor.offset)
                        .map_err(|_| MacAuditError::Invalid("page offset is too large".into()))?,
                },
                limit,
            )
            .map_err(|error| MacAuditError::Invalid(error.to_string()))?;
        queries::grow(
            &mut memory,
            page.rows.iter().fold(
                page.rows
                    .len()
                    .saturating_mul(std::mem::size_of::<DirEntry>()),
                |bytes, row| {
                    bytes
                        .saturating_add(row.path.len())
                        .saturating_add(row.name.len())
                },
            ),
        )?;
        timing.record("request_id", page.metadata.request_id);
        diagnostics::query_rows(&timing, &page.rows);
        let request_id = page.metadata.request_id;
        let revision = page.metadata.revision;
        let observed_at_ms = page.metadata.observed_unix_millis;
        let coverage = format!("{:?}", page.metadata.coverage).to_lowercase();
        let entries = std::mem::take(&mut page.rows);
        let next_cursor = page.next_cursor.take();
        metadata.query_memory = Some(QueryMemory::keep_page(page, memory));
        Ok(DirectoryQueryPage {
            metadata,
            request_id,
            revision,
            observed_at_ms,
            coverage,
            entries,
            next_cursor: next_cursor.map(|next| DirectoryCursor {
                handle: next.handle,
                run_id: next.run_id,
                revision: next.revision,
                offset: next.offset as u64,
                unsupported_paths: cursor.unsupported_paths,
            }),
        })
    }

    pub fn release_directory_query(&self, cursor: DirectoryCursor) {
        let _gate = self.shared.run_gate.lock().unwrap();
        if cursor.run_id == self.shared.session.lock().unwrap().run_id {
            self.shared.queries.lock().unwrap().remove(cursor.handle);
        }
    }

    /// Plan a batch for `selection` and run the in-memory preflight. The plan
    /// may contain zero runnable actions (everything refused) — the summary
    /// says why, so the user can still see it.
    pub fn plan(&self, selection: Vec<Selection>) -> Result<Arc<Plan>, MacAuditError> {
        let _permit = self.shared.query_slots.acquire(None)?;
        let _gate = self.shared.run_gate.lock().unwrap();
        if self.cleanup_stop.lock().unwrap().is_some() {
            return Err(MacAuditError::Busy("cleanup locks planning".into()));
        }
        if selection.is_empty() || selection.len() > 500 {
            return Err(MacAuditError::Invalid(
                "cleanup selection must contain 1...500 rows".into(),
            ));
        }
        let (run_id, current, memory) = {
            let session = self.shared.session.lock().unwrap();
            let (current, memory) = session
                .all_findings()
                .map_err(|error| MacAuditError::Invalid(error.to_string()))?;
            (session.run_id, current, memory)
        };
        drop(_gate);
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
        let _gate = self.shared.run_gate.lock().unwrap();
        if run_id != self.shared.session.lock().unwrap().run_id {
            return Err(MacAuditError::Invalid(
                "plan belongs to a superseded run".into(),
            ));
        }
        if self.cleanup_stop.lock().unwrap().is_some() {
            return Err(MacAuditError::Busy("cleanup locks planning".into()));
        }
        Ok(Arc::new(Plan {
            run_id,
            session: Arc::downgrade(&self.shared),
            confirmed: report,
            affected,
            summary,
            _memory: Some(memory),
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
        let _gate = self.shared.run_gate.lock().unwrap();
        if plan.confirmed.ok.is_empty() {
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
        if !plan.session.ptr_eq(&Arc::downgrade(&self.shared))
            || plan.run_id != self.shared.session.lock().unwrap().run_id
        {
            return Err(MacAuditError::Invalid(
                "cleanup plan belongs to a superseded run".into(),
            ));
        }
        let (current, memory) = self
            .shared
            .session
            .lock()
            .unwrap()
            .all_findings()
            .map_err(|error| MacAuditError::Invalid(error.to_string()))?;
        let stop = CancellationToken::new();
        *slot = Some(stop.clone());
        drop(slot);

        let manager = self.shared.manager.clone();
        let deps = ExecDeps {
            runner: if self.fake {
                Arc::new(macaudit::runner::MockCommandRunner::new())
            } else {
                manager.runner()
            },
            trash: if self.fake {
                Arc::new(FakeEffects)
            } else {
                Arc::new(RealTrash)
            },
            clipboard: if self.fake {
                Arc::new(FakeEffects)
            } else {
                Arc::new(RealClipboard)
            },
            paths: manager.paths(),
            config: manager.config(),
            delete_mode: manager.delete_mode(),
        };
        let (etx, mut erx) = mpsc::channel::<cleanup::ExecEvent>(64);
        let confirmed = plan.confirmed.clone();
        let affected = plan.affected.clone();
        let shared = self.shared.clone();
        let stop_slot = self.cleanup_stop.clone();

        runtime().spawn(async move {
            let _memory = memory;
            let _plan = plan;
            cleanup::run_confirmed_batch(confirmed, current, deps, etx, stop).await;
        });
        runtime().spawn(async move {
            let mut executed = None;
            let mut completed = false;
            while let Some(ev) = erx.recv().await {
                let finished = matches!(ev, cleanup::ExecEvent::Finished(_));
                let ffi = ExecEvent::from(ev);
                if matches!(ffi, ExecEvent::Executed { .. }) {
                    executed = Some(ffi);
                    continue;
                }
                if finished {
                    completed = true;
                    if let Some(mut executed) = executed.take() {
                        let _gate = shared.run_gate.lock().unwrap();
                        *stop_slot.lock().unwrap() = None;
                        if !affected.is_empty() {
                            let root = shared.selected_root.lock().unwrap().clone();
                            if let Ok(gen) = shared.start_run(root, None) {
                                if let ExecEvent::Executed {
                                    rescanning,
                                    rescan_gen,
                                    ..
                                } = &mut executed
                                {
                                    *rescan_gen = Some(gen);
                                    *rescanning = ScannerId::ALL
                                        .iter()
                                        .map(|section| SectionId::from(*section))
                                        .collect();
                                }
                            }
                        }
                        drop(_gate);
                        listener.on_event(executed);
                    } else {
                        *stop_slot.lock().unwrap() = None;
                    }
                }
                listener.on_event(ffi);
            }
            if !completed {
                *stop_slot.lock().unwrap() = None;
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

    /// Where the user's config file lives (for the Settings pane).
    pub fn config_path(&self) -> String {
        self.shared
            .manager
            .paths()
            .config_file()
            .to_string_lossy()
            .into_owned()
    }

    /// Whether this process can read TCC-protected user data (Full Disk
    /// Access). See `macaudit::scan::tcc`.
    pub fn full_disk_access(&self) -> bool {
        macaudit::scan::tcc::full_disk_access(&self.shared.manager.paths())
    }

    /// The root of the first walked Disk tree, or `None` until a Disk scan
    /// has completed at least once.
    pub fn dir_root(&self) -> Option<DirEntry> {
        let _gate = self.shared.run_gate.lock().unwrap();
        let trees = self.shared.dir_trees.read().unwrap();
        let tree = trees.first()?;
        tree.node
            .find(&tree.root, &tree.root)
            .and_then(|directory| directory_entry(directory, tree.root.clone()))
    }

    /// The single directory at `path`, with no children expanded.
    pub fn dir_entry(&self, path: String) -> Option<DirEntry> {
        let _gate = self.shared.run_gate.lock().unwrap();
        let path = std::path::PathBuf::from(path);
        let trees = self.shared.dir_trees.read().unwrap();
        let tree = trees.iter().find(|t| path.starts_with(&t.root))?;
        tree.node
            .find(&tree.root, &path)
            .and_then(|directory| directory_entry(directory, path))
    }

    /// `path`'s direct children, already sorted by allocated size descending.
    /// Empty when `path` is unknown or a leaf.
    pub fn dir_children(&self, path: String) -> Vec<DirEntry> {
        let Ok(_permit) = self.shared.query_slots.acquire(None) else {
            return Vec::new();
        };
        let Ok(mut memory) = queries::reserve(
            &self.shared.query_budget,
            500,
            std::mem::size_of::<DirEntry>(),
            path.len(),
        ) else {
            return Vec::new();
        };
        let _gate = self.shared.run_gate.lock().unwrap();
        let path = std::path::PathBuf::from(path);
        let trees = self.shared.dir_trees.read().unwrap();
        let Some(tree) = trees.iter().find(|tree| path.starts_with(&tree.root)) else {
            return Vec::new();
        };
        let Some(directory) = tree.node.find(&tree.root, &path) else {
            return Vec::new();
        };
        let mut candidates = std::collections::BinaryHeap::with_capacity(500);
        for child in directory
            .children()
            .filter(|child| std::str::from_utf8(child.raw_name()).is_ok())
        {
            let candidate =
                std::cmp::Reverse((child.alloc, std::cmp::Reverse(child.raw_name()), child.id.0));
            if candidates.len() < 500 {
                candidates.push(candidate);
            } else if candidates
                .peek()
                .is_some_and(|smallest| candidate < *smallest)
            {
                candidates.pop();
                candidates.push(candidate);
            }
        }
        let mut selected: Vec<_> = candidates
            .into_iter()
            .map(|candidate| candidate.0)
            .collect();
        selected.sort_unstable_by(|left, right| {
            right.0.cmp(&left.0).then_with(|| left.1 .0.cmp(right.1 .0))
        });
        let mut entries = Vec::with_capacity(selected.len());
        for (_, _, id) in selected {
            let child = tree.node.directory(DirId(id)).unwrap();
            if queries::grow(
                &mut memory,
                path.as_os_str().len() + child.raw_name().len() * 2 + 1,
            )
            .is_err()
            {
                return Vec::new();
            }
            if let Some(entry) = directory_entry(
                child,
                path.join(std::ffi::OsStr::from_bytes(child.raw_name())),
            ) {
                entries.push(entry);
            }
        }
        entries
    }

    /// `path`'s subtree, expanded `depth` levels and flattened preorder,
    /// capped at `max_nodes` entries.
    pub fn dir_subtree(&self, path: String, depth: u32, max_nodes: u32) -> Vec<DirEntry> {
        let max_nodes = max_nodes.min(500) as usize;
        if max_nodes == 0 {
            return Vec::new();
        }
        let Ok(_permit) = self.shared.query_slots.acquire(None) else {
            return Vec::new();
        };
        let Ok(mut memory) = queries::reserve(
            &self.shared.query_budget,
            max_nodes,
            std::mem::size_of::<DirEntry>(),
            path.len(),
        ) else {
            return Vec::new();
        };
        let _gate = self.shared.run_gate.lock().unwrap();
        let mut path = std::path::PathBuf::from(path);
        let trees = self.shared.dir_trees.read().unwrap();
        let Some(tree) = trees.iter().find(|t| path.starts_with(&t.root)) else {
            return Vec::new();
        };
        let Some(directory) = tree.node.find(&tree.root, &path) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(max_nodes);
        if flatten_preorder(
            directory,
            &mut path,
            depth.min(64),
            max_nodes,
            &mut out,
            &mut memory,
        )
        .is_err()
        {
            return Vec::new();
        }
        out
    }

    /// The `n` largest files directly inside `path`, listed live (one directory, no
    /// recursion) so the tree does not have to carry a file list per directory.
    pub fn dir_top_files(&self, path: String, n: u32) -> Vec<TopFile> {
        if n == 0 {
            return Vec::new();
        }
        self.live_files_page(path, n.min(500))
            .map(|page| page.files)
            .unwrap_or_default()
    }

    pub fn live_files_page(
        &self,
        path: String,
        limit: u32,
    ) -> Result<LiveFilesPage, MacAuditError> {
        let limit = page_limit(limit)?;
        let _permit = self.shared.query_slots.acquire(None)?;
        let mut memory = queries::reserve(
            &self.shared.query_budget,
            limit,
            std::mem::size_of::<TopFile>() + std::mem::size_of::<std::path::PathBuf>(),
            path.len(),
        )?;
        let mut metadata = self.session_metadata();
        let request_id = next_request_id();
        let timing =
            diagnostics::query("live_files", metadata.run_id, request_id, metadata.revision);
        let _timing = timing.enter();
        let observed_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let home = &self.shared.manager.paths().home;
        let path = RunRequest::resolve_root(std::path::Path::new(&path), home, home)
            .map_err(|error| MacAuditError::Invalid(error.to_string()))?;
        supported_path(&path)?;
        if !path.starts_with(&metadata.selected_root) {
            return Err(MacAuditError::Invalid(
                "live listing is outside the selected root".into(),
            ));
        }
        let listing = macaudit::scan::walk::listing::list(&path)
            .map_err(|error| MacAuditError::Invalid(error.to_string()))?;
        let longest_name = listing
            .entries
            .iter()
            .map(|entry| entry.name.len())
            .max()
            .unwrap_or_default();
        queries::grow(
            &mut memory,
            (limit + 1).saturating_mul(path.as_os_str().len() + longest_name + 1),
        )?;
        let LiveSelection {
            files,
            dataless,
            candidates,
            unsupported,
        } = select_live_files(&path, &listing.entries, limit);
        let mut stop_reasons = Vec::new();
        if dataless > 0 {
            stop_reasons.push("dataless".into());
        }
        if listing.errors > 0 {
            stop_reasons.push("unreadable".into());
        }
        unsupported_paths(&mut metadata, unsupported);
        if unsupported > 0 {
            stop_reasons.push("unsupported_paths".into());
        }
        let _gate = self.shared.run_gate.lock().unwrap();
        if metadata.run_id != self.shared.session.lock().unwrap().run_id {
            return Err(MacAuditError::Invalid(
                "live listing belongs to a retired run".into(),
            ));
        }
        diagnostics::query_rows(&timing, &files);
        metadata.query_memory = Some(QueryMemory::keep(memory));
        Ok(LiveFilesPage {
            request_id,
            subject_path: supported_path(&path)?.to_owned(),
            metadata,
            observed_at_ms,
            coverage: if stop_reasons.is_empty() {
                "complete".into()
            } else {
                "partial".into()
            },
            files,
            dataless,
            errors: listing.errors,
            truncated: candidates > limit,
            stop_reasons,
        })
    }

    /// The largest files across every walked root, allocated size descending.
    pub fn largest_files(&self, n: u32) -> Vec<TopFile> {
        let Ok(_permit) = self.shared.query_slots.acquire(None) else {
            return Vec::new();
        };
        let _gate = self.shared.run_gate.lock().unwrap();
        let n = n.min(500) as usize;
        if n == 0 {
            return Vec::new();
        }
        let trees = self.shared.dir_trees.read().unwrap();
        let longest_path = trees
            .iter()
            .flat_map(|tree| &tree.top_files)
            .map(|file| file.path.as_os_str().len())
            .max()
            .unwrap_or(0);
        let Ok(_memory) = queries::reserve(
            &self.shared.query_budget,
            n,
            std::mem::size_of::<TopFile>() + std::mem::size_of::<(u64, &std::path::PathBuf)>(),
            longest_path.saturating_mul(n),
        ) else {
            return Vec::new();
        };
        let mut files = std::collections::BinaryHeap::with_capacity(n);
        for file in trees.iter().flat_map(|tree| tree.top_files.iter()) {
            if file.path.to_str().is_none() {
                continue;
            }
            let candidate = std::cmp::Reverse((file.alloc, &file.path));
            if files.len() < n {
                files.push(candidate);
            } else if files.peek().is_some_and(|smallest| candidate < *smallest) {
                files.pop();
                files.push(candidate);
            }
        }
        let mut merged: Vec<_> = files
            .into_iter()
            .map(|std::cmp::Reverse((alloc, path))| TopFile {
                path: path.to_str().expect("validated file path").to_owned(),
                alloc,
            })
            .collect();
        merged.sort_by_key(|f| std::cmp::Reverse(f.alloc));
        merged
    }

    /// Summary counters for the first walked root, for the Disk section's
    /// header/status. `None` until a Disk scan has completed at least once.
    pub fn dir_tree_stats(&self) -> Option<DirTreeStats> {
        let _gate = self.shared.run_gate.lock().unwrap();
        let trees = self.shared.dir_trees.read().unwrap();
        let tree = trees.first()?;
        Some(DirTreeStats {
            root: supported_path(&tree.root).ok()?.to_owned(),
            files: tree.files,
            directory_entries: tree.entries,
            externally_linked_bytes: tree.externally_linked,
            dirs: tree.dirs,
            bytes: tree.bytes,
            errors: tree.errors,
            complete: tree.complete,
            elapsed_ms: tree.elapsed.as_millis() as u64,
            coverage: WalkCoverage::from(&tree.coverage),
        })
    }

    /// One owner's full breakdown, by the `Finding.id` of its `Project`/
    /// `AppOwner` row — `None` before that axis has scanned, or if `id`
    /// doesn't belong to an owner row. The entry list can be large, so it is
    /// fetched on demand here rather than carried on the `Finding` itself;
    /// Swift retries on the next `sectionFinished`.
    ///
    /// Takes only the `footprints` read lock, never `session` — the pump
    /// (`session.rs`) always takes `session` before touching `footprints`
    /// when both are needed, so taking `session` here too could deadlock
    /// against it under the opposite order. `footprint`/`footprint_buckets`
    /// avoid the question entirely by never touching `session`.
    pub fn footprint(&self, finding_id: u64) -> Option<Footprint> {
        self.footprint_for_run(finding_id, self.session_metadata().run_id)
            .ok()
            .flatten()
    }

    pub fn footprint_for_run(
        &self,
        finding_id: u64,
        run_id: u64,
    ) -> Result<Option<Footprint>, MacAuditError> {
        let _permit = self.shared.query_slots.acquire(None)?;
        let _gate = self.shared.run_gate.lock().unwrap();
        if self.shared.session.lock().unwrap().run_id != run_id {
            return Err(MacAuditError::Invalid(
                "owner detail belongs to a retired run".into(),
            ));
        }
        let footprints = self.shared.footprints.read().unwrap();
        let Some(footprint) = footprints
            .values()
            .find_map(|set| set.footprints.iter().find(|fp| fp.finding.0 == finding_id))
        else {
            return Ok(None);
        };
        let mut memory = queries::reserve(
            &self.shared.query_budget,
            500,
            std::mem::size_of::<FootprintEntry>()
                + std::mem::size_of::<FootprintGroup>()
                + std::mem::size_of::<Proc>()
                + std::mem::size_of::<String>(),
            footprint.owner.key.len()
                + footprint.owner.name.len()
                + footprint
                    .owner
                    .path
                    .as_ref()
                    .map_or(0, |path| path.as_os_str().len()),
        )?;
        for entry in footprint
            .groups
            .iter()
            .take(500)
            .flat_map(|group| &group.entries)
            .filter(|entry| entry.path.to_str().is_some())
            .take(500)
        {
            queries::grow(&mut memory, queries::entry_bytes(entry))?;
        }
        for path in footprint
            .worktrees
            .iter()
            .filter(|path| path.to_str().is_some())
            .take(500)
        {
            queries::grow(&mut memory, path.as_os_str().len())?;
        }
        for process in footprint
            .processes
            .iter()
            .filter(|process| process.cwd.to_str().is_some())
            .take(500)
        {
            queries::grow(
                &mut memory,
                process.cwd.as_os_str().len() + process.name.len(),
            )?;
        }
        let mut result = Footprint::from(footprint);
        result.query_memory = Some(QueryMemory::keep(memory));
        Ok(Some(result))
    }

    pub fn footprint_entries_page(
        &self,
        finding_id: u64,
        offset: u64,
        limit: u32,
    ) -> Result<FootprintEntriesPage, MacAuditError> {
        self.footprint_entries_page_for_run(
            finding_id,
            self.session_metadata().run_id,
            None,
            None,
            offset,
            limit,
        )
    }

    pub fn footprint_cursor_page(
        &self,
        cursor: FootprintCursor,
        limit: u32,
    ) -> Result<FootprintEntriesPage, MacAuditError> {
        self.footprint_entries_page_for_run(
            cursor.finding_id,
            cursor.run_id,
            Some(cursor.revision),
            Some(cursor.request_id),
            cursor.offset,
            limit,
        )
    }

    pub fn footprint_entries_page_for_run(
        &self,
        finding_id: u64,
        run_id: u64,
        revision: Option<u64>,
        request_id: Option<u64>,
        offset: u64,
        limit: u32,
    ) -> Result<FootprintEntriesPage, MacAuditError> {
        if offset != 0 && (revision.is_none() || request_id.is_none()) {
            return Err(MacAuditError::Invalid(
                "continuation requires a run-stamped cursor".into(),
            ));
        }
        let limit = page_limit(limit)?;
        let offset = usize::try_from(offset)
            .map_err(|_| MacAuditError::Invalid("page offset is too large".into()))?;
        let _permit = self.shared.query_slots.acquire(None)?;
        let mut memory = queries::reserve(
            &self.shared.query_budget,
            limit + 1,
            std::mem::size_of::<FootprintEntry>(),
            0,
        )?;
        let _gate = self.shared.run_gate.lock().unwrap();
        let mut metadata = self.metadata_locked();
        if metadata.run_id != run_id
            || revision.is_some_and(|revision| revision != metadata.revision)
        {
            return Err(MacAuditError::Invalid(
                "owner page belongs to a retired run or revision".into(),
            ));
        }
        let revision = metadata.revision;
        let request_id = request_id.unwrap_or_else(next_request_id);
        let timing = diagnostics::query("owner_entries", run_id, request_id, revision);
        let _timing = timing.enter();
        let footprints = self.shared.footprints.read().unwrap();
        let footprint = footprints
            .values()
            .find_map(|set| {
                set.footprints
                    .iter()
                    .find(|footprint| footprint.finding.0 == finding_id)
            })
            .ok_or_else(|| MacAuditError::Invalid("owner is not in the current run".into()))?;
        unsupported_paths(
            &mut metadata,
            footprint
                .groups
                .iter()
                .flat_map(|group| group.entries.iter())
                .filter(|entry| entry.path.to_str().is_none())
                .count() as u64,
        );
        let mut entries = Vec::with_capacity(limit + 1);
        for entry in footprint
            .groups
            .iter()
            .flat_map(|group| group.entries.iter())
            .filter(|entry| entry.path.to_str().is_some())
            .skip(offset)
            .take(limit + 1)
        {
            queries::grow(&mut memory, queries::entry_bytes(entry))?;
            entries.push(FootprintEntry::from(entry));
        }
        let more = entries.len() > limit;
        entries.truncate(limit);
        diagnostics::query_rows(&timing, &entries);
        metadata.query_memory = Some(QueryMemory::keep(memory));
        let total = footprint
            .groups
            .iter()
            .flat_map(|group| group.entries.iter())
            .filter(|entry| entry.path.to_str().is_some())
            .count() as u64;
        Ok(FootprintEntriesPage {
            next_cursor: more.then_some(FootprintCursor {
                finding_id,
                run_id,
                revision,
                request_id,
                offset: offset as u64 + entries.len() as u64,
            }),
            request_id,
            revision,
            total,
            metadata,
            finding_id,
            next_offset: more.then_some(offset as u64 + entries.len() as u64),
            entries,
        })
    }

    /// One axis's coverage buckets (Baseline, Unattributed, disk/attributed
    /// totals, missing deps) — `None` until that axis has scanned at least
    /// once. See `footprint` for the lock-order note.
    pub fn footprint_buckets(&self, axis: Axis) -> Option<FootprintBuckets> {
        self.footprint_buckets_for_run(axis, self.session_metadata().run_id)
            .ok()
            .flatten()
    }

    pub fn footprint_buckets_for_run(
        &self,
        axis: Axis,
        run_id: u64,
    ) -> Result<Option<FootprintBuckets>, MacAuditError> {
        let _permit = self.shared.query_slots.acquire(None)?;
        let _gate = self.shared.run_gate.lock().unwrap();
        if self.shared.session.lock().unwrap().run_id != run_id {
            return Err(MacAuditError::Invalid(
                "owner buckets belong to a retired run".into(),
            ));
        }
        let footprints = self.shared.footprints.read().unwrap();
        let Some(set) = footprints.get(&axis.into()) else {
            return Ok(None);
        };
        let mut memory = queries::reserve(
            &self.shared.query_budget,
            1000,
            std::mem::size_of::<FootprintEntry>(),
            0,
        )?;
        for entries in [&set.baseline, &set.unattributed] {
            for entry in entries
                .iter()
                .filter(|entry| entry.path.to_str().is_some())
                .take(500)
            {
                queries::grow(&mut memory, queries::entry_bytes(entry))?;
            }
        }
        let mut result = FootprintBuckets::from(set.as_ref());
        result.query_memory = Some(QueryMemory::keep(memory));
        Ok(Some(result))
    }
}

/// Depth-first, parent-before-children flatten of a summary tree, stopping
/// once `out` reaches `max_nodes`.
fn flatten_preorder(
    directory: DirectoryRef<'_>,
    path: &mut std::path::PathBuf,
    depth: u32,
    max_nodes: usize,
    out: &mut Vec<DirEntry>,
    memory: &mut macaudit::inventory::Reservation,
) -> Result<(), MacAuditError> {
    if out.len() >= max_nodes {
        return Ok(());
    }
    if path.to_str().is_none() {
        return Ok(());
    }
    queries::grow(memory, path.as_os_str().len() + directory.raw_name().len())?;
    let Some(entry) = directory_entry(directory, path.clone()) else {
        return Ok(());
    };
    out.push(entry);
    if depth == 0 {
        return Ok(());
    }
    for child in directory.children() {
        if out.len() >= max_nodes {
            break;
        }
        if std::str::from_utf8(child.raw_name()).is_err() {
            continue;
        }
        queries::grow(memory, path.as_os_str().len() + child.raw_name().len() + 1)?;
        path.push(std::ffi::OsStr::from_bytes(child.raw_name()));
        flatten_preorder(child, path, depth - 1, max_nodes, out, memory)?;
        path.pop();
    }
    Ok(())
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
    fn retired_run_reconciles_terminals_after_a_stalled_pump() {
        let (engine, _home) = fake_engine();
        let listener = Arc::new(Collector(Mutex::new(Vec::new())));
        let sections = ScannerId::ALL
            .iter()
            .map(|scanner| (*scanner).into())
            .collect();
        let run_id = engine.start_scan(sections, listener.clone());
        let session = engine.shared.session.lock().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while engine.shared.tx.capacity() != 0 {
            assert!(
                Instant::now() < deadline,
                "the stalled pump queue did not fill"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        engine
            .shared
            .manager
            .resource_limited(macaudit::engine::RunId(run_id), ScannerId::Apps);
        let deadline = Instant::now() + Duration::from_secs(3);
        while engine.shared.manager.current_run().unwrap().active_scanners != 0 {
            assert!(
                Instant::now() < deadline,
                "cancelled scanners did not retire"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(session);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if ScannerId::ALL.iter().all(|scanner| {
                engine
                    .section_summary((*scanner).into(), run_id)
                    .unwrap()
                    .terminal
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "retired sections still appear scanning"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        listener.wait_for_terminal(ScannerId::ALL.len());
        assert!(engine
            .session_metadata()
            .audit_stop_reasons
            .iter()
            .any(|reason| reason == "resource_limited"));
    }

    fn cleanup_fixture(engine: &Engine, home: &std::path::Path) -> Finding {
        let path = home.join("cleanup-fixture");
        std::fs::write(&path, "test target").unwrap();
        let mut session = engine.shared.session.lock().unwrap();
        let mut finding = session
            .findings_page(ScannerId::Fs, 0, 500)
            .into_iter()
            .find(|finding| {
                finding
                    .remedies
                    .iter()
                    .any(|remedy| remedy.destructive && !remedy.alternative)
            })
            .unwrap();
        finding.path = Some(path.clone());
        for remedy in &mut finding.remedies {
            if let macaudit::model::RemedyCommand::Trash { path: target }
            | macaudit::model::RemedyCommand::RevealInFinder { path: target } =
                &mut remedy.command
            {
                *target = path.clone();
            }
        }
        let gen = session.run_id;
        session.apply(&macaudit::model::ScanEvent::Finding {
            scanner: ScannerId::Fs,
            gen,
            finding: Box::new(finding.clone()),
        });
        Finding::from(&finding)
    }

    struct ExecCollector(Mutex<Vec<ExecEvent>>);

    impl ExecListener for ExecCollector {
        fn on_event(&self, event: ExecEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    impl ExecCollector {
        fn wait_for_finished(&self) {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !self
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|event| matches!(event, ExecEvent::Finished { .. }))
            {
                assert!(Instant::now() < deadline, "cleanup did not finish in time");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    #[test]
    fn cleanup_refuses_replaced_confirmation_targets_without_trashing_replacement() {
        let (engine, home) = fake_engine();
        scan_all(&engine);
        let finding = cleanup_fixture(&engine, home.path());
        let plan = engine
            .plan(vec![Selection {
                finding_id: finding.id,
                remedy_index: None,
            }])
            .unwrap();
        assert_eq!(plan.summary().actions.len(), 1);
        let target = home.path().join("cleanup-fixture");
        let original = home.path().join("confirmed-original");
        std::fs::rename(&target, &original).unwrap();
        std::fs::write(&target, "replacement must survive").unwrap();
        let collector = Arc::new(ExecCollector(Mutex::new(Vec::new())));
        engine.execute(plan, collector.clone()).unwrap();
        collector.wait_for_finished();
        let events = collector.0.lock().unwrap();
        assert!(events.iter().any(|event| matches!(event,
            ExecEvent::PreflightDone { ok, refused }
                if ok.is_empty() && refused.iter().any(|action| action.reason.contains("replaced since confirmation"))
        )));
        assert!(!events
            .iter()
            .any(|event| matches!(event, ExecEvent::ActionStarted { .. })));
        assert_eq!(
            std::fs::read_to_string(target).unwrap(),
            "replacement must survive"
        );
        assert_eq!(std::fs::read_to_string(original).unwrap(), "test target");
    }

    #[test]
    fn fake_cleanup_refuses_physical_effects_on_unchanged_targets() {
        let (engine, home) = fake_engine();
        scan_all(&engine);
        let finding = cleanup_fixture(&engine, home.path());
        let plan = engine
            .plan(vec![Selection {
                finding_id: finding.id,
                remedy_index: None,
            }])
            .unwrap();
        let collector = Arc::new(ExecCollector(Mutex::new(Vec::new())));
        engine.execute(plan, collector.clone()).unwrap();
        collector.wait_for_finished();
        assert_eq!(
            std::fs::read_to_string(home.path().join("cleanup-fixture")).unwrap(),
            "test target"
        );
        assert!(!collector
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, ExecEvent::ActionDone { ok: true, .. })));
    }

    #[test]
    fn fake_scan_streams_every_section_and_matches_pull() {
        let (engine, _home) = fake_engine();
        let collector = scan_all(&engine);
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
        assert_eq!(engine.sections().len(), ScannerId::ALL.len());
    }

    #[test]
    fn plan_uses_engine_rules_and_rejects_unknown_ids() {
        let (engine, home) = fake_engine();
        scan_all(&engine);
        let destructive = cleanup_fixture(&engine, home.path());
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
        let (engine, home) = fake_engine();
        scan_all(&engine);
        struct Sink;
        impl ExecListener for Sink {
            fn on_event(&self, _: ExecEvent) {}
        }
        let empty = Arc::new(Plan {
            run_id: engine.shared.session.lock().unwrap().run_id,
            session: Arc::downgrade(&engine.shared),
            confirmed: cleanup::PreflightReport::default(),
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
            _memory: None,
        });
        assert!(matches!(
            engine.execute(empty, Arc::new(Sink)),
            Err(MacAuditError::Invalid(_))
        ));

        let reveal = cleanup_fixture(&engine, home.path());
        let plan = engine
            .plan(vec![Selection {
                finding_id: reveal.id,
                remedy_index: None,
            }])
            .unwrap();
        *engine.cleanup_stop.lock().unwrap() = Some(CancellationToken::new());
        assert!(matches!(
            engine.plan(vec![Selection {
                finding_id: reveal.id,
                remedy_index: None
            }]),
            Err(MacAuditError::Busy(_))
        ));
        assert!(matches!(
            engine.execute(plan, Arc::new(Sink)),
            Err(MacAuditError::Busy(_))
        ));
    }

    fn scan_fs(engine: &Engine) -> Arc<Collector> {
        let collector = Arc::new(Collector(Mutex::new(Vec::new())));
        let listener: Arc<dyn ScanListener> = collector.clone();
        engine.start_scan(vec![SectionId::Fs], listener);
        collector.wait_for_terminal(ScannerId::ALL.len());
        collector
    }

    #[test]
    fn dir_top_files_lists_live_and_handles_missing_path() {
        let (engine, _home) = fake_engine();
        let dir = tempfile::tempdir().unwrap();
        engine
            .set_root(dir.path().to_string_lossy().into_owned())
            .unwrap();
        std::fs::write(dir.path().join("small"), vec![0u8; 4096]).unwrap();
        std::fs::write(dir.path().join("medium"), vec![0u8; 8192]).unwrap();
        std::fs::write(dir.path().join("large"), vec![0u8; 12288]).unwrap();

        let top = engine.dir_top_files(dir.path().to_string_lossy().into_owned(), 5);
        let names: Vec<_> = top
            .iter()
            .map(|f| {
                std::path::Path::new(&f.path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, ["large", "medium", "small"]);
        assert!(top.windows(2).all(|w| w[0].alloc >= w[1].alloc));

        assert!(engine
            .dir_top_files(dir.path().join("missing").to_string_lossy().into_owned(), 5)
            .is_empty());
    }

    #[test]
    fn dir_tree_is_absent_before_a_scan() {
        let (engine, _home) = fake_engine();
        assert!(engine.dir_root().is_none());
        assert!(engine.dir_tree_stats().is_none());
        assert!(engine.dir_entry("/Users/dev".to_string()).is_none());
        assert!(engine.dir_children("/Users/dev".to_string()).is_empty());
        assert!(engine
            .dir_subtree("/Users/dev".to_string(), 2, 5)
            .is_empty());
        assert!(engine.largest_files(3).is_empty());
    }

    #[test]
    fn fake_scan_exposes_dir_tree() {
        let (engine, _home) = fake_engine();
        scan_fs(&engine);

        let root = engine.dir_root().expect("dir tree after a Disk scan");
        assert_eq!(root.path, engine.selected_root());

        let children = engine.dir_children(root.path.clone());
        assert!(!children.is_empty());
        assert!(children
            .iter()
            .all(|c| c.path.starts_with(&root.path) && c.path != root.path));
        assert!(children.windows(2).all(|w| w[0].alloc >= w[1].alloc));

        let trees = engine.shared.dir_trees.read().unwrap();
        let tree = trees.first().unwrap();
        assert_eq!(root.node_revision, tree.node.revision);
        for entry in &children {
            assert_eq!(
                entry.node_revision,
                tree.node
                    .find(&tree.root, std::path::Path::new(&entry.path))
                    .unwrap()
                    .revision
            );
        }
        drop(trees);

        assert!(engine.dir_entry("/nope".to_string()).is_none());

        let leaf = children
            .iter()
            .find(|c| !c.has_children)
            .expect("a leaf directory in the fake tree");
        assert!(engine.dir_children(leaf.path.clone()).is_empty());

        let subtree = engine.dir_subtree(root.path.clone(), 2, 5);
        assert!(subtree.len() <= 5);

        let largest = engine.largest_files(3);
        assert!(largest.len() <= 3);
        assert!(largest.windows(2).all(|w| w[0].alloc >= w[1].alloc));
    }

    #[test]
    fn fake_inventory_moves_to_the_selected_root_on_refresh() {
        let (engine, home) = fake_engine();
        scan_fs(&engine);
        let previous = engine.dir_root().unwrap().path;
        std::fs::create_dir(home.path().join("selected")).unwrap();
        engine.set_root("selected".into()).unwrap();
        scan_fs(&engine);
        let selected = engine.selected_root();
        assert_ne!(selected, previous);
        assert_eq!(engine.dir_root().unwrap().path, selected);
        assert!(engine.dir_entry(previous).is_none());
        assert!(engine
            .dir_children(selected.clone())
            .iter()
            .all(|entry| std::path::Path::new(&entry.path).starts_with(&selected)));
    }

    #[test]
    fn non_utf8_directory_rows_never_alias_a_replacement_character_path() {
        let (engine, _home) = fake_engine();
        let root = std::path::PathBuf::from(engine.selected_root());
        let mut tree = macaudit::fake::dir_tree_at(&root);
        tree.node = macaudit::inventory::DiskInventory::new(MemoryBudget::shared()).unwrap();
        let root_id = tree.node.add_directory(None, root.as_os_str()).unwrap();
        let invalid_name = std::ffi::OsStr::from_bytes(b"entry\xff");
        let invalid = tree
            .node
            .add_directory(Some(root_id), invalid_name)
            .unwrap();
        tree.node.update(
            invalid,
            &macaudit::scan::walk::DirNode {
                alloc: 999,
                ..Default::default()
            },
        );
        tree.node
            .add_directory(Some(invalid), std::ffi::OsStr::new("entry-descendant"))
            .unwrap();
        let valid_name = "entry\u{fffd}";
        let valid = tree
            .node
            .add_directory(Some(root_id), std::ffi::OsStr::new(valid_name))
            .unwrap();
        tree.node.update(
            valid,
            &macaudit::scan::walk::DirNode {
                alloc: 111,
                ..Default::default()
            },
        );
        tree.top_files = vec![
            macaudit::scan::walk::BigFile {
                path: root.join(invalid_name),
                alloc: 999,
            },
            macaudit::scan::walk::BigFile {
                path: root.join(valid_name),
                alloc: 111,
            },
        ];
        engine
            .shared
            .dir_trees
            .write()
            .unwrap()
            .push(Arc::new(tree));
        let path = root.to_str().unwrap().to_owned();
        let children = engine.dir_children_page(path.clone(), 0, 500).unwrap();
        assert_eq!(children.entries.len(), 1);
        assert_eq!(children.entries[0].alloc, 111);
        assert_eq!(children.metadata.walk_coverage.unsupported_paths, 1);
        assert!(children
            .metadata
            .disk_stop_reasons
            .iter()
            .any(|reason| reason == "unsupported_paths"));
        assert_eq!(engine.dir_children(path.clone()), children.entries);
        assert_eq!(engine.dir_subtree(path, 64, 500).len(), 2);
        assert_eq!(
            engine
                .dir_entry(root.join(valid_name).to_str().unwrap().into())
                .unwrap()
                .alloc,
            111
        );
        assert_eq!(engine.largest_files(500).len(), 1);
        assert_eq!(engine.largest_files(500)[0].alloc, 111);
        let search = engine
            .name_search("entry".into(), 1000, QueryCancellation::new())
            .unwrap();
        assert_eq!(search.entries, children.entries);
        assert_eq!(search.metadata.walk_coverage.unsupported_paths, 2);
        let cursor = engine
            .open_name_query("entry".into(), 1000, QueryCancellation::new())
            .unwrap();
        let cached = engine.directory_query_page(cursor, 500).unwrap();
        assert_eq!(cached.entries, search.entries);
        assert_eq!(cached.metadata.walk_coverage.unsupported_paths, 2);
        assert_eq!(cached.coverage, "partial");
    }

    #[test]
    fn non_utf8_live_candidates_are_omitted_without_lossy_aliases() {
        let (engine, home) = fake_engine();
        engine
            .set_root(home.path().to_str().unwrap().into())
            .unwrap();
        let entry = |name: &std::ffi::OsStr, alloc| macaudit::scan::walk::listing::Entry {
            name: name.to_owned(),
            kind: macaudit::scan::walk::listing::Kind::File,
            dev: 1,
            ino: alloc,
            nlink: 1,
            alloc,
            apparent: alloc,
            mtime_secs: 0,
            mount_point: false,
            dataless: false,
        };
        let selection = select_live_files(
            home.path(),
            &[
                entry(std::ffi::OsStr::from_bytes(b"entry\xff"), 999),
                entry(std::ffi::OsStr::new("entry\u{fffd}"), 111),
            ],
            500,
        );
        assert_eq!(selection.files.len(), 1);
        assert_eq!(selection.files[0].alloc, 111);
        assert_eq!(selection.unsupported, 1);
        let mut metadata = engine.session_metadata();
        unsupported_paths(&mut metadata, selection.unsupported);
        assert_eq!(metadata.walk_coverage.unsupported_paths, 1);
        assert_eq!(metadata.disk_coverage, "partial");
        assert!(metadata
            .disk_stop_reasons
            .iter()
            .any(|reason| reason == "unsupported_paths"));
    }

    #[test]
    fn non_utf8_root_paths_are_refused_instead_of_lossily_represented() {
        let (engine, home) = fake_engine();
        let invalid = home.path().join(std::ffi::OsStr::from_bytes(b"root\xff"));
        let previous = engine.selected_root();
        assert!(supported_path(&invalid).is_err());
        assert_eq!(
            supported_path(&home.path().join("root\u{fffd}")).unwrap(),
            invalid.to_string_lossy()
        );
        assert_eq!(engine.selected_root(), previous);
        assert_eq!(engine.session_metadata().run_id, 0);
    }

    #[test]
    fn diagnostics_subprocess_fixture() {
        if std::env::var_os("MACAUDIT_FFI_TRACE_TEST").is_none() {
            return;
        }
        let (engine, _home) = fake_engine();
        scan_fs(&engine);
        let root = engine.dir_root().unwrap();
        engine.dir_children_page(root.path, 0, 10).unwrap();
        engine
            .name_search("a".into(), 10, QueryCancellation::new())
            .unwrap();
    }

    #[test]
    fn diagnostics_are_opt_in_and_write_only_to_stderr() {
        let run = |enabled| {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "tests::diagnostics_subprocess_fixture",
                    "--nocapture",
                ])
                .env("MACAUDIT_FFI_TRACE_TEST", "1")
                .env_remove("RUST_LOG");
            if enabled {
                command.env("RUST_LOG", "macaudit_ffi=debug");
            }
            command.output().unwrap()
        };
        let silent = run(false);
        assert!(silent.status.success());
        assert!(silent.stderr.is_empty());
        let traced = run(true);
        assert!(traced.status.success());
        let stdout = String::from_utf8(traced.stdout).unwrap();
        let stderr = String::from_utf8(traced.stderr).unwrap();
        assert!(!stdout.contains("ffi_"));
        for field in [
            "ffi_query",
            "ffi_serialize",
            "ffi_publication",
            "run_id=",
            "request_id=",
            "revision=",
            "bytes=",
            "time.busy=",
        ] {
            assert!(stderr.contains(field), "missing {field}: {stderr}");
        }
        assert!(!stderr.contains('\u{1b}'));
    }

    #[test]
    fn directory_local_revisions_are_independent_of_finding_revisions() {
        let (engine, _home) = fake_engine();
        engine
            .shared
            .session
            .lock()
            .unwrap()
            .begin_scan(77, ScannerId::ALL);
        let tree = Arc::new(macaudit::fake::dir_tree());
        engine.shared.dir_trees.write().unwrap().push(tree.clone());
        let root = engine.dir_root().unwrap();
        let mut entries = engine
            .dir_children_page(root.path.clone(), 0, 500)
            .unwrap()
            .entries;
        entries.extend(engine.dir_children(root.path.clone()));
        entries.extend(engine.dir_subtree(root.path.clone(), 64, 500));
        entries.extend(
            engine
                .name_search("a".into(), 1000, QueryCancellation::new())
                .unwrap()
                .entries,
        );
        for entry in entries {
            assert_eq!(
                entry.node_revision,
                tree.node
                    .find(&tree.root, std::path::Path::new(&entry.path))
                    .unwrap()
                    .revision
            );
        }
        let before = engine.session_metadata().revision;
        engine
            .shared
            .session
            .lock()
            .unwrap()
            .apply(&macaudit::model::ScanEvent::Finding {
                scanner: ScannerId::Apps,
                gen: 77,
                finding: Box::new(macaudit::fake::fixtures(ScannerId::Apps).remove(0)),
            });
        assert!(engine.session_metadata().revision > before);
        assert_eq!(
            engine.dir_entry(root.path).unwrap().node_revision,
            root.node_revision
        );
    }

    #[test]
    fn scoped_stats_preserve_entry_and_external_link_counters() {
        let (engine, _home) = fake_engine();
        let mut tree = macaudit::fake::dir_tree_at(std::path::Path::new(&engine.selected_root()));
        tree.entries = Some(19);
        tree.files = 7;
        tree.externally_linked = Some(1234);
        engine
            .shared
            .dir_trees
            .write()
            .unwrap()
            .push(Arc::new(tree));
        let stats = engine.dir_tree_stats().unwrap();
        assert_eq!(stats.directory_entries, Some(19));
        assert_eq!(stats.files, 7);
        assert_eq!(stats.externally_linked_bytes, Some(1234));
    }

    #[test]
    fn partial_stats_leave_unavailable_accounting_counters_unknown() {
        let (engine, _home) = fake_engine();
        let mut tree = macaudit::fake::dir_tree_at(std::path::Path::new(&engine.selected_root()));
        tree.entries = None;
        tree.externally_linked = None;
        tree.complete = false;
        tree.files = 7;
        engine
            .shared
            .dir_trees
            .write()
            .unwrap()
            .push(Arc::new(tree));
        let stats = engine.dir_tree_stats().unwrap();
        assert_eq!(stats.directory_entries, None);
        assert_eq!(stats.externally_linked_bytes, None);
        assert_eq!(stats.files, 7);
        assert!(!stats.complete);
    }

    #[test]
    fn footprint_is_absent_before_any_scan() {
        let (engine, _home) = fake_engine();
        assert!(engine.footprint(0).is_none());
        assert!(engine.footprint_buckets(Axis::Projects).is_none());
        assert!(engine.footprint_buckets(Axis::AppStorage).is_none());
    }

    #[test]
    fn footprint_resolves_every_project_and_app_owner_finding() {
        let (engine, _home) = fake_engine();
        scan_all(&engine);

        for section in [SectionId::Projects, SectionId::AppStorage] {
            let owner_findings: Vec<Finding> = engine
                .findings(section)
                .into_iter()
                .filter(|f| matches!(f.kind, FindingKind::Project | FindingKind::AppOwner))
                .collect();
            assert!(
                !owner_findings.is_empty(),
                "{section:?} produced no owner findings"
            );
            for f in owner_findings {
                let fp = engine
                    .footprint(f.id)
                    .unwrap_or_else(|| panic!("no footprint for finding {}", f.id));
                assert_eq!(fp.finding, f.id);
                assert_eq!(fp.owner.name, f.title);
            }
        }

        let projects = engine
            .footprint_buckets(Axis::Projects)
            .expect("Projects buckets after a scan");
        assert_eq!(projects.axis, Axis::Projects);
        let apps = engine
            .footprint_buckets(Axis::AppStorage)
            .expect("AppStorage buckets after a scan");
        assert_eq!(apps.axis, Axis::AppStorage);
    }

    #[test]
    fn invalid_root_preserves_the_current_run_and_snapshot() {
        let (engine, home) = fake_engine();
        scan_all(&engine);
        let before = engine.session_metadata();
        let findings = engine.findings(SectionId::Apps);
        let listener = Arc::new(Collector(Mutex::new(Vec::new())));
        assert!(engine
            .start_run(
                home.path().join("missing").to_string_lossy().into_owned(),
                listener
            )
            .is_err());
        assert_eq!(engine.session_metadata().run_id, before.run_id);
        assert_eq!(engine.findings(SectionId::Apps), findings);
        assert!(engine.set_root(String::new()).is_err());
        assert!(engine.set_root("~someone".into()).is_err());
    }

    #[test]
    fn gui_relative_roots_use_home_for_setter_and_start() {
        let (engine, home) = fake_engine();
        let relative = "selected-child";
        let selected = home.path().join(relative);
        std::fs::create_dir(&selected).unwrap();
        let canonical = selected
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        engine.set_root(relative.into()).unwrap();
        assert_eq!(engine.selected_root(), canonical);
        let listener = Arc::new(Collector(Mutex::new(Vec::new())));
        let run_id = engine.start_run(relative.into(), listener.clone()).unwrap();
        listener.wait_for_terminal(ScannerId::ALL.len());
        assert_eq!(engine.session_metadata().selected_root, canonical);
        assert_eq!(engine.session_metadata().run_id, run_id);
    }

    #[test]
    fn owner_and_finding_continuations_are_run_and_revision_fenced() {
        let (engine, _home) = fake_engine();
        scan_all(&engine);
        let metadata = engine.session_metadata();
        let findings = engine
            .findings_page_for_run(SectionId::Apps, metadata.run_id, None, None, 0, 1)
            .unwrap();
        assert_eq!(
            findings.total,
            engine.findings(SectionId::Apps).len() as u64
        );
        let finding_cursor = findings.next_cursor.unwrap();
        assert!(engine
            .findings_cursor_page(finding_cursor.clone(), 1)
            .is_ok());
        assert!(engine.findings_page(SectionId::Apps, 1, 1).is_err());
        let owner = engine
            .findings(SectionId::Projects)
            .into_iter()
            .find(|finding| finding.kind == FindingKind::Project)
            .unwrap();
        let page = engine
            .footprint_entries_page_for_run(owner.id, metadata.run_id, None, None, 0, 1)
            .unwrap();
        let owner_cursor = page.next_cursor.unwrap();
        assert!(engine
            .footprint_cursor_page(owner_cursor.clone(), 1)
            .is_ok());
        assert!(engine.footprint_entries_page(owner.id, 1, 1).is_err());
        let mut stale_revision = owner_cursor.clone();
        stale_revision.revision += 1;
        assert!(engine.footprint_cursor_page(stale_revision, 1).is_err());
        scan_all(&engine);
        assert!(engine.footprint_for_run(owner.id, metadata.run_id).is_err());
        assert!(engine
            .footprint_buckets_for_run(Axis::Projects, metadata.run_id)
            .is_err());
        assert!(engine.footprint_cursor_page(owner_cursor, 1).is_err());
        assert!(engine.findings_cursor_page(finding_cursor, 1).is_err());
        assert!(engine
            .section_summary(SectionId::Apps, metadata.run_id)
            .is_err());
    }

    #[test]
    fn cleanup_plans_are_run_and_engine_scoped_and_refresh_is_locked() {
        let (engine, home) = fake_engine();
        scan_all(&engine);
        let finding = engine
            .findings(SectionId::Fs)
            .into_iter()
            .find(|finding| !finding.remedies.is_empty())
            .unwrap();
        let plan = engine
            .plan(vec![Selection {
                finding_id: finding.id,
                remedy_index: None,
            }])
            .unwrap();
        scan_all(&engine);
        struct Sink;
        impl ExecListener for Sink {
            fn on_event(&self, _: ExecEvent) {}
        }
        assert!(matches!(
            engine.execute(plan, Arc::new(Sink)),
            Err(MacAuditError::Invalid(_))
        ));
        *engine.cleanup_stop.lock().unwrap() = Some(CancellationToken::new());
        let current = engine.session_metadata().run_id;
        assert!(matches!(
            engine.start_run(
                home.path().to_string_lossy().into_owned(),
                Arc::new(Collector(Mutex::new(Vec::new())))
            ),
            Err(MacAuditError::Busy(_))
        ));
        assert!(matches!(
            engine.set_root(home.path().to_string_lossy().into_owned()),
            Err(MacAuditError::Busy(_))
        ));
        assert_eq!(engine.session_metadata().run_id, current);
    }

    #[test]
    fn query_limits_and_expired_handles_are_safe() {
        let (engine, _home) = fake_engine();
        scan_all(&engine);
        let root = engine.dir_root().unwrap();
        assert!(engine.dir_children_page(root.path.clone(), 0, 501).is_err());
        assert!(engine.findings_page(SectionId::Fs, 0, 0).is_err());
        assert!(engine
            .name_search("a".into(), 1001, QueryCancellation::new())
            .is_err());
        assert!(engine
            .dir_subtree(root.path.clone(), u32::MAX, 0)
            .is_empty());
        assert!(engine.dir_subtree(root.path, u32::MAX, u32::MAX).len() <= 500);
        let cursor = engine
            .open_name_query("a".into(), 1000, QueryCancellation::new())
            .unwrap();
        assert!(engine.directory_query_page(cursor.clone(), 500).is_ok());
        engine.release_directory_query(cursor.clone());
        assert!(engine.directory_query_page(cursor, 500).is_err());
        let cursor = engine
            .open_name_query("a".into(), 1000, QueryCancellation::new())
            .unwrap();
        scan_all(&engine);
        assert!(engine.directory_query_page(cursor, 500).is_err());
        let cancellation = QueryCancellation::new();
        cancellation.cancel();
        assert!(engine.name_search("a".into(), 1000, cancellation).is_err());
    }

    #[test]
    fn directory_live_and_search_results_stamp_subject_request_and_credit() {
        let (engine, home) = fake_engine();
        scan_fs(&engine);
        let root = engine.selected_root();
        let first = engine.dir_children_page(root.clone(), 0, 2).unwrap();
        let second = engine.dir_children_page(root.clone(), 0, 2).unwrap();
        assert_eq!(first.subject_path, root);
        assert_eq!(first.metadata.run_id, engine.session_metadata().run_id);
        assert_ne!(first.request_id, second.request_id);
        assert!(first.request_id > 0);
        assert!(first.metadata.query_memory.is_some());
        let query = " a ";
        let search = engine
            .name_search(query.into(), 10, QueryCancellation::new())
            .unwrap();
        assert_eq!(search.query, query);
        assert!(search.request_id > 0);
        assert!(search.metadata.query_memory.is_some());
        std::fs::write(home.path().join("live-fixture"), "live").unwrap();
        let live = engine.live_files_page(root.clone(), 2).unwrap();
        assert_eq!(live.subject_path, root);
        assert!(live.request_id > 0);
        assert_eq!(live.metadata.run_id, first.metadata.run_id);
        assert!(live.metadata.query_memory.is_some());
        assert!(live
            .files
            .iter()
            .any(|file| file.path.ends_with("live-fixture")));
    }

    #[test]
    fn name_search_finds_live_files_and_relative_paths_without_changing_scan_totals() {
        let (engine, home) = fake_engine();
        scan_fs(&engine);
        let before = engine.dir_root().unwrap();
        let folder = home.path().join("projects/demo");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("Report.csv"), "fixture").unwrap();
        for query in ["REPORT.CSV", "projects/demo"] {
            let page = engine
                .name_search(query.into(), 1000, QueryCancellation::new())
                .unwrap();
            assert!(page
                .files
                .iter()
                .any(|file| file.path.ends_with("projects/demo/Report.csv")));
            assert!(page.observed_at_ms > 0);
            assert_eq!(page.coverage, "complete");
        }
        let page = engine
            .name_search("Library/Caches".into(), 1000, QueryCancellation::new())
            .unwrap();
        assert!(!page.entries.is_empty());
        assert_eq!(engine.dir_root().unwrap(), before);
    }

    #[test]
    fn engine_query_admission_cancels_search_and_does_not_hold_run_gate() {
        let (engine, _home) = fake_engine();
        let _first = engine.shared.query_slots.acquire(None).unwrap();
        let _second = engine.shared.query_slots.acquire(None).unwrap();
        let cancellation = QueryCancellation::new();
        std::thread::scope(|scope| {
            let search_engine = engine.clone();
            let token = cancellation.clone();
            let search = scope.spawn(move || search_engine.name_search("a".into(), 1000, token));
            std::thread::sleep(Duration::from_millis(20));
            assert!(engine.shared.run_gate.try_lock().is_ok());
            let started = Instant::now();
            cancellation.cancel();
            assert!(
                matches!(search.join().unwrap(), Err(MacAuditError::Invalid(message)) if message.contains("admission"))
            );
            assert!(started.elapsed() < Duration::from_millis(250));
        });
    }

    #[test]
    fn planning_query_admission_does_not_hold_run_gate() {
        let (engine, _home) = fake_engine();
        let first = engine.shared.query_slots.acquire(None).unwrap();
        let second = engine.shared.query_slots.acquire(None).unwrap();
        std::thread::scope(|scope| {
            let planning_engine = engine.clone();
            let planning = scope.spawn(move || {
                planning_engine.plan(vec![Selection {
                    finding_id: 0,
                    remedy_index: None,
                }])
            });
            std::thread::sleep(Duration::from_millis(20));
            assert!(engine.shared.run_gate.try_lock().is_ok());
            drop(first);
            drop(second);
            assert!(matches!(
                planning.join().unwrap(),
                Err(MacAuditError::Invalid(_))
            ));
        });
    }

    #[test]
    fn cached_page_keeps_credit_after_cache_eviction_until_foreign_result_drops() {
        let (engine, _home) = fake_engine();
        let budget = MemoryBudget::new(8192);
        *engine.shared.queries.lock().unwrap() = QueryRegistry::new(0, budget.clone());
        let memory = budget.reserve(2048).unwrap();
        let tree = macaudit::fake::dir_tree();
        let row = directory_entry(
            tree.node.find(&tree.root, &tree.root).unwrap(),
            tree.root.clone(),
        )
        .unwrap();
        let handle = engine
            .shared
            .queries
            .lock()
            .unwrap()
            .insert(123, 0, Coverage::Complete, vec![row], memory)
            .unwrap();
        let result = engine
            .directory_query_page(
                DirectoryCursor {
                    handle,
                    run_id: 0,
                    revision: 0,
                    offset: 0,
                    unsupported_paths: 0,
                },
                1,
            )
            .unwrap();
        let retained = result.metadata.clone();
        engine.shared.queries.lock().unwrap().clear();
        assert!(budget.used() > 0);
        drop(result);
        assert!(budget.used() > 0);
        drop(retained);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn memory_pressure_evicts_query_cache_and_expires_handles() {
        let (engine, _home) = fake_engine();
        let budget = MemoryBudget::new(8192);
        *engine.shared.queries.lock().unwrap() = QueryRegistry::new(0, budget.clone());
        budget.register_reclaimer(engine.shared.query_reclaimer.get().unwrap());
        let memory = budget.reserve(2048).unwrap();
        let tree = macaudit::fake::dir_tree();
        let row = directory_entry(
            tree.node.find(&tree.root, &tree.root).unwrap(),
            tree.root.clone(),
        )
        .unwrap();
        let handle = engine
            .shared
            .queries
            .lock()
            .unwrap()
            .insert(1, 0, Coverage::Complete, vec![row.clone()], memory)
            .unwrap();
        let cursor = DirectoryCursor {
            handle,
            run_id: 0,
            revision: 0,
            offset: 0,
            unsupported_paths: 0,
        };
        assert!(budget.used() > 0);
        let inventory_memory = budget.reserve(budget.limit()).unwrap();
        assert_eq!(budget.used(), budget.limit());
        assert!(engine.directory_query_page(cursor.clone(), 500).is_err());
        drop(inventory_memory);
        let memory = budget.reserve(2048).unwrap();
        let replacement = engine
            .shared
            .queries
            .lock()
            .unwrap()
            .insert(2, 0, Coverage::Complete, vec![row], memory)
            .unwrap();
        assert_ne!(handle, replacement);
        assert!(engine.directory_query_page(cursor, 500).is_err());
    }

    #[test]
    fn memory_pressure_skips_a_locked_query_cache_without_deadlock() {
        let (engine, _home) = fake_engine();
        let budget = MemoryBudget::new(8192);
        *engine.shared.queries.lock().unwrap() = QueryRegistry::new(0, budget.clone());
        budget.register_reclaimer(engine.shared.query_reclaimer.get().unwrap());
        let memory = budget.reserve(2048).unwrap();
        let tree = macaudit::fake::dir_tree();
        let row = directory_entry(
            tree.node.find(&tree.root, &tree.root).unwrap(),
            tree.root.clone(),
        )
        .unwrap();
        let mut queries = engine.shared.queries.lock().unwrap();
        let handle = queries
            .insert(1, 0, Coverage::Complete, vec![row], memory)
            .unwrap();
        let used = budget.used();
        let started = Instant::now();
        assert!(budget.reserve(budget.limit()).is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(budget.used(), used);
        drop(queries);
        assert!(engine
            .directory_query_page(
                DirectoryCursor {
                    handle,
                    run_id: 0,
                    revision: 0,
                    offset: 0,
                    unsupported_paths: 0,
                },
                500,
            )
            .is_ok());
    }

    #[test]
    fn finding_backlogs_do_not_starve_inventory_invalidation() {
        let (engine, _home) = fake_engine();
        let collector = Arc::new(Collector(Mutex::new(Vec::new())));
        *engine.shared.listener.lock().unwrap() = Some(collector.clone());
        let tree = Arc::new(macaudit::fake::dir_tree());
        {
            let mut session = engine.shared.session.lock().unwrap();
            session.begin_scan(77, ScannerId::ALL);
            let template = macaudit::fake::fixtures(ScannerId::Apps).remove(0);
            for index in 0..1000 {
                let mut finding = template.clone();
                finding.id = FindingId(index);
                session.apply(&macaudit::model::ScanEvent::Finding {
                    scanner: ScannerId::Apps,
                    gen: 77,
                    finding: Box::new(finding),
                });
            }
            session.apply(&macaudit::model::ScanEvent::DirTree {
                scanner: ScannerId::Fs,
                gen: 77,
                tree,
            });
        }
        let _ = engine.shared.publish.try_send(());
        let started = Instant::now();
        loop {
            let events = collector.0.lock().unwrap();
            if let Some(position) = events.iter().position(|event| matches!(event,
                ScanEvent::Findings { section: SectionId::Fs, gen: 77, findings } if findings.is_empty())) {
                let published: usize = events[..position].iter().map(|event| match event {
                    ScanEvent::Findings { findings, .. } => findings.len(),
                    _ => 0,
                }).sum();
                assert!(published <= 200);
                break;
            }
            drop(events);
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn publication_ticks_during_continuous_progress() {
        let (engine, _home) = fake_engine();
        let collector = Arc::new(Collector(Mutex::new(Vec::new())));
        *engine.shared.listener.lock().unwrap() = Some(collector.clone());
        engine
            .shared
            .session
            .lock()
            .unwrap()
            .begin_scan(77, ScannerId::ALL);
        let producer_stop = CancellationToken::new();
        let token = producer_stop.clone();
        let tx = engine.shared.tx.clone();
        runtime().spawn(async move {
            let finding = macaudit::fake::fixtures(ScannerId::Apps)
                .into_iter()
                .next()
                .unwrap();
            tx.send(macaudit::model::ScanEvent::Finding {
                scanner: ScannerId::Apps,
                gen: 77,
                finding: Box::new(finding),
            })
            .await
            .unwrap();
            while !token.is_cancelled() {
                tx.send(macaudit::model::ScanEvent::Progress {
                    scanner: ScannerId::Apps,
                    gen: 77,
                    msg: "busy".into(),
                    done: 0,
                    total: None,
                })
                .await
                .unwrap();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        let started = Instant::now();
        while !collector
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, ScanEvent::Findings { .. }))
        {
            assert!(
                started.elapsed() < Duration::from_millis(600),
                "continuous progress starved publication"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        producer_stop.cancel();
    }

    #[test]
    fn partial_inventory_publishes_invalidation_before_terminal() {
        let (engine, _home) = fake_engine();
        let collector = Arc::new(Collector(Mutex::new(Vec::new())));
        *engine.shared.listener.lock().unwrap() = Some(collector.clone());
        engine
            .shared
            .session
            .lock()
            .unwrap()
            .begin_scan(77, ScannerId::ALL);
        let mut tree = macaudit::fake::dir_tree();
        tree.complete = false;
        let root = tree.root.clone();
        engine
            .shared
            .tx
            .blocking_send(macaudit::model::ScanEvent::DirTree {
                scanner: ScannerId::Fs,
                gen: 77,
                tree: Arc::new(tree),
            })
            .unwrap();
        let started = Instant::now();
        while !collector.0.lock().unwrap().iter().any(|event| matches!(event,
            ScanEvent::Findings { section: SectionId::Fs, gen: 77, findings } if findings.is_empty())) {
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(collector.terminal_count(), 0);
        assert!(!engine.dir_tree_stats().unwrap().complete);
        assert!(engine
            .dir_entry(
                root.join("not-in-projection")
                    .to_string_lossy()
                    .into_owned()
            )
            .is_none());
        let cursor = engine
            .open_name_query("a".into(), 1000, QueryCancellation::new())
            .unwrap();
        let replacement = macaudit::fake::dir_tree();
        engine
            .shared
            .tx
            .blocking_send(macaudit::model::ScanEvent::DirTree {
                scanner: ScannerId::Fs,
                gen: 77,
                tree: Arc::new(replacement),
            })
            .unwrap();
        while engine.session_metadata().revision == cursor.revision {
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(engine.directory_query_page(cursor, 500).is_err());
    }

    #[test]
    fn blocked_callback_does_not_block_canonical_reduction() {
        struct BlockingListener {
            entered: std::sync::atomic::AtomicBool,
            release: (Mutex<bool>, std::sync::Condvar),
        }
        impl ScanListener for BlockingListener {
            fn on_event(&self, _: ScanEvent) {
                self.entered
                    .store(true, std::sync::atomic::Ordering::Release);
                let (lock, wake) = &self.release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = wake.wait(released).unwrap();
                }
            }
        }
        let (engine, _home) = fake_engine();
        let listener = Arc::new(BlockingListener {
            entered: std::sync::atomic::AtomicBool::new(false),
            release: (Mutex::new(false), std::sync::Condvar::new()),
        });
        *engine.shared.listener.lock().unwrap() = Some(listener.clone());
        engine
            .shared
            .session
            .lock()
            .unwrap()
            .begin_scan(88, ScannerId::ALL);
        let _ = engine.shared.publish.try_send(());
        let deadline = Instant::now() + Duration::from_secs(2);
        while !listener.entered.load(std::sync::atomic::Ordering::Acquire) {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        let finding = macaudit::fake::fixtures(ScannerId::Apps)
            .into_iter()
            .next()
            .unwrap();
        runtime()
            .block_on(engine.shared.tx.send(macaudit::model::ScanEvent::Finding {
                scanner: ScannerId::Apps,
                gen: 88,
                finding: Box::new(finding),
            }))
            .unwrap();
        while engine.findings(SectionId::Apps).is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let reduced = !engine.findings(SectionId::Apps).is_empty();
        *listener.release.0.lock().unwrap() = true;
        listener.release.1.notify_all();
        assert!(reduced, "a foreign callback blocked findings storage");
    }
}
