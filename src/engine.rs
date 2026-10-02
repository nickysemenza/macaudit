//! One validated root, one run identity, and one cancellation boundary.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::attribution::bus::ScanBus;
use crate::attribution::model::{FootprintEntry, FootprintSet};
use crate::attribution::{AppStorageScanner, ProjectsScanner};
use crate::config::{Config, Paths};
use crate::fake::FakeScanner;
use crate::inventory::{serialized_size, InventoryError, MemoryBudget, Reservation};
use crate::model::{Finding, FindingId, FindingKind, Guard, RemedyCommand, ScanEvent, ScannerId};
use crate::net::HttpFetcher;
use crate::registry;
use crate::runner::{BoundedCommandRunner, CmdOutput, CommandRunner};
use crate::scan::pipe::repo_channel;
use crate::scan::walk::WalkCoverage;
use crate::scan::{ScanCtx, Scanner};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Real,
    Fake,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RunId(pub u64);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RunOptions {
    pub offline: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRequest {
    pub selected_root: PathBuf,
    #[serde(default)]
    pub options: RunOptions,
}

impl RunRequest {
    pub fn new(selected_root: impl Into<PathBuf>) -> Self {
        Self {
            selected_root: selected_root.into(),
            options: RunOptions::default(),
        }
    }

    pub fn resolve_root(input: &Path, home: &Path, cwd: &Path) -> anyhow::Result<PathBuf> {
        use anyhow::Context;
        anyhow::ensure!(!input.as_os_str().is_empty(), "root must not be empty");
        let input_text = input.to_str().context("root must be valid UTF-8")?;
        let expanded = if input_text == "~" {
            home.to_path_buf()
        } else if let Some(suffix) = input_text.strip_prefix("~/") {
            home.join(suffix)
        } else {
            anyhow::ensure!(
                !input_text.starts_with('~'),
                "unsupported home expression: {input_text}"
            );
            cwd.join(input)
        };
        let _materialization = crate::scan::walk::listing::MaterializationGuard::enter()
            .context("cannot disable filesystem materialization for root validation")?;
        let root = expanded
            .canonicalize()
            .with_context(|| format!("invalid root {}", expanded.display()))?;
        anyhow::ensure!(root.is_dir(), "root is not a directory: {}", root.display());
        anyhow::ensure!(root.to_str().is_some(), "root must be valid UTF-8");
        std::fs::read_dir(&root)
            .with_context(|| format!("root is not readable: {}", root.display()))?;
        Ok(root)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RunContext {
    Disk { selected_root: PathBuf },
    AuditHost { home: PathBuf },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Pending,
    Running,
    Complete,
    Partial,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum RunStopReason {
    Unreadable,
    Excluded,
    Dataless,
    Aliases,
    Mounts,
    Cancelled,
    ResourceLimited,
    SummariesTruncated,
    Deadline,
    EntryLimit,
    ScannerFailed { scanner: ScannerId },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContextMetadata {
    pub context: RunContext,
    pub completeness: Completeness,
    pub completed_sections: Vec<ScannerId>,
    pub failed_sections: Vec<ScannerId>,
    pub coverage: Option<WalkCoverage>,
    pub stop_reasons: Vec<RunStopReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<DiscoveryMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryMetadata {
    pub completeness: Completeness,
    pub coverage: Option<WalkCoverage>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunMetadata {
    pub run_id: RunId,
    pub request: RunRequest,
    pub disk: ContextMetadata,
    pub audit_host: ContextMetadata,
    pub active_scanners: usize,
    pub retiring_count: usize,
    pub retiring_runs: Vec<RetiringRun>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetiringRun {
    pub run_id: RunId,
    pub active_scanners: usize,
}

struct WorkerGuard {
    run_id: RunId,
    workers: Arc<Mutex<BTreeMap<RunId, usize>>>,
    memory: Option<Arc<Reservation>>,
}

impl WorkerGuard {
    fn new(run_id: RunId, workers: Arc<Mutex<BTreeMap<RunId, usize>>>) -> Self {
        *workers.lock().unwrap().entry(run_id).or_default() += 1;
        Self {
            run_id,
            workers,
            memory: None,
        }
    }

    fn with_memory(mut self, memory: Arc<Reservation>) -> Self {
        self.memory = Some(memory);
        self
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        let mut workers = self.workers.lock().unwrap();
        if let Some(count) = workers.get_mut(&self.run_id) {
            *count -= 1;
            if *count == 0 {
                workers.remove(&self.run_id);
            }
        }
        let remaining_workers = workers.get(&self.run_id).copied().unwrap_or_default();
        drop(workers);
        tracing::debug!(
            run_id = self.run_id.0,
            remaining_workers,
            "scanner worker retired"
        );
    }
}

struct ActiveRun {
    metadata: RunMetadata,
    failures: Vec<(ScannerId, String)>,
    token: CancellationToken,
    disk_partial: bool,
    audit_partial: bool,
    discovery_separate: bool,
    primary_fs_terminal: Option<bool>,
    discovery_terminal: Option<bool>,
    discovery_partial: bool,
    paths: Arc<Paths>,
    memory: Arc<Reservation>,
}

struct RunCommandRunner {
    inner: Arc<dyn CommandRunner>,
    active: Arc<Mutex<Option<ActiveRun>>>,
    bus: Arc<ScanBus>,
    tx: mpsc::Sender<ScanEvent>,
    run_id: RunId,
    scanner: ScannerId,
}

#[async_trait::async_trait]
impl CommandRunner for RunCommandRunner {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        token: &CancellationToken,
    ) -> anyhow::Result<CmdOutput> {
        let result = self
            .inner
            .run(program, args, token)
            .instrument(tracing::debug_span!(
                "scanner_subprocess",
                run_id = self.run_id.0,
                scanner = ?self.scanner
            ))
            .await;
        if result
            .as_ref()
            .err()
            .is_some_and(crate::runner::is_resource_limit)
        {
            {
                let mut active = self.active.lock().unwrap();
                if let Some(run) = active
                    .as_mut()
                    .filter(|run| run.metadata.run_id == self.run_id)
                {
                    mark_resource_limited(run, self.scanner);
                    self.bus.cancel_generation(self.run_id.0);
                }
            }
            token.cancel();
            let _ = self
                .tx
                .send(ScanEvent::Failed {
                    scanner: self.scanner,
                    gen: self.run_id.0,
                    error: "resource limit: subprocess output budget exhausted".to_string(),
                })
                .await;
        }
        result
    }
}

pub struct ScannerManager {
    config: Arc<Config>,
    paths: Arc<Paths>,
    runner: Arc<dyn CommandRunner>,
    mode: Mode,
    gen: AtomicU64,
    active: Arc<Mutex<Option<ActiveRun>>>,
    workers: Arc<Mutex<BTreeMap<RunId, usize>>>,
    audit_slots: Arc<Semaphore>,
    fetcher: Option<Arc<dyn HttpFetcher>>,
    bus: Arc<ScanBus>,
    initial_request: RunRequest,
}

impl ScannerManager {
    pub fn new(
        config: Arc<Config>,
        paths: Arc<Paths>,
        runner: Arc<dyn CommandRunner>,
        mode: Mode,
    ) -> Self {
        let initial_request = RunRequest::new(paths.home.clone());
        Self {
            config,
            paths,
            runner: Arc::new(BoundedCommandRunner::new(runner)),
            mode,
            gen: AtomicU64::new(0),
            active: Arc::new(Mutex::new(None)),
            workers: Arc::new(Mutex::new(BTreeMap::new())),
            audit_slots: Arc::new(Semaphore::new(2)),
            fetcher: None,
            bus: ScanBus::new(),
            initial_request,
        }
    }

    pub fn with_request(mut self, mut request: RunRequest) -> anyhow::Result<Self> {
        request.selected_root = RunRequest::resolve_root(
            &request.selected_root,
            &self.paths.home,
            &std::env::current_dir()?,
        )?;
        self.initial_request = request;
        Ok(self)
    }

    pub fn request(&self) -> RunRequest {
        self.current_run()
            .map(|run| run.request)
            .unwrap_or_else(|| self.initial_request.clone())
    }

    pub fn current_generation(&self) -> u64 {
        self.gen.load(Ordering::SeqCst)
    }

    pub fn is_fake(&self) -> bool {
        self.mode == Mode::Fake
    }
    pub fn current_run(&self) -> Option<RunMetadata> {
        let active = self.active.lock().unwrap();
        let run = active.as_ref()?;
        let workers = self.workers.lock().unwrap();
        let mut metadata = run.metadata.clone();
        metadata.active_scanners = workers.get(&metadata.run_id).copied().unwrap_or_default();
        metadata.retiring_runs = workers
            .iter()
            .filter(|(id, _)| **id != metadata.run_id || run.token.is_cancelled())
            .map(|(run_id, active_scanners)| RetiringRun {
                run_id: *run_id,
                active_scanners: *active_scanners,
            })
            .collect();
        metadata.retiring_count = metadata
            .retiring_runs
            .iter()
            .map(|run| run.active_scanners)
            .sum();
        Some(metadata)
    }
    pub fn run_token(&self) -> Option<CancellationToken> {
        self.active
            .lock()
            .unwrap()
            .as_ref()
            .map(|run| run.token.clone())
    }
    pub fn run_paths(&self) -> Option<Arc<Paths>> {
        self.active
            .lock()
            .unwrap()
            .as_ref()
            .map(|run| run.paths.clone())
    }
    pub fn delete_mode(&self) -> crate::config::DeleteMode {
        self.config.behavior.delete_mode
    }
    pub fn runner(&self) -> Arc<dyn CommandRunner> {
        self.runner.clone()
    }
    pub fn paths(&self) -> Arc<Paths> {
        self.paths.clone()
    }
    pub fn config(&self) -> Arc<Config> {
        self.config.clone()
    }
    pub fn with_fetcher(mut self, fetcher: Arc<dyn HttpFetcher>) -> Self {
        self.fetcher = Some(fetcher);
        self
    }
    pub fn fetcher(&self) -> Option<Arc<dyn HttpFetcher>> {
        self.fetcher.clone()
    }
    pub fn cancel(&self) {
        let mut active = self.active.lock().unwrap();
        if let Some(run) = active.as_mut() {
            let active_scanners = self
                .workers
                .lock()
                .unwrap()
                .get(&run.metadata.run_id)
                .copied()
                .unwrap_or_default();
            tracing::info!(
                run_id = run.metadata.run_id.0,
                active_scanners,
                retiring_count = active_scanners,
                "run cancellation requested; workers may still be retiring"
            );
            run.token.cancel();
            for context in [&mut run.metadata.disk, &mut run.metadata.audit_host] {
                if matches!(
                    context.completeness,
                    Completeness::Pending | Completeness::Running
                ) {
                    context.completeness = Completeness::Cancelled;
                    add_reason(context, RunStopReason::Cancelled);
                    if let Some(coverage) = context.coverage.as_mut() {
                        coverage.cancelled = true;
                    }
                }
                if let Some(discovery) = context.discovery.as_mut() {
                    if discovery.completeness == Completeness::Running {
                        discovery.completeness = Completeness::Cancelled;
                        if let Some(coverage) = discovery.coverage.as_mut() {
                            coverage.cancelled = true;
                        }
                    }
                }
            }
            self.bus.cancel_generation(run.metadata.run_id.0);
        }
    }

    pub fn resource_limited(&self, run_id: RunId, scanner: ScannerId) {
        let mut active = self.active.lock().unwrap();
        if let Some(run) = active.as_mut().filter(|run| run.metadata.run_id == run_id) {
            mark_resource_limited(run, scanner);
            self.bus.cancel_generation(run_id.0);
        }
    }

    fn finding_resource_limited(&self, run_id: RunId, scanner: ScannerId, finding: &Finding) {
        let mut active = self.active.lock().unwrap();
        if let Some(run) = active.as_mut().filter(|run| run.metadata.run_id == run_id) {
            let host = matches!(
                context_of_finding(
                    finding,
                    &run.metadata.request.selected_root,
                    &run.paths.home
                ),
                RunContext::AuditHost { .. }
            );
            mark_context_resource_limited(run, scanner, host);
            self.bus.cancel_generation(run_id.0);
        }
    }

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

    fn audit_admission(&self, scanner: ScannerId, discovery_only: bool) -> Option<Arc<Semaphore>> {
        (self.mode == Mode::Real
            && (discovery_only
                || !matches!(
                    scanner,
                    ScannerId::Fs | ScannerId::Git | ScannerId::Projects | ScannerId::AppStorage
                )))
        .then(|| self.audit_slots.clone())
    }

    pub fn start_run(
        &self,
        tx: &mpsc::Sender<ScanEvent>,
        mut request: RunRequest,
    ) -> anyhow::Result<RunId> {
        request.selected_root = RunRequest::resolve_root(
            &request.selected_root,
            &self.paths.home,
            &std::env::current_dir()?,
        )?;
        let memory = Arc::new(run_reservation(
            &request,
            &self.config,
            &MemoryBudget::shared(),
        )?);
        let home_is_selected = crate::scan::walk::listing::MaterializationGuard::enter()
            .ok()
            .is_some_and(|_guard| {
                self.paths.home.canonicalize().ok().as_ref() == Some(&request.selected_root)
            });
        let mut active = self.active.lock().unwrap();
        if let Some(previous) = active.as_ref() {
            tracing::debug!(
                run_id = previous.metadata.run_id.0,
                active_scanners = self
                    .workers
                    .lock()
                    .unwrap()
                    .get(&previous.metadata.run_id)
                    .copied()
                    .unwrap_or_default(),
                "superseded run cancellation requested"
            );
            previous.token.cancel();
        }
        let run_id = RunId(self.gen.fetch_add(1, Ordering::SeqCst) + 1);
        let token = CancellationToken::new();
        let paths = Arc::new(self.paths.with_fresh_measurements());
        let context = |context| ContextMetadata {
            discovery: matches!(&context, RunContext::AuditHost { .. }).then_some(
                DiscoveryMetadata {
                    completeness: Completeness::Running,
                    coverage: None,
                    error: None,
                },
            ),
            context,
            completeness: Completeness::Running,
            completed_sections: Vec::new(),
            failed_sections: Vec::new(),
            coverage: None,
            stop_reasons: Vec::new(),
        };
        *active = Some(ActiveRun {
            metadata: RunMetadata {
                run_id,
                request: request.clone(),
                disk: context(RunContext::Disk {
                    selected_root: request.selected_root.clone(),
                }),
                audit_host: context(RunContext::AuditHost {
                    home: self.paths.home.clone(),
                }),
                active_scanners: 0,
                retiring_count: 0,
                retiring_runs: Vec::new(),
            },
            token: token.clone(),
            failures: Vec::new(),
            disk_partial: false,
            audit_partial: false,
            discovery_separate: !home_is_selected && self.mode == Mode::Real,
            primary_fs_terminal: None,
            discovery_terminal: None,
            discovery_partial: false,
            paths: paths.clone(),
            memory: memory.clone(),
        });
        let registrations: Vec<_> = registry::REGISTRY
            .iter()
            .map(|section| (section.id, token.clone()))
            .collect();
        self.bus.begin(run_id.0, &registrations);
        drop(active);
        self.spawn_set(tx, run_id, &request, token, paths, memory);
        tracing::info!(run_id = run_id.0, root = %request.selected_root.display(), "run started");
        Ok(run_id)
    }

    fn spawn_set(
        &self,
        tx: &mpsc::Sender<ScanEvent>,
        run_id: RunId,
        request: &RunRequest,
        token: CancellationToken,
        paths: Arc<Paths>,
        memory: Arc<Reservation>,
    ) {
        let (repo_tx, repo_rx) = repo_channel();
        let repo_rx = Arc::new(tokio::sync::Mutex::new(repo_rx));
        let (internal_tx, mut internal_rx) = mpsc::channel::<ScanEvent>(32);
        let discovery_separate = self
            .active
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|run| run.metadata.run_id == run_id && run.discovery_separate);
        let mut host_config = (*self.config).clone();
        host_config.scan.roots = vec![self.paths.home.to_string_lossy().into_owned()];
        host_config.network.offline |= request.options.offline;
        let mut disk_config = host_config.clone();
        disk_config.scan.roots = vec![request.selected_root.to_string_lossy().into_owned()];
        let host_config = Arc::new(host_config);
        let disk_config = Arc::new(disk_config);
        let disk_started = CancellationToken::new();
        let base = ScanCtx {
            tx: internal_tx.clone(),
            token: token.clone(),
            gen: run_id.0,
            config: host_config,
            paths,
            runner: self.runner.clone(),
            current: ScannerId::Apps,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        let sections = std::iter::once(registry::section(ScannerId::Fs)).chain(
            registry::REGISTRY
                .iter()
                .filter(|section| section.id != ScannerId::Fs),
        );
        for section in sections {
            let mut ctx = base.clone().with_current(section.id);
            ctx.runner = Arc::new(RunCommandRunner {
                inner: self.runner.clone(),
                active: self.active.clone(),
                bus: self.bus.clone(),
                tx: internal_tx.clone(),
                run_id,
                scanner: section.id,
            });
            match section.id {
                ScannerId::Fs => {
                    ctx.config = disk_config.clone();
                    if !discovery_separate {
                        ctx.repo_tx = Some(repo_tx.clone());
                    }
                }
                ScannerId::Git => {
                    ctx.repo_rx = Some(repo_rx.clone());
                }
                _ => {}
            }
            spawn_one(
                self.build_scanner(section.id),
                ctx,
                internal_tx.clone(),
                WorkerGuard::new(run_id, self.workers.clone()).with_memory(memory.clone()),
                self.audit_admission(section.id, false),
                Some(disk_started.clone()),
            );
        }
        if discovery_separate {
            let (discovery_tx, mut discovery_rx) = mpsc::channel(1);
            let mut ctx = base.with_current(ScannerId::Fs);
            ctx.tx = discovery_tx.clone();
            ctx.repo_tx = Some(repo_tx.clone());
            ctx.fs_discovery_only = true;
            spawn_one(
                self.build_scanner(ScannerId::Fs),
                ctx,
                discovery_tx.clone(),
                WorkerGuard::new(run_id, self.workers.clone()).with_memory(memory.clone()),
                self.audit_admission(ScannerId::Fs, true),
                Some(disk_started.clone()),
            );
            drop(discovery_tx);
            let active = self.active.clone();
            let bus = self.bus.clone();
            let external_tx = tx.clone();
            let discovery_token = token.clone();
            let discovery_memory = memory.clone();
            tokio::spawn(async move {
                let _memory = discovery_memory;
                while let Some(event) = discovery_rx.recv().await {
                    let diagnostic = {
                        let mut current = active.lock().unwrap();
                        let Some(run) =
                            current.as_mut().filter(|run| run.metadata.run_id == run_id)
                        else {
                            continue;
                        };
                        observe_discovery(run, &event)
                    };
                    if discovery_token.is_cancelled() {
                        bus.cancel_generation(run_id.0);
                    }
                    if let Some(diagnostic) = diagnostic {
                        publish_run_event(&external_tx, diagnostic, &discovery_token, run_id, &bus)
                            .await;
                    }
                }
                let diagnostic = {
                    let mut current = active.lock().unwrap();
                    current
                        .as_mut()
                        .filter(|run| {
                            run.metadata.run_id == run_id && run.discovery_terminal.is_none()
                        })
                        .and_then(|run| {
                            let error = if discovery_token.is_cancelled() {
                                "run cancelled"
                            } else {
                                "Home discovery worker retired without terminal status"
                            };
                            observe_discovery(
                                run,
                                &ScanEvent::Failed {
                                    scanner: ScannerId::Fs,
                                    gen: run_id.0,
                                    error: error.into(),
                                },
                            )
                        })
                };
                if let Some(diagnostic) = diagnostic {
                    publish_run_event(&external_tx, diagnostic, &discovery_token, run_id, &bus)
                        .await;
                }
            });
        }
        drop(repo_tx);
        drop(repo_rx);
        drop(internal_tx);
        let bus = self.bus.clone();
        let active = self.active.clone();
        let external_tx = tx.clone();
        tokio::spawn(async move {
            let _memory = memory;
            while let Some(mut event) = internal_rx.recv().await {
                if let ScanEvent::Failed { error, .. } = &mut event {
                    *error = bounded_error(error.as_str());
                }
                {
                    let mut current = active.lock().unwrap();
                    if current.as_ref().map(|run| run.metadata.run_id) != Some(run_id) {
                        continue;
                    }
                    if let Some(run) = current.as_mut() {
                        if let ScanEvent::Finding { finding, .. } = &mut event {
                            let context = context_of_finding(
                                finding,
                                &run.metadata.request.selected_root,
                                &run.paths.home,
                            );
                            stamp_context(finding, &context);
                        }
                        if let ScanEvent::Failed { scanner, error, .. } = &event {
                            if error.contains("resource limit")
                                || error.contains("memory budget exhausted")
                            {
                                mark_resource_limited(run, *scanner);
                            }
                        }
                        observe_run(run, &event);
                    }
                    if bus.observe_checked(&event).is_err() {
                        if let Some(run) = current.as_mut() {
                            if let ScanEvent::Finding { finding, .. } = &event {
                                let host = matches!(
                                    context_of_finding(
                                        finding,
                                        &run.metadata.request.selected_root,
                                        &run.paths.home
                                    ),
                                    RunContext::AuditHost { .. }
                                );
                                mark_context_resource_limited(run, event.scanner(), host);
                            } else {
                                mark_resource_limited(run, event.scanner());
                            }
                        }
                        bus.cancel_generation(run_id.0);
                        event = ScanEvent::Failed {
                            scanner: event.scanner(),
                            gen: run_id.0,
                            error: "resource limit: finding storage budget exhausted".into(),
                        };
                    }
                }
                publish_run_event(&external_tx, event, &token, run_id, &bus).await;
            }
        });
    }

    pub fn start(&self, tx: &mpsc::Sender<ScanEvent>, _requested: &[ScannerId]) -> u64 {
        let request = self.request();
        self.start_run(tx, request)
            .map(|run_id| run_id.0)
            .unwrap_or_else(|_| self.current_generation())
    }

    pub async fn run_request_to_completion(
        &self,
        request: RunRequest,
    ) -> anyhow::Result<ScanOutcome> {
        let (tx, mut rx) = mpsc::channel::<ScanEvent>(32);
        let run_id = self.start_run(&tx, request)?;
        let (token, paths, memory) = {
            let active = self.active.lock().unwrap();
            let run = active
                .as_ref()
                .filter(|run| run.metadata.run_id == run_id)
                .ok_or_else(|| anyhow::anyhow!("run superseded before collection"))?;
            (run.token.clone(), run.paths.clone(), run.memory.clone())
        };
        drop(tx);
        let mut outcome = ScanOutcome {
            control_memory: Some(memory),
            ..ScanOutcome::default()
        };
        while let Some(event) = rx.recv().await {
            if event.generation() != run_id.0 {
                continue;
            }
            match event {
                ScanEvent::Finding {
                    scanner, finding, ..
                } => match finding_reservation(&finding, &MemoryBudget::shared()) {
                    Ok(memory) => {
                        let finding_id = finding.id;
                        outcome.findings.insert(finding.id, *finding);
                        outcome.memory.insert(finding_id, Arc::new(memory));
                    }
                    Err(error) => {
                        self.finding_resource_limited(run_id, scanner, &finding);
                        upsert_failure(&mut outcome, scanner, &bounded_error(error));
                    }
                },
                ScanEvent::DirTree { tree, .. } => {
                    upsert_tree(&mut outcome.dir_trees, tree);
                }
                ScanEvent::Footprints { scanner, set, .. } => {
                    let memory = footprint_reservation(&set, &MemoryBudget::shared());
                    match memory {
                        Ok(memory) => {
                            upsert_footprints(&mut outcome, set, memory);
                        }
                        Err(error) => {
                            self.resource_limited(run_id, scanner);
                            upsert_failure(&mut outcome, scanner, &bounded_error(error));
                        }
                    }
                }
                ScanEvent::Failed { scanner, error, .. } => {
                    upsert_failure(&mut outcome, scanner, &error);
                }
                _ => {}
            }
        }
        crate::correlate::correlate(&mut outcome.findings);
        if !token.is_cancelled() {
            let fetcher = if self
                .current_run()
                .is_some_and(|run| run.request.options.offline)
            {
                None
            } else {
                self.fetcher.clone()
            };
            crate::net::enrich(&mut outcome.findings, fetcher, &paths, &self.config, &token).await;
        }
        {
            let active = self.active.lock().unwrap();
            if let Some(run) = active.as_ref().filter(|run| run.metadata.run_id == run_id) {
                for (scanner, error) in &run.failures {
                    upsert_failure(&mut outcome, *scanner, error);
                }
            }
        }
        outcome.run = self.current_run().filter(|run| run.run_id == run_id);
        Ok(outcome)
    }

    pub async fn run_to_completion(&self, _requested: &[ScannerId]) -> ScanOutcome {
        let request = self.request();
        self.run_request_to_completion(request)
            .await
            .unwrap_or_else(|error| ScanOutcome {
                failures: vec![(ScannerId::Fs, bounded_error(error))],
                ..ScanOutcome::default()
            })
    }
}

fn observe_run(run: &mut ActiveRun, event: &ScanEvent) {
    if let ScanEvent::Failed { scanner, error, .. } = event {
        retain_failure(&mut run.failures, *scanner, error);
    }
    let scanner = event.scanner();
    match event {
        ScanEvent::Finding { finding, .. }
            if finding
                .meta
                .get("complete")
                .and_then(serde_json::Value::as_bool)
                == Some(false)
                && matches!(
                    context_of_finding(
                        finding,
                        &run.metadata.request.selected_root,
                        &run.paths.home
                    ),
                    RunContext::AuditHost { .. }
                ) =>
        {
            run.audit_partial = true;
        }
        ScanEvent::Footprints { set, .. } if !set.missing_deps.is_empty() => {
            run.audit_partial = true;
        }
        _ => {}
    }
    if let ScanEvent::DirTree { tree, .. } = event {
        run.disk_partial = !tree.complete || tree.errors > 0;
        let previous_reasons = run
            .metadata
            .disk
            .coverage
            .as_ref()
            .map(coverage_reasons)
            .unwrap_or_default();
        let mut coverage = tree.coverage.clone();
        coverage.cancelled |= run.token.is_cancelled();
        coverage.resource_limited |= run
            .metadata
            .disk
            .stop_reasons
            .contains(&RunStopReason::ResourceLimited);
        run.metadata.disk.stop_reasons.retain(|reason| {
            !previous_reasons.contains(reason)
                || matches!(
                    reason,
                    RunStopReason::Cancelled | RunStopReason::ResourceLimited
                )
        });
        let reasons = coverage_reasons(&coverage);
        run.metadata.disk.coverage = Some(coverage);
        for reason in reasons {
            add_reason(&mut run.metadata.disk, reason);
        }
        if !run.discovery_separate {
            run.discovery_partial = run.disk_partial;
            set_discovery_coverage(run, tree.coverage.clone());
        }
    }
    let terminal = match event {
        ScanEvent::Finished { .. } => Some(true),
        ScanEvent::Failed { .. } => Some(false),
        _ => None,
    };
    if scanner == ScannerId::Fs {
        if let Some(success) = terminal {
            run.primary_fs_terminal = Some(run.primary_fs_terminal.unwrap_or(true) && success);
            record_terminal(&mut run.metadata.disk, scanner, success);
            if !success && !run.token.is_cancelled() {
                add_reason(
                    &mut run.metadata.disk,
                    RunStopReason::ScannerFailed { scanner },
                );
            }
            if !run.discovery_separate {
                run.discovery_terminal = run.primary_fs_terminal;
                if let ScanEvent::Failed { error, .. } = event {
                    run.metadata.audit_host.discovery.as_mut().unwrap().error =
                        Some(bounded_error(error));
                }
                refresh_discovery(run);
            }
        }
        refresh_context(&mut run.metadata.disk, 1, run.disk_partial, &run.token);
    } else if let Some(success) = terminal {
        record_terminal(&mut run.metadata.audit_host, scanner, success);
        if !success && !run.token.is_cancelled() {
            add_reason(
                &mut run.metadata.audit_host,
                RunStopReason::ScannerFailed { scanner },
            );
        }
    }
    refresh_host(run);
}

fn record_terminal(context: &mut ContextMetadata, scanner: ScannerId, success: bool) {
    if !success {
        context
            .completed_sections
            .retain(|section| *section != scanner);
        if !context.failed_sections.contains(&scanner) {
            context.failed_sections.push(scanner);
        }
    } else if !context.failed_sections.contains(&scanner)
        && !context.completed_sections.contains(&scanner)
    {
        context.completed_sections.push(scanner);
    }
}

fn refresh_context(
    context: &mut ContextMetadata,
    expected: usize,
    partial: bool,
    token: &CancellationToken,
) {
    if token.is_cancelled() {
        if context.completeness == Completeness::Running {
            context.completeness = Completeness::Cancelled;
            add_reason(context, RunStopReason::Cancelled);
        }
    } else if context.completed_sections.len() + context.failed_sections.len() == expected {
        context.completeness = if !context.failed_sections.is_empty() {
            if context.completed_sections.is_empty() {
                Completeness::Failed
            } else {
                Completeness::Partial
            }
        } else if partial {
            Completeness::Partial
        } else {
            Completeness::Complete
        };
    }
}

fn refresh_host(run: &mut ActiveRun) {
    if let (Some(primary), Some(discovery)) = (run.primary_fs_terminal, run.discovery_terminal) {
        record_terminal(
            &mut run.metadata.audit_host,
            ScannerId::Fs,
            primary && discovery,
        );
        if !(run.token.is_cancelled() || primary && discovery) {
            add_reason(
                &mut run.metadata.audit_host,
                RunStopReason::ScannerFailed {
                    scanner: ScannerId::Fs,
                },
            );
        }
    }
    refresh_context(
        &mut run.metadata.audit_host,
        registry::REGISTRY.len(),
        run.audit_partial || run.discovery_partial,
        &run.token,
    );
}

fn set_discovery_coverage(run: &mut ActiveRun, mut coverage: WalkCoverage) {
    let context = &mut run.metadata.audit_host;
    let previous_reasons = context
        .coverage
        .as_ref()
        .map(coverage_reasons)
        .unwrap_or_default();
    coverage.cancelled |= run.token.is_cancelled();
    coverage.resource_limited |= context
        .stop_reasons
        .contains(&RunStopReason::ResourceLimited);
    context.stop_reasons.retain(|reason| {
        !previous_reasons.contains(reason)
            || matches!(
                reason,
                RunStopReason::Cancelled | RunStopReason::ResourceLimited
            )
    });
    for reason in coverage_reasons(&coverage) {
        add_reason(context, reason);
    }
    context.discovery.as_mut().unwrap().coverage = Some(coverage.clone());
    context.coverage = Some(coverage);
}

fn refresh_discovery(run: &mut ActiveRun) {
    let Some(success) = run.discovery_terminal else {
        if run.token.is_cancelled() {
            let discovery = run.metadata.audit_host.discovery.as_mut().unwrap();
            discovery.completeness = if discovery
                .coverage
                .as_ref()
                .is_some_and(|coverage| coverage.resource_limited)
            {
                Completeness::Partial
            } else {
                Completeness::Cancelled
            };
        }
        return;
    };
    let discovery = run.metadata.audit_host.discovery.as_mut().unwrap();
    discovery.completeness = if discovery
        .coverage
        .as_ref()
        .is_some_and(|coverage| coverage.resource_limited)
    {
        Completeness::Partial
    } else if run.token.is_cancelled() {
        Completeness::Cancelled
    } else if !success {
        Completeness::Failed
    } else if run.discovery_partial {
        Completeness::Partial
    } else {
        Completeness::Complete
    };
}

fn observe_discovery(run: &mut ActiveRun, event: &ScanEvent) -> Option<ScanEvent> {
    if event.generation() != run.metadata.run_id.0 {
        return None;
    }
    match event {
        ScanEvent::Finding { finding, .. }
            if finding
                .meta
                .get("host_discovery")
                .and_then(serde_json::Value::as_bool)
                == Some(true) =>
        {
            let coverage = finding
                .meta
                .get("walk_coverage")
                .and_then(|value| WalkCoverage::deserialize(value).ok());
            run.discovery_partial = finding
                .meta
                .get("complete")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
                || coverage.is_none();
            if let Some(coverage) = coverage {
                run.discovery_partial |= coverage.unreadable > 0
                    || coverage.cancelled
                    || coverage.resource_limited
                    || coverage.deadline
                    || coverage.entry_limit
                    || coverage.summaries_truncated;
                set_discovery_coverage(run, coverage);
            }
        }
        ScanEvent::Finished { .. } => {
            run.discovery_terminal = Some(run.discovery_terminal.unwrap_or(true));
            if run.metadata.audit_host.coverage.is_none() {
                run.discovery_partial = true;
                run.metadata.audit_host.discovery.as_mut().unwrap().error =
                    Some("Host discovery coverage unavailable".into());
            }
        }
        ScanEvent::Failed { error, .. } => {
            run.discovery_terminal = Some(false);
            run.discovery_partial = true;
            let discovery = run.metadata.audit_host.discovery.as_mut().unwrap();
            if error == "run cancelled"
                && discovery.error.is_none()
                && discovery
                    .coverage
                    .as_ref()
                    .is_some_and(|coverage| coverage.resource_limited)
            {
                discovery.error = Some("resource limit: Home discovery was incomplete".into());
            } else if !(error == "run cancelled"
                && discovery.error.as_ref().is_some_and(|previous| {
                    previous.contains("resource limit")
                        || previous.contains("memory budget exhausted")
                }))
            {
                discovery.error = Some(bounded_error(error));
            }
            if !run.token.is_cancelled() {
                add_reason(
                    &mut run.metadata.audit_host,
                    RunStopReason::ScannerFailed {
                        scanner: ScannerId::Fs,
                    },
                );
            }
            if error.contains("resource limit") || error.contains("memory budget exhausted") {
                let coverage = run
                    .metadata
                    .audit_host
                    .coverage
                    .get_or_insert_with(WalkCoverage::default);
                coverage.resource_limited = true;
            }
        }
        _ => return None,
    }
    if run
        .metadata
        .audit_host
        .coverage
        .as_ref()
        .is_some_and(|coverage| coverage.resource_limited)
    {
        run.token.cancel();
        run.metadata.audit_host.completeness = Completeness::Partial;
        add_reason(&mut run.metadata.audit_host, RunStopReason::ResourceLimited);
        let coverage = run.metadata.audit_host.coverage.clone().unwrap();
        set_discovery_coverage(run, coverage);
        refresh_context(&mut run.metadata.disk, 1, run.disk_partial, &run.token);
    }
    refresh_discovery(run);
    refresh_host(run);
    let discovery = run.metadata.audit_host.discovery.as_ref().unwrap();
    let detail = discovery.error.as_deref().unwrap_or_else(|| {
        if discovery
            .coverage
            .as_ref()
            .is_some_and(|coverage| coverage.resource_limited)
        {
            "Host discovery stopped at a resource limit; current disk results are retained"
        } else if run.token.is_cancelled() {
            "Host discovery cancelled; current partial results are retained"
        } else if run.discovery_partial {
            "Global Home discovery is partial; separate from selected-root disk inventory"
        } else {
            "Global Home discovery; separate from selected-root disk inventory"
        }
    });
    let mut finding = Finding::new(FindingKind::DiskCategory, "fs:host-discovery-coverage", "Host project discovery coverage")
        .detail(detail)
        .severity(if run.discovery_partial || run.token.is_cancelled() {
            crate::model::Severity::Warning
        } else {
            crate::model::Severity::Info
        })
        .meta(serde_json::json!({
            "context": "audit_host", "host_discovery": true,
            "complete": !run.discovery_partial && run.discovery_terminal != Some(false) && !run.token.is_cancelled(),
            "walk_coverage": discovery.coverage,
            "discovery_completeness": discovery.completeness,
            "error": discovery.error,
        }));
    stamp_context(&mut finding, &run.metadata.audit_host.context);
    Some(ScanEvent::Finding {
        scanner: ScannerId::Fs,
        gen: run.metadata.run_id.0,
        finding: Box::new(finding),
    })
}

fn mark_resource_limited(run: &mut ActiveRun, scanner: ScannerId) {
    mark_context_resource_limited(run, scanner, scanner != ScannerId::Fs);
}

fn mark_context_resource_limited(run: &mut ActiveRun, scanner: ScannerId, host: bool) {
    tracing::warn!(
        run_id = run.metadata.run_id.0,
        scanner = scanner.slug(),
        audit_host = host,
        "run resource limit reached"
    );
    run.token.cancel();
    retain_failure(
        &mut run.failures,
        scanner,
        "resource limit: operation exceeded the engine memory budget",
    );
    for context in [&mut run.metadata.disk, &mut run.metadata.audit_host] {
        if context.completeness == Completeness::Running {
            context.completeness = Completeness::Cancelled;
            add_reason(context, RunStopReason::Cancelled);
        }
        if let Some(discovery) = context.discovery.as_mut() {
            if discovery.completeness == Completeness::Running {
                discovery.completeness = Completeness::Cancelled;
                if let Some(coverage) = discovery.coverage.as_mut() {
                    coverage.cancelled = true;
                }
            }
        }
    }
    let context = if host {
        &mut run.metadata.audit_host
    } else {
        &mut run.metadata.disk
    };
    context.completeness = Completeness::Partial;
    add_reason(context, RunStopReason::ResourceLimited);
    if !host {
        context
            .coverage
            .get_or_insert_with(WalkCoverage::default)
            .resource_limited = true;
    }
}

pub fn context_of_finding(finding: &Finding, selected_root: &Path, home: &Path) -> RunContext {
    if finding
        .meta
        .get("context")
        .and_then(serde_json::Value::as_str)
        == Some("audit_host")
    {
        return RunContext::AuditHost {
            home: home.to_path_buf(),
        };
    }
    if let Some(context_type) = finding
        .meta
        .get("run_context")
        .and_then(|value| value.get("type"))
        .and_then(serde_json::Value::as_str)
    {
        match context_type {
            "disk" => {
                return RunContext::Disk {
                    selected_root: selected_root.to_path_buf(),
                }
            }
            "audit_host" => {
                return RunContext::AuditHost {
                    home: home.to_path_buf(),
                }
            }
            _ => {}
        }
    }
    if finding.kind.scanner() == ScannerId::Fs
        && !matches!(finding.kind, FindingKind::CacheDir | FindingKind::IosBackup)
    {
        RunContext::Disk {
            selected_root: selected_root.to_path_buf(),
        }
    } else {
        RunContext::AuditHost {
            home: home.to_path_buf(),
        }
    }
}

fn stamp_context(finding: &mut Finding, context: &RunContext) {
    if !finding.meta.is_object() {
        finding.meta = serde_json::json!({});
    }
    finding.meta["run_context"] = serde_json::to_value(context).unwrap();
}

pub fn finding_reservation(
    finding: &Finding,
    budget: &Arc<MemoryBudget>,
) -> Result<Reservation, crate::inventory::InventoryError> {
    budget.reserve(finding_storage_bytes(finding)?)
}

pub fn finding_storage_bytes(finding: &Finding) -> Result<usize, InventoryError> {
    let mut retained = AllocationSize(std::mem::size_of::<Finding>() + 512);
    retained.string(&finding.title);
    retained.string(&finding.detail);
    retained.optional_path(finding.path.as_ref());
    retained.optional_string(finding.provenance.as_ref());
    retained.optional_string(finding.coverage.as_ref());
    retained.vector(&finding.remedies);
    for remedy in &finding.remedies {
        retained.string(&remedy.label);
        match &remedy.command {
            RemedyCommand::Trash { path } | RemedyCommand::RevealInFinder { path } => {
                retained.path(path)
            }
            RemedyCommand::CopyToClipboard { text } => retained.string(text),
            RemedyCommand::Shell { program, args } | RemedyCommand::Probe { program, args, .. } => {
                retained.string(program);
                retained.strings(args);
            }
        }
        match &remedy.guard {
            Some(Guard::BrewFormula {
                full_name,
                expected_version,
                ..
            }) => {
                retained.string(full_name);
                retained.optional_string(expected_version.as_ref());
            }
            Some(Guard::BrewCask {
                token,
                expected_version,
            }) => {
                retained.string(token);
                retained.optional_string(expected_version.as_ref());
            }
            Some(Guard::ToolInstall {
                manager,
                identity_key,
                root,
                expected_version,
                program_must_exist,
            }) => {
                retained.string(manager);
                retained.string(identity_key);
                retained.path(root);
                retained.optional_string(expected_version.as_ref());
                retained.optional_path(program_must_exist.as_ref());
            }
            Some(Guard::Launcher {
                path,
                expected_target,
                owner_key,
                ..
            }) => {
                retained.path(path);
                retained.optional_path(expected_target.as_ref());
                retained.string(owner_key);
            }
            Some(Guard::PipPackage {
                site,
                name,
                interpreter,
            }) => {
                retained.path(site);
                retained.string(name);
                retained.path(interpreter);
            }
            None => {}
        }
    }
    retained.json(&finding.meta, 0)?;
    result_storage_bytes(finding, retained.0)
}

struct AllocationSize(usize);

impl AllocationSize {
    fn add(&mut self, bytes: usize) {
        self.0 = self.0.saturating_add(bytes);
    }
    fn string(&mut self, string: &String) {
        self.add(string.capacity());
    }
    fn path(&mut self, path: &PathBuf) {
        self.add(path.capacity());
    }
    fn optional_string(&mut self, string: Option<&String>) {
        if let Some(string) = string {
            self.string(string);
        }
    }
    fn optional_path(&mut self, path: Option<&PathBuf>) {
        if let Some(path) = path {
            self.path(path);
        }
    }
    fn vector<T>(&mut self, values: &Vec<T>) {
        self.add(values.capacity().saturating_mul(std::mem::size_of::<T>()));
    }
    fn strings(&mut self, strings: &Vec<String>) {
        self.vector(strings);
        for string in strings {
            self.string(string);
        }
    }
    fn json(&mut self, value: &serde_json::Value, depth: usize) -> Result<(), InventoryError> {
        if depth > 128 {
            return Err(InventoryError::ResourceLimit);
        }
        match value {
            serde_json::Value::String(string) => self.string(string),
            serde_json::Value::Array(values) => {
                self.vector(values);
                for value in values {
                    self.json(value, depth + 1)?;
                }
            }
            serde_json::Value::Object(values) => {
                self.add(
                    values
                        .len()
                        .saturating_mul(std::mem::size_of::<serde_json::Value>() + 1024),
                );
                for (key, value) in values {
                    self.string(key);
                    self.json(value, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn entry(&mut self, entry: &FootprintEntry) {
        self.path(&entry.path);
        self.strings(&entry.owners);
        self.string(&entry.evidence);
        self.string(&entry.label);
        self.optional_string(entry.reason.as_ref());
    }
    fn entries(&mut self, entries: &Vec<FootprintEntry>) {
        self.vector(entries);
        for entry in entries {
            self.entry(entry);
        }
    }
}

fn result_storage_bytes(value: &impl Serialize, retained: usize) -> Result<usize, InventoryError> {
    let serialized = serialized_size(value)?
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(512))
        .ok_or(InventoryError::ResourceLimit)?;
    let retained = retained
        .checked_mul(2)
        .ok_or(InventoryError::ResourceLimit)?;
    Ok(retained.max(serialized))
}

pub(crate) fn footprint_reservation(
    set: &FootprintSet,
    budget: &Arc<MemoryBudget>,
) -> Result<Reservation, InventoryError> {
    budget.reserve(footprint_storage_bytes(set)?)
}

pub fn footprint_storage_bytes(set: &FootprintSet) -> Result<usize, InventoryError> {
    let mut retained = AllocationSize(std::mem::size_of::<FootprintSet>() + 512);
    retained.vector(&set.footprints);
    retained.entries(&set.baseline);
    retained.entries(&set.unattributed);
    retained.vector(&set.missing_deps);
    for footprint in &set.footprints {
        retained.string(&footprint.owner.key);
        retained.string(&footprint.owner.name);
        retained.optional_path(footprint.owner.path.as_ref());
        retained.vector(&footprint.groups);
        for group in &footprint.groups {
            retained.entries(&group.entries);
        }
        retained.vector(&footprint.worktrees);
        for path in &footprint.worktrees {
            retained.path(path);
        }
        retained.vector(&footprint.processes);
        for process in &footprint.processes {
            retained.string(&process.name);
            retained.path(&process.cwd);
        }
        retained.vector(&footprint.ports);
    }
    result_storage_bytes(set, retained.0)
}

fn add_reason(context: &mut ContextMetadata, reason: RunStopReason) {
    if !context.stop_reasons.contains(&reason) {
        context.stop_reasons.push(reason);
    }
}

fn coverage_reasons(coverage: &WalkCoverage) -> Vec<RunStopReason> {
    let mut reasons = Vec::new();
    for (present, reason) in [
        (coverage.unreadable > 0, RunStopReason::Unreadable),
        (coverage.excluded > 0, RunStopReason::Excluded),
        (coverage.dataless > 0, RunStopReason::Dataless),
        (coverage.aliases > 0, RunStopReason::Aliases),
        (coverage.mounts > 0, RunStopReason::Mounts),
        (coverage.cancelled, RunStopReason::Cancelled),
        (coverage.resource_limited, RunStopReason::ResourceLimited),
        (
            coverage.summaries_truncated,
            RunStopReason::SummariesTruncated,
        ),
        (coverage.deadline, RunStopReason::Deadline),
        (coverage.entry_limit, RunStopReason::EntryLimit),
    ] {
        if present {
            reasons.push(reason);
        }
    }
    reasons
}

#[derive(Default)]
pub struct ScanOutcome {
    pub run: Option<RunMetadata>,
    pub findings: BTreeMap<FindingId, Finding>,
    pub failures: Vec<(ScannerId, String)>,
    pub dir_trees: Vec<Arc<crate::scan::walk::DirTree>>,
    pub footprints: Vec<Arc<FootprintSet>>,
    pub memory: BTreeMap<FindingId, Arc<Reservation>>,
    pub footprint_memory: Vec<Arc<Reservation>>,
    pub control_memory: Option<Arc<Reservation>>,
}

fn run_reservation(
    request: &RunRequest,
    config: &Config,
    budget: &Arc<MemoryBudget>,
) -> Result<Reservation, InventoryError> {
    let bytes = serialized_size(config)?
        .checked_mul(32)
        .and_then(|bytes| bytes.checked_add(request.selected_root.capacity().saturating_mul(64)))
        .and_then(|bytes| bytes.checked_add(128 * 1024))
        .and_then(|bytes| {
            bytes.checked_add(
                ScannerId::ALL.len() * 2 * (4096 + std::mem::size_of::<(ScannerId, String)>()),
            )
        })
        .ok_or(InventoryError::ResourceLimit)?;
    budget.reserve(bytes)
}

fn bounded_error(error: impl std::fmt::Display) -> String {
    use std::fmt::Write;
    struct Message(String);
    impl Write for Message {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            let mut end = text.len().min(4096 - self.0.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            self.0.push_str(&text[..end]);
            if end < text.len() {
                Err(std::fmt::Error)
            } else {
                Ok(())
            }
        }
    }
    let mut message = Message(String::with_capacity(4096));
    let _ = write!(message, "{error}");
    message.0
}

fn upsert_footprints(outcome: &mut ScanOutcome, set: Arc<FootprintSet>, memory: Reservation) {
    if let Some(index) = outcome
        .footprints
        .iter()
        .position(|previous| previous.axis == set.axis)
    {
        outcome.footprints[index] = set;
        outcome.footprint_memory[index] = Arc::new(memory);
    } else {
        outcome.footprints.push(set);
        outcome.footprint_memory.push(Arc::new(memory));
    }
}

fn upsert_failure(outcome: &mut ScanOutcome, scanner: ScannerId, error: &str) {
    retain_failure(&mut outcome.failures, scanner, error);
}

fn retain_failure(failures: &mut Vec<(ScannerId, String)>, scanner: ScannerId, error: &str) {
    let mut end = error.len().min(4096);
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    let error = error[..end].to_owned();
    if let Some(previous) = failures.iter_mut().find(|(id, _)| *id == scanner) {
        if error == "run cancelled"
            && (previous.1.contains("resource limit")
                || previous.1.contains("memory budget exhausted"))
        {
            return;
        }
        previous.1 = error;
    } else {
        failures.push((scanner, error));
    }
}

pub(crate) fn upsert_tree(
    trees: &mut Vec<Arc<crate::scan::walk::DirTree>>,
    tree: Arc<crate::scan::walk::DirTree>,
) {
    if let Some(previous) = trees.iter_mut().find(|previous| previous.root == tree.root) {
        *previous = tree;
    } else {
        trees.push(tree);
    }
}

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

async fn publish_run_event(
    tx: &mpsc::Sender<ScanEvent>,
    event: ScanEvent,
    token: &CancellationToken,
    run_id: RunId,
    bus: &ScanBus,
) {
    tokio::select! {
        biased;
        result = tx.reserve() => {
            match result {
                Ok(permit) => permit.send(event),
                Err(_) => {
                    token.cancel();
                    bus.cancel_generation(run_id.0);
                }
            }
        },
        _ = token.cancelled() => bus.cancel_generation(run_id.0),
    }
}

fn spawn_one(
    scanner: Box<dyn Scanner>,
    ctx: ScanCtx,
    tx: mpsc::Sender<ScanEvent>,
    worker: WorkerGuard,
    audit_admission: Option<Arc<Semaphore>>,
    disk_started: Option<CancellationToken>,
) {
    tokio::spawn(async move {
        let _worker = worker;
        let scanner_id = scanner.id();
        let gen = ctx.gen;
        let token = ctx.token.clone();
        let selected_disk = scanner_id == ScannerId::Fs && !ctx.fs_discovery_only;
        let _ = tx
            .send(ScanEvent::Started {
                scanner: scanner_id,
                gen,
            })
            .await;
        let start = Instant::now();
        let scan = async {
            let _audit_permit = if let Some(admission) = audit_admission {
                let queued = Instant::now();
                if let Some(disk_started) = disk_started.as_ref() {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => anyhow::bail!("run cancelled"),
                        _ = disk_started.cancelled() => {}
                    }
                }
                let permit = tokio::select! {
                    biased;
                    _ = token.cancelled() => anyhow::bail!("run cancelled"),
                    permit = admission.acquire_owned() => permit?,
                };
                tracing::debug!(
                    run_id = gen,
                    scanner = ?scanner_id,
                    permit_wait_ms = queued.elapsed().as_secs_f64() * 1000.0,
                    "host audit admitted"
                );
                Some(permit)
            } else {
                None
            };
            anyhow::ensure!(!token.is_cancelled(), "run cancelled");
            let scan = scanner.scan(ctx);
            tokio::pin!(scan);
            std::future::poll_fn(|context| {
                let result = std::future::Future::poll(scan.as_mut(), context);
                if selected_disk {
                    if let Some(disk_started) = disk_started.as_ref() {
                        disk_started.cancel();
                    }
                }
                result
            })
            .await
        };
        tokio::pin!(scan);
        let result = tokio::select! {
            result = &mut scan => result,
            _ = token.cancelled() => {
                tracing::debug!(run_id = gen, scanner = ?scanner_id, "scanner cancellation requested; awaiting worker retirement");
                let _ = (&mut scan).await;
                Err(anyhow::anyhow!("run cancelled"))
            }
        };
        let result = if token.is_cancelled() {
            Err(anyhow::anyhow!("run cancelled"))
        } else {
            result
        };
        tracing::debug!(
            run_id = gen,
            scanner = ?scanner_id,
            duration_ms = start.elapsed().as_secs_f64() * 1000.0,
            cancelled = token.is_cancelled(),
            success = result.is_ok(),
            "scanner completed"
        );
        let event = match result {
            Ok(()) => ScanEvent::Finished {
                scanner: scanner_id,
                gen,
                duration: start.elapsed(),
            },
            Err(error) => ScanEvent::Failed {
                scanner: scanner_id,
                gen,
                error: bounded_error(error),
            },
        };
        let _ = tx.send(event).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockCommandRunner;

    fn manager(home: &Path) -> ScannerManager {
        ScannerManager::new(
            Arc::new(Config::default()),
            Arc::new(Paths::from_home(home)),
            Arc::new(MockCommandRunner::new()),
            Mode::Fake,
        )
    }

    #[tokio::test]
    async fn cancellation_retires_workers_with_an_undrained_event_receiver() {
        let home = tempfile::tempdir().unwrap();
        let subset = home.path().join("cf-repos");
        std::fs::create_dir(&subset).unwrap();
        for root in [home.path(), subset.as_path()] {
            let manager = manager(home.path());
            let (tx, _rx) = mpsc::channel(1);
            let run_id = manager.start_run(&tx, RunRequest::new(root)).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while tx.capacity() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(manager.workers.lock().unwrap().contains_key(&run_id));
            manager.cancel();
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while manager.workers.lock().unwrap().contains_key(&run_id) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("a full external event queue must not prevent worker retirement");
            let metadata = manager.current_run().unwrap();
            assert_eq!(metadata.disk.completeness, Completeness::Cancelled);
            assert_eq!(metadata.audit_host.completeness, Completeness::Cancelled);
        }
    }

    #[tokio::test]
    async fn old_receiver_closure_does_not_finish_new_generation_attribution() {
        let home = tempfile::tempdir().unwrap();
        let manager = manager(home.path());
        let (old_tx, old_rx) = mpsc::channel(1);
        let old_id = manager
            .start_run(&old_tx, RunRequest::new(home.path()))
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while old_tx.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let (new_tx, _new_rx) = mpsc::channel(1);
        let new_id = manager
            .start_run(&new_tx, RunRequest::new(home.path()))
            .unwrap();
        let pending = CancellationToken::new();
        manager
            .bus
            .begin(new_id.0, &[(ScannerId::Apps, pending.clone())]);
        drop(old_rx);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while manager.workers.lock().unwrap().contains_key(&old_id) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("superseded workers must retire");
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            manager.bus.wait_for(&[ScannerId::Apps], new_id.0, &pending),
        )
        .await
        .is_err());
        manager.cancel();
    }

    fn discovery_fixture() -> ActiveRun {
        let paths = Arc::new(Paths::from_home("/fixture/Home"));
        let request = RunRequest::new("/fixture/selected");
        let context = |context| ContextMetadata {
            discovery: matches!(&context, RunContext::AuditHost { .. }).then_some(
                DiscoveryMetadata {
                    completeness: Completeness::Running,
                    coverage: None,
                    error: None,
                },
            ),
            context,
            completeness: Completeness::Running,
            completed_sections: Vec::new(),
            failed_sections: Vec::new(),
            coverage: None,
            stop_reasons: Vec::new(),
        };
        ActiveRun {
            metadata: RunMetadata {
                run_id: RunId(42),
                disk: context(RunContext::Disk {
                    selected_root: request.selected_root.clone(),
                }),
                audit_host: context(RunContext::AuditHost {
                    home: paths.home.clone(),
                }),
                request,
                active_scanners: 0,
                retiring_count: 0,
                retiring_runs: Vec::new(),
            },
            token: CancellationToken::new(),
            failures: Vec::new(),
            disk_partial: false,
            audit_partial: false,
            discovery_separate: true,
            primary_fs_terminal: None,
            discovery_terminal: None,
            discovery_partial: false,
            paths,
            memory: Arc::new(MemoryBudget::new(128 * 1024).reserve(128 * 1024).unwrap()),
        }
    }

    fn finish_primary_sections(run: &mut ActiveRun) {
        for section in registry::REGISTRY {
            observe_run(
                run,
                &ScanEvent::Finished {
                    scanner: section.id,
                    gen: run.metadata.run_id.0,
                    duration: std::time::Duration::ZERO,
                },
            );
        }
    }

    fn discovery_coverage_event(coverage: WalkCoverage, complete: bool) -> ScanEvent {
        ScanEvent::Finding {
            scanner: ScannerId::Fs,
            gen: 42,
            finding: Box::new(
                Finding::new(FindingKind::DiskCategory, "coverage", "coverage").meta(
                    serde_json::json!({
                        "context": "audit_host", "host_discovery": true, "complete": complete,
                        "walk_coverage": coverage,
                    }),
                ),
            ),
        }
    }

    fn finish_discovery(run: &mut ActiveRun) -> ScanEvent {
        observe_discovery(
            run,
            &ScanEvent::Finished {
                scanner: ScannerId::Fs,
                gen: run.metadata.run_id.0,
                duration: std::time::Duration::ZERO,
            },
        )
        .unwrap()
    }

    #[test]
    fn selected_disk_completion_does_not_credit_pending_host_discovery() {
        let mut run = discovery_fixture();
        finish_primary_sections(&mut run);
        assert_eq!(run.metadata.disk.completeness, Completeness::Complete);
        assert_eq!(run.metadata.audit_host.completeness, Completeness::Running);
        assert!(!run
            .metadata
            .audit_host
            .completed_sections
            .contains(&ScannerId::Fs));
        let home_tree = ScanEvent::DirTree {
            scanner: ScannerId::Fs,
            gen: 42,
            tree: Arc::new(crate::fake::dir_tree()),
        };
        assert!(observe_discovery(&mut run, &home_tree).is_none());
        let home_finding = ScanEvent::Finding {
            scanner: ScannerId::Fs,
            gen: 42,
            finding: Box::new(
                Finding::new(FindingKind::LargeFile, "homefile", "Home file")
                    .path("/fixture/Home/file"),
            ),
        };
        assert!(observe_discovery(&mut run, &home_finding).is_none());
        assert!(run.metadata.disk.coverage.is_none());
        let diagnostic = observe_discovery(
            &mut run,
            &discovery_coverage_event(
                WalkCoverage {
                    unreadable: 2,
                    excluded: 5,
                    entry_limit: true,
                    ..WalkCoverage::default()
                },
                false,
            ),
        )
        .unwrap();
        let ScanEvent::Finding { finding, .. } = diagnostic else {
            panic!("expected lightweight discovery diagnostic");
        };
        assert_eq!(
            context_of_finding(
                &finding,
                &run.metadata.request.selected_root,
                &run.paths.home
            ),
            run.metadata.audit_host.context
        );
        assert!(finding.path.is_none());
        assert!(finding.remedies.is_empty());
        assert_eq!(run.metadata.audit_host.completeness, Completeness::Running);
        finish_discovery(&mut run);
        assert_eq!(run.metadata.disk.completeness, Completeness::Complete);
        assert_eq!(run.metadata.audit_host.completeness, Completeness::Partial);
        assert_eq!(
            run.metadata
                .audit_host
                .discovery
                .as_ref()
                .unwrap()
                .completeness,
            Completeness::Partial
        );
        assert_eq!(
            run.metadata
                .audit_host
                .coverage
                .as_ref()
                .unwrap()
                .unreadable,
            2
        );
        assert!(run
            .metadata
            .audit_host
            .stop_reasons
            .contains(&RunStopReason::Unreadable));
        assert!(run
            .metadata
            .audit_host
            .stop_reasons
            .contains(&RunStopReason::EntryLimit));
        assert_eq!(
            run.metadata.audit_host.completed_sections.len(),
            registry::REGISTRY.len()
        );
        assert!(run.metadata.audit_host.failed_sections.is_empty());
    }

    #[test]
    fn host_discovery_failures_remain_inspectable_in_both_terminal_orders() {
        for discovery_first in [false, true] {
            let mut run = discovery_fixture();
            if !discovery_first {
                finish_primary_sections(&mut run);
            }
            let diagnostic = observe_discovery(
                &mut run,
                &ScanEvent::Failed {
                    scanner: ScannerId::Fs,
                    gen: 42,
                    error: "Home inaccessible ".repeat(1024),
                },
            )
            .unwrap();
            let ScanEvent::Finding { finding, .. } = diagnostic else {
                panic!("discovery error must not fail selected Disk section");
            };
            assert_eq!(finding.meta["complete"], false);
            assert_eq!(finding.detail.len(), 4096);
            assert!(finding.path.is_none());
            if discovery_first {
                finish_primary_sections(&mut run);
            }
            assert_eq!(run.metadata.disk.completeness, Completeness::Complete);
            assert_eq!(run.metadata.audit_host.completeness, Completeness::Partial);
            let discovery = run.metadata.audit_host.discovery.as_ref().unwrap();
            assert_eq!(discovery.completeness, Completeness::Failed);
            assert_eq!(discovery.error.as_ref().unwrap().len(), 4096);
            assert_eq!(run.metadata.audit_host.failed_sections, vec![ScannerId::Fs]);
            assert!(!run
                .metadata
                .audit_host
                .completed_sections
                .contains(&ScannerId::Fs));
            assert!(observe_discovery(
                &mut run,
                &ScanEvent::Failed {
                    scanner: ScannerId::Fs,
                    gen: 41,
                    error: "stale".into()
                }
            )
            .is_none());
            assert_ne!(
                run.metadata
                    .audit_host
                    .discovery
                    .as_ref()
                    .unwrap()
                    .error
                    .as_deref(),
                Some("stale")
            );
        }
    }

    #[test]
    fn host_discovery_success_requires_observed_coverage() {
        for has_coverage in [false, true] {
            let mut run = discovery_fixture();
            if has_coverage {
                observe_discovery(
                    &mut run,
                    &discovery_coverage_event(WalkCoverage::default(), true),
                );
            }
            finish_discovery(&mut run);
            assert_eq!(run.metadata.audit_host.completeness, Completeness::Running);
            finish_primary_sections(&mut run);
            let expected = if has_coverage {
                Completeness::Complete
            } else {
                Completeness::Partial
            };
            assert_eq!(run.metadata.audit_host.completeness, expected);
            assert_eq!(
                run.metadata
                    .audit_host
                    .discovery
                    .as_ref()
                    .unwrap()
                    .completeness,
                expected
            );
            assert_eq!(
                run.metadata
                    .audit_host
                    .discovery
                    .as_ref()
                    .unwrap()
                    .error
                    .is_some(),
                !has_coverage
            );
        }
    }

    #[test]
    fn host_discovery_resource_limit_preserves_completed_disk_and_error() {
        let mut run = discovery_fixture();
        finish_primary_sections(&mut run);
        observe_discovery(
            &mut run,
            &ScanEvent::Failed {
                scanner: ScannerId::Fs,
                gen: 42,
                error: "resource limit: Home discovery storage".into(),
            },
        );
        observe_discovery(
            &mut run,
            &ScanEvent::Failed {
                scanner: ScannerId::Fs,
                gen: 42,
                error: "run cancelled".into(),
            },
        );
        assert!(run.token.is_cancelled());
        assert_eq!(run.metadata.disk.completeness, Completeness::Complete);
        assert_eq!(run.metadata.audit_host.completeness, Completeness::Partial);
        assert!(run
            .metadata
            .audit_host
            .stop_reasons
            .contains(&RunStopReason::ResourceLimited));
        let discovery = run.metadata.audit_host.discovery.as_ref().unwrap();
        assert_eq!(discovery.completeness, Completeness::Partial);
        assert_eq!(
            discovery.error.as_deref(),
            Some("resource limit: Home discovery storage")
        );
        assert!(discovery.coverage.as_ref().unwrap().resource_limited);
        assert!(discovery.coverage.as_ref().unwrap().cancelled);
    }

    #[test]
    fn host_discovery_resource_marker_preserves_stop_reason_before_retirement() {
        let mut run = discovery_fixture();
        finish_primary_sections(&mut run);
        let diagnostic = observe_discovery(
            &mut run,
            &discovery_coverage_event(
                WalkCoverage {
                    resource_limited: true,
                    ..WalkCoverage::default()
                },
                false,
            ),
        )
        .unwrap();
        let ScanEvent::Finding { finding, .. } = diagnostic else {
            panic!("expected coverage finding");
        };
        assert!(finding.detail.contains("resource limit"));
        assert_eq!(finding.severity, crate::model::Severity::Warning);
        assert_eq!(
            run.metadata
                .audit_host
                .discovery
                .as_ref()
                .unwrap()
                .completeness,
            Completeness::Partial
        );
        assert!(run.discovery_terminal.is_none());
        observe_discovery(
            &mut run,
            &ScanEvent::Failed {
                scanner: ScannerId::Fs,
                gen: 42,
                error: "run cancelled".into(),
            },
        );
        assert!(run
            .metadata
            .audit_host
            .discovery
            .as_ref()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .contains("resource limit"));
        assert_eq!(run.metadata.disk.completeness, Completeness::Complete);
    }

    #[test]
    fn host_fixed_finding_storage_pressure_is_not_a_disk_resource_stop() {
        let mut run = discovery_fixture();
        finish_primary_sections(&mut run);
        mark_context_resource_limited(&mut run, ScannerId::Fs, true);
        assert_eq!(run.metadata.disk.completeness, Completeness::Complete);
        assert!(!run
            .metadata
            .disk
            .stop_reasons
            .contains(&RunStopReason::ResourceLimited));
        assert_eq!(run.metadata.audit_host.completeness, Completeness::Partial);
        assert!(run
            .metadata
            .audit_host
            .stop_reasons
            .contains(&RunStopReason::ResourceLimited));
        assert_eq!(
            run.metadata
                .audit_host
                .discovery
                .as_ref()
                .unwrap()
                .completeness,
            Completeness::Cancelled
        );
    }

    #[test]
    fn finding_budget_counts_spare_capacity_and_json_value_storage() {
        let mut finding = Finding::new(FindingKind::App, "budgeted", "budgeted");
        finding.detail = String::with_capacity(64 * 1024);
        finding.detail.push_str("small payload");
        let budget = MemoryBudget::new(32 * 1024);
        assert!(finding_reservation(&finding, &budget).is_err());
        assert_eq!(budget.used(), 0);
        finding.detail = String::new();
        finding.meta = serde_json::Value::Array(vec![serde_json::Value::Null; 2048]);
        assert!(serialized_size(&finding).unwrap() * 2 < budget.limit());
        assert!(finding_reservation(&finding, &budget).is_err());
        assert_eq!(budget.used(), 0);
        let budget = MemoryBudget::new(256 * 1024);
        let reservation = finding_reservation(&finding, &budget).unwrap();
        assert_eq!(
            finding_storage_bytes(&finding).unwrap(),
            reservation.bytes()
        );
        assert!(reservation.bytes() >= 2 * 2048 * std::mem::size_of::<serde_json::Value>());
        drop(reservation);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn finding_budget_rejects_excessively_nested_metadata() {
        let mut finding = Finding::new(FindingKind::App, "deep", "deep");
        for _ in 0..130 {
            finding.meta = serde_json::Value::Array(vec![finding.meta]);
        }
        assert!(finding_reservation(&finding, &MemoryBudget::new(1024 * 1024)).is_err());
    }

    #[test]
    fn finding_budget_covers_sparse_json_tree_nodes_before_clone() {
        let mut finding = Finding::new(FindingKind::App, "sparse", "sparse");
        for _ in 0..64 {
            finding.meta = serde_json::json!({"k": finding.meta});
        }
        let bytes = finding_storage_bytes(&finding).unwrap();
        assert!(bytes >= 2 * 64 * 1024);
        assert!(serialized_size(&finding).unwrap() * 2 < 64 * 1024);
        let budget = MemoryBudget::new(64 * 1024);
        assert!(finding_reservation(&finding, &budget).is_err());
        assert_eq!(budget.used(), 0);
    }

    fn empty_footprints(axis: crate::attribution::model::Axis, gen: u64) -> FootprintSet {
        FootprintSet {
            axis,
            gen,
            footprints: Vec::new(),
            baseline: Vec::new(),
            unattributed: Vec::new(),
            disk_total: 0,
            attributed_total: 0,
            missing_deps: Vec::new(),
        }
    }

    #[test]
    fn footprint_updates_retain_only_latest_per_axis_and_release_credits() {
        use crate::attribution::model::Axis;
        let budget = MemoryBudget::new(16 * 1024);
        let mut outcome = ScanOutcome::default();
        let first = Arc::new(empty_footprints(Axis::Projects, 1));
        let weak = Arc::downgrade(&first);
        let memory = footprint_reservation(&first, &budget).unwrap();
        upsert_footprints(&mut outcome, first, memory);
        for gen in 2..100 {
            for axis in Axis::ALL {
                let set = Arc::new(empty_footprints(*axis, gen));
                let memory = footprint_reservation(&set, &budget).unwrap();
                upsert_footprints(&mut outcome, set, memory);
            }
        }
        assert!(weak.upgrade().is_none());
        assert_eq!(outcome.footprints.len(), Axis::ALL.len());
        assert!(outcome.footprints.iter().all(|set| set.gen == 99));
        assert_eq!(outcome.footprint_memory.len(), outcome.footprints.len());
        drop(outcome);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn footprint_budget_counts_empty_reserved_vectors() {
        let mut set = empty_footprints(crate::attribution::model::Axis::Projects, 1);
        set.footprints = Vec::with_capacity(4096);
        assert!(footprint_reservation(&set, &MemoryBudget::new(4096)).is_err());
    }

    #[test]
    fn error_history_is_utf8_bounded_and_latest_per_scanner() {
        let mut outcome = ScanOutcome::default();
        let source = "🦀".repeat(5000);
        let bounded = bounded_error(&source);
        assert_eq!(bounded.len(), 4096);
        for _ in 0..1000 {
            for scanner in ScannerId::ALL {
                upsert_failure(&mut outcome, *scanner, &source);
            }
        }
        assert_eq!(outcome.failures.len(), ScannerId::ALL.len());
        assert!(outcome
            .failures
            .iter()
            .all(|(_, error)| error.len() == 4096));
        upsert_failure(&mut outcome, ScannerId::Fs, "latest");
        assert_eq!(
            outcome
                .failures
                .iter()
                .find(|(id, _)| *id == ScannerId::Fs)
                .unwrap()
                .1,
            "latest"
        );
    }

    #[test]
    fn cancellation_terminal_events_do_not_overwrite_resource_failures() {
        for errors in [
            [
                "resource limit: finding storage budget exhausted",
                "run cancelled",
            ],
            [
                "run cancelled",
                "resource limit: finding storage budget exhausted",
            ],
        ] {
            let mut outcome = ScanOutcome::default();
            for error in errors {
                upsert_failure(&mut outcome, ScannerId::Fs, error);
            }
            assert_eq!(outcome.failures.len(), 1);
            assert!(outcome.failures[0].1.contains("resource limit"));
        }
    }

    #[test]
    fn retiring_worker_holds_run_control_reservation() {
        let budget = MemoryBudget::new(1024 * 1024);
        let memory = Arc::new(
            run_reservation(&RunRequest::new("/selected"), &Config::default(), &budget).unwrap(),
        );
        let workers = Arc::new(Mutex::new(BTreeMap::new()));
        let worker = WorkerGuard::new(RunId(1), workers.clone()).with_memory(memory.clone());
        drop(memory);
        assert!(budget.used() >= 128 * 1024);
        assert_eq!(workers.lock().unwrap().get(&RunId(1)), Some(&1));
        drop(worker);
        assert_eq!(budget.used(), 0);
        assert!(workers.lock().unwrap().is_empty());
    }

    #[test]
    fn incremental_trees_replace_and_release_previous_reservations() {
        let budget = MemoryBudget::new(4096);
        let mut first = crate::fake::dir_tree();
        first.complete = false;
        first.memory = Some(Arc::new(budget.reserve(2048).unwrap()));
        let first = Arc::new(first);
        let weak = Arc::downgrade(&first);
        let mut outcome = ScanOutcome::default();
        upsert_tree(&mut outcome.dir_trees, first);
        assert_eq!(budget.used(), 2048);
        let mut final_tree = crate::fake::dir_tree();
        final_tree.complete = true;
        upsert_tree(&mut outcome.dir_trees, Arc::new(final_tree));
        assert_eq!(outcome.dir_trees.len(), 1);
        assert!(outcome.dir_trees[0].complete);
        assert!(weak.upgrade().is_none());
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn final_tree_replaces_transient_coverage_without_double_counting() {
        let home = tempfile::tempdir().unwrap();
        let manager = manager(home.path());
        let (tx, _rx) = mpsc::channel(32);
        let run_id = manager
            .start_run(&tx, RunRequest::new(home.path()))
            .unwrap();
        {
            let mut active = manager.active.lock().unwrap();
            let run = active.as_mut().unwrap();
            let mut partial = crate::fake::dir_tree();
            partial.complete = false;
            partial.coverage.excluded = 2;
            partial.coverage.summaries_truncated = true;
            observe_run(
                run,
                &ScanEvent::DirTree {
                    scanner: ScannerId::Fs,
                    gen: run_id.0,
                    tree: Arc::new(partial),
                },
            );
            let mut final_tree = crate::fake::dir_tree();
            final_tree.complete = true;
            final_tree.errors = 0;
            final_tree.coverage.excluded = 2;
            observe_run(
                run,
                &ScanEvent::DirTree {
                    scanner: ScannerId::Fs,
                    gen: run_id.0,
                    tree: Arc::new(final_tree),
                },
            );
            observe_run(
                run,
                &ScanEvent::Finished {
                    scanner: ScannerId::Fs,
                    gen: run_id.0,
                    duration: std::time::Duration::ZERO,
                },
            );
            assert_eq!(run.metadata.disk.completeness, Completeness::Complete);
            assert_eq!(run.metadata.disk.coverage.as_ref().unwrap().excluded, 2);
            assert!(!run
                .metadata
                .disk
                .stop_reasons
                .contains(&RunStopReason::SummariesTruncated));
        }
        manager.cancel();
    }

    #[tokio::test]
    async fn finding_byte_budget_cancels_run_with_explicit_resource_metadata() {
        let home = tempfile::tempdir().unwrap();
        let mut manager = manager(home.path());
        let budget = MemoryBudget::new(1);
        manager.bus = ScanBus::with_budget(budget.clone());
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            manager.run_request_to_completion(RunRequest::new(home.path())),
        )
        .await
        .unwrap()
        .unwrap();
        let run = outcome.run.unwrap();
        assert!(manager.run_token().unwrap().is_cancelled());
        assert!(outcome
            .failures
            .iter()
            .any(|(_, error)| error.contains("resource limit")));
        assert!([&run.disk, &run.audit_host].iter().any(|context| {
            context.completeness == Completeness::Partial
                && context
                    .stop_reasons
                    .contains(&RunStopReason::ResourceLimited)
        }));
        assert!(outcome
            .findings
            .keys()
            .all(|finding_id| outcome.memory.contains_key(finding_id)));
        assert_eq!(budget.used(), 0);
        assert_eq!(budget.peak(), 0);
    }

    #[tokio::test]
    async fn incomplete_fixed_measurement_marks_host_partial_not_disk() {
        let home = tempfile::tempdir().unwrap();
        let manager = manager(home.path());
        let (tx, _rx) = mpsc::channel(32);
        let run_id = manager
            .start_run(&tx, RunRequest::new(home.path()))
            .unwrap();
        {
            let mut active = manager.active.lock().unwrap();
            let run = active.as_mut().unwrap();
            observe_run(
                run,
                &ScanEvent::Finding {
                    scanner: ScannerId::Fs,
                    gen: run_id.0,
                    finding: Box::new(
                        Finding::new(FindingKind::CacheDir, "fixed", "Host cache")
                            .meta(serde_json::json!({"context": "audit_host", "complete": false})),
                    ),
                },
            );
            for section in registry::REGISTRY {
                observe_run(
                    run,
                    &ScanEvent::Finished {
                        scanner: section.id,
                        gen: run_id.0,
                        duration: std::time::Duration::ZERO,
                    },
                );
            }
            assert_eq!(run.metadata.disk.completeness, Completeness::Complete);
            assert_eq!(run.metadata.audit_host.completeness, Completeness::Partial);
            assert_eq!(
                run.metadata.audit_host.completed_sections.len(),
                registry::REGISTRY.len()
            );
        }
        manager.cancel();
    }

    #[tokio::test]
    async fn stale_resource_limit_does_not_cancel_new_run_or_dependency_bus() {
        let home = tempfile::tempdir().unwrap();
        let manager = manager(home.path());
        let (tx, _rx) = mpsc::channel(32);
        let first = manager
            .start_run(&tx, RunRequest::new(home.path()))
            .unwrap();
        let second = manager
            .start_run(&tx, RunRequest::new(home.path()))
            .unwrap();
        let token = manager.run_token().unwrap();
        manager.resource_limited(first, ScannerId::Fs);
        assert!(!token.is_cancelled());
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(5),
            manager.bus.wait_for(&[ScannerId::Ports], second.0, &token),
        )
        .await
        .is_err());
        assert_eq!(
            manager.current_run().unwrap().disk.completeness,
            Completeness::Running
        );
        manager.cancel();
    }

    struct BlockedScanner {
        id: ScannerId,
        entered: Arc<tokio::sync::Semaphore>,
        release: Arc<tokio::sync::Semaphore>,
    }

    #[async_trait::async_trait]
    impl Scanner for BlockedScanner {
        fn id(&self) -> ScannerId {
            self.id
        }
        async fn scan(&self, _ctx: ScanCtx) -> anyhow::Result<()> {
            self.entered.add_permits(1);
            self.release.acquire().await?.forget();
            Ok(())
        }
    }

    #[test]
    fn host_admission_leaves_disk_and_dependency_waiters_unblocked() {
        let home = tempfile::tempdir().unwrap();
        let manager = ScannerManager::new(
            Arc::new(Config::default()),
            Arc::new(Paths::from_home(home.path())),
            Arc::new(MockCommandRunner::new()),
            Mode::Real,
        );
        for scanner in [
            ScannerId::Fs,
            ScannerId::Git,
            ScannerId::Projects,
            ScannerId::AppStorage,
        ] {
            assert!(manager.audit_admission(scanner, false).is_none());
        }
        assert_eq!(manager.audit_slots.available_permits(), 2);
        assert!(Arc::ptr_eq(
            &manager.audit_admission(ScannerId::Apps, false).unwrap(),
            &manager.audit_admission(ScannerId::Fs, true).unwrap(),
        ));
    }

    #[tokio::test]
    async fn host_admission_waits_for_selected_disk_first_poll() {
        let home = tempfile::tempdir().unwrap();
        let manager = ScannerManager::new(
            Arc::new(Config::default()),
            Arc::new(Paths::from_home(home.path())),
            Arc::new(MockCommandRunner::new()),
            Mode::Real,
        );
        let token = CancellationToken::new();
        let disk_started = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel(8);
        let host_entered = Arc::new(Semaphore::new(0));
        let disk_entered = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        for (scanner, entered) in [
            (ScannerId::Apps, host_entered.clone()),
            (ScannerId::Fs, disk_entered.clone()),
        ] {
            spawn_one(
                Box::new(BlockedScanner {
                    id: scanner,
                    entered,
                    release: release.clone(),
                }),
                ScanCtx {
                    tx: tx.clone(),
                    gen: 1,
                    token: token.clone(),
                    paths: manager.paths(),
                    config: manager.config(),
                    runner: manager.runner(),
                    current: scanner,
                    repo_tx: None,
                    repo_rx: None,
                    fs_discovery_only: false,
                },
                tx.clone(),
                WorkerGuard::new(RunId(1), manager.workers.clone()),
                manager.audit_admission(scanner, false),
                Some(disk_started.clone()),
            );
            if scanner == ScannerId::Apps {
                assert!(matches!(
                    rx.recv().await,
                    Some(ScanEvent::Started {
                        scanner: ScannerId::Apps,
                        ..
                    })
                ));
                tokio::task::yield_now().await;
                assert_eq!(host_entered.available_permits(), 0);
                assert_eq!(manager.audit_slots.available_permits(), 2);
            }
        }
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            host_entered.acquire().await.unwrap().forget();
            assert_eq!(disk_entered.available_permits(), 1);
            release.add_permits(2);
            while manager.workers.lock().unwrap().contains_key(&RunId(1)) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn disk_bypasses_busy_host_slots_and_cancel_skips_queued_audits() {
        let home = tempfile::tempdir().unwrap();
        let manager = ScannerManager::new(
            Arc::new(Config::default()),
            Arc::new(Paths::from_home(home.path())),
            Arc::new(MockCommandRunner::new()),
            Mode::Real,
        );
        let occupied = manager
            .audit_slots
            .clone()
            .acquire_many_owned(2)
            .await
            .unwrap();
        let token = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel(8);
        let host_entered = Arc::new(Semaphore::new(0));
        let disk_entered = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        for (scanner, entered) in [
            (ScannerId::Apps, host_entered.clone()),
            (ScannerId::Fs, disk_entered.clone()),
        ] {
            spawn_one(
                Box::new(BlockedScanner {
                    id: scanner,
                    entered,
                    release: release.clone(),
                }),
                ScanCtx {
                    tx: tx.clone(),
                    gen: 1,
                    token: token.clone(),
                    paths: manager.paths(),
                    config: manager.config(),
                    runner: manager.runner(),
                    current: scanner,
                    repo_tx: None,
                    repo_rx: None,
                    fs_discovery_only: false,
                },
                tx.clone(),
                WorkerGuard::new(RunId(1), manager.workers.clone()),
                manager.audit_admission(scanner, false),
                None,
            );
        }
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            disk_entered.acquire().await.unwrap().forget();
            assert_eq!(host_entered.available_permits(), 0);
            token.cancel();
            while !matches!(
                rx.recv().await,
                Some(ScanEvent::Failed {
                    scanner: ScannerId::Apps,
                    ..
                })
            ) {}
            drop(occupied);
            assert_eq!(host_entered.available_permits(), 0);
            release.add_permits(1);
            while manager.workers.lock().unwrap().contains_key(&RunId(1)) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(manager.audit_slots.available_permits(), 2);
    }

    #[tokio::test]
    async fn retiring_worker_remains_counted_until_its_future_returns() {
        let home = tempfile::tempdir().unwrap();
        let manager = manager(home.path());
        let (tx, _rx) = mpsc::channel(1024);
        let first = manager
            .start_run(&tx, RunRequest::new(home.path()))
            .unwrap();
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let (blocked_tx, _blocked_rx) = mpsc::channel(8);
        let ctx = ScanCtx {
            tx: blocked_tx.clone(),
            gen: first.0,
            token: manager.run_token().unwrap(),
            paths: manager.run_paths().unwrap(),
            config: manager.config(),
            runner: manager.runner(),
            current: ScannerId::Fs,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        spawn_one(
            Box::new(BlockedScanner {
                id: ScannerId::Fs,
                entered: entered.clone(),
                release: release.clone(),
            }),
            ctx,
            blocked_tx,
            WorkerGuard::new(first, manager.workers.clone()),
            None,
            None,
        );
        entered.acquire().await.unwrap().forget();
        manager.cancel();
        assert!(manager.current_run().unwrap().retiring_count > 0);
        let second = manager
            .start_run(&tx, RunRequest::new(home.path()))
            .unwrap();
        tokio::task::yield_now().await;
        let metadata = manager.current_run().unwrap();
        assert_eq!(metadata.run_id, second);
        assert!(metadata
            .retiring_runs
            .iter()
            .any(|run| run.run_id == first && run.active_scanners > 0));
        release.add_permits(1);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while manager
                .current_run()
                .unwrap()
                .retiring_runs
                .iter()
                .any(|run| run.run_id == first)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        manager.cancel();
    }

    #[test]
    fn fixed_targets_are_global_but_inventory_findings_are_root_scoped() {
        let root = Path::new("/selected");
        let home = Path::new("/home");
        let tagged = Finding::new(FindingKind::BuildArtifact, "fixed", "Global fixed target")
            .meta(serde_json::json!({"context": "audit_host"}));
        assert_eq!(
            context_of_finding(&tagged, root, home),
            RunContext::AuditHost { home: home.into() }
        );
        for kind in [
            FindingKind::CacheDir,
            FindingKind::IosBackup,
            FindingKind::App,
        ] {
            assert!(matches!(
                context_of_finding(&Finding::new(kind, "key", "title"), root, home),
                RunContext::AuditHost { .. }
            ));
        }
        for kind in [
            FindingKind::DiskCategory,
            FindingKind::BuildArtifact,
            FindingKind::LargeFile,
        ] {
            assert_eq!(
                context_of_finding(&Finding::new(kind, "key", "title"), root, home),
                RunContext::Disk {
                    selected_root: root.into()
                }
            );
        }
    }

    #[test]
    fn coverage_stop_reasons_include_resource_and_materialization_limits() {
        let coverage = WalkCoverage {
            unreadable: 1,
            resource_limited: true,
            cancelled: true,
            deadline: true,
            entry_limit: true,
            ..WalkCoverage::default()
        };
        let reasons = coverage_reasons(&coverage);
        for reason in [
            RunStopReason::Unreadable,
            RunStopReason::ResourceLimited,
            RunStopReason::Cancelled,
            RunStopReason::Deadline,
            RunStopReason::EntryLimit,
        ] {
            assert!(reasons.contains(&reason));
        }
    }

    #[tokio::test]
    async fn invalid_root_does_not_replace_or_cancel_active_run() {
        let home = tempfile::tempdir().unwrap();
        let manager = manager(home.path());
        let (tx, _rx) = mpsc::channel(1024);
        let run_id = manager
            .start_run(&tx, RunRequest::new(home.path()))
            .unwrap();
        let token = manager.run_token().unwrap();
        assert!(manager
            .start_run(&tx, RunRequest::new(home.path().join("missing")))
            .is_err());
        assert_eq!(manager.current_generation(), run_id.0);
        assert!(!token.is_cancelled());
        assert_eq!(
            manager.current_run().unwrap().request.selected_root,
            home.path().canonicalize().unwrap()
        );
        manager.cancel();
    }

    #[tokio::test]
    async fn compatibility_refresh_restarts_whole_run() {
        let home = tempfile::tempdir().unwrap();
        let manager = manager(home.path());
        let (tx, _rx) = mpsc::channel(1024);
        let first = manager.start(&tx, &[ScannerId::Ports]);
        let token = manager.run_token().unwrap();
        let second = manager.start(&tx, &[ScannerId::Fs]);
        assert!(token.is_cancelled());
        assert!(second > first);
        manager.cancel();
        assert_eq!(
            manager.current_run().unwrap().disk.completeness,
            Completeness::Cancelled
        );
        assert_eq!(
            manager.current_run().unwrap().audit_host.completeness,
            Completeness::Cancelled
        );
    }

    #[tokio::test]
    async fn full_run_upserts_and_completes_both_contexts() {
        let home = tempfile::tempdir().unwrap();
        let manager = manager(home.path());
        let outcome = manager
            .run_request_to_completion(RunRequest::new(home.path()))
            .await
            .unwrap();
        let run = outcome.run.unwrap();
        assert_eq!(run.disk.completeness, Completeness::Complete);
        assert_eq!(run.audit_host.completeness, Completeness::Complete);
        assert_eq!(
            run.audit_host.completed_sections.len(),
            registry::REGISTRY.len()
        );
        assert!(outcome.failures.is_empty());
        let expected = crate::fake::fixtures(ScannerId::Fs);
        let disk: Vec<_> = outcome
            .findings
            .values()
            .filter(|finding| finding.kind.scanner() == ScannerId::Fs)
            .collect();
        assert_eq!(disk.len(), expected.len());
        assert_eq!(
            disk.iter()
                .filter(|finding| finding.size_bytes.is_some())
                .count(),
            expected
                .iter()
                .filter(|finding| finding.size_bytes.is_some())
                .count()
        );
        assert_eq!(outcome.footprints.len(), 2);
    }

    #[test]
    fn request_round_trips_and_resolves_tilde_and_relative_root() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("nested")).unwrap();
        let absolute = home.path().join("nested").canonicalize().unwrap();
        assert_eq!(
            RunRequest::resolve_root(Path::new("~/nested"), home.path(), Path::new("/")).unwrap(),
            absolute
        );
        assert_eq!(
            RunRequest::resolve_root(Path::new("nested"), home.path(), home.path()).unwrap(),
            absolute
        );
        let request = RunRequest::new(absolute);
        assert_eq!(
            serde_json::from_str::<RunRequest>(&serde_json::to_string(&request).unwrap()).unwrap(),
            request
        );
        assert!(RunRequest::resolve_root(Path::new(""), home.path(), home.path()).is_err());
        assert!(RunRequest::resolve_root(Path::new("~someone"), home.path(), home.path()).is_err());
        let file = home.path().join("file");
        std::fs::write(&file, "not a directory").unwrap();
        assert!(RunRequest::resolve_root(&file, home.path(), home.path()).is_err());
    }

    #[tokio::test]
    async fn cancel_preserves_headless_partials() {
        let home = tempfile::tempdir().unwrap();
        let manager = Arc::new(manager(home.path()));
        let worker = manager.clone();
        let root = home.path().to_path_buf();
        let task = tokio::spawn(async move {
            worker
                .run_request_to_completion(RunRequest::new(root))
                .await
                .unwrap()
        });
        while manager.current_generation() == 0 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(180)).await;
        manager.cancel();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert!(!outcome.findings.is_empty());
        let metadata = outcome.run.unwrap();
        assert!(matches!(
            metadata.disk.completeness,
            Completeness::Complete | Completeness::Cancelled
        ));
        assert!(matches!(
            metadata.audit_host.completeness,
            Completeness::Complete | Completeness::Cancelled
        ));
    }
}
