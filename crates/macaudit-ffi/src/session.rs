//! The headless scan session: the TUI's `AppState` reducer minus rendering,
//! plus the event pump that feeds it and forwards batched events to Swift.
//!
//! Rules copied from `macaudit::ui` (state.rs / mod.rs) so the two front-ends
//! agree on what a scan means:
//! - an event is applied only when its gen EXACTLY matches the section's
//!   expected gen (drops superseded runs and the discovery-only Fs helper);
//! - once every correlated section is terminal, correlate in memory, then
//!   run network enrichment in the background.

use std::collections::{BTreeMap, HashMap};
use std::sync::{mpsc as callback_channel, Arc, Mutex, OnceLock, RwLock, Weak};
use std::time::Duration;

use macaudit::attribution::model::{Axis, FootprintSet};
use macaudit::correlate::{self, CORRELATED_SECTIONS};
use macaudit::engine::{
    finding_storage_bytes, footprint_storage_bytes, RunMetadata, RunRequest, RunStopReason,
    ScannerManager,
};
use macaudit::inventory::{
    InventoryError, MemoryBudget, MemoryReclaimer, QueryRegistry, Reservation,
};
use macaudit::model::{Finding, FindingId, FindingKind, ScanEvent, ScannerId};
use macaudit::scan::walk::DirTree;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::mapping;
use crate::runtime::runtime;
use crate::ScanListener;

type FindingChanges = Vec<(u64, ScannerId, Finding)>;
type FindingPage = (Vec<Finding>, Reservation);

/// Flush pending finding batches at least this often while a scan streams.
const FLUSH_INTERVAL: Duration = Duration::from_millis(100);
/// …and whenever this many findings are queued, regardless of time.
const FLUSH_THRESHOLD: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Idle,
    Scanning,
    Done,
    Failed(String),
}

#[derive(Default)]
pub struct Session {
    pub run_id: u64,
    pub started_at_ms: u64,
    revision: u64,
    pub query_revision: u64,
    inventory_revisions: HashMap<ScannerId, u64>,
    revisions: BTreeMap<u64, (ScannerId, FindingId)>,
    finding_revisions: HashMap<FindingId, u64>,
    progress: HashMap<ScannerId, mapping::ScanEvent>,
    durations: HashMap<ScannerId, u64>,
    memory: Option<Reservation>,
    finding_sizes: HashMap<FindingId, usize>,
    reported_bytes: HashMap<ScannerId, u64>,
    resource_limited: std::collections::HashSet<ScannerId>,
    cancelled: bool,
    findings: HashMap<ScannerId, BTreeMap<FindingId, Finding>>,
    expected_gen: HashMap<ScannerId, u64>,
    status: HashMap<ScannerId, Status>,
    /// The generation of the last scan that included a correlated section.
    full_scan_gen: u64,
    /// The generation correlation last ran for.
    correlated_gen: u64,
}

impl Session {
    /// Register `gen` as the expected generation for `sections` and reset
    /// their state. Mirrors `AppState::begin_scan` plus the run loop's
    /// full-scan bookkeeping.
    pub fn begin_scan(&mut self, gen: u64, sections: &[ScannerId]) {
        *self = Self::default();
        self.run_id = gen;
        self.memory = MemoryBudget::shared().reserve(0).ok();
        self.started_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        for id in sections {
            self.expected_gen.insert(*id, gen);
            self.findings.entry(*id).or_default().clear();
            self.status.insert(*id, Status::Scanning);
        }
        let full = ScannerId::ALL.iter().all(|s| sections.contains(s));
        if full || sections.iter().any(|s| CORRELATED_SECTIONS.contains(s)) {
            self.full_scan_gen = gen;
        }
    }

    /// Apply one engine event; `false` when it was dropped (wrong gen).
    pub fn apply(&mut self, ev: &ScanEvent) -> bool {
        if self.expected_gen.get(&ev.scanner()) != Some(&ev.generation()) {
            return false;
        }
        if self.cancelled
            && !matches!(
                ev,
                ScanEvent::Finding { .. }
                    | ScanEvent::DirTree { .. }
                    | ScanEvent::Footprints { .. }
            )
        {
            return false;
        }
        if self.resource_limited.contains(&ev.scanner()) {
            return true;
        }
        match ev {
            ScanEvent::Started { scanner, .. } => {
                self.findings.entry(*scanner).or_default().clear();
                self.status.insert(*scanner, Status::Scanning);
            }
            ScanEvent::Progress {
                scanner,
                gen,
                msg,
                done,
                total,
            } => {
                self.progress.insert(
                    *scanner,
                    mapping::ScanEvent::Progress {
                        section: (*scanner).into(),
                        gen: *gen,
                        msg: msg.clone(),
                        done: *done,
                        total: *total,
                    },
                );
            }
            ScanEvent::Finding {
                scanner, finding, ..
            } => {
                self.upsert(*scanner, finding);
            }
            ScanEvent::Finished {
                scanner, duration, ..
            } => {
                self.durations.insert(*scanner, duration.as_millis() as u64);
                self.status.insert(*scanner, Status::Done);
            }
            ScanEvent::Failed { scanner, error, .. } => {
                self.status.insert(*scanner, Status::Failed(error.clone()));
            }
            // Stored on `Shared` by the pump (outside this lock); accepted here
            // so the gen check above still gates it.
            ScanEvent::DirTree { scanner, .. } | ScanEvent::Footprints { scanner, .. } => {
                self.query_revision += 1;
                *self.inventory_revisions.entry(*scanner).or_default() += 1;
            }
        }
        true
    }

    pub fn status_of(&self, id: ScannerId) -> Status {
        self.status.get(&id).cloned().unwrap_or(Status::Idle)
    }

    pub fn resource_limited(&self) -> bool {
        !self.resource_limited.is_empty()
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.progress.clear();
        for section in ScannerId::ALL {
            if matches!(self.status_of(*section), Status::Scanning) {
                self.status.insert(
                    *section,
                    Status::Failed("cancelled; partial results retained".into()),
                );
            }
        }
    }

    pub fn reconcile_retired(&mut self, run: &RunMetadata) -> bool {
        let stopped = [&run.disk, &run.audit_host].iter().any(|context| {
            context.stop_reasons.iter().any(|reason| {
                matches!(
                    reason,
                    RunStopReason::Cancelled | RunStopReason::ResourceLimited
                )
            })
        });
        if run.run_id.0 != self.run_id || run.active_scanners != 0 || !stopped {
            return false;
        }
        let mut changed = !self.cancelled || !self.progress.is_empty();
        self.cancelled = true;
        self.progress.clear();
        for scanner in self.expected_gen.keys() {
            if !matches!(self.status_of(*scanner), Status::Idle | Status::Scanning) {
                continue;
            }
            let context = if *scanner == ScannerId::Fs {
                &run.disk
            } else {
                &run.audit_host
            };
            let status = if context.completed_sections.contains(scanner) {
                Status::Done
            } else {
                let error = if context
                    .stop_reasons
                    .contains(&RunStopReason::ResourceLimited)
                {
                    "resource limit; partial results retained"
                } else {
                    "cancelled; partial results retained"
                };
                Status::Failed(error.into())
            };
            self.status.insert(*scanner, status);
            changed = true;
        }
        changed
    }

    fn upsert(&mut self, scanner: ScannerId, finding: &Finding) {
        let bytes = retained_finding_bytes(finding);
        let previous = self
            .finding_sizes
            .get(&finding.id)
            .copied()
            .unwrap_or_default();
        if self.memory.is_none() {
            self.memory = MemoryBudget::shared().reserve(0).ok();
        }
        if self
            .memory
            .as_mut()
            .is_none_or(|memory| memory.grow(bytes.saturating_sub(previous)).is_err())
        {
            self.resource_limited.insert(scanner);
            self.status.insert(
                scanner,
                Status::Failed("finding retention exceeded the engine memory budget".into()),
            );
            return;
        }
        self.finding_sizes.insert(finding.id, bytes.max(previous));
        let old_bytes = self
            .findings
            .get(&scanner)
            .and_then(|rows| rows.get(&finding.id))
            .and_then(|finding| finding.size_bytes)
            .unwrap_or_default();
        let reported = self.reported_bytes.entry(scanner).or_default();
        *reported = reported
            .saturating_sub(old_bytes)
            .saturating_add(finding.size_bytes.unwrap_or_default());
        if let Some(old) = self.finding_revisions.remove(&finding.id) {
            self.revisions.remove(&old);
        }
        self.revision += 1;
        self.query_revision += 1;
        self.revisions.insert(self.revision, (scanner, finding.id));
        self.finding_revisions.insert(finding.id, self.revision);
        self.findings
            .entry(scanner)
            .or_default()
            .insert(finding.id, finding.clone());
    }

    pub fn findings_page(&self, section: ScannerId, offset: usize, limit: usize) -> Vec<Finding> {
        self.findings
            .get(&section)
            .map(|findings| {
                findings
                    .values()
                    .skip(offset)
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn budgeted_findings_page(
        &self,
        section: ScannerId,
        offset: usize,
        limit: usize,
        budget: &Arc<MemoryBudget>,
    ) -> Result<FindingPage, macaudit::inventory::InventoryError> {
        let bytes = self
            .findings
            .get(&section)
            .map(|findings| {
                findings
                    .values()
                    .skip(offset)
                    .take(limit)
                    .map(|finding| retained_finding_bytes(finding).saturating_mul(3))
                    .sum()
            })
            .unwrap_or_default();
        let memory = budget.reserve(bytes)?;
        Ok((self.findings_page(section, offset, limit), memory))
    }

    pub fn finding_count(&self, section: ScannerId) -> u64 {
        self.findings
            .get(&section)
            .map(|rows| rows.len() as u64)
            .unwrap_or_default()
    }

    pub fn reported_bytes(&self, section: ScannerId) -> u64 {
        self.reported_bytes
            .get(&section)
            .copied()
            .unwrap_or_default()
    }

    fn changes(
        &self,
        after: u64,
    ) -> Result<(FindingChanges, Reservation), macaudit::inventory::InventoryError> {
        let rows: Vec<_> = self
            .revisions
            .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
            .take(FLUSH_THRESHOLD)
            .filter_map(|(revision, (section, id))| {
                self.findings
                    .get(section)?
                    .get(id)
                    .map(|finding| (*revision, *section, finding))
            })
            .collect();
        let bytes = rows
            .iter()
            .map(|(_, _, finding)| retained_finding_bytes(finding).saturating_mul(3))
            .sum();
        let memory = MemoryBudget::shared().reserve(bytes)?;
        Ok((
            rows.into_iter()
                .map(|(revision, section, finding)| (revision, section, finding.clone()))
                .collect(),
            memory,
        ))
    }

    pub fn sections_terminal(&self, sections: &[ScannerId]) -> bool {
        sections
            .iter()
            .all(|id| matches!(self.status_of(*id), Status::Done | Status::Failed(_)))
    }

    pub fn all_findings(
        &self,
    ) -> Result<(BTreeMap<FindingId, Finding>, Reservation), macaudit::inventory::InventoryError>
    {
        let memory = MemoryBudget::shared().reserve(self.snapshot_bytes())?;
        let mut out = BTreeMap::new();
        for m in self.findings.values() {
            for (id, f) in m {
                out.insert(*id, f.clone());
            }
        }
        Ok((out, memory))
    }

    fn snapshot_bytes(&self) -> usize {
        self.finding_sizes
            .values()
            .fold(0usize, |total, bytes| total.saturating_add(*bytes))
            .saturating_mul(3)
    }

    /// The merged correlated-section maps: input to correlation and enrichment.
    pub fn correlated_findings(
        &self,
    ) -> Result<(BTreeMap<FindingId, Finding>, Reservation), macaudit::inventory::InventoryError>
    {
        let memory = MemoryBudget::shared().reserve(self.snapshot_bytes())?;
        let mut merged = BTreeMap::new();
        for id in CORRELATED_SECTIONS {
            if let Some(map) = self.findings.get(id) {
                for (fid, f) in map {
                    merged.insert(*fid, f.clone());
                }
            }
        }
        Ok((merged, memory))
    }

    /// Run cross-scanner correlation over the in-memory findings and write
    /// the results back. Returns the rewritten findings for the listener.
    pub fn correlate_now(&mut self) -> Result<(), macaudit::inventory::InventoryError> {
        let (mut merged, _memory) = self.correlated_findings()?;
        if merged.is_empty() {
            return Ok(());
        }
        correlate::correlate(&mut merged);
        for (fid, f) in merged {
            let _ = fid;
            self.upsert(f.kind.scanner(), &f);
        }
        Ok(())
    }

    /// Upsert enrichment results for `gen`; superseded batches are dropped.
    pub fn apply_enriched(&mut self, gen: u64, findings: Vec<Finding>) -> Vec<Finding> {
        if self.cancelled {
            return Vec::new();
        }
        let mut kept = Vec::new();
        for f in findings {
            let section = f.kind.scanner();
            if self.expected_gen.get(&section) == Some(&gen) {
                self.upsert(section, &f);
                kept.push(f);
            }
        }
        kept
    }
}

fn retained_finding_bytes(finding: &Finding) -> usize {
    finding_storage_bytes(finding).unwrap_or(usize::MAX)
}

pub struct RetainedFootprints {
    set: Arc<FootprintSet>,
    _memory: Reservation,
}

impl RetainedFootprints {
    fn new(set: Arc<FootprintSet>, budget: &Arc<MemoryBudget>) -> Result<Self, InventoryError> {
        let memory = budget.reserve(footprint_storage_bytes(&set)?)?;
        Ok(Self {
            set,
            _memory: memory,
        })
    }
}

impl std::ops::Deref for RetainedFootprints {
    type Target = FootprintSet;

    fn deref(&self) -> &Self::Target {
        &self.set
    }
}

impl AsRef<FootprintSet> for RetainedFootprints {
    fn as_ref(&self) -> &FootprintSet {
        &self.set
    }
}

/// Everything the pump, the engine and the enrichment task share.
pub struct Shared {
    pub run_gate: Mutex<()>,
    pub selected_root: Mutex<String>,
    pub publish: callback_channel::SyncSender<()>,
    pub queries: Mutex<QueryRegistry<mapping::DirEntry>>,
    pub query_budget: Arc<MemoryBudget>,
    pub query_reclaimer: OnceLock<Arc<MemoryReclaimer>>,
    pub query_slots: crate::queries::QueryAdmission,
    pub manager: Arc<ScannerManager>,
    pub session: Mutex<Session>,
    pub listener: Mutex<Option<Arc<dyn ScanListener>>>,
    /// The one long-lived scan channel, kept across rescans like the TUI's.
    pub tx: mpsc::Sender<ScanEvent>,
    /// Directory trees from the most recent completed Disk walk, one per
    /// root. Kept outside `session` so drill-down reads never contend with
    /// the pump, and replaced (not cleared) on rescan so the UI never blanks.
    pub dir_trees: RwLock<Vec<Arc<DirTree>>>,
    /// The latest admitted `FootprintSet` per attribution axis. Consumer
    /// leases survive producer retirement and clear when the run changes.
    /// `Engine::footprint`/`footprint_buckets` read this.
    pub footprints: RwLock<HashMap<Axis, RetainedFootprints>>,
}

impl Shared {
    fn reconcile_retired_run(&self) {
        let mut session = self.session.lock().unwrap();
        if let Some(run) = self.manager.current_run() {
            session.reconcile_retired(&run);
        }
    }

    pub fn register_query_reclaimer(self: &Arc<Self>) {
        let reclaimer = self.query_reclaimer.get_or_init(|| {
            let weak = Arc::downgrade(self);
            Arc::new(move || {
                let Some(shared) = weak.upgrade() else {
                    return;
                };
                if let Ok(mut queries) = shared.queries.try_lock() {
                    queries.clear();
                };
            })
        });
        self.query_budget.register_reclaimer(reclaimer);
    }

    /// Start (or restart) a scan of `sections`, reporting to the current
    /// listener. Locks the session across `manager.start` so the pump cannot
    /// see the new generation's events before `begin_scan` expects them.
    pub fn start_run(
        &self,
        root: String,
        listener: Option<Arc<dyn ScanListener>>,
    ) -> Result<u64, crate::MacAuditError> {
        let home = &self.manager.paths().home;
        let root = RunRequest::resolve_root(std::path::Path::new(&root), home, home)
            .map_err(|error| crate::MacAuditError::Invalid(error.to_string()))?;
        crate::supported_path(&root)?;
        let mut session = self.session.lock().unwrap();
        let _guard = runtime().enter();
        let gen = self
            .manager
            .start_run(&self.tx, RunRequest::new(root))
            .map_err(|error| crate::MacAuditError::Invalid(error.to_string()))?
            .0;
        session.begin_scan(gen, ScannerId::ALL);
        self.dir_trees.write().unwrap().clear();
        self.footprints.write().unwrap().clear();
        *self.queries.lock().unwrap() = QueryRegistry::new(gen, self.query_budget.clone());
        if let Some(listener) = listener {
            *self.listener.lock().unwrap() = Some(listener);
        }
        if let Some(metadata) = self.manager.current_run() {
            *self.selected_root.lock().unwrap() = metadata
                .request
                .selected_root
                .to_string_lossy()
                .into_owned();
        }
        let _ = self.publish.try_send(());
        Ok(gen)
    }

    fn emit(&self, ev: mapping::ScanEvent) {
        if ev.generation() != self.session.lock().unwrap().run_id {
            return;
        }
        let listener = self.listener.lock().unwrap().clone();
        if let Some(l) = listener {
            l.on_event(ev);
        }
    }

    fn emit_all(&self, evs: Vec<mapping::ScanEvent>) {
        for ev in evs {
            self.emit(ev);
        }
    }
}

pub fn dispatch(rx: callback_channel::Receiver<()>, weak: Weak<Shared>) {
    let mut gen = 0;
    let mut revision = 0;
    let mut statuses = HashMap::new();
    let mut progress = HashMap::new();
    let mut inventories = HashMap::new();
    while rx.recv().is_ok() {
        let Some(shared) = weak.upgrade() else {
            return;
        };
        let (current, current_revision) = {
            let session = shared.session.lock().unwrap();
            (session.run_id, session.query_revision)
        };
        let timing = crate::diagnostics::publication(current, current_revision);
        let _timing = timing.enter();
        if current != gen {
            gen = current;
            revision = 0;
            statuses.clear();
            progress.clear();
            inventories.clear();
            for section in ScannerId::ALL {
                shared.emit(mapping::ScanEvent::SectionStarted {
                    section: (*section).into(),
                    gen,
                });
                statuses.insert(*section, Status::Scanning);
            }
        }
        {
            let changes = {
                let session = shared.session.lock().unwrap();
                if session.run_id != gen {
                    continue;
                }
                session.changes(revision)
            };
            match changes {
                Ok((changes, _publication_memory)) => {
                    timing.record("rows", changes.len());
                    timing.record("reserved_bytes", _publication_memory.bytes());
                    let mut batches: HashMap<ScannerId, Vec<mapping::Finding>> = HashMap::new();
                    let mut metadata_bytes = 0;
                    for (next, section, finding) in changes {
                        revision = next;
                        let finding = mapping::Finding::from(&finding);
                        metadata_bytes += finding.meta_json.len();
                        batches.entry(section).or_default().push(finding);
                    }
                    timing.record("bytes", metadata_bytes);
                    for (section, findings) in batches {
                        shared.emit(mapping::ScanEvent::Findings {
                            section: section.into(),
                            gen,
                            findings,
                        });
                    }
                }
                Err(error) => {
                    let _gate = shared.run_gate.lock().unwrap();
                    let mut session = shared.session.lock().unwrap();
                    if session.run_id == gen {
                        revision = session.revision;
                        for section in ScannerId::ALL {
                            session.resource_limited.insert(*section);
                            session
                                .status
                                .insert(*section, Status::Failed(error.to_string()));
                        }
                        shared
                            .manager
                            .resource_limited(macaudit::engine::RunId(gen), ScannerId::Fs);
                    }
                }
            }
        }
        let events = {
            let session = shared.session.lock().unwrap();
            if session.run_id != gen {
                continue;
            }
            let mut events = Vec::new();
            for (section, revision) in &session.inventory_revisions {
                if inventories.get(section) != Some(revision) {
                    inventories.insert(*section, *revision);
                    events.push(mapping::ScanEvent::Findings {
                        section: (*section).into(),
                        gen,
                        findings: Vec::new(),
                    });
                }
            }
            for (section, event) in &session.progress {
                if progress.get(section) != Some(event) {
                    progress.insert(*section, event.clone());
                    events.push(event.clone());
                }
            }
            if session.revision <= revision {
                for section in ScannerId::ALL {
                    let status = session.status_of(*section);
                    if statuses.get(section) == Some(&status) {
                        continue;
                    }
                    statuses.insert(*section, status.clone());
                    match status {
                        Status::Done => events.push(mapping::ScanEvent::SectionFinished {
                            section: (*section).into(),
                            gen,
                            duration_ms: session
                                .durations
                                .get(section)
                                .copied()
                                .unwrap_or_default(),
                        }),
                        Status::Failed(error) => events.push(mapping::ScanEvent::SectionFailed {
                            section: (*section).into(),
                            gen,
                            error,
                        }),
                        _ => {}
                    }
                }
            }
            events
        };
        shared.emit_all(events);
    }
}

/// Drain the engine channel forever: apply each event to the session, batch
/// what goes to Swift, and run the post-scan steps (correlate, enrich)
/// exactly as the TUI loop does.
///
/// Holds the session weakly: `Shared` owns the channel's sender, so a strong
/// reference here would keep the channel open (and this task alive) after
/// the app drops its `Engine`. When the engine is gone, the pump exits.
pub async fn pump(mut rx: mpsc::Receiver<ScanEvent>, weak: Weak<Shared>) {
    let mut ticks = tokio::time::interval(FLUSH_INTERVAL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = ticks.tick() => {
                let Some(shared) = weak.upgrade() else { return; };
                shared.reconcile_retired_run();
                let _ = shared.publish.try_send(());
            }
            event = rx.recv() => {
                let Some(event) = event else { return; };
                let Some(shared) = weak.upgrade() else { return; };
                let terminal = matches!(event, ScanEvent::Finished { .. } | ScanEvent::Failed { .. });
                {
                    let _gate = shared.run_gate.lock().unwrap();
                    let mut session = shared.session.lock().unwrap();
                    let limited = session.resource_limited();
                    if !session.apply(&event) { continue; }
                    if !limited && session.resource_limited() {
                        shared.manager.resource_limited(macaudit::engine::RunId(session.run_id), event.scanner());
                    }
                    drop(session);
                    match event {
                        ScanEvent::DirTree { tree, .. } => {
                            let mut trees = shared.dir_trees.write().unwrap();
                            trees.retain(|current| current.root != tree.root);
                            trees.push(tree);
                        }
                        ScanEvent::Footprints { scanner, set, .. } => {
                            match RetainedFootprints::new(set, &shared.query_budget) {
                                Ok(set) => {
                                    shared.footprints.write().unwrap().insert(set.axis, set);
                                }
                                Err(error) => {
                                    let mut session = shared.session.lock().unwrap();
                                    session.resource_limited.insert(scanner);
                                    session.status.insert(scanner, Status::Failed(error.to_string()));
                                    let run_id = macaudit::engine::RunId(session.run_id);
                                    drop(session);
                                    shared.manager.resource_limited(run_id, scanner);
                                    let _ = shared.publish.try_send(());
                                }
                            }
                        }
                        _ => {},
                    }
                }
                if terminal { after_terminal(&shared); }
            }
        }
    }
}

/// Correlate once the correlated sections are terminal (once per full-scan
/// generation), then kick off enrichment when online.
fn after_terminal(shared: &Arc<Shared>) {
    let mut enrich: Option<(
        u64,
        BTreeMap<FindingId, Finding>,
        Reservation,
        CancellationToken,
    )> = None;
    {
        let _gate = shared.run_gate.lock().unwrap();
        let mut session = shared.session.lock().unwrap();
        if session.correlated_gen != session.full_scan_gen
            && session.sections_terminal(CORRELATED_SECTIONS)
        {
            let gen = session.full_scan_gen;
            session.correlated_gen = gen;
            if let Err(error) = session.correlate_now() {
                for section in CORRELATED_SECTIONS {
                    session.resource_limited.insert(*section);
                    session
                        .status
                        .insert(*section, Status::Failed(error.to_string()));
                }
                shared
                    .manager
                    .resource_limited(macaudit::engine::RunId(gen), ScannerId::Apps);
                let _ = shared.publish.try_send(());
                return;
            }
            if shared.manager.fetcher().is_some() {
                match session.correlated_findings() {
                    Ok((map, memory)) => {
                        enrich = Some((
                            gen,
                            map,
                            memory,
                            shared.manager.run_token().unwrap_or_default(),
                        ))
                    }
                    Err(error) => {
                        session.resource_limited.insert(ScannerId::Apps);
                        session
                            .status
                            .insert(ScannerId::Apps, Status::Failed(error.to_string()));
                        shared
                            .manager
                            .resource_limited(macaudit::engine::RunId(gen), ScannerId::Apps);
                    }
                }
            }
        }
    }
    let _ = shared.publish.try_send(());

    if let Some((gen, mut map, memory, token)) = enrich {
        let shared = shared.clone();
        runtime().spawn(async move {
            let manager = shared.manager.clone();
            let _memory = memory;
            macaudit::net::enrich(
                &mut map,
                manager.fetcher(),
                &manager.paths(),
                &manager.config(),
                &token,
            )
            .await;
            if token.is_cancelled() {
                return;
            }
            // Only findings enrichment actually touched (catalog matches carry
            // `available_cask`; the release check only runs on those).
            let changed: Vec<Finding> = map
                .into_values()
                .filter(|f| f.kind == FindingKind::App && f.meta.get("available_cask").is_some())
                .collect();
            let kept = {
                let mut session = shared.session.lock().unwrap();
                session.apply_enriched(gen, changed)
            };
            if !kept.is_empty() {
                let _ = shared.publish.try_send(());
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use macaudit::engine::{Completeness, ContextMetadata, RunContext, RunId};

    fn retired_run(run_id: u64) -> RunMetadata {
        let context = |context| ContextMetadata {
            context,
            completeness: Completeness::Partial,
            completed_sections: Vec::new(),
            failed_sections: Vec::new(),
            coverage: None,
            stop_reasons: vec![RunStopReason::ResourceLimited],
            discovery: None,
        };
        RunMetadata {
            run_id: RunId(run_id),
            request: RunRequest::new("/fixture"),
            disk: context(RunContext::Disk {
                selected_root: "/fixture".into(),
            }),
            audit_host: context(RunContext::AuditHost {
                home: "/fixture".into(),
            }),
            active_scanners: 0,
            retiring_count: 0,
            retiring_runs: Vec::new(),
        }
    }

    #[test]
    fn retirement_reconciliation_rejects_stale_active_and_unstopped_runs() {
        let mut session = Session::default();
        session.begin_scan(7, ScannerId::ALL);
        assert!(!session.reconcile_retired(&retired_run(6)));
        let mut run = retired_run(7);
        run.active_scanners = 1;
        assert!(!session.reconcile_retired(&run));
        run.active_scanners = 0;
        run.disk.stop_reasons.clear();
        run.audit_host.stop_reasons.clear();
        assert!(!session.reconcile_retired(&run));
        assert!(!session.cancelled);
        assert!(matches!(
            session.status_of(ScannerId::Apps),
            Status::Scanning
        ));
    }

    #[test]
    fn retirement_reconciliation_preserves_findings_and_terminal_errors() {
        let mut session = Session::default();
        session.begin_scan(7, ScannerId::ALL);
        let finding = macaudit::fake::fixtures(ScannerId::Apps)
            .into_iter()
            .next()
            .unwrap();
        session.apply(&ScanEvent::Finding {
            scanner: ScannerId::Apps,
            gen: 7,
            finding: Box::new(finding),
        });
        session.apply(&ScanEvent::Failed {
            scanner: ScannerId::Apps,
            gen: 7,
            error: "specific scanner failure".into(),
        });
        let mut run = retired_run(7);
        run.disk.completed_sections.push(ScannerId::Fs);
        assert!(session.reconcile_retired(&run));
        assert_eq!(session.status_of(ScannerId::Fs), Status::Done);
        assert_eq!(
            session.status_of(ScannerId::Apps),
            Status::Failed("specific scanner failure".into())
        );
        assert_eq!(session.findings_page(ScannerId::Apps, 0, 500).len(), 1);
        assert!(!session.reconcile_retired(&run));
        assert!(!session.apply(&ScanEvent::Started {
            scanner: ScannerId::Apps,
            gen: 7
        }));
        assert_eq!(session.findings_page(ScannerId::Apps, 0, 500).len(), 1);
    }

    #[test]
    fn retirement_reconciliation_uses_the_subjects_stop_reason() {
        let mut session = Session::default();
        session.begin_scan(7, ScannerId::ALL);
        let mut run = retired_run(7);
        run.disk.stop_reasons = vec![RunStopReason::Cancelled];
        assert!(session.reconcile_retired(&run));
        assert_eq!(
            session.status_of(ScannerId::Fs),
            Status::Failed("cancelled; partial results retained".into())
        );
        assert_eq!(
            session.status_of(ScannerId::Apps),
            Status::Failed("resource limit; partial results retained".into())
        );
    }

    #[test]
    fn cancellation_keeps_partial_findings_and_rejects_late_completion() {
        let mut session = Session::default();
        session.begin_scan(7, ScannerId::ALL);
        session.cancel();
        let finding = macaudit::fake::fixtures(ScannerId::Apps)
            .into_iter()
            .next()
            .unwrap();
        assert!(session.apply(&ScanEvent::Finding {
            scanner: ScannerId::Apps,
            gen: 7,
            finding: Box::new(finding)
        }));
        assert!(!session.apply(&ScanEvent::Finished {
            scanner: ScannerId::Apps,
            gen: 7,
            duration: Duration::ZERO
        }));
        assert_eq!(session.findings_page(ScannerId::Apps, 0, 500).len(), 1);
        assert!(matches!(
            session.status_of(ScannerId::Apps),
            Status::Failed(_)
        ));
        session.begin_scan(8, ScannerId::ALL);
        assert!(!session.apply(&ScanEvent::Finished {
            scanner: ScannerId::Apps,
            gen: 7,
            duration: Duration::ZERO
        }));
        assert!(session.findings_page(ScannerId::Apps, 0, 500).is_empty());
    }

    #[test]
    fn finding_admission_fails_before_retention_when_budget_is_exhausted() {
        let mut session = Session::default();
        session.begin_scan(7, ScannerId::ALL);
        let budget = MemoryBudget::new(64);
        session.memory = Some(budget.reserve(0).unwrap());
        let finding = macaudit::fake::fixtures(ScannerId::Apps)
            .into_iter()
            .next()
            .unwrap();
        session.upsert(ScannerId::Apps, &finding);
        assert!(session.resource_limited());
        assert_eq!(budget.used(), 0);
        assert!(session.findings_page(ScannerId::Apps, 0, 500).is_empty());
    }

    #[test]
    fn dense_metadata_heap_is_reserved_before_finding_retention() {
        let mut session = Session::default();
        session.begin_scan(7, ScannerId::ALL);
        let budget = MemoryBudget::new(4096);
        session.memory = Some(budget.reserve(0).unwrap());
        let mut finding = macaudit::fake::fixtures(ScannerId::Apps)
            .into_iter()
            .next()
            .unwrap();
        finding.title = "x".into();
        finding.detail.clear();
        finding.remedies.clear();
        finding.meta = serde_json::Value::Object(
            (0..100)
                .map(|index| (index.to_string(), serde_json::Value::Null))
                .collect(),
        );
        assert!(macaudit::inventory::serialized_size(&finding).unwrap() < budget.limit());
        assert!(retained_finding_bytes(&finding) > budget.limit());
        session.upsert(ScannerId::Apps, &finding);
        assert!(session.resource_limited());
        assert_eq!(budget.used(), 0);
        assert!(session.findings_page(ScannerId::Apps, 0, 500).is_empty());
    }

    fn sparse_footprints() -> Arc<FootprintSet> {
        Arc::new(FootprintSet {
            axis: Axis::Projects,
            gen: 7,
            footprints: Vec::new(),
            baseline: Vec::with_capacity(4096),
            unattributed: Vec::new(),
            disk_total: 0,
            attributed_total: 0,
            missing_deps: Vec::new(),
        })
    }

    #[test]
    fn footprint_consumer_lease_survives_producer_release() {
        let set = sparse_footprints();
        let bytes = footprint_storage_bytes(&set).unwrap();
        let budget = MemoryBudget::new(bytes);
        let retained = RetainedFootprints::new(set.clone(), &budget).unwrap();
        assert_eq!(budget.used(), bytes);
        drop(set);
        assert_eq!(budget.used(), bytes);
        drop(retained);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn footprint_admission_counts_spare_capacity_before_retention() {
        let set = sparse_footprints();
        let budget = MemoryBudget::new(4096);
        assert!(macaudit::inventory::serialized_size(set.as_ref()).unwrap() < budget.limit());
        assert!(matches!(
            RetainedFootprints::new(set, &budget),
            Err(InventoryError::ResourceLimit)
        ));
        assert_eq!(budget.used(), 0);
    }
}
