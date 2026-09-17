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
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use macaudit::attribution::model::{Axis, FootprintSet};
use macaudit::correlate::{self, CORRELATED_SECTIONS};
use macaudit::engine::ScannerManager;
use macaudit::model::{Finding, FindingId, FindingKind, ScanEvent, ScannerId};
use macaudit::scan::walk::DirTree;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::mapping;
use crate::runtime::runtime;
use crate::ScanListener;

/// Flush pending finding batches at least this often while a scan streams.
const FLUSH_INTERVAL: Duration = Duration::from_millis(50);
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
        match ev {
            ScanEvent::Started { scanner, .. } => {
                self.findings.entry(*scanner).or_default().clear();
                self.status.insert(*scanner, Status::Scanning);
            }
            ScanEvent::Progress { .. } => {}
            ScanEvent::Finding {
                scanner, finding, ..
            } => {
                self.findings
                    .entry(*scanner)
                    .or_default()
                    .insert(finding.id, (**finding).clone());
            }
            ScanEvent::Finished { scanner, .. } => {
                self.status.insert(*scanner, Status::Done);
            }
            ScanEvent::Failed { scanner, error, .. } => {
                self.status.insert(*scanner, Status::Failed(error.clone()));
            }
            // Stored on `Shared` by the pump (outside this lock); accepted here
            // so the gen check above still gates it.
            ScanEvent::DirTree { .. } => {}
            ScanEvent::Footprints { .. } => {}
        }
        true
    }

    pub fn status_of(&self, id: ScannerId) -> Status {
        self.status.get(&id).cloned().unwrap_or(Status::Idle)
    }

    pub fn sections_terminal(&self, sections: &[ScannerId]) -> bool {
        sections
            .iter()
            .all(|id| matches!(self.status_of(*id), Status::Done | Status::Failed(_)))
    }

    pub fn section_findings(&self, id: ScannerId) -> Vec<Finding> {
        self.findings
            .get(&id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn all_findings(&self) -> BTreeMap<FindingId, Finding> {
        let mut out = BTreeMap::new();
        for m in self.findings.values() {
            for (id, f) in m {
                out.insert(*id, f.clone());
            }
        }
        out
    }

    /// The merged correlated-section maps: input to correlation and enrichment.
    pub fn correlated_findings(&self) -> BTreeMap<FindingId, Finding> {
        let mut merged = BTreeMap::new();
        for id in CORRELATED_SECTIONS {
            if let Some(map) = self.findings.get(id) {
                for (fid, f) in map {
                    merged.insert(*fid, f.clone());
                }
            }
        }
        merged
    }

    /// Run cross-scanner correlation over the in-memory findings and write
    /// the results back. Returns the rewritten findings for the listener.
    pub fn correlate_now(&mut self) -> Vec<Finding> {
        let mut merged = self.correlated_findings();
        if merged.is_empty() {
            return Vec::new();
        }
        correlate::correlate(&mut merged);
        let out: Vec<Finding> = merged.values().cloned().collect();
        for (fid, f) in merged {
            self.findings
                .entry(f.kind.scanner())
                .or_default()
                .insert(fid, f);
        }
        out
    }

    /// Upsert enrichment results for `gen`; superseded batches are dropped.
    pub fn apply_enriched(&mut self, gen: u64, findings: Vec<Finding>) -> Vec<Finding> {
        let mut kept = Vec::new();
        for f in findings {
            let section = f.kind.scanner();
            if self.expected_gen.get(&section) == Some(&gen) {
                self.findings
                    .entry(section)
                    .or_default()
                    .insert(f.id, f.clone());
                kept.push(f);
            }
        }
        kept
    }
}

/// Everything the pump, the engine and the enrichment task share.
pub struct Shared {
    pub manager: Arc<ScannerManager>,
    pub session: Mutex<Session>,
    pub listener: Mutex<Option<Arc<dyn ScanListener>>>,
    /// The one long-lived scan channel, kept across rescans like the TUI's.
    pub tx: mpsc::Sender<ScanEvent>,
    /// Directory trees from the most recent completed Disk walk, one per
    /// root. Kept outside `session` so drill-down reads never contend with
    /// the pump, and replaced (not cleared) on rescan so the UI never blanks.
    pub dir_trees: RwLock<Vec<Arc<DirTree>>>,
    /// The latest `FootprintSet` per attribution axis. Kept outside
    /// `session` for the same reason as `dir_trees`, and replaced (not
    /// cleared) on rescan. `Engine::footprint`/`footprint_buckets` read this.
    pub footprints: RwLock<HashMap<Axis, Arc<FootprintSet>>>,
}

impl Shared {
    /// Start (or restart) a scan of `sections`, reporting to the current
    /// listener. Locks the session across `manager.start` so the pump cannot
    /// see the new generation's events before `begin_scan` expects them.
    pub fn start_scan(&self, sections: &[ScannerId]) -> u64 {
        let mut session = self.session.lock().unwrap();
        let _guard = runtime().enter();
        let gen = self.manager.start(&self.tx, sections);
        session.begin_scan(gen, sections);
        gen
    }

    fn emit(&self, ev: mapping::ScanEvent) {
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

/// Pending per-section batches between flushes. Progress is coalesced to
/// the latest message per section; findings accumulate in arrival order.
#[derive(Default)]
struct Pending {
    findings: Vec<(ScannerId, u64, Vec<mapping::Finding>)>,
    progress: HashMap<ScannerId, mapping::ScanEvent>,
    count: usize,
}

impl Pending {
    fn push_finding(&mut self, scanner: ScannerId, gen: u64, f: mapping::Finding) {
        match self.findings.last_mut() {
            Some((s, g, batch)) if *s == scanner && *g == gen => batch.push(f),
            _ => self.findings.push((scanner, gen, vec![f])),
        }
        self.count += 1;
    }

    fn drain(&mut self) -> Vec<mapping::ScanEvent> {
        let mut out = Vec::new();
        for (scanner, gen, findings) in self.findings.drain(..) {
            out.push(mapping::ScanEvent::Findings {
                section: scanner.into(),
                gen,
                findings,
            });
        }
        for (_, ev) in self.progress.drain() {
            out.push(ev);
        }
        self.count = 0;
        out
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
    let mut pending = Pending::default();
    loop {
        let Some(shared) = weak.upgrade() else {
            return;
        };
        match tokio::time::timeout(FLUSH_INTERVAL, rx.recv()).await {
            Ok(Some(ev)) => {
                let (accepted, terminal) = {
                    let mut session = shared.session.lock().unwrap();
                    let accepted = session.apply(&ev);
                    let terminal =
                        matches!(ev, ScanEvent::Finished { .. } | ScanEvent::Failed { .. });
                    (accepted, terminal)
                };
                if !accepted {
                    continue;
                }
                let scanner = ev.scanner();
                let gen = ev.generation();
                match ev {
                    ScanEvent::Started { .. } => {
                        shared.emit_all(pending.drain());
                        shared.emit(mapping::ScanEvent::SectionStarted {
                            section: scanner.into(),
                            gen,
                        });
                    }
                    ScanEvent::Progress {
                        msg, done, total, ..
                    } => {
                        pending.progress.insert(
                            scanner,
                            mapping::ScanEvent::Progress {
                                section: scanner.into(),
                                gen,
                                msg,
                                done,
                                total,
                            },
                        );
                    }
                    ScanEvent::Finding { finding, .. } => {
                        pending.push_finding(scanner, gen, mapping::Finding::from(&*finding));
                        if pending.count >= FLUSH_THRESHOLD {
                            shared.emit_all(pending.drain());
                        }
                    }
                    ScanEvent::Finished { duration, .. } => {
                        shared.emit_all(pending.drain());
                        shared.emit(mapping::ScanEvent::SectionFinished {
                            section: scanner.into(),
                            gen,
                            duration_ms: duration.as_millis() as u64,
                        });
                    }
                    ScanEvent::Failed { error, .. } => {
                        shared.emit_all(pending.drain());
                        shared.emit(mapping::ScanEvent::SectionFailed {
                            section: scanner.into(),
                            gen,
                            error,
                        });
                    }
                    ScanEvent::DirTree { tree, .. } => {
                        let mut trees = shared.dir_trees.write().unwrap();
                        trees.retain(|t| t.root != tree.root);
                        trees.push(tree);
                    }
                    ScanEvent::Footprints { set, .. } => {
                        shared.footprints.write().unwrap().insert(set.axis, set);
                    }
                }
                if terminal {
                    after_terminal(&shared);
                }
            }
            Ok(None) => {
                shared.emit_all(pending.drain());
                return;
            }
            Err(_elapsed) => {
                shared.emit_all(pending.drain());
            }
        }
    }
}

/// Correlate once the correlated sections are terminal (once per full-scan
/// generation), then kick off enrichment when online.
fn after_terminal(shared: &Arc<Shared>) {
    let mut events = Vec::new();
    let mut enrich: Option<(u64, BTreeMap<FindingId, Finding>)> = None;
    {
        let mut session = shared.session.lock().unwrap();
        if session.correlated_gen != session.full_scan_gen
            && session.sections_terminal(CORRELATED_SECTIONS)
        {
            let gen = session.full_scan_gen;
            session.correlated_gen = gen;
            let rewritten = session.correlate_now();
            if !rewritten.is_empty() {
                events.push(mapping::ScanEvent::Correlated {
                    gen,
                    findings: mapping::findings(rewritten),
                });
            }
            if shared.manager.fetcher().is_some() {
                enrich = Some((gen, session.correlated_findings()));
            }
        }
    }
    shared.emit_all(events);

    if let Some((gen, mut map)) = enrich {
        let shared = shared.clone();
        runtime().spawn(async move {
            let manager = shared.manager.clone();
            let token = CancellationToken::new();
            macaudit::net::enrich(
                &mut map,
                manager.fetcher(),
                &manager.paths(),
                &manager.config(),
                &token,
            )
            .await;
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
                shared.emit(mapping::ScanEvent::Enriched {
                    gen,
                    findings: mapping::findings(kept),
                });
            }
        });
    }
}
