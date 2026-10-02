//! Scan-event ingestion and section-status bookkeeping: the reducer's "what
//! did the scanners report" half. `apply`, `begin_scan`, and `apply_enriched`
//! are the sole mutation paths for `findings` — upsert-by-id keeps
//! sizes/dedup correct. The read-only helpers here (`status_of`,
//! `section_count`, ...) back the sidebar, the Resource Health overview, and
//! the run loop's rescan bookkeeping.

use std::collections::BTreeMap;

use crate::config::DeleteMode;
use crate::model::{Finding, FindingId, FindingKind, ScanEvent, ScannerId, Severity};
use crate::ui::app::{AppState, SectionStatus};

pub use crate::correlate::CORRELATED_SECTIONS;

impl AppState {
    pub(super) fn result_memory(&self) -> Vec<std::sync::Arc<crate::inventory::Reservation>> {
        self.finding_memory.values().cloned().collect()
    }

    fn retain_finding(&mut self, scanner: ScannerId, finding: Finding) {
        match crate::engine::finding_reservation(&finding, &self.memory_budget) {
            Ok(memory) => {
                self.finding_memory
                    .insert(finding.id, std::sync::Arc::new(memory));
                self.findings
                    .entry(scanner)
                    .or_default()
                    .insert(finding.id, finding);
            }
            Err(_) => self.result_resource_limit(scanner),
        }
    }

    fn result_resource_limit(&mut self, scanner: ScannerId) {
        self.pending_resource_limit.get_or_insert(scanner);
        self.status.insert(
            scanner,
            SectionStatus::Failed {
                error: "resource limit: TUI result storage budget exhausted".to_string(),
            },
        );
    }
    pub(crate) fn delete_mode(&self) -> DeleteMode {
        self.delete_mode
    }

    /// Set the delete mode used when planning remedies (wired from `Config` by
    /// the run loop, honoring `--rm`).
    pub fn set_delete_mode(&mut self, mode: DeleteMode) {
        self.delete_mode = mode;
    }

    /// Which section currently holds a finding, for post-remedy targeted rescan.
    pub fn section_of(&self, id: FindingId) -> Option<ScannerId> {
        self.findings
            .iter()
            .find(|(_, m)| m.contains_key(&id))
            .map(|(s, _)| *s)
    }

    /// A flat copy of every current finding, keyed by id.
    pub fn all_findings(&self) -> BTreeMap<FindingId, Finding> {
        let mut out = BTreeMap::new();
        for m in self.findings.values() {
            for (id, f) in m {
                out.insert(*id, f.clone());
            }
        }
        out
    }

    /// Whether every listed section is Done or Failed.
    pub fn sections_terminal(&self, sections: &[ScannerId]) -> bool {
        sections.iter().all(|id| {
            matches!(
                self.status_of(*id),
                SectionStatus::Done { .. } | SectionStatus::Failed { .. }
            )
        })
    }

    /// A merged copy of the correlated section maps — the input to both
    /// sync correlation and the async network-enrichment task.
    pub fn apps_brew_findings(&self) -> BTreeMap<FindingId, Finding> {
        let mut merged: BTreeMap<FindingId, Finding> = BTreeMap::new();
        for id in CORRELATED_SECTIONS {
            if let Some(map) = self.findings.get(id) {
                for (fid, f) in map {
                    merged.insert(*fid, f.clone());
                }
            }
        }
        merged
    }

    /// Run cross-scanner correlation over the in-memory findings (the TUI
    /// equivalent of the headless path's `correlate()` call): merge the Apps +
    /// Brew section maps, correlate, write mutated findings back to their
    /// sections. Sync and cheap (hundreds of items); call once both sections
    /// are terminal so cask labels appear in the TUI.
    pub fn correlate_now(&mut self) {
        let mut merged = self.apps_brew_findings();
        if merged.is_empty() {
            return;
        }
        crate::correlate::correlate(&mut merged);
        self.brew_version += 1;
        for f in merged.into_values() {
            self.retain_finding(f.kind.scanner(), f);
        }
    }

    /// Upsert a batch of enriched findings (async network enrichment results)
    /// for generation `gen`. Batches from superseded generations are dropped:
    /// every enriched finding's section must still expect `gen`.
    pub fn apply_enriched(&mut self, gen: u64, findings: Vec<Finding>) {
        if self.scan_cancelled {
            return;
        }
        for f in findings {
            let section = f.kind.scanner();
            if self.expected_gen.get(&section) == Some(&gen) {
                self.retain_finding(section, f);
            }
        }
    }

    /// Append a line to the activity log (capped so it can't grow unbounded
    /// across a long session).
    pub fn push_activity(&mut self, line: String) {
        self.activity.push(line);
        if self.activity.len() > 200 {
            self.activity.remove(0);
        }
    }

    /// Apply a scan event. Accepts an event only when its gen EXACTLY matches
    /// the section's expected gen — `<` drops superseded/cancelled runs, and
    /// `>` drops runs the UI never requested for that section (the discovery-
    /// only Fs helper spawned by a git-only rescan, whose `Started{Fs}` would
    /// otherwise wipe the Disk pane). This is the sole mutation path for
    /// findings; upsert-by-id keeps sizes/dedup correct.
    pub fn apply(&mut self, ev: ScanEvent) {
        if self.expected_gen.get(&ev.scanner()) != Some(&ev.generation()) {
            return;
        }
        if self.scan_cancelled
            && matches!(
                ev,
                ScanEvent::Started { .. } | ScanEvent::Progress { .. } | ScanEvent::Finished { .. }
            )
        {
            return;
        }
        match ev {
            ScanEvent::Started { scanner, .. } => {
                if let Some(findings) = self.findings.get(&scanner) {
                    for id in findings.keys() {
                        self.finding_memory.remove(id);
                    }
                }
                self.findings.entry(scanner).or_default().clear();
                if scanner == ScannerId::Fs {
                    self.dir_trees.clear();
                }
                if scanner == ScannerId::Brew {
                    self.brew_version += 1;
                }
                self.status.insert(
                    scanner,
                    SectionStatus::Scanning {
                        done: 0,
                        total: None,
                        msg: String::new(),
                    },
                );
            }
            ScanEvent::Progress {
                scanner,
                msg,
                done,
                total,
                ..
            } => {
                self.status
                    .insert(scanner, SectionStatus::Scanning { done, total, msg });
            }
            ScanEvent::Finding {
                scanner, finding, ..
            } => {
                if scanner == ScannerId::Brew {
                    self.brew_version += 1;
                }
                self.retain_finding(scanner, *finding);
            }
            ScanEvent::Finished {
                scanner, duration, ..
            } => {
                self.status
                    .insert(scanner, SectionStatus::Done { duration });
                if scanner == ScannerId::Brew {
                    self.brew_version += 1;
                }
                self.drop_stale_marks(scanner);
            }
            ScanEvent::Failed { scanner, error, .. } => {
                if self.scan_cancelled
                    && error == "run cancelled"
                    && matches!(
                        self.status.get(&scanner),
                        Some(SectionStatus::Failed { .. })
                    )
                {
                    return;
                }
                self.status.insert(scanner, SectionStatus::Failed { error });
                self.drop_stale_marks(scanner);
            }
            ScanEvent::DirTree { tree, .. } => {
                self.dir_trees.insert(tree.root.clone(), tree);
            }
            ScanEvent::Footprints { set, .. } => {
                let memory = crate::engine::footprint_reservation(&set, &self.memory_budget);
                match memory {
                    Ok(memory) => {
                        self.footprint_memory
                            .insert(set.axis, std::sync::Arc::new(memory));
                        self.footprints.insert(set.axis, set);
                    }
                    Err(_) => self.result_resource_limit(set.axis.scanner()),
                }
            }
        }
    }

    /// After a section re-scans, marks (and remedy choices) whose findings no
    /// longer exist are dropped and announced, and an open confirm dialog is
    /// rebuilt so it cannot reference a vanished target.
    fn drop_stale_marks(&mut self, scanner: ScannerId) {
        if self.marked.is_empty() {
            return;
        }
        let present: std::collections::HashSet<FindingId> = self
            .findings
            .values()
            .flat_map(|m| m.keys().copied())
            .collect();
        let stale: Vec<FindingId> = self
            .marked
            .iter()
            .filter(|id| !present.contains(id))
            .copied()
            .collect();
        if stale.is_empty() {
            return;
        }
        for id in &stale {
            self.marked.remove(id);
            self.remedy_choice.remove(id);
        }
        self.push_activity(format!(
            "dropped {} stale mark(s) after rescanning {}",
            stale.len(),
            scanner.slug()
        ));
        if self.mode == crate::ui::app::Mode::Confirm {
            self.confirm = None;
            self.mode = crate::ui::app::Mode::Normal;
            self.open_confirm();
        }
    }

    /// Reset the given sections to Scanning-pending and register `gen` as their
    /// expected generation. Callers pass the *requested* set, never the
    /// engine's planned set (the discovery-only Fs helper must stay
    /// unexpected so its events are dropped).
    pub fn begin_scan(&mut self, gen: u64, _sections: &[ScannerId]) {
        self.scan_cancelled = false;
        self.findings.clear();
        self.finding_memory.clear();
        self.footprint_memory.clear();
        self.pending_resource_limit = None;
        self.dir_trees.clear();
        self.footprints.clear();
        self.marked.clear();
        self.remedy_choice.clear();
        self.confirm = None;
        if matches!(
            self.mode,
            crate::ui::app::Mode::Confirm | crate::ui::app::Mode::Preview
        ) {
            self.mode = crate::ui::app::Mode::Normal;
        }
        self.pending_execute = None;
        self.browse = crate::ui::browse::BrowseState::default();
        self.selected_row = 0;
        self.detail_scroll = 0;
        self.collapsed_groups.clear();
        self.expanded_nodes.clear();
        self.brew_graph.replace(None);
        self.brew_version += 1;
        self.expected_gen.clear();
        for id in ScannerId::ALL {
            self.expected_gen.insert(*id, gen);
        }
        for id in ScannerId::ALL {
            self.findings.entry(*id).or_default().clear();
            self.status.insert(
                *id,
                SectionStatus::Scanning {
                    done: 0,
                    total: None,
                    msg: String::new(),
                },
            );
        }
    }

    pub fn begin_run(&mut self, run: &crate::engine::RunMetadata) {
        self.selected_root = run.request.selected_root.clone();
        self.retiring_count = run.retiring_count;
        self.begin_scan(run.run_id.0, ScannerId::ALL);
        if self.mode == crate::ui::app::Mode::Browse {
            self.browse.path = self.selected_root.clone();
        }
        self.push_activity(format!(
            "run {} · Disk {} · audits: host home",
            run.run_id.0,
            self.selected_root.display()
        ));
    }

    pub(super) fn reconcile_run(&mut self, run: &crate::engine::RunMetadata) {
        use crate::engine::{Completeness, RunStopReason};

        if run.active_scanners != 0
            || ScannerId::ALL
                .iter()
                .any(|scanner| self.expected_gen.get(scanner) != Some(&run.run_id.0))
        {
            return;
        }
        self.scan_cancelled |= [&run.disk, &run.audit_host].iter().any(|context| {
            context.completeness == Completeness::Cancelled
                || context.stop_reasons.contains(&RunStopReason::Cancelled)
                || context
                    .stop_reasons
                    .contains(&RunStopReason::ResourceLimited)
        });
        for scanner in ScannerId::ALL {
            if !matches!(
                self.status.get(scanner),
                Some(SectionStatus::Scanning { .. })
            ) {
                continue;
            }
            let context = if *scanner == ScannerId::Fs {
                &run.disk
            } else {
                &run.audit_host
            };
            if matches!(
                context.completeness,
                Completeness::Pending | Completeness::Running
            ) {
                continue;
            }
            let status = if context.completed_sections.contains(scanner)
                && !context.failed_sections.contains(scanner)
            {
                SectionStatus::Done {
                    duration: std::time::Duration::ZERO,
                }
            } else {
                let error = if context
                    .stop_reasons
                    .contains(&RunStopReason::ResourceLimited)
                {
                    "resource limit: run stopped; partial results retained"
                } else if context.completeness == Completeness::Cancelled
                    || context.stop_reasons.contains(&RunStopReason::Cancelled)
                {
                    "run cancelled; partial results retained"
                } else if context.failed_sections.contains(scanner) {
                    "scanner failed; partial results retained"
                } else {
                    "run ended before this section completed; partial results retained"
                };
                SectionStatus::Failed {
                    error: error.to_string(),
                }
            };
            self.status.insert(*scanner, status);
            if *scanner == ScannerId::Brew {
                self.brew_version += 1;
            }
        }
    }

    pub fn cancel_scan(&mut self) {
        self.scan_cancelled = true;
        for status in self.status.values_mut() {
            if matches!(status, SectionStatus::Scanning { .. }) {
                *status = SectionStatus::Failed {
                    error: "run cancelled; partial results retained".to_string(),
                };
            }
        }
        self.push_activity("run cancelled; partial results retained".to_string());
    }

    // ---- read-only helpers used by the reducer and by sibling render modules ----

    pub(crate) fn status_of(&self, id: ScannerId) -> SectionStatus {
        self.status.get(&id).cloned().unwrap_or(SectionStatus::Idle)
    }

    pub(crate) fn section_count(&self, id: ScannerId) -> usize {
        self.findings.get(&id).map(|m| m.len()).unwrap_or(0)
    }

    pub(crate) fn section_reclaimable(&self, id: ScannerId) -> u64 {
        self.findings
            .get(&id)
            .map(|m| {
                m.values()
                    .filter(|f| f.severity == Severity::Reclaimable)
                    .filter_map(|f| f.size_bytes)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Read-only source data for the Resource Health overview. This is kept in
    /// the reducer so the renderer cannot accidentally duplicate selection or
    /// filtering policy.
    pub(crate) fn overview_findings(&self, id: ScannerId) -> Vec<&Finding> {
        self.findings
            .get(&id)
            .map(|m| m.values().collect())
            .unwrap_or_default()
    }

    /// The Disk section's `DiskCategory` findings, in their section order —
    /// the source for both the Overview's "Disk categories" list and its
    /// click-to-Browse indices (`Hit::OverviewCategory`).
    pub(crate) fn disk_categories(&self) -> Vec<&Finding> {
        self.overview_findings(ScannerId::Fs)
            .into_iter()
            .filter(|f| f.kind == FindingKind::DiskCategory)
            .collect()
    }

    pub(crate) fn marked_total(&self) -> (usize, u64) {
        let mut count = 0;
        let mut bytes = 0;
        for map in self.findings.values() {
            for f in map.values() {
                if self.marked.contains(&f.id) {
                    count += 1;
                    bytes += f.size_bytes.unwrap_or(0);
                }
            }
        }
        (count, bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::engine::{
        Completeness, ContextMetadata, RunContext, RunId, RunMetadata, RunStopReason,
    };
    use crate::model::FindingKind;
    use crate::ui::app::RescanRequest;
    use crate::ui::keys::Action;
    use crate::ui::testutil::*;

    fn completed_run(gen: u64, home: &std::path::Path) -> RunMetadata {
        let context = |context| ContextMetadata {
            context,
            completeness: Completeness::Complete,
            completed_sections: Vec::new(),
            failed_sections: Vec::new(),
            coverage: None,
            stop_reasons: Vec::new(),
            discovery: None,
        };
        let mut disk = context(RunContext::Disk {
            selected_root: home.to_path_buf(),
        });
        disk.completed_sections.push(ScannerId::Fs);
        let mut audit_host = context(RunContext::AuditHost {
            home: home.to_path_buf(),
        });
        audit_host.completed_sections = ScannerId::ALL.to_vec();
        RunMetadata {
            run_id: RunId(gen),
            request: crate::engine::RunRequest::new(home),
            disk,
            audit_host,
            active_scanners: 0,
            retiring_count: 0,
            retiring_runs: Vec::new(),
        }
    }

    #[tokio::test]
    async fn cancelled_full_forwarding_reconciles_without_losing_current_results() {
        let home = tempfile::tempdir().unwrap();
        let manager = crate::engine::ScannerManager::new(
            Arc::new(crate::config::Config::default()),
            Arc::new(crate::config::Paths::from_home(home.path())),
            Arc::new(crate::runner::MockCommandRunner::new()),
            crate::engine::Mode::Fake,
        );
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let run_id = manager
            .start_run(&sender, crate::engine::RunRequest::new(home.path()))
            .unwrap();
        let mut app = AppState {
            memory_budget: crate::inventory::MemoryBudget::new(16 * 1024 * 1024),
            ..AppState::default()
        };
        app.begin_run(&manager.current_run().unwrap());
        tokio::time::timeout(Duration::from_secs(2), async {
            while sender.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        manager.resource_limited(run_id, ScannerId::Apps);
        let run = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let run = manager.current_run().unwrap();
                if run.active_scanners == 0 {
                    break run;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        while let Ok(event) = receiver.try_recv() {
            app.apply(event);
        }
        app.apply(finding_event(run_id.0, "/partial", Some(3)));
        app.apply(ScanEvent::Failed {
            scanner: ScannerId::Brew,
            gen: run_id.0,
            error: "genuine brew failure".to_string(),
        });
        app.apply(ScanEvent::Finished {
            scanner: ScannerId::Ios,
            gen: run_id.0,
            duration: Duration::from_secs(7),
        });
        let finding_id = Finding::new(FindingKind::App, "/partial", "/partial").id;
        app.marked.insert(finding_id);
        let memory = app.memory_budget.used();
        assert!(!app.sections_terminal(ScannerId::ALL));

        app.reconcile_run(&run);

        assert!(app.sections_terminal(ScannerId::ALL));
        assert_eq!(app.section_count(ScannerId::Apps), 1);
        assert!(app.marked.contains(&finding_id));
        assert_eq!(app.memory_budget.used(), memory);
        assert!(matches!(
            app.status_of(ScannerId::Apps),
            SectionStatus::Failed { error } if error.contains("resource limit")
        ));
        assert_eq!(
            app.status_of(ScannerId::Brew),
            SectionStatus::Failed {
                error: "genuine brew failure".to_string(),
            }
        );
        assert_eq!(
            app.status_of(ScannerId::Ios),
            SectionStatus::Done {
                duration: Duration::from_secs(7),
            }
        );
        app.apply(ScanEvent::Started {
            scanner: ScannerId::Apps,
            gen: run_id.0,
        });
        app.apply(ScanEvent::Progress {
            scanner: ScannerId::Apps,
            gen: run_id.0,
            done: 1,
            total: None,
            msg: "late progress".to_string(),
        });
        app.apply(finding_event(run_id.0, "/late", Some(4)));
        assert_eq!(app.section_count(ScannerId::Apps), 2);
        assert!(app.sections_terminal(ScannerId::ALL));
    }

    #[test]
    fn reconciliation_requires_current_generation_and_retired_workers() {
        let home = tempfile::tempdir().unwrap();
        let mut run = completed_run(2, home.path());
        let mut app = AppState::default();
        app.begin_run(&run);
        app.apply(finding_event(2, "/current", Some(3)));
        let mut stale = completed_run(1, home.path());
        stale.disk.completeness = Completeness::Cancelled;
        stale.audit_host.completeness = Completeness::Cancelled;
        app.reconcile_run(&stale);
        let mut foreign = stale.clone();
        foreign.run_id = RunId(3);
        app.reconcile_run(&foreign);
        run.active_scanners = 1;
        app.reconcile_run(&run);
        assert!(ScannerId::ALL
            .iter()
            .all(|scanner| matches!(app.status_of(*scanner), SectionStatus::Scanning { .. })));
        assert!(!app.scan_cancelled);
        assert_eq!(app.section_count(ScannerId::Apps), 1);

        run.active_scanners = 0;
        run.disk.completeness = Completeness::Running;
        run.audit_host.completeness = Completeness::Running;
        app.reconcile_run(&run);
        assert!(!app.sections_terminal(ScannerId::ALL));
        assert!(matches!(
            app.status_of(ScannerId::Fs),
            SectionStatus::Scanning { .. }
        ));
        assert!(matches!(
            app.status_of(ScannerId::Apps),
            SectionStatus::Scanning { .. }
        ));

        run.disk.completeness = Completeness::Complete;
        run.audit_host.completeness = Completeness::Complete;
        app.reconcile_run(&run);
        assert!(ScannerId::ALL
            .iter()
            .all(|scanner| matches!(app.status_of(*scanner), SectionStatus::Done { .. })));
        assert_eq!(app.section_count(ScannerId::Apps), 1);
    }

    #[test]
    fn reconciliation_preserves_partial_success_payloads_and_terminal_details() {
        let home = tempfile::tempdir().unwrap();
        let mut run = completed_run(7, home.path());
        run.disk.completeness = Completeness::Partial;
        run.disk.stop_reasons.push(RunStopReason::Unreadable);
        run.audit_host.completeness = Completeness::Partial;
        run.audit_host
            .completed_sections
            .retain(|scanner| *scanner != ScannerId::Apps);
        run.audit_host.failed_sections.push(ScannerId::Apps);
        let mut app = AppState {
            memory_budget: crate::inventory::MemoryBudget::new(16 * 1024 * 1024),
            ..AppState::default()
        };
        app.begin_run(&run);
        app.apply(finding_event(7, "/partial", Some(3)));
        app.apply(ScanEvent::Failed {
            scanner: ScannerId::Brew,
            gen: 7,
            error: "detailed scanner failure".to_string(),
        });
        app.apply(ScanEvent::Finished {
            scanner: ScannerId::Ios,
            gen: 7,
            duration: Duration::from_secs(9),
        });
        let tree = Arc::new(crate::fake::dir_tree_at(home.path()));
        app.apply(ScanEvent::DirTree {
            scanner: ScannerId::Fs,
            gen: 7,
            tree: tree.clone(),
        });
        let footprints = Arc::new(crate::fake::fake_footprint_set(
            crate::attribution::model::Axis::Projects,
        ));
        app.apply(ScanEvent::Footprints {
            scanner: ScannerId::Projects,
            gen: 7,
            set: footprints.clone(),
        });

        app.reconcile_run(&run);

        assert!(app.sections_terminal(ScannerId::ALL));
        assert!(!app.scan_cancelled);
        assert!(matches!(
            app.status_of(ScannerId::Fs),
            SectionStatus::Done { .. }
        ));
        assert_eq!(
            app.status_of(ScannerId::Apps),
            SectionStatus::Failed {
                error: "scanner failed; partial results retained".to_string(),
            }
        );
        assert_eq!(
            app.status_of(ScannerId::Brew),
            SectionStatus::Failed {
                error: "detailed scanner failure".to_string(),
            }
        );
        assert_eq!(
            app.status_of(ScannerId::Ios),
            SectionStatus::Done {
                duration: Duration::from_secs(9),
            }
        );
        assert_eq!(app.section_count(ScannerId::Apps), 1);
        assert!(Arc::ptr_eq(app.dir_trees.get(home.path()).unwrap(), &tree));
        assert!(Arc::ptr_eq(
            app.footprints
                .get(&crate::attribution::model::Axis::Projects)
                .unwrap(),
            &footprints
        ));
        let memory = app.memory_budget.used();
        let activity_count = app.activity.len();
        let brew_version = app.brew_version;
        for _ in 0..100 {
            app.reconcile_run(&run);
        }
        assert_eq!(app.memory_budget.used(), memory);
        assert_eq!(app.activity.len(), activity_count);
        assert_eq!(app.brew_version, brew_version);
    }

    #[test]
    fn reconciliation_keeps_resource_failures_after_late_cancellation_events() {
        let home = tempfile::tempdir().unwrap();
        let mut run = completed_run(1, home.path());
        run.disk.completed_sections.clear();
        run.disk.completeness = Completeness::Cancelled;
        run.disk.stop_reasons.push(RunStopReason::Cancelled);
        run.audit_host.completed_sections.clear();
        run.audit_host.completeness = Completeness::Partial;
        run.audit_host
            .stop_reasons
            .push(RunStopReason::ResourceLimited);
        let mut app = AppState::default();
        app.begin_run(&run);
        app.apply(ScanEvent::Failed {
            scanner: ScannerId::Apps,
            gen: 1,
            error: "resource limit: precise allocation failure".to_string(),
        });

        app.reconcile_run(&run);
        app.apply(ScanEvent::Failed {
            scanner: ScannerId::Apps,
            gen: 1,
            error: "run cancelled".to_string(),
        });

        assert_eq!(
            app.status_of(ScannerId::Apps),
            SectionStatus::Failed {
                error: "resource limit: precise allocation failure".to_string(),
            }
        );
        assert!(matches!(
            app.status_of(ScannerId::Fs),
            SectionStatus::Failed { error } if error.contains("run cancelled")
        ));
        assert!(matches!(
            app.status_of(ScannerId::Ports),
            SectionStatus::Failed { error } if error.contains("resource limit")
        ));
        app.apply(ScanEvent::Failed {
            scanner: ScannerId::Ports,
            gen: 1,
            error: "late genuine failure".to_string(),
        });
        assert_eq!(
            app.status_of(ScannerId::Ports),
            SectionStatus::Failed {
                error: "late genuine failure".to_string(),
            }
        );
    }

    #[test]
    fn upsert_dedups_by_id() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/a", None));
        app.apply(finding_event(1, "/a", Some(999))); // same id, now sized
        let map = app.findings.get(&ScannerId::Apps).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.values().next().unwrap().size_bytes, Some(999));
    }

    #[test]
    fn pressure_keeps_partials_and_requests_run_cancellation() {
        let mut app = app_with_gen(1);
        app.memory_budget = crate::inventory::MemoryBudget::new(4096);
        app.apply(finding_event(1, "/partial", Some(1)));
        assert_eq!(app.section_count(ScannerId::Apps), 1);
        let oversized = Finding::new(FindingKind::App, "large", "x".repeat(4096));
        app.apply(ScanEvent::Finding {
            scanner: ScannerId::Apps,
            gen: 1,
            finding: Box::new(oversized),
        });
        assert_eq!(app.section_count(ScannerId::Apps), 1);
        assert_eq!(app.pending_resource_limit, Some(ScannerId::Apps));
        let memory = app.result_memory();
        let budget = app.memory_budget.clone();
        app.begin_scan(2, ScannerId::ALL);
        assert!(budget.used() > 0);
        drop(memory);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn footprint_pressure_counts_spare_capacity_and_preserves_current_set() {
        use crate::attribution::model::{Axis, FootprintSet};
        let mut app = app_with_gen(1);
        app.memory_budget = crate::inventory::MemoryBudget::new(16 * 1024);
        let previous = Arc::new(FootprintSet {
            axis: Axis::Projects,
            gen: 1,
            footprints: Vec::new(),
            baseline: Vec::new(),
            unattributed: Vec::new(),
            disk_total: 0,
            attributed_total: 0,
            missing_deps: Vec::new(),
        });
        app.apply(ScanEvent::Footprints {
            scanner: ScannerId::Projects,
            gen: 1,
            set: previous.clone(),
        });
        let retained = app.memory_budget.used();
        assert!(retained > 0);
        let mut oversized = previous.as_ref().clone();
        oversized.baseline = Vec::with_capacity(1024);
        assert!(crate::inventory::serialized_size(&oversized).unwrap() * 2 < 16 * 1024);
        app.apply(ScanEvent::Footprints {
            scanner: ScannerId::Projects,
            gen: 1,
            set: Arc::new(oversized),
        });
        assert!(Arc::ptr_eq(
            app.footprints.get(&Axis::Projects).unwrap(),
            &previous
        ));
        assert_eq!(app.memory_budget.used(), retained);
        assert_eq!(app.pending_resource_limit, Some(ScannerId::Projects));
        app.begin_scan(2, ScannerId::ALL);
        assert_eq!(app.memory_budget.used(), 0);
    }

    #[test]
    fn stale_generation_dropped() {
        let mut app = app_with_gen(2);
        app.apply(finding_event(1, "/old", Some(1))); // stale gen
        assert_eq!(app.section_count(ScannerId::Apps), 0);
    }

    #[test]
    fn per_section_staleness_exact_match() {
        let mut app = AppState::default();
        app.begin_scan(2, &[ScannerId::Apps]);
        app.apply(finding_event(1, "/older", Some(1))); // gen < expected: dropped
        app.apply(finding_event(3, "/newer", Some(1))); // gen > expected: dropped
        app.apply(finding_event(2, "/right", Some(1))); // exact: applied
        assert_eq!(app.section_count(ScannerId::Apps), 1);
    }

    #[test]
    fn compatibility_section_refresh_clears_all_and_rejects_old_run() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/old-app", Some(1)));
        app.dir_trees.insert(
            PathBuf::from("/Users/dev"),
            Arc::new(crate::fake::dir_tree()),
        );
        app.footprints.insert(
            crate::attribution::model::Axis::Projects,
            Arc::new(crate::fake::fake_footprint_set(
                crate::attribution::model::Axis::Projects,
            )),
        );
        app.marked
            .insert(Finding::new(FindingKind::App, "/old-app", "old").id);
        app.begin_scan(2, &[ScannerId::Ports]);
        assert!(app.dir_trees.is_empty());
        assert!(app.footprints.is_empty());
        assert!(app.marked.is_empty());
        assert_eq!(app.section_count(ScannerId::Apps), 0);
        assert!(ScannerId::ALL
            .iter()
            .all(|id| app.expected_gen.get(id) == Some(&2)));
        app.apply(finding_event(1, "/old-app", Some(1)));
        app.apply(ScanEvent::Finished {
            scanner: ScannerId::Brew,
            gen: 1,
            duration: Duration::from_secs(1),
        });
        assert_eq!(app.section_count(ScannerId::Apps), 0);
        assert!(matches!(
            app.status_of(ScannerId::Brew),
            SectionStatus::Scanning { .. }
        ));
        app.apply(finding_event(2, "/new-app", Some(2)));
        assert_eq!(app.section_count(ScannerId::Apps), 1);
    }

    #[test]
    fn cancel_keeps_partials_and_accepts_final_current_run_data() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/partial", Some(3)));
        app.cancel_scan();
        app.apply(finding_event(1, "/late", Some(4)));
        assert_eq!(app.section_count(ScannerId::Apps), 2);
        app.apply_enriched(1, vec![Finding::new(FindingKind::App, "/enriched", "late")]);
        assert_eq!(app.section_count(ScannerId::Apps), 2);
    }

    #[test]
    fn double_rescan_drops_old_run_events() {
        let mut app = AppState::default();
        app.begin_scan(1, &[ScannerId::Apps]);
        app.begin_scan(2, &[ScannerId::Apps]);
        app.apply(finding_event(1, "/from-old-run", Some(1))); // dropped
        app.apply(finding_event(2, "/from-new-run", Some(1))); // kept
        let map = app.findings.get(&ScannerId::Apps).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.values().next().unwrap().title, "/from-new-run");
    }

    #[test]
    fn correlate_now_marks_installed_cask_apps() {
        let mut app = app_with_gen(1);
        let cask = Finding::new(FindingKind::BrewCask, "slack", "slack")
            .meta(serde_json::json!({"token": "slack", "app_paths": ["/Applications/Slack.app"]}));
        let mut a = Finding::new(FindingKind::App, "/Applications/Slack.app", "Slack")
            .path("/Applications/Slack.app")
            .meta(serde_json::json!({"classification": "unmanaged", "group": "Unmanaged"}));
        a.severity = Severity::Attention;
        app.apply(ScanEvent::Finding {
            scanner: ScannerId::Brew,
            gen: 1,
            finding: Box::new(cask),
        });
        app.apply(ScanEvent::Finding {
            scanner: ScannerId::Apps,
            gen: 1,
            finding: Box::new(a.clone()),
        });

        app.correlate_now();

        let apps = app.findings.get(&ScannerId::Apps).unwrap();
        let updated = apps.get(&a.id).unwrap();
        assert_eq!(updated.meta["group"], "Homebrew Cask");
        assert_eq!(updated.meta["managed_by_cask"], "slack");
    }

    #[test]
    fn apply_enriched_respects_generation() {
        let mut app = AppState::default();
        app.begin_scan(2, &[ScannerId::Apps]);
        let f = Finding::new(FindingKind::App, "/Applications/X.app", "X");
        app.apply_enriched(1, vec![f.clone()]); // stale batch dropped
        assert_eq!(app.section_count(ScannerId::Apps), 0);
        app.apply_enriched(2, vec![f]); // current batch applied
        assert_eq!(app.section_count(ScannerId::Apps), 1);
    }

    #[test]
    fn sidebar_status_transitions_scanning_done_failed() {
        let mut app = app_with_gen(1);
        assert_eq!(app.status_of(ScannerId::Apps), SectionStatus::Idle);

        app.apply(ScanEvent::Started {
            scanner: ScannerId::Apps,
            gen: 1,
        });
        assert!(matches!(
            app.status_of(ScannerId::Apps),
            SectionStatus::Scanning { .. }
        ));

        app.apply(ScanEvent::Finished {
            scanner: ScannerId::Apps,
            gen: 1,
            duration: Duration::from_secs(1),
        });
        assert!(matches!(
            app.status_of(ScannerId::Apps),
            SectionStatus::Done { .. }
        ));

        app.apply(ScanEvent::Started {
            scanner: ScannerId::Brew,
            gen: 1,
        });
        app.apply(ScanEvent::Failed {
            scanner: ScannerId::Brew,
            gen: 1,
            error: "boom".into(),
        });
        assert!(matches!(
            app.status_of(ScannerId::Brew),
            SectionStatus::Failed { .. }
        ));
    }

    #[test]
    fn rescan_section_requested() {
        let mut app = AppState::default();
        app.handle(Action::Char('R'));
        assert_eq!(app.pending_rescan, Some(RescanRequest::All));
    }
}
