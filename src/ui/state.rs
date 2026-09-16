//! Scan-event ingestion and section-status bookkeeping: the reducer's "what
//! did the scanners report" half. `apply`, `begin_scan`, and `apply_enriched`
//! are the sole mutation paths for `findings` — upsert-by-id keeps
//! sizes/dedup correct. The read-only helpers here (`status_of`,
//! `section_count`, ...) back the sidebar, the Resource Health overview, and
//! the run loop's rescan bookkeeping.

use std::collections::BTreeMap;

use crate::config::DeleteMode;
use crate::model::{Finding, FindingId, ScanEvent, ScannerId, Severity};
use crate::ui::app::{AppState, SectionStatus};

pub use crate::correlate::CORRELATED_SECTIONS;

impl AppState {
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
        for (fid, f) in merged {
            self.findings
                .entry(f.kind.scanner())
                .or_default()
                .insert(fid, f);
        }
    }

    /// Upsert a batch of enriched findings (async network enrichment results)
    /// for generation `gen`. Batches from superseded generations are dropped:
    /// every enriched finding's section must still expect `gen`.
    pub fn apply_enriched(&mut self, gen: u64, findings: Vec<Finding>) {
        for f in findings {
            let section = f.kind.scanner();
            if self.expected_gen.get(&section) == Some(&gen) {
                self.findings.entry(section).or_default().insert(f.id, f);
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
        match ev {
            ScanEvent::Started { scanner, .. } => {
                self.findings.entry(scanner).or_default().clear();
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
                self.findings
                    .entry(scanner)
                    .or_default()
                    .insert(finding.id, *finding);
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
                self.status.insert(scanner, SectionStatus::Failed { error });
                self.drop_stale_marks(scanner);
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
    pub fn begin_scan(&mut self, gen: u64, sections: &[ScannerId]) {
        for id in sections {
            self.expected_gen.insert(*id, gen);
        }
        for id in sections {
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
    use std::time::Duration;

    use super::*;
    use crate::model::FindingKind;
    use crate::ui::app::RescanRequest;
    use crate::ui::keys::Action;
    use crate::ui::testutil::*;

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
    fn section_rescan_keeps_other_sections_events() {
        // The headline regression: rescanning Ports must not orphan the rest of
        // an in-flight full scan.
        let mut app = AppState::default();
        app.begin_scan(1, ScannerId::ALL);
        app.begin_scan(2, &[ScannerId::Ports]);

        // Old-gen events from the still-running full scan keep landing.
        app.apply(finding_event(1, "/apps-item", Some(1)));
        app.apply(ScanEvent::Finished {
            scanner: ScannerId::Brew,
            gen: 1,
            duration: Duration::from_secs(1),
        });
        app.apply(ScanEvent::Finished {
            scanner: ScannerId::Ports,
            gen: 2,
            duration: Duration::from_secs(1),
        });

        assert_eq!(
            app.section_count(ScannerId::Apps),
            1,
            "full-scan finding kept"
        );
        assert!(
            matches!(app.status_of(ScannerId::Brew), SectionStatus::Done { .. }),
            "old code left Brew stuck Scanning"
        );
        assert!(matches!(
            app.status_of(ScannerId::Ports),
            SectionStatus::Done { .. }
        ));
    }

    #[test]
    fn git_rescan_discovery_fs_does_not_clobber_disk() {
        let mut app = AppState::default();
        app.begin_scan(1, ScannerId::ALL);
        // Disk finishes with findings.
        let mut f = Finding::new(FindingKind::BuildArtifact, "/p/node_modules", "nm");
        f.size_bytes = Some(10);
        app.apply(ScanEvent::Finding {
            scanner: ScannerId::Fs,
            gen: 1,
            finding: Box::new(f),
        });
        app.apply(ScanEvent::Finished {
            scanner: ScannerId::Fs,
            gen: 1,
            duration: Duration::from_secs(1),
        });

        // Git-only rescan: engine spawns a discovery-only Fs at gen 2, whose
        // Started{Fs} previously wiped the Disk pane.
        app.begin_scan(2, &[ScannerId::Git]);
        app.apply(ScanEvent::Started {
            scanner: ScannerId::Fs,
            gen: 2,
        });

        assert_eq!(app.section_count(ScannerId::Fs), 1, "Disk findings wiped");
        assert!(matches!(
            app.status_of(ScannerId::Fs),
            SectionStatus::Done { .. }
        ));
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
