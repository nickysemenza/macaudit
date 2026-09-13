//! Marking findings for batch remedy execution, and the confirm-dialog
//! reducer that lands or discards the resulting plan.

use std::collections::BTreeMap;

use crate::cleanup::{self, ExecEvent};
use crate::model::{FindingId, Remedy};
use crate::remedy::RemedyEngine;
use crate::ui::app::{AppState, CleanupPhase, CleanupRequest, CleanupRun, ConfirmModel, Mode};
use crate::ui::keys::Action;

impl AppState {
    pub(super) fn toggle_mark_selected(&mut self) {
        if let Some(id) = self.selected_finding().map(|f| f.id) {
            if !self.marked.insert(id) {
                self.marked.remove(&id);
            }
        }
    }

    /// `e`: cycle which remedy the selected finding will run (its primary
    /// remedies, then each alternative one by one) and mark it.
    pub(super) fn cycle_remedy_choice(&mut self) {
        let Some(f) = self.selected_finding() else {
            return;
        };
        if f.remedies.is_empty() {
            return;
        }
        let id = f.id;
        let n = f.remedies.len();
        let next = match self.remedy_choice.get(&id) {
            None => Some(0),
            Some(i) if i + 1 < n => Some(i + 1),
            Some(_) => None,
        };
        match next {
            Some(i) => {
                self.remedy_choice.insert(id, i);
            }
            None => {
                self.remedy_choice.remove(&id);
            }
        }
        self.marked.insert(id);
    }

    pub(super) fn remedy_choice_for(&self, id: FindingId) -> Option<usize> {
        self.remedy_choice.get(&id).copied()
    }

    /// Gather marked findings' remedies, plan them, run the in-memory
    /// preflight, and open the confirm dialog (even when everything was
    /// refused, so the user sees why).
    pub(super) fn open_confirm(&mut self) {
        if self.marked.is_empty() {
            return;
        }
        let items: Vec<(FindingId, Remedy)> = self
            .findings
            .values()
            .flat_map(|m| m.values())
            .filter(|f| self.marked.contains(&f.id))
            .flat_map(|f| {
                execution_remedies(f, self.remedy_choice_for(f.id))
                    .into_iter()
                    .map(|r| (f.id, r.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        if items.is_empty() {
            return;
        }
        let engine = RemedyEngine::new(self.delete_mode);
        let planned = engine.plan(&items);
        let current = self.all_findings();
        let report = cleanup::preflight_static(&planned, &current);
        self.confirm = Some(ConfirmModel {
            actions: report.ok,
            refused: report.refused,
            removed: report.removed,
            remaining: report.remaining,
            follow_up: report.follow_up,
            impact: report.brew_preview,
            scroll: 0,
        });
        self.mode = Mode::Confirm;
    }

    pub(super) fn handle_confirm(&mut self, action: Action) {
        match action {
            Action::CtrlC => self.should_quit = true,
            Action::Char('y') | Action::Enter => {
                let Some(model) = self.confirm.take() else {
                    self.mode = Mode::Normal;
                    return;
                };
                if model.actions.is_empty() {
                    self.mode = Mode::Normal;
                    return;
                }
                let current = self.all_findings();
                let affected = cleanup::affected_sections(&model.actions, &current);
                for a in &model.actions {
                    self.marked.remove(&a.finding_id);
                    self.remedy_choice.remove(&a.finding_id);
                }
                self.cleanup = Some(CleanupRun {
                    phase: CleanupPhase::Preflight,
                    actions: model.actions.clone(),
                    refused: model.refused.clone(),
                    results: BTreeMap::new(),
                    cancelled: Vec::new(),
                    cancel_requested: false,
                    affected: affected.clone(),
                    report: None,
                });
                self.pending_execute = Some(CleanupRequest {
                    actions: model.actions,
                    affected,
                });
                self.mode = Mode::Cleanup;
            }
            Action::Char('n') | Action::Esc => {
                self.confirm = None;
                self.mode = Mode::Normal;
            }
            Action::Char('J') | Action::Down | Action::ScrollDetail(_) => {
                if let Some(m) = &mut self.confirm {
                    m.scroll = m.scroll.saturating_add(3);
                }
            }
            Action::Char('K') | Action::Up => {
                if let Some(m) = &mut self.confirm {
                    m.scroll = m.scroll.saturating_sub(3);
                }
            }
            _ => {}
        }
    }

    /// `Mode::Preview`: `x` continues to the confirm dialog.
    pub(super) fn handle_preview(&mut self, action: Action) {
        match action {
            Action::CtrlC => self.should_quit = true,
            Action::Esc | Action::Char('v') | Action::Char('q') => {
                self.mode = Mode::Normal;
                self.overlay_scroll = 0;
            }
            Action::Char('x') | Action::Enter => {
                self.overlay_scroll = 0;
                self.mode = Mode::Normal;
                self.open_confirm();
            }
            Action::Char('J') | Action::Down => {
                self.overlay_scroll = self.overlay_scroll.saturating_add(3)
            }
            Action::Char('K') | Action::Up => {
                self.overlay_scroll = self.overlay_scroll.saturating_sub(3)
            }
            _ => {}
        }
    }

    /// `Mode::Cleanup`: Esc asks the loop to stop after the current action.
    pub(super) fn handle_cleanup(&mut self, action: Action) {
        match action {
            Action::CtrlC => self.should_quit = true,
            Action::Esc | Action::Char('q') => {
                if let Some(run) = &mut self.cleanup {
                    if run.phase != CleanupPhase::Done {
                        run.cancel_requested = true;
                        self.pending_cancel_cleanup = true;
                    }
                }
            }
            Action::Char('J') | Action::Down => {
                self.overlay_scroll = self.overlay_scroll.saturating_add(3)
            }
            Action::Char('K') | Action::Up => {
                self.overlay_scroll = self.overlay_scroll.saturating_sub(3)
            }
            _ => {}
        }
    }

    pub(super) fn handle_report(&mut self, action: Action) {
        match action {
            Action::CtrlC => self.should_quit = true,
            Action::Esc | Action::Char('q') | Action::Enter | Action::Char('c') => {
                self.mode = Mode::Normal;
                self.overlay_scroll = 0;
            }
            Action::Char('J') | Action::Down => {
                self.overlay_scroll = self.overlay_scroll.saturating_add(3)
            }
            Action::Char('K') | Action::Up => {
                self.overlay_scroll = self.overlay_scroll.saturating_sub(3)
            }
            _ => {}
        }
    }

    /// `c`: reopen the last cleanup report.
    pub(super) fn open_report(&mut self) {
        if self
            .cleanup
            .as_ref()
            .map(|r| r.report.is_some())
            .unwrap_or(false)
        {
            self.overlay_scroll = 0;
            self.mode = Mode::Report;
        }
    }

    /// `v`: impact preview of the marked batch.
    pub(super) fn open_preview(&mut self) {
        if !self.marked.is_empty() {
            self.overlay_scroll = 0;
            self.mode = Mode::Preview;
        }
    }

    /// The preflight model for whatever is marked right now (used by the
    /// preview overlay and the detail pane's batch impact).
    pub(crate) fn marked_preflight(&self) -> Option<ConfirmModel> {
        if self.marked.is_empty() {
            return None;
        }
        let items: Vec<(FindingId, Remedy)> = self
            .findings
            .values()
            .flat_map(|m| m.values())
            .filter(|f| self.marked.contains(&f.id))
            .flat_map(|f| {
                execution_remedies(f, self.remedy_choice_for(f.id))
                    .into_iter()
                    .map(|r| (f.id, r.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        let planned = RemedyEngine::new(self.delete_mode).plan(&items);
        let current = self.all_findings();
        let report = cleanup::preflight_static(&planned, &current);
        Some(ConfirmModel {
            actions: report.ok,
            refused: report.refused,
            removed: report.removed,
            remaining: report.remaining,
            follow_up: report.follow_up,
            impact: report.brew_preview,
            scroll: self.overlay_scroll,
        })
    }

    /// Feed a cleanup progress event into the run state.
    pub fn apply_exec(&mut self, ev: ExecEvent) {
        let Some(run) = &mut self.cleanup else {
            return;
        };
        match ev {
            ExecEvent::PreflightDone(report) => {
                let report = *report;
                let refused = report.refused.len();
                run.actions = report.ok;
                run.refused.extend(report.refused);
                run.phase = CleanupPhase::Executing {
                    idx: 0,
                    total: run.actions.len(),
                };
                if refused > 0 {
                    self.push_activity(format!(
                        "cleanup: {refused} action(s) refused by the refreshed preflight"
                    ));
                }
            }
            ExecEvent::ActionStarted(i) => {
                let total = run.actions.len();
                run.phase = CleanupPhase::Executing { idx: i, total };
            }
            ExecEvent::ActionDone(i, result) => {
                let line = match &result {
                    Ok(msg) => msg.clone(),
                    Err(e) => format!(
                        "error: {} — {e}",
                        run.actions
                            .get(i)
                            .map(|a| a.rendered.clone())
                            .unwrap_or_default()
                    ),
                };
                run.results.insert(i, result);
                self.push_activity(line);
            }
            ExecEvent::Executed { cancelled } => {
                run.cancelled = cancelled;
                run.phase = CleanupPhase::Verifying;
            }
            ExecEvent::Verifying => run.phase = CleanupPhase::Verifying,
            ExecEvent::Finished(report) => {
                run.phase = CleanupPhase::Done;
                let summary = report.summary();
                let path = report.audit_path.clone();
                run.report = Some(*report);
                self.push_activity(match path {
                    Some(p) => format!("{summary} — report {}", p.display()),
                    None => summary,
                });
                if self.mode == Mode::Cleanup {
                    self.mode = Mode::Report;
                    self.overlay_scroll = 0;
                }
            }
        }
    }
}

pub(crate) use crate::remedy::execution_remedies;

#[cfg(test)]
mod tests {
    use crate::ui::app::Mode;
    use crate::ui::keys::Action;
    use crate::ui::testutil::*;

    #[test]
    fn marking_toggles() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/a", Some(10)));
        // Apps is a Tree-view section: row 0 is the group header, row 1 is
        // the finding itself.
        app.handle(Action::Down);
        app.handle(Action::Char(' '));
        assert_eq!(app.marked_total().0, 1);
        app.handle(Action::Char(' '));
        assert_eq!(app.marked_total().0, 0);
    }

    #[test]
    fn confirm_flow_produces_pending_execute() {
        let mut app = app_with_gen(1);
        app.apply(finding_with_remedy(1, "/Applications/Old.app"));
        app.handle(Action::Down); // Apps is Tree view: row 0 is the group header
        app.handle(Action::Char(' ')); // mark the only row
        assert_eq!(app.marked_total().0, 1);

        app.handle(Action::Char('x')); // open confirm
        assert_eq!(app.mode, Mode::Confirm);
        let model = app.confirm.as_ref().unwrap();
        assert_eq!(model.actions.len(), 1);
        assert!(model.actions[0].rendered.contains("trash"));
        assert!(model.refused.is_empty());

        app.handle(Action::Char('y')); // confirm
        assert_eq!(app.mode, Mode::Cleanup);
        assert_eq!(app.marked_total().0, 0); // cleared after queuing
        let req = app.pending_execute.take().expect("pending_execute set");
        assert_eq!(req.actions.len(), 1);
        assert_eq!(req.affected, vec![crate::model::ScannerId::Apps]);
    }

    #[test]
    fn confirm_cancel_leaves_marks_and_sets_no_pending_execute() {
        let mut app = app_with_gen(1);
        app.apply(finding_with_remedy(1, "/Applications/Old.app"));
        app.handle(Action::Down); // Apps is Tree view: row 0 is the group header
        app.handle(Action::Char(' '));
        app.handle(Action::Char('x'));
        app.handle(Action::Char('n'));
        assert_eq!(app.mode, Mode::Normal);
        assert!(app.pending_execute.is_none());
        assert_eq!(app.marked_total().0, 1); // still marked, nothing executed
    }

    #[test]
    fn execution_remedies_skips_alternatives_unless_chosen() {
        use crate::model::{Finding, FindingKind, Remedy, RemedyCommand};
        let f = Finding::new(FindingKind::GlobalTool, "npm:/r:x", "x")
            .remedy(
                Remedy::new(
                    "Uninstall",
                    RemedyCommand::Shell {
                        program: "npm".into(),
                        args: vec!["uninstall".into()],
                    },
                )
                .destructive(),
            )
            .remedy(
                Remedy::new(
                    "Remove launcher only",
                    RemedyCommand::Trash { path: "/l".into() },
                )
                .destructive()
                .alternative(),
            )
            .remedy(
                Remedy::new(
                    "Verify",
                    RemedyCommand::Probe {
                        program: "/l".into(),
                        args: vec![],
                        timeout_secs: 5,
                    },
                )
                .alternative(),
            );
        let primary = super::execution_remedies(&f, None);
        assert_eq!(primary.len(), 1);
        assert_eq!(primary[0].label, "Uninstall");
        let chosen = super::execution_remedies(&f, Some(2));
        assert_eq!(chosen[0].label, "Verify");
    }

    #[test]
    fn e_cycles_remedy_choice_and_marks_v_opens_preview_c_reopens_report() {
        use crate::cleanup::{CleanupReport, ExecEvent, PreflightReport};
        use crate::ui::app::CleanupPhase;
        let mut app = app_with_gen(1);
        app.apply(finding_with_remedy(1, "/Applications/Old.app"));
        app.handle(Action::Down);
        // No report yet: `c` is a no-op; `v` needs marks.
        app.handle(Action::Char('c'));
        app.handle(Action::Char('v'));
        assert_eq!(app.mode, Mode::Normal);
        app.handle(Action::Char('e'));
        assert_eq!(app.marked_total().0, 1);
        let id = app.selected_finding().unwrap().id;
        assert_eq!(app.remedy_choice_for(id), Some(0));
        app.handle(Action::Char('e')); // wraps back to "primary"
        assert_eq!(app.remedy_choice_for(id), None);
        app.handle(Action::Char('v'));
        assert_eq!(app.mode, Mode::Preview);
        assert_eq!(app.marked_preflight().unwrap().actions.len(), 1);
        app.handle(Action::Char('x'));
        assert_eq!(app.mode, Mode::Confirm);
        app.handle(Action::Char('y'));
        assert_eq!(app.mode, Mode::Cleanup);
        let req = app.pending_execute.take().unwrap();

        // Drive the batch through its phases.
        app.apply_exec(ExecEvent::PreflightDone(Box::new(PreflightReport {
            ok: req.actions.clone(),
            ..Default::default()
        })));
        assert!(matches!(
            app.cleanup.as_ref().unwrap().phase,
            CleanupPhase::Executing { idx: 0, total: 1 }
        ));
        app.handle(Action::Esc);
        assert!(app.pending_cancel_cleanup);
        assert!(app.cleanup.as_ref().unwrap().cancel_requested);
        app.apply_exec(ExecEvent::ActionStarted(0));
        app.apply_exec(ExecEvent::ActionDone(0, Ok("Trashed".into())));
        app.apply_exec(ExecEvent::Executed { cancelled: vec![] });
        assert_eq!(app.cleanup.as_ref().unwrap().phase, CleanupPhase::Verifying);
        app.apply_exec(ExecEvent::Finished(Box::new(CleanupReport {
            note: "No rollback".into(),
            ..Default::default()
        })));
        assert_eq!(app.mode, Mode::Report);
        assert!(app.activity.iter().any(|l| l.starts_with("cleanup:")));
        app.handle(Action::Esc);
        assert_eq!(app.mode, Mode::Normal);
        app.handle(Action::Char('c'));
        assert_eq!(app.mode, Mode::Report);
    }

    #[test]
    fn stale_marks_are_dropped_after_rescan_and_confirm_is_rebuilt() {
        use crate::model::{ScanEvent, ScannerId};
        let mut app = app_with_gen(1);
        app.apply(finding_with_remedy(1, "/Applications/Old.app"));
        app.apply(finding_with_remedy(1, "/Applications/Other.app"));
        app.handle(Action::Down);
        app.handle(Action::Char(' '));
        app.handle(Action::Down);
        app.handle(Action::Char(' '));
        assert_eq!(app.marked_total().0, 2);
        app.handle(Action::Char('x'));
        assert_eq!(app.confirm.as_ref().unwrap().actions.len(), 2);
        // Rescan Apps: only one of the two comes back.
        app.begin_scan(2, &[ScannerId::Apps]);
        app.apply(finding_with_remedy(2, "/Applications/Other.app"));
        app.apply(ScanEvent::Finished {
            scanner: ScannerId::Apps,
            gen: 2,
            duration: std::time::Duration::from_secs(1),
        });
        assert_eq!(app.marked_total().0, 1);
        assert!(app.activity.iter().any(|l| l.contains("stale mark")));
        assert_eq!(app.mode, Mode::Confirm);
        assert_eq!(app.confirm.as_ref().unwrap().actions.len(), 1);
    }
}
