//! Marking findings for batch remedy execution, and the confirm-dialog
//! reducer that lands or discards the resulting plan.

use crate::model::{Finding, FindingId, Remedy, RemedyCommand};
use crate::remedy::RemedyEngine;
use crate::ui::app::{AppState, Mode};
use crate::ui::keys::Action;

impl AppState {
    pub(super) fn toggle_mark_selected(&mut self) {
        if let Some(id) = self.selected_finding().map(|f| f.id) {
            if !self.marked.insert(id) {
                self.marked.remove(&id);
            }
        }
    }

    /// Gather marked findings' primary remedies, plan them via `RemedyEngine`,
    /// and open the confirm dialog. No-op if nothing marked has an
    /// executable remedy.
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
                execution_remedies(f)
                    .into_iter()
                    .map(|r| (f.id, r.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        if items.is_empty() {
            return;
        }
        let engine = RemedyEngine::new(self.delete_mode);
        self.confirm_actions = engine.plan(&items);
        self.mode = Mode::Confirm;
    }

    pub(super) fn handle_confirm(&mut self, action: Action) {
        match action {
            Action::CtrlC => self.should_quit = true,
            Action::Char('y') | Action::Enter => {
                self.pending_execute = Some(std::mem::take(&mut self.confirm_actions));
                self.marked.clear();
                self.mode = Mode::Normal;
            }
            Action::Char('n') | Action::Esc => {
                self.confirm_actions.clear();
                self.mode = Mode::Normal;
            }
            _ => {}
        }
    }
}

/// The remedies to plan when a finding is marked for batch execution:
///
/// - ALL destructive remedies, in emission order — multi-step workflows like
///   launchd's "bootout, THEN trash the plist" execute as an ordered sequence
///   (previously only the first ever ran and the trash was unreachable).
/// - Else the first Shell remedy — an actionable command like
///   `brew install --adopt` must not lose to an earlier Reveal-in-Finder.
/// - Else the first remedy, if any (reveal/copy-only findings).
fn execution_remedies(f: &Finding) -> Vec<&Remedy> {
    let destructive: Vec<&Remedy> = f.remedies.iter().filter(|r| r.destructive).collect();
    if !destructive.is_empty() {
        return destructive;
    }
    if let Some(shell) = f
        .remedies
        .iter()
        .find(|r| matches!(r.command, RemedyCommand::Shell { .. }))
    {
        return vec![shell];
    }
    f.remedies.first().into_iter().collect()
}

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
        assert_eq!(app.confirm_actions.len(), 1);
        assert!(app.confirm_actions[0].rendered.contains("trash"));

        app.handle(Action::Char('y')); // confirm
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(app.marked_total().0, 0); // cleared after queuing
        let actions = app.pending_execute.take().expect("pending_execute set");
        assert_eq!(actions.len(), 1);
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
}
