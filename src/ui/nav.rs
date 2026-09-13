//! Cursor movement, section switching, and the Normal/Filter/Help mode
//! reducers. `Mode::Confirm`'s reducer (`handle_confirm`) lives in
//! `marking.rs`, alongside the confirm-dialog planning it feeds.

use crate::model::ScannerId;
use crate::ui::app::{AppState, Mode, RescanRequest};
use crate::ui::keys::Action;
use crate::ui::layout::DetailMode;
use crate::ui::rows::RenderRow;
use crate::ui::sidebar;

impl AppState {
    /// Normal-mode keymap. Every key does one thing regardless of what is
    /// under the cursor: `←/→`/`h`/`l`/Tab switch sections, `↑/↓`/`j`/`k`
    /// move rows, digits jump, `z` folds, `p` toggles the detail pane.
    pub(super) fn handle_normal(&mut self, action: Action) {
        match action {
            Action::CtrlC | Action::Char('q') => self.should_quit = true,
            Action::Esc => self.on_esc(),
            Action::Up | Action::Char('k') => self.move_by(-1),
            Action::Down | Action::Char('j') => self.move_by(1),
            Action::PageUp => self.move_by(-(self.viewport.page_size() as isize)),
            Action::PageDown => self.move_by(self.viewport.page_size() as isize),
            Action::Tab | Action::Right | Action::Char('l') => self.next_section(),
            Action::BackTab | Action::Left | Action::Char('h') => self.prev_section(),
            Action::JumpSection(i) => self.select_section(i),
            Action::Char(c) if sidebar::section_for_digit(c).is_some() => {
                self.select_section(sidebar::section_for_digit(c).unwrap_or(0));
            }
            Action::SelectRow(i) => self.select_row(i),
            Action::Char(' ') => self.toggle_mark_selected(),
            Action::Enter => self.on_enter(),
            Action::Char('z') => self.fold_at_cursor(),
            Action::Char('p') => self.toggle_detail(),
            Action::Char('J') => self.scroll_detail(3),
            Action::Char('K') => self.scroll_detail(-3),
            Action::ScrollDetail(d) => self.scroll_detail(d),
            Action::Char('x') => self.open_confirm(),
            Action::Char('v') => self.open_preview(),
            Action::Char('c') => self.open_report(),
            Action::Char('e') => self.cycle_remedy_choice(),
            Action::Char('r') => {
                self.pending_rescan = Some(RescanRequest::Section(self.selected_section_id()));
            }
            Action::Char('R') => self.pending_rescan = Some(RescanRequest::All),
            Action::Char('/') => self.mode = Mode::Filter,
            Action::Char('s') => self.set_sort(self.presenter().next_sort(self.sort())),
            Action::SortBy(col) => self.set_sort(self.presenter().click_sort(self.sort(), col)),
            Action::Char('H') => self.show_system = !self.show_system,
            Action::Char('?') => self.mode = Mode::Help,
            _ => {}
        }
    }

    /// `Mode::Help`: only closing keys (and ctrl-c, handled above every
    /// mode) do anything — everything else, including the letters that are
    /// shortcuts in Normal mode, is swallowed so the overlay can't silently
    /// mutate state while it's up.
    pub(super) fn handle_help(&mut self, action: Action) {
        match action {
            Action::CtrlC => self.should_quit = true,
            Action::Char('?') | Action::Esc | Action::Char('q') | Action::Enter => {
                self.mode = Mode::Normal;
            }
            _ => {}
        }
    }

    pub(super) fn handle_filter(&mut self, action: Action) {
        match action {
            Action::CtrlC => self.should_quit = true,
            Action::Char(c) => {
                self.filter.push(c);
                self.selected_row = 0;
            }
            Action::Backspace => {
                self.filter.pop();
                self.selected_row = 0;
            }
            Action::Enter => self.mode = Mode::Normal,
            Action::Esc => {
                self.filter.clear();
                self.mode = Mode::Normal;
                self.selected_row = 0;
            }
            // Mouse-driven actions keep working while the filter box is up;
            // it only changes what *typing* means.
            Action::Up => self.move_by(-1),
            Action::Down => self.move_by(1),
            Action::SelectRow(i) => self.select_row(i),
            Action::JumpSection(i) => self.select_section(i),
            Action::ScrollDetail(d) => self.scroll_detail(d),
            _ => {}
        }
    }

    /// Esc clears an active filter first; with nothing to clear it quits.
    fn on_esc(&mut self) {
        if self.filter.is_empty() {
            self.should_quit = true;
        } else {
            self.filter.clear();
            self.selected_row = 0;
        }
    }

    /// Move the cursor `delta` rows, clamped to the section's rows.
    fn move_by(&mut self, delta: isize) {
        let n = self.row_count();
        if n == 0 {
            self.selected_row = 0;
        } else {
            let target = (self.selected_row as isize + delta).clamp(0, n as isize - 1);
            self.selected_row = target as usize;
        }
        self.detail_scroll = 0;
    }

    /// Put the cursor on an absolute row (mouse). Out-of-range is clamped.
    fn select_row(&mut self, row: usize) {
        let n = self.row_count();
        self.selected_row = row.min(n.saturating_sub(1));
        self.detail_scroll = 0;
    }

    fn next_section(&mut self) {
        self.select_section((self.selected_section + 1) % ScannerId::ALL.len());
    }

    fn prev_section(&mut self) {
        self.select_section(
            (self.selected_section + ScannerId::ALL.len() - 1) % ScannerId::ALL.len(),
        );
    }

    /// Switch to the section at `index` (a `REGISTRY`/`ScannerId::ALL` position),
    /// resetting the row cursor, scroll window, and detail scroll — the single
    /// path used by keyboard section-switching, digits, and rail clicks.
    /// Out-of-range indices are ignored.
    pub(super) fn select_section(&mut self, index: usize) {
        if index >= ScannerId::ALL.len() {
            return;
        }
        self.selected_section = index;
        self.selected_row = 0;
        self.viewport.row_offset = 0;
        self.detail_scroll = 0;
    }

    /// The tree group header at or above the cursor: the header itself when
    /// the cursor is on one, else the group the selected leaf belongs to.
    fn group_at_cursor(&self) -> Option<(usize, String)> {
        if !self.is_tree_view() {
            return None;
        }
        let rows = self.rows();
        (0..=self.selected_row.min(rows.len().saturating_sub(1)))
            .rev()
            .find_map(|i| match rows.get(i) {
                Some(RenderRow::Group { key, .. }) => Some((i, key.clone())),
                _ => None,
            })
    }

    /// `z`: toggle the group under the cursor. On a leaf, this folds its
    /// parent and moves the cursor onto the header so `z` again re-opens it.
    fn fold_at_cursor(&mut self) {
        if let Some((header_row, key)) = self.group_at_cursor() {
            self.toggle_group(key);
            self.selected_row = header_row;
            self.detail_scroll = 0;
        }
    }

    fn toggle_group(&mut self, key: String) {
        let entry = (self.selected_section_id(), key);
        if !self.collapsed_groups.remove(&entry) {
            self.collapsed_groups.insert(entry);
        }
    }

    /// Enter: "activate" the row — a group header folds/unfolds, a leaf opens
    /// the detail pane (forcing it on even below the auto-show width).
    fn on_enter(&mut self) {
        if self.is_tree_view() {
            if let Some(RenderRow::Group { key, .. }) = self.rows().get(self.selected_row) {
                let key = key.clone();
                self.toggle_group(key);
                return;
            }
        }
        self.detail_mode = DetailMode::ForceOn;
        self.detail_scroll = 0;
    }

    /// `p`: flip the detail pane relative to what is currently shown.
    fn toggle_detail(&mut self) {
        self.detail_mode = match self.detail_mode {
            DetailMode::ForceOn => DetailMode::ForceOff,
            DetailMode::ForceOff => DetailMode::ForceOn,
            DetailMode::Auto if self.viewport.detail_visible => DetailMode::ForceOff,
            DetailMode::Auto => DetailMode::ForceOn,
        };
        self.detail_scroll = 0;
    }

    fn scroll_detail(&mut self, delta: i16) {
        self.detail_scroll = self.detail_scroll.saturating_add_signed(delta);
    }
}

#[cfg(test)]
mod tests {
    use crate::ui::app::{AppState, Mode};
    use crate::ui::keys::Action;
    use crate::ui::layout::DetailMode;
    use crate::ui::testutil::*;

    #[test]
    fn tab_and_backtab_cycle_sections() {
        let mut app = AppState::default();
        let start = app.selected_section_index();
        app.handle(Action::Tab);
        assert_eq!(
            app.selected_section_index(),
            (start + 1) % crate::model::ScannerId::ALL.len()
        );
        app.handle(Action::BackTab);
        assert_eq!(app.selected_section_index(), start);
    }

    #[test]
    fn q_quits_in_normal_mode_but_is_text_in_filter_mode() {
        let mut app = AppState::default();
        app.handle(Action::Char('/'));
        app.handle(Action::Char('q'));
        assert!(!app.should_quit);
        assert_eq!(app.filter, "q");
        app.handle(Action::Esc);
        app.handle(Action::Char('q'));
        assert!(app.should_quit);
    }

    #[test]
    fn filter_mode_captures_shortcut_letters_as_text() {
        let mut app = AppState::default();
        app.handle(Action::Char('/'));
        assert_eq!(app.mode, Mode::Filter);
        for c in ['j', 'k', 'q', ' ', 'x'] {
            app.handle(Action::Char(c));
        }
        assert_eq!(app.filter, "jkq x");
        app.handle(Action::Enter);
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(app.filter, "jkq x"); // Enter applies without clearing
    }

    #[test]
    fn filter_esc_clears_and_exits() {
        let mut app = AppState::default();
        app.handle(Action::Char('/'));
        app.handle(Action::Char('a'));
        app.handle(Action::Esc);
        assert_eq!(app.mode, Mode::Normal);
        assert!(app.filter.is_empty());
    }

    #[test]
    fn left_right_switch_section_even_on_group_header() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/App1", Some(10)));
        app.apply(finding_event(1, "/App2", Some(20)));
        assert_eq!(app.rows().len(), 3); // header + 2 items, cursor on header
        let section = app.selected_section_index();

        app.handle(Action::Left);
        assert_eq!(app.selected_section_index(), section - 1);
        app.handle(Action::Right);
        assert_eq!(app.selected_section_index(), section);
        assert_eq!(app.rows().len(), 3, "arrows never fold");

        app.handle(Action::Char('l'));
        assert_eq!(app.selected_section_index(), section + 1);
        app.handle(Action::Char('h'));
        assert_eq!(app.selected_section_index(), section);
    }

    #[test]
    fn z_and_enter_fold_header_but_enter_on_leaf_opens_detail() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/App1", Some(10)));
        app.apply(finding_event(1, "/App2", Some(20)));

        app.handle(Action::Char('z')); // cursor on header → collapse
        assert_eq!(app.rows().len(), 1);
        app.handle(Action::Enter); // enter on header → expand
        assert_eq!(app.rows().len(), 3);
        assert_eq!(
            app.detail_mode,
            DetailMode::Auto,
            "header never toggles detail"
        );

        app.handle(Action::Down); // onto a leaf
        app.handle(Action::Enter);
        assert_eq!(app.detail_mode, DetailMode::ForceOn);
        app.handle(Action::Enter);
        assert_eq!(
            app.detail_mode,
            DetailMode::ForceOn,
            "enter opens, never toggles"
        );

        // z on a leaf folds its parent and parks the cursor on the header.
        app.handle(Action::Char('z'));
        assert_eq!(app.rows().len(), 1);
        assert_eq!(app.selected_row, 0);
    }

    #[test]
    fn digit_keys_jump_sections_zero_is_tenth_out_of_range_ignored() {
        let mut app = AppState::default();
        app.handle(Action::Char('4'));
        assert_eq!(app.selected_section_index(), 3);
        app.handle(Action::Char('0'));
        assert_eq!(app.selected_section_index(), 9);
        app.handle(Action::Char('1'));
        assert_eq!(app.selected_section_index(), 0);
        app.handle(Action::JumpSection(99));
        assert_eq!(app.selected_section_index(), 0);
    }

    #[test]
    fn esc_clears_filter_before_quitting() {
        let mut app = AppState::default();
        app.handle(Action::Char('/'));
        app.handle(Action::Char('a'));
        app.handle(Action::Enter); // apply, back to Normal with filter set
        app.handle(Action::Esc);
        assert!(!app.should_quit);
        assert!(app.filter.is_empty());
        app.handle(Action::Esc);
        assert!(app.should_quit);
    }

    #[test]
    fn p_toggles_detail_relative_to_current_visibility() {
        let mut app = AppState::default();
        // Auto at a wide width shows the pane; p should then force it off.
        render(&mut app, 150, 40);
        assert!(app.viewport.detail_visible);
        app.handle(Action::Char('p'));
        assert_eq!(app.detail_mode, DetailMode::ForceOff);
        app.handle(Action::Char('p'));
        assert_eq!(app.detail_mode, DetailMode::ForceOn);

        // Auto at a narrow width hides it; p forces it on.
        let mut app = AppState::default();
        render(&mut app, 100, 40);
        assert!(!app.viewport.detail_visible);
        app.handle(Action::Char('p'));
        assert_eq!(app.detail_mode, DetailMode::ForceOn);
    }

    #[test]
    fn question_mark_opens_help_and_esc_closes_it() {
        let mut app = AppState::default();
        assert_eq!(app.mode, Mode::Normal);

        app.handle(Action::Char('?'));
        assert_eq!(app.mode, Mode::Help);

        app.handle(Action::Esc);
        assert_eq!(app.mode, Mode::Normal);
    }

    #[test]
    fn help_mode_also_closes_on_q_enter_or_question_mark() {
        for closer in [Action::Char('q'), Action::Enter, Action::Char('?')] {
            let mut app = AppState::default();
            app.handle(Action::Char('?'));
            assert_eq!(app.mode, Mode::Help);
            app.handle(closer);
            assert_eq!(app.mode, Mode::Normal, "{closer:?} should close Help");
        }
    }

    #[test]
    fn help_mode_swallows_shortcut_keys_without_mutating_state() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/a", Some(10)));
        app.apply(finding_event(1, "/b", Some(20)));
        let row_before = app.selected_row;
        let filter_before = app.filter.clone();
        let marked_before = app.marked_total();

        app.handle(Action::Char('?'));
        assert_eq!(app.mode, Mode::Help);

        // Keys that are shortcuts elsewhere must be no-ops while Help is up.
        for action in [
            Action::Char('j'),
            Action::Down,
            Action::Char(' '),
            Action::Char('x'),
            Action::Char('/'),
            Action::Char('s'),
            Action::Char('H'),
            Action::Char('r'),
        ] {
            app.handle(action);
        }

        assert_eq!(
            app.mode,
            Mode::Help,
            "still in Help — nothing should escape it"
        );
        assert_eq!(app.selected_row, row_before, "selection must not move");
        assert_eq!(app.filter, filter_before, "filter must not change");
        assert_eq!(app.marked_total(), marked_before, "marks must not change");
        assert!(app.pending_rescan.is_none(), "no rescan should be queued");
    }

    #[test]
    fn ctrl_c_quits_even_while_help_is_open() {
        let mut app = AppState::default();
        app.handle(Action::Char('?'));
        assert_eq!(app.mode, Mode::Help);
        app.handle(Action::CtrlC);
        assert!(app.should_quit);
    }

    #[test]
    fn page_keys_move_selection_by_visible_rows_and_jk_scroll_detail() {
        let mut app = app_with_gen(1);
        for i in 0..40 {
            app.apply(finding_event(1, &format!("/App{i:02}"), Some(1)));
        }
        render(&mut app, 150, 20);
        let page = app.viewport.page_size();
        assert!(page > 1);
        app.handle(Action::PageDown);
        assert_eq!(app.selected_row, page);
        app.handle(Action::PageUp);
        assert_eq!(app.selected_row, 0);

        app.handle(Action::Char('J'));
        assert_eq!(app.detail_scroll, 3);
        app.handle(Action::Char('K'));
        app.handle(Action::Char('K'));
        assert_eq!(app.detail_scroll, 0, "saturates at 0");
    }

    #[test]
    fn detail_scroll_resets_on_selection_and_section_change() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/a", Some(10)));
        app.apply(finding_event(1, "/b", Some(20)));
        app.detail_scroll = 15;

        app.handle(Action::Down); // moves selection within the section
        assert_eq!(app.detail_scroll, 0, "moving selection resets scroll");

        app.detail_scroll = 15;
        app.handle(Action::Tab); // switches section
        assert_eq!(app.detail_scroll, 0, "switching section resets scroll");

        app.detail_scroll = 15;
        app.handle(Action::Char('p')); // toggles the detail pane
        assert_eq!(app.detail_scroll, 0, "toggling detail resets scroll");
    }
}
