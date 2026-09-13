//! Mouse routing. Every click/wheel resolves to a `Hit` from the last frame's
//! `Viewport` and is then re-expressed as a keyboard `Action`, so the mouse
//! can never do anything a key can't (and the reducer tests cover both).

use std::time::{Duration, Instant};

use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

use crate::ui::app::{AppState, Mode};
use crate::ui::keys::Action;
use crate::ui::layout::Hit;

/// Two left-clicks on the same row within this window count as a double-click.
pub const DOUBLE_CLICK_WINDOW: Duration = Duration::from_millis(350);
/// Rows (or detail lines) moved per wheel notch.
const WHEEL_STEP: i16 = 3;

impl AppState {
    pub fn handle_mouse(&mut self, me: MouseEvent) {
        self.handle_mouse_at(me, Instant::now());
    }

    /// `handle_mouse` with an explicit clock, for double-click tests.
    pub(super) fn handle_mouse_at(&mut self, me: MouseEvent, now: Instant) {
        // Modals own the screen; the filter box only changes what typing
        // means, so pointing still works there.
        if matches!(self.mode, Mode::Confirm | Mode::Help) {
            return;
        }
        let Some(hit) = self.viewport.hit(me.column, me.row) else {
            return;
        };
        match me.kind {
            MouseEventKind::Down(MouseButton::Left) => self.on_left_click(hit, now),
            MouseEventKind::ScrollUp => self.on_wheel(hit, -1),
            MouseEventKind::ScrollDown => self.on_wheel(hit, 1),
            _ => {}
        }
    }

    fn on_left_click(&mut self, hit: Hit, now: Instant) {
        let double = matches!(
            self.last_click,
            Some((t, prev)) if prev == hit && now.duration_since(t) <= DOUBLE_CLICK_WINDOW
        );
        self.last_click = Some((now, hit));
        match hit {
            Hit::RailRow(i) | Hit::OverviewSection(i) => self.handle(Action::JumpSection(i)),
            Hit::ColumnHeader(col) if self.mode == Mode::Normal => self.handle(Action::SortBy(col)),
            Hit::Row(i) => {
                self.handle(Action::SelectRow(i));
                if double {
                    self.handle(Action::Enter);
                }
            }
            // Hints are Normal-mode shortcuts; while filtering they'd just be
            // typed into the box.
            Hit::StatusHint(action) if self.mode == Mode::Normal => self.handle(action),
            _ => {}
        }
    }

    fn on_wheel(&mut self, hit: Hit, direction: i16) {
        match hit {
            Hit::Rail | Hit::RailRow(_) => self.handle(if direction < 0 {
                Action::BackTab
            } else {
                Action::Tab
            }),
            Hit::Detail => self.handle(Action::ScrollDetail(direction * WHEEL_STEP)),
            Hit::MainPanel | Hit::Row(_) | Hit::OverviewSection(_) => {
                let step = if direction < 0 {
                    Action::Up
                } else {
                    Action::Down
                };
                for _ in 0..WHEEL_STEP {
                    self.handle(step);
                }
            }
            Hit::StatusHint(_) | Hit::ColumnHeader(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crossterm::event::{KeyModifiers, MouseEvent, MouseEventKind};

    use crate::ui::app::{AppState, Mode};
    use crate::ui::keys::Action;
    use crate::ui::layout::{DetailMode, Hit};
    use crate::ui::testutil::*;

    fn wheel(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    /// Screen position of the first registered `Row(index)` hit.
    fn row_pos(app: &AppState, index: usize) -> (u16, u16) {
        app.viewport
            .position_of(Hit::Row(index))
            .expect("row is on screen")
    }

    #[test]
    fn rail_click_selects_section_row() {
        let mut app = AppState::default();
        render(&mut app, 150, 40);
        let (x, y) = app.viewport.position_of(Hit::RailRow(3)).unwrap();
        app.handle_mouse(left_click(x, y));
        assert_eq!(app.selected_section_index(), 3);
        render(&mut app, 150, 40); // a frame is drawn between clicks

        // A click in the (empty) main panel leaves the section alone.
        app.handle_mouse(left_click(60, 20));
        assert_eq!(app.selected_section_index(), 3);

        // A rail row below the last section isn't registered at all.
        let (x0, y0) = app.viewport.position_of(Hit::RailRow(0)).unwrap();
        app.handle_mouse(left_click(x0, y0 + 30));
        assert_eq!(app.selected_section_index(), 3);

        app.handle_mouse(left_click(x0, y0));
        assert_eq!(app.selected_section_index(), 0);
    }

    #[test]
    fn sidebar_click_ignored_in_modal_mode() {
        let mut app = AppState::default();
        render(&mut app, 150, 40);
        let (x, y) = app.viewport.position_of(Hit::RailRow(3)).unwrap();
        app.mode = Mode::Help;
        app.handle_mouse(left_click(x, y));
        assert_eq!(app.selected_section_index(), 0); // unchanged while modal
    }

    #[test]
    fn click_row_selects_with_scroll_offset() {
        let mut app = app_with_gen(1);
        for i in 0..50 {
            app.apply(finding_event(1, &format!("/App{i:02}"), Some(1)));
        }
        // 20 rows tall: the main panel shows ~17 rows; move deep into the list
        // so the window has scrolled.
        for _ in 0..35 {
            app.handle(Action::Down);
        }
        render(&mut app, 150, 20);
        let offset = app.viewport.row_offset;
        assert!(offset > 0, "window should have scrolled");

        let (x, y) = row_pos(&app, offset + 2);
        app.handle_mouse(left_click(x, y));
        assert_eq!(app.selected_row, offset + 2);
    }

    #[test]
    fn double_click_opens_detail_only_within_window() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/a", Some(1)));
        app.detail_mode = DetailMode::ForceOff;
        render(&mut app, 150, 40);
        let (x, y) = row_pos(&app, 1); // row 0 is the group header

        let t0 = Instant::now();
        app.handle_mouse_at(left_click(x, y), t0);
        app.handle_mouse_at(left_click(x, y), t0 + Duration::from_millis(100));
        assert_eq!(
            app.detail_mode,
            DetailMode::ForceOn,
            "double-click opens detail"
        );

        app.detail_mode = DetailMode::ForceOff;
        app.handle_mouse_at(left_click(x, y), t0 + Duration::from_millis(1000));
        app.handle_mouse_at(left_click(x, y), t0 + Duration::from_millis(1600));
        assert_eq!(
            app.detail_mode,
            DetailMode::ForceOff,
            "slow clicks are two singles"
        );
    }

    #[test]
    fn double_click_on_group_header_folds_it() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/a", Some(1)));
        app.apply(finding_event(1, "/b", Some(2)));
        render(&mut app, 150, 40);
        let (x, y) = row_pos(&app, 0);
        let t0 = Instant::now();
        app.handle_mouse_at(left_click(x, y), t0);
        app.handle_mouse_at(left_click(x, y), t0 + Duration::from_millis(50));
        assert_eq!(app.rows().len(), 1, "group collapsed");
        assert_eq!(
            app.detail_mode,
            DetailMode::Auto,
            "no detail toggle on a header"
        );
    }

    #[test]
    fn wheel_over_rail_switches_section_and_over_rows_moves_three() {
        let mut app = app_with_gen(1);
        for i in 0..10 {
            app.apply(finding_event(1, &format!("/App{i}"), Some(1)));
        }
        render(&mut app, 150, 40);

        let (rx, ry) = app.viewport.position_of(Hit::RailRow(0)).unwrap();
        app.handle_mouse(wheel(MouseEventKind::ScrollDown, rx, ry));
        assert_eq!(app.selected_section_index(), 2);
        app.handle_mouse(wheel(MouseEventKind::ScrollUp, rx, ry));
        assert_eq!(app.selected_section_index(), 1);

        let (x, y) = row_pos(&app, 0);
        app.handle_mouse(wheel(MouseEventKind::ScrollDown, x, y));
        assert_eq!(app.selected_row, 3);
        app.handle_mouse(wheel(MouseEventKind::ScrollUp, x, y));
        assert_eq!(app.selected_row, 0);
    }

    #[test]
    fn wheel_over_detail_scrolls_it() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/a", Some(1)));
        app.handle(Action::Down);
        app.detail_mode = DetailMode::ForceOn;
        render(&mut app, 150, 40);
        let (x, y) = app.viewport.position_of(Hit::Detail).unwrap();
        app.handle_mouse(wheel(MouseEventKind::ScrollDown, x + 2, y + 2));
        assert_eq!(app.detail_scroll, 3);
        app.handle_mouse(wheel(MouseEventKind::ScrollUp, x + 2, y + 2));
        assert_eq!(app.detail_scroll, 0);
    }

    #[test]
    fn column_header_click_sorts_then_flips_direction() {
        use crate::model::{Finding, FindingKind, ScanEvent, ScannerId};
        use crate::ui::present::{ColumnId, SortDir, SortSpec};

        let mut app = app_with_gen(1);
        app.handle(Action::Char('0')); // Git
        for (name, branch) in [("a", "zeta"), ("b", "alpha")] {
            let f = Finding::new(FindingKind::GitRepo, name, name)
                .meta(serde_json::json!({ "branch": branch }));
            app.apply(ScanEvent::Finding {
                scanner: ScannerId::Git,
                gen: 1,
                finding: Box::new(f),
            });
        }
        render(&mut app, 200, 40);
        let (x, y) = app
            .viewport
            .position_of(Hit::ColumnHeader(ColumnId::Branch))
            .unwrap();
        app.handle_mouse(left_click(x, y));
        assert_eq!(app.sort(), SortSpec::col(ColumnId::Branch, SortDir::Asc));
        assert_eq!(app.visible_findings()[0].title, "b");
        render(&mut app, 200, 40);
        app.handle_mouse(left_click(x, y));
        assert_eq!(app.sort(), SortSpec::col(ColumnId::Branch, SortDir::Desc));
        assert_eq!(app.visible_findings()[0].title, "a");
    }

    #[test]
    fn statusbar_hint_click_performs_its_action() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/a", Some(1)));
        render(&mut app, 150, 40);
        let (x, y) = app
            .viewport
            .position_of(Hit::StatusHint(Action::Char('?')))
            .unwrap();
        app.handle_mouse(left_click(x, y));
        assert_eq!(app.mode, Mode::Help);
    }

    #[test]
    fn overview_source_row_click_jumps_to_section() {
        let mut app = AppState::default();
        render(&mut app, 150, 40);
        let (x, y) = app.viewport.position_of(Hit::OverviewSection(3)).unwrap();
        app.handle_mouse(left_click(x, y));
        assert_eq!(app.selected_section_index(), 3); // Disk
    }
}
