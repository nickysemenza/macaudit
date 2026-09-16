//! Frame geometry that the reducer needs to know about after a draw: which
//! screen cells map to which interactive thing (`Hit`), how far the main
//! panel is scrolled, and whether the detail pane / nav rail are visible at
//! the current width. `draw()` rebuilds a `Viewport` every frame and stores
//! it on `AppState`; mouse handling and paging read it back.

use ratatui::layout::{Constraint, Direction, Layout, Rect};

use crate::ui::keys::Action;
use crate::ui::present::ColumnId;

/// Something under the mouse. Registered by the widgets during `draw`, in
/// paint order — later (more specific) regions win on overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hit {
    /// The nav rail as a whole (wheel target).
    Rail,
    /// One section row in the nav rail.
    RailRow(usize),
    /// The main panel as a whole (wheel target).
    MainPanel,
    /// One data row in the main panel; the index is already offset-adjusted
    /// (it indexes `tree_rows()` / `visible_findings()` directly).
    Row(usize),
    /// A sortable column's header cell.
    ColumnHeader(ColumnId),
    /// The detail pane (wheel target).
    Detail,
    /// A clickable key hint in the statusbar.
    StatusHint(Action),
    /// A row in the Overview's "sources" list that links to a section.
    OverviewSection(usize),
}

/// Geometry recorded by the last `draw`.
#[derive(Debug, Default)]
pub struct Viewport {
    hits: Vec<(Rect, Hit)>,
    /// First visible data row of the main panel. Persists across frames so
    /// the window only moves when the selection would leave it.
    pub row_offset: usize,
    /// Data rows that fit in the main panel (the page size).
    pub rows_visible: usize,
    pub detail_visible: bool,
}

impl Viewport {
    /// Fresh viewport carrying over the previous frame's scroll offset (the
    /// only piece of state that must persist between frames).
    pub fn new(row_offset: usize) -> Self {
        Viewport {
            row_offset,
            ..Default::default()
        }
    }

    pub fn push(&mut self, area: Rect, hit: Hit) {
        if area.width > 0 && area.height > 0 {
            self.hits.push((area, hit));
        }
    }

    /// The most specific region containing (`x`, `y`), if any.
    pub fn hit(&self, x: u16, y: u16) -> Option<Hit> {
        self.hits
            .iter()
            .rev()
            .find(|(r, _)| r.contains(ratatui::layout::Position { x, y }))
            .map(|(_, h)| *h)
    }

    /// Top-left cell of the first region registered for `hit` (tests).
    #[cfg(test)]
    pub fn position_of(&self, hit: Hit) -> Option<(u16, u16)> {
        self.hits
            .iter()
            .find(|(_, h)| *h == hit)
            .map(|(r, _)| (r.x, r.y))
    }

    /// Rows per page for PgUp/PgDn. Before the first frame nothing has been
    /// measured, so fall back to a sane default rather than paging by zero.
    pub fn page_size(&self) -> usize {
        self.rows_visible.max(1)
    }
}

/// Whether the detail pane is shown. `Auto` follows the terminal width; the
/// `p` key forces it either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DetailMode {
    #[default]
    Auto,
    ForceOn,
    ForceOff,
}

/// Detail pane appears automatically at this width or wider.
pub const DETAIL_AUTO_MIN_WIDTH: u16 = 120;

pub fn detail_visible(mode: DetailMode, width: u16) -> bool {
    match mode {
        DetailMode::Auto => width >= DETAIL_AUTO_MIN_WIDTH,
        DetailMode::ForceOn => true,
        DetailMode::ForceOff => false,
    }
}

/// Width of the detail pane for a frame `width` wide.
pub fn detail_constraint(width: u16) -> Constraint {
    if width >= 160 {
        Constraint::Length(48)
    } else {
        Constraint::Percentage(35)
    }
}

/// How much of the nav rail fits. Narrow terminals collapse the badges, then
/// drop the rail entirely (the statusbar shows `n/13 Section` instead).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RailMode {
    Full,
    Compact,
    Hidden,
}

impl RailMode {
    pub fn for_width(width: u16) -> RailMode {
        if width >= 100 {
            RailMode::Full
        } else if width >= 70 {
            RailMode::Compact
        } else {
            RailMode::Hidden
        }
    }

    /// Columns the rail occupies, including its right border.
    pub fn width(self) -> u16 {
        match self {
            RailMode::Full => 26,
            RailMode::Compact => 15,
            RailMode::Hidden => 0,
        }
    }
}

/// A `percent_x` × `percent_y` rectangle centered within `r`.
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

/// Compute a scroll offset such that `selected` stays within the visible
/// window `[offset, offset+visible)`, moving `prev` as little as possible.
/// Clamped so `offset <= len.saturating_sub(visible)`. Degenerate inputs
/// (`visible == 0` or `len == 0`) return 0.
pub fn adjust_offset(prev: usize, selected: usize, len: usize, visible: usize) -> usize {
    if visible == 0 || len == 0 {
        return 0;
    }
    let max_offset = len.saturating_sub(visible);
    let mut offset = prev.min(max_offset);
    if selected < offset {
        offset = selected;
    } else if selected >= offset + visible {
        offset = selected + 1 - visible;
    }
    offset.min(max_offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_below_window_scrolls_down_minimally() {
        // Window of 5 rows, cursor moves to row 7: offset advances just
        // enough that row 7 becomes the last visible row (offset 3).
        assert_eq!(adjust_offset(0, 7, 20, 5), 3);
    }

    #[test]
    fn selection_above_window_scrolls_up_to_selection() {
        assert_eq!(adjust_offset(10, 2, 20, 5), 2);
    }

    #[test]
    fn selection_in_window_keeps_prev() {
        assert_eq!(adjust_offset(3, 4, 20, 5), 3);
    }

    #[test]
    fn clamps_at_end_of_list() {
        // prev is already beyond what a shrunk list allows.
        assert_eq!(adjust_offset(15, 9, 10, 5), 5);
    }

    #[test]
    fn shrink_handling_zero_visible_or_len() {
        assert_eq!(adjust_offset(3, 1, 0, 5), 0);
        assert_eq!(adjust_offset(3, 1, 5, 0), 0);
    }

    #[test]
    fn hit_prefers_most_recently_pushed_region() {
        let mut vp = Viewport::new(0);
        vp.push(Rect::new(0, 0, 80, 10), Hit::MainPanel);
        vp.push(Rect::new(0, 3, 80, 1), Hit::Row(7));
        assert_eq!(vp.hit(5, 3), Some(Hit::Row(7)));
        assert_eq!(vp.hit(5, 4), Some(Hit::MainPanel));
        assert_eq!(vp.hit(5, 20), None);
    }

    #[test]
    fn detail_auto_threshold_and_force_override() {
        assert!(!detail_visible(DetailMode::Auto, 119));
        assert!(detail_visible(DetailMode::Auto, 120));
        assert!(detail_visible(DetailMode::ForceOn, 40));
        assert!(!detail_visible(DetailMode::ForceOff, 200));
    }

    #[test]
    fn rail_mode_by_width() {
        assert_eq!(RailMode::for_width(150), RailMode::Full);
        assert_eq!(RailMode::for_width(100), RailMode::Full);
        assert_eq!(RailMode::for_width(99), RailMode::Compact);
        assert_eq!(RailMode::for_width(70), RailMode::Compact);
        assert_eq!(RailMode::for_width(69), RailMode::Hidden);
    }
}
