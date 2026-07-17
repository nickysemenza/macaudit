//! Colors and glyphs shared across UI widgets.

use ratatui::style::Color;

use crate::model::Severity;

/// Color for a severity badge.
pub fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::Info => Color::Gray,
        Severity::Attention => Color::Yellow,
        Severity::Reclaimable => Color::Cyan,
        Severity::Warning => Color::Red,
    }
}

/// Spinner frames for in-progress sections.
pub const SPINNER: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// Spinner glyph for a tick counter.
pub fn spinner(tick: usize) -> char {
    SPINNER[tick % SPINNER.len()]
}

/// Glyph shown next to a marked row.
pub const MARK: &str = "●";

/// Glyphs for an expanded / collapsed tree group header.
pub const EXPANDED: &str = "▾";
pub const COLLAPSED: &str = "▸";

/// Color for a remedy command, based on whether it's destructive. Detail and
/// confirm panes both use this so "red means it deletes/changes something"
/// stays consistent everywhere a rendered command is shown.
pub fn remedy_color(destructive: bool) -> Color {
    if destructive {
        Color::Red
    } else {
        Color::Green
    }
}
