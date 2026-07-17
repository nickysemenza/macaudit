//! Colors and glyphs shared across UI widgets. Lane U may expand.

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
