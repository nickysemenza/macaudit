//! Activity log pane: remediation results stream in here as tokio tasks
//! complete (spec §4). Shown only while there's something to show — an empty
//! log costs no screen real estate.

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Number of trailing lines visible at once; the full history is kept in
/// `AppState::activity`, this just windows the tail.
pub const VISIBLE_LINES: usize = 5;

pub fn draw(frame: &mut Frame, area: Rect, lines: &[String]) {
    let start = lines.len().saturating_sub(VISIBLE_LINES);
    let text: Vec<Line> = lines[start..]
        .iter()
        .map(|l| {
            Line::from(Span::styled(
                l.clone(),
                Style::default().fg(Color::DarkGray),
            ))
        })
        .collect();
    // A single rule above the log instead of a box: it's a footer, not a pane.
    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " activity ",
            Style::default().fg(Color::DarkGray),
        ));
    frame.render_widget(Paragraph::new(text).block(block), area);
}

/// Rendered height (including the top rule) for a non-empty activity log.
pub fn height_for(lines: &[String]) -> u16 {
    if lines.is_empty() {
        0
    } else {
        (lines.len().min(VISIBLE_LINES) + 1) as u16
    }
}
