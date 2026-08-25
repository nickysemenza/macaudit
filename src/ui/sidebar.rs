//! Left sidebar: one row per `registry::REGISTRY` section, with a status
//! glyph (spinner while scanning, ✓ + count/reclaimable when done, ⚠ on
//! failure) and highlighting for the selected section.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem};
use ratatui::Frame;

use crate::registry;
use crate::ui::app::{AppState, SectionStatus};
use crate::ui::theme;

pub fn draw(app: &AppState, frame: &mut Frame, area: Rect) {
    let items: Vec<ListItem> = registry::REGISTRY
        .iter()
        .enumerate()
        .map(|(i, meta)| {
            let status = app.status_of(meta.id);
            let glyph = match &status {
                SectionStatus::Idle => " ".to_string(),
                SectionStatus::Scanning { .. } => theme::spinner(app.tick).to_string(),
                SectionStatus::Done { .. } => "✓".to_string(),
                SectionStatus::Failed { .. } => "⚠".to_string(),
            };
            let count = app.section_count(meta.id);
            let reclaim = app.section_reclaimable(meta.id);
            let suffix = if matches!(status, SectionStatus::Done { .. }) && count > 0 {
                if reclaim > 0 {
                    format!(
                        "{count} · {}",
                        humansize::format_size(reclaim, humansize::BINARY)
                    )
                } else {
                    format!("{count}")
                }
            } else {
                String::new()
            };
            let selected = i == app.selected_section_index();
            let style = if selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            // "Δ since last snapshot" badge: growth red, shrink green.
            let mut spans = vec![
                Span::raw(format!("{glyph} ")),
                Span::raw(format!("{:<15}", meta.title)),
                Span::styled(suffix, Style::default().fg(Color::DarkGray)),
            ];
            if let Some(delta) = app.section_reclaimable_delta(meta.id) {
                let mag = humansize::format_size(delta.unsigned_abs(), humansize::BINARY);
                let (sign, color) = if delta > 0 {
                    ("+", Color::Red)
                } else {
                    ("-", Color::Green)
                };
                spans.push(Span::styled(
                    format!(" Δ{sign}{mag}"),
                    Style::default().fg(color),
                ));
            }
            ListItem::new(Line::from(spans)).style(style)
        })
        .collect();
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(" macaudit "));
    frame.render_widget(list, area);
}
