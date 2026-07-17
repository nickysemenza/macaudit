//! Detail pane (toggled by `enter`): the selected Finding's full metadata
//! plus every remedy's *literal* command string. This pane is the guarantee
//! behind spec §4's promise — "the tool must never run anything the user
//! hasn't seen verbatim" — so it must render `remedy.command.rendered()`
//! unmodified, never a paraphrase.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::config::DeleteMode;
use crate::model::Finding;
use crate::remedy::RemedyEngine;
use crate::ui::theme;

pub fn draw(frame: &mut Frame, area: Rect, selected: Option<&Finding>, delete_mode: DeleteMode) {
    let block = Block::default().borders(Borders::ALL).title(" Detail ");
    let text: Vec<Line> = match selected {
        None => vec![Line::from("No selection")],
        Some(f) => render_finding(f, delete_mode),
    };
    frame.render_widget(Paragraph::new(text).block(block), area);
}

fn render_finding(f: &Finding, delete_mode: DeleteMode) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(
            f.title.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(f.detail.clone()),
    ];
    if let Some(p) = &f.path {
        lines.push(Line::from(format!("path: {}", p.display())));
    }
    if let Some(b) = f.size_bytes {
        lines.push(Line::from(format!(
            "size: {}",
            humansize::format_size(b, humansize::BINARY)
        )));
    }
    if let Some(t) = f.last_used {
        if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
            lines.push(Line::from(format!(
                "last used: {}s since epoch",
                d.as_secs()
            )));
        }
    }

    if !f.meta.is_null() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Meta:",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        let pretty = serde_json::to_string_pretty(&f.meta).unwrap_or_else(|_| f.meta.to_string());
        for line in pretty.lines() {
            lines.push(Line::from(format!("  {line}")));
        }
    }

    if !f.remedies.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Remedies:",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        // Render through the RemedyEngine so the string shown matches what would
        // actually run — under `--rm`, a Trash remedy displays as `rm -rf …`.
        let engine = RemedyEngine::new(delete_mode);
        for r in &f.remedies {
            let action = engine.plan_one(f.id, r);
            let color = theme::remedy_color(r.destructive);
            lines.push(Line::from(vec![
                Span::raw(format!("  {} — ", r.label)),
                Span::styled(action.rendered, Style::default().fg(color)),
            ]));
        }
    }
    lines
}
