//! Sortable flat table view for `ViewKind::Table` sections (Disk, Daemons,
//! Shell, Runtimes, Docker, Ports, Git, Simulators, Keys, Snapshots).

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};
use ratatui::Frame;

use crate::model::{Finding, FindingId};
use crate::ui::theme;

/// Render `rows` (already filtered/sorted by the caller) as a table,
/// highlighting `selected`. Marked rows show `theme::MARK` in the first
/// column.
pub fn draw(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    rows: &[&Finding],
    is_marked: impl Fn(FindingId) -> bool,
    selected: usize,
) {
    let table_rows: Vec<Row> = rows
        .iter()
        .map(|f| {
            let mark = if is_marked(f.id) { theme::MARK } else { " " };
            let size = f
                .size_bytes
                .map(|b| humansize::format_size(b, humansize::BINARY))
                .unwrap_or_else(|| "…".to_string());
            Row::new(vec![
                Cell::from(mark),
                Cell::from(f.title.clone()),
                Cell::from(size),
                Cell::from(Span::styled(
                    severity_label(f.severity),
                    Style::default().fg(theme::severity_color(f.severity)),
                )),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(2),
        Constraint::Min(20),
        Constraint::Length(12),
        Constraint::Length(12),
    ];
    let table = Table::new(table_rows, widths)
        .header(
            Row::new(vec!["", "Name", "Size", "Severity"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {title} ")),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    let mut ts = TableState::default();
    if !rows.is_empty() {
        ts.select(Some(selected.min(rows.len() - 1)));
    }
    frame.render_stateful_widget(table, area, &mut ts);
}

fn severity_label(sev: crate::model::Severity) -> &'static str {
    use crate::model::Severity;
    match sev {
        Severity::Info => "info",
        Severity::Attention => "attention",
        Severity::Reclaimable => "reclaim",
        Severity::Warning => "warning",
    }
}
