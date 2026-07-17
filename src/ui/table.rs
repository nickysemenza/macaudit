//! Sortable flat table view for `ViewKind::Table` sections (Disk, Daemons,
//! Shell, Runtimes, Docker, Ports, Git, Simulators, Keys, Snapshots).

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};
use ratatui::Frame;

use crate::model::{Finding, FindingId};
use crate::ui::theme;

/// Render `rows` (already filtered/sorted by the caller) as a table,
/// highlighting `selected`. Marked rows show `theme::MARK` in the first column.
/// `is_scanning` controls the size placeholder: a `None` size shows `…` only
/// while the section is still scanning (a genuinely pending fs size), and blank
/// once done (most sections have no size concept at all).
pub fn draw(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    rows: &[&Finding],
    is_marked: impl Fn(FindingId) -> bool,
    selected: usize,
    is_scanning: bool,
) {
    let table_rows: Vec<Row> = rows
        .iter()
        .map(|f| {
            let mark = if is_marked(f.id) { theme::MARK } else { " " };
            Row::new(vec![
                Cell::from(mark),
                Cell::from(f.title.clone()),
                Cell::from(Span::styled(
                    abbrev_path(f),
                    Style::default().fg(Color::DarkGray),
                )),
                Cell::from(render_size(f.size_bytes, is_scanning)),
                Cell::from(Span::styled(
                    severity_label(f.severity),
                    Style::default().fg(theme::severity_color(f.severity)),
                )),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(2),
        Constraint::Min(18),
        Constraint::Min(24),
        Constraint::Length(11),
        Constraint::Length(10),
    ];
    let table = Table::new(table_rows, widths)
        .header(
            Row::new(vec!["", "Name", "Path", "Size", "Severity"])
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

/// Size cell text: the human size, `…` while a size is still pending, else blank.
fn render_size(size: Option<u64>, is_scanning: bool) -> String {
    match size {
        Some(b) => humansize::format_size(b, humansize::BINARY),
        None if is_scanning => "…".to_string(),
        None => String::new(),
    }
}

/// Display path with the user's home abbreviated to `~` (macOS `/Users/<u>/…`).
/// Empty when the finding has no path.
pub fn abbrev_path(f: &Finding) -> String {
    let Some(p) = &f.path else {
        return String::new();
    };
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("/Users/") {
        if let Some(idx) = rest.find('/') {
            return format!("~{}", &rest[idx..]);
        }
    }
    s.into_owned()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FindingKind;

    #[test]
    fn abbreviates_home() {
        let f = Finding::new(
            FindingKind::BuildArtifact,
            "/Users/nicky/dev/x/target",
            "target",
        )
        .path("/Users/nicky/dev/x/target");
        assert_eq!(abbrev_path(&f), "~/dev/x/target");
    }

    #[test]
    fn non_home_path_untouched_and_missing_is_blank() {
        let f = Finding::new(FindingKind::LaunchdItem, "/Library/x.plist", "x")
            .path("/Library/x.plist");
        assert_eq!(abbrev_path(&f), "/Library/x.plist");
        let g = Finding::new(FindingKind::GitRepo, "k", "k");
        assert_eq!(abbrev_path(&g), "");
    }

    #[test]
    fn size_placeholder_only_while_scanning() {
        assert_eq!(render_size(None, true), "…");
        assert_eq!(render_size(None, false), "");
        assert_eq!(render_size(Some(1024), false), "1 KiB");
    }
}
