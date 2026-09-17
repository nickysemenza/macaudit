//! The manual Resource Health overview. It summarizes actual scanner findings
//! without manufacturing cleanup actions: every recommendation points back to
//! the existing Disk/Docker/Simulators/Time Machine source sections in the sidebar.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::model::{Finding, FindingKind, ScannerId, Severity};
use crate::ui::app::{AppState, SectionStatus};
use crate::ui::layout::{Hit, Viewport};
use crate::ui::{fmt, theme};

pub fn draw(app: &AppState, frame: &mut Frame, area: Rect, vp: &mut Viewport) {
    // One frame, three headed sections — nested boxes cost four cells each
    // and made the cards wrap early.
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Resource Health ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Min(6),
        ])
        .split(inner);
    draw_now(app, frame, rows[0]);
    draw_attention(app, frame, rows[1]);
    draw_sources(app, frame, rows[2], vp);
}

fn heading(text: &'static str) -> Line<'static> {
    Line::from(Span::styled(
        text,
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ))
}

fn draw_now(app: &AppState, frame: &mut Frame, area: Rect) {
    let findings = app.overview_findings(ScannerId::System);
    let cards: Vec<Line> = ["cpu", "memory", "swap", "disk"]
        .iter()
        .filter_map(|role| metric(&findings, role))
        .map(|f| {
            Line::from(vec![
                Span::styled(
                    format!("{: <16}", f.title),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    f.detail.clone(),
                    Style::default().fg(theme::severity_color(f.severity)),
                ),
            ])
        })
        .collect();
    let mut text = vec![heading("Now — manual point-in-time sample")];
    if cards.is_empty() {
        text.push(Line::from(Span::styled(
            "Waiting for the manual resource sample…",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        text.extend(cards);
    }
    frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), area);
}

fn draw_attention(app: &AppState, frame: &mut Frame, area: Rect) {
    let mut items: Vec<&Finding> = app
        .overview_findings(ScannerId::System)
        .into_iter()
        .filter(|f| {
            matches!(f.kind, FindingKind::ProcessResource) || f.severity >= Severity::Attention
        })
        .collect();
    items.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.size_bytes.cmp(&a.size_bytes))
    });
    let mut lines = vec![heading("Attention & active consumers")];
    for f in items.into_iter().take(5) {
        lines.push(Line::from(vec![
            Span::styled("• ", Style::default().fg(theme::severity_color(f.severity))),
            Span::styled(
                f.title.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" — {}", f.detail)),
        ]));
    }
    if lines.len() == 1 {
        lines.push(Line::from(Span::styled(
            "No current pressure signals or sampled top processes yet.",
            Style::default().fg(Color::DarkGray),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

fn draw_sources(app: &AppState, frame: &mut Frame, area: Rect, vp: &mut Viewport) {
    // Heading + hint are one line each and kept short enough not to wrap at
    // any width the rail is shown at, so the source rows below land at
    // predictable y positions for hit-testing.
    let mut lines = vec![
        heading("Disk and cleanup sources"),
        Line::from(Span::styled(
            "Click a row (or Tab) to drill in; cleanup stays on the source findings.",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    for (i, (id, label)) in [
        (ScannerId::Fs, "Disk allocation"),
        (ScannerId::Docker, "Docker"),
        (ScannerId::Simulator, "Simulators"),
        (ScannerId::TimeMachine, "Time Machine"),
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(idx) = ScannerId::ALL.iter().position(|s| *s == id) {
            vp.push(
                Rect::new(area.x, area.y + 2 + i as u16, area.width, 1),
                Hit::OverviewSection(idx),
            );
        }
        let findings = app.overview_findings(id);
        let bytes: u64 = findings.iter().filter_map(|f| f.size_bytes).sum();
        let reclaimable: u64 = findings
            .iter()
            .filter(|f| f.severity == Severity::Reclaimable)
            .filter_map(|f| f.size_bytes)
            .sum();
        let state = match app.status_of(id) {
            SectionStatus::Done { .. } => "ready",
            SectionStatus::Scanning { .. } => "scanning",
            SectionStatus::Failed { .. } => "unavailable",
            SectionStatus::Idle => "idle",
        };
        let suffix = if reclaimable > 0 {
            format!(" · {} actionable", fmt::bytes(reclaimable))
        } else {
            String::new()
        };
        let size_text = tm_destination_status(&findings).unwrap_or_else(|| fmt::bytes(bytes));
        lines.push(Line::from(vec![
            Span::styled(
                format!("{label:<18}"),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "{state} · {} findings · {size_text}{suffix}",
                findings.len(),
            )),
        ]));
    }
    let categories = app.disk_categories();
    if !categories.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Disk categories",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        let base = lines.len() as u16;
        for (i, category) in categories.into_iter().take(6).enumerate() {
            vp.push(
                Rect::new(area.x, area.y + base + i as u16, area.width, 1),
                Hit::OverviewCategory(i),
            );
            // Exact unless folders were unreadable; only then say so.
            let note = match category.meta.get("complete").and_then(|v| v.as_bool()) {
                Some(false) => " (partial)",
                _ => "",
            };
            lines.push(Line::from(format!(
                "  {} — {}{note}",
                category.title,
                fmt::bytes(category.size_bytes.unwrap_or(0)),
            )));
        }
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

/// The Time Machine row's status text, when the section has a `TmDestination`
/// finding to report on: "not configured" for the unconfigured destination
/// (`meta.destination_id == "none"`), otherwise "last backup {N}d ago"
/// ("today" for 0), flagged with " ⚠" when that finding is a `Warning`.
/// `None` for every other section, or a `TmDestination` with neither shape,
/// so the caller falls back to the generic bytes text.
fn tm_destination_status(findings: &[&Finding]) -> Option<String> {
    let dest = findings
        .iter()
        .copied()
        .find(|f| f.kind == FindingKind::TmDestination)?;
    if dest.meta.get("destination_id").and_then(|v| v.as_str()) == Some("none") {
        return Some("not configured".to_string());
    }
    let days = dest.meta.get("last_backup_days").and_then(|v| v.as_u64())?;
    let mut text = if days == 0 {
        "last backup today".to_string()
    } else {
        format!("last backup {days}d ago")
    };
    if dest.severity == Severity::Warning {
        text.push_str(" ⚠");
    }
    Some(text)
}

fn metric<'a>(findings: &'a [&Finding], role: &str) -> Option<&'a Finding> {
    findings
        .iter()
        .copied()
        .find(|f| f.meta.get("role").and_then(|v| v.as_str()) == Some(role))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_selects_role_not_title() {
        let f = Finding::new(FindingKind::SystemMetric, "memory", "Not the role")
            .meta(serde_json::json!({ "role": "memory" }));
        assert_eq!(metric(&[&f], "memory").unwrap().title, "Not the role");
    }
}
