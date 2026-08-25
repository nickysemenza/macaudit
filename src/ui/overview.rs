//! The manual Resource Health overview. It summarizes actual scanner findings
//! without manufacturing cleanup actions: every recommendation points back to
//! the existing Disk/Docker/Simulators/Snapshots source sections in the sidebar.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::model::{Finding, FindingKind, ScannerId, Severity};
use crate::ui::app::{AppState, SectionStatus};
use crate::ui::theme;

pub fn draw(app: &AppState, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Min(8),
        ])
        .split(area);
    draw_now(app, frame, rows[0]);
    draw_attention(app, frame, rows[1]);
    draw_sources(app, frame, rows[2]);
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
    let text = if cards.is_empty() {
        vec![Line::from("Waiting for the manual resource snapshot…")]
    } else {
        cards
    };
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Now — manual point-in-time sample "),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
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
    let mut lines = Vec::new();
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
    if lines.is_empty() {
        lines.push(Line::from(
            "No current pressure signals or sampled top processes yet.",
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Attention & active consumers "),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_sources(app: &AppState, frame: &mut Frame, area: Rect) {
    let mut lines = vec![Line::from(Span::styled(
        "Drill into these source sections with Tab or the sidebar. Cleanup actions remain only on their original findings.",
        Style::default().fg(Color::DarkGray),
    ))];
    for (id, label) in [
        (ScannerId::Fs, "Disk allocation"),
        (ScannerId::Docker, "Docker"),
        (ScannerId::Simulator, "Simulators"),
        (ScannerId::TmSnapshots, "Snapshots"),
    ] {
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
            format!(" · {} actionable", human(reclaimable))
        } else {
            String::new()
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{label:<18}"),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "{state} · {} findings · {}{suffix}",
                findings.len(),
                human(bytes)
            )),
        ]));
    }
    let categories: Vec<&Finding> = app
        .overview_findings(ScannerId::Fs)
        .into_iter()
        .filter(|f| f.kind == FindingKind::DiskCategory)
        .collect();
    if !categories.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Bounded disk categories",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for category in categories.into_iter().take(6) {
            lines.push(Line::from(format!(
                "  {} — {} ({})",
                category.title,
                human(category.size_bytes.unwrap_or(0)),
                category.coverage.as_deref().unwrap_or("scope unknown")
            )));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Disk and cleanup sources "),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn metric<'a>(findings: &'a [&Finding], role: &str) -> Option<&'a Finding> {
    findings
        .iter()
        .copied()
        .find(|f| f.meta.get("role").and_then(|v| v.as_str()) == Some(role))
}

fn human(bytes: u64) -> String {
    humansize::format_size(bytes, humansize::BINARY)
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
