//! Confirm dialog (`x` on marked items): every exact rendered command that
//! would run, destructive ones in red; the actions the in-memory preflight
//! refused (with reasons); and the batch's Homebrew impact — what is
//! removed, what stays because it is still needed, what is predicted to
//! become unneeded (and which of those Homebrew itself already lists).
//! `y`/`enter` confirms (a refreshing preflight runs before anything
//! executes), `n`/`esc` cancels. Second half of spec §4's "never run
//! anything unseen".

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::config::DeleteMode;
use crate::ui::app::ConfirmModel;
use crate::ui::layout::centered_rect;
use crate::ui::{fmt, theme};

fn bold(s: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(
        s.into(),
        Style::default().add_modifier(Modifier::BOLD),
    ))
}

fn dim(s: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(s.into(), Style::default().fg(Color::DarkGray)))
}

/// The body lines of the dialog (pure, for tests).
pub fn lines(model: &ConfirmModel, delete_mode: DeleteMode) -> Vec<Line<'static>> {
    let total: u64 = model.actions.iter().filter_map(|a| a.reclaims_bytes).sum();
    let mode_label = match delete_mode {
        DeleteMode::Trash => "trash",
        DeleteMode::Rm => "rm",
    };
    let n = model.actions.len();
    let mut out = vec![bold(if n == 0 {
        "Nothing runnable in this batch".to_string()
    } else {
        format!(
            "Execute {n} remed{} ({mode_label} mode)?",
            if n == 1 { "y" } else { "ies" }
        )
    })];
    if n > 0 {
        out.push(Line::from(""));
        out.push(bold("Will run, in this order:"));
        for a in &model.actions {
            out.push(Line::from(vec![
                Span::raw(format!("  {} — ", a.label)),
                Span::styled(
                    a.rendered.clone(),
                    Style::default().fg(theme::remedy_color(a.destructive)),
                ),
            ]));
        }
    }
    if !model.refused.is_empty() {
        out.push(Line::from(""));
        out.push(bold("Refused (will not run):"));
        for r in &model.refused {
            out.push(Line::from(vec![Span::styled(
                format!("  {} — {}", r.action.label, r.action.rendered),
                Style::default().fg(Color::DarkGray),
            )]));
            out.push(Line::from(Span::styled(
                format!("      {}", r.reason),
                Style::default().fg(Color::Red),
            )));
        }
    }
    if !model.remaining.is_empty() {
        out.push(Line::from(""));
        out.push(bold("Stays:"));
        for r in &model.remaining {
            out.push(Line::from(format!("  {r}")));
        }
    }
    if let Some(p) = &model.impact {
        if !p.removable.is_empty()
            || !p.blocked.is_empty()
            || !p.newly_orphaned.is_empty()
            || !p.uncertain_orphans.is_empty()
        {
            out.push(Line::from(""));
            out.push(bold("Homebrew impact:"));
            if !p.removable.is_empty() {
                out.push(Line::from(format!("  removes: {}", p.removable.join(", "))));
            }
            for (pkg, deps) in &p.blocked {
                out.push(Line::from(Span::styled(
                    format!("  {pkg} stays — still needed by {}", deps.join(", ")),
                    Style::default().fg(Color::Red),
                )));
            }
            if !p.newly_orphaned.is_empty() {
                out.push(Line::from(format!(
                    "  predicted to become unneeded: {}",
                    p.newly_orphaned.join(", ")
                )));
            }
            if !p.confirmed_orphans.is_empty() {
                out.push(Line::from(Span::styled(
                    format!(
                        "  brew already lists as unneeded: {}",
                        p.confirmed_orphans.join(", ")
                    ),
                    Style::default().fg(Color::Cyan),
                )));
            }
            if !p.uncertain_orphans.is_empty() {
                out.push(Line::from(Span::styled(
                    format!(
                        "  origin unknown, verify before autoremove: {}",
                        p.uncertain_orphans.join(", ")
                    ),
                    Style::default().fg(Color::Yellow),
                )));
            }
            out.push(dim(
                "  after removal, review: brew autoremove --dry-run (re-run automatically)",
            ));
            for c in p.caveats.iter().take(3) {
                out.push(dim(format!("  note: {c}")));
            }
            if p.caveats.len() > 3 {
                out.push(dim(format!(
                    "  … {} more graph notes (see the detail pane)",
                    p.caveats.len() - 3
                )));
            }
        }
    }
    if !model.follow_up.is_empty() {
        out.push(Line::from(""));
        out.push(bold("Follow-up:"));
        for f in &model.follow_up {
            out.push(Line::from(format!("  {f}")));
        }
    }
    out.push(Line::from(""));
    out.push(Line::from(format!("Reclaims: {}", fmt::bytes(total))));
    out.push(Line::from(""));
    out.push(dim(if n == 0 {
        "n / esc: close"
    } else {
        "y / enter: run (re-checks every target first)    n / esc: cancel    J/K: scroll"
    }));
    out
}

pub fn draw(frame: &mut Frame, area: Rect, model: &ConfirmModel, delete_mode: DeleteMode) {
    let popup = centered_rect(80, 80, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Confirm ")
        .border_style(Style::default().fg(Color::Yellow));
    frame.render_widget(
        Paragraph::new(lines(model, delete_mode))
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((model.scroll, 0)),
        popup,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brewgraph::RemovalPreview;
    use crate::cleanup::Refused;
    use crate::model::{FindingId, FindingKind, RemedyCommand};
    use crate::remedy::PlannedAction;

    fn action(rendered: &str) -> PlannedAction {
        PlannedAction {
            finding_id: FindingId::new(FindingKind::BrewFormula, rendered),
            label: "Uninstall".into(),
            command: RemedyCommand::Shell {
                program: "brew".into(),
                args: vec!["uninstall".into(), rendered.into()],
            },
            rendered: rendered.into(),
            destructive: true,
            reclaims_bytes: Some(10),
            guard: None,
        }
    }

    fn text(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn renders_refusals_impact_and_empty_state() {
        let model = ConfirmModel {
            actions: vec![action("brew uninstall wget")],
            refused: vec![Refused {
                action: action("brew uninstall openssl@3"),
                reason: "blocked: still needed by python@3.14".into(),
            }],
            removed: vec![],
            remaining: vec!["python@3.14 (still needs openssl@3)".into()],
            follow_up: vec!["review autoremove".into()],
            impact: Some(RemovalPreview {
                removable: vec!["wget".into()],
                blocked: vec![("openssl@3".into(), vec!["python@3.14".into()])],
                newly_orphaned: vec!["libidn2".into()],
                confirmed_orphans: vec![],
                uncertain_orphans: vec!["oldlib".into()],
                ..Default::default()
            }),
            scroll: 0,
        };
        let t = text(&lines(&model, DeleteMode::Trash));
        assert!(t.contains("Execute 1 remedy (trash mode)?"));
        assert!(t.contains("Refused (will not run):"));
        assert!(t.contains("still needed by python@3.14"));
        assert!(t.contains("predicted to become unneeded: libidn2"));
        assert!(t.contains("origin unknown, verify before autoremove: oldlib"));
        assert!(t.contains("Reclaims: 10 B"));
        let empty = ConfirmModel::default();
        let t = text(&lines(&empty, DeleteMode::Rm));
        assert!(t.contains("Nothing runnable"));
        assert!(t.contains("n / esc: close"));
    }
}
