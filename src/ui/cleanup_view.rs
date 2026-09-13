//! Overlays for the cleanup workflow: the marked-batch impact preview
//! (`v`), the live progress of a running batch (Esc stops after the current
//! action), and the completion report (`c` reopens it).

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::cleanup::{CleanupReport, Verdict};
use crate::ui::app::{AppState, CleanupPhase, CleanupRun};
use crate::ui::layout::centered_rect;
use crate::ui::{confirm, fmt, theme};

fn bold(s: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(
        s.into(),
        Style::default().add_modifier(Modifier::BOLD),
    ))
}

fn dim(s: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(s.into(), Style::default().fg(Color::DarkGray)))
}

fn overlay(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    color: Color,
    lines: Vec<Line<'static>>,
    scroll: u16,
) {
    let popup = centered_rect(80, 80, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {title} "))
        .border_style(Style::default().fg(color));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        popup,
    );
}

pub fn draw_preview(app: &AppState, frame: &mut Frame, area: Rect) {
    let mut lines = match app.marked_preflight() {
        Some(model) => {
            let mut v = vec![
                bold(format!("Preview: {} marked", app.marked_total().0)),
                Line::from(""),
            ];
            v.extend(
                confirm::lines(&model, app.delete_mode())
                    .into_iter()
                    .skip(1),
            );
            v.pop(); // replace the confirm footer
            v
        }
        None => vec![bold("Nothing marked"), Line::from("")],
    };
    lines.push(dim(
        "x / enter: open confirm    esc / v: close    J/K: scroll",
    ));
    overlay(
        frame,
        area,
        "Removal preview",
        Color::Cyan,
        lines,
        app.overlay_scroll,
    );
}

/// Progress lines for a running batch (pure, for tests).
pub fn progress_lines(run: &CleanupRun) -> Vec<Line<'static>> {
    let mut out = vec![bold(match &run.phase {
        CleanupPhase::Preflight => "Re-checking every target against a fresh scan…".to_string(),
        CleanupPhase::Executing { idx, total } => format!("Running action {} of {total}…", idx + 1),
        CleanupPhase::Verifying => {
            "Verifying retained tools and re-running brew autoremove --dry-run…".to_string()
        }
        CleanupPhase::Done => "Done".to_string(),
    })];
    if run.cancel_requested && run.phase != CleanupPhase::Done {
        out.push(Line::from(Span::styled(
            "stop requested — finishing the current action, remaining actions will not run",
            Style::default().fg(Color::Yellow),
        )));
    }
    out.push(Line::from(""));
    for (i, a) in run.actions.iter().enumerate() {
        let (glyph, color) = match run.results.get(&i) {
            Some(Ok(_)) => ("✓", Color::Green),
            Some(Err(_)) => ("✗", Color::Red),
            None if run.cancelled.iter().any(|c| c.rendered == a.rendered) => {
                ("–", Color::DarkGray)
            }
            None if matches!(run.phase, CleanupPhase::Executing { idx, .. } if idx == i) => {
                ("⠋", Color::Cyan)
            }
            None => (" ", Color::DarkGray),
        };
        out.push(Line::from(vec![
            Span::styled(format!(" {glyph} "), Style::default().fg(color)),
            Span::raw(format!("{} — ", a.label)),
            Span::styled(
                a.rendered.clone(),
                Style::default().fg(theme::remedy_color(a.destructive)),
            ),
        ]));
        if let Some(Err(e)) = run.results.get(&i) {
            out.push(Line::from(Span::styled(
                format!("     {e}"),
                Style::default().fg(Color::Red),
            )));
        }
    }
    for r in &run.refused {
        out.push(Line::from(vec![
            Span::styled(" ⊘ ", Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{} — {}", r.action.label, r.action.rendered),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
        out.push(Line::from(Span::styled(
            format!("     refused: {}", r.reason),
            Style::default().fg(Color::Yellow),
        )));
    }
    out.push(Line::from(""));
    out.push(dim(
        "esc: stop after the current action (an in-flight command is never killed)",
    ));
    out
}

pub fn draw_progress(app: &AppState, frame: &mut Frame, area: Rect) {
    let lines = match &app.cleanup {
        Some(run) => progress_lines(run),
        None => vec![bold("No cleanup running")],
    };
    overlay(
        frame,
        area,
        "Cleanup",
        Color::Yellow,
        lines,
        app.overlay_scroll,
    );
}

fn verdict_color(v: Verdict) -> Color {
    match v {
        Verdict::Ok | Verdict::RemovedAsExpected => Color::Green,
        Verdict::PreExistingFailure => Color::Yellow,
        Verdict::Regression | Verdict::StillPresent => Color::Red,
        Verdict::Skipped => Color::DarkGray,
    }
}

fn verdict_label(v: Verdict) -> &'static str {
    match v {
        Verdict::Ok => "ok",
        Verdict::RemovedAsExpected => "removed",
        Verdict::StillPresent => "STILL PRESENT",
        Verdict::PreExistingFailure => "pre-existing failure",
        Verdict::Regression => "REGRESSION",
        Verdict::Skipped => "skipped",
    }
}

/// Report lines (pure, for tests).
pub fn report_lines(report: &CleanupReport) -> Vec<Line<'static>> {
    let mut out = vec![bold(report.summary()), Line::from("")];
    if !report.executed.is_empty() {
        out.push(bold("Ran:"));
        for r in &report.executed {
            out.push(Line::from(vec![
                Span::styled(" ✓ ", Style::default().fg(Color::Green)),
                Span::raw(r.action.rendered.clone()),
                Span::styled(
                    format!("  {}", r.message),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }
    }
    if !report.failed.is_empty() {
        out.push(bold("Failed:"));
        for r in &report.failed {
            out.push(Line::from(vec![
                Span::styled(" ✗ ", Style::default().fg(Color::Red)),
                Span::raw(r.action.rendered.clone()),
            ]));
            out.push(Line::from(Span::styled(
                format!("     {}", r.message),
                Style::default().fg(Color::Red),
            )));
        }
    }
    if !report.cancelled.is_empty() {
        out.push(bold("Cancelled (not run):"));
        for a in &report.cancelled {
            out.push(Line::from(format!(" – {}", a.rendered)));
        }
    }
    if !report.refused.is_empty() {
        out.push(bold("Refused (not run):"));
        for r in &report.refused {
            out.push(Line::from(format!(" ⊘ {}", r.action.rendered)));
            out.push(Line::from(Span::styled(
                format!("     {}", r.reason),
                Style::default().fg(Color::Yellow),
            )));
        }
    }
    if let Some(auto) = &report.brew_autoremove_after {
        out.push(Line::from(""));
        out.push(if auto.is_empty() {
            Line::from("brew autoremove --dry-run: nothing left to remove")
        } else {
            Line::from(Span::styled(
                format!("brew autoremove --dry-run now lists: {} — rescan Brew and remove them from there", auto.join(", ")),
                Style::default().fg(Color::Cyan),
            ))
        });
    }
    if !report.verification.is_empty() {
        out.push(Line::from(""));
        out.push(bold("Verification (before → after):"));
        for v in &report.verification {
            let b = v
                .before
                .map(|x| if x { "ok" } else { "bad" })
                .unwrap_or("?");
            let a = v.after.map(|x| if x { "ok" } else { "bad" }).unwrap_or("?");
            out.push(Line::from(vec![
                Span::raw(format!(
                    "  {:<28} {:<24} {b} → {a}  ",
                    fmt::truncate_end(&v.name, 28),
                    v.check
                )),
                Span::styled(
                    verdict_label(v.verdict).to_string(),
                    Style::default().fg(verdict_color(v.verdict)),
                ),
                Span::styled(
                    v.detail
                        .clone()
                        .map(|d| format!("  {d}"))
                        .unwrap_or_default(),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }
    }
    out.push(Line::from(""));
    out.push(dim(report.note.clone()));
    if let Some(p) = &report.audit_path {
        out.push(dim(format!("saved: {}", p.display())));
    }
    out.push(Line::from(""));
    out.push(dim("esc / enter / c: close    J/K: scroll"));
    out
}

pub fn draw_report(app: &AppState, frame: &mut Frame, area: Rect) {
    let lines = match app.cleanup.as_ref().and_then(|r| r.report.as_ref()) {
        Some(report) => report_lines(report),
        None => vec![bold("No cleanup report yet")],
    };
    overlay(
        frame,
        area,
        "Cleanup report",
        Color::Green,
        lines,
        app.overlay_scroll,
    );
}
