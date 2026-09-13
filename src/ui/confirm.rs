//! Confirm dialog (`x` on marked items): lists every exact rendered command
//! that would run, destructive ones in red, plus a total-reclaimable summary.
//! `y`/`enter` confirms, `n`/`esc` cancels. This is the second half of spec
//! §4's "never run anything unseen" guarantee — the detail pane shows one
//! finding's commands, this shows the whole batch right before it runs.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::config::DeleteMode;
use crate::remedy::PlannedAction;
use crate::ui::layout::centered_rect;
use crate::ui::{fmt, theme};

pub fn draw(frame: &mut Frame, area: Rect, actions: &[PlannedAction], delete_mode: DeleteMode) {
    let popup = centered_rect(72, 60, area);
    frame.render_widget(Clear, popup);

    let total: u64 = actions.iter().filter_map(|a| a.reclaims_bytes).sum();
    let mode_label = match delete_mode {
        DeleteMode::Trash => "trash",
        DeleteMode::Rm => "rm",
    };

    let mut lines = vec![
        Line::from(Span::styled(
            format!(
                "Execute {} remed{} ({} mode)?",
                actions.len(),
                if actions.len() == 1 { "y" } else { "ies" },
                mode_label
            ),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    for a in actions {
        let color = theme::remedy_color(a.destructive);
        lines.push(Line::from(vec![
            Span::raw(format!("  {} — ", a.label)),
            Span::styled(a.rendered.clone(), Style::default().fg(color)),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(format!("Reclaims: {}", fmt::bytes(total))));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "y / enter: confirm    n / esc: cancel",
        Style::default().fg(Color::DarkGray),
    )));

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Confirm ")
        .border_style(Style::default().fg(Color::Yellow));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup,
    );
}
