//! Help overlay (`?`): a centered modal listing every keybinding, following
//! the same centering/`Clear` popup pattern as `confirm.rs`. `AppState`'s
//! `Mode::Help` reducer is the gate — only `?`/`esc`/`q`/`enter` (and
//! ctrl-c, which always quits) do anything while this is up, so nothing
//! drawn here can be mistaken for an active navigation surface.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::ui::layout::centered_rect;

/// Keybinding, short description pairs, in the order they read most usefully
/// (navigation first, then actions, then view controls).
const BINDINGS: &[(&str, &str)] = &[
    ("←/→, h/l, tab / shift-tab", "previous / next section"),
    ("1-9, 0", "jump to section"),
    ("j/k, ↑/↓", "move selection"),
    ("PgUp / PgDn (ctrl-u / ctrl-d)", "page selection"),
    ("space", "mark / unmark row"),
    ("enter", "open detail (on a group header: fold/unfold)"),
    (
        "z",
        "fold / unfold the group or dependency node under the cursor",
    ),
    ("d", "Brew: flip the explorer between needs / needed-by"),
    ("p", "show / hide detail pane"),
    ("J / K, wheel", "scroll detail pane"),
    ("e", "cycle which remedy the row will run (marks it)"),
    ("v", "preview the marked batch (impact, refusals)"),
    (
        "x",
        "execute marked remedies (confirm dialog; re-checked before running)",
    ),
    ("c", "reopen the last cleanup report"),
    ("r", "refresh current section's point-in-time sample"),
    ("R", "refresh all sections and save durable history"),
    ("/", "filter by substring (esc clears)"),
    ("s", "cycle sort (size / name / severity)"),
    ("H", "toggle System apps visibility"),
    ("?", "toggle this help"),
    ("q", "quit"),
];

pub fn draw(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(60, 70, area);
    frame.render_widget(Clear, popup);

    let mut lines = vec![
        Line::from(Span::styled(
            "Keybindings",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    for (key, desc) in BINDINGS {
        lines.push(Line::from(vec![
            Span::styled(format!("  {key:<30}"), Style::default().fg(Color::Yellow)),
            Span::raw(*desc),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "?  esc  enter  q : close",
        Style::default().fg(Color::DarkGray),
    )));

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help ")
        .border_style(Style::default().fg(Color::Cyan));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup,
    );
}
