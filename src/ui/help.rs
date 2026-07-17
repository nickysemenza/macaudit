//! Help overlay (`?`): a centered modal listing every keybinding, following
//! the same centering/`Clear` popup pattern as `confirm.rs`. `AppState`'s
//! `Mode::Help` reducer is the gate — only `?`/`esc`/`q`/`enter` (and
//! ctrl-c, which always quits) do anything while this is up, so nothing
//! drawn here can be mistaken for an active navigation surface.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

/// Keybinding, short description pairs, in the order they read most usefully
/// (navigation first, then actions, then view controls).
const BINDINGS: &[(&str, &str)] = &[
    ("j/k, ↑/↓", "move selection"),
    ("tab / shift-tab", "next / previous section"),
    ("←/→", "collapse/expand tree group (else switch section)"),
    ("space", "mark / unmark row"),
    ("enter", "toggle detail pane (else expand/collapse group)"),
    ("x", "execute marked remedies (confirm dialog)"),
    ("r", "rescan current section"),
    ("R", "rescan all sections"),
    ("/", "filter by substring"),
    ("s", "cycle sort (size / name / severity)"),
    ("h", "toggle System apps visibility"),
    ("PgUp / PgDn (ctrl-u / ctrl-d)", "scroll detail pane"),
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

/// A `percent_x` × `percent_y` rectangle centered within `area`.
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}
