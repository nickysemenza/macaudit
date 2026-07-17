//! Bottom bar: keybind hints + running totals ("Selected: 7 items · 18.3 GB").
//! While in Filter mode this becomes the filter's text-input line instead —
//! it's the one modal state that borrows the statusbar rather than opening
//! a popup, since a filter box reads naturally as "where you'd normally see
//! hints."

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::Frame;

use crate::ui::app::{AppState, Mode};

pub fn draw(app: &AppState, frame: &mut Frame, area: Rect) {
    if app.mode == Mode::Filter {
        draw_filter_input(app, frame, area);
        return;
    }

    let (n, bytes) = app.marked_total();
    let left = format!(
        " jk/arrows:nav  tab:section  space:mark  enter:detail  x:exec  r/R:rescan  /:filter  s:sort({})  h:sys  ?:help  q:quit",
        app.sort_label()
    );
    let right = format!(
        "Selected: {n} items · {} ",
        humansize::format_size(bytes, humansize::BINARY)
    );
    let bar = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(10), Constraint::Length(right.len() as u16)])
        .split(area);
    frame.render_widget(
        ratatui::widgets::Paragraph::new(left)
            .style(Style::default().bg(Color::DarkGray).fg(Color::White)),
        bar[0],
    );
    frame.render_widget(
        ratatui::widgets::Paragraph::new(right)
            .style(Style::default().bg(Color::DarkGray).fg(Color::White)),
        bar[1],
    );
}

fn draw_filter_input(app: &AppState, frame: &mut Frame, area: Rect) {
    let text = format!(" /{}_   (enter: apply · esc: clear)", app.filter);
    frame.render_widget(
        ratatui::widgets::Paragraph::new(text)
            .style(Style::default().bg(Color::Blue).fg(Color::White)),
        area,
    );
}
