//! Bottom bar: clickable key hints + running totals ("Selected: 7 items ·
//! 18.3 GB"). While in Filter mode this becomes the filter's text-input line
//! instead — it's the one modal state that borrows the statusbar rather than
//! opening a popup, since a filter box reads naturally as "where you'd
//! normally see hints."

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::registry;
use crate::ui::app::{AppState, Mode};
use crate::ui::browse::BrowseSort;
use crate::ui::fmt;
use crate::ui::keys::Action;
use crate::ui::layout::{Hit, RailMode, Viewport};

/// Key hints in display order. Each is `(key, label, action)`; the action is
/// what a click performs, so a hint is exactly as capable as its key.
fn hints(app: &AppState) -> Vec<(&'static str, String, Action)> {
    vec![
        ("␣", "mark".into(), Action::Char(' ')),
        ("⏎", "open".into(), Action::Enter),
        ("z", "fold".into(), Action::Char('z')),
        ("x", "exec".into(), Action::Char('x')),
        ("r", "rescan".into(), Action::Char('r')),
        ("/", "filter".into(), Action::Char('/')),
        ("s", format!("sort:{}", app.sort_label()), Action::Char('s')),
        ("p", "detail".into(), Action::Char('p')),
        ("H", "sys-apps".into(), Action::Char('H')),
        ("?", "help".into(), Action::Char('?')),
        ("q", "quit".into(), Action::Char('q')),
    ]
}

/// Key hints for `Mode::Browse` — a different surface (no marking/exec/
/// filter here), so it gets its own hint set rather than reusing `hints`.
fn browse_hints(app: &AppState) -> Vec<(&'static str, String, Action)> {
    let sort = match app.browse.sort {
        BrowseSort::Size => "size",
        BrowseSort::Name => "name",
    };
    vec![
        ("⏎", "open".into(), Action::Enter),
        ("⌫", "up".into(), Action::Backspace),
        ("s", format!("sort:{sort}"), Action::Char('s')),
        ("p", "detail".into(), Action::Char('p')),
        ("b", "back".into(), Action::Char('b')),
        ("?", "help".into(), Action::Char('?')),
    ]
}

pub fn draw(app: &AppState, frame: &mut Frame, area: Rect, rail: RailMode, vp: &mut Viewport) {
    if app.mode == Mode::Filter {
        draw_filter_input(app, frame, area);
        return;
    }

    let base = Style::default().bg(Color::DarkGray).fg(Color::White);
    let key_style = base.add_modifier(Modifier::BOLD).fg(Color::Yellow);

    let (n, bytes) = app.marked_total();
    let right = format!(" Selected: {n} · {} ", fmt::bytes(bytes));
    let bar = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(10),
            Constraint::Length(right.width() as u16),
        ])
        .split(area);

    let mut spans: Vec<Span> = Vec::new();
    let mut x = bar[0].x;
    // With the rail hidden, the bar is the only place the current section is
    // named.
    if rail == RailMode::Hidden {
        let id = app.selected_section_id();
        let label = format!(
            " {}/{} {} ",
            app.selected_section_index() + 1,
            registry::REGISTRY.len(),
            registry::section(id).short_title
        );
        x += label.width() as u16;
        spans.push(Span::styled(label, base.add_modifier(Modifier::BOLD)));
    }
    spans.push(Span::styled(" ", base));
    x += 1;
    let hint_list = if app.mode == Mode::Browse {
        browse_hints(app)
    } else {
        hints(app)
    };
    for (key, label, action) in hint_list {
        let w = (key.width() + 1 + label.width()) as u16;
        if x + w > bar[0].right() {
            break;
        }
        vp.push(Rect::new(x, area.y, w, 1), Hit::StatusHint(action));
        spans.push(Span::styled(key, key_style));
        spans.push(Span::styled(format!(":{label}"), base));
        spans.push(Span::styled("  ", base));
        x += w + 2;
    }

    frame.render_widget(Paragraph::new(Line::from(spans)).style(base), bar[0]);
    frame.render_widget(Paragraph::new(right).style(base), bar[1]);
}

fn draw_filter_input(app: &AppState, frame: &mut Frame, area: Rect) {
    let text = format!(" /{}_   (enter: apply · esc: clear)", app.filter);
    frame.render_widget(
        Paragraph::new(text).style(Style::default().bg(Color::Blue).fg(Color::White)),
        area,
    );
}
