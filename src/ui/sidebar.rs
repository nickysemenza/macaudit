//! Nav rail: one row per `registry::REGISTRY` section. It is a *map*, not a
//! list — nothing in it takes focus. The current section is marked with `▸`
//! and bold; `←/→`, digits, Tab, or a click switch sections.
//!
//! Full row layout (25 cells + right border = `RailMode::Full.width()`):
//!
//! ```text
//! ▸2⠇ Apps        142  2.1G
//! │││ │           │    └ reclaimable, compact (5)
//! │││ │           └ finding count (4)
//! │││ └ short title (10)
//! ││└ spinner while scanning / ⚠ failed / blank
//! │└ digit hotkey for the first ten sections
//! └ current-section marker
//! ```

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::registry;
use crate::ui::app::{AppState, SectionStatus};
use crate::ui::layout::{Hit, RailMode, Viewport};
use crate::ui::{fmt, theme};

/// Digit hotkey for a section index (`1`–`9`, then `0` for the tenth), or a
/// blank for sections beyond the tenth.
pub fn hotkey(index: usize) -> char {
    match index {
        0..=8 => char::from(b'1' + index as u8),
        9 => '0',
        _ => ' ',
    }
}

/// Section index for a digit key, inverse of `hotkey`.
pub fn section_for_digit(c: char) -> Option<usize> {
    match c {
        '1'..='9' => Some((c as u8 - b'1') as usize),
        '0' => Some(9),
        _ => None,
    }
}

pub fn draw(app: &AppState, frame: &mut Frame, area: Rect, mode: RailMode, vp: &mut Viewport) {
    let block = Block::default().borders(Borders::RIGHT);
    let inner = block.inner(area);
    vp.push(area, Hit::Rail);

    let lines: Vec<Line> = registry::REGISTRY
        .iter()
        .enumerate()
        .map(|(i, meta)| {
            if (i as u16) < inner.height {
                vp.push(
                    Rect::new(inner.x, inner.y + i as u16, inner.width, 1),
                    Hit::RailRow(i),
                );
            }
            row(app, i, meta, mode)
        })
        .collect();

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn row<'a>(app: &AppState, i: usize, meta: &registry::SectionMeta, mode: RailMode) -> Line<'a> {
    let current = i == app.selected_section_index();
    let status = app.status_of(meta.id);
    let glyph = match &status {
        SectionStatus::Scanning { .. } => theme::spinner(app.tick).to_string(),
        SectionStatus::Failed { .. } => "⚠".to_string(),
        _ => " ".to_string(),
    };
    let marker = if current { "▸" } else { " " };
    let title_style = if current {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let mut spans = vec![
        Span::styled(marker.to_string(), title_style),
        Span::styled(hotkey(i).to_string(), Style::default().fg(Color::DarkGray)),
        Span::styled(
            glyph,
            match &status {
                SectionStatus::Failed { .. } => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::DarkGray),
            },
        ),
        Span::styled(format!(" {:<10}", meta.short_title), title_style),
    ];
    if mode == RailMode::Compact {
        return Line::from(spans);
    }

    let done = matches!(status, SectionStatus::Done { .. });
    let count = if done {
        app.section_count(meta.id).to_string()
    } else {
        String::new()
    };
    let reclaim = app.section_reclaimable(meta.id);
    let size = if done && reclaim > 0 {
        fmt::bytes_compact(reclaim)
    } else {
        String::new()
    };
    spans.push(Span::styled(
        format!(" {count:>4} {size:>5}"),
        Style::default().fg(Color::DarkGray),
    ));
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotkeys_cover_first_ten_sections_then_blank() {
        assert_eq!(hotkey(0), '1');
        assert_eq!(hotkey(8), '9');
        assert_eq!(hotkey(9), '0');
        assert_eq!(hotkey(10), ' ');
        for i in 0..10 {
            assert_eq!(section_for_digit(hotkey(i)), Some(i));
        }
        assert_eq!(section_for_digit('a'), None);
    }

    #[test]
    fn rail_rows_fit_width_for_all_sections() {
        use std::time::Duration;
        use unicode_width::UnicodeWidthStr;

        use crate::model::{Finding, FindingKind, ScanEvent, ScannerId, Severity};
        use crate::ui::layout::RailMode;

        let mut app = crate::ui::testutil::app_with_gen(1);
        for id in ScannerId::ALL.iter() {
            // Big, four-digit counts and multi-GiB reclaimable totals so every
            // column is at its widest.
            for n in 0..1200 {
                let f = Finding::new(FindingKind::CacheDir, &format!("{id:?}/{n}"), "x")
                    .size(900 << 20)
                    .severity(Severity::Reclaimable);
                app.apply(ScanEvent::Finding {
                    scanner: *id,
                    gen: 1,
                    finding: Box::new(f),
                });
            }
            app.apply(ScanEvent::Finished {
                scanner: *id,
                gen: 1,
                duration: Duration::from_secs(1),
            });
        }

        for (i, meta) in registry::REGISTRY.iter().enumerate() {
            let line = row(&app, i, meta, RailMode::Full);
            let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
            let inner = (RailMode::Full.width() - 1) as usize;
            assert!(
                text.width() <= inner,
                "rail row {i} is {} cells wide (> {inner}): {text:?}",
                text.width()
            );
            assert!(text.contains(meta.short_title), "{text:?}");
            assert_eq!(text.chars().nth(1), Some(hotkey(i)), "{text:?}");
        }
    }
}
