//! The one row renderer for both `ViewKind::Table` and `ViewKind::Tree`
//! sections. Columns come from the section's `SectionPresenter`; the only
//! difference between a tree and a table is that a tree interleaves group
//! header rows and indents its items.
//!
//! Layout is resolved here first (so every painted row and sortable header
//! can be registered as a `Hit` with exact geometry), then handed to
//! ratatui's `Table` as fixed `Length` widths so the two can't disagree.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use crate::model::{Finding, FindingId, Severity};
use crate::ui::layout::{self, Hit, Viewport};
use crate::ui::present::{CellCtx, Column, ColumnId, SectionPresenter, SortBy, SortSpec};
use crate::ui::{fmt, theme};

/// One navigable row. `Group` rows only appear in tree sections.
#[derive(Clone, Debug)]
pub enum RenderRow<'a> {
    Group {
        key: String,
        count: usize,
        reclaimable_bytes: u64,
        expanded: bool,
    },
    Item {
        f: &'a Finding,
        depth: u8,
    },
}

/// Everything the renderer needs besides the frame.
pub struct RowsView<'a, M: Fn(FindingId) -> bool> {
    pub title: &'a str,
    pub presenter: &'static SectionPresenter,
    pub rows: &'a [RenderRow<'a>],
    pub ctx: CellCtx,
    pub selected: usize,
    pub sort: SortSpec,
    pub is_marked: M,
    /// Shown when there are no rows.
    pub empty_message: &'a str,
}

const GUTTER: u16 = 2;
const SPACING: u16 = 1;
/// A `Fill` column narrower than this is unreadable; drop other columns first.
const MIN_FILL_WIDTH: u16 = 16;

/// The columns that fit in `width`: all of them when there's room, else the
/// trailing non-primary, non-Size columns are dropped (last first) until the
/// fixed widths leave every `Fill` column at least `MIN_FILL_WIDTH`. Sections
/// list their columns most-important-first, so this degrades sensibly.
pub fn fitting_columns(columns: &'static [Column], width: u16) -> Vec<&'static Column> {
    let mut kept: Vec<&'static Column> = columns.iter().collect();
    loop {
        let spacing = SPACING * kept.len() as u16;
        let fixed: u16 = kept
            .iter()
            .map(|c| match c.width {
                Constraint::Length(n) | Constraint::Min(n) | Constraint::Max(n) => n,
                _ => MIN_FILL_WIDTH,
            })
            .sum();
        if GUTTER + spacing + fixed <= width {
            return kept;
        }
        let Some(pos) = kept
            .iter()
            .rposition(|c| !c.primary && c.id != ColumnId::Size)
        else {
            return kept;
        };
        kept.remove(pos);
    }
}

pub fn draw<M: Fn(FindingId) -> bool>(
    frame: &mut Frame,
    area: Rect,
    view: RowsView<'_, M>,
    vp: &mut Viewport,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} ", view.title));
    let inner = block.inner(area);
    let columns = fitting_columns(view.presenter.columns, inner.width);

    // Resolve column geometry once; the table gets these exact widths back.
    let mut constraints = vec![Constraint::Length(GUTTER)];
    constraints.extend(columns.iter().map(|c| c.width));
    let rects = Layout::horizontal(&constraints)
        .spacing(SPACING)
        .split(inner);
    let widths: Vec<Constraint> = rects.iter().map(|r| Constraint::Length(r.width)).collect();

    // Header row: sortable headers are click targets.
    let header_cells: Vec<Cell> = std::iter::once(Cell::from(""))
        .chain(columns.iter().enumerate().map(|(i, col)| {
            let rect = rects[i + 1];
            if col.sort_key.is_some() && inner.height > 0 {
                vp.push(
                    Rect::new(rect.x, inner.y, rect.width, 1),
                    Hit::ColumnHeader(col.id),
                );
            }
            let active = view.sort.by == SortBy::Column(col.id);
            let label = if active {
                format!("{}{}", col.header, view.sort.dir.arrow())
            } else {
                col.header.to_string()
            };
            let style = if active {
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Color::Cyan)
            } else {
                Style::default().add_modifier(Modifier::BOLD)
            };
            Cell::from(
                Line::from(Span::styled(
                    fmt::truncate_end(&label, rect.width as usize),
                    style,
                ))
                .alignment(col.align),
            )
        }))
        .collect();

    // Data rows: only the visible window is materialised.
    let visible = inner.height.saturating_sub(1) as usize;
    let n = view.rows.len();
    let selected = view.selected.min(n.saturating_sub(1));
    let offset = layout::adjust_offset(vp.row_offset, selected, n, visible);
    vp.row_offset = offset;
    vp.rows_visible = visible;
    let window = &view.rows[offset.min(n)..(offset + visible).min(n)];
    for i in 0..window.len() {
        vp.push(
            Rect::new(inner.x, inner.y + 1 + i as u16, inner.width, 1),
            Hit::Row(offset + i),
        );
    }
    let size_col = columns.iter().copied().find(|c| c.id == ColumnId::Size);
    let table_rows: Vec<Row> = window
        .iter()
        .map(|row| render_row(row, &columns, &rects, size_col, &view))
        .collect();

    if n == 0 {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                view.empty_message,
                Style::default().fg(Color::DarkGray),
            )))
            .block(block)
            .alignment(Alignment::Center),
            area,
        );
        return;
    }

    let table = Table::new(table_rows, widths)
        .column_spacing(SPACING)
        .header(Row::new(header_cells))
        .block(block)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut ts = TableState::default().with_selected(Some(selected - offset));
    frame.render_stateful_widget(table, area, &mut ts);
}

fn render_row<'a, M: Fn(FindingId) -> bool>(
    row: &RenderRow<'a>,
    columns: &[&'static Column],
    rects: &[Rect],
    size_col: Option<&'static Column>,
    view: &RowsView<'_, M>,
) -> Row<'a> {
    match row {
        RenderRow::Group {
            key,
            count,
            reclaimable_bytes,
            expanded,
        } => {
            let glyph = if *expanded {
                theme::EXPANDED
            } else {
                theme::COLLAPSED
            };
            let mut cells = vec![Cell::from(Span::styled(
                glyph,
                Style::default().fg(Color::DarkGray),
            ))];
            for (i, col) in columns.iter().enumerate() {
                let width = rects[i + 1].width as usize;
                let text = if col.primary {
                    format!("{key}  ({count})")
                } else if size_col.is_some_and(|s| s.id == col.id) && *reclaimable_bytes > 0 {
                    fmt::bytes(*reclaimable_bytes)
                } else {
                    String::new()
                };
                cells.push(Cell::from(
                    Line::from(Span::styled(
                        fmt::truncate_end(&text, width),
                        Style::default().add_modifier(Modifier::BOLD),
                    ))
                    .alignment(col.align),
                ));
            }
            Row::new(cells)
        }
        RenderRow::Item { f, depth } => {
            let gutter = if (view.is_marked)(f.id) {
                Span::styled(theme::MARK, Style::default().fg(Color::Cyan))
            } else if f.severity == Severity::Warning {
                Span::styled("!", Style::default().fg(theme::severity_color(f.severity)))
            } else {
                Span::raw(" ")
            };
            let mut cells = vec![Cell::from(gutter)];
            for (i, col) in columns.iter().enumerate() {
                let width = rects[i + 1].width as usize;
                let mut cell = (col.cell)(f, &view.ctx);
                if col.primary && *depth > 0 {
                    cell.text = format!("{}{}", "  ".repeat(*depth as usize), cell.text);
                }
                let text = if col.middle_ellipsis {
                    fmt::truncate_middle(&cell.text, width)
                } else {
                    fmt::truncate_end(&cell.text, width)
                };
                cells.push(Cell::from(
                    Line::from(Span::styled(text, cell.style)).alignment(col.align),
                ));
            }
            Row::new(cells)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScannerId;
    use crate::ui::present;

    #[test]
    fn narrow_panels_drop_trailing_columns_but_keep_primary_and_size() {
        let cols = present::presenter(ScannerId::Git).columns;
        let wide = fitting_columns(cols, 200);
        assert_eq!(wide.len(), cols.len());

        let narrow = fitting_columns(cols, 50);
        assert!(narrow.len() < cols.len());
        assert!(narrow.iter().any(|c| c.primary), "primary survives");
        assert!(
            narrow.iter().any(|c| c.id == ColumnId::Size),
            "size survives"
        );
        // Order is preserved.
        let ids: Vec<ColumnId> = narrow.iter().map(|c| c.id).collect();
        let mut expected: Vec<ColumnId> = cols.iter().map(|c| c.id).collect();
        expected.retain(|id| ids.contains(id));
        assert_eq!(ids, expected);
    }
}
