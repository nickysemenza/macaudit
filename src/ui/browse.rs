//! Folder drill-down ("browse") mode: walk the Disk section's `DirTree`s
//! node by node, like a very fast Finder column view. `BrowseState` is the
//! cursor/sort/breadcrumb-stack `AppState` carries while `mode ==
//! Mode::Browse`; `draw`/`draw_detail` render it into the main panel and
//! detail slot respectively (see `nav.rs` for the mode's reducer).
//!
//! The main panel lists only *directories* — a directory's own loose files
//! never get a row there, since there is nothing to descend into. They show
//! up instead as bounded retained scan summaries in the detail pane.

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;

use crate::inventory::{DirectoryRef, MemoryBudget, Reservation};
use crate::model::{ScannerId, Severity};
use crate::scan::walk::DirTree;
use crate::ui::app::AppState;
use crate::ui::layout::{self, Hit, Viewport};
use crate::ui::present::{self, kv, Field};
use crate::ui::{fmt, theme};

/// Which order `entries` lists a directory's children in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BrowseSort {
    Size,
    Name,
}

/// Where the user is while browsing: the current directory (absolute, always
/// a tree root or something under one), the row under the cursor, the active
/// sort, and the breadcrumb stack Backspace unwinds.
pub struct BrowseState {
    pub path: PathBuf,
    pub cursor: usize,
    pub sort: BrowseSort,
    /// `(parent path, cursor in the parent)` pushed on descend, popped on
    /// Backspace — so going back up lands the cursor exactly where it was.
    pub stack: Vec<(PathBuf, usize)>,
}

impl Default for BrowseState {
    fn default() -> Self {
        BrowseState {
            path: PathBuf::new(),
            cursor: 0,
            sort: BrowseSort::Size,
            stack: Vec::new(),
        }
    }
}

/// The tree node for `path`: the tree whose root is a prefix of `path`, then
/// `DirNode::find` down to it. `None` when no loaded tree covers `path` (no
/// scan yet, or a path outside every walked root).
pub fn node_at<'a>(
    trees: &'a BTreeMap<PathBuf, Arc<DirTree>>,
    path: &Path,
) -> Option<DirectoryRef<'a>> {
    let (root, tree) = trees
        .iter()
        .find(|(root, _)| path.starts_with(root.as_path()))?;
    tree.node.find(root, path)
}

/// The first bounded page of `node`'s scanned children, sorted within the page:
/// `Size` is allocation descending; `Name` is case-insensitive.
const MAX_CHILDREN: usize = 500;

pub struct BrowseEntries<'arena> {
    rows: Vec<DirectoryRef<'arena>>,
    truncated: bool,
    resource_limited: bool,
    _memory: Option<Reservation>,
}

impl<'arena> std::ops::Deref for BrowseEntries<'arena> {
    type Target = [DirectoryRef<'arena>];

    fn deref(&self) -> &Self::Target {
        &self.rows
    }
}

pub fn entries(node: DirectoryRef<'_>, sort: BrowseSort) -> BrowseEntries<'_> {
    entries_with_budget(node, sort, &MemoryBudget::shared())
}

fn entries_with_budget<'arena>(
    node: DirectoryRef<'arena>,
    sort: BrowseSort,
    budget: &Arc<MemoryBudget>,
) -> BrowseEntries<'arena> {
    let memory = match budget.reserve(MAX_CHILDREN * std::mem::size_of::<DirectoryRef<'_>>() + 8192)
    {
        Ok(memory) => memory,
        Err(_) => {
            return BrowseEntries {
                rows: Vec::new(),
                truncated: false,
                resource_limited: true,
                _memory: None,
            };
        }
    };
    let mut children = node.children();
    let mut rows = Vec::with_capacity(MAX_CHILDREN);
    rows.extend(children.by_ref().take(MAX_CHILDREN));
    let truncated = children.next().is_some();
    match sort {
        BrowseSort::Size => {
            rows.sort_unstable_by(|left, right| {
                right
                    .alloc
                    .cmp(&left.alloc)
                    .then_with(|| left.raw_name().cmp(right.raw_name()))
            });
        }
        BrowseSort::Name => rows.sort_unstable_by(|left, right| {
            left.name()
                .chars()
                .flat_map(char::to_lowercase)
                .cmp(right.name().chars().flat_map(char::to_lowercase))
                .then_with(|| left.raw_name().cmp(right.raw_name()))
        }),
    }
    BrowseEntries {
        rows,
        truncated,
        resource_limited: false,
        _memory: Some(memory),
    }
}

/// A `width`-cell bar, `part / whole` filled with `█`, the rest `░`. A zero
/// `whole` (nothing to divide by) reads as empty rather than dividing by
/// zero or filling solid.
pub fn bar(part: u64, whole: u64, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if whole == 0 {
        return "░".repeat(width);
    }
    let frac = (part as f64 / whole as f64).clamp(0.0, 1.0);
    let filled = (frac * width as f64).round() as usize;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

/// Bar width in cells, shown only when the panel is wide enough (see
/// `show_bar` below) — mirrors how `rows::fitting_columns` degrades.
const BAR_WIDTH: usize = 20;
/// Below this inner width the Share column drops its bar and shows the bare
/// percentage instead.
const BAR_MIN_WIDTH: u16 = 80;

/// Thousands-grouped integer, e.g. `128431` → `"128,431"`.
fn thousands(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

/// Main panel: the current directory's children as a directory listing (no
/// group headers, no files — a directory's own files are the detail pane's
/// bounded scan summary). Falls back to an "indexing" placeholder when the tree
/// has vanished (a Disk rescan clears `dir_trees` while still in Browse).
pub fn draw(app: &AppState, frame: &mut Frame, area: Rect, vp: &mut Viewport) {
    let Some(node) = node_at(&app.dir_trees, &app.browse.path) else {
        draw_indexing(frame, area);
        return;
    };

    let entries = entries(node, app.browse.sort);
    let mut title = format!(
        " {} · {} · {} files{} ",
        fmt::abbrev_home(&app.browse.path),
        fmt::bytes(node.alloc),
        thousands(node.files),
        if node.errors > 0 {
            format!(" · {} unreadable", thousands(node.errors))
        } else {
            String::new()
        },
    );
    if entries.truncated {
        title.push_str(" first 500 scanned children · page-local sort ");
    }
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);

    if entries.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                if entries.resource_limited {
                    "memory budget exhausted; folder page unavailable"
                } else {
                    "no subdirectories"
                },
                Style::default().fg(Color::DarkGray),
            )))
            .block(block)
            .alignment(Alignment::Center),
            area,
        );
        return;
    }

    let show_bar = inner.width >= BAR_MIN_WIDTH;
    let constraints = vec![
        Constraint::Length(2),
        Constraint::Fill(2),
        Constraint::Length(10),
        Constraint::Length(if show_bar { 5 + BAR_WIDTH as u16 } else { 4 }),
        Constraint::Length(9),
        Constraint::Length(6),
    ];
    let rects = Layout::horizontal(&constraints).spacing(1).split(inner);
    let widths: Vec<Constraint> = rects.iter().map(|r| Constraint::Length(r.width)).collect();

    let header_cells: Vec<Cell> = ["", "Name", "Size", "Share", "Files", "Dirs"]
        .into_iter()
        .enumerate()
        .map(|(i, h)| {
            let align = if i >= 4 {
                Alignment::Right
            } else {
                Alignment::Left
            };
            Cell::from(
                Line::from(Span::styled(
                    h,
                    Style::default().add_modifier(Modifier::BOLD),
                ))
                .alignment(align),
            )
        })
        .collect();

    let visible = inner.height.saturating_sub(1) as usize;
    let n = entries.len();
    let cursor = app.browse.cursor.min(n.saturating_sub(1));
    let offset = layout::adjust_offset(vp.row_offset, cursor, n, visible);
    vp.row_offset = offset;
    vp.rows_visible = visible;
    let window = &entries[offset.min(n)..(offset + visible).min(n)];
    for i in 0..window.len() {
        vp.push(
            Rect::new(inner.x, inner.y + 1 + i as u16, inner.width, 1),
            Hit::Row(offset + i),
        );
    }

    let table_rows: Vec<Row> = window
        .iter()
        .map(|child| render_entry_row(child, node.alloc, show_bar, &rects))
        .collect();

    let table = Table::new(table_rows, widths)
        .column_spacing(1)
        .header(Row::new(header_cells))
        .block(block)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut ts = TableState::default().with_selected(Some(cursor - offset));
    frame.render_stateful_widget(table, area, &mut ts);
}

fn render_entry_row(
    child: &DirectoryRef<'_>,
    parent_alloc: u64,
    show_bar: bool,
    rects: &[Rect],
) -> Row<'static> {
    let has_children = child.children().next().is_some();
    let gutter = if child.errors > 0 {
        Span::styled("!", Style::default().fg(Color::Red))
    } else {
        Span::raw(" ")
    };
    let glyph = if has_children { theme::COLLAPSED } else { " " };
    let name = fmt::truncate_end(
        &format!("{glyph} {}", child.name()),
        rects[1].width as usize,
    );
    let size = fmt::bytes(child.alloc);
    let pct = if parent_alloc == 0 {
        0.0
    } else {
        child.alloc as f64 / parent_alloc as f64 * 100.0
    };
    let share = if show_bar {
        format!("{pct:>3.0}% {}", bar(child.alloc, parent_alloc, BAR_WIDTH))
    } else {
        format!("{pct:>3.0}%")
    };
    let share = fmt::truncate_end(&share, rects[3].width as usize);
    Row::new(vec![
        Cell::from(gutter),
        Cell::from(name),
        Cell::from(Line::from(size).alignment(Alignment::Right)),
        Cell::from(share),
        Cell::from(Line::from(thousands(child.files)).alignment(Alignment::Right)),
        Cell::from(Line::from(thousands(child.dirs)).alignment(Alignment::Right)),
    ])
}

fn draw_indexing(frame: &mut Frame, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Folders ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "Indexing… (tree will reappear when the Disk scan finishes)",
            Style::default().fg(Color::DarkGray),
        )))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true }),
        inner,
    );
}

/// Detail pane: totals for the entry under the cursor (or the current
/// directory itself when it has no children), retained own-file summaries, and
/// the Disk findings rooted under it.
pub fn draw_detail(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = Block::default().borders(Borders::LEFT).title(" Detail ");
    let Some(node) = node_at(&app.dir_trees, &app.browse.path) else {
        frame.render_widget(Paragraph::new(""), area);
        return;
    };
    let kids = entries(node, app.browse.sort);
    if kids.resource_limited {
        frame.render_widget(
            Paragraph::new("memory budget exhausted; folder detail unavailable").block(block),
            area,
        );
        return;
    }
    let (target, path) = if kids.is_empty() {
        (node, app.browse.path.clone())
    } else {
        let idx = app.browse.cursor.min(kids.len() - 1);
        (
            kids[idx],
            app.browse
                .path
                .join(std::ffi::OsStr::from_bytes(kids[idx].raw_name())),
        )
    };
    let fields = detail_fields(app, target, &path);
    let inner_width = block.inner(area).width;
    let text = crate::ui::detail::render(&fields, inner_width);
    frame.render_widget(
        Paragraph::new(text).block(block).wrap(Wrap { trim: false }),
        area,
    );
}

fn detail_fields(app: &AppState, node: DirectoryRef<'_>, path: &Path) -> Vec<Field> {
    let mut fields = vec![
        Field::Header(""),
        Field::Text(node.name().into_owned()),
        Field::Blank,
        kv("Allocated", fmt::bytes(node.alloc)),
        kv("Apparent", fmt::bytes(node.apparent)),
        kv("Files", thousands(node.files)),
        kv("Folders", thousands(node.dirs)),
    ];
    fields.push(if node.errors > 0 {
        present::kv_styled("Unreadable", thousands(node.errors), Color::Red)
    } else {
        kv("Unreadable", "0")
    });

    if let Some(tree) = app
        .dir_trees
        .values()
        .find(|tree| path.starts_with(&tree.root))
    {
        fields.push(Field::Blank);
        fields.push(Field::Header("Large files · scan summary"));
        fields.push(Field::Text(
            "Up to 3 retained entries; not an exact folder ranking".into(),
        ));
        fields.push(kv(
            "Scan coverage",
            if tree.complete {
                "complete snapshot"
            } else {
                "partial snapshot; files may be absent"
            },
        ));
        let mut retained = 0;
        for f in tree
            .top_files
            .iter()
            .filter(|file| file.path.parent() == Some(path))
            .take(3)
        {
            let name = f
                .path
                .file_name()
                .map_or_else(|| f.path.to_string_lossy(), |n| n.to_string_lossy());
            fields.push(kv(fmt::bytes(f.alloc), name.into_owned()));
            retained += 1;
        }
        if retained == 0 {
            fields.push(Field::Text(
                "No entries retained for this folder; it may still contain files".into(),
            ));
        }
    }

    let (count, reclaimable) = findings_under(app, path);
    if count > 0 {
        fields.push(Field::Blank);
        fields.push(Field::Header("Findings here"));
        fields.push(kv("Count", count.to_string()));
        if reclaimable > 0 {
            fields.push(present::kv_styled(
                "Reclaimable",
                fmt::bytes(reclaimable),
                theme::severity_color(Severity::Reclaimable),
            ));
        }
    }
    fields
}

/// Disk findings rooted under `dir`: how many, and how many bytes of them
/// are `Severity::Reclaimable`.
fn findings_under(app: &AppState, dir: &Path) -> (usize, u64) {
    let mut count = 0usize;
    let mut reclaimable = 0u64;
    if let Some(map) = app.findings.get(&ScannerId::Fs) {
        for f in map.values() {
            let Some(p) = &f.path else { continue };
            if !p.starts_with(dir) {
                continue;
            }
            count += 1;
            if f.severity == Severity::Reclaimable {
                reclaimable += f.size_bytes.unwrap_or(0);
            }
        }
    }
    (count, reclaimable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake;

    fn trees() -> BTreeMap<PathBuf, Arc<DirTree>> {
        let tree = fake::dir_tree();
        let mut map = BTreeMap::new();
        map.insert(tree.root.clone(), Arc::new(tree));
        map
    }

    #[test]
    fn node_at_resolves_root_nested_and_outside() {
        let trees = trees();
        let root = PathBuf::from("/Users/dev");
        assert_eq!(&*node_at(&trees, &root).unwrap().name(), "/Users/dev");

        let nested = root.join("dev/cubby");
        let node = node_at(&trees, &nested).expect("nested path resolves");
        assert_eq!(&*node.name(), "cubby");

        assert!(node_at(&trees, Path::new("/Users/other")).is_none());
    }

    #[test]
    fn entries_orders_by_active_sort() {
        let trees = trees();
        let root = node_at(&trees, &PathBuf::from("/Users/dev")).unwrap();

        let by_size = entries(root, BrowseSort::Size);
        assert!(
            by_size.windows(2).all(|w| w[0].alloc >= w[1].alloc),
            "Size sort must be allocation descending"
        );

        let by_name = entries(root, BrowseSort::Name);
        let names: Vec<String> = by_name.iter().map(|n| n.name().to_lowercase()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "Name sort must be case-insensitive A-Z");
    }

    #[test]
    fn wide_child_pages_are_bounded_and_hold_their_memory_credit() {
        let arena_budget = MemoryBudget::new(8 * 1024 * 1024);
        let mut arena = crate::inventory::DiskInventory::new(arena_budget).unwrap();
        let root = arena
            .add_directory(None, std::ffi::OsStr::new("root"))
            .unwrap();
        for position in 0..10_000 {
            arena
                .add_directory(
                    Some(root),
                    std::ffi::OsStr::new(&format!("child-{position:05}")),
                )
                .unwrap();
        }
        let node = arena.directory(root).unwrap();
        let page_budget = MemoryBudget::new(64 * 1024);
        for sort in [BrowseSort::Name, BrowseSort::Size] {
            let page = entries_with_budget(node, sort, &page_budget);
            assert_eq!(page.len(), MAX_CHILDREN);
            assert!(page.truncated);
            assert!(!page.resource_limited);
            assert!(page_budget.used() > 0);
            assert!(page
                .iter()
                .all(|child| child.raw_name() >= b"child-09500".as_slice()));
            drop(page);
            assert_eq!(page_budget.used(), 0);
        }
        let denied_budget = MemoryBudget::new(1);
        let denied = entries_with_budget(node, BrowseSort::Name, &denied_budget);
        assert!(denied.is_empty());
        assert!(denied.resource_limited);
        assert_eq!(denied_budget.used(), 0);
    }

    #[test]
    fn detail_uses_retained_direct_file_summaries_without_frame_time_io() {
        let home = tempfile::tempdir().unwrap();
        let selected = home.path().join("Movies");
        std::fs::create_dir(&selected).unwrap();
        std::fs::write(selected.join("fresh-not-scanned.bin"), vec![1; 1024]).unwrap();
        let mut tree = fake::dir_tree_at(home.path());
        tree.complete = false;
        tree.top_files = (0..4)
            .map(|position| crate::scan::walk::BigFile {
                path: selected.join(format!("retained-{position}.bin")),
                alloc: 1000 - position,
            })
            .collect();
        tree.top_files.insert(
            0,
            crate::scan::walk::BigFile {
                path: selected.join("nested/not-direct.bin"),
                alloc: 2000,
            },
        );
        let mut app = AppState::default();
        app.dir_trees.insert(tree.root.clone(), Arc::new(tree));
        let node = node_at(&app.dir_trees, &selected).unwrap();
        let fields = detail_fields(&app, node, &selected);
        let rendered = crate::ui::detail::render(&fields, 80)
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("scan summary"));
        assert!(rendered.contains("not an exact folder ranking"));
        assert!(rendered.contains("partial snapshot"));
        assert!(rendered.contains("retained-0.bin"));
        assert!(rendered.contains("retained-2.bin"));
        assert!(!rendered.contains("retained-3.bin"));
        assert!(!rendered.contains("not-direct.bin"));
        assert!(!rendered.contains("fresh-not-scanned.bin"));
    }

    #[test]
    fn bar_widths() {
        assert_eq!(bar(0, 100, 10), "░".repeat(10), "0% is empty");
        assert_eq!(
            bar(50, 100, 10),
            format!("{}{}", "█".repeat(5), "░".repeat(5)),
            "50% is half filled"
        );
        assert_eq!(bar(100, 100, 10), "█".repeat(10), "100% is solid");
        assert_eq!(
            bar(5, 0, 10),
            "░".repeat(10),
            "a zero whole must not divide by zero or fill solid"
        );
    }

    #[test]
    fn thousands_groups_by_three() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(128_431), "128,431");
    }
}
