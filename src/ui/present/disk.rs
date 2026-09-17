//! Disk: build artifacts, caches, large files, iOS backups and bounded disk
//! categories, grouped by `meta.group` and ordered by size.

use ratatui::layout::Constraint;

use super::*;

fn detail(_: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    m.skip("group");
    out.extend(kv_str(m, "artifact", "Artifact"));
    out.extend(kv_str(m, "category", "Category"));
    if let Some(stale) = m.bool("stale") {
        out.push(kv("Stale", yes_no(stale)));
    }
    if let Some(complete) = m.bool("complete") {
        out.push(kv(
            "Measurement",
            if complete {
                "complete"
            } else {
                "bounded (partial)"
            },
        ));
    }
    out.extend(kv_u64(m, "entries", "Entries"));
    out.extend(kv_str(m, "marker", "Recognised by"));
    if let Some(main) = m.str("worktree_of") {
        let name = m.str("worktree_name").unwrap_or("?");
        out.push(kv("Worktree", format!("{name} of {main}")));
    }
    out.extend(kv_str(m, "repo_root", "Repository"));
    if let Some(layout) = m.str("layout") {
        out.push(kv("Layout", layout));
        out.extend(kv_str(m, "store_dir", "pnpm store"));
        out.extend(kv_str(m, "import_method", "Import method"));
        match m.u64("shared_hardlink_bytes") {
            Some(b) => out.push(kv_styled(
                "Hard-linked from store",
                fmt::bytes(b),
                ratatui::style::Color::Yellow,
            )),
            None => out.push(kv_styled(
                "Hard-linked from store",
                "not measured",
                ratatui::style::Color::DarkGray,
            )),
        }
        if let Some(r) = m.u64("estimated_reclaim_bytes") {
            out.push(kv("Reclaim (at most)", fmt::bytes(r)));
        }
    }
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "Name", Constraint::Fill(2), name_cell)
        .primary()
        .sortable(key_title, SortDir::Asc),
    Column::new(ColumnId::Size, "Size", Constraint::Length(10), size_cell)
        .right()
        .sortable(key_size, SortDir::Desc),
    Column::new(ColumnId::Age, "Used", Constraint::Length(8), age_cell)
        .right()
        .sortable(key_age, SortDir::Desc),
    Column::new(ColumnId::Path, "Path", Constraint::Fill(3), path_cell)
        .middle()
        .sortable(key_path, SortDir::Asc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Size, SortDir::Desc),
    detail,
};
