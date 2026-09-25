//! Git: repositories under the scanned roots. State composes dirty / ahead /
//! behind / stash into one glanceable cell (`✗ ↑2 ↓1 ⊟3`).

use ratatui::layout::Constraint;
use ratatui::style::Color;

use super::*;
use crate::model::Severity;

fn branch(f: &Finding, _: &CellCtx) -> CellText {
    plain(meta_str(f, "branch").unwrap_or(""))
}

fn state(f: &Finding, _: &CellCtx) -> CellText {
    let mut parts = Vec::new();
    if meta_bool(f, "dirty").unwrap_or(false) {
        parts.push("✗".to_string());
    }
    if let Some(n) = meta_u64(f, "ahead").filter(|n| *n > 0) {
        parts.push(format!("↑{n}"));
    }
    if let Some(n) = meta_u64(f, "behind").filter(|n| *n > 0) {
        parts.push(format!("↓{n}"));
    }
    if let Some(n) = meta_u64(f, "stash_count").filter(|n| *n > 0) {
        parts.push(format!("⊟{n}"));
    }
    if meta_bool(f, "has_upstream") == Some(false) {
        parts.push("no upstream".to_string());
    }
    if parts.is_empty() {
        dim("clean")
    } else {
        colored(parts.join(" "), theme::severity_color(Severity::Attention))
    }
}

fn key_branch(f: &Finding) -> SortKey {
    key_meta_text(f, "branch")
}
fn key_state(f: &Finding) -> SortKey {
    // Most "needs attention" first.
    let score = meta_bool(f, "dirty").unwrap_or(false) as i64 * 100
        + meta_u64(f, "ahead").unwrap_or(0) as i64
        + meta_u64(f, "behind").unwrap_or(0) as i64
        + meta_u64(f, "stash_count").unwrap_or(0) as i64
        + (meta_bool(f, "has_upstream") == Some(false)) as i64 * 10;
    SortKey::Int(score)
}

fn detail(_: &Finding, m: &mut MetaView<'_>, _ctx: &DetailCtx) -> Vec<Field> {
    let mut out = Vec::new();
    out.extend(kv_str(m, "branch", "Branch"));
    if let Some(dirty) = m.bool("dirty") {
        out.push(if dirty {
            kv_styled("Working tree", "uncommitted changes", Color::Yellow)
        } else {
            kv("Working tree", "clean")
        });
    }
    match m.bool("has_upstream") {
        Some(false) => out.push(kv_styled("Upstream", "none", Color::Yellow)),
        _ => {
            let ahead = m.u64("ahead").unwrap_or(0);
            let behind = m.u64("behind").unwrap_or(0);
            out.push(kv(
                "Upstream",
                match (ahead, behind) {
                    (0, 0) => "in sync".to_string(),
                    (a, 0) => format!("{a} ahead"),
                    (0, b) => format!("{b} behind"),
                    (a, b) => format!("{a} ahead, {b} behind"),
                },
            ));
        }
    }
    m.skip("ahead");
    m.skip("behind");
    out.extend(kv_u64(m, "stash_count", "Stashes"));
    m.skip("size_cached");
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "Repo", Constraint::Fill(2), name_cell)
        .primary()
        .sortable(key_title, SortDir::Asc),
    Column::new(ColumnId::Branch, "Branch", Constraint::Length(16), branch)
        .sortable(key_branch, SortDir::Asc),
    Column::new(ColumnId::State, "State", Constraint::Length(16), state)
        .sortable(key_state, SortDir::Desc),
    Column::new(
        ColumnId::Size,
        ".git size",
        Constraint::Length(10),
        size_cell,
    )
    .right()
    .sortable(key_size, SortDir::Desc),
    Column::new(ColumnId::Age, "Used", Constraint::Length(8), age_cell)
        .right()
        .sortable(key_age, SortDir::Desc),
    Column::new(ColumnId::Path, "Path", Constraint::Fill(2), path_cell)
        .middle()
        .sortable(key_path, SortDir::Asc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Size, SortDir::Desc),
    detail,
};
