//! Projects: one row per discovered project — a git repo root or a lone
//! manifest dir — with the exclusive/shared/reach/baseline-share numbers,
//! worktree/process/port counts, and a detail pane breaking down what the
//! project actually touches (see `super::attribution_detail`). The three
//! synthetic bucket rows (Baseline/Unattributed/Coverage, `FindingKind::
//! ProjectBucket`) render dim and sort to the bottom regardless of column —
//! `bucket_aware_name_cell`/`key_name_bucket_last` in `present/mod.rs`.

use ratatui::layout::Constraint;

use super::*;

fn worktrees_cell(f: &Finding, _: &CellCtx) -> CellText {
    count_cell(meta_len(f, "worktrees"))
}
fn procs_cell(f: &Finding, _: &CellCtx) -> CellText {
    count_cell(meta_u64(f, "process_count").unwrap_or(0) as usize)
}
fn ports_cell(f: &Finding, _: &CellCtx) -> CellText {
    count_cell(meta_len(f, "ports"))
}

fn key_worktrees(f: &Finding) -> SortKey {
    key_meta_array_len(f, "worktrees")
}
fn key_procs(f: &Finding) -> SortKey {
    key_meta_int(f, "process_count")
}
fn key_ports(f: &Finding) -> SortKey {
    key_meta_array_len(f, "ports")
}

fn detail(f: &Finding, m: &mut MetaView<'_>, ctx: &DetailCtx) -> Vec<Field> {
    attribution_detail(f, m, Axis::Projects, ctx)
}

static COLUMNS: &[Column] = &[
    Column::new(
        ColumnId::Name,
        "Project",
        Constraint::Fill(2),
        bucket_aware_name_cell,
    )
    .primary()
    .sortable(key_name_bucket_last, SortDir::Asc),
    Column::new(ColumnId::Size, "Excl", Constraint::Length(10), excl_cell)
        .right()
        .sortable(key_excl, SortDir::Desc),
    Column::new(
        ColumnId::Shared,
        "Shared",
        Constraint::Length(10),
        shared_cell,
    )
    .right()
    .sortable(key_shared, SortDir::Desc),
    Column::new(ColumnId::Reach, "Reach", Constraint::Length(10), reach_cell)
        .right()
        .sortable(key_reach, SortDir::Desc),
    Column::new(
        ColumnId::Worktrees,
        "Worktrees",
        Constraint::Length(9),
        worktrees_cell,
    )
    .right()
    .sortable(key_worktrees, SortDir::Desc),
    Column::new(ColumnId::Procs, "Procs", Constraint::Length(5), procs_cell)
        .right()
        .sortable(key_procs, SortDir::Desc),
    Column::new(ColumnId::Ports, "Ports", Constraint::Length(5), ports_cell)
        .right()
        .sortable(key_ports, SortDir::Desc),
    Column::new(ColumnId::Path, "Path", Constraint::Fill(3), path_cell)
        .middle()
        .sortable(key_path, SortDir::Asc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Size, SortDir::Desc),
    detail,
};
