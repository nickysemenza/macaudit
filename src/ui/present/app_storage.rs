//! App Storage: one row per app/formula/Homebrew/tool owner, with the
//! exclusive/shared/reach numbers and a detail pane breaking down what the
//! owner actually touches (see `super::attribution_detail`). The three
//! synthetic bucket rows (Baseline/Unattributed/Coverage, `FindingKind::
//! AppStorageBucket`) render dim and sort to the bottom regardless of
//! column — `bucket_aware_name_cell`/`key_name_bucket_last` in
//! `present/mod.rs`.

use ratatui::layout::Constraint;

use super::*;

fn kind_cell(f: &Finding, _: &CellCtx) -> CellText {
    match meta_str(f, "owner_kind") {
        Some(k) => plain(k),
        None => plain(""),
    }
}
fn key_kind(f: &Finding) -> SortKey {
    key_meta_text(f, "owner_kind")
}

fn detail(f: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    attribution_detail(f, m, Axis::AppStorage)
}

static COLUMNS: &[Column] = &[
    Column::new(
        ColumnId::Name,
        "Owner",
        Constraint::Fill(2),
        bucket_aware_name_cell,
    )
    .primary()
    .sortable(key_name_bucket_last, SortDir::Asc),
    Column::new(
        ColumnId::Classification,
        "Kind",
        Constraint::Length(10),
        kind_cell,
    )
    .sortable(key_kind, SortDir::Asc),
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
    Column::new(ColumnId::Path, "Path", Constraint::Fill(3), path_cell)
        .middle()
        .sortable(key_path, SortDir::Asc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Size, SortDir::Desc),
    detail,
};
