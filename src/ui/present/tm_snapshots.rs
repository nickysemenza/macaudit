//! Snapshots: local Time Machine snapshots (APFS). macOS doesn't report
//! their size, so there is no Size column.

use ratatui::layout::Constraint;

use super::*;

fn date(f: &Finding, _: &CellCtx) -> CellText {
    plain(meta_str(f, "date").unwrap_or(""))
}

fn key_date(f: &Finding) -> SortKey {
    key_meta_text(f, "date")
}

fn detail(_: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    out.extend(kv_str(m, "date", "Created"));
    out.extend(kv_str(m, "name", "Snapshot name"));
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "Snapshot", Constraint::Fill(1), name_cell)
        .primary()
        .sortable(key_title, SortDir::Asc),
    Column::new(ColumnId::Date, "Date", Constraint::Length(22), date)
        .sortable(key_date, SortDir::Desc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Date, SortDir::Desc),
    detail,
};
