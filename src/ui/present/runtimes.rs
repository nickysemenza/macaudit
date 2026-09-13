//! Runtimes: language versions per version manager, plus rustup toolchains
//! and "multiple managers for X" conflicts.

use ratatui::layout::Constraint;

use super::*;

fn runtime(f: &Finding, ctx: &CellCtx) -> CellText {
    let mut c = name_cell(f, ctx);
    if let Some(rt) = meta_str(f, "runtime") {
        if meta_str(f, "version").is_some() {
            c.text = rt.to_string();
        }
    }
    c
}

fn version(f: &Finding, _: &CellCtx) -> CellText {
    plain(meta_str(f, "version").unwrap_or(""))
}

fn manager(f: &Finding, _: &CellCtx) -> CellText {
    dim(meta_str(f, "manager").unwrap_or(""))
}

fn default(f: &Finding, _: &CellCtx) -> CellText {
    check(meta_bool(f, "is_default").unwrap_or(false))
}

fn key_runtime(f: &Finding) -> SortKey {
    key_meta_text(f, "runtime")
}
fn key_version(f: &Finding) -> SortKey {
    key_meta_text(f, "version")
}
fn key_manager(f: &Finding) -> SortKey {
    key_meta_text(f, "manager")
}

fn detail(_: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    out.extend(kv_str(m, "runtime", "Runtime"));
    out.extend(kv_str(m, "version", "Version"));
    out.extend(kv_str(m, "manager", "Manager"));
    out.extend(kv_bool(m, "is_default", "Default toolchain"));
    out.extend(kv_list(m, "managers", "Managers present"));
    m.skip("size_bytes"); // shown as the finding's size
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Runtime, "Runtime", Constraint::Fill(1), runtime)
        .primary()
        .sortable(key_runtime, SortDir::Asc),
    Column::new(
        ColumnId::Version,
        "Version",
        Constraint::Length(14),
        version,
    )
    .sortable(key_version, SortDir::Asc),
    Column::new(
        ColumnId::Manager,
        "Manager",
        Constraint::Length(10),
        manager,
    )
    .sortable(key_manager, SortDir::Asc),
    Column::new(ColumnId::Default, "Default", Constraint::Length(7), default),
    Column::new(ColumnId::Size, "Size", Constraint::Length(10), size_cell)
        .right()
        .sortable(key_size, SortDir::Desc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Size, SortDir::Desc),
    detail,
};
