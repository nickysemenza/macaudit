//! Brew: formulae and casks (tree grouped by kind). Status shows what the
//! user can act on — `outdated` — else whether a formula is a leaf.

use ratatui::layout::Constraint;
use ratatui::style::Color;

use super::*;
use crate::model::{FindingKind, Severity};

fn version(f: &Finding, _: &CellCtx) -> CellText {
    dim(meta_str(f, "version").unwrap_or(""))
}

fn status(f: &Finding, _: &CellCtx) -> CellText {
    if meta_bool(f, "outdated").unwrap_or(false) {
        let latest = meta_str(f, "current_version").unwrap_or("");
        return colored(
            format!("outdated → {latest}"),
            theme::severity_color(Severity::Attention),
        );
    }
    match f.kind {
        FindingKind::BrewCask => dim("cask"),
        _ if meta_bool(f, "is_leaf").unwrap_or(false) => plain("leaf"),
        _ => dim("dependency"),
    }
}

fn deps(f: &Finding, _: &CellCtx) -> CellText {
    let n = meta_len(f, "dependents");
    if n == 0 {
        plain("")
    } else {
        dim(format!("{n}"))
    }
}

fn key_status(f: &Finding) -> SortKey {
    // Outdated first, then leaves, then dependencies.
    SortKey::Int(match (meta_bool(f, "outdated"), meta_bool(f, "is_leaf")) {
        (Some(true), _) => 0,
        (_, Some(true)) => 1,
        _ => 2,
    })
}
fn key_deps(f: &Finding) -> SortKey {
    SortKey::Int(meta_len(f, "dependents") as i64)
}

fn detail(_: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    m.skip("name");
    m.skip("token");
    out.extend(kv_str(m, "version", "Installed"));
    if m.bool("outdated").unwrap_or(false) {
        if let Some(latest) = m.str("current_version") {
            out.push(kv_styled("Latest", latest, Color::Yellow));
        }
    } else {
        m.skip("current_version");
    }
    out.extend(kv_bool(m, "is_leaf", "Leaf (nothing depends on it)"));
    out.extend(kv_list(m, "dependencies", "Depends on"));
    out.extend(kv_list(m, "dependents", "Used by"));
    out.extend(kv_list(m, "app_paths", "Installs"));
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "Name", Constraint::Fill(2), name_cell)
        .primary()
        .sortable(key_title, SortDir::Asc),
    Column::new(
        ColumnId::Version,
        "Version",
        Constraint::Length(14),
        version,
    ),
    Column::new(ColumnId::Status, "Status", Constraint::Length(22), status)
        .sortable(key_status, SortDir::Asc),
    Column::new(ColumnId::Deps, "Used by", Constraint::Length(7), deps)
        .right()
        .sortable(key_deps, SortDir::Desc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Name, SortDir::Asc),
    detail,
};
