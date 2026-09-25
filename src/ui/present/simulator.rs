//! Simulators: Xcode simulator runtimes (`kind: runtime`) and devices
//! (`kind: device`).

use ratatui::layout::Constraint;
use ratatui::style::Color;

use super::*;
use crate::model::Severity;

fn runtime(f: &Finding, _: &CellCtx) -> CellText {
    dim(match meta_str(f, "kind") {
        Some("runtime") => meta_str(f, "version").unwrap_or(""),
        _ => meta_str(f, "runtime").unwrap_or(""),
    })
}

fn state(f: &Finding, _: &CellCtx) -> CellText {
    if meta_bool(f, "available") == Some(false) {
        return colored("unavailable", theme::severity_color(Severity::Reclaimable));
    }
    match meta_str(f, "kind") {
        Some("runtime") => dim("runtime"),
        _ => match meta_str(f, "state") {
            Some("Booted") => colored("booted", ratatui::style::Color::Green),
            Some(s) => dim(s.to_lowercase()),
            None => plain(""),
        },
    }
}

fn key_runtime(f: &Finding) -> SortKey {
    match meta_str(f, "kind") {
        Some("runtime") => key_meta_text(f, "version"),
        _ => key_meta_text(f, "runtime"),
    }
}
fn key_state(f: &Finding) -> SortKey {
    // Unavailable (reclaimable) first, then booted, then shutdown.
    SortKey::Int(if meta_bool(f, "available") == Some(false) {
        0
    } else if meta_str(f, "state") == Some("Booted") {
        1
    } else {
        2
    })
}

fn detail(_: &Finding, m: &mut MetaView<'_>, _ctx: &DetailCtx) -> Vec<Field> {
    let mut out = Vec::new();
    out.extend(kv_str(m, "kind", "Kind"));
    out.extend(kv_str(m, "runtime", "Runtime"));
    out.extend(kv_str(m, "version", "Version"));
    out.extend(kv_str(m, "build", "Build"));
    out.extend(kv_str(m, "state", "State"));
    if let Some(avail) = m.bool("available") {
        out.push(if avail {
            kv("Available", "yes")
        } else {
            kv_styled("Available", "no — runtime missing", Color::Cyan)
        });
    }
    out.extend(kv_str(m, "udid", "UDID"));
    out.extend(kv_str(m, "identifier", "Identifier"));
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "Name", Constraint::Fill(1), name_cell)
        .primary()
        .sortable(key_title, SortDir::Asc),
    Column::new(
        ColumnId::Runtime,
        "Runtime",
        Constraint::Length(18),
        runtime,
    )
    .sortable(key_runtime, SortDir::Asc),
    Column::new(ColumnId::State, "State", Constraint::Length(12), state)
        .sortable(key_state, SortDir::Asc),
    Column::new(ColumnId::Size, "Size", Constraint::Length(10), size_cell)
        .right()
        .sortable(key_size, SortDir::Desc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Size, SortDir::Desc),
    detail,
};
