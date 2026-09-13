//! Docker: `docker system df` rows (images / containers / volumes / build
//! cache) plus any active containers.

use ratatui::layout::Constraint;

use super::*;

fn kind(f: &Finding, ctx: &CellCtx) -> CellText {
    let mut c = name_cell(f, ctx);
    match meta_str(f, "type") {
        Some("active_container") => {
            c.text = meta_str(f, "name").unwrap_or(&f.title).to_string();
        }
        Some(ty) => c.text = ty.to_string(),
        None => {}
    }
    c
}

fn count(f: &Finding, _: &CellCtx) -> CellText {
    match meta_u64(f, "total_count") {
        Some(n) => plain(n.to_string()),
        None => dim(meta_str(f, "status").unwrap_or("")),
    }
}

fn active(f: &Finding, _: &CellCtx) -> CellText {
    match meta_u64(f, "active") {
        Some(n) => plain(n.to_string()),
        None => match meta_f64(f, "cpu_percent") {
            Some(cpu) => plain(format!("{cpu:.0}% cpu")),
            None => plain(""),
        },
    }
}

/// `size_bytes` on a `docker system df` row is the reclaimable amount (the
/// remedy's payoff); active containers carry no size.
fn reclaimable(f: &Finding, ctx: &CellCtx) -> CellText {
    if meta_str(f, "type") == Some("active_container") {
        return plain("");
    }
    size_cell(f, ctx)
}

fn total(f: &Finding, ctx: &CellCtx) -> CellText {
    match meta_u64(f, "total_size_bytes").or(meta_u64(f, "memory_bytes")) {
        Some(b) => dim(fmt::bytes(b)),
        None => size_cell(f, ctx),
    }
}

fn key_count(f: &Finding) -> SortKey {
    key_meta_int(f, "total_count")
}
fn key_total(f: &Finding) -> SortKey {
    match meta_u64(f, "total_size_bytes").or(meta_u64(f, "memory_bytes")) {
        Some(b) => SortKey::Bytes(b),
        None => SortKey::None,
    }
}

fn detail(_: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    if m.str("type") == Some("active_container") {
        out.extend(kv_str(m, "name", "Container"));
        out.extend(kv_str(m, "id", "Id"));
        out.extend(kv_str(m, "status", "Status"));
        if let Some(cpu) = m.f64("cpu_percent") {
            out.push(kv("CPU", format!("{cpu:.1}%")));
        }
        if let Some(mem) = m.bytes("memory_bytes") {
            out.push(kv("Memory", mem));
        }
        return out;
    }
    out.extend(kv_u64(m, "total_count", "Objects"));
    out.extend(kv_u64(m, "active", "Active"));
    if let Some(total) = m.bytes("total_size_bytes") {
        out.push(kv("Total size", total));
    }
    // Docker's own strings, kept because they're what `docker system df` shows.
    out.extend(kv_str(m, "size", "Docker reports size"));
    out.extend(kv_str(m, "reclaimable", "Docker reports reclaimable"));
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "Type", Constraint::Fill(1), kind)
        .primary()
        .sortable(key_title, SortDir::Asc),
    Column::new(ColumnId::Count, "Count", Constraint::Length(8), count)
        .right()
        .sortable(key_count, SortDir::Desc),
    Column::new(ColumnId::Active, "Active", Constraint::Length(9), active).right(),
    Column::new(
        ColumnId::Reclaimable,
        "Reclaimable",
        Constraint::Length(12),
        reclaimable,
    )
    .right()
    .sortable(key_size, SortDir::Desc),
    Column::new(ColumnId::Size, "Total", Constraint::Length(10), total)
        .right()
        .sortable(key_total, SortDir::Desc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Reclaimable, SortDir::Desc),
    detail,
};
