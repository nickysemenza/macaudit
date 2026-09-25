//! iOS Devices: one `ios_device` row per connected iPhone/iPad (capacity,
//! free, purgeable, app totals) and one `ios_app` row per installed app with
//! its bundle (`static_bytes`) and data (`dynamic_bytes`) split. Status rows
//! (tools missing, no device, locked) are `ios_device` rows with no numbers.

use ratatui::layout::Constraint;

use super::*;
use crate::model::{FindingKind, Severity};

fn kind(f: &Finding, _: &CellCtx) -> CellText {
    match f.kind {
        FindingKind::IosApp => match meta_str(f, "app_type") {
            Some("System") => dim("system"),
            _ => plain("user"),
        },
        _ if meta_u64(f, "capacity_bytes").is_some() => plain("device"),
        _ => dim(""),
    }
}

fn app_bytes(f: &Finding, _: &CellCtx) -> CellText {
    dim(meta_u64(f, "static_bytes")
        .map(fmt::bytes)
        .unwrap_or_default())
}

/// Data-heavy apps (Attention) get their data column painted so the reason
/// for the flag is visible without opening the detail pane.
fn data_bytes(f: &Finding, _: &CellCtx) -> CellText {
    let text = meta_u64(f, "dynamic_bytes")
        .map(fmt::bytes)
        .unwrap_or_default();
    if f.severity == Severity::Attention {
        colored(text, theme::severity_color(Severity::Attention))
    } else {
        plain(text)
    }
}

fn key_kind(f: &Finding) -> SortKey {
    // Devices first, then user apps, then system apps.
    SortKey::Int(match f.kind {
        FindingKind::IosApp if meta_str(f, "app_type") == Some("System") => 2,
        FindingKind::IosApp => 1,
        _ => 0,
    })
}

fn key_meta_bytes(f: &Finding, key: &str) -> SortKey {
    match meta_u64(f, key) {
        Some(b) => SortKey::Bytes(b),
        None => SortKey::None,
    }
}
fn key_app_bytes(f: &Finding) -> SortKey {
    key_meta_bytes(f, "static_bytes")
}
fn key_data_bytes(f: &Finding) -> SortKey {
    key_meta_bytes(f, "dynamic_bytes")
}

fn detail(f: &Finding, m: &mut MetaView<'_>, _ctx: &DetailCtx) -> Vec<Field> {
    let mut out = Vec::new();
    match f.kind {
        FindingKind::IosApp => {
            out.extend(kv_str(m, "bundle_id", "Bundle ID"));
            out.extend(kv_str(m, "app_version", "Version"));
            out.extend(kv_str(m, "app_type", "Type"));
            if let Some(b) = m.bytes("static_bytes") {
                out.push(kv("App size", b));
            }
            if let Some(b) = m.bytes("dynamic_bytes") {
                out.push(kv("Data size", b));
            }
            out.extend(kv_str(m, "device", "Device"));
        }
        _ => {
            out.extend(kv_str(m, "device", "Device"));
            out.extend(kv_str(m, "product_type", "Model"));
            out.extend(kv_str(m, "ios_version", "iOS"));
            if let Some(b) = m.bytes("capacity_bytes") {
                out.push(kv("Capacity", b));
            }
            if let Some(b) = m.bytes("used_bytes") {
                out.push(kv(
                    "Used",
                    format!("{b} (what Settings shows; includes purgeable)"),
                ));
            }
            if let Some(b) = m.bytes("free_bytes") {
                out.push(kv("Free", b));
            }
            if let Some(b) = m.bytes("purgeable_bytes") {
                out.push(kv_styled(
                    "Purgeable",
                    format!("{b} — caches iOS frees on demand; Settings never shows this"),
                    Color::Cyan,
                ));
            }
            if let Some(b) = m.bytes("committed_bytes") {
                out.push(kv(
                    "Committed",
                    format!("{b} — stays used after iOS purges everything it can"),
                ));
            }
            m.skip("available_bytes");
            if let (Some(b), Some(n)) = (m.bytes("apps_bytes"), m.u64("app_count")) {
                out.push(kv("Apps", format!("{b} across {n} apps (bundle + data)")));
            }
            if let Some(b) = m.bytes("unattributed_bytes") {
                out.push(kv(
                    "Not attributed",
                    format!("{b} — media, Messages, system, purgeable caches"),
                ));
            }
        }
    }
    out.extend(kv_str(m, "udid", "UDID"));
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "Name", Constraint::Fill(1), name_cell)
        .primary()
        .sortable(key_title, SortDir::Asc),
    Column::new(
        ColumnId::Classification,
        "Kind",
        Constraint::Length(7),
        kind,
    )
    .sortable(key_kind, SortDir::Asc),
    Column::new(ColumnId::AppBytes, "App", Constraint::Length(11), app_bytes)
        .right()
        .sortable(key_app_bytes, SortDir::Desc),
    Column::new(
        ColumnId::DataBytes,
        "Data",
        Constraint::Length(9),
        data_bytes,
    )
    .right()
    .sortable(key_data_bytes, SortDir::Desc),
    Column::new(ColumnId::Size, "Size", Constraint::Length(10), size_cell)
        .right()
        .sortable(key_size, SortDir::Desc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Size, SortDir::Desc),
    detail,
};
