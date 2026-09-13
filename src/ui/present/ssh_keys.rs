//! Keys: SSH key pairs under `~/.ssh`.

use ratatui::layout::Constraint;
use ratatui::style::Color;

use super::*;
use crate::model::Severity;

fn key_type(f: &Finding, _: &CellCtx) -> CellText {
    plain(meta_str(f, "type").unwrap_or(""))
}

fn bits(f: &Finding, _: &CellCtx) -> CellText {
    let weak = meta_str(f, "type").is_some_and(|t| t.contains("rsa"))
        && meta_u64(f, "bits").is_some_and(|b| b <= 2048);
    let text = meta_u64(f, "bits")
        .map(|b| b.to_string())
        .unwrap_or_default();
    if weak {
        colored(text, theme::severity_color(Severity::Attention))
    } else {
        plain(text)
    }
}

fn age(f: &Finding, _: &CellCtx) -> CellText {
    let days = meta_u64(f, "age_days");
    let text = match days {
        Some(d) if d >= 365 => format!("{:.1}y", d as f64 / 365.0),
        Some(d) if d >= 30 => format!("{}mo", d / 30),
        Some(d) => format!("{d}d"),
        None => String::new(),
    };
    if days.is_some_and(|d| d > 5 * 365) {
        colored(text, theme::severity_color(Severity::Attention))
    } else {
        dim(text)
    }
}

fn config(f: &Finding, _: &CellCtx) -> CellText {
    check(meta_bool(f, "has_config_entry").unwrap_or(false))
}

fn key_type_key(f: &Finding) -> SortKey {
    key_meta_text(f, "type")
}
fn key_bits(f: &Finding) -> SortKey {
    key_meta_int(f, "bits")
}
fn key_age_days(f: &Finding) -> SortKey {
    key_meta_int(f, "age_days")
}

fn detail(_: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    out.extend(kv_str(m, "type", "Type"));
    out.extend(kv_u64(m, "bits", "Bits"));
    if let Some(days) = m.u64("age_days") {
        let text = if days >= 365 {
            format!("{days} days (~{:.1} years)", days as f64 / 365.0)
        } else {
            format!("{days} days")
        };
        out.push(if days > 5 * 365 {
            kv_styled("Age", text, Color::Yellow)
        } else {
            kv("Age", text)
        });
    }
    out.extend(kv_str(m, "comment", "Comment"));
    out.extend(kv_bool(m, "has_config_entry", "In ~/.ssh/config"));
    out.extend(kv_bool(m, "has_private_key", "Private key present"));
    out.extend(kv_str(m, "pubkey_path", "Public key"));
    out.extend(kv_str(m, "private_key_path", "Private key"));
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "File", Constraint::Fill(1), name_cell)
        .primary()
        .sortable(key_title, SortDir::Asc),
    Column::new(ColumnId::KeyType, "Type", Constraint::Length(9), key_type)
        .sortable(key_type_key, SortDir::Asc),
    Column::new(ColumnId::Bits, "Bits", Constraint::Length(5), bits)
        .right()
        .sortable(key_bits, SortDir::Asc),
    Column::new(ColumnId::Age, "Age", Constraint::Length(6), age)
        .right()
        .sortable(key_age_days, SortDir::Desc),
    Column::new(ColumnId::Config, "Config", Constraint::Length(6), config),
    Column::new(ColumnId::Path, "Path", Constraint::Fill(1), path_cell).middle(),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Age, SortDir::Desc),
    detail,
};
