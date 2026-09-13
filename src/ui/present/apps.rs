//! Apps: tree grouped by `meta.group` (System / User / App Store / Homebrew
//! Cask / Unmanaged…). Sizes are not collected for apps, so there is no Size
//! column; the cask-available badge rides on the name.

use ratatui::layout::Constraint;
use ratatui::style::Color;

use super::*;
use crate::model::Severity;

fn name(f: &Finding, ctx: &CellCtx) -> CellText {
    let mut c = name_cell(f, ctx);
    if let Some(token) = meta_str(f, "available_cask") {
        c.text.push_str(&format!("  ⚠ cask: {token}"));
        c.style = c.style.fg(theme::severity_color(Severity::Attention));
    }
    c
}

fn version(f: &Finding, _: &CellCtx) -> CellText {
    dim(meta_str(f, "version").unwrap_or(""))
}

fn classification(f: &Finding, _: &CellCtx) -> CellText {
    let label = match meta_str(f, "classification") {
        Some("system") => "system",
        Some("app_store") => "App Store",
        Some("cask") => "cask",
        Some("user") => "user",
        Some("unmanaged") => "unmanaged",
        Some(other) => other,
        None => "",
    };
    match label {
        "unmanaged" => colored(label, theme::severity_color(Severity::Attention)),
        _ => plain(label),
    }
}

fn arch(f: &Finding, _: &CellCtx) -> CellText {
    let rosetta = meta_bool(f, "rosetta_or_intel_only").unwrap_or(false);
    let label = match meta_str(f, "arch") {
        Some("arch_arm_i64") => "universal",
        Some("arch_arm") => "arm64",
        Some("arch_i64") => "intel",
        Some(other) => other,
        None => "",
    };
    if rosetta {
        colored(label, Color::Yellow)
    } else {
        dim(label)
    }
}

fn key_version(f: &Finding) -> SortKey {
    key_meta_text(f, "version")
}
fn key_classification(f: &Finding) -> SortKey {
    key_meta_text(f, "classification")
}
fn key_arch(f: &Finding) -> SortKey {
    key_meta_text(f, "arch")
}

fn detail(_: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    out.extend(kv_str(m, "bundle_id", "Bundle id"));
    out.extend(kv_str(m, "version", "Version"));
    out.extend(kv_str(m, "classification", "Source"));
    out.extend(kv_str(m, "group", "Group"));
    out.extend(kv_str(m, "obtained_from", "Obtained from"));
    out.extend(kv_str(m, "signed_by", "Signed by"));
    if let Some(arch) = m.str("arch") {
        let label = match arch {
            "arch_arm_i64" => "universal",
            "arch_arm" => "arm64",
            "arch_i64" => "intel",
            other => other,
        };
        let rosetta = m.bool("rosetta_or_intel_only").unwrap_or(false);
        out.push(if rosetta {
            kv_styled(
                "Architecture",
                format!("{label} (runs under Rosetta)"),
                Color::Yellow,
            )
        } else {
            kv("Architecture", label)
        });
    }
    m.skip("is_apple_silicon_host");
    out.extend(kv_bool(m, "managed_by_cask", "Managed by Homebrew"));
    if let Some(token) = m.str("available_cask") {
        let via = m.str("catalog_matched_by").unwrap_or("catalog");
        out.push(kv_styled(
            "Cask available",
            format!("{token} (matched by {via})"),
            Color::Yellow,
        ));
    }
    out.extend(kv_str(m, "cask_homepage", "Homepage"));
    out.extend(kv_str(m, "latest_release", "Latest release"));
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "Name", Constraint::Fill(3), name)
        .primary()
        .sortable(key_title, SortDir::Asc),
    Column::new(
        ColumnId::Version,
        "Version",
        Constraint::Length(12),
        version,
    )
    .sortable(key_version, SortDir::Asc),
    Column::new(
        ColumnId::Classification,
        "Source",
        Constraint::Length(10),
        classification,
    )
    .sortable(key_classification, SortDir::Asc),
    Column::new(ColumnId::Arch, "Arch", Constraint::Length(9), arch)
        .sortable(key_arch, SortDir::Asc),
    Column::new(ColumnId::Path, "Path", Constraint::Fill(2), path_cell)
        .middle()
        .sortable(key_path, SortDir::Asc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Name, SortDir::Asc),
    detail,
};
