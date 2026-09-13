//! Global Tools: one row per manager-owned installation (npm/pnpm/cargo/pipx/
//! uv/pip/bun), plus command-resolution rows and the scan coverage row.
//!
//! Meta contract (mirrored by `fake::tools_fixtures`): `manager`, `name`,
//! `version` (null when unknown), `identity_key`, `root`, `commands[]`,
//! `launchers[]`, `resolution{cmd → {user_shell, process, status}}`,
//! `classifications[]`, `primary_classification`, `completeness`, `removal`.

use ratatui::layout::Constraint;
use ratatui::style::Color;

use super::*;
use crate::model::FindingKind;

fn version(f: &Finding, _: &CellCtx) -> CellText {
    match f.kind {
        FindingKind::GlobalTool => match meta_str(f, "version") {
            Some(v) => plain(v),
            None => dim("unknown"),
        },
        _ => plain(""),
    }
}

fn manager(f: &Finding, _: &CellCtx) -> CellText {
    match f.kind {
        FindingKind::CommandResolution => dim("shell"),
        FindingKind::ToolCoverage => dim("scan"),
        _ => dim(meta_str(f, "manager").unwrap_or("")),
    }
}

/// Colour for a classification tag. Broken is red; anything that may lead to
/// a removal is yellow/cyan; "required"/"review" stay quiet.
pub(crate) fn class_color(class: &str) -> Color {
    match class {
        "broken" => Color::Red,
        "duplicate" | "shadowed" => Color::Yellow,
        "project_alternative" | "orphan" => Color::Cyan,
        "review" => Color::Magenta,
        _ => Color::DarkGray,
    }
}

fn class(f: &Finding, _: &CellCtx) -> CellText {
    match f.kind {
        FindingKind::CommandResolution => {
            if meta_bool(f, "differs").unwrap_or(false) {
                colored("differs", Color::Yellow)
            } else if meta_str(f, "user_resolution").is_none() {
                colored("not in shell", Color::Red)
            } else {
                dim("same")
            }
        }
        FindingKind::ToolCoverage => dim(""),
        _ => {
            let c = meta_str(f, "primary_classification").unwrap_or("review");
            let mut text = c.replace('_', "-");
            if let Some(level) = f
                .meta
                .get("completeness")
                .and_then(|c| c.get("level"))
                .and_then(|l| l.as_str())
            {
                if level != "full" {
                    text.push_str(" (partial)");
                }
            }
            colored(text, class_color(c))
        }
    }
}

fn commands(f: &Finding, _: &CellCtx) -> CellText {
    match f.kind {
        FindingKind::GlobalTool => {
            let names: Vec<String> = f
                .meta
                .get("commands")
                .and_then(|c| c.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
                        .map(|n| {
                            let status = f
                                .meta
                                .get("resolution")
                                .and_then(|r| r.get(n))
                                .and_then(|r| r.get("status"))
                                .and_then(|s| s.as_str())
                                .unwrap_or("unknown");
                            match status {
                                "active_in_shell" | "active" => n.to_string(),
                                "shadowed" => format!("{n}↯"),
                                "not_on_path" => format!("{n}∅"),
                                "active_in_process_only" => format!("{n}·"),
                                _ => format!("{n}?"),
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            dim(names.join(" "))
        }
        FindingKind::CommandResolution => dim(meta_str(f, "user_resolution")
            .map(|p| fmt::abbrev_home(std::path::Path::new(p)))
            .unwrap_or_else(|| "—".to_string())),
        _ => dim(""),
    }
}

fn key_class(f: &Finding) -> SortKey {
    let rank = match meta_str(f, "primary_classification") {
        Some("broken") => 0,
        Some("orphan") => 1,
        Some("duplicate") => 2,
        Some("shadowed") => 3,
        Some("project_alternative") => 4,
        Some("review") => 5,
        Some("required") => 6,
        _ => 7,
    };
    SortKey::Int(rank)
}
fn key_manager(f: &Finding) -> SortKey {
    key_meta_text(f, "manager")
}

fn detail(f: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    match f.kind {
        FindingKind::GlobalTool => {
            out.extend(kv_str(m, "manager", "Manager"));
            if let Some(layout) = m.str("layout") {
                out.push(kv("Layout", layout));
            }
            out.push(match m.str("version") {
                Some(v) => kv("Version", v),
                None => kv_styled("Version", "unknown", Color::DarkGray),
            });
            out.extend(kv_str(m, "root", "Install root"));
            out.extend(kv_str(m, "identity_key", "Identity"));
            out.extend(kv_str(m, "primary_classification", "Classification"));
            m.skip("name");
        }
        FindingKind::CommandResolution => {
            out.extend(kv_str(m, "command", "Command"));
            out.extend(kv_str(m, "user_resolution", "In login shell"));
            out.extend(kv_str(m, "process_resolution", "In this process"));
            out.extend(kv_bool(m, "differs", "Differs"));
        }
        _ => {}
    }
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "Name", Constraint::Fill(2), name_cell)
        .primary()
        .sortable(key_title, SortDir::Asc),
    Column::new(
        ColumnId::Version,
        "Version",
        Constraint::Length(12),
        version,
    ),
    Column::new(ColumnId::Manager, "Manager", Constraint::Length(8), manager)
        .sortable(key_manager, SortDir::Asc),
    Column::new(
        ColumnId::Classification,
        "Class",
        Constraint::Length(20),
        class,
    )
    .sortable(key_class, SortDir::Asc),
    Column::new(ColumnId::Command, "Commands", Constraint::Fill(1), commands).middle(),
    Column::new(ColumnId::Size, "Size", Constraint::Length(10), size_cell)
        .right()
        .sortable(key_size, SortDir::Desc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Classification, SortDir::Asc),
    detail,
};
