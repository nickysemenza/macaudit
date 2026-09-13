//! Shell: `$PATH` entries (one finding each) plus the startup-time finding.
//! The entry *is* the path, so there is no separate Path column.

use ratatui::layout::Constraint;
use ratatui::style::Color;

use super::*;
use crate::model::Severity;

fn entry(f: &Finding, ctx: &CellCtx) -> CellText {
    let mut c = name_cell(f, ctx);
    if f.path.is_some() {
        c.text = fmt::abbrev_home(std::path::Path::new(&f.title));
    }
    c
}

fn status(f: &Finding, _: &CellCtx) -> CellText {
    if let Some(only) = f.meta.get("only_in_shell").and_then(|v| v.as_array()) {
        let only_proc = meta_len(f, "only_in_process");
        return if only.is_empty() && only_proc == 0 {
            dim("same")
        } else {
            colored(
                format!("differs (+{} / -{})", only.len(), only_proc),
                theme::severity_color(Severity::Attention),
            )
        };
    }
    if let Some(ms) = meta_f64(f, "median_ms") {
        return colored(format!("{ms:.0} ms"), theme::severity_color(f.severity));
    }
    let attention = theme::severity_color(Severity::Attention);
    if meta_bool(f, "exists") == Some(false) {
        return colored("missing", attention);
    }
    if meta_str(f, "shadowed_by").is_some() {
        return colored("shadowed", attention);
    }
    match meta_u64(f, "occurrences") {
        Some(n) if n > 1 => colored(format!("dup ×{n}"), attention),
        _ => dim("ok"),
    }
}

fn shadowed_by(f: &Finding, _: &CellCtx) -> CellText {
    dim(meta_str(f, "shadowed_by")
        .map(|s| fmt::abbrev_home(std::path::Path::new(s)))
        .unwrap_or_default())
}

fn key_status(f: &Finding) -> SortKey {
    // Problems first: missing, shadowed, duplicate, then fine.
    SortKey::Int(if meta_bool(f, "exists") == Some(false) {
        0
    } else if meta_str(f, "shadowed_by").is_some() {
        1
    } else if meta_u64(f, "occurrences").unwrap_or(1) > 1 {
        2
    } else {
        3
    })
}
fn key_index(f: &Finding) -> SortKey {
    key_meta_int(f, "index")
}

fn detail(f: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    if f.meta.get("only_in_shell").is_some() {
        out.extend(kv_str(m, "login_shell", "Login shell"));
        out.extend(kv_str(m, "source", "PATH read via"));
        m.skip("shell");
        out.extend(kv_u64(m, "shell_entries", "Shell PATH entries"));
        out.extend(kv_u64(m, "process_entries", "Process PATH entries"));
        out.extend(kv_list(m, "only_in_shell", "Only in login shell"));
        out.extend(kv_list(m, "only_in_process", "Only in this process"));
        out.extend(kv_list(m, "notes", "Notes"));
        return out;
    }
    if let Some(ms) = m.f64("median_ms") {
        out.extend(kv_str(m, "shell", "Shell"));
        out.push(kv("Median startup", format!("{ms:.0} ms")));
        if let Some(runs) = m.list("runs_ms") {
            let runs: Vec<String> = runs
                .iter()
                .map(|r| format!("{:.0}", r.parse::<f64>().unwrap_or(0.0)))
                .collect();
            out.push(kv("Runs (ms)", runs.join(", ")));
        }
        return out;
    }
    m.skip("entry");
    out.extend(kv_str(m, "shell", "Login shell"));
    out.extend(kv_u64(m, "index", "Position in $PATH"));
    if let Some(in_proc) = m.bool("in_process_path") {
        out.push(if in_proc {
            kv("In process PATH", "yes")
        } else {
            kv_styled(
                "In process PATH",
                "no — this process cannot see it",
                Color::Yellow,
            )
        });
    }
    m.skip("from_login_shell");
    if let Some(exists) = m.bool("exists") {
        out.push(if exists {
            kv("Exists", "yes")
        } else {
            kv_styled("Exists", "no — directory is missing", Color::Yellow)
        });
    }
    if let Some(n) = m.u64("occurrences") {
        out.push(if n > 1 {
            kv_styled("Occurrences", format!("{n} (duplicate)"), Color::Yellow)
        } else {
            kv("Occurrences", "1")
        });
    }
    if let Some(by) = m.str("shadowed_by") {
        out.push(kv_styled("Shadowed by", by, Color::Yellow));
    }
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "Entry", Constraint::Fill(2), entry)
        .primary()
        .middle()
        .sortable(key_index, SortDir::Asc),
    Column::new(ColumnId::Status, "Status", Constraint::Length(10), status)
        .sortable(key_status, SortDir::Asc),
    Column::new(
        ColumnId::ShadowedBy,
        "Shadowed by",
        Constraint::Fill(1),
        shadowed_by,
    )
    .middle(),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Status, SortDir::Asc),
    detail,
};
