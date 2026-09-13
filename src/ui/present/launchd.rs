//! Daemons: launchd agents/daemons. The plist path is the finding path; what
//! the user wants to see is where it came from (domain), whether it's
//! running, and what binary it points at.

use ratatui::layout::Constraint;
use ratatui::style::Color;

use super::*;

fn domain(f: &Finding, _: &CellCtx) -> CellText {
    plain(match meta_str(f, "domain") {
        Some("user_agent") => "user",
        Some("library_agent") => "library",
        Some("library_daemon") => "daemon",
        Some(other) => other,
        None => "",
    })
}

fn running(f: &Finding, _: &CellCtx) -> CellText {
    if meta_bool(f, "disabled").unwrap_or(false) {
        return dim("disabled");
    }
    match meta_bool(f, "running") {
        Some(true) => colored("running", Color::Green),
        Some(false) => dim("stopped"),
        None => plain(""),
    }
}

fn program(f: &Finding, _: &CellCtx) -> CellText {
    let p = meta_str(f, "program")
        .or_else(|| {
            f.meta
                .get("program_arguments")
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
        })
        .unwrap_or("");
    dim(fmt::abbrev_home(std::path::Path::new(p)))
}

fn key_domain(f: &Finding) -> SortKey {
    key_meta_text(f, "domain")
}
fn key_running(f: &Finding) -> SortKey {
    SortKey::Bool(meta_bool(f, "running").unwrap_or(false))
}
fn key_program(f: &Finding) -> SortKey {
    key_meta_text(f, "program")
}

fn detail(_: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    m.skip("label");
    out.push(kv(
        "Domain",
        match m.str("domain") {
            Some("user_agent") => "user agent (~/Library/LaunchAgents)",
            Some("library_agent") => "library agent (/Library/LaunchAgents)",
            Some("library_daemon") => "daemon (/Library/LaunchDaemons)",
            Some(other) => other,
            None => "—",
        },
    ));
    out.extend(kv_str(m, "program", "Program"));
    out.extend(kv_list(m, "program_arguments", "Arguments"));
    out.extend(kv_bool(m, "running", "Running"));
    out.extend(kv_bool(m, "run_at_load", "Run at load"));
    out.extend(kv_bool(m, "disabled", "Disabled"));
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "Label", Constraint::Fill(2), name_cell)
        .primary()
        .sortable(key_title, SortDir::Asc),
    Column::new(ColumnId::Domain, "Domain", Constraint::Length(8), domain)
        .sortable(key_domain, SortDir::Asc),
    Column::new(ColumnId::Running, "State", Constraint::Length(9), running)
        .sortable(key_running, SortDir::Desc),
    Column::new(ColumnId::Program, "Program", Constraint::Fill(3), program)
        .middle()
        .sortable(key_program, SortDir::Asc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Running, SortDir::Desc),
    detail,
};
