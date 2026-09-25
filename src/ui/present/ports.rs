//! Ports: listening sockets. The port is what you scan for, so it leads.

use ratatui::layout::Constraint;

use super::*;

fn port(f: &Finding, _: &CellCtx) -> CellText {
    plain(
        meta_u64(f, "port")
            .map(|p| p.to_string())
            .unwrap_or_default(),
    )
}

fn pid(f: &Finding, _: &CellCtx) -> CellText {
    dim(meta_u64(f, "pid")
        .map(|p| p.to_string())
        .unwrap_or_default())
}

fn command(f: &Finding, ctx: &CellCtx) -> CellText {
    let mut c = name_cell(f, ctx);
    if let Some(cmd) = meta_str(f, "command") {
        c.text = cmd.to_string();
    }
    c
}

fn user(f: &Finding, _: &CellCtx) -> CellText {
    dim(meta_str(f, "user").unwrap_or(""))
}

fn host(f: &Finding, _: &CellCtx) -> CellText {
    dim(meta_str(f, "host").unwrap_or(""))
}

fn key_port(f: &Finding) -> SortKey {
    key_meta_int(f, "port")
}
fn key_pid(f: &Finding) -> SortKey {
    key_meta_int(f, "pid")
}
fn key_command(f: &Finding) -> SortKey {
    key_meta_text(f, "command")
}
fn key_user(f: &Finding) -> SortKey {
    key_meta_text(f, "user")
}

fn detail(_: &Finding, m: &mut MetaView<'_>, _ctx: &DetailCtx) -> Vec<Field> {
    let mut out = Vec::new();
    out.extend(kv_u64(m, "port", "Port"));
    out.extend(kv_str(m, "host", "Bound to"));
    out.extend(kv_u64(m, "pid", "PID"));
    out.extend(kv_str(m, "command", "Command"));
    out.extend(kv_str(m, "user", "User"));
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Port, "Port", Constraint::Length(6), port)
        .right()
        .sortable(key_port, SortDir::Asc),
    Column::new(ColumnId::Pid, "PID", Constraint::Length(7), pid)
        .right()
        .sortable(key_pid, SortDir::Asc),
    Column::new(ColumnId::Command, "Command", Constraint::Fill(1), command)
        .primary()
        .sortable(key_command, SortDir::Asc),
    Column::new(ColumnId::User, "User", Constraint::Length(10), user)
        .sortable(key_user, SortDir::Asc),
    Column::new(ColumnId::Host, "Host", Constraint::Length(12), host),
    Column::new(ColumnId::Path, "Binary", Constraint::Fill(2), path_cell).middle(),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Port, SortDir::Asc),
    detail,
};
