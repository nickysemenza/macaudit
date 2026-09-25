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

fn list_of(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .map(|x| match x.as_str() {
                    Some(s) => s.to_string(),
                    None => x.to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn owner_label(owner: &serde_json::Value) -> String {
    match owner.get("kind").and_then(|k| k.as_str()) {
        Some("this_install") => "this installation".into(),
        Some("other_tool") => format!(
            "{} ({})",
            owner
                .get("manager")
                .and_then(|m| m.as_str())
                .unwrap_or("other tool"),
            owner
                .get("identity_key")
                .and_then(|m| m.as_str())
                .unwrap_or("?")
        ),
        Some("homebrew_cask") => format!(
            "Homebrew cask {}",
            owner.get("token").and_then(|t| t.as_str()).unwrap_or("?")
        ),
        Some("homebrew_formula") => format!(
            "Homebrew formula {}",
            owner.get("name").and_then(|t| t.as_str()).unwrap_or("?")
        ),
        Some("rustup_proxy") => "rustup proxy".into(),
        Some("pnpm_home") => "pnpm home shim".into(),
        _ => "unknown owner".into(),
    }
}

fn abbrev(s: &str) -> String {
    fmt::abbrev_home(std::path::Path::new(s))
}

fn tool_detail(f: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    let meta = &f.meta;
    // Classification + why.
    let classes = meta
        .get("classifications")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    for c in &classes {
        let kind = c.get("kind").and_then(|k| k.as_str()).unwrap_or("review");
        let why = match kind {
            "broken" => c
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("")
                .to_string(),
            "duplicate" => format!("also provided by {}", list_of(c, "peers").join(", ")),
            "shadowed" => format!(
                "{} wins in the login shell ({})",
                c.get("by")
                    .and_then(|b| b.as_str())
                    .map(abbrev)
                    .unwrap_or_default(),
                c.get("owner").map(owner_label).unwrap_or_default()
            ),
            "project_alternative" => format!(
                "installed locally in {}",
                list_of(c, "projects")
                    .iter()
                    .map(|p| abbrev(p))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "required" => format!("required by {}", list_of(c, "by").join(", ")),
            "orphan" => c
                .get("confirmed_by")
                .and_then(|r| r.as_str())
                .unwrap_or("")
                .to_string(),
            _ => c
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("")
                .to_string(),
        };
        out.push(kv_styled(kind.replace('_', "-"), why, class_color(kind)));
    }
    m.skip("classifications");
    m.skip("primary_classification");
    out.push(Field::Blank);
    out.push(Field::Header("Installation"));
    out.extend(kv_str(m, "manager", "Manager"));
    out.extend(kv_str(m, "layout", "Layout"));
    out.push(match m.str("version") {
        Some(v) => kv("Version", v),
        None => kv_styled("Version", "unknown", Color::DarkGray),
    });
    out.extend(kv_str(m, "root", "Root"));
    out.extend(kv_str(m, "root_realpath", "Real path"));
    out.extend(kv_str(m, "install_dir", "Install dir"));
    out.extend(kv_str(m, "identity_key", "Identity"));
    if let Some(p) = m.str("protected") {
        out.push(kv_styled("Protected", p, Color::Yellow));
    }
    if let Some(rt) = meta.get("runtime").filter(|r| !r.is_null()) {
        let path = rt
            .get("path")
            .and_then(|p| p.as_str())
            .map(abbrev)
            .unwrap_or_else(|| "unknown".into());
        let exists = match rt.get("exists").and_then(|e| e.as_bool()) {
            Some(true) => "exists",
            Some(false) => "MISSING",
            None => "unchecked",
        };
        let owner = rt
            .get("owner")
            .and_then(|o| o.as_str())
            .map(|o| {
                let present = rt.get("owner_present").and_then(|p| p.as_bool());
                format!(
                    " · owned by {o}{}",
                    match present {
                        Some(false) => " (not installed)",
                        _ => "",
                    }
                )
            })
            .unwrap_or_default();
        let label = format!(
            "{} {}",
            rt.get("kind").and_then(|k| k.as_str()).unwrap_or("runtime"),
            rt.get("version").and_then(|v| v.as_str()).unwrap_or("")
        );
        out.push(kv_styled(
            "Interpreter",
            format!("{} — {path} ({exists}){owner}", label.trim()),
            if exists == "MISSING" {
                Color::Red
            } else {
                Color::Reset
            },
        ));
        m.skip("runtime");
    }
    // Commands + resolution.
    let commands = meta
        .get("commands")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    let resolution = meta
        .get("resolution")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if !commands.is_empty() {
        out.push(Field::Blank);
        out.push(Field::Header("Commands (login shell vs this process)"));
        for c in &commands {
            let name = c.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let r = resolution.get(name);
            let status = r
                .and_then(|r| r.get("status"))
                .and_then(|s| s.as_str())
                .unwrap_or("unknown");
            let shell = r
                .and_then(|r| r.get("user_shell"))
                .and_then(|s| s.as_str())
                .map(abbrev)
                .unwrap_or_else(|| "—".into());
            let proc = r
                .and_then(|r| r.get("process"))
                .and_then(|s| s.as_str())
                .map(abbrev)
                .unwrap_or_else(|| "—".into());
            let color = match status {
                "active" | "active_in_process_only" => Color::Green,
                "shadowed" => Color::Yellow,
                "not_on_path" => Color::DarkGray,
                _ => Color::Reset,
            };
            out.push(kv_styled(
                name.to_string(),
                format!("{status} · shell: {shell} · process: {proc}"),
                color,
            ));
            if let Some(by) = r
                .and_then(|r| r.get("shadowed_by"))
                .and_then(|s| s.as_str())
            {
                out.push(kv("  shadowed by", abbrev(by)));
            }
        }
    }
    m.skip("commands");
    m.skip("resolution");
    // Launchers.
    let launchers = meta
        .get("launchers")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    let foreign = meta
        .get("foreign_launchers")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    if !launchers.is_empty() || !foreign.is_empty() {
        out.push(Field::Blank);
        out.push(Field::Header("Launchers"));
        for l in &launchers {
            let path = l
                .get("path")
                .and_then(|p| p.as_str())
                .map(abbrev)
                .unwrap_or_default();
            let target = l.get("target").and_then(|p| p.as_str()).map(abbrev);
            let exists = l.get("target_exists").and_then(|e| e.as_bool());
            let text = match (target, exists) {
                (Some(t), Some(false)) => format!("{path} → {t} (MISSING)"),
                (Some(t), _) => format!("{path} → {t}"),
                (None, _) => path,
            };
            out.push(kv_styled(
                l.get("kind")
                    .and_then(|k| k.as_str())
                    .unwrap_or("launcher")
                    .replace('_', " "),
                text,
                if exists == Some(false) {
                    Color::Red
                } else {
                    Color::Reset
                },
            ));
        }
        for l in &foreign {
            out.push(kv_styled(
                "preserved",
                format!(
                    "{} — {}",
                    l.get("path")
                        .and_then(|p| p.as_str())
                        .map(abbrev)
                        .unwrap_or_default(),
                    l.get("owner").map(owner_label).unwrap_or_default()
                ),
                Color::Cyan,
            ));
        }
    }
    m.skip("launchers");
    m.skip("foreign_launchers");
    // Project evidence.
    let refs = meta
        .get("project_refs")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    if !refs.is_empty() {
        out.push(Field::Blank);
        out.push(Field::Header("Project evidence"));
        for r in refs.iter().take(12) {
            let project = r
                .get("project")
                .and_then(|p| p.as_str())
                .map(abbrev)
                .unwrap_or_default();
            let kind = r
                .get("kind")
                .and_then(|k| k.as_str())
                .unwrap_or("")
                .replace('_', " ");
            let declared = r
                .get("declared_version")
                .and_then(|v| v.as_str())
                .map(|v| format!(" {v}"))
                .unwrap_or_default();
            let local = r.get("local_binary");
            let installed = local
                .and_then(|l| l.get("exists"))
                .and_then(|e| e.as_bool())
                .unwrap_or(false);
            let lv = local
                .and_then(|l| l.get("version"))
                .and_then(|v| v.as_str())
                .map(|v| format!(" {v}"))
                .unwrap_or_default();
            let sat = match r
                .get("global_satisfies_declaration")
                .and_then(|s| s.as_bool())
            {
                Some(true) => " · global satisfies it",
                Some(false) => " · global does NOT satisfy it",
                None => "",
            };
            let value = if installed {
                format!("{kind}{declared} — local copy installed{lv}{sat}")
            } else {
                format!("{kind}{declared} — declared only{sat}")
            };
            out.push(kv_styled(
                project,
                value,
                if installed { Color::Cyan } else { Color::Reset },
            ));
        }
        if refs.len() > 12 {
            out.push(Field::Text(format!("  … {} more", refs.len() - 12)));
        }
    }
    m.skip("project_refs");
    if let Some(cov) = meta.get("project_coverage").filter(|c| !c.is_null()) {
        out.push(kv(
            "Project coverage",
            format!(
                "{} project(s) under {}{}",
                cov.get("scanned").and_then(|s| s.as_u64()).unwrap_or(0),
                list_of(cov, "roots")
                    .iter()
                    .map(|r| abbrev(r))
                    .collect::<Vec<_>>()
                    .join(", "),
                if cov
                    .get("truncated")
                    .and_then(|t| t.as_bool())
                    .unwrap_or(false)
                {
                    " (truncated)"
                } else {
                    ""
                }
            ),
        ));
    }
    m.skip("project_coverage");
    if let Some(h) = meta.get("history").filter(|h| h.is_object()) {
        let parts: Vec<String> = h
            .as_object()
            .map(|o| {
                o.iter()
                    .map(|(k, v)| {
                        format!(
                            "{k}: {}×",
                            v.get("count").and_then(|c| c.as_u64()).unwrap_or(0)
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.push(kv(
            "Shell history",
            if parts.is_empty() {
                "no invocations recorded".into()
            } else {
                parts.join(", ")
            },
        ));
    }
    m.skip("history");
    // Evidence + removal.
    let evidence = meta
        .get("evidence")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    if !evidence.is_empty() {
        out.push(Field::Blank);
        out.push(Field::Header("Evidence"));
        for e in &evidence {
            out.push(kv(
                e.get("kind")
                    .and_then(|k| k.as_str())
                    .unwrap_or("")
                    .replace('_', " "),
                format!(
                    "{} ({}; {})",
                    e.get("summary").and_then(|s| s.as_str()).unwrap_or(""),
                    e.get("source")
                        .and_then(|s| s.as_str())
                        .map(abbrev)
                        .unwrap_or_default(),
                    e.get("confidence").and_then(|c| c.as_str()).unwrap_or("?")
                ),
            ));
        }
    }
    m.skip("evidence");
    if let Some(removal) = meta.get("removal") {
        let refusals = list_of(removal, "refusals");
        let follow = list_of(removal, "follow_up");
        if !refusals.is_empty() || !follow.is_empty() {
            out.push(Field::Blank);
            out.push(Field::Header("Removal notes"));
            for r in refusals {
                out.push(kv_styled("not offered", r, Color::Yellow));
            }
            for f in follow {
                out.push(kv("follow-up", f));
            }
        }
    }
    m.skip("removal");
    if let Some(c) = meta.get("completeness") {
        if c.get("level").and_then(|l| l.as_str()) != Some("full") {
            out.push(kv_styled(
                "Partial metadata",
                list_of(c, "missing").join("; "),
                Color::Yellow,
            ));
        }
    }
    m.skip("completeness");
    m.skip("name");
    m.skip("group");
    m.skip("size_bytes");
    m.skip("brew_cask_peer");
    out
}

fn command_detail(f: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    let shell = f
        .meta
        .get("user_shell")
        .and_then(|s| s.get("shell"))
        .and_then(|s| s.as_str())
        .unwrap_or("login shell")
        .to_string();
    out.push(match m.str("user_resolution") {
        Some(p) => kv(format!("In {shell}"), abbrev(p)),
        None => kv_styled(format!("In {shell}"), "not resolvable", Color::Yellow),
    });
    out.push(match m.str("process_resolution") {
        Some(p) => kv("In this process", abbrev(p)),
        None => kv_styled("In this process", "not resolvable", Color::Yellow),
    });
    out.push(match m.bool("differs") {
        Some(true) => kv_styled(
            "Differs",
            "yes — the shell and this process run different files",
            Color::Yellow,
        ),
        Some(false) => kv("Differs", "no"),
        None => kv("Differs", "unknown (login-shell PATH unavailable)"),
    });
    m.skip("user_shell");
    m.skip("command");
    if let Some(c) = f.meta.get("candidates").and_then(|c| c.as_array()) {
        out.push(Field::Blank);
        out.push(Field::Header("Candidates on PATH (in order)"));
        for cand in c {
            let path = cand
                .get("path")
                .and_then(|p| p.as_str())
                .map(abbrev)
                .unwrap_or_default();
            let target = cand
                .get("target")
                .and_then(|p| p.as_str())
                .map(|t| format!(" → {}", abbrev(t)))
                .unwrap_or_default();
            out.push(kv(
                path,
                format!(
                    "{}{target}",
                    cand.get("owner").map(owner_label).unwrap_or_default()
                ),
            ));
        }
    }
    m.skip("candidates");
    m.skip("group");
    out
}

fn coverage_detail(f: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    if let Some(managers) = f.meta.get("managers").and_then(|x| x.as_object()) {
        out.push(Field::Header("Managers"));
        for (name, st) in managers {
            let status = st.get("status").and_then(|s| s.as_str()).unwrap_or("?");
            let detail = st
                .get("detail")
                .and_then(|d| d.as_str())
                .map(|d| format!(" — {d}"))
                .unwrap_or_default();
            let missing = list_of(st, "missing");
            let extra = if missing.is_empty() {
                String::new()
            } else {
                format!(" — {}", missing.join("; "))
            };
            out.push(kv_styled(
                name.clone(),
                format!("{status}{detail}{extra}"),
                match status {
                    "ok" => Color::Green,
                    "absent" => Color::DarkGray,
                    _ => Color::Yellow,
                },
            ));
        }
    }
    m.skip("managers");
    if let Some(shell) = f.meta.get("shell") {
        out.push(Field::Blank);
        out.push(Field::Header("Shell"));
        out.push(kv(
            "Login shell",
            shell
                .get("login_shell")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown"),
        ));
        out.push(kv(
            "PATH read via",
            shell
                .get("source")
                .and_then(|s| s.as_str())
                .unwrap_or("process PATH"),
        ));
        for n in list_of(shell, "notes") {
            out.push(kv_styled("note", n, Color::Yellow));
        }
        if let Some(d) = shell.get("disclosure").and_then(|s| s.as_str()) {
            out.push(Field::Text(d.to_string()));
        }
    }
    m.skip("shell");
    if let Some(p) = f.meta.get("projects").filter(|p| !p.is_null()) {
        out.push(Field::Blank);
        out.push(Field::Header("Projects"));
        out.push(kv(
            "Roots",
            list_of(p, "roots")
                .iter()
                .map(|r| abbrev(r))
                .collect::<Vec<_>>()
                .join(", "),
        ));
        out.push(kv(
            "Scanned",
            format!(
                "{}{}",
                p.get("scanned").and_then(|s| s.as_u64()).unwrap_or(0),
                if p.get("truncated")
                    .and_then(|t| t.as_bool())
                    .unwrap_or(false)
                {
                    " (truncated by depth/time budget)"
                } else {
                    ""
                }
            ),
        ));
    }
    m.skip("projects");
    if let Some(h) = f.meta.get("history") {
        out.push(kv(
            "Shell history evidence",
            if h.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false) {
                "enabled (aggregated counts only)"
            } else {
                "disabled ([tools] shell_history_evidence)"
            },
        ));
    }
    m.skip("history");
    m.skip("group");
    out
}

fn detail(f: &Finding, m: &mut MetaView<'_>, _ctx: &DetailCtx) -> Vec<Field> {
    match f.kind {
        FindingKind::GlobalTool => tool_detail(f, m),
        FindingKind::CommandResolution => command_detail(f, m),
        FindingKind::ToolCoverage => coverage_detail(f, m),
        _ => Vec::new(),
    }
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
