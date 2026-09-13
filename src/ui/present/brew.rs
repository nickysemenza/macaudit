//! Brew: formulae and casks (tree grouped by kind). Status shows what the
//! user can act on — `outdated` — else whether a formula is a leaf.

use ratatui::layout::Constraint;
use ratatui::style::Color;

use super::*;
use crate::model::{FindingKind, Severity};

fn version(f: &Finding, _: &CellCtx) -> CellText {
    dim(meta_str(f, "version").unwrap_or(""))
}

fn status(f: &Finding, _: &CellCtx) -> CellText {
    if meta_bool(f, "outdated").unwrap_or(false) {
        let latest = meta_str(f, "current_version").unwrap_or("");
        return colored(
            format!("outdated → {latest}"),
            theme::severity_color(Severity::Attention),
        );
    }
    match f.kind {
        FindingKind::BrewCask => dim("cask"),
        _ if f.meta.get("candidates").is_some() => dim("summary"),
        _ if meta_bool(f, "autoremove_candidate").unwrap_or(false) => {
            colored("autoremove", theme::severity_color(Severity::Reclaimable))
        }
        _ => {
            // Origin from Homebrew's own flag; a leaf is only a suffix, never
            // an origin claim.
            let leaf = meta_bool(f, "is_leaf").unwrap_or(false);
            match meta_str(f, "install_reason") {
                Some("requested") => plain(if leaf {
                    "requested · leaf"
                } else {
                    "requested"
                }),
                Some("dependency") => dim(if leaf {
                    "dependency · leaf"
                } else {
                    "dependency"
                }),
                Some(_) | None => colored(
                    if leaf { "origin? · leaf" } else { "origin?" },
                    theme::severity_color(Severity::Attention),
                ),
            }
        }
    }
}

fn deps(f: &Finding, _: &CellCtx) -> CellText {
    let n = meta_len(f, "dependents");
    if n == 0 {
        plain("")
    } else {
        dim(format!("{n}"))
    }
}

fn key_status(f: &Finding) -> SortKey {
    // Outdated first, then leaves, then dependencies.
    SortKey::Int(match (meta_bool(f, "outdated"), meta_bool(f, "is_leaf")) {
        (Some(true), _) => 0,
        (_, Some(true)) => 1,
        _ => 2,
    })
}
fn key_deps(f: &Finding) -> SortKey {
    SortKey::Int(meta_len(f, "dependents") as i64)
}

fn detail(f: &Finding, m: &mut MetaView<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    m.skip("name");
    m.skip("token");
    out.extend(kv_str(m, "version", "Installed"));
    if m.bool("outdated").unwrap_or(false) {
        if let Some(latest) = m.str("current_version") {
            out.push(kv_styled("Latest", latest, Color::Yellow));
        }
    } else {
        m.skip("current_version");
    }
    if let Some(reason) = m.str("install_reason") {
        out.push(match reason {
            "requested" => kv("Origin", "explicitly installed (installed_on_request)"),
            "dependency" => kv("Origin", "installed as a dependency"),
            _ => kv_styled(
                "Origin",
                "unknown — Homebrew reported no flag",
                Color::Yellow,
            ),
        });
    }
    m.skip("installed_on_request");
    m.skip("installed_as_dependency");
    out.extend(kv_bool(m, "is_leaf", "Leaf (nothing depends on it)"));
    if let Some(auto) = m.bool("autoremove_candidate") {
        out.push(if auto {
            kv_styled(
                "Autoremove",
                "yes — brew autoremove --dry-run lists it",
                Color::Cyan,
            )
        } else {
            kv("Autoremove", "no")
        });
    } else if f.meta.get("autoremove_candidate").is_some() {
        out.push(kv_styled(
            "Autoremove",
            "unknown (dry-run failed)",
            Color::Yellow,
        ));
        m.skip("autoremove_candidate");
    }
    out.extend(kv_str(m, "dependency_source", "Dependency data"));
    out.extend(kv_list(m, "dependencies", "Needs"));
    out.extend(kv_list(m, "dependencies_transitive", "Needs (transitive)"));
    out.extend(kv_list(m, "dependents", "Needed by"));
    out.extend(kv_list(
        m,
        "dependents_transitive",
        "Needed by (transitive)",
    ));
    out.extend(kv_list(m, "cask_dependents", "Needed by casks"));
    if let Some(why) = f.meta.get("why_installed") {
        let roots: Vec<String> = why
            .get("requested_roots")
            .and_then(|r| r.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if !roots.is_empty() {
            out.push(kv("Kept because of", roots.join(", ")));
        }
        if let Some(paths) = why.get("paths").and_then(|p| p.as_array()) {
            for p in paths.iter().take(3) {
                let chain: Vec<String> = p
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                if chain.len() > 1 {
                    out.push(kv("  chain", chain.join(" ← ")));
                }
            }
        }
        m.skip("why_installed");
    }
    if let Some(p) = f.meta.get("removal_preview") {
        out.push(Field::Header("If removed"));
        let list = |k: &str| -> Vec<String> {
            p.get(k)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        let blocked = list("blocked_by");
        if blocked.is_empty() {
            out.push(kv("Removable", "yes — nothing installed still needs it"));
        } else {
            out.push(kv_styled("Blocked by", blocked.join(", "), Color::Red));
        }
        let orphans = list("would_orphan");
        if !orphans.is_empty() {
            out.push(kv("Would orphan", orphans.join(", ")));
        }
        let confirmed = list("confirmed_orphans");
        if !confirmed.is_empty() {
            out.push(kv_styled(
                "brew-confirmed",
                confirmed.join(", "),
                Color::Cyan,
            ));
        }
        let uncertain = list("uncertain_orphans");
        if !uncertain.is_empty() {
            out.push(kv_styled(
                "Origin unknown",
                uncertain.join(", "),
                Color::Yellow,
            ));
        }
        m.skip("removal_preview");
    }
    out.extend(kv_list(m, "graph_caveats", "Graph caveats"));
    out.extend(kv_list(m, "binaries", "Binaries"));
    out.extend(kv_list(m, "app_paths", "Installs"));
    out.extend(kv_list(m, "tool_peers", "Same command as tools"));
    m.skip("group");
    m.skip("completeness");
    m.skip("full_name");
    m.skip("tap");
    m.skip("aliases");
    m.skip("pinned");
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "Name", Constraint::Fill(2), name_cell)
        .primary()
        .sortable(key_title, SortDir::Asc),
    Column::new(
        ColumnId::Version,
        "Version",
        Constraint::Length(14),
        version,
    ),
    Column::new(ColumnId::Status, "Status", Constraint::Length(22), status)
        .sortable(key_status, SortDir::Asc),
    Column::new(ColumnId::Deps, "Used by", Constraint::Length(7), deps)
        .right()
        .sortable(key_deps, SortDir::Desc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Name, SortDir::Asc),
    detail,
};
