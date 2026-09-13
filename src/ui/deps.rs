//! The Brew dependency explorer: a real, recursive tree over the Homebrew
//! graph, grouped by origin. Forward (`what does X need`) or reverse (`why
//! is X installed`), toggled with `d`; nodes fold with `z`/enter and start
//! collapsed. A shared dependency appears under every parent that needs it
//! (marks follow the finding, so marking it once marks every occurrence);
//! a node already on its own ancestor path is shown once as a cycle marker.

use std::collections::BTreeMap;

use crate::brewgraph::{BrewGraph, Direction, Relation};
use crate::model::{Finding, FindingKind, Severity};
use crate::ui::rows::RenderRow;

/// Fixed group order: what Homebrew already flags first, then the user's
/// own choices, then what those pulled in, then the unknowns, then casks.
pub const GROUPS: &[&str] = &[
    "Autoremove candidates",
    "Explicitly installed",
    "Installed as dependency",
    "Unknown origin",
    "Casks",
];

/// The group a Brew finding roots under.
pub fn origin_group(f: &Finding) -> &'static str {
    if f.kind == FindingKind::BrewCask {
        return "Casks";
    }
    if f.meta
        .get("autoremove_candidate")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || f.meta.get("candidates").is_some()
    {
        return "Autoremove candidates";
    }
    match f.meta.get("install_reason").and_then(|v| v.as_str()) {
        Some("requested") => "Explicitly installed",
        Some("dependency") => "Installed as dependency",
        _ => "Unknown origin",
    }
}

/// Graph node id for a Brew finding (formula full_name / `cask:<token>`).
pub fn node_id(f: &Finding) -> Option<String> {
    match f.kind {
        FindingKind::BrewFormula => f
            .meta
            .get("full_name")
            .or_else(|| f.meta.get("name"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
        FindingKind::BrewCask => f
            .meta
            .get("token")
            .and_then(|v| v.as_str())
            .map(|t| format!("cask:{t}")),
        _ => None,
    }
}

pub fn direction_prefix(dir: Direction) -> &'static str {
    match dir {
        Direction::Forward => "fwd",
        Direction::Reverse => "rev",
    }
}

/// Flatten the explorer. `roots` keep the caller's order (the active sort);
/// `by_id` maps graph ids to findings so child rows carry their finding.
pub fn build_explorer_rows<'a>(
    graph: &BrewGraph,
    roots: &[&'a Finding],
    dir: Direction,
    is_group_collapsed: &dyn Fn(&str) -> bool,
    is_node_expanded: &dyn Fn(&str) -> bool,
) -> Vec<RenderRow<'a>> {
    let by_id: BTreeMap<String, &'a Finding> = roots
        .iter()
        .filter_map(|f| node_id(f).map(|id| (id, *f)))
        .collect();
    let mut groups: BTreeMap<&'static str, Vec<&'a Finding>> = BTreeMap::new();
    for f in roots {
        groups.entry(origin_group(f)).or_default().push(f);
    }
    let prefix = direction_prefix(dir);
    let mut rows = Vec::new();
    for &group in GROUPS {
        let Some(items) = groups.get(group) else {
            continue;
        };
        let reclaimable_bytes = items
            .iter()
            .filter(|f| f.severity == Severity::Reclaimable)
            .filter_map(|f| f.size_bytes)
            .sum();
        let expanded = !is_group_collapsed(group);
        rows.push(RenderRow::Group {
            key: group.to_string(),
            count: items.len(),
            reclaimable_bytes,
            expanded,
        });
        if !expanded {
            continue;
        }
        for f in items {
            let Some(id) = node_id(f) else {
                // Synthetic rows (the autoremove summary) are plain items.
                rows.push(RenderRow::Item { f, depth: 1 });
                continue;
            };
            if graph.get(&id).is_none() {
                rows.push(RenderRow::Item { f, depth: 1 });
                continue;
            }
            for w in graph.walk(&id, dir, is_node_expanded, prefix, 8) {
                let finding = w.id.as_ref().and_then(|i| by_id.get(i).copied());
                rows.push(RenderRow::Node {
                    f: finding,
                    name: w.name,
                    version: w
                        .id
                        .as_ref()
                        .and_then(|i| graph.get(i))
                        .and_then(|n| n.version.clone()),
                    depth: w.depth as u8,
                    expanded: w.has_children && is_node_expanded(&w.path_key),
                    has_children: w.has_children,
                    relation: w.relation,
                    cycle: w.cycle,
                    path_key: w.path_key,
                });
            }
        }
    }
    rows
}

/// Suffix shown after a node name.
pub fn relation_suffix(relation: Relation, cycle: bool) -> &'static str {
    if cycle {
        return "↻ cycle";
    }
    match relation {
        Relation::Root => "",
        Relation::Direct => "direct",
        Relation::Transitive => "transitive",
        Relation::Unknown => "dependency data unavailable",
        Relation::NotInstalled => "not installed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn formula(
        name: &str,
        reason: &str,
        deps: &[&str],
        dependents: &[&str],
        auto: bool,
    ) -> Finding {
        Finding::new(FindingKind::BrewFormula, name, name).meta(serde_json::json!({
            "name": name, "full_name": name, "version": "1.0", "install_reason": reason,
            "installed_on_request": match reason { "requested" => Some(true), "dependency" => Some(false), _ => None },
            "dependencies": deps, "dependents": dependents, "autoremove_candidate": auto,
        }))
    }

    #[test]
    fn groups_in_fixed_order_and_nodes_start_collapsed() {
        let wget = formula("wget", "requested", &["libidn2"], &[], false);
        let libidn2 = formula("libidn2", "dependency", &["libunistring"], &["wget"], false);
        let libunistring = formula("libunistring", "dependency", &[], &["libidn2"], false);
        let orphan = formula("libevent", "dependency", &[], &[], true);
        let odd = formula("oldlib", "unknown", &[], &[], false);
        let all = [&odd, &wget, &libunistring, &libidn2, &orphan];
        let graph = BrewGraph::from_findings(all.iter().copied());
        let none: HashSet<String> = HashSet::new();
        let rows = build_explorer_rows(&graph, &all, Direction::Forward, &|_| false, &|k| {
            none.contains(k)
        });
        let labels: Vec<String> = rows
            .iter()
            .map(|r| match r {
                RenderRow::Group { key, count, .. } => format!("G:{key}({count})"),
                RenderRow::Node { name, depth, .. } => {
                    format!("{}{name}", "  ".repeat(*depth as usize))
                }
                RenderRow::Item { f, .. } => format!("I:{}", f.title),
            })
            .collect();
        assert_eq!(
            labels,
            [
                "G:Autoremove candidates(1)",
                "  libevent",
                "G:Explicitly installed(1)",
                "  wget",
                "G:Installed as dependency(2)",
                "  libunistring",
                "  libidn2",
                "G:Unknown origin(1)",
                "  oldlib",
            ]
        );
        // Expand wget forward: libidn2 (direct) then libunistring (transitive).
        let expanded: HashSet<String> = ["fwd|wget".to_string(), "fwd|wget/libidn2".to_string()]
            .into_iter()
            .collect();
        let rows = build_explorer_rows(&graph, &all, Direction::Forward, &|_| false, &|k| {
            expanded.contains(k)
        });
        let under_wget: Vec<(String, Relation, u8)> = rows
            .iter()
            .filter_map(|r| match r {
                RenderRow::Node {
                    name,
                    relation,
                    depth,
                    ..
                } if *depth > 1 => Some((name.clone(), *relation, *depth)),
                _ => None,
            })
            .collect();
        assert_eq!(
            under_wget,
            [
                ("libidn2".into(), Relation::Direct, 2),
                ("libunistring".into(), Relation::Transitive, 3)
            ]
        );
        // Child rows carry their finding so marking/detail work on them.
        assert!(rows.iter().any(|r| matches!(r, RenderRow::Node { f: Some(f), depth: 3, .. } if f.title == "libunistring")));
        // Reverse from libunistring: libidn2 then wget.
        let rev: HashSet<String> = [
            "rev|libunistring".to_string(),
            "rev|libunistring/libidn2".to_string(),
        ]
        .into_iter()
        .collect();
        let rows = build_explorer_rows(
            &graph,
            &[&libunistring],
            Direction::Reverse,
            &|_| false,
            &|k| rev.contains(k),
        );
        let names: Vec<&str> = rows
            .iter()
            .filter_map(|r| match r {
                RenderRow::Node { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(names, ["libunistring", "libidn2", "wget"]);
    }
}
