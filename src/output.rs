//! Machine-readable output for headless commands.

use std::collections::BTreeMap;

use crate::brewgraph::{BrewGraph, Direction};
use crate::cleanup::{self, PreflightReport};
use crate::config::DeleteMode;
use crate::model::{Finding, FindingId, FindingKind, Remedy};
use crate::remedy::RemedyEngine;

/// Serialize findings as a JSON array (`Vec<Finding>`), sorted by id for stable
/// output. This is the contract behind `macaudit scan --json` (spec §5).
pub fn findings_to_json(findings: &BTreeMap<FindingId, Finding>) -> anyhow::Result<String> {
    let list: Vec<&Finding> = findings.values().collect();
    Ok(serde_json::to_string_pretty(&list)?)
}

/// Which findings a dry run lists. Without `--select`, Brew and Tools rows
/// appear only when evidence suggests removal (broken/duplicate/shadowed/
/// orphan, autoremove candidates) — listing `brew uninstall` for every
/// formula would be noise, not a preview. Other sections keep the old rule:
/// every destructive remedy.
pub fn dry_run_selection<'a>(
    findings: &'a BTreeMap<FindingId, Finding>,
    select: &[String],
) -> Vec<&'a Finding> {
    let suggested = |f: &Finding| -> bool {
        match f.kind {
            FindingKind::BrewFormula | FindingKind::BrewCask => {
                f.meta.get("autoremove_candidate").and_then(|v| v.as_bool()) == Some(true)
                    || f.meta.get("candidates").is_some()
            }
            FindingKind::GlobalTool => matches!(
                f.meta
                    .get("primary_classification")
                    .and_then(|v| v.as_str()),
                Some("broken") | Some("duplicate") | Some("shadowed") | Some("orphan")
            ),
            FindingKind::CommandResolution | FindingKind::ToolCoverage => false,
            _ => true,
        }
    };
    let selected = |f: &Finding| -> bool {
        select.iter().any(|s| {
            s == &f.title
                || f.meta.get("identity_key").and_then(|v| v.as_str()) == Some(s.as_str())
                || f.meta.get("full_name").and_then(|v| v.as_str()) == Some(s.as_str())
                || f.meta.get("token").and_then(|v| v.as_str()) == Some(s.as_str())
        })
    };
    findings
        .values()
        .filter(|f| {
            if select.is_empty() {
                suggested(f)
            } else {
                selected(f)
            }
        })
        .collect()
}

/// Plan the primary destructive remedies of `selected` and preflight them.
pub fn dry_run_plan(
    findings: &BTreeMap<FindingId, Finding>,
    selected: &[&Finding],
    delete_mode: DeleteMode,
) -> PreflightReport {
    let engine = RemedyEngine::new(delete_mode);
    let items: Vec<(FindingId, Remedy)> = selected
        .iter()
        .flat_map(|f| {
            f.remedies
                .iter()
                .filter(|r| r.destructive && !r.alternative)
                .map(|r| (f.id, r.clone()))
                .collect::<Vec<_>>()
        })
        .collect();
    let planned = engine.plan(&items);
    cleanup::preflight_static(&planned, findings)
}

/// Human-readable dry-run listing of the remedy commands that `clean` would
/// run, running nothing (spec §5 `clean --dry-run`), followed by the
/// preflight refusals and the Homebrew impact of the batch.
///
/// Commands are rendered through `RemedyEngine` with the active `delete_mode`,
/// so under `--rm` the preview shows the literal `rm -rf …` that would
/// actually run — never `trash …` for an operation that is really
/// irreversible.
pub fn dry_run_report(findings: &BTreeMap<FindingId, Finding>, delete_mode: DeleteMode) -> String {
    dry_run_report_selected(findings, delete_mode, &[])
}

pub fn dry_run_report_selected(
    findings: &BTreeMap<FindingId, Finding>,
    delete_mode: DeleteMode,
    select: &[String],
) -> String {
    use std::fmt::Write;
    let selected = dry_run_selection(findings, select);
    let report = dry_run_plan(findings, &selected, delete_mode);
    let mut out = String::new();
    let mut reclaim: u64 = 0;
    for a in &report.ok {
        let title = findings
            .get(&a.finding_id)
            .map(|f| format!("{}  ({})", f.title, f.severity_label()))
            .unwrap_or_default();
        let _ = writeln!(out, "# {title}");
        let _ = writeln!(out, "{}", a.rendered);
        reclaim += a.reclaims_bytes.unwrap_or(0);
    }
    let n = report.ok.len();
    let human = humansize::format_size(reclaim, humansize::BINARY);
    let _ = writeln!(
        out,
        "\n# {n} destructive remed{} — up to {human} reclaimable",
        if n == 1 { "y" } else { "ies" }
    );
    if !report.refused.is_empty() {
        let _ = writeln!(out, "\n# Preflight — refused (would not run):");
        for r in &report.refused {
            let _ = writeln!(out, "#   {}  — {}", r.action.rendered, r.reason);
        }
    }
    if let Some(p) = &report.brew_preview {
        let _ = writeln!(out, "\n# Homebrew impact:");
        if !p.removable.is_empty() {
            let _ = writeln!(out, "#   removes: {}", p.removable.join(", "));
        }
        for (pkg, deps) in &p.blocked {
            let _ = writeln!(out, "#   {pkg} stays — still needed by {}", deps.join(", "));
        }
        if !p.newly_orphaned.is_empty() {
            let _ = writeln!(
                out,
                "#   predicted to become unneeded: {}",
                p.newly_orphaned.join(", ")
            );
        }
        if !p.confirmed_orphans.is_empty() {
            let _ = writeln!(
                out,
                "#   brew already lists as unneeded: {}",
                p.confirmed_orphans.join(", ")
            );
        }
        if !p.uncertain_orphans.is_empty() {
            let _ = writeln!(
                out,
                "#   origin unknown, verify first: {}",
                p.uncertain_orphans.join(", ")
            );
        }
    }
    // Selected findings that carry no primary destructive remedy: say why.
    let not_offered: Vec<String> = selected
        .iter()
        .filter(|f| !f.remedies.iter().any(|r| r.destructive && !r.alternative))
        .map(|f| format!("{} — {}", f.title, not_offered_reason(f)))
        .collect();
    if !not_offered.is_empty() {
        let _ = writeln!(out, "\n# Not offered (no destructive remedy):");
        for n in &not_offered {
            let _ = writeln!(out, "#   {n}");
        }
    }
    if !report.remaining.is_empty() {
        let _ = writeln!(out, "\n# Stays:");
        for r in &report.remaining {
            let _ = writeln!(out, "#   {r}");
        }
    }
    if !report.follow_up.is_empty() {
        let _ = writeln!(out, "\n# Follow-up:");
        for f in &report.follow_up {
            let _ = writeln!(out, "#   {f}");
        }
    }
    if select.is_empty() {
        let _ = writeln!(
            out,
            "\n# Brew/Tools rows are listed only when evidence suggests removal; use --select <identity_key|name> for others."
        );
    }
    out
}

fn not_offered_reason(f: &Finding) -> String {
    if let Some(p) = f.meta.get("protected").and_then(|v| v.as_str()) {
        return format!("protected: {p}");
    }
    if let Some(blocked) = f
        .meta
        .pointer("/removal_preview/blocked_by")
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
    {
        let names: Vec<&str> = blocked.iter().filter_map(|v| v.as_str()).collect();
        return format!("still needed by {}", names.join(", "));
    }
    if f.meta.get("pinned").and_then(|v| v.as_bool()) == Some(true) {
        return "pinned in Homebrew".into();
    }
    if let Some(refusals) = f
        .meta
        .pointer("/removal/refusals")
        .and_then(|v| v.as_array())
    {
        if let Some(r) = refusals.first().and_then(|v| v.as_str()) {
            return r.to_string();
        }
    }
    "no removal command is known for it".into()
}

/// `clean --dry-run --json`.
pub fn dry_run_json(
    findings: &BTreeMap<FindingId, Finding>,
    delete_mode: DeleteMode,
    select: &[String],
) -> anyhow::Result<String> {
    let selected = dry_run_selection(findings, select);
    let report = dry_run_plan(findings, &selected, delete_mode);
    let actions: Vec<serde_json::Value> = report
        .ok
        .iter()
        .map(|a| {
            let mut v = serde_json::to_value(a).unwrap_or(serde_json::Value::Null);
            if let Some(o) = v.as_object_mut() {
                o.insert(
                    "title".into(),
                    serde_json::json!(findings.get(&a.finding_id).map(|f| f.title.clone())),
                );
            }
            v
        })
        .collect();
    let reclaimable: u64 = report.ok.iter().filter_map(|a| a.reclaims_bytes).sum();
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "actions": actions,
        "refused": report.refused,
        "impact": report.brew_preview,
        "remaining": report.remaining,
        "follow_up": report.follow_up,
        "reclaimable_bytes": reclaimable,
    }))?)
}

/// `macaudit tools`: one line per installation.
pub fn tools_table(findings: &[&Finding]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<6} {:<28} {:<14} {:<20} {:<40} COMMANDS",
        "MANAGER", "PACKAGE", "VERSION", "CLASS", "ROOT"
    );
    let mut rows: Vec<&&Finding> = findings.iter().collect();
    rows.sort_by_key(|f| {
        (
            f.meta
                .get("manager")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            f.meta
                .get("root")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            f.title.clone(),
        )
    });
    for f in rows {
        let m = &f.meta;
        let s = |k: &str| {
            m.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string()
        };
        let commands: Vec<String> = m
            .get("commands")
            .and_then(|c| c.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.get("name").and_then(|n| n.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "{:<6} {:<28} {:<14} {:<20} {:<40} {}",
            s("manager"),
            truncate(&f.title, 28),
            truncate(&s("version"), 14),
            s("primary_classification").replace('_', "-"),
            truncate(&s("root"), 40),
            commands.join(" ")
        );
    }
    let _ = writeln!(out, "\n{} installation(s)", findings.len());
    out
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Text tree for `brew why` / `brew deps`.
pub fn brew_tree_text(graph: &BrewGraph, name: &str, dir: Direction, max_depth: u16) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let Some(id) = graph.resolve(name) else {
        return format!("unknown or ambiguous package: {name}\n");
    };
    let node = graph.get(&id).expect("resolved");
    let why = graph.why_installed(&id);
    let _ = writeln!(
        out,
        "{} {} — installed on request: {} · autoremove candidate: {} · leaf: {}",
        node.name,
        node.version.clone().unwrap_or_else(|| "unknown".into()),
        match node.installed_on_request {
            Some(true) => "yes",
            Some(false) => "no",
            None => "unknown",
        },
        match graph.autoremove.as_ref() {
            Some(set) =>
                if set.contains(&id) {
                    "yes"
                } else {
                    "no"
                },
            None => "unknown",
        },
        if graph.is_leaf(&id) { "yes" } else { "no" }
    );
    if dir == Direction::Reverse && !why.requested_roots.is_empty() {
        let _ = writeln!(out, "kept because of: {}", why.requested_roots.join(", "));
    }
    let _ = writeln!(
        out,
        "{}",
        if dir == Direction::Forward {
            "needs:"
        } else {
            "needed by:"
        }
    );
    let walk = graph.walk(&id, dir, &|_| true, "cli", max_depth);
    let n = walk.len();
    for (i, w) in walk.iter().enumerate().skip(1) {
        let indent = "    ".repeat((w.depth as usize).saturating_sub(2));
        let last = i + 1 >= n || walk[i + 1].depth < w.depth;
        let branch = if last { "└── " } else { "├── " };
        let suffix = crate::brewgraph::relation_suffix(w.relation, w.cycle);
        let _ = writeln!(
            out,
            "{indent}{branch}{}{}",
            w.name,
            if suffix.is_empty() {
                String::new()
            } else {
                format!("  ({suffix})")
            }
        );
    }
    if n == 1 {
        let _ = writeln!(out, "    (none)");
    }
    for c in &graph.caveats {
        if c.contains(&node.name) {
            let _ = writeln!(out, "note: {c}");
        }
    }
    out
}

/// JSON for `brew why` / `brew deps`.
pub fn brew_tree_json(
    graph: &BrewGraph,
    name: &str,
    dir: Direction,
    max_depth: u16,
) -> anyhow::Result<String> {
    let Some(id) = graph.resolve(name) else {
        anyhow::bail!("unknown or ambiguous package: {name}");
    };
    let node = graph.get(&id).expect("resolved");
    let direct = graph.children(&id, dir);
    let closure = match dir {
        Direction::Forward => graph.transitive_deps(&id),
        Direction::Reverse => graph.transitive_dependents(&id),
    };
    let transitive: Vec<&String> = closure.keys().filter(|k| !direct.contains(k)).collect();
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "name": node.name,
        "id": id,
        "version": node.version,
        "direction": dir,
        "origin": {
            "installed_on_request": node.installed_on_request,
            "installed_as_dependency": node.installed_as_dependency,
            "install_reason": node.reason().label(),
            "autoremove_candidate": graph.autoremove.as_ref().map(|s| s.contains(&id)),
            "is_leaf": graph.is_leaf(&id),
        },
        "why_installed": graph.why_installed(&id),
        "direct": direct,
        "transitive": transitive,
        "tree": graph.walk(&id, dir, &|_| true, "cli", max_depth),
        "caveats": graph.caveats,
    }))?)
}

impl Finding {
    /// Lowercase severity label for reports.
    pub fn severity_label(&self) -> &'static str {
        match self.severity {
            crate::model::Severity::Info => "info",
            crate::model::Severity::Attention => "attention",
            crate::model::Severity::Reclaimable => "reclaimable",
            crate::model::Severity::Warning => "warning",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FindingKind, Remedy, RemedyCommand, Severity};

    fn sample() -> BTreeMap<FindingId, Finding> {
        let mut m = BTreeMap::new();
        let f = Finding::new(
            FindingKind::BuildArtifact,
            "/p/node_modules",
            "node_modules",
        )
        .size(1000)
        .severity(Severity::Reclaimable)
        .remedy(Remedy {
            label: "Trash".into(),
            command: RemedyCommand::Trash {
                path: "/p/node_modules".into(),
            },
            reclaims_bytes: Some(1000),
            destructive: true,
            alternative: false,
            guard: None,
        });
        m.insert(f.id, f);
        m
    }

    #[test]
    fn json_is_an_array() {
        let json = findings_to_json(&sample()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array());
        assert_eq!(v[0]["kind"], "build_artifact");
    }

    #[test]
    fn dry_run_lists_command_verbatim() {
        let report = dry_run_report(&sample(), DeleteMode::Trash);
        assert!(report.contains("trash /p/node_modules"));
        assert!(report.contains("destructive remedy"));
    }

    #[test]
    fn dry_run_rm_mode_shows_rm_not_trash() {
        // The whole point of the dry run is an honest preview: in --rm mode it
        // must show the literal `rm -rf`, never `trash`.
        let report = dry_run_report(&sample(), DeleteMode::Rm);
        assert!(report.contains("rm -rf /p/node_modules"), "got: {report}");
        assert!(!report.contains("trash /p/node_modules"));
    }
}
