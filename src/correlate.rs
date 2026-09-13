//! Cross-scanner joins applied after a full scan collects into a map.
//!
//! The apps ↔ brew cask join: an app whose bundle path matches an **installed**
//! cask's artifact paths (from `brew info --installed --cask`) is managed by
//! Homebrew. We mark those apps so the UI can group them under "Homebrew Cask"
//! and stop flagging them as Unmanaged — answering "which apps did brew
//! install?" at a glance.
//!
//! We do NOT offer a `brew install --cask --adopt` remedy here: matching only
//! against *installed* casks means a match is already-managed (adopting it would
//! be a no-op), and detecting a manually-installed app that an *available* cask
//! could adopt requires the online cask catalog (formulae.brew.sh), which is
//! v1.1. The `meta.app_paths`/`meta.classification` fields are left in place for
//! that future pass.
//!
//! Findings are keyed by id in a `BTreeMap`, so the join is two passes: collect
//! `(app_id, cask_token)` matches by immutable iteration, then mutate — this
//! satisfies the borrow checker without cloning the whole map. Defensive
//! throughout: missing/malformed `meta` fields are tolerated, never panicked on.

use std::collections::BTreeMap;

use crate::model::{Finding, FindingId, FindingKind, Severity};

/// Enrich findings in place using information across scanners.
pub fn correlate(findings: &mut BTreeMap<FindingId, Finding>) {
    mark_cask_managed_apps(findings);
    link_cask_binaries_to_tools(findings);
    link_tool_interpreters(findings);
}

fn classification_rank(slug: &str) -> u8 {
    match slug {
        "broken" => 0,
        "required" => 1,
        "orphan" => 2,
        "duplicate" => 3,
        "shadowed" => 4,
        "project_alternative" => 5,
        _ => 6,
    }
}

/// A cask `binary` artifact provides the same command as a manager-installed
/// tool (on the audited Mac: the `codex` cask vs npm's `@openai/codex`). The
/// tool gains a `brew_cask:<token>` duplicate peer; the cask lists its peers.
fn link_cask_binaries_to_tools(findings: &mut BTreeMap<FindingId, Finding>) {
    // (token, command name, launcher target)
    let mut cask_bins: Vec<(FindingId, String, String, String)> = Vec::new();
    for f in findings
        .values()
        .filter(|f| f.kind == FindingKind::BrewCask)
    {
        let token = f
            .meta
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap_or(&f.title)
            .to_string();
        if let Some(bins) = f.meta.get("binaries").and_then(|b| b.as_array()) {
            for b in bins {
                let source = b.get("source").and_then(|s| s.as_str()).unwrap_or("");
                let target = b.get("target").and_then(|t| t.as_str()).unwrap_or("");
                let cmd = target
                    .rsplit('/')
                    .next()
                    .filter(|c| !c.is_empty())
                    .or_else(|| source.rsplit('/').next())
                    .unwrap_or("")
                    .to_string();
                if !cmd.is_empty() {
                    cask_bins.push((f.id, token.clone(), cmd, target.to_string()));
                }
            }
        }
    }
    if cask_bins.is_empty() {
        return;
    }
    let mut tool_updates: Vec<(FindingId, String)> = Vec::new();
    let mut cask_updates: Vec<(FindingId, String)> = Vec::new();
    for f in findings
        .values()
        .filter(|f| f.kind == FindingKind::GlobalTool)
    {
        let commands: Vec<String> = f
            .meta
            .get("commands")
            .and_then(|c| c.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.get("name").and_then(|n| n.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let key = f
            .meta
            .get("identity_key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        for (cask_id, token, cmd, _) in &cask_bins {
            if commands.iter().any(|c| c == cmd) {
                tool_updates.push((f.id, token.clone()));
                cask_updates.push((*cask_id, key.clone()));
            }
        }
    }
    for (id, token) in tool_updates {
        if let Some(f) = findings.get_mut(&id) {
            if let Some(obj) = f.meta.as_object_mut() {
                obj.insert("brew_cask_peer".into(), serde_json::json!(token));
                let peer = format!("brew_cask:{token}");
                let mut classes = obj
                    .get("classifications")
                    .and_then(|c| c.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut merged = false;
                for c in classes.iter_mut() {
                    if c.get("kind").and_then(|k| k.as_str()) == Some("duplicate") {
                        if let Some(peers) = c.get_mut("peers").and_then(|p| p.as_array_mut()) {
                            if !peers.iter().any(|p| p.as_str() == Some(&peer)) {
                                peers.push(serde_json::json!(peer));
                            }
                        }
                        merged = true;
                    }
                }
                if !merged {
                    classes.push(serde_json::json!({ "kind": "duplicate", "peers": [peer] }));
                }
                classes.sort_by_key(|c| {
                    classification_rank(c.get("kind").and_then(|k| k.as_str()).unwrap_or(""))
                });
                let primary = classes
                    .first()
                    .and_then(|c| c.get("kind"))
                    .and_then(|k| k.as_str())
                    .unwrap_or("review")
                    .to_string();
                obj.insert("classifications".into(), serde_json::Value::Array(classes));
                obj.insert("primary_classification".into(), serde_json::json!(primary));
                if matches!(primary.as_str(), "duplicate" | "shadowed")
                    && f.severity < Severity::Attention
                {
                    f.severity = Severity::Attention;
                }
            }
        }
    }
    for (id, key) in cask_updates {
        if let Some(f) = findings.get_mut(&id) {
            if let Some(obj) = f.meta.as_object_mut() {
                let mut peers = obj
                    .get("tool_peers")
                    .and_then(|p| p.as_array())
                    .cloned()
                    .unwrap_or_default();
                if !peers.iter().any(|p| p.as_str() == Some(&key)) {
                    peers.push(serde_json::json!(key));
                }
                obj.insert("tool_peers".into(), serde_json::Value::Array(peers));
            }
        }
    }
}

/// Which finding owns the interpreter a pipx/uv/pip installation runs on:
/// a Homebrew `python@X.Y` formula or a version-manager runtime. Records the
/// owner (or that the owning formula is no longer installed) in
/// `meta.runtime.owner` / `meta.runtime.owner_present`.
fn link_tool_interpreters(findings: &mut BTreeMap<FindingId, Finding>) {
    let formulae: Vec<String> = findings
        .values()
        .filter(|f| f.kind == FindingKind::BrewFormula)
        .filter_map(|f| {
            f.meta
                .get("name")
                .and_then(|n| n.as_str())
                .map(str::to_string)
        })
        .collect();
    let runtimes: Vec<(String, String)> = findings
        .values()
        .filter(|f| f.kind == FindingKind::RuntimeVersion)
        .filter_map(|f| {
            f.path
                .as_ref()
                .map(|p| (f.title.clone(), p.display().to_string()))
        })
        .collect();
    let mut updates: Vec<(FindingId, String, Option<bool>)> = Vec::new();
    for f in findings
        .values()
        .filter(|f| f.kind == FindingKind::GlobalTool)
    {
        let Some(path) = f
            .meta
            .get("runtime")
            .and_then(|r| r.get("path"))
            .and_then(|p| p.as_str())
        else {
            continue;
        };
        if let Some(name) = python_formula_from_path(path) {
            let present = formulae.iter().any(|n| n == &name);
            updates.push((f.id, format!("brew_formula:{name}"), Some(present)));
            continue;
        }
        if let Some((title, _)) = runtimes.iter().find(|(_, p)| path.starts_with(p.as_str())) {
            updates.push((f.id, format!("runtime:{title}"), Some(true)));
        }
    }
    for (id, owner, present) in updates {
        if let Some(f) = findings.get_mut(&id) {
            if let Some(rt) = f.meta.get_mut("runtime").and_then(|r| r.as_object_mut()) {
                rt.insert("owner".into(), serde_json::json!(owner));
                rt.insert("owner_present".into(), serde_json::json!(present));
            }
        }
    }
}

/// `…/opt/python@3.14/…` or `…/Cellar/python@3.14/…` → `python@3.14`.
fn python_formula_from_path(path: &str) -> Option<String> {
    for marker in ["/opt/", "/Cellar/"] {
        for (idx, _) in path.match_indices(marker) {
            let rest = &path[idx + marker.len()..];
            let seg = rest.split('/').next().unwrap_or("");
            if seg.starts_with("python@") {
                return Some(seg.to_string());
            }
        }
    }
    None
}

/// One installed cask, collected from the map before any mutation.
struct CaskCandidate {
    token: String,
    app_paths: Vec<String>,
}

fn mark_cask_managed_apps(findings: &mut BTreeMap<FindingId, Finding>) {
    let casks: Vec<CaskCandidate> = findings
        .values()
        .filter(|f| f.kind == FindingKind::BrewCask)
        .map(|f| {
            let token = f
                .meta
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or(f.title.as_str())
                .to_string();
            let app_paths = f
                .meta
                .get("app_paths")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            CaskCandidate { token, app_paths }
        })
        .collect();

    if casks.is_empty() {
        return;
    }

    // Pass 1: find apps whose path matches an installed cask's artifact paths.
    let mut matches: Vec<(FindingId, String)> = Vec::new();
    for f in findings.values() {
        if f.kind != FindingKind::App {
            continue;
        }
        let Some(app_path) = f.path.as_ref().map(|p| p.to_string_lossy().to_string()) else {
            continue;
        };
        if let Some(cask) = casks
            .iter()
            .find(|c| c.app_paths.iter().any(|ap| ap == &app_path))
        {
            matches.push((f.id, cask.token.clone()));
        }
    }

    // Pass 2: mark the matched apps as cask-managed.
    for (app_id, token) in matches {
        if let Some(app) = findings.get_mut(&app_id) {
            if let Some(obj) = app.meta.as_object_mut() {
                obj.insert("group".to_string(), serde_json::json!("Homebrew Cask"));
                obj.insert("classification".to_string(), serde_json::json!("cask"));
                obj.insert("managed_by_cask".to_string(), serde_json::json!(token));
            }
            // A brew-managed app isn't an "unmanaged" concern.
            if app.severity == Severity::Attention {
                app.severity = Severity::Info;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use serde_json::json;

    fn app_finding(path: &str, name: &str) -> Finding {
        Finding::new(FindingKind::App, path, name)
            .path(path)
            .severity(Severity::Attention)
            .meta(json!({ "classification": "unmanaged", "group": "Unmanaged" }))
    }

    fn cask_finding(token: &str, app_paths: Vec<&str>) -> Finding {
        Finding::new(FindingKind::BrewCask, token, token)
            .meta(json!({ "token": token, "app_paths": app_paths }))
    }

    #[test]
    fn marks_app_cask_managed_when_path_matches() {
        let mut map = BTreeMap::new();
        let app = app_finding("/Applications/Slack.app", "Slack");
        let cask = cask_finding("slack", vec!["/Applications/Slack.app"]);
        map.insert(app.id, app.clone());
        map.insert(cask.id, cask);

        correlate(&mut map);

        let updated = map.get(&app.id).unwrap();
        assert_eq!(updated.meta["group"], "Homebrew Cask");
        assert_eq!(updated.meta["classification"], "cask");
        assert_eq!(updated.meta["managed_by_cask"], "slack");
        // No longer an "unmanaged" attention item.
        assert_eq!(updated.severity, Severity::Info);
        // We do not offer an adopt remedy in v1.
        assert!(updated.remedies.is_empty());
    }

    #[test]
    fn name_only_match_is_not_marked() {
        // Same normalized name but the cask's app_paths don't include this path:
        // without a path match we can't claim it's the installed one.
        let mut map = BTreeMap::new();
        let app = app_finding("/Applications/Visual Studio Code.app", "Visual Studio Code");
        let cask = cask_finding("visual-studio-code", vec!["/some/other/path.app"]);
        map.insert(app.id, app.clone());
        map.insert(cask.id, cask);

        correlate(&mut map);

        let updated = map.get(&app.id).unwrap();
        assert_eq!(updated.meta["group"], "Unmanaged");
    }

    #[test]
    fn no_panic_on_missing_meta_fields() {
        let mut map = BTreeMap::new();
        let app = Finding::new(FindingKind::App, "/Applications/Weird.app", "Weird");
        let cask = Finding::new(FindingKind::BrewCask, "weird", "weird");
        map.insert(app.id, app);
        map.insert(cask.id, cask);
        correlate(&mut map); // must not panic
    }

    #[test]
    fn app_with_no_cask_is_untouched() {
        let mut map = BTreeMap::new();
        let app = app_finding("/Applications/Bespoke.app", "Bespoke");
        map.insert(app.id, app.clone());
        correlate(&mut map);
        let updated = map.get(&app.id).unwrap();
        assert_eq!(updated.meta["group"], "Unmanaged");
    }

    #[test]
    fn cask_binary_becomes_duplicate_peer_of_tool_and_interpreter_owner_is_linked() {
        let mut map = BTreeMap::new();
        let cask = Finding::new(FindingKind::BrewCask, "codex", "codex").meta(serde_json::json!({
            "token": "codex", "binaries": [{ "source": "bin/codex", "target": "/opt/homebrew/bin/codex" }]
        }));
        let tool = Finding::new(
            FindingKind::GlobalTool,
            "npm:/p:@openai/codex",
            "@openai/codex",
        )
        .meta(serde_json::json!({
            "identity_key": "npm:/p:@openai/codex",
            "commands": [{ "name": "codex", "declared_target": null }],
            "classifications": [{ "kind": "review", "reason": "x" }],
            "primary_classification": "review",
            "runtime": { "kind": "node", "path": "/opt/homebrew/bin/node" }
        }));
        let pipx = Finding::new(FindingKind::GlobalTool, "pipx:/v:rendercv", "rendercv").meta(serde_json::json!({
            "identity_key": "pipx:/v:rendercv", "commands": [],
            "classifications": [{ "kind": "broken", "reason": "interp" }], "primary_classification": "broken",
            "runtime": { "kind": "python", "path": "/opt/homebrew/opt/python@3.13/bin/python3.13", "exists": false }
        }));
        let uv = Finding::new(FindingKind::GlobalTool, "uv:/t:mcp-proxy", "mcp-proxy").meta(serde_json::json!({
            "identity_key": "uv:/t:mcp-proxy", "commands": [],
            "classifications": [{ "kind": "review", "reason": "x" }], "primary_classification": "review",
            "runtime": { "kind": "python", "path": "/opt/homebrew/opt/python@3.14/bin", "exists": true }
        }));
        let py = Finding::new(FindingKind::BrewFormula, "python@3.14", "python@3.14")
            .meta(serde_json::json!({ "name": "python@3.14" }));
        for f in [cask, tool, pipx, uv, py] {
            map.insert(f.id, f);
        }
        correlate(&mut map);
        let tool = map.values().find(|f| f.title == "@openai/codex").unwrap();
        assert_eq!(tool.meta["brew_cask_peer"], "codex");
        assert_eq!(tool.meta["primary_classification"], "duplicate");
        assert_eq!(tool.severity, Severity::Attention);
        let cask = map.values().find(|f| f.title == "codex").unwrap();
        assert_eq!(cask.meta["tool_peers"][0], "npm:/p:@openai/codex");
        let pipx = map.values().find(|f| f.title == "rendercv").unwrap();
        assert_eq!(pipx.meta["runtime"]["owner"], "brew_formula:python@3.13");
        assert_eq!(pipx.meta["runtime"]["owner_present"], false);
        // Broken stays primary over duplicate.
        assert_eq!(pipx.meta["primary_classification"], "broken");
        let uv = map.values().find(|f| f.title == "mcp-proxy").unwrap();
        assert_eq!(uv.meta["runtime"]["owner"], "brew_formula:python@3.14");
        assert_eq!(uv.meta["runtime"]["owner_present"], true);
    }
}
