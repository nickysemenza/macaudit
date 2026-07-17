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
}
