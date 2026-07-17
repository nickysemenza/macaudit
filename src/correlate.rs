//! Cross-scanner joins applied after a full scan collects into a map.
//!
//! Lane S1 implements the apps ↔ brew cask join: for every Unmanaged app
//! (AppsScanner, `meta.classification == "unmanaged"`), look for a BrewCask
//! finding whose `meta.app_paths` includes the app's path, or whose token
//! matches the app's name once normalized. When found, attach a
//! `brew install --cask --adopt <token>` remedy to the app finding and note
//! the match in its `meta`.
//!
//! Findings are keyed by id in a `BTreeMap`, so joins are done in two passes:
//! first collect `(app_id, cask_token)` matches by immutable iteration, then
//! mutate the map — this satisfies the borrow checker without cloning the
//! whole map. Defensive throughout: missing/malformed `meta` fields are
//! tolerated, never panicked on.

use std::collections::BTreeMap;

use crate::model::{Finding, FindingId, FindingKind, Remedy, RemedyCommand};

/// Enrich findings in place using information across scanners.
pub fn correlate(findings: &mut BTreeMap<FindingId, Finding>) {
    correlate_apps_to_casks(findings);
}

/// Normalize a display name into something comparable to a brew cask token:
/// lowercase, strip a trailing ".app", collapse whitespace to single hyphens.
fn normalize_for_cask_match(name: &str) -> String {
    let name = name.trim().trim_end_matches(".app");
    name.to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-")
}

/// One cask candidate available for correlation, collected from the map
/// before any mutation.
struct CaskCandidate {
    token: String,
    app_paths: Vec<String>,
}

fn correlate_apps_to_casks(findings: &mut BTreeMap<FindingId, Finding>) {
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

    // Pass 1: find matches without mutating.
    let mut matches: Vec<(FindingId, String)> = Vec::new();
    for f in findings.values() {
        if f.kind != FindingKind::App {
            continue;
        }
        let is_unmanaged = f
            .meta
            .get("classification")
            .and_then(|v| v.as_str())
            .map(|s| s == "unmanaged")
            .unwrap_or(false);
        if !is_unmanaged {
            continue;
        }

        let app_path = f.path.as_ref().map(|p| p.to_string_lossy().to_string());
        let app_name_normalized = normalize_for_cask_match(&f.title);

        let found = casks.iter().find(|c| {
            let path_match = app_path
                .as_deref()
                .map(|p| c.app_paths.iter().any(|ap| ap == p))
                .unwrap_or(false);
            let name_match = c.token == app_name_normalized;
            path_match || name_match
        });

        if let Some(cask) = found {
            matches.push((f.id, cask.token.clone()));
        }
    }

    // Pass 2: mutate.
    for (app_id, token) in matches {
        if let Some(app) = findings.get_mut(&app_id) {
            app.remedies.push(Remedy {
                label: format!("Adopt into Homebrew cask `{token}`"),
                command: RemedyCommand::Shell {
                    program: "brew".to_string(),
                    args: vec![
                        "install".to_string(),
                        "--cask".to_string(),
                        "--adopt".to_string(),
                        token.clone(),
                    ],
                },
                reclaims_bytes: None,
                destructive: false,
            });

            let mut meta = app.meta.clone();
            if let Some(obj) = meta.as_object_mut() {
                obj.insert("matched_cask".to_string(), serde_json::Value::String(token));
            }
            app.meta = meta;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FindingKind, Severity};
    use serde_json::json;

    fn app_finding(path: &str, name: &str) -> Finding {
        Finding::new(FindingKind::App, path, name)
            .path(path)
            .severity(Severity::Attention)
            .meta(json!({ "classification": "unmanaged" }))
    }

    fn cask_finding(token: &str, app_paths: Vec<&str>) -> Finding {
        Finding::new(FindingKind::BrewCask, token, token)
            .meta(json!({ "token": token, "app_paths": app_paths }))
    }

    #[test]
    fn adds_adopt_remedy_when_app_path_matches_cask_app_paths() {
        let mut map = BTreeMap::new();
        let app = app_finding("/Applications/Slack.app", "Slack");
        let cask = cask_finding("slack", vec!["/Applications/Slack.app"]);
        map.insert(app.id, app.clone());
        map.insert(cask.id, cask);

        correlate(&mut map);

        let updated = map.get(&app.id).unwrap();
        assert!(updated.remedies.iter().any(|r| matches!(
            &r.command,
            RemedyCommand::Shell { program, args }
                if program == "brew" && args == &vec![
                    "install".to_string(), "--cask".to_string(), "--adopt".to_string(), "slack".to_string()
                ]
        )));
        assert_eq!(updated.meta["matched_cask"], "slack");
    }

    #[test]
    fn adds_adopt_remedy_when_name_matches_token() {
        let mut map = BTreeMap::new();
        // No app_paths overlap, but the normalized name matches the token.
        let app = app_finding("/Applications/Visual Studio Code.app", "Visual Studio Code");
        let cask = cask_finding("visual-studio-code", vec![]);
        map.insert(app.id, app.clone());
        map.insert(cask.id, cask);

        correlate(&mut map);

        let updated = map.get(&app.id).unwrap();
        assert_eq!(updated.remedies.len(), 1);
        assert_eq!(updated.meta["matched_cask"], "visual-studio-code");
    }

    #[test]
    fn does_not_touch_managed_apps() {
        let mut map = BTreeMap::new();
        let mut app = app_finding("/Applications/Xcode.app", "Xcode");
        app.meta = json!({ "classification": "app_store" });
        let cask = cask_finding("xcode", vec!["/Applications/Xcode.app"]);
        map.insert(app.id, app.clone());
        map.insert(cask.id, cask);

        correlate(&mut map);

        let updated = map.get(&app.id).unwrap();
        assert!(updated.remedies.is_empty());
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
    fn unrelated_app_with_no_cask_gets_no_remedy() {
        let mut map = BTreeMap::new();
        let app = app_finding("/Applications/Nothing.app", "Nothing");
        let cask = cask_finding("slack", vec!["/Applications/Slack.app"]);
        map.insert(app.id, app.clone());
        map.insert(cask.id, cask);

        correlate(&mut map);

        let updated = map.get(&app.id).unwrap();
        assert!(updated.remedies.is_empty());
        assert!(updated.meta.get("matched_cask").is_none());
    }
}
