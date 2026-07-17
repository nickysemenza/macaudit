//! Network enrichment orchestrator (spec M7).
//!
//! Loads the cask catalog (`catalog.rs`), matches Unmanaged apps to available
//! casks (offering a `brew install --cask --adopt` remedy), and best-effort
//! checks GitHub releases (`github.rs`) for matched apps whose homepage is a
//! GitHub repo. Runs AFTER the sync `correlate()` pass in both the headless and
//! TUI paths — installed-cask apps are reclassified to `"cask"` first so they
//! are never offered `--adopt`.
//!
//! Contract: a total no-op (no disk or network I/O) when there are no Unmanaged
//! App findings; otherwise every network/cache failure degrades silently.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, Paths};
use crate::model::{Finding, FindingId, FindingKind, Remedy, RemedyCommand, Severity};
use crate::net::{catalog, github, HttpFetcher};

/// A matched app that is a GitHub-release check candidate.
struct GhCandidate {
    id: FindingId,
    owner: String,
    repo: String,
    version: String,
}

/// Enrich findings in place with network-derived data.
pub async fn enrich(
    findings: &mut BTreeMap<FindingId, Finding>,
    fetcher: Option<Arc<dyn HttpFetcher>>,
    paths: &Paths,
    config: &Config,
    token: &CancellationToken,
) {
    // 1. Nothing to enrich unless there's at least one Unmanaged app. This keeps
    // the disk-only e2e path hermetic: no cache reads, no network.
    if !findings.values().any(is_unmanaged_app) {
        return;
    }

    // 2. Load the cask catalog (may be served from cache, or unavailable).
    let net = &config.network;
    let Some(catalog) = catalog::load(fetcher.as_deref(), paths, net, token).await else {
        return;
    };

    // 3. Match each Unmanaged app to a cask; apply meta + adopt remedy.
    let mut gh_candidates: Vec<GhCandidate> = Vec::new();
    for f in findings.values_mut() {
        if !is_unmanaged_app(f) {
            continue;
        }
        let file_name = f
            .path
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        // Display name for the fuzzy rule is the bundle's on-disk name (the
        // finding title carries the version, which would break normalization).
        let display_name = f
            .path
            .as_ref()
            .and_then(|p| p.file_stem())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| f.title.clone());
        let bundle_id = f
            .meta
            .get("bundle_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let Some((cask, rule)) = catalog.match_app(&file_name, &display_name, bundle_id.as_deref())
        else {
            continue;
        };
        let cask_token = cask.token.clone();
        let homepage = cask.homepage.clone();

        if let Some(obj) = f.meta.as_object_mut() {
            obj.insert("available_cask".to_string(), json!(cask_token));
            obj.insert("catalog_matched_by".to_string(), json!(rule));
            if let Some(hp) = &homepage {
                obj.insert("cask_homepage".to_string(), json!(hp));
            }
        }
        f.detail = format!("{} — available as cask {}", f.detail, cask_token);

        let remedy = Remedy {
            label: "Adopt with Homebrew".to_string(),
            command: RemedyCommand::Shell {
                program: "brew".to_string(),
                args: vec![
                    "install".to_string(),
                    "--cask".to_string(),
                    "--adopt".to_string(),
                    cask_token.clone(),
                ],
            },
            reclaims_bytes: None,
            destructive: false,
        };
        let rendered = remedy.command.rendered();
        if !f.remedies.iter().any(|r| r.command.rendered() == rendered) {
            f.remedies.push(remedy);
        }

        // Queue a GitHub check if the homepage is a repo and we have a version.
        if let Some(hp) = &homepage {
            if let Some((owner, repo)) = github::parse_github_repo(hp) {
                if let Some(version) = f.meta.get("version").and_then(|v| v.as_str()) {
                    gh_candidates.push(GhCandidate {
                        id: f.id,
                        owner,
                        repo,
                        version: version.to_string(),
                    });
                }
            }
        }
    }

    // 4. GitHub release pass over matched candidates (needs a live fetcher).
    let Some(fetcher) = fetcher.as_deref() else {
        return;
    };
    if gh_candidates.is_empty() {
        return;
    }
    let mut checker = github::GithubChecker::load(&paths.cache_dir, net);
    for cand in gh_candidates {
        if token.is_cancelled() {
            break;
        }
        let Some(tag) = checker
            .latest_tag(&cand.owner, &cand.repo, fetcher, token)
            .await
        else {
            continue;
        };
        if github::is_newer(&tag, &cand.version) {
            if let Some(f) = findings.get_mut(&cand.id) {
                if let Some(obj) = f.meta.as_object_mut() {
                    obj.insert("latest_release".to_string(), json!(tag));
                }
                f.detail = format!("{} — newer release {} available", f.detail, tag);
                if f.severity < Severity::Attention {
                    f.severity = Severity::Attention;
                }
            }
        }
    }
    checker.save();
}

/// An App finding still classified `"unmanaged"` (i.e. `correlate` did not
/// reclassify it as cask-managed).
fn is_unmanaged_app(f: &Finding) -> bool {
    f.kind == FindingKind::App
        && f.meta.get("classification").and_then(|v| v.as_str()) == Some("unmanaged")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkConfig;
    use crate::net::MockHttpFetcher;
    use std::path::Path;

    const CATALOG: &str = r#"[
        {"token":"slack","name":["Slack"],"homepage":"https://slack.com",
         "artifacts":[{"app":["Slack.app"]}]},
        {"token":"acme","name":["Acme"],"homepage":"https://github.com/acme/acme",
         "artifacts":[{"app":["Acme.app"]}]}
    ]"#;

    fn paths_with_catalog(home: &Path) -> Paths {
        let p = Paths::from_home(home);
        std::fs::create_dir_all(&p.cache_dir).unwrap();
        std::fs::write(p.cache_dir.join("cask.json"), CATALOG).unwrap();
        let meta = json!({ "etag": "v1", "fetched_at": now_secs() });
        std::fs::write(p.cache_dir.join("cask.json.meta"), meta.to_string()).unwrap();
        p
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn unmanaged_app(path: &str, name: &str, version: &str) -> Finding {
        Finding::new(FindingKind::App, path, name)
            .path(path)
            .severity(Severity::Attention)
            .detail("unmanaged — identified_developer")
            .meta(json!({
                "classification": "unmanaged",
                "group": "Unmanaged",
                "version": version,
                "bundle_id": null
            }))
    }

    fn config() -> Config {
        Config::default()
    }

    fn insert(map: &mut BTreeMap<FindingId, Finding>, f: Finding) {
        map.insert(f.id, f);
    }

    #[tokio::test]
    async fn unmanaged_app_gains_adopt_remedy_and_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_with_catalog(tmp.path());
        let mut map = BTreeMap::new();
        let app = unmanaged_app("/Applications/Slack.app", "Slack 4.36.0", "4.36.0");
        let id = app.id;
        insert(&mut map, app);

        // Fresh cache ⇒ the fetcher is never touched.
        let fetcher = Arc::new(MockHttpFetcher::new());
        enrich(
            &mut map,
            Some(fetcher.clone()),
            &paths,
            &config(),
            &CancellationToken::new(),
        )
        .await;

        let f = map.get(&id).unwrap();
        assert_eq!(f.meta["available_cask"], "slack");
        assert_eq!(f.meta["catalog_matched_by"], "app_name");
        assert_eq!(f.meta["cask_homepage"], "https://slack.com");
        assert!(f.detail.contains("available as cask slack"));
        let adopt = f
            .remedies
            .iter()
            .find(|r| r.label == "Adopt with Homebrew")
            .unwrap();
        assert_eq!(
            adopt.command.rendered(),
            "brew install --cask --adopt slack"
        );
        assert!(!adopt.destructive);
        assert!(fetcher.calls().is_empty());
    }

    #[tokio::test]
    async fn adopt_remedy_is_not_duplicated() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_with_catalog(tmp.path());
        let mut map = BTreeMap::new();
        let mut app = unmanaged_app("/Applications/Slack.app", "Slack 4.36.0", "4.36.0");
        // Pre-existing identical remedy.
        app = app.remedy(Remedy {
            label: "Adopt with Homebrew".to_string(),
            command: RemedyCommand::Shell {
                program: "brew".to_string(),
                args: vec![
                    "install".to_string(),
                    "--cask".to_string(),
                    "--adopt".to_string(),
                    "slack".to_string(),
                ],
            },
            reclaims_bytes: None,
            destructive: false,
        });
        let id = app.id;
        insert(&mut map, app);

        enrich(&mut map, None, &paths, &config(), &CancellationToken::new()).await;

        let f = map.get(&id).unwrap();
        let count = f
            .remedies
            .iter()
            .filter(|r| r.command.rendered() == "brew install --cask --adopt slack")
            .count();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn cask_managed_app_is_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_with_catalog(tmp.path());
        let mut map = BTreeMap::new();
        // One unmanaged app so enrich proceeds past the early return.
        let un = unmanaged_app("/Applications/Slack.app", "Slack 4.36.0", "4.36.0");
        // A cask-managed app whose name would otherwise match a cask.
        let managed = Finding::new(FindingKind::App, "/Applications/Acme.app", "Acme 1.0")
            .path("/Applications/Acme.app")
            .meta(json!({ "classification": "cask", "group": "Homebrew Cask" }));
        let managed_id = managed.id;
        insert(&mut map, un);
        insert(&mut map, managed);

        enrich(&mut map, None, &paths, &config(), &CancellationToken::new()).await;

        let m = map.get(&managed_id).unwrap();
        assert!(m.meta.get("available_cask").is_none());
        assert!(m.remedies.is_empty());
    }

    #[tokio::test]
    async fn empty_map_makes_zero_fetcher_calls() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let mut map: BTreeMap<FindingId, Finding> = BTreeMap::new();
        let fetcher = Arc::new(MockHttpFetcher::new());
        enrich(
            &mut map,
            Some(fetcher.clone()),
            &paths,
            &config(),
            &CancellationToken::new(),
        )
        .await;
        assert!(fetcher.calls().is_empty());
        // No cache files were created either (no cache_dir I/O at all).
        assert!(!paths.cache_dir.join("cask.json").exists());
    }

    #[tokio::test]
    async fn github_newer_release_raises_severity_and_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_with_catalog(tmp.path());
        let mut map = BTreeMap::new();
        // Acme's cask homepage is github.com/acme/acme; installed version 1.0.0.
        let app = unmanaged_app("/Applications/Acme.app", "Acme 1.0.0", "1.0.0");
        let id = app.id;
        // Start below Attention to prove severity is raised.
        let mut app = app;
        app.severity = Severity::Info;
        insert(&mut map, app);

        let releases_url = "https://api.github.com/repos/acme/acme/releases/latest";
        let fetcher = Arc::new(MockHttpFetcher::new().on(
            releases_url,
            200,
            None,
            r#"{"tag_name":"v2.0.0"}"#,
        ));
        enrich(
            &mut map,
            Some(fetcher.clone()),
            &paths,
            &config(),
            &CancellationToken::new(),
        )
        .await;

        let f = map.get(&id).unwrap();
        assert_eq!(f.meta["available_cask"], "acme");
        assert_eq!(f.meta["latest_release"], "v2.0.0");
        assert!(f.detail.contains("newer release v2.0.0 available"));
        assert_eq!(f.severity, Severity::Attention);
        assert_eq!(fetcher.calls(), vec![(releases_url.to_string(), None)]);
    }

    // Sanity: NetworkConfig default is what these tests assume.
    #[test]
    fn default_network_config_is_online() {
        assert!(!NetworkConfig::default().offline);
    }
}
