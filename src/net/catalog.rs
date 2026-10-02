//! The Homebrew cask catalog held only in the owning run's memory.
//! Legacy cache files are never read, created, or modified.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use crate::config::{NetworkConfig, Paths};
use crate::inventory::{MemoryBudget, Reservation};
use crate::net::HttpFetcher;

const CASK_URL: &str = "https://formulae.brew.sh/api/cask.json";

/// One cask distilled to just what matching needs.
#[derive(Debug)]
pub struct CatalogCask {
    pub token: String,
    /// Human names (`name` array in the API).
    pub names: Vec<String>,
    pub homepage: Option<String>,
    /// App bundle file names from `app` artifacts, e.g. `Slack.app`.
    pub app_names: Vec<String>,
    /// Bundle ids gleaned from `uninstall`/`zap` `quit:` stanzas.
    pub bundle_ids: Vec<String>,
}

/// The parsed catalog plus lookup indices for the three match rules.
///
/// Every index uses "ambiguity poisoning": a key claimed by two or more
/// distinct casks maps to `None` and never matches. This matters because a
/// match feeds a `brew install --cask --adopt` command — an arbitrary
/// first-cask-wins pick could install the wrong package (Homebrew genuinely
/// ships distinct casks sharing an `.app` filename: beta/variant families).
#[derive(Clone, Debug)]
pub struct CaskCatalog {
    data: Arc<CatalogData>,
    budget: Arc<MemoryBudget>,
}

#[derive(Debug)]
struct CatalogData {
    casks: Vec<CatalogCask>,
    /// lowercased bundle id → cask index (`None` = ambiguous, poisoned)
    bundle_index: HashMap<String, Option<usize>>,
    /// lowercased app file name → cask index (`None` = ambiguous, poisoned)
    app_index: HashMap<String, Option<usize>>,
    /// normalized name/token → cask index (`None` = ambiguous, poisoned)
    name_index: HashMap<String, Option<usize>>,
    _memory: Reservation,
}

/// Insert a key claiming `idx`, poisoning the slot if a different cask already
/// claimed it.
fn claim(index: &mut HashMap<String, Option<usize>>, key: String, idx: usize) {
    index
        .entry(key)
        .and_modify(|slot| {
            if *slot != Some(idx) {
                *slot = None;
            }
        })
        .or_insert(Some(idx));
}

impl CaskCatalog {
    /// Match an app to a cask, returning the cask and which rule fired. Rules are
    /// tried in priority order with exact equality: bundle id, then app file
    /// name, then normalized display name/token.
    pub fn match_app(
        &self,
        app_file_name: &str,
        display_name: &str,
        bundle_id: Option<&str>,
    ) -> Option<(&CatalogCask, &'static str)> {
        let bytes = app_file_name
            .len()
            .checked_add(display_name.len())?
            .checked_add(bundle_id.map(str::len).unwrap_or(0))?
            .checked_mul(12)?
            .checked_add(128)?;
        let _scratch = self.budget.reserve(bytes).ok()?;
        if let Some(bid) = bundle_id {
            let key = bid.to_lowercase();
            if let Some(Some(idx)) = self.data.bundle_index.get(&key) {
                return Some((&self.data.casks[*idx], "bundle_id"));
            }
        }
        let app_key = app_file_name.to_lowercase();
        if !app_key.is_empty() {
            if let Some(Some(idx)) = self.data.app_index.get(&app_key) {
                return Some((&self.data.casks[*idx], "app_name"));
            }
        }
        let name_key = normalize(display_name);
        if !name_key.is_empty() {
            if let Some(Some(idx)) = self.data.name_index.get(&name_key) {
                return Some((&self.data.casks[*idx], "name"));
            }
        }
        None
    }

    /// Number of casks retained (post-filter). Used in tests.
    pub fn len(&self) -> usize {
        self.data.casks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.casks.is_empty()
    }

    fn from_casks(casks: Vec<CatalogCask>, memory: Reservation, budget: Arc<MemoryBudget>) -> Self {
        let mut bundle_index: HashMap<String, Option<usize>> = HashMap::new();
        let mut app_index: HashMap<String, Option<usize>> = HashMap::new();
        let mut name_index: HashMap<String, Option<usize>> = HashMap::new();
        for (idx, cask) in casks.iter().enumerate() {
            for bid in &cask.bundle_ids {
                claim(&mut bundle_index, bid.to_lowercase(), idx);
            }
            for app in &cask.app_names {
                claim(&mut app_index, app.to_lowercase(), idx);
            }
            for name in cask.names.iter().chain(std::iter::once(&cask.token)) {
                let key = normalize(name);
                if key.is_empty() {
                    continue;
                }
                claim(&mut name_index, key, idx);
            }
        }
        CaskCatalog {
            data: Arc::new(CatalogData {
                casks,
                bundle_index,
                app_index,
                name_index,
                _memory: memory,
            }),
            budget,
        }
    }
}

/// Normalize a name/token for the fuzzy name rule: lowercase, drop a trailing
/// `.app`, then keep only alphanumerics. `"Visual Studio Code"` and
/// `"visual-studio-code"` both become `"visualstudiocode"`.
fn normalize(s: &str) -> String {
    let lower = s.trim().to_lowercase();
    let stripped = lower.strip_suffix(".app").unwrap_or(&lower);
    stripped.chars().filter(|c| c.is_alphanumeric()).collect()
}

/// Fetch the catalog at most once per run, sharing the parsed result in memory.
/// Offline, cancellation and failures never consult a persistent cache.
pub async fn load(
    fetcher: Option<&dyn HttpFetcher>,
    paths: &Paths,
    cfg: &NetworkConfig,
    token: &CancellationToken,
) -> Option<CaskCatalog> {
    if cfg.offline || token.is_cancelled() {
        return None;
    }
    let mut cached = tokio::select! {
        biased;
        _ = token.cancelled() => return None,
        cached = paths.catalog_cache.as_ref()?.value.lock() => cached,
    };
    if let Some(catalog) = cached.as_ref() {
        let catalog = catalog.clone();
        if paths.size_cache.memory_budget().reserve(4096).is_err() {
            cached.take();
        }
        return Some(catalog);
    }
    let response = fetcher?.get(CASK_URL, None, token).await.ok()?;
    if !response.ok() || token.is_cancelled() {
        return None;
    }
    let catalog = parse_catalog_with_budget(&response.body, paths.size_cache.memory_budget())?;
    *cached = Some(catalog.clone());
    Some(catalog)
}

/// Raw cask shape, lenient: unknown fields ignored, everything defaulted.
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawCask {
    token: String,
    name: Vec<String>,
    homepage: Option<String>,
    deprecated: bool,
    disabled: bool,
    artifacts: Vec<serde_json::Value>,
}

#[cfg(test)]
fn parse_catalog(body: &[u8]) -> Option<CaskCatalog> {
    parse_catalog_with_budget(body, MemoryBudget::shared())
}

fn parse_catalog_with_budget(body: &[u8], budget: Arc<MemoryBudget>) -> Option<CaskCatalog> {
    let memory = super::reserve_json(&budget, body)?;
    let raws: Vec<RawCask> = serde_json::from_slice(body).ok()?;
    let mut casks = Vec::with_capacity(raws.len());
    for raw in raws {
        if raw.deprecated || raw.disabled || raw.token.is_empty() {
            continue;
        }
        let (app_names, bundle_ids) = extract_artifacts(&raw.artifacts);
        casks.push(CatalogCask {
            token: raw.token,
            names: raw.name,
            homepage: raw.homepage,
            app_names,
            bundle_ids,
        });
    }
    Some(CaskCatalog::from_casks(casks, memory, budget))
}

/// Walk the `artifacts` array defensively: `app:` arrays yield app file names;
/// `uninstall:`/`zap:` stanzas' `quit:` (string or array) yield bundle ids.
fn extract_artifacts(artifacts: &[serde_json::Value]) -> (Vec<String>, Vec<String>) {
    let mut app_names = Vec::new();
    let mut bundle_ids = Vec::new();
    for art in artifacts {
        let Some(obj) = art.as_object() else {
            continue;
        };
        for (key, val) in obj {
            match key.as_str() {
                "app" => {
                    if let Some(arr) = val.as_array() {
                        for e in arr {
                            if let Some(s) = e.as_str() {
                                app_names.push(s.to_string());
                            }
                        }
                    }
                }
                "uninstall" | "zap" => {
                    if let Some(arr) = val.as_array() {
                        for stanza in arr {
                            if let Some(q) = stanza.as_object().and_then(|o| o.get("quit")) {
                                collect_quit(q, &mut bundle_ids);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    (app_names, bundle_ids)
}

fn collect_quit(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => {
            for e in a {
                if let Some(s) = e.as_str() {
                    out.push(s.to_string());
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::MockHttpFetcher;

    // One app+name cask, one uninstall-quit-as-STRING, one zap-quit-as-ARRAY,
    // one deprecated (excluded), one artifact-less (tolerated).
    const FIXTURE: &str = r#"[
        {
            "token": "slack",
            "name": ["Slack"],
            "homepage": "https://slack.com",
            "artifacts": [{"app": ["Slack.app"]}]
        },
        {
            "token": "whatsapp",
            "name": ["WhatsApp"],
            "homepage": "https://github.com/foo/whatsapp",
            "artifacts": [
                {"app": ["WhatsApp.app"]},
                {"uninstall": [{"quit": "com.whatsapp.desktop"}]}
            ]
        },
        {
            "token": "zoom",
            "name": ["Zoom"],
            "artifacts": [
                {"zap": [{"quit": ["us.zoom.xos", "us.zoom.aux"]}]}
            ]
        },
        {
            "token": "legacy",
            "name": ["Legacy"],
            "deprecated": true,
            "artifacts": [{"app": ["Legacy.app"]}]
        },
        {
            "token": "bare",
            "name": ["Bare"]
        }
    ]"#;

    fn catalog() -> CaskCatalog {
        parse_catalog(FIXTURE.as_bytes()).unwrap()
    }

    #[test]
    fn catalog_clones_share_budgeted_data_and_release_on_last_drop() {
        let budget = MemoryBudget::new(1024 * 1024);
        let catalog = parse_catalog_with_budget(FIXTURE.as_bytes(), budget.clone()).unwrap();
        let used = budget.used();
        assert!(used > 0);
        let cloned = catalog.clone();
        assert!(Arc::ptr_eq(&catalog.data, &cloned.data));
        assert_eq!(budget.used(), used);
        drop(catalog);
        assert_eq!(budget.used(), used);
        drop(cloned);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn catalog_budget_denial_and_malformed_json_release_all_charges() {
        let tiny = MemoryBudget::new(32);
        assert!(parse_catalog_with_budget(FIXTURE.as_bytes(), tiny.clone()).is_none());
        assert_eq!(tiny.used(), 0);
        let budget = MemoryBudget::new(1024 * 1024);
        assert!(parse_catalog_with_budget(br#"[{"token":"bad""#, budget.clone()).is_none());
        assert_eq!(budget.used(), 0);
        assert!(budget.peak() <= budget.limit());
    }

    #[tokio::test]
    async fn catalog_retention_is_evicted_under_shared_pressure() {
        let budget = MemoryBudget::new(1024 * 1024);
        let paths = Paths::with_memory_budget("/unused", budget.clone());
        let fetcher = MockHttpFetcher::new().on(CASK_URL, 200, None, CACHE_BODY);
        let token = CancellationToken::new();
        let cfg = NetworkConfig::default();
        let first = load(Some(&fetcher), &paths, &cfg, &token).await.unwrap();
        let pressure = budget.reserve(budget.limit() - budget.used()).unwrap();
        let second = load(Some(&fetcher), &paths, &cfg, &token).await.unwrap();
        assert!(Arc::ptr_eq(&first.data, &second.data));
        assert!(paths
            .catalog_cache
            .as_ref()
            .unwrap()
            .value
            .lock()
            .await
            .is_none());
        drop(first);
        assert!(budget.used() > pressure.bytes());
        drop(second);
        drop(pressure);
        drop(paths);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn parse_excludes_deprecated_and_tolerates_missing_artifacts() {
        let c = catalog();
        // slack, whatsapp, zoom, bare — legacy is deprecated.
        assert_eq!(c.len(), 4);
        assert!(c.match_app("Legacy.app", "Legacy", None).is_none());
        // bare has no artifacts but still matches by name.
        let (bare, rule) = c.match_app("", "Bare", None).unwrap();
        assert_eq!(bare.token, "bare");
        assert_eq!(rule, "name");
    }

    #[test]
    fn parses_quit_string_and_array() {
        let c = catalog();
        let (wa, _) = c.match_app("", "", Some("com.whatsapp.desktop")).unwrap();
        assert_eq!(wa.token, "whatsapp");
        let (z1, _) = c.match_app("", "", Some("us.zoom.xos")).unwrap();
        assert_eq!(z1.token, "zoom");
        let (z2, _) = c.match_app("", "", Some("us.zoom.aux")).unwrap();
        assert_eq!(z2.token, "zoom");
    }

    #[test]
    fn matches_each_rule() {
        let c = catalog();
        // bundle id
        let (m, rule) = c
            .match_app("Slack.app", "Slack", Some("com.whatsapp.desktop"))
            .unwrap();
        assert_eq!(rule, "bundle_id");
        assert_eq!(m.token, "whatsapp");
        // app file name (case-insensitive)
        let (m, rule) = c.match_app("slack.app", "Nonsense", None).unwrap();
        assert_eq!(rule, "app_name");
        assert_eq!(m.token, "slack");
        // normalized name
        let (m, rule) = c.match_app("no-such.app", "Zoom", None).unwrap();
        assert_eq!(rule, "name");
        assert_eq!(m.token, "zoom");
    }

    #[test]
    fn bundle_id_beats_name() {
        let c = catalog();
        // display name says "Slack" but bundle id says WhatsApp → bundle wins.
        let (m, rule) = c
            .match_app("", "Slack", Some("com.whatsapp.desktop"))
            .unwrap();
        assert_eq!(rule, "bundle_id");
        assert_eq!(m.token, "whatsapp");
    }

    #[test]
    fn hyphen_and_space_normalize_equal() {
        let body = r#"[
            {"token": "visual-studio-code", "name": ["Visual Studio Code"],
             "artifacts": [{"app": ["Visual Studio Code.app"]}]}
        ]"#;
        let c = parse_catalog(body.as_bytes()).unwrap();
        let (m, rule) = c.match_app("no.app", "Visual Studio Code", None).unwrap();
        assert_eq!(rule, "name");
        assert_eq!(m.token, "visual-studio-code");
    }

    #[test]
    fn ambiguous_normalized_name_never_matches() {
        // Two distinct casks whose names both normalize to "thing".
        let body = r#"[
            {"token": "foo", "name": ["Thing"]},
            {"token": "bar", "name": ["Thing"]}
        ]"#;
        let c = parse_catalog(body.as_bytes()).unwrap();
        assert!(c.match_app("x.app", "Thing", None).is_none());
        // But an unambiguous token still matches directly.
        let (m, _) = c.match_app("", "foo", None).unwrap();
        assert_eq!(m.token, "foo");
    }

    /// Regression: poisoning must apply to ALL indexes, not just names. Two
    /// casks sharing an `.app` filename (beta/variant families exist in the
    /// real catalog) or a `quit:` bundle id must never yield an arbitrary
    /// first-cask-wins match — a wrong match feeds `brew install --adopt`.
    #[test]
    fn ambiguous_app_name_and_bundle_id_never_match() {
        let body = r#"[
            {"token": "tool", "name": ["Tool"],
             "artifacts": [{"app": ["Tool.app"]},
                           {"uninstall": [{"quit": "com.example.tool"}]}]},
            {"token": "tool-beta", "name": ["Tool Beta"],
             "artifacts": [{"app": ["Tool.app"]},
                           {"uninstall": [{"quit": "com.example.tool"}]}]}
        ]"#;
        let c = parse_catalog(body.as_bytes()).unwrap();
        // Shared app filename: poisoned.
        assert!(c.match_app("Tool.app", "zzz", None).is_none());
        // Shared bundle id: poisoned.
        assert!(c
            .match_app("zzz.app", "zzz", Some("com.example.tool"))
            .is_none());
        // Unambiguous name rules still work for each cask.
        assert_eq!(c.match_app("", "Tool", None).unwrap().0.token, "tool");
        assert_eq!(
            c.match_app("", "Tool Beta", None).unwrap().0.token,
            "tool-beta"
        );
    }

    const CACHE_BODY: &str = r#"[{"token":"slack","name":["Slack"],
        "artifacts":[{"app":["Slack.app"]}]}]"#;

    fn seed_legacy_files(paths: &Paths) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        std::fs::create_dir_all(&paths.cache_dir).unwrap();
        [
            ("cask.json", CACHE_BODY),
            (
                "cask.json.meta",
                r#"{"etag":"legacy","fetched_at":18446744073709551615}"#,
            ),
            ("cask.json.tmp", "existing temporary artifact"),
        ]
        .into_iter()
        .map(|(name, contents)| {
            let file = paths.cache_dir.join(name);
            std::fs::write(&file, contents).unwrap();
            (file, contents.as_bytes().to_vec())
        })
        .collect()
    }

    #[tokio::test]
    async fn legacy_files_are_ignored_and_untouched() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        let legacy = seed_legacy_files(&paths);
        let body = CACHE_BODY.replace("slack", "new");
        let fetcher = MockHttpFetcher::new().on(CASK_URL, 200, Some("new-etag"), &body);
        let catalog = load(
            Some(&fetcher),
            &paths,
            &NetworkConfig::default(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(catalog.data.casks[0].token, "new");
        assert_eq!(fetcher.calls(), vec![(CASK_URL.to_string(), None)]);
        for (file, contents) in legacy {
            assert_eq!(std::fs::read(file).unwrap(), contents);
        }
        assert_eq!(std::fs::read_dir(&paths.cache_dir).unwrap().count(), 3);
    }

    #[tokio::test]
    async fn catalog_is_shared_in_memory_and_isolated_between_runs() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        let fetcher = MockHttpFetcher::new().on(CASK_URL, 200, None, CACHE_BODY);
        let cfg = NetworkConfig::default();
        for _ in 0..2 {
            assert_eq!(
                load(
                    Some(&fetcher),
                    &paths.clone(),
                    &cfg,
                    &CancellationToken::new()
                )
                .await
                .unwrap()
                .len(),
                1
            );
        }
        assert_eq!(fetcher.calls().len(), 1);
        let next_run = paths.with_fresh_measurements();
        assert!(load(None, &next_run, &cfg, &CancellationToken::new())
            .await
            .is_none());
        assert!(!paths.cache_dir.exists());
    }

    #[tokio::test]
    async fn offline_cancellation_and_failures_never_serve_legacy_cache() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        let legacy = seed_legacy_files(&paths);
        let cfg = NetworkConfig::default();
        let offline = NetworkConfig {
            offline: true,
            ..cfg.clone()
        };
        let fetcher = MockHttpFetcher::new().on(CASK_URL, 200, None, CACHE_BODY);
        assert!(
            load(Some(&fetcher), &paths, &offline, &CancellationToken::new())
                .await
                .is_none()
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(load(Some(&fetcher), &paths, &cfg, &cancelled)
            .await
            .is_none());
        assert!(load(None, &paths, &cfg, &CancellationToken::new())
            .await
            .is_none());
        assert!(fetcher.calls().is_empty());
        for failing in [
            MockHttpFetcher::new().on_err(CASK_URL),
            MockHttpFetcher::new().on(CASK_URL, 304, None, ""),
            MockHttpFetcher::new().on(CASK_URL, 200, None, "not json"),
            MockHttpFetcher::new().on(CASK_URL, 500, None, CACHE_BODY),
        ] {
            assert!(
                load(Some(&failing), &paths, &cfg, &CancellationToken::new())
                    .await
                    .is_none()
            );
        }
        for (file, contents) in legacy {
            assert_eq!(std::fs::read(file).unwrap(), contents);
        }
    }
}
