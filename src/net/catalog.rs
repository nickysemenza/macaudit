//! The Homebrew cask catalog (`formulae.brew.sh/api/cask.json`), cached to disk
//! and used to match Unmanaged apps to an available cask (spec M7).
//!
//! Every failure mode degrades to `None` — a missing/corrupt cache, a transport
//! error, an unparseable body, or offline with no cache all just mean "no
//! catalog", never an error that fails the scan. When online and the cache is
//! stale we revalidate with `If-None-Match` so a 304 costs nothing but a bumped
//! timestamp.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::config::{NetworkConfig, Paths};
use crate::net::HttpFetcher;

const CASK_URL: &str = "https://formulae.brew.sh/api/cask.json";
const BODY_FILE: &str = "cask.json";
const META_FILE: &str = "cask.json.meta";

/// One cask distilled to just what matching needs.
#[derive(Clone, Debug)]
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
    casks: Vec<CatalogCask>,
    /// lowercased bundle id → cask index (`None` = ambiguous, poisoned)
    bundle_index: HashMap<String, Option<usize>>,
    /// lowercased app file name → cask index (`None` = ambiguous, poisoned)
    app_index: HashMap<String, Option<usize>>,
    /// normalized name/token → cask index (`None` = ambiguous, poisoned)
    name_index: HashMap<String, Option<usize>>,
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
        if let Some(bid) = bundle_id {
            let key = bid.to_lowercase();
            if let Some(Some(idx)) = self.bundle_index.get(&key) {
                return Some((&self.casks[*idx], "bundle_id"));
            }
        }
        let app_key = app_file_name.to_lowercase();
        if !app_key.is_empty() {
            if let Some(Some(idx)) = self.app_index.get(&app_key) {
                return Some((&self.casks[*idx], "app_name"));
            }
        }
        let name_key = normalize(display_name);
        if !name_key.is_empty() {
            if let Some(Some(idx)) = self.name_index.get(&name_key) {
                return Some((&self.casks[*idx], "name"));
            }
        }
        None
    }

    /// Number of casks retained (post-filter). Used in tests.
    pub fn len(&self) -> usize {
        self.casks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.casks.is_empty()
    }

    fn from_casks(casks: Vec<CatalogCask>) -> Self {
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
            let mut keys: Vec<String> = cask.names.iter().map(|n| normalize(n)).collect();
            keys.push(normalize(&cask.token));
            for key in keys {
                if key.is_empty() {
                    continue;
                }
                claim(&mut name_index, key, idx);
            }
        }
        CaskCatalog {
            casks,
            bundle_index,
            app_index,
            name_index,
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

/// Load the catalog: fresh cache served with zero network; stale cache
/// revalidated online; offline serves any cache (even stale) or `None`.
pub async fn load(
    fetcher: Option<&dyn HttpFetcher>,
    paths: &Paths,
    cfg: &NetworkConfig,
    token: &CancellationToken,
) -> Option<CaskCatalog> {
    let body_path = paths.cache_dir.join(BODY_FILE);
    let meta_path = paths.cache_dir.join(META_FILE);
    let now = now_secs();
    let max_age = cfg.catalog_max_age_days.saturating_mul(86_400);

    // Any read/parse failure is a cache miss.
    let cached = read_cache(&body_path, &meta_path);

    // Fresh enough → serve without touching the network.
    if let Some((catalog, meta)) = &cached {
        if now.saturating_sub(meta.fetched_at) < max_age {
            return Some(catalog.clone());
        }
    }

    // Offline: whatever we have (even stale), or nothing.
    let Some(fetcher) = fetcher else {
        return cached.map(|(c, _)| c);
    };
    if token.is_cancelled() {
        return cached.map(|(c, _)| c);
    }

    let etag = cached.as_ref().and_then(|(_, m)| m.etag.clone());
    match fetcher.get(CASK_URL, etag.as_deref(), token).await {
        Ok(resp) if resp.not_modified() => {
            // Cache is still current: bump fetched_at, serve it.
            match cached {
                Some((catalog, meta)) => {
                    write_meta(
                        &meta_path,
                        &CacheMeta {
                            etag: meta.etag,
                            fetched_at: now,
                        },
                    );
                    Some(catalog)
                }
                None => None,
            }
        }
        Ok(resp) if resp.ok() => match parse_catalog(&resp.body) {
            Some(catalog) => {
                // Body first, then meta, so a crash never leaves meta pointing
                // at a body that isn't there yet.
                write_body(&body_path, &resp.body);
                write_meta(
                    &meta_path,
                    &CacheMeta {
                        etag: resp.etag.clone(),
                        fetched_at: now,
                    },
                );
                Some(catalog)
            }
            None => cached.map(|(c, _)| c),
        },
        // Transport error or any other status: serve stale cache if we have one.
        _ => cached.map(|(c, _)| c),
    }
}

/// On-disk sidecar next to the cached body.
#[derive(Serialize, Deserialize, Default)]
struct CacheMeta {
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    fetched_at: u64,
}

fn read_cache(body_path: &Path, meta_path: &Path) -> Option<(CaskCatalog, CacheMeta)> {
    let body = std::fs::read(body_path).ok()?;
    let meta_str = std::fs::read_to_string(meta_path).ok()?;
    let meta: CacheMeta = serde_json::from_str(&meta_str).ok()?;
    let catalog = parse_catalog(&body)?;
    Some((catalog, meta))
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

fn parse_catalog(body: &[u8]) -> Option<CaskCatalog> {
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
    Some(CaskCatalog::from_casks(casks))
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

fn write_body(path: &Path, bytes: &[u8]) {
    write_atomic(path, bytes);
}

fn write_meta(path: &Path, meta: &CacheMeta) {
    if let Ok(bytes) = serde_json::to_vec(meta) {
        write_atomic(path, &bytes);
    }
}

/// Write via a process-unique sibling `.tmp` then rename, so readers never see
/// a partial file and two concurrent enrichment tasks can't tear each other's
/// tmp file. Best-effort: any error is swallowed (caching is a nicety).
fn write_atomic(path: &Path, bytes: &[u8]) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp.{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    if std::fs::write(&tmp, bytes).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    // ---- cache behavior ----

    const CACHE_BODY: &str = r#"[{"token":"slack","name":["Slack"],
        "artifacts":[{"app":["Slack.app"]}]}]"#;

    fn paths(home: &Path) -> Paths {
        Paths::from_home(home)
    }

    fn seed_cache(p: &Paths, body: &str, etag: Option<&str>, fetched_at: u64) {
        let dir = &p.cache_dir;
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(BODY_FILE), body).unwrap();
        let meta = serde_json::json!({ "etag": etag, "fetched_at": fetched_at });
        std::fs::write(dir.join(META_FILE), meta.to_string()).unwrap();
    }

    fn read_meta(p: &Paths) -> CacheMeta {
        let s = std::fs::read_to_string(p.cache_dir.join(META_FILE)).unwrap();
        serde_json::from_str(&s).unwrap()
    }

    #[tokio::test]
    async fn fresh_cache_serves_without_network() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        seed_cache(&p, CACHE_BODY, Some("v1"), now_secs());
        let fetcher = MockHttpFetcher::new(); // no responses registered
        let cfg = NetworkConfig::default();
        let cat = load(Some(&fetcher), &p, &cfg, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(cat.len(), 1);
        assert!(fetcher.calls().is_empty());
    }

    #[tokio::test]
    async fn stale_cache_revalidates_and_304_refreshes() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        let old = now_secs() - 30 * 86_400;
        seed_cache(&p, CACHE_BODY, Some("etag-abc"), old);
        let fetcher = MockHttpFetcher::new().on(CASK_URL, 304, None, "");
        let cfg = NetworkConfig::default();
        let cat = load(Some(&fetcher), &p, &cfg, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(cat.len(), 1);
        // GET carried If-None-Match with the stored etag.
        assert_eq!(
            fetcher.calls(),
            vec![(CASK_URL.to_string(), Some("etag-abc".to_string()))]
        );
        // fetched_at bumped; etag preserved.
        let meta = read_meta(&p);
        assert!(meta.fetched_at > old);
        assert_eq!(meta.etag.as_deref(), Some("etag-abc"));
    }

    #[tokio::test]
    async fn stale_cache_200_rewrites_body_and_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        seed_cache(&p, CACHE_BODY, Some("old"), now_secs() - 30 * 86_400);
        let new_body = r#"[{"token":"newcask","name":["NewCask"],
            "artifacts":[{"app":["NewCask.app"]}]}]"#;
        let fetcher = MockHttpFetcher::new().on(CASK_URL, 200, Some("new-etag"), new_body);
        let cfg = NetworkConfig::default();
        let cat = load(Some(&fetcher), &p, &cfg, &CancellationToken::new())
            .await
            .unwrap();
        // Served the NEW body.
        let (m, _) = cat.match_app("NewCask.app", "NewCask", None).unwrap();
        assert_eq!(m.token, "newcask");
        // Body + meta rewritten on disk.
        let on_disk = std::fs::read_to_string(p.cache_dir.join(BODY_FILE)).unwrap();
        assert!(on_disk.contains("newcask"));
        assert_eq!(read_meta(&p).etag.as_deref(), Some("new-etag"));
    }

    #[tokio::test]
    async fn corrupt_meta_forces_refetch_without_etag() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        std::fs::create_dir_all(&p.cache_dir).unwrap();
        std::fs::write(p.cache_dir.join(BODY_FILE), CACHE_BODY).unwrap();
        std::fs::write(p.cache_dir.join(META_FILE), "}{ not json").unwrap();
        let fetcher = MockHttpFetcher::new().on(CASK_URL, 200, Some("e"), CACHE_BODY);
        let cfg = NetworkConfig::default();
        let cat = load(Some(&fetcher), &p, &cfg, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(cat.len(), 1);
        // No usable cache ⇒ no If-None-Match.
        assert_eq!(fetcher.calls(), vec![(CASK_URL.to_string(), None)]);
    }

    #[tokio::test]
    async fn offline_serves_stale_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        seed_cache(&p, CACHE_BODY, Some("v1"), now_secs() - 90 * 86_400);
        let cfg = NetworkConfig::default();
        let cat = load(None, &p, &cfg, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(cat.len(), 1);
    }

    #[tokio::test]
    async fn offline_no_cache_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        let cfg = NetworkConfig::default();
        assert!(load(None, &p, &cfg, &CancellationToken::new())
            .await
            .is_none());
    }

    #[tokio::test]
    async fn transport_error_serves_stale_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        seed_cache(&p, CACHE_BODY, Some("v1"), now_secs() - 30 * 86_400);
        let fetcher = MockHttpFetcher::new().on_err(CASK_URL);
        let cfg = NetworkConfig::default();
        let cat = load(Some(&fetcher), &p, &cfg, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(cat.len(), 1);
        assert_eq!(fetcher.calls().len(), 1);
    }
}
