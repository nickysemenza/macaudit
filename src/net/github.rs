//! GitHub-releases "is there a newer version?" checks for matched apps whose
//! cask homepage is a GitHub repo (spec M7).
//!
//! Best-effort and rate-conscious: results (positive and negative) are cached to
//! one JSON map on disk, network fetches are capped per scan, and any 403/429
//! latches off all further GitHub traffic for the rest of the scan. Everything
//! degrades to "no newer version known".

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::config::NetworkConfig;
use crate::net::HttpFetcher;

const CACHE_FILE: &str = "github_releases.json";

/// Parse `https://github.com/{owner}/{repo}` (trailing slash tolerated). Deeper
/// paths and other hosts are rejected.
pub fn parse_github_repo(homepage: &str) -> Option<(String, String)> {
    let rest = homepage.strip_prefix("https://github.com/")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let mut parts = rest.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    if owner.is_empty() || repo.is_empty() || parts.next().is_some() {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

/// Is `latest_tag` a strictly newer version than `current`? Both are reduced to
/// their first whitespace token, one leading `v`/`V` stripped, then split on `.`
/// into u64 segments (missing trailing segments count as 0). Any non-numeric
/// segment ⇒ `false` (we don't guess about date tags or funky schemes).
pub fn is_newer(latest_tag: &str, current: &str) -> bool {
    match (parse_version(latest_tag), parse_version(current)) {
        (Some(l), Some(c)) => version_gt(&l, &c),
        _ => false,
    }
}

fn parse_version(s: &str) -> Option<Vec<u64>> {
    let tok = s.split_whitespace().next()?;
    let tok = tok
        .strip_prefix('v')
        .or_else(|| tok.strip_prefix('V'))
        .unwrap_or(tok);
    if tok.is_empty() {
        return None;
    }
    let mut segs = Vec::new();
    for part in tok.split('.') {
        segs.push(part.parse::<u64>().ok()?);
    }
    Some(segs)
}

fn version_gt(a: &[u64], b: &[u64]) -> bool {
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

/// One cached release lookup. Negative results (404/403/…) are cached too so we
/// don't re-hammer a repo with no releases.
#[derive(Serialize, Deserialize, Clone)]
struct ReleaseEntry {
    tag: Option<String>,
    status: u16,
    fetched_at: u64,
}

/// Per-scan GitHub release checker: owns the on-disk cache map, enforces the
/// fetch cap, and latches off on rate-limit responses.
pub struct GithubChecker {
    path: PathBuf,
    cache: HashMap<String, ReleaseEntry>,
    ttl_secs: u64,
    max_fetches: usize,
    fetches_done: usize,
    latched_off: bool,
    dirty: bool,
}

impl GithubChecker {
    /// Load the cache map from `cache_dir/github_releases.json` (empty on any
    /// failure).
    pub fn load(cache_dir: &Path, cfg: &NetworkConfig) -> Self {
        let path = cache_dir.join(CACHE_FILE);
        let cache = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        GithubChecker {
            path,
            cache,
            ttl_secs: cfg.github_cache_ttl_hours.saturating_mul(3_600),
            max_fetches: cfg.github_max_checks_per_scan,
            fetches_done: 0,
            latched_off: false,
            dirty: false,
        }
    }

    /// The latest release tag for `owner/repo`, or `None`. Serves fresh cache
    /// entries (including negative ones) for free; otherwise spends one of the
    /// scan's network budget unless the budget is exhausted or GitHub traffic is
    /// latched off.
    pub async fn latest_tag(
        &mut self,
        owner: &str,
        repo: &str,
        fetcher: &dyn HttpFetcher,
        token: &CancellationToken,
    ) -> Option<String> {
        let key = format!("{owner}/{repo}");
        let now = now_secs();

        if let Some(entry) = self.cache.get(&key) {
            if now.saturating_sub(entry.fetched_at) < self.ttl_secs {
                return entry.tag.clone();
            }
        }

        if self.latched_off || self.fetches_done >= self.max_fetches || token.is_cancelled() {
            return None;
        }
        self.fetches_done += 1;

        let url = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
        match fetcher.get(&url, None, token).await {
            Ok(resp) => {
                let status = resp.status;
                if status == 403 || status == 429 {
                    // Rate limited: record the negative result, then stop all
                    // further GitHub network traffic this scan.
                    self.latched_off = true;
                    self.record(&key, None, status, now);
                    return None;
                }
                let tag = if resp.ok() {
                    parse_tag(&resp.body)
                } else {
                    None
                };
                self.record(&key, tag.clone(), status, now);
                tag
            }
            // Transport error: not cached (might be transient), just no result.
            Err(_) => None,
        }
    }

    /// Persist the cache map once, atomically, if anything changed.
    pub fn save(&self) {
        if !self.dirty {
            return;
        }
        if let Ok(bytes) = serde_json::to_vec(&self.cache) {
            write_atomic(&self.path, &bytes);
        }
    }

    fn record(&mut self, key: &str, tag: Option<String>, status: u16, now: u64) {
        self.cache.insert(
            key.to_string(),
            ReleaseEntry {
                tag,
                status,
                fetched_at: now,
            },
        );
        self.dirty = true;
    }
}

fn parse_tag(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.get("tag_name")?.as_str().map(|s| s.to_string())
}

/// Process-unique tmp suffix so concurrent enrichment tasks can't tear each
/// other's in-progress write (see catalog.rs's twin).
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

    #[test]
    fn parse_repo_accepts_exact_and_trailing_slash() {
        assert_eq!(
            parse_github_repo("https://github.com/owner/repo"),
            Some(("owner".to_string(), "repo".to_string()))
        );
        assert_eq!(
            parse_github_repo("https://github.com/owner/repo/"),
            Some(("owner".to_string(), "repo".to_string()))
        );
    }

    #[test]
    fn parse_repo_rejects_deep_paths_and_other_hosts() {
        assert!(parse_github_repo("https://github.com/owner/repo/tree/main").is_none());
        assert!(parse_github_repo("https://github.com/owner").is_none());
        assert!(parse_github_repo("https://gitlab.com/owner/repo").is_none());
        assert!(parse_github_repo("http://github.com/owner/repo").is_none());
        assert!(parse_github_repo("https://github.com/").is_none());
    }

    #[test]
    fn is_newer_table() {
        assert!(!is_newer("1.2.3", "1.2.3"));
        assert!(!is_newer("v1.2.3", "1.2.3"));
        assert!(is_newer("1.10", "1.9"));
        assert!(is_newer("2.0", "1.9.9"));
        assert!(is_newer("1.2.3", "1.2")); // missing trailing = 0
        assert!(!is_newer("1.2", "1.2.3"));
        assert!(is_newer("1.2.3 (456)", "1.2.2")); // first whitespace token
        assert!(!is_newer("1.2.3", "1.2.3 (999)"));
        assert!(!is_newer("2021-05-01", "2020-01-01")); // date tags ⇒ false
        assert!(!is_newer("nightly", "1.0.0"));
        assert!(is_newer("V2", "v1"));
    }

    fn cfg(max: usize) -> NetworkConfig {
        NetworkConfig {
            offline: false,
            catalog_max_age_days: 7,
            github_max_checks_per_scan: max,
            github_cache_ttl_hours: 72,
        }
    }

    fn rel(tag: &str) -> String {
        format!(r#"{{"tag_name": "{tag}"}}"#)
    }

    #[tokio::test]
    async fn rate_limit_latches_off_further_calls() {
        let tmp = tempfile::tempdir().unwrap();
        let url1 = "https://api.github.com/repos/a/one/releases/latest";
        let url2 = "https://api.github.com/repos/b/two/releases/latest";
        let fetcher =
            MockHttpFetcher::new()
                .on(url1, 403, None, "")
                .on(url2, 200, None, &rel("v9.9.9"));
        let mut ck = GithubChecker::load(tmp.path(), &cfg(10));
        let token = CancellationToken::new();
        assert_eq!(ck.latest_tag("a", "one", &fetcher, &token).await, None);
        // Latched: the second repo is never fetched.
        assert_eq!(ck.latest_tag("b", "two", &fetcher, &token).await, None);
        assert_eq!(fetcher.calls().len(), 1);
    }

    #[tokio::test]
    async fn fetch_cap_is_enforced() {
        let tmp = tempfile::tempdir().unwrap();
        let url1 = "https://api.github.com/repos/a/one/releases/latest";
        let url2 = "https://api.github.com/repos/b/two/releases/latest";
        let fetcher = MockHttpFetcher::new()
            .on(url1, 200, None, &rel("v1.0.0"))
            .on(url2, 200, None, &rel("v2.0.0"));
        let mut ck = GithubChecker::load(tmp.path(), &cfg(1));
        let token = CancellationToken::new();
        assert_eq!(
            ck.latest_tag("a", "one", &fetcher, &token).await,
            Some("v1.0.0".to_string())
        );
        // Budget exhausted → no second network call.
        assert_eq!(ck.latest_tag("b", "two", &fetcher, &token).await, None);
        assert_eq!(fetcher.calls().len(), 1);
    }

    #[tokio::test]
    async fn fresh_negative_cache_is_respected() {
        let tmp = tempfile::tempdir().unwrap();
        // Seed a fresh negative (404) entry.
        let map = serde_json::json!({
            "a/one": { "tag": null, "status": 404, "fetched_at": now_secs() }
        });
        std::fs::write(tmp.path().join(CACHE_FILE), map.to_string()).unwrap();
        let fetcher = MockHttpFetcher::new(); // nothing registered
        let mut ck = GithubChecker::load(tmp.path(), &cfg(10));
        let token = CancellationToken::new();
        assert_eq!(ck.latest_tag("a", "one", &fetcher, &token).await, None);
        assert!(fetcher.calls().is_empty());
    }

    #[tokio::test]
    async fn positive_result_is_cached_and_saved() {
        let tmp = tempfile::tempdir().unwrap();
        let url = "https://api.github.com/repos/a/one/releases/latest";
        let fetcher = MockHttpFetcher::new().on(url, 200, None, &rel("v3.1.4"));
        let mut ck = GithubChecker::load(tmp.path(), &cfg(10));
        let token = CancellationToken::new();
        assert_eq!(
            ck.latest_tag("a", "one", &fetcher, &token).await,
            Some("v3.1.4".to_string())
        );
        ck.save();
        // A fresh checker serves it from disk without any network call.
        let fetcher2 = MockHttpFetcher::new();
        let mut ck2 = GithubChecker::load(tmp.path(), &cfg(10));
        assert_eq!(
            ck2.latest_tag("a", "one", &fetcher2, &token).await,
            Some("v3.1.4".to_string())
        );
        assert!(fetcher2.calls().is_empty());
    }
}
