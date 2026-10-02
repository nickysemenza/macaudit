//! GitHub-releases "is there a newer version?" checks for matched apps whose
//! cask homepage is a GitHub repo (spec M7).
//!
//! Best-effort and rate-conscious: results (positive and negative) stay in
//! bounded run-owned memory, network fetches are capped per scan, and any 403/429
//! latches off all further GitHub traffic for the rest of the scan. Everything
//! degrades to "no newer version known".

use std::path::Path;

use tokio_util::sync::CancellationToken;

use crate::config::NetworkConfig;
use crate::net::HttpFetcher;

const MAX_CACHE_ENTRIES: usize = 4096;
const MAX_TAG_BYTES: usize = 4096;

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

#[derive(Debug)]
struct TagData {
    tag: String,
    _memory: crate::inventory::Reservation,
}

#[derive(Clone, Debug)]
pub struct ReleaseTag(std::sync::Arc<TagData>);

impl std::ops::Deref for ReleaseTag {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0.tag
    }
}

impl std::fmt::Display for ReleaseTag {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(self)
    }
}

impl serde::Serialize for ReleaseTag {
    fn serialize<Serializer: serde::Serializer>(
        &self,
        serializer: Serializer,
    ) -> Result<Serializer::Ok, Serializer::Error> {
        serializer.serialize_str(self)
    }
}

impl PartialEq for ReleaseTag {
    fn eq(&self, other: &Self) -> bool {
        self.0.tag == other.0.tag
    }
}

struct CacheEntry {
    tag: Option<ReleaseTag>,
    sequence: u64,
    _memory: crate::inventory::Reservation,
}

/// Bounded release metadata owned only by this run.
pub struct GithubChecker {
    cache: std::collections::BTreeMap<String, CacheEntry>,
    budget: std::sync::Arc<crate::inventory::MemoryBudget>,
    max_fetches: usize,
    fetches_done: usize,
    sequence: u64,
    latched_off: bool,
}

impl GithubChecker {
    pub fn new(cfg: &NetworkConfig) -> Self {
        Self::with_budget(cfg, crate::inventory::MemoryBudget::shared())
    }

    pub fn with_budget(
        cfg: &NetworkConfig,
        budget: std::sync::Arc<crate::inventory::MemoryBudget>,
    ) -> Self {
        Self {
            cache: std::collections::BTreeMap::new(),
            budget,
            max_fetches: cfg.github_max_checks_per_scan,
            fetches_done: 0,
            sequence: 0,
            latched_off: cfg.offline,
        }
    }

    pub fn load(_cache_dir: &Path, cfg: &NetworkConfig) -> Self {
        Self::new(cfg)
    }

    pub async fn latest_tag(
        &mut self,
        owner: &str,
        repo: &str,
        fetcher: &dyn HttpFetcher,
        token: &CancellationToken,
    ) -> Option<ReleaseTag> {
        if token.is_cancelled() {
            return None;
        }
        let key_bytes = owner.len().checked_add(repo.len())?.checked_add(1)?;
        if key_bytes > MAX_TAG_BYTES {
            return None;
        }
        let _scratch = self.reserve(key_bytes.checked_mul(2)?.checked_add(128)?)?;
        let key = format!("{owner}/{repo}");
        if let Some(entry) = self.cache.get(&key) {
            return entry.tag.clone();
        }
        if self.latched_off || self.fetches_done >= self.max_fetches || token.is_cancelled() {
            return None;
        }
        self.fetches_done += 1;
        let url = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
        let response = fetcher.get(&url, None, token).await.ok()?;
        if token.is_cancelled() {
            return None;
        }
        if response.status == 403 || response.status == 429 {
            self.latched_off = true;
            self.record(&key, None);
            return None;
        }
        let tag = if response.ok() {
            let memory = loop {
                if let Some(memory) = super::reserve_json(&self.budget, &response.body) {
                    break Some(memory);
                }
                if !self.evict_oldest() {
                    break None;
                }
            }?;
            parse_tag(&response.body, memory, &self.budget)
        } else {
            None
        };
        self.record(&key, tag.clone());
        tag
    }

    fn evict_oldest(&mut self) -> bool {
        let Some(sequence) = self.cache.values().map(|entry| entry.sequence).min() else {
            return false;
        };
        self.cache.retain(|_, entry| entry.sequence != sequence);
        if self.cache.is_empty() {
            self.cache = std::collections::BTreeMap::new();
        }
        true
    }

    fn reserve(&mut self, bytes: usize) -> Option<crate::inventory::Reservation> {
        loop {
            if let Ok(memory) = self.budget.reserve(bytes) {
                return Some(memory);
            }
            if !self.evict_oldest() {
                return None;
            }
        }
    }

    fn record(&mut self, key: &str, tag: Option<ReleaseTag>) {
        if key.len() > MAX_TAG_BYTES {
            return;
        }
        self.cache.remove(key);
        if self.cache.is_empty() {
            self.cache = std::collections::BTreeMap::new();
        }
        while self.cache.len() >= MAX_CACHE_ENTRIES {
            self.evict_oldest();
        }
        let bytes = key
            .len()
            .saturating_add(std::mem::size_of::<(String, CacheEntry)>().saturating_mul(16))
            .saturating_add(256);
        let Some(memory) = self.reserve(bytes) else {
            return;
        };
        self.sequence = self.sequence.saturating_add(1);
        self.cache.insert(
            key.to_string(),
            CacheEntry {
                tag,
                sequence: self.sequence,
                _memory: memory,
            },
        );
    }
}

fn parse_tag(
    body: &[u8],
    _scratch: crate::inventory::Reservation,
    budget: &std::sync::Arc<crate::inventory::MemoryBudget>,
) -> Option<ReleaseTag> {
    #[derive(serde::Deserialize)]
    struct Release<'tag> {
        #[serde(borrow)]
        tag_name: std::borrow::Cow<'tag, str>,
    }
    let release: Release<'_> = serde_json::from_slice(body).ok()?;
    if release.tag_name.len() > MAX_TAG_BYTES {
        return None;
    }
    let memory = budget
        .reserve(
            release
                .tag_name
                .len()
                .checked_add(std::mem::size_of::<TagData>() + 64)?,
        )
        .ok()?;
    Some(ReleaseTag(std::sync::Arc::new(TagData {
        tag: release.tag_name.into_owned(),
        _memory: memory,
    })))
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
            github_max_checks_per_scan: max,
        }
    }

    #[tokio::test]
    async fn returned_tags_retain_charges_after_checker_drop() {
        let budget = crate::inventory::MemoryBudget::new(128 * 1024);
        let mut checker = GithubChecker::with_budget(&cfg(10), budget.clone());
        let fetcher = MockHttpFetcher::new().on(
            "https://api.github.com/repos/a/one/releases/latest",
            200,
            None,
            &rel("v2"),
        );
        let tag = checker
            .latest_tag("a", "one", &fetcher, &CancellationToken::new())
            .await
            .unwrap();
        let used = budget.used();
        let cached = checker
            .latest_tag("a", "one", &fetcher, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(budget.used(), used);
        assert!(std::sync::Arc::ptr_eq(&tag.0, &cached.0));
        drop(checker);
        assert!(budget.used() > 0);
        drop(tag);
        assert!(budget.used() > 0);
        drop(cached);
        assert_eq!(budget.used(), 0);
        assert_eq!(fetcher.calls().len(), 1);
    }

    #[tokio::test]
    async fn budget_denial_happens_before_network_and_old_entries_are_evicted() {
        let budget = crate::inventory::MemoryBudget::new(16 * 1024);
        let mut checker = GithubChecker::with_budget(&cfg(10), budget.clone());
        checker.record("a/one", None);
        let pressure = budget.reserve(budget.limit() - budget.used()).unwrap();
        checker.record("b/two", None);
        assert!(!checker.cache.contains_key("a/one"));
        assert!(checker.cache.contains_key("b/two"));
        drop(checker);
        drop(pressure);
        assert_eq!(budget.used(), 0);
        let tiny = crate::inventory::MemoryBudget::new(0);
        let mut checker = GithubChecker::with_budget(&cfg(10), tiny.clone());
        let fetcher = MockHttpFetcher::new();
        assert!(checker
            .latest_tag("a", "one", &fetcher, &CancellationToken::new())
            .await
            .is_none());
        assert!(fetcher.calls().is_empty());
        assert_eq!(tiny.used(), 0);
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
            ck.latest_tag("a", "one", &fetcher, &token).await.as_deref(),
            Some("v1.0.0")
        );
        // Budget exhausted → no second network call.
        assert_eq!(ck.latest_tag("b", "two", &fetcher, &token).await, None);
        assert_eq!(fetcher.calls().len(), 1);
    }

    #[tokio::test]
    async fn negative_results_are_reused_only_in_memory() {
        let cfg = cfg(10);
        let fetcher = MockHttpFetcher::new().on(
            "https://api.github.com/repos/a/one/releases/latest",
            404,
            None,
            "",
        );
        let mut checker = GithubChecker::new(&cfg);
        let token = CancellationToken::new();
        for _ in 0..2 {
            assert_eq!(checker.latest_tag("a", "one", &fetcher, &token).await, None);
        }
        assert_eq!(fetcher.calls().len(), 1);
    }

    #[tokio::test]
    async fn positive_results_are_run_owned_and_legacy_files_untouched() {
        let home = tempfile::tempdir().unwrap();
        let file = home.path().join("github_releases.json");
        let legacy = r#"{"a/one":{"tag":"v9.9.9","status":200,"fetched_at":18446744073709551615}}"#;
        std::fs::write(&file, legacy).unwrap();
        let url = "https://api.github.com/repos/a/one/releases/latest";
        let fetcher = MockHttpFetcher::new().on(url, 200, None, &rel("v3.1.4"));
        let mut checker = GithubChecker::load(home.path(), &cfg(10));
        let token = CancellationToken::new();
        for _ in 0..2 {
            assert_eq!(
                checker
                    .latest_tag("a", "one", &fetcher, &token)
                    .await
                    .as_deref(),
                Some("v3.1.4")
            );
        }
        assert_eq!(fetcher.calls().len(), 1);
        let fetcher2 = MockHttpFetcher::new().on(url, 200, None, &rel("v4.0.0"));
        let mut next_run = GithubChecker::load(home.path(), &cfg(10));
        assert_eq!(
            next_run
                .latest_tag("a", "one", &fetcher2, &token)
                .await
                .as_deref(),
            Some("v4.0.0")
        );
        assert_eq!(fetcher2.calls().len(), 1);
        assert_eq!(std::fs::read_to_string(file).unwrap(), legacy);
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn github_never_creates_cache_directory_and_offline_never_fetches() {
        let home = tempfile::tempdir().unwrap();
        let missing = home.path().join("missing/cache");
        let fetcher = MockHttpFetcher::new().on(
            "https://api.github.com/repos/a/one/releases/latest",
            200,
            None,
            &rel("v1.0.0"),
        );
        let mut checker = GithubChecker::load(&missing, &cfg(10));
        checker
            .latest_tag("a", "one", &fetcher, &CancellationToken::new())
            .await;
        assert!(!missing.exists());
        let mut offline = GithubChecker::new(&NetworkConfig {
            offline: true,
            ..cfg(10)
        });
        assert_eq!(
            offline
                .latest_tag("a", "one", &fetcher, &CancellationToken::new())
                .await,
            None
        );
        assert_eq!(fetcher.calls().len(), 1);
    }

    #[test]
    fn github_memory_and_tag_sizes_are_bounded() {
        let mut checker = GithubChecker::new(&cfg(usize::MAX));
        for index in 0..=MAX_CACHE_ENTRIES {
            checker.record(&format!("owner/repo-{index}"), None);
        }
        assert_eq!(checker.cache.len(), MAX_CACHE_ENTRIES);
        let body = rel(&"x".repeat(MAX_TAG_BYTES + 1));
        let memory = super::super::reserve_json(&checker.budget, body.as_bytes()).unwrap();
        assert!(parse_tag(body.as_bytes(), memory, &checker.budget).is_none());
    }
}
