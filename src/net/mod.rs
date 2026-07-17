//! Network layer (spec M7). All network access is optional, cached, and
//! degrades silently — a scan with no network behaves exactly like v1.
//!
//! `HttpFetcher` is the injectable seam mirroring `runner::CommandRunner`:
//! production uses `ReqwestFetcher`; tests use `MockHttpFetcher` with fixture
//! bodies and never touch the network. Non-2xx statuses are returned as values
//! (the caller decides what 304/403 mean); `Err` is transport-only.

pub mod catalog;
pub mod enrich;
pub mod github;

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

pub use enrich::enrich;

/// A completed HTTP response.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    /// The `ETag` response header, if present.
    pub etag: Option<String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn not_modified(&self) -> bool {
        self.status == 304
    }
}

/// GET a URL, optionally with `If-None-Match`. Implementors must be cheap to
/// `Arc`-share. Cancellable via the scan generation token.
#[async_trait]
pub trait HttpFetcher: Send + Sync {
    async fn get(
        &self,
        url: &str,
        if_none_match: Option<&str>,
        token: &CancellationToken,
    ) -> anyhow::Result<HttpResponse>;
}

/// Production fetcher. One shared client: rustls, gzip, sane timeouts, and a
/// User-Agent (GitHub's API rejects requests without one).
pub struct ReqwestFetcher {
    client: reqwest::Client,
}

impl ReqwestFetcher {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("macaudit/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client construction cannot fail with static config");
        ReqwestFetcher { client }
    }
}

impl Default for ReqwestFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpFetcher for ReqwestFetcher {
    async fn get(
        &self,
        url: &str,
        if_none_match: Option<&str>,
        token: &CancellationToken,
    ) -> anyhow::Result<HttpResponse> {
        let mut req = self.client.get(url);
        if let Some(etag) = if_none_match {
            req = req.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        let resp = tokio::select! {
            _ = token.cancelled() => anyhow::bail!("request to {url} cancelled"),
            r = req.send() => r.map_err(|e| anyhow::anyhow!("GET {url}: {e}"))?,
        };
        let status = resp.status().as_u16();
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = tokio::select! {
            _ = token.cancelled() => anyhow::bail!("request to {url} cancelled"),
            b = resp.bytes() => b.map_err(|e| anyhow::anyhow!("GET {url} body: {e}"))?,
        };
        Ok(HttpResponse {
            status,
            etag,
            body: body.to_vec(),
        })
    }
}

/// Deterministic fetcher for tests, mirroring `MockCommandRunner`: register
/// responses per URL; unmatched URLs error loudly; calls (with the
/// `If-None-Match` value sent) are recorded for assertions.
#[derive(Default)]
pub struct MockHttpFetcher {
    responses: HashMap<String, Result<HttpResponse, String>>,
    calls: Mutex<Vec<(String, Option<String>)>>,
}

impl MockHttpFetcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a response for a URL.
    pub fn on(mut self, url: &str, status: u16, etag: Option<&str>, body: &str) -> Self {
        self.responses.insert(
            url.to_string(),
            Ok(HttpResponse {
                status,
                etag: etag.map(str::to_string),
                body: body.as_bytes().to_vec(),
            }),
        );
        self
    }

    /// Register a transport error for a URL.
    pub fn on_err(mut self, url: &str) -> Self {
        self.responses
            .insert(url.to_string(), Err(format!("transport error for {url}")));
        self
    }

    /// The requests made, in order: `(url, if_none_match_sent)`.
    pub fn calls(&self) -> Vec<(String, Option<String>)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl HttpFetcher for MockHttpFetcher {
    async fn get(
        &self,
        url: &str,
        if_none_match: Option<&str>,
        _token: &CancellationToken,
    ) -> anyhow::Result<HttpResponse> {
        self.calls
            .lock()
            .unwrap()
            .push((url.to_string(), if_none_match.map(str::to_string)));
        match self.responses.get(url) {
            Some(Ok(resp)) => Ok(resp.clone()),
            Some(Err(e)) => anyhow::bail!("{e}"),
            None => anyhow::bail!("MockHttpFetcher: no response registered for {url}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_returns_registered_and_records_etag() {
        let f = MockHttpFetcher::new().on("https://x/y", 304, Some("W/\"abc\""), "");
        let resp = f
            .get("https://x/y", Some("W/\"abc\""), &CancellationToken::new())
            .await
            .unwrap();
        assert!(resp.not_modified());
        assert_eq!(
            f.calls(),
            vec![("https://x/y".to_string(), Some("W/\"abc\"".to_string()))]
        );
    }

    #[tokio::test]
    async fn mock_unmatched_is_loud() {
        let f = MockHttpFetcher::new();
        let err = f
            .get("https://nope", None, &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no response registered"));
    }
}
