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
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::inventory::{MemoryBudget, Reservation};

const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_JSON_MEMORY: usize = 512 * 1024 * 1024;

pub(crate) fn reserve_json(budget: &Arc<MemoryBudget>, body: &[u8]) -> Option<Reservation> {
    use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};

    struct Counter<'memory>(&'memory mut Reservation);
    impl Counter<'_> {
        fn charge<Error: serde::de::Error>(&mut self, bytes: usize) -> Result<(), Error> {
            if self.0.bytes().saturating_add(bytes) > MAX_JSON_MEMORY {
                return Err(Error::custom("JSON memory limit exceeded"));
            }
            self.0.grow(bytes).map_err(Error::custom)
        }
    }
    impl<'de> DeserializeSeed<'de> for Counter<'_> {
        type Value = ();
        fn deserialize<Deserializer: serde::Deserializer<'de>>(
            mut self,
            deserializer: Deserializer,
        ) -> Result<(), Deserializer::Error> {
            self.charge(2048)?;
            deserializer.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Counter<'_> {
        type Value = ();
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("JSON")
        }
        fn visit_bool<Error: serde::de::Error>(self, _: bool) -> Result<(), Error> {
            Ok(())
        }
        fn visit_i64<Error: serde::de::Error>(self, _: i64) -> Result<(), Error> {
            Ok(())
        }
        fn visit_u64<Error: serde::de::Error>(self, _: u64) -> Result<(), Error> {
            Ok(())
        }
        fn visit_f64<Error: serde::de::Error>(self, _: f64) -> Result<(), Error> {
            Ok(())
        }
        fn visit_unit<Error: serde::de::Error>(self) -> Result<(), Error> {
            Ok(())
        }
        fn visit_str<Error: serde::de::Error>(mut self, value: &str) -> Result<(), Error> {
            self.charge(value.len().saturating_mul(16))
        }
        fn visit_seq<Access: SeqAccess<'de>>(
            self,
            mut access: Access,
        ) -> Result<(), Access::Error> {
            while access.next_element_seed(Counter(self.0))?.is_some() {}
            Ok(())
        }
        fn visit_map<Access: MapAccess<'de>>(
            self,
            mut access: Access,
        ) -> Result<(), Access::Error> {
            while access.next_key_seed(Counter(self.0))?.is_some() {
                access.next_value_seed(Counter(self.0))?;
            }
            Ok(())
        }
    }
    if body.len() > MAX_RESPONSE_BYTES {
        return None;
    }
    let mut memory = budget
        .reserve(body.len().checked_mul(2)?.checked_add(4096)?)
        .ok()?;
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    Counter(&mut memory).deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()?;
    Some(memory)
}

#[derive(Debug)]
struct ResponseData {
    body: Vec<u8>,
    _memory: Reservation,
}

#[derive(Clone, Debug)]
pub struct ResponseBody(Arc<ResponseData>);

impl std::ops::Deref for ResponseBody {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0.body
    }
}

fn append_body(body: &mut Vec<u8>, memory: &mut Reservation, chunk: &[u8]) -> anyhow::Result<()> {
    let length = body
        .len()
        .checked_add(chunk.len())
        .ok_or(crate::inventory::InventoryError::ResourceLimit)?;
    anyhow::ensure!(
        length <= MAX_RESPONSE_BYTES,
        "HTTP response exceeds memory limit"
    );
    if length > body.capacity() {
        let capacity = length
            .checked_next_power_of_two()
            .ok_or(crate::inventory::InventoryError::ResourceLimit)?;
        memory.grow(capacity)?;
        body.try_reserve_exact(capacity - body.len())?;
    }
    body.extend_from_slice(chunk);
    Ok(())
}

pub use enrich::enrich;

/// A completed HTTP response.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    /// The `ETag` response header, if present.
    pub etag: Option<String>,
    pub body: ResponseBody,
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
    budget: Arc<MemoryBudget>,
}

impl ReqwestFetcher {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("macaudit/", env!("MACAUDIT_VERSION")))
            .build()
            .expect("reqwest client construction cannot fail with static config");
        ReqwestFetcher {
            client,
            budget: MemoryBudget::shared(),
        }
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
        let mut resp = tokio::select! {
            _ = token.cancelled() => anyhow::bail!("request to {url} cancelled"),
            r = req.send() => r.map_err(|e| anyhow::anyhow!("GET {url}: {e}"))?,
        };
        let status = resp.status().as_u16();
        if resp
            .content_length()
            .is_some_and(|bytes| bytes > MAX_RESPONSE_BYTES as u64)
        {
            anyhow::bail!("HTTP response exceeds memory limit");
        }
        let mut memory = self
            .budget
            .reserve(std::mem::size_of::<ResponseData>() + 64)?;
        let mut body = Vec::new();
        loop {
            let chunk = tokio::select! {
                _ = token.cancelled() => anyhow::bail!("request cancelled"),
                chunk = resp.chunk() => chunk?,
            };
            let Some(chunk) = chunk else {
                break;
            };
            append_body(&mut body, &mut memory, &chunk)?;
        }
        Ok(HttpResponse {
            status,
            etag: None,
            body: ResponseBody(Arc::new(ResponseData {
                body,
                _memory: memory,
            })),
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
                body: {
                    let mut memory = MemoryBudget::shared()
                        .reserve(std::mem::size_of::<ResponseData>() + 64)
                        .unwrap();
                    let mut bytes = Vec::new();
                    append_body(&mut bytes, &mut memory, body.as_bytes()).unwrap();
                    ResponseBody(Arc::new(ResponseData {
                        body: bytes,
                        _memory: memory,
                    }))
                },
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

    #[test]
    fn response_growth_checks_budget_before_allocating() {
        let budget = MemoryBudget::new(3);
        let mut memory = budget.reserve(0).unwrap();
        let mut body = Vec::new();
        assert!(append_body(&mut body, &mut memory, b"1234").is_err());
        assert_eq!(body.capacity(), 0);
        assert_eq!(budget.peak(), 0);
    }

    #[test]
    fn response_clones_keep_their_storage_charged() {
        let budget = MemoryBudget::new(1024);
        let mut memory = budget
            .reserve(std::mem::size_of::<ResponseData>() + 64)
            .unwrap();
        let mut body = Vec::new();
        append_body(&mut body, &mut memory, b"body").unwrap();
        let response = ResponseBody(Arc::new(ResponseData {
            body,
            _memory: memory,
        }));
        let charged = budget.used();
        let clone = response.clone();
        assert_eq!(budget.used(), charged);
        drop(response);
        assert_eq!(&*clone, b"body");
        assert_eq!(budget.used(), charged);
        drop(clone);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn json_preflight_releases_charges_on_invalid_or_denied_input() {
        let denied = MemoryBudget::new(4096);
        assert!(reserve_json(&denied, b"[1]").is_none());
        assert_eq!(denied.used(), 0);
        let budget = MemoryBudget::new(1 << 20);
        assert!(reserve_json(&budget, b"{\"a\": [1,}").is_none());
        assert_eq!(budget.used(), 0);
        let reservation = reserve_json(&budget, b"{\"a\": [1]}").unwrap();
        assert!(reservation.bytes() > 4096);
        drop(reservation);
        assert_eq!(budget.used(), 0);
    }

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
