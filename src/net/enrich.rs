//! Network enrichment orchestrator (spec M7).
//!
//! STUB owned by lane N: the real implementation loads the cask catalog
//! (`catalog.rs`), matches Unmanaged apps to available casks (adopt remedy),
//! and best-effort checks GitHub releases (`github.rs`). Runs AFTER the sync
//! `correlate()` pass in both the headless and TUI paths — installed-cask apps
//! must be reclassified first so they are never offered `--adopt`.
//!
//! Contract: silent no-op when `fetcher` is `None` (offline), when there are no
//! unmanaged App findings, or on any network/cache failure.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::config::{Config, Paths};
use crate::model::{Finding, FindingId};
use crate::net::HttpFetcher;

/// Enrich findings in place with network-derived data. No-op until lane N.
pub async fn enrich(
    _findings: &mut BTreeMap<FindingId, Finding>,
    _fetcher: Option<Arc<dyn HttpFetcher>>,
    _paths: &Paths,
    _config: &Config,
    _token: &CancellationToken,
) {
    // Lane N: catalog matching + GitHub release checks.
}
