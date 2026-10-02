//! Run-owned, budgeted codesign entitlements with bounded worker concurrency.
//! No legacy database is opened or consulted.
//!
//! Feeds the linker's tier 1 (`linkers.rs`): `com.apple.security.
//! application-groups`, the array of Group Container ids an app can see.
//! Tier 2 (the `group.<id>` name heuristic) is not gated on sandbox status —
//! it simply runs whenever tier 1 misses, whether that's because the app
//! isn't sandboxed, isn't signed, or its entitlements just don't declare any
//! groups.
//!
//! `ResolveEnv`'s memo cache is a `Mutex` (so the type itself is `Sync`),
//! which is what lets the batched lookup below share `&ResolveEnv` directly
//! across `std::thread::scope` worker threads.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use serde::Deserialize;

use crate::attribution::model::ResolveEnv;
use crate::inventory::{MemoryBudget, Reservation};
use crate::size_cache::{SharedGroups, SizeCache};
use std::sync::Arc;

/// Up to this many `codesign` processes run at once.
const MAX_WORKERS: usize = 8;

/// The one entitlements key the linker cares about, deserialized straight
/// out of `codesign`'s XML plist output.
#[derive(Deserialize, Default)]
struct EntitlementsPlist {
    #[serde(rename = "com.apple.security.application-groups", default)]
    application_groups: Vec<String>,
}

/// Parse `codesign`'s entitlements XML. Pure — the only part of this module
/// unit-tested without a real signed app bundle or a Tokio runtime. `None`
/// for anything that doesn't parse as a plist (unsigned apps print "code
/// object is not signed at all" on stderr and empty/garbage stdout).
fn parse_entitlements(xml: &[u8]) -> Option<Vec<String>> {
    let parsed: EntitlementsPlist = plist::from_bytes(xml).ok()?;
    Some(parsed.application_groups)
}

/// Batched entitlements lookup for every App-axis owner app, run across up
/// to `MAX_WORKERS` plain OS threads (not Tokio tasks — the resolve pass
/// that calls this is itself synchronous). Missing lookups are simply
/// absent from the map; callers treat that the same as "no groups".
#[derive(Default)]
pub struct EntitlementMap {
    values: HashMap<PathBuf, Vec<String>>,
    _entries: Vec<Reservation>,
    _storage: Option<Reservation>,
}

impl std::ops::Deref for EntitlementMap {
    type Target = HashMap<PathBuf, Vec<String>>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

pub fn app_groups_for(env: &ResolveEnv<'_>, apps: &[&Path]) -> EntitlementMap {
    if apps.is_empty() {
        return EntitlementMap::default();
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return EntitlementMap::default();
    };
    let budget = env.paths.size_cache.memory_budget();
    let bytes = apps.len().saturating_mul(
        std::mem::size_of::<(PathBuf, Vec<String>)>() * 4 + std::mem::size_of::<Reservation>(),
    );
    let Ok(storage) = budget.reserve(bytes) else {
        return EntitlementMap::default();
    };
    let mut values = HashMap::new();
    let mut entries = Vec::new();
    if values.try_reserve(apps.len()).is_err() || entries.try_reserve_exact(apps.len()).is_err() {
        return EntitlementMap::default();
    }
    let results = Mutex::new(EntitlementMap {
        values,
        _entries: entries,
        _storage: Some(storage),
    });
    let next = AtomicUsize::new(0);
    let workers = apps.len().clamp(1, MAX_WORKERS);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let handle = handle.clone();
            let next = &next;
            let results = &results;
            let budget = &budget;
            let cache = env.paths.size_cache.clone();
            scope.spawn(move || {
                let _guard = handle.enter();
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&app_path) = apps.get(index) else {
                        break;
                    };
                    if let Some(groups) = lookup(env, app_path, &cache) {
                        let bytes =
                            groups
                                .iter()
                                .try_fold(app_path.as_os_str().len(), |bytes, group| {
                                    bytes.checked_add(group.len() + std::mem::size_of::<String>())
                                });
                        let Some(bytes) = bytes else {
                            continue;
                        };
                        let Ok(memory) = budget.reserve(bytes) else {
                            continue;
                        };
                        let mut results = results.lock().unwrap();
                        results
                            .values
                            .insert(app_path.to_path_buf(), groups.to_vec());
                        results._entries.push(memory);
                    }
                }
            });
        }
    });
    results.into_inner().unwrap()
}

fn lookup(env: &ResolveEnv<'_>, app_path: &Path, cache: &SizeCache) -> Option<SharedGroups> {
    if let Ok(Some(cached)) = cache.get_entitlements(app_path, 0) {
        return Some(cached.app_groups);
    }
    let budget: Arc<MemoryBudget> = cache.memory_budget();
    let _path_memory = budget
        .reserve(app_path.as_os_str().len().checked_mul(3)?.checked_add(64)?)
        .ok()?;
    let path_str = app_path.to_string_lossy().into_owned();
    let xml = env.run_blocking(
        "codesign",
        &["-d", "--entitlements", "-", "--xml", &path_str],
    )?;
    let _parse_memory = budget
        .reserve(xml.len().checked_mul(16)?.checked_add(8192)?)
        .ok()?;
    let app_groups = parse_entitlements(&xml)?;
    cache.put_entitlements(app_path, 0, &app_groups).ok()?;
    cache
        .get_entitlements(app_path, 0)
        .ok()
        .flatten()
        .map(|cached| cached.app_groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.io.robbie.homeassistant</string>
    </array>
</dict>
</plist>"#;

    #[test]
    fn parses_app_groups() {
        let groups = parse_entitlements(SAMPLE.as_bytes()).unwrap();
        assert_eq!(groups, vec!["group.io.robbie.homeassistant".to_string()]);
    }

    #[test]
    fn missing_key_defaults_to_empty() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.application-identifier</key>
    <string>ABCDE12345.com.example.app</string>
</dict>
</plist>"#;
        let groups = parse_entitlements(xml.as_bytes()).unwrap();
        assert!(groups.is_empty());
    }

    #[test]
    fn garbage_input_is_none() {
        assert_eq!(parse_entitlements(b"not a plist"), None);
    }

    #[test]
    fn empty_apps_list_skips_the_runtime_lookup_entirely() {
        // No Tokio runtime is running in this plain `#[test]` fn — proves
        // the empty-input fast path never touches `Handle::try_current`.
        let fixture = crate::attribution::testutil::EnvFixture::new();
        assert!(app_groups_for(&fixture.env(), &[]).is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cache_hits_share_the_run_and_return_a_budget_owned_map() {
        let budget = MemoryBudget::new(1 << 20);
        let mut fixture = crate::attribution::testutil::EnvFixture::new();
        fixture.paths = crate::config::Paths::with_memory_budget("/unused", budget.clone());
        let app = Path::new("/App.app");
        fixture
            .paths
            .size_cache
            .put_entitlements(app, 0, &["group.test".into()])
            .unwrap();
        let map = app_groups_for(&fixture.env(), &[app]);
        assert_eq!(map.get(app).unwrap(), &["group.test".to_string()]);
        assert!(fixture.runner.calls().is_empty());
        drop(fixture);
        assert!(budget.used() > 0);
        assert_eq!(map.get(app).unwrap()[0], "group.test");
        drop(map);
        assert_eq!(budget.used(), 0);
    }
}
