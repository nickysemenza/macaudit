//! `codesign -d --entitlements - --xml <app>` for the ~110 owner apps,
//! bounded concurrency, cached in `sizes.db` (`entitlements_v2(app_path PK,
//! mtime, app_groups_json)` — a `busy_timeout` is required since Git writes
//! the same db concurrently).
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
use crate::size_cache::{self, SizeCache};

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
pub fn app_groups_for(env: &ResolveEnv<'_>, apps: &[&Path]) -> HashMap<PathBuf, Vec<String>> {
    if apps.is_empty() {
        return HashMap::new();
    }
    // No Tokio runtime on this thread (e.g. a unit test calling this
    // directly, outside `AppStorageScanner::scan`) — entitlements are
    // best-effort, so degrade to "none found" instead of panicking.
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return HashMap::new();
    };

    let next = AtomicUsize::new(0);
    let results: Mutex<HashMap<PathBuf, Vec<String>>> = Mutex::new(HashMap::new());
    let workers = apps.len().clamp(1, MAX_WORKERS);
    let db_path = size_cache::db_path(env.paths);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let handle = handle.clone();
            let next = &next;
            let results = &results;
            let db_path = &db_path;
            scope.spawn(move || {
                // Entering the handle makes `Handle::try_current()` valid on
                // this plain OS thread — both for this loop and for the
                // nested thread `env.run_blocking` itself spawns per
                // `codesign` call.
                let _guard = handle.enter();
                // One `SizeCache` connection per worker thread, opened once
                // and reused for every app it looks up (not twice per app,
                // once to read and once to write) — `sizes.db` is opened
                // with a `busy_timeout`, so the sibling worker threads (and
                // Git, writing the same db concurrently) are safe to share
                // it with.
                let cache = SizeCache::open(db_path).ok();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&app_path) = apps.get(i) else {
                        break;
                    };
                    if let Some(found) = lookup(env, app_path, cache.as_ref()) {
                        results
                            .lock()
                            .unwrap()
                            .insert(app_path.to_path_buf(), found);
                    }
                }
            });
        }
    });

    results.into_inner().unwrap()
}

fn lookup(env: &ResolveEnv<'_>, app_path: &Path, cache: Option<&SizeCache>) -> Option<Vec<String>> {
    let mtime = size_cache::root_mtime_secs(app_path);

    if let Some(cache) = cache {
        if let Ok(Some(cached)) = cache.get_entitlements(app_path, mtime) {
            return Some(cached.app_groups);
        }
    }

    let path_str = app_path.to_string_lossy().into_owned();
    let xml = env.run_blocking(
        "codesign",
        &["-d", "--entitlements", "-", "--xml", &path_str],
    )?;
    let app_groups = parse_entitlements(&xml)?;

    if let Some(cache) = cache {
        let _ = cache.put_entitlements(app_path, mtime, &app_groups);
    }

    Some(app_groups)
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
}
