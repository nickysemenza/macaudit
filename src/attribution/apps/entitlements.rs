//! `codesign -d --entitlements - --xml <app>` for the ~110 owner apps,
//! bounded concurrency, cached in `sizes.db` (`entitlements(app_path PK,
//! mtime, app_groups_json, sandboxed)` — a `busy_timeout` is required since
//! Git writes the same db concurrently).
//!
//! Two entitlements feed the linker's tier 1/2 (`linkers.rs`):
//! `com.apple.security.application-groups` (the array of Group Container
//! ids an app can see) and `com.apple.security.app-sandbox` (whether the
//! app is sandboxed at all — an unsandboxed app has no group entitlement to
//! read, so the linker falls back to the `group.<id>` name heuristic for
//! it).
//!
//! `ResolveEnv` holds a `RefCell` memo cache and so isn't `Sync`, which
//! means a `&ResolveEnv` can't be shared across `std::thread::scope` worker
//! threads (`&T: Send` requires `T: Sync`). The batched lookup below instead
//! shares just `env.runner` (`dyn CommandRunner: Send + Sync`) and
//! `env.paths` (plain `PathBuf`s, so auto-`Sync`) across workers.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde::Deserialize;

use crate::attribution::model::ResolveEnv;
use crate::config::Paths;
use crate::runner::CommandRunner;
use crate::size_cache::{self, SizeCache};

/// Up to this many `codesign` processes run at once.
const MAX_WORKERS: usize = 8;

/// The two entitlements keys the linker cares about, deserialized straight
/// out of `codesign`'s XML plist output.
#[derive(Deserialize, Default)]
struct EntitlementsPlist {
    #[serde(rename = "com.apple.security.application-groups", default)]
    application_groups: Vec<String>,
    #[serde(rename = "com.apple.security.app-sandbox", default)]
    app_sandbox: bool,
}

/// Parse `codesign`'s entitlements XML. Pure — the only part of this module
/// unit-tested without a real signed app bundle or a Tokio runtime. `None`
/// for anything that doesn't parse as a plist (unsigned apps print "code
/// object is not signed at all" on stderr and empty/garbage stdout).
fn parse_entitlements(xml: &[u8]) -> Option<(Vec<String>, bool)> {
    let parsed: EntitlementsPlist = plist::from_bytes(xml).ok()?;
    Some((parsed.application_groups, parsed.app_sandbox))
}

/// One app's entitlements (app-groups, sandboxed), cached in `sizes.db`
/// keyed by the bundle's own mtime. `None` when the app isn't signed,
/// `codesign` isn't on `$PATH`, the lookup times out, or the output can't be
/// parsed — all of which are common (many apps are unsigned or ad-hoc
/// signed) and not scan errors.
///
/// Requires a Tokio runtime context on the calling thread (`env.runner` is
/// async) — call this only from `app_groups_for`'s worker threads, which
/// `enter()` a captured `Handle` before calling in, or from other code
/// that's already inside a Tokio runtime.
pub fn app_groups(env: &ResolveEnv<'_>, app_path: &Path) -> Option<(Vec<String>, bool)> {
    lookup(env.runner, env.paths, app_path)
}

/// Batched entitlements lookup for every App-axis owner app, run across up
/// to `MAX_WORKERS` plain OS threads (not Tokio tasks — the resolve pass
/// that calls this is itself synchronous). Missing lookups are simply
/// absent from the map; callers treat that the same as "unsandboxed, no
/// groups".
pub fn app_groups_for(
    env: &ResolveEnv<'_>,
    apps: &[&Path],
) -> HashMap<PathBuf, (Vec<String>, bool)> {
    if apps.is_empty() {
        return HashMap::new();
    }
    // No Tokio runtime on this thread (e.g. a unit test calling this
    // directly, outside `AppStorageScanner::scan`) — entitlements are
    // best-effort, so degrade to "none found" instead of panicking.
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return HashMap::new();
    };

    let runner = env.runner;
    let paths = env.paths;
    let next = AtomicUsize::new(0);
    let results: Mutex<HashMap<PathBuf, (Vec<String>, bool)>> = Mutex::new(HashMap::new());
    let workers = apps.len().clamp(1, MAX_WORKERS);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let handle = handle.clone();
            let next = &next;
            let results = &results;
            scope.spawn(move || {
                // Entering the handle makes `Handle::current()` valid on
                // this plain OS thread for `lookup`'s `block_on` — this
                // thread never polls a Tokio task itself, so that
                // `block_on` is a normal sync-to-async bridge, not a
                // (panicking) reentrant one.
                let _guard = handle.enter();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&app_path) = apps.get(i) else {
                        break;
                    };
                    if let Some(found) = lookup(runner, paths, app_path) {
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

fn lookup(
    runner: &dyn CommandRunner,
    paths: &Paths,
    app_path: &Path,
) -> Option<(Vec<String>, bool)> {
    let mtime = size_cache::root_mtime_secs(app_path);

    if let Ok(cache) = SizeCache::open(&size_cache::db_path(paths)) {
        if let Ok(Some(cached)) = cache.get_entitlements(app_path, mtime) {
            return Some((cached.app_groups, cached.sandboxed));
        }
    }

    let xml = run_codesign(runner, app_path)?;
    let (app_groups, sandboxed) = parse_entitlements(&xml)?;

    if let Ok(cache) = SizeCache::open(&size_cache::db_path(paths)) {
        let _ = cache.put_entitlements(app_path, mtime, &app_groups, sandboxed);
    }

    Some((app_groups, sandboxed))
}

fn run_codesign(runner: &dyn CommandRunner, app_path: &Path) -> Option<Vec<u8>> {
    let path_str = app_path.to_string_lossy().into_owned();
    let token = tokio_util::sync::CancellationToken::new();
    let handle = tokio::runtime::Handle::current();
    let result = handle.block_on(tokio::time::timeout(
        Duration::from_secs(10),
        runner.run(
            "codesign",
            &["-d", "--entitlements", "-", "--xml", &path_str],
            &token,
        ),
    ));
    match result {
        Ok(Ok(out)) if out.success() => Some(out.stdout),
        _ => None,
    }
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
    fn parses_app_groups_and_sandbox_flag() {
        let (groups, sandboxed) = parse_entitlements(SAMPLE.as_bytes()).unwrap();
        assert_eq!(groups, vec!["group.io.robbie.homeassistant".to_string()]);
        assert!(sandboxed);
    }

    #[test]
    fn missing_keys_default_to_empty_and_unsandboxed() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.application-identifier</key>
    <string>ABCDE12345.com.example.app</string>
</dict>
</plist>"#;
        let (groups, sandboxed) = parse_entitlements(xml.as_bytes()).unwrap();
        assert!(groups.is_empty());
        assert!(!sandboxed);
    }

    #[test]
    fn garbage_input_is_none() {
        assert_eq!(parse_entitlements(b"not a plist"), None);
    }

    #[test]
    fn empty_apps_list_skips_the_runtime_lookup_entirely() {
        // No Tokio runtime is running in this plain `#[test]` fn — proves
        // the empty-input fast path never touches `Handle::try_current`.
        let paths = Paths::from_home("/tmp/macaudit-entitlements-test-home");
        let config = crate::config::Config::default();
        let trees: Vec<std::sync::Arc<crate::scan::walk::DirTree>> = Vec::new();
        let snapshots: HashMap<crate::model::ScannerId, crate::attribution::bus::Snapshot> =
            HashMap::new();
        let runner = crate::runner::MockCommandRunner::new();
        let env = ResolveEnv::new(&paths, &config, &trees, &snapshots, &runner);
        assert!(app_groups_for(&env, &[]).is_empty());
    }
}
