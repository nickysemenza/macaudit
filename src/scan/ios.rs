//! IosScanner — storage on USB-connected iPhones/iPads, read through
//! libimobiledevice: `idevice_id -l` to find devices, `ideviceinfo` for the
//! identity and the `com.apple.disk_usage` domain (capacity / free / purgeable),
//! and `ideviceinstaller list` for per-app bundle and data sizes.
//!
//! Everything here is read-only and nothing is ever executed against the
//! phone: the only remedy is an `ideviceinstaller uninstall` command copied to
//! the clipboard. The tools are optional Homebrew formulae, so every way the
//! scan can come up empty — tools missing, no device, device locked or not
//! trusted — is one Info finding, never a failed section. Those status rows
//! are `Ephemeral` so plugging the phone in and out does not churn history.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::{run_classified, CmdOutcome, ScanCtx, Scanner};

const ID_TIMEOUT: Duration = Duration::from_secs(10);
const INFO_TIMEOUT: Duration = Duration::from_secs(20);
/// The device computes every app's size on demand; ~10–20 s for 400 apps.
const LIST_TIMEOUT: Duration = Duration::from_secs(60);

/// An app is flagged for attention when its data dwarfs the app itself —
/// offline downloads, caches — not merely because it is big (a 3 GB game with
/// 0.5 GB of saves is just a big game).
const DATA_HEAVY_MIN_BYTES: u64 = 1 << 30;
const DATA_HEAVY_RATIO: u64 = 4;

const INSTALL_ALL: &str = "brew install libimobiledevice ideviceinstaller";
const INSTALL_LISTER: &str = "brew install ideviceinstaller";

/// Attributes requested from installation_proxy. Sizes are only returned when
/// asked for explicitly, and asking for just these keeps the plist small.
const APP_LIST_ATTRS: &[&str] = &[
    "CFBundleIdentifier",
    "CFBundleDisplayName",
    "CFBundleName",
    "CFBundleShortVersionString",
    "ApplicationType",
    "StaticDiskUsage",
    "DynamicDiskUsage",
];

/// `ideviceinstaller` arguments for one device. Shared with the tests because
/// the mock runner matches the exact argument vector.
pub fn list_args(udid: &str) -> Vec<String> {
    let mut args = vec![
        "-u".to_string(),
        udid.to_string(),
        "list".to_string(),
        "--all".to_string(),
        "--xml".to_string(),
    ];
    for attr in APP_LIST_ATTRS {
        args.push("-a".to_string());
        args.push((*attr).to_string());
    }
    args
}

#[derive(Default)]
pub struct IosScanner;

#[async_trait]
impl Scanner for IosScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Ios
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        let udids = match run_classified(&ctx, "idevice_id", &["-l"], ID_TIMEOUT).await {
            CmdOutcome::Ok(out) => out
                .stdout_str()
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect::<Vec<_>>(),
            CmdOutcome::NotInstalled(_) => {
                ctx.emit(
                    status("ios:unavailable", "libimobiledevice not installed")
                        .detail(
                            "Install it to see a connected iPhone's capacity, free and \
                             purgeable space, and every app's bundle and data size",
                        )
                        .remedy(copy_remedy("Copy install command", INSTALL_ALL)),
                )
                .await;
                return Ok(());
            }
            CmdOutcome::Failed(out) => {
                ctx.emit(
                    status("ios:unavailable", "idevice_id failed")
                        .detail(out.stderr_str().trim().to_string()),
                )
                .await;
                return Ok(());
            }
            CmdOutcome::TimedOut => {
                ctx.emit(
                    status("ios:unavailable", "idevice_id timed out")
                        .detail("usbmuxd did not answer; try unplugging and replugging"),
                )
                .await;
                return Ok(());
            }
        };

        if udids.is_empty() {
            ctx.emit(
                status("ios:no-device", "No iOS device connected")
                    .detail("Plug in an iPhone or iPad over USB, unlock it and tap Trust"),
            )
            .await;
            return Ok(());
        }

        for udid in &udids {
            if ctx.cancelled() {
                break;
            }
            scan_device(&ctx, udid).await;
        }
        Ok(())
    }
}

/// What `ideviceinfo -x` tells us about one device.
pub(crate) struct DeviceInfo {
    pub(crate) name: String,
    pub(crate) product_type: String,
    pub(crate) ios_version: String,
}

/// The `com.apple.disk_usage` numbers and what they mean. `purgeable` is the
/// gap between what iOS could free on demand and what is free right now —
/// the number Settings never shows. `committed` is what stays used even after
/// iOS purges everything it can.
#[derive(Clone, Copy)]
pub(crate) struct DiskUsage {
    pub(crate) capacity: u64,
    pub(crate) free: u64,
    pub(crate) available: u64,
}

impl DiskUsage {
    fn purgeable(self) -> u64 {
        self.available.saturating_sub(self.free)
    }
    fn used(self) -> u64 {
        self.capacity.saturating_sub(self.free)
    }
    fn committed(self) -> u64 {
        self.capacity.saturating_sub(self.available)
    }
}

pub(crate) struct AppUsage {
    pub(crate) bundle_id: String,
    pub(crate) title: String,
    pub(crate) app_type: String,
    pub(crate) version: Option<String>,
    pub(crate) static_bytes: u64,
    pub(crate) dynamic_bytes: u64,
}

impl AppUsage {
    fn total(&self) -> u64 {
        self.static_bytes + self.dynamic_bytes
    }
    fn data_heavy(&self) -> bool {
        self.dynamic_bytes >= DATA_HEAVY_MIN_BYTES
            && self.dynamic_bytes >= self.static_bytes.saturating_mul(DATA_HEAVY_RATIO)
    }
}

async fn scan_device(ctx: &ScanCtx, udid: &str) {
    let info = match run_classified(ctx, "ideviceinfo", &["-u", udid, "-x"], INFO_TIMEOUT).await {
        CmdOutcome::Ok(out) => parse_device_info(&out.stdout, udid),
        other => {
            ctx.emit(unreadable(udid, &outcome_text(&other))).await;
            return;
        }
    };
    let usage = match run_classified(
        ctx,
        "ideviceinfo",
        &["-u", udid, "-q", "com.apple.disk_usage", "-x"],
        INFO_TIMEOUT,
    )
    .await
    {
        CmdOutcome::Ok(out) => parse_disk_usage(&out.stdout),
        other => {
            ctx.emit(unreadable(udid, &outcome_text(&other))).await;
            return;
        }
    };
    let Some(usage) = usage else {
        ctx.emit(unreadable(
            udid,
            "com.apple.disk_usage domain missing the capacity keys",
        ))
        .await;
        return;
    };

    // The device row goes out immediately so the storage bar is on screen
    // while the (slow) app listing runs; it is re-emitted with app totals
    // below — same key, same id, so the UI upserts in place.
    ctx.emit(device_finding(udid, &info, usage, &[])).await;
    ctx.progress(format!("Listing apps on {}…", info.name), 0, None)
        .await;

    let args = list_args(udid);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let apps = match run_classified(ctx, "ideviceinstaller", &args, LIST_TIMEOUT).await {
        CmdOutcome::Ok(out) => parse_apps(&out.stdout),
        CmdOutcome::NotInstalled(_) => {
            ctx.emit(
                status(
                    &format!("ios:{udid}:apps-unavailable"),
                    "ideviceinstaller not installed — per-app sizes unavailable",
                )
                .meta(json!({ "udid": udid, "device": info.name }))
                .remedy(copy_remedy("Copy install command", INSTALL_LISTER)),
            )
            .await;
            return;
        }
        other => {
            ctx.emit(
                status(
                    &format!("ios:{udid}:apps-unavailable"),
                    "Could not list apps — per-app sizes unavailable",
                )
                .detail(outcome_text(&other))
                .meta(json!({ "udid": udid, "device": info.name })),
            )
            .await;
            return;
        }
    };

    for app in &apps {
        ctx.emit(app_finding(udid, &info, app)).await;
    }
    ctx.emit(device_finding(udid, &info, usage, &apps)).await;
}

fn outcome_text(o: &CmdOutcome) -> String {
    match o {
        CmdOutcome::Ok(_) => String::new(),
        CmdOutcome::NotInstalled(e) => e.clone(),
        CmdOutcome::Failed(out) => out.stderr_str().trim().to_string(),
        CmdOutcome::TimedOut => "timed out waiting for the device".to_string(),
    }
}

fn status(key: &str, title: &str) -> Finding {
    Finding::new(FindingKind::IosDevice, key, title)
        .severity(Severity::Info)
        .ephemeral()
}

fn copy_remedy(label: &str, text: &str) -> Remedy {
    Remedy::new(
        label,
        RemedyCommand::CopyToClipboard {
            text: text.to_string(),
        },
    )
}

/// `ideviceinfo` could not talk to the device. Lockdown's error strings
/// name the reason (pairing dialog pending, user denied pairing, password
/// protected); surface the human fix when it is one of those.
fn unreadable(udid: &str, stderr: &str) -> Finding {
    let lower = stderr.to_ascii_lowercase();
    let locked = ["pair", "trust", "password"]
        .iter()
        .any(|needle| lower.contains(needle));
    let title = if locked {
        "Device locked or not trusted — unlock it and tap Trust"
    } else {
        "Device not readable"
    };
    status(&format!("ios:{udid}:unreadable"), title)
        .detail(stderr.to_string())
        .meta(json!({ "udid": udid }))
}

pub(crate) fn device_finding(
    udid: &str,
    info: &DeviceInfo,
    usage: DiskUsage,
    apps: &[AppUsage],
) -> Finding {
    let apps_bytes: u64 = apps.iter().map(AppUsage::total).sum();
    let unattributed = usage.used().saturating_sub(apps_bytes);
    Finding::new(
        FindingKind::IosDevice,
        &format!("ios:{udid}"),
        format!(
            "{} · {} · iOS {}",
            info.name, info.product_type, info.ios_version
        ),
    )
    .detail(
        "USB can't split media, Messages, system and purgeable caches — \
         see Settings › General › iPhone Storage for those",
    )
    .size(usage.used())
    .severity(Severity::Info)
    .provenance(
        "ideviceinfo com.apple.disk_usage; purgeable = TotalDataAvailable − AmountDataAvailable",
    )
    .meta(json!({
        "udid": udid,
        "device": info.name,
        "product_type": info.product_type,
        "ios_version": info.ios_version,
        "capacity_bytes": usage.capacity,
        "free_bytes": usage.free,
        "available_bytes": usage.available,
        "purgeable_bytes": usage.purgeable(),
        "used_bytes": usage.used(),
        "committed_bytes": usage.committed(),
        "apps_bytes": apps_bytes,
        "unattributed_bytes": unattributed,
        "app_count": apps.len(),
    }))
}

pub(crate) fn app_finding(udid: &str, info: &DeviceInfo, app: &AppUsage) -> Finding {
    let user_app = app.app_type == "User";
    let mut f = Finding::new(
        FindingKind::IosApp,
        &format!("ios:{udid}:{}", app.bundle_id),
        app.title.clone(),
    )
    .detail(format!("{} · {}", app.bundle_id, app.app_type))
    .size(app.total())
    .severity(if app.data_heavy() {
        Severity::Attention
    } else {
        Severity::Info
    })
    .coverage("Data size includes content iOS may count as purgeable")
    .meta(json!({
        "udid": udid,
        "device": info.name,
        "bundle_id": app.bundle_id,
        "app_type": app.app_type,
        // Not `version`: that key is a tracked snapshot field and every
        // auto-update would show up as a change.
        "app_version": app.version,
        "static_bytes": app.static_bytes,
        "dynamic_bytes": app.dynamic_bytes,
    }));
    if user_app {
        f = f.remedy(copy_remedy(
            "Copy uninstall command (removes the app and its data)",
            &format!("ideviceinstaller -u {udid} uninstall {}", app.bundle_id),
        ));
    }
    f
}

fn plist_str(d: &plist::Dictionary, key: &str) -> Option<String> {
    d.get(key).and_then(|v| v.as_string()).map(String::from)
}

fn plist_u64(d: &plist::Dictionary, key: &str) -> Option<u64> {
    d.get(key).and_then(|v| v.as_unsigned_integer())
}

fn parse_device_info(xml: &[u8], udid: &str) -> DeviceInfo {
    let dict = plist::Value::from_reader_xml(std::io::Cursor::new(xml))
        .ok()
        .and_then(|v| v.into_dictionary())
        .unwrap_or_default();
    DeviceInfo {
        name: plist_str(&dict, "DeviceName").unwrap_or_else(|| udid.to_string()),
        product_type: plist_str(&dict, "ProductType").unwrap_or_else(|| "unknown".into()),
        ios_version: plist_str(&dict, "ProductVersion").unwrap_or_else(|| "?".into()),
    }
}

fn parse_disk_usage(xml: &[u8]) -> Option<DiskUsage> {
    let dict = plist::Value::from_reader_xml(std::io::Cursor::new(xml))
        .ok()?
        .into_dictionary()?;
    Some(DiskUsage {
        capacity: plist_u64(&dict, "TotalDataCapacity")?,
        free: plist_u64(&dict, "AmountDataAvailable")?,
        available: plist_u64(&dict, "TotalDataAvailable")?,
    })
}

/// Apps with a size. Entries without `StaticDiskUsage` are Apple frameworks
/// that installation_proxy lists as System apps; they carry no storage.
fn parse_apps(xml: &[u8]) -> Vec<AppUsage> {
    let Some(entries) = plist::Value::from_reader_xml(std::io::Cursor::new(xml))
        .ok()
        .and_then(|v| v.into_array())
    else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|v| v.as_dictionary())
        .filter_map(|d| {
            let bundle_id = plist_str(d, "CFBundleIdentifier")?;
            let static_bytes = plist_u64(d, "StaticDiskUsage")?;
            Some(AppUsage {
                title: plist_str(d, "CFBundleDisplayName")
                    .or_else(|| plist_str(d, "CFBundleName"))
                    .unwrap_or_else(|| bundle_id.clone()),
                app_type: plist_str(d, "ApplicationType").unwrap_or_else(|| "User".into()),
                version: plist_str(d, "CFBundleShortVersionString"),
                dynamic_bytes: plist_u64(d, "DynamicDiskUsage").unwrap_or(0),
                static_bytes,
                bundle_id,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ScanEvent, SnapshotPolicy};
    use crate::runner::MockCommandRunner;

    const UDID: &str = "00008150-001915442138401C";
    const DISK_USAGE: &str = include_str!("../../tests/fixtures/ios/disk_usage.plist");
    const DEVICE_INFO: &str = include_str!("../../tests/fixtures/ios/ideviceinfo.plist");
    const APPS: &str = include_str!("../../tests/fixtures/ios/apps.plist");

    fn ctx_with(mock: MockCommandRunner, tx: tokio::sync::mpsc::Sender<ScanEvent>) -> ScanCtx {
        ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: std::sync::Arc::new(crate::config::Config::default()),
            paths: std::sync::Arc::new(crate::config::Paths::from_home("/tmp/fh")),
            runner: std::sync::Arc::new(mock),
            current: ScannerId::Ios,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        }
    }

    /// Everything up to (not including) the app listing succeeds.
    fn device_ok() -> MockCommandRunner {
        MockCommandRunner::new()
            .on("idevice_id", &["-l"], &format!("{UDID}\n"))
            .on("ideviceinfo", &["-u", UDID, "-x"], DEVICE_INFO)
            .on(
                "ideviceinfo",
                &["-u", UDID, "-q", "com.apple.disk_usage", "-x"],
                DISK_USAGE,
            )
    }

    async fn run(mock: MockCommandRunner) -> Vec<Finding> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        IosScanner.scan(ctx_with(mock, tx)).await.unwrap();
        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        findings
    }

    fn copied_text(f: &Finding) -> Vec<&str> {
        f.remedies
            .iter()
            .filter_map(|r| match &r.command {
                RemedyCommand::CopyToClipboard { text } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn missing_libimobiledevice_is_one_info_row_with_install_hint() {
        // The mock errors on any unregistered call, i.e. the spawn fails.
        let findings = run(MockCommandRunner::new()).await;
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::IosDevice);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.snapshot_policy, SnapshotPolicy::Ephemeral);
        assert_eq!(f.title, "libimobiledevice not installed");
        assert_eq!(copied_text(f), vec![INSTALL_ALL]);
        assert!(f.remedies.iter().all(|r| !r.destructive));
    }

    #[tokio::test]
    async fn no_device_is_one_info_row() {
        let findings = run(MockCommandRunner::new().on("idevice_id", &["-l"], "")).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "No iOS device connected");
        assert!(findings[0].remedies.is_empty());
        assert_eq!(findings[0].snapshot_policy, SnapshotPolicy::Ephemeral);
    }

    #[tokio::test]
    async fn locked_device_names_the_fix_and_scan_still_succeeds() {
        let mock = MockCommandRunner::new()
            .on("idevice_id", &["-l"], &format!("{UDID}\n"))
            .on_fail(
                "ideviceinfo",
                &["-u", UDID, "-x"],
                255,
                "ERROR: Could not connect to lockdownd: Please accept the trust dialog on the screen of device",
            );
        let findings = run(mock).await;
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].title.contains("not trusted"),
            "{}",
            findings[0].title
        );
        assert!(findings[0].detail.contains("trust dialog"));
        assert_eq!(findings[0].meta["udid"], UDID);
    }

    #[tokio::test]
    async fn missing_ideviceinstaller_keeps_the_device_row() {
        let findings = run(device_ok()).await;
        // Device row (no apps yet) + the apps-unavailable status row.
        assert_eq!(findings.len(), 2);
        let device = &findings[0];
        assert_eq!(device.kind, FindingKind::IosDevice);
        assert_eq!(device.meta["apps_bytes"], 0);
        assert_eq!(
            device.meta["purgeable_bytes"],
            166_055_415_808u64 - 19_632_939_008
        );
        let status = &findings[1];
        assert!(status.title.contains("ideviceinstaller not installed"));
        assert_eq!(copied_text(status), vec![INSTALL_LISTER]);
        assert_eq!(status.snapshot_policy, SnapshotPolicy::Ephemeral);
    }

    #[tokio::test]
    async fn lists_apps_with_sizes_and_reemits_device_totals() {
        let args = list_args(UDID);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let findings = run(device_ok().on("ideviceinstaller", &args, APPS)).await;

        // Device (early) + 4 sized apps (the framework without StaticDiskUsage
        // is skipped) + device (final).
        assert_eq!(findings.len(), 6);
        assert_eq!(findings[0].kind, FindingKind::IosDevice);
        let last = findings.last().unwrap();
        assert_eq!(last.kind, FindingKind::IosDevice);
        assert_eq!(last.id, findings[0].id, "re-emit must upsert the same row");
        assert_eq!(last.snapshot_policy, SnapshotPolicy::Durable);
        assert_eq!(last.title, "Nicky iPhone · iPhone18,1 · iOS 27.0");

        let apps: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::IosApp)
            .collect();
        assert_eq!(apps.len(), 4);
        assert!(apps
            .iter()
            .all(|f| f.snapshot_policy == SnapshotPolicy::Durable));
        assert!(apps.iter().all(|f| f.meta.get("version").is_none()));

        let spotify = apps.iter().find(|f| f.title == "Spotify").unwrap();
        assert_eq!(spotify.size_bytes, Some(260_000_000 + 38_290_000_000));
        assert_eq!(spotify.severity, Severity::Attention);
        assert_eq!(spotify.meta["app_version"], "9.0.86");
        assert_eq!(
            copied_text(spotify),
            vec![format!("ideviceinstaller -u {UDID} uninstall com.spotify.client").as_str()]
        );

        // Big app, modest data: not a data hoarder.
        let game = apps.iter().find(|f| f.title == "Big Game").unwrap();
        assert_eq!(game.severity, Severity::Info);

        // No display name → bundle name; system app → no uninstall remedy.
        assert!(apps.iter().any(|f| f.title == "Nameless"));
        let notes = apps.iter().find(|f| f.title == "Notes").unwrap();
        assert_eq!(notes.meta["app_type"], "System");
        assert!(notes.remedies.is_empty());

        let apps_bytes: u64 = apps.iter().map(|f| f.size_bytes.unwrap()).sum();
        let capacity = 246_266_159_104u64;
        let free = 19_632_939_008u64;
        let available = 166_055_415_808u64;
        assert_eq!(last.meta["app_count"], 4);
        assert_eq!(last.meta["apps_bytes"], apps_bytes);
        assert_eq!(last.meta["used_bytes"], capacity - free);
        assert_eq!(last.size_bytes, Some(capacity - free));
        assert_eq!(last.meta["purgeable_bytes"], available - free);
        assert_eq!(last.meta["committed_bytes"], capacity - available);
        assert_eq!(
            last.meta["unattributed_bytes"],
            capacity - free - apps_bytes
        );
    }

    #[tokio::test]
    async fn app_listing_failure_is_reported_not_fatal() {
        let args = list_args(UDID);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let findings = run(device_ok().on_fail("ideviceinstaller", &args, 1, "boom")).await;
        assert_eq!(findings.len(), 2);
        assert!(findings[1].title.contains("Could not list apps"));
        assert_eq!(findings[1].detail, "boom");
        assert!(findings[1].remedies.is_empty());
    }
}
