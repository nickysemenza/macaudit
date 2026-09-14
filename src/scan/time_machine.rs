//! TimeMachineScanner (spec §3.12) — the "is my backup actually working, and
//! what is it backing up?" section.
//!
//! Five groups of findings, each from an independent stage so one unavailable
//! source never hides the others:
//!
//! - **Backup** — one `TmDestination` per configured destination (last
//!   successful backup age, last result code, quota use) merged from
//!   `tmutil destinationinfo -X` and the Time Machine preferences, plus
//!   `TmStaleMount` for leftover `/Volumes/Backups of …` directories.
//! - **Backup set** — one `TmBackupEstimate`: what a backup would contain,
//!   measured. Directories are enumerated a few levels deep, classified with
//!   batched `tmutil isexcluded`, and the included ones sized with the bounded
//!   walker; the finding streams as a lower bound and is re-emitted as roots
//!   finish (same id ⇒ the engine upserts).
//! - **Exclusions** — one `TmExclusion` per skipped path (System Settings list,
//!   sticky attribute or macOS default), sized so the saving is visible.
//!   Always `Info`, never `Reclaimable`: excluded bytes are not reclaimable.
//! - **Suggested exclusions** — `TmExclusionCandidate` for regenerable caches,
//!   toolchains and cloud-synced folders that are still being backed up.
//! - **Local snapshots** — one `LocalSnapshot` per APFS snapshot (destructive
//!   `tmutil deletelocalsnapshots`), plus `TmPurgeable`: the volume's purgeable
//!   space, the honest upper bound for what deleting them all frees (macOS
//!   exposes no per-snapshot size without root).
//!
//! Platform facts this leans on (verified on macOS 26): the preferences plist
//! is TCC-protected but `defaults export` serves it through cfprefsd without
//! Full Disk Access; `tmutil isexcluded` aborts (exit 80) at the first
//! privacy-protected argument and reports only the paths before it, so
//! classification pre-filters unreadable directories and resumes after a short
//! answer; `tmutil addexclusion <path>` (sticky) needs no root while `-p`
//! (fixed-path, shown in System Settings) does, so the runnable remedy is the
//! sticky form and the `-p` form is offered as a copy-to-clipboard command.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde_json::json;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScanEvent, ScannerId, Severity};
use crate::scan::sizing::on_disk_bytes;
use crate::scan::volume;
use crate::scan::{ScanCtx, Scanner};
use crate::size_cache::{self, is_fresh, root_mtime_secs, CachedSize, SizeCache};

const GROUP_BACKUP: &str = "Backup";
const GROUP_BACKUP_SET: &str = "Backup set";
const GROUP_EXCLUSIONS: &str = "Exclusions";
const GROUP_CANDIDATES: &str = "Suggested exclusions";
const GROUP_SNAPSHOTS: &str = "Local snapshots";

const CMD_TIMEOUT: Duration = Duration::from_secs(10);
/// Paths per `tmutil isexcluded` invocation. Well under any argv limit; small
/// enough that a protected path mid-batch costs little to resume after.
const ISEXCLUDED_CHUNK: usize = 200;
/// Minimum interval between re-emits of the estimate while sizing streams.
const ESTIMATE_EMIT_INTERVAL: Duration = Duration::from_millis(500);
const MAX_SKIPPED_LISTED: usize = 8;

pub struct TimeMachineScanner {
    /// The on-disk preferences, read directly only as a fallback (a process
    /// with Full Disk Access, or a test pointing at a fixture).
    pub prefs_path: PathBuf,
    /// Where network destinations get mounted (`/Volumes`).
    pub volumes_dir: PathBuf,
    /// The root whose top level is enumerated for the estimate (`/`).
    pub system_root: PathBuf,
    /// Mount point passed to `diskutil info` for the Data volume.
    pub data_mount: String,
}

impl Default for TimeMachineScanner {
    fn default() -> Self {
        TimeMachineScanner {
            prefs_path: PathBuf::from("/Library/Preferences/com.apple.TimeMachine.plist"),
            volumes_dir: PathBuf::from("/Volumes"),
            system_root: PathBuf::from("/"),
            data_mount: "/System/Volumes/Data".to_string(),
        }
    }
}

#[async_trait]
impl Scanner for TimeMachineScanner {
    fn id(&self) -> ScannerId {
        ScannerId::TimeMachine
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        let home = ctx.paths.home.clone();

        // 1. Local snapshots.
        ctx.progress("local snapshots", 0, Some(6)).await;
        let snapshot_count = scan_local_snapshots(&ctx).await;
        if ctx.cancelled() {
            return Ok(());
        }

        // 2. Volume capacity: purgeable upper bound + Data volume usage.
        ctx.progress("volume capacity", 1, Some(6)).await;
        let capacity = volume::macos_capacity(&ctx, CMD_TIMEOUT).await;
        let data_usage = volume::diskutil_info(&ctx, &self.data_mount, CMD_TIMEOUT).await;
        if let Some(cap) = &capacity {
            if cap.purgeable() > 0 {
                ctx.emit(purgeable_finding(cap, snapshot_count)).await;
            }
        }
        let data_used_bytes = data_usage
            .as_ref()
            .and_then(|d| d.capacity_in_use.or(Some(d.used)))
            .or_else(|| {
                capacity
                    .as_ref()
                    .map(|c| c.total.saturating_sub(c.physical))
            });
        if ctx.cancelled() {
            return Ok(());
        }

        // 3. Destinations + stale mount points.
        ctx.progress("backup destinations", 2, Some(6)).await;
        let prefs = load_prefs(&ctx, &self.prefs_path).await;
        let dest_info = load_destinationinfo(&ctx).await;
        let now = SystemTime::now();
        let stale_days = ctx.config.time_machine.stale_backup_days;
        let destinations = merge_destinations(prefs.as_ref(), &dest_info);
        if destinations.is_empty() {
            ctx.emit(not_configured_finding(prefs.is_some())).await;
        }
        for d in &destinations {
            ctx.emit(destination_finding(d, prefs.as_ref(), now, stale_days))
                .await;
        }
        for f in stale_mount_findings(&self.volumes_dir) {
            ctx.emit(f).await;
        }
        let quota_bytes = estimate_quota(&destinations, prefs.as_ref());
        if ctx.cancelled() {
            return Ok(());
        }

        // 4. Classify + enumerate.
        ctx.progress("classifying paths", 3, Some(6)).await;
        let skip_paths: Vec<PathBuf> = prefs
            .as_ref()
            .map(|p| p.skip_paths.clone())
            .unwrap_or_default();
        let candidates = candidate_roots(&ctx);
        let enumeration = enumerate(&ctx, &self.system_root, &home, &skip_paths, &candidates).await;
        if ctx.cancelled() {
            return Ok(());
        }

        // Exclusion rows are emitted unsized right away (`…` while measuring).
        let mut jobs: BTreeMap<PathBuf, Roles> = BTreeMap::new();
        for sp in &skip_paths {
            let exists = sp.exists();
            let f = exclusion_finding(sp, &home, ExclusionKind::FixedPath, exists, None);
            ctx.emit(f).await;
            if exists {
                jobs.entry(sp.clone()).or_default().exclusion = Some(ExclusionKind::FixedPath);
            }
        }

        let mut enumeration = match enumeration {
            Some(e) => e,
            None => {
                // tmutil itself is unavailable: still size the configured
                // exclusions, but the estimate and suggestions need isexcluded.
                ctx.emit(estimate_unavailable_finding(&home)).await;
                run_sizing(&ctx, jobs, None, &home, quota_bytes, data_used_bytes).await;
                ctx.progress("done", 6, Some(6)).await;
                return Ok(());
            }
        };

        enumeration.skip_paths_known = prefs.is_some();

        // Sticky/default exclusions are only shown once sized (most are tiny
        // system-managed folders that would just be noise).
        for p in &enumeration.sticky_excluded {
            let kind = if is_macos_default_exclusion(p, &home) {
                ExclusionKind::MacosDefault
            } else {
                ExclusionKind::StickyOrDefault
            };
            jobs.entry(p.clone()).or_default().exclusion = Some(kind);
        }
        for c in &enumeration.included_candidates {
            let roles = jobs.entry(c.path.clone()).or_default();
            roles.candidate = Some(c.candidate);
            roles.estimate_root = c.counted_separately;
        }
        for hw in &enumeration.hub_walks {
            let roles = jobs.entry(hw.hub.clone()).or_default();
            roles.estimate_root = true;
            roles.hub_skip = Some(hw.skip.clone());
        }

        ctx.emit(estimate_finding(&EstimateState::pending(
            &enumeration,
            &home,
            quota_bytes,
            data_used_bytes,
        )))
        .await;

        // 5. Size everything once, streaming re-emits.
        ctx.progress("measuring backup set", 4, Some(6)).await;
        run_sizing(
            &ctx,
            jobs,
            Some(enumeration),
            &home,
            quota_bytes,
            data_used_bytes,
        )
        .await;
        ctx.progress("done", 6, Some(6)).await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Stage 1: local snapshots
// ---------------------------------------------------------------------------

/// Emit one Reclaimable finding per local snapshot; returns how many. If tmutil
/// is absent or errors, emit a single Info finding and return 0.
async fn scan_local_snapshots(ctx: &ScanCtx) -> u64 {
    let out = match ctx
        .runner
        .run("tmutil", &["listlocalsnapshots", "/"], &ctx.token)
        .await
    {
        Ok(o) if o.success() => o,
        Ok(o) => {
            emit_unavailable(ctx, o.stderr_str().trim()).await;
            return 0;
        }
        Err(e) => {
            emit_unavailable(ctx, &e.to_string()).await;
            return 0;
        }
    };

    let mut count = 0;
    for line in out.stdout_str().lines() {
        let Some((name, date)) = parse_snapshot_line(line) else {
            continue;
        };
        count += 1;
        let human = humanize_date(&date);
        let finding = Finding::new(
            FindingKind::LocalSnapshot,
            &name,
            format!("Local snapshot {human}"),
        )
        .detail(format!(
            "Time Machine local snapshot {name}; macOS manages its purgeable space and does not report a reliable per-snapshot reclaimable size — see the Purgeable space row for the total."
        ))
        .severity(Severity::Reclaimable)
        .provenance("tmutil listlocalsnapshots /")
        .coverage("Presence is measured; reclaimable bytes are intentionally not estimated per snapshot.")
        .meta(json!({
            "group": GROUP_SNAPSHOTS,
            "status": human,
            "name": name,
            "date": date,
        }))
        .remedy(
            Remedy::new(
                "Delete local snapshot",
                RemedyCommand::Shell {
                    program: "tmutil".to_string(),
                    args: vec!["deletelocalsnapshots".to_string(), date.clone()],
                },
            )
            .destructive(),
        );
        ctx.emit(finding).await;
    }
    count
}

async fn emit_unavailable(ctx: &ScanCtx, detail: &str) {
    ctx.emit(
        Finding::new(
            FindingKind::LocalSnapshot,
            "tmutil:unavailable",
            "tmutil not available",
        )
        .detail(if detail.is_empty() {
            "tmutil is missing or failed to list local snapshots".to_string()
        } else {
            detail.to_string()
        })
        .severity(Severity::Info)
        .meta(json!({ "group": GROUP_SNAPSHOTS, "status": "unavailable" })),
    )
    .await;
}

/// Parse one line of `tmutil listlocalsnapshots /` output. Data lines look
/// like `com.apple.TimeMachine.2024-06-01-120000.local`; header/prose lines
/// (e.g. "Snapshots for disk /:") are skipped. Returns the full snapshot
/// identifier and the extracted `YYYY-MM-DD-HHMMSS` date string.
fn parse_snapshot_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    let rest = line.strip_prefix("com.apple.TimeMachine.")?;
    let date = rest.strip_suffix(".local").unwrap_or(rest);
    if date.is_empty() {
        return None;
    }
    Some((line.to_string(), date.to_string()))
}

/// Best-effort "YYYY-MM-DD-HHMMSS" -> "YYYY-MM-DD HH:MM:SS" formatting for
/// the finding title. Falls back to the raw string if it isn't the expected
/// fixed-width shape.
fn humanize_date(date: &str) -> String {
    let bytes = date.as_bytes();
    if bytes.len() == 17 && date.chars().filter(|c| *c == '-').count() == 3 {
        let ymd = &date[0..10];
        let hms = &date[11..17];
        format!("{ymd} {}:{}:{}", &hms[0..2], &hms[2..4], &hms[4..6])
    } else {
        date.to_string()
    }
}

// ---------------------------------------------------------------------------
// Stage 2: purgeable space
// ---------------------------------------------------------------------------

fn purgeable_finding(cap: &volume::MacosCapacity, snapshot_count: u64) -> Finding {
    let purgeable = cap.purgeable();
    Finding::new(FindingKind::TmPurgeable, "purgeable", "Purgeable space")
        .size(purgeable)
        .severity(Severity::Info)
        .detail(format!(
            "Up to {} is held by local Time Machine snapshots and other purgeable data macOS frees on demand. This is an upper bound on what deleting all {snapshot_count} local snapshots would free; macOS does not report per-snapshot sizes.",
            human(purgeable)
        ))
        .provenance("NSURLVolumeAvailableCapacityForImportantUsageKey minus real free space (osascript, Foundation only)")
        .meta(json!({
            "group": GROUP_SNAPSHOTS,
            "status": "upper bound",
            "macos_available_bytes": cap.important,
            "apfs_free_bytes": cap.physical,
            "snapshot_count": snapshot_count,
        }))
        .remedy(
            Remedy::new(
                "Thin local snapshots (aggressive)",
                RemedyCommand::Shell {
                    program: "tmutil".to_string(),
                    args: vec![
                        "thinlocalsnapshots".to_string(),
                        "/".to_string(),
                        "9999999999999".to_string(),
                        "4".to_string(),
                    ],
                },
            )
            .destructive(),
        )
}

// ---------------------------------------------------------------------------
// Stage 3: preferences, destinations, stale mounts
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
struct TmPrefs {
    auto_backup: Option<bool>,
    auto_backup_interval: Option<u64>,
    skip_paths: Vec<PathBuf>,
    last_destination_id: Option<String>,
    destinations: Vec<TmPrefsDestination>,
}

#[derive(Debug, Default, Clone)]
struct TmPrefsDestination {
    id: String,
    volume_name: Option<String>,
    network_url: Option<String>,
    quota_gb: Option<u64>,
    bytes_available: Option<u64>,
    bytes_used: Option<u64>,
    result: Option<i64>,
    snapshot_dates: Vec<SystemTime>,
    attempt_dates: Vec<SystemTime>,
}

#[derive(Debug, Default, Clone)]
struct TmDestInfo {
    id: String,
    name: Option<String>,
    kind: Option<String>,
    url: Option<String>,
    mount_point: Option<PathBuf>,
    quota_gb: Option<u64>,
    last: bool,
}

/// A destination as shown to the user: the union of what `destinationinfo`
/// knows (live: mount point, kind) and what the preferences remember
/// (history: result, dates, bytes).
#[derive(Debug, Default, Clone)]
struct Destination {
    id: String,
    info: Option<TmDestInfo>,
    prefs: Option<TmPrefsDestination>,
}

/// The preferences via `defaults export` (cfprefsd, no Full Disk Access
/// needed), falling back to reading the plist file directly.
async fn load_prefs(ctx: &ScanCtx, prefs_path: &Path) -> Option<TmPrefs> {
    let domain = prefs_path.with_extension("").to_string_lossy().into_owned();
    if let Some(out) =
        crate::scan::run_with_timeout(ctx, "defaults", &["export", &domain, "-"], CMD_TIMEOUT).await
    {
        if let Ok(v) = plist::Value::from_reader_xml(std::io::Cursor::new(out.stdout)) {
            return Some(parse_prefs(&v));
        }
    }
    plist::Value::from_file(prefs_path)
        .ok()
        .map(|v| parse_prefs(&v))
}

async fn load_destinationinfo(ctx: &ScanCtx) -> Vec<TmDestInfo> {
    let Some(out) =
        crate::scan::run_with_timeout(ctx, "tmutil", &["destinationinfo", "-X"], CMD_TIMEOUT).await
    else {
        return Vec::new();
    };
    plist::Value::from_reader_xml(std::io::Cursor::new(out.stdout))
        .ok()
        .map(|v| parse_destinationinfo(&v))
        .unwrap_or_default()
}

fn parse_prefs(v: &plist::Value) -> TmPrefs {
    let Some(dict) = v.as_dictionary() else {
        return TmPrefs::default();
    };
    let destinations = dict
        .get("Destinations")
        .and_then(|d| d.as_array())
        .map(|arr| arr.iter().filter_map(parse_prefs_destination).collect())
        .unwrap_or_default();
    TmPrefs {
        auto_backup: dict.get("AutoBackup").and_then(plist_bool),
        auto_backup_interval: dict
            .get("AutoBackupInterval")
            .and_then(|v| v.as_unsigned_integer()),
        skip_paths: dict
            .get("SkipPaths")
            .and_then(|s| s.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|p| p.as_string())
                    .map(PathBuf::from)
                    .collect()
            })
            .unwrap_or_default(),
        last_destination_id: dict
            .get("LastDestinationID")
            .and_then(|v| v.as_string())
            .map(str::to_string),
        destinations,
    }
}

fn parse_prefs_destination(v: &plist::Value) -> Option<TmPrefsDestination> {
    let d = v.as_dictionary()?;
    let id = d.get("DestinationID")?.as_string()?.to_string();
    let dates = |key: &str| -> Vec<SystemTime> {
        let mut out: Vec<SystemTime> = d
            .get(key)
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_date())
                    .map(SystemTime::from)
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    };
    Some(TmPrefsDestination {
        id,
        volume_name: d
            .get("LastKnownVolumeName")
            .and_then(|v| v.as_string())
            .map(str::to_string),
        network_url: d
            .get("NetworkURL")
            .and_then(|v| v.as_string())
            .map(str::to_string),
        quota_gb: d.get("QuotaGB").and_then(|v| v.as_unsigned_integer()),
        bytes_available: d
            .get("BytesAvailable")
            .and_then(|v| v.as_unsigned_integer()),
        bytes_used: d.get("BytesUsed").and_then(|v| v.as_unsigned_integer()),
        result: d.get("RESULT").and_then(|v| v.as_signed_integer()),
        snapshot_dates: dates("SnapshotDates"),
        attempt_dates: dates("AttemptDates"),
    })
}

fn parse_destinationinfo(v: &plist::Value) -> Vec<TmDestInfo> {
    let Some(arr) = v
        .as_dictionary()
        .and_then(|d| d.get("Destinations"))
        .and_then(|d| d.as_array())
    else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|item| {
            let d = item.as_dictionary()?;
            let id = d.get("ID")?.as_string()?.to_string();
            let s = |k: &str| d.get(k).and_then(|v| v.as_string()).map(str::to_string);
            Some(TmDestInfo {
                id,
                name: s("Name"),
                kind: s("Kind"),
                url: s("URL"),
                mount_point: s("MountPoint").map(PathBuf::from),
                quota_gb: d.get("QuotaGB").and_then(|v| v.as_unsigned_integer()),
                last: d
                    .get("LastDestination")
                    .and_then(plist_bool)
                    .unwrap_or(false),
            })
        })
        .collect()
}

/// `defaults export` writes booleans as `<integer>1</integer>`; the raw plist
/// uses `<true/>`. Accept both.
fn plist_bool(v: &plist::Value) -> Option<bool> {
    v.as_boolean()
        .or_else(|| v.as_unsigned_integer().map(|n| n != 0))
        .or_else(|| v.as_signed_integer().map(|n| n != 0))
}

fn merge_destinations(prefs: Option<&TmPrefs>, info: &[TmDestInfo]) -> Vec<Destination> {
    let mut by_id: BTreeMap<String, Destination> = BTreeMap::new();
    for i in info {
        by_id
            .entry(i.id.clone())
            .or_insert_with(|| Destination {
                id: i.id.clone(),
                ..Default::default()
            })
            .info = Some(i.clone());
    }
    if let Some(p) = prefs {
        for d in &p.destinations {
            by_id
                .entry(d.id.clone())
                .or_insert_with(|| Destination {
                    id: d.id.clone(),
                    ..Default::default()
                })
                .prefs = Some(d.clone());
        }
    }
    by_id.into_values().collect()
}

/// The quota the estimate is compared against: the destination Time Machine
/// used last, else the first one with a quota.
fn estimate_quota(destinations: &[Destination], prefs: Option<&TmPrefs>) -> Option<u64> {
    let quota_of = |d: &Destination| -> Option<u64> {
        d.info
            .as_ref()
            .and_then(|i| i.quota_gb)
            .or_else(|| d.prefs.as_ref().and_then(|p| p.quota_gb))
            .map(gb_to_bytes)
    };
    let last_id = destinations
        .iter()
        .find(|d| d.info.as_ref().is_some_and(|i| i.last))
        .map(|d| d.id.clone())
        .or_else(|| prefs.and_then(|p| p.last_destination_id.clone()));
    if let Some(id) = last_id {
        if let Some(d) = destinations.iter().find(|d| d.id == id) {
            if let Some(q) = quota_of(d) {
                return Some(q);
            }
        }
    }
    destinations.iter().find_map(quota_of)
}

/// Apple's `QuotaGB` is decimal gigabytes.
fn gb_to_bytes(gb: u64) -> u64 {
    gb.saturating_mul(1_000_000_000)
}

/// Human label for the `RESULT` code Time Machine stores after each attempt.
fn result_label(code: i64) -> String {
    match code {
        0 => "OK".to_string(),
        56 => "destination full".to_string(),
        n => format!("error {n}"),
    }
}

fn destination_finding(
    d: &Destination,
    prefs: Option<&TmPrefs>,
    now: SystemTime,
    stale_days: u64,
) -> Finding {
    let title = d
        .prefs
        .as_ref()
        .and_then(|p| p.volume_name.clone())
        .or_else(|| d.info.as_ref().and_then(|i| i.name.clone()))
        .unwrap_or_else(|| "Time Machine destination".to_string());
    let quota_bytes = d
        .info
        .as_ref()
        .and_then(|i| i.quota_gb)
        .or_else(|| d.prefs.as_ref().and_then(|p| p.quota_gb))
        .map(gb_to_bytes);
    let mounted = d
        .info
        .as_ref()
        .and_then(|i| i.mount_point.as_ref())
        .is_some();
    let auto_backup = prefs.and_then(|p| p.auto_backup);

    let mut f = Finding::new(FindingKind::TmDestination, &d.id, title);
    let mut meta = serde_json::Map::new();
    meta.insert("group".into(), json!(GROUP_BACKUP));
    meta.insert("destination_id".into(), json!(d.id));
    meta.insert("mounted".into(), json!(mounted));
    meta.insert("prefs_readable".into(), json!(d.prefs.is_some()));
    if let Some(q) = quota_bytes {
        meta.insert("quota_bytes".into(), json!(q));
    }
    if let Some(i) = &d.info {
        if let Some(k) = &i.kind {
            meta.insert("kind".into(), json!(k));
        }
        if let Some(u) = &i.url {
            meta.insert("network_url".into(), json!(u));
        }
        if let Some(mp) = &i.mount_point {
            f = f.path(mp.clone());
        }
    }
    if let Some(a) = auto_backup {
        meta.insert("auto_backup".into(), json!(a));
    }
    if let Some(secs) = prefs.and_then(|p| p.auto_backup_interval) {
        meta.insert("auto_backup_interval_secs".into(), json!(secs));
    }

    let mut severity = Severity::Info;
    let status;
    let detail;
    match &d.prefs {
        Some(p) => {
            if let Some(u) = &p.network_url {
                meta.entry("network_url").or_insert(json!(u));
            }
            meta.entry("kind")
                .or_insert(json!(if p.network_url.is_some() {
                    "Network"
                } else {
                    "Local"
                }));
            if let Some(b) = p.bytes_used {
                f = f.size(b);
                meta.insert("bytes_used".into(), json!(b));
            }
            if let Some(b) = p.bytes_available {
                meta.insert("bytes_available".into(), json!(b));
            }
            let result = p.result.unwrap_or(0);
            let label = result_label(result);
            meta.insert("result".into(), json!(result));
            meta.insert("result_label".into(), json!(label));
            meta.insert("backup_count".into(), json!(p.snapshot_dates.len()));
            meta.insert("attempt_count".into(), json!(p.attempt_dates.len()));
            if let Some(first) = p.snapshot_dates.first() {
                meta.insert("oldest_backup".into(), json!(format_time(*first)));
            }
            if let Some(last_attempt) = p.attempt_dates.last() {
                meta.insert("last_attempt".into(), json!(format_time(*last_attempt)));
            }

            let last = p.snapshot_dates.last().copied();
            let age_days = last.map(|t| days_between(t, now));
            if let Some(t) = last {
                f = f.last_used(t);
                meta.insert("last_backup".into(), json!(format_time(t)));
            }
            if let Some(days) = age_days {
                meta.insert("last_backup_days".into(), json!(days));
            }

            let stale = age_days.is_none_or(|days| days > stale_days);
            let failed = result != 0;
            let nearly_full_single = match (p.bytes_available, quota_bytes) {
                (Some(avail), Some(q)) if q > 0 => {
                    avail.saturating_mul(10) < q && p.snapshot_dates.len() <= 1
                }
                _ => false,
            };
            if failed || stale || nearly_full_single {
                severity = Severity::Warning;
            } else if auto_backup == Some(false) {
                severity = Severity::Attention;
            }

            let age_text = match age_days {
                Some(0) => "today".to_string(),
                Some(days) => format!("{days}d ago"),
                None => "never".to_string(),
            };
            status = if failed {
                format!("Failed ({label}) · {age_text}")
            } else if last.is_none() {
                "Never completed".to_string()
            } else {
                format!("OK · {age_text}")
            };

            let mut parts: Vec<String> = Vec::new();
            match last {
                Some(t) => parts.push(format!(
                    "Last successful backup {} ({age_text})",
                    format_time(t)
                )),
                None => parts.push("No backup has ever completed to this destination".to_string()),
            }
            if failed {
                parts.push(format!(
                    "the most recent attempt ended with result {result} ({label})"
                ));
            }
            if let (Some(used), Some(avail)) = (p.bytes_used, p.bytes_available) {
                let total = used.saturating_add(avail);
                let pct = if total > 0 { used * 100 / total } else { 0 };
                parts.push(format!(
                    "{} used, {} free ({pct}% full)",
                    human(used),
                    human(avail)
                ));
            }
            if p.snapshot_dates.len() <= 1 && p.bytes_used.is_some() {
                parts.push("only one backup exists, so Time Machine has nothing older to thin when space runs out".to_string());
            }
            if auto_backup == Some(false) {
                parts.push("automatic backups are off".to_string());
            }
            detail = parts.join("; ") + ".";
        }
        None => {
            status = "configured (history unavailable)".to_string();
            detail = "Destination is configured, but the Time Machine preferences could not be read, so the backup history and last result are unknown.".to_string();
        }
    }
    meta.insert("status".into(), json!(status));

    if let Some(mp) = d.info.as_ref().and_then(|i| i.mount_point.clone()) {
        f = f.remedy(Remedy::new(
            "Reveal in Finder",
            RemedyCommand::RevealInFinder { path: mp },
        ));
    }
    f.detail(detail)
        .severity(severity)
        .provenance("tmutil destinationinfo -X; defaults export com.apple.TimeMachine")
        .meta(serde_json::Value::Object(meta))
}

fn not_configured_finding(prefs_readable: bool) -> Finding {
    Finding::new(
        FindingKind::TmDestination,
        "none",
        "Time Machine not configured",
    )
    .detail(if prefs_readable {
        "No backup destination is configured. Add one in System Settings → General → Time Machine."
    } else {
        "No backup destination was reported by tmutil, and the Time Machine preferences could not be read."
    })
    .severity(Severity::Info)
    .provenance("tmutil destinationinfo -X; defaults export com.apple.TimeMachine")
    .meta(json!({
        "group": GROUP_BACKUP,
        "status": "not configured",
        "destination_id": "none",
        "prefs_readable": prefs_readable,
    }))
}

/// Leftover mount-point directories in `/Volumes`: Time Machine mounts a
/// network destination's disk image as `Backups of <Mac>` and after an unclean
/// unmount the empty directory stays, so the next mount lands on `… 1`, `… 2`.
/// A stub shares `/Volumes`' device id; a live mount has its own.
fn stale_mount_findings(volumes_dir: &Path) -> Vec<Finding> {
    use std::os::unix::fs::MetadataExt;
    let Ok(volumes_dev) = std::fs::metadata(volumes_dir).map(|m| m.dev()) else {
        return Vec::new();
    };
    let Ok(rd) = std::fs::read_dir(volumes_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("Backups of ") {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() || meta.file_type().is_symlink() || meta.dev() != volumes_dev {
            continue;
        }
        let path_str = path.to_string_lossy().into_owned();
        out.push(
            Finding::new(FindingKind::TmStaleMount, &path_str, name)
                .path(path.clone())
                .severity(Severity::Attention)
                .detail(
                    "Leftover mount point from a Time Machine network destination that was not unmounted cleanly. Nothing is mounted here; the live backup image mounts under a numbered sibling instead. Removing it needs admin rights."
                )
                .provenance("/Volumes listing; device id compared with /Volumes")
                .meta(json!({ "group": GROUP_BACKUP, "status": "Not mounted" }))
                .remedy(Remedy::new(
                    "Copy rmdir command (needs admin)",
                    RemedyCommand::CopyToClipboard {
                        text: format!("sudo rmdir {}", crate::model::shell_quote(&path_str)),
                    },
                ))
                .remedy(
                    Remedy::new(
                        "Reveal in Finder",
                        RemedyCommand::RevealInFinder { path: path.clone() },
                    )
                    .alternative(),
                ),
        );
    }
    out.sort_by(|a, b| a.title.cmp(&b.title));
    out
}

// ---------------------------------------------------------------------------
// Stage 4: classification and enumeration
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Exclusion {
    Excluded,
    Included,
    /// Path does not exist (`[UNKNOWN]`).
    Unknown,
    /// Unreadable by this process (macOS privacy controls); never sent to
    /// tmutil and never sized.
    Protected,
}

/// Parse `tmutil isexcluded` output: `[Excluded]  /p`, `[Included]  /p`,
/// `[UNKNOWN]   /p`. Lines that don't match are skipped (the Full Disk Access
/// complaint goes to stderr, but be tolerant).
fn parse_isexcluded(stdout: &str) -> Vec<(PathBuf, Exclusion)> {
    stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim_end();
            let rest = line.strip_prefix('[')?;
            let close = rest.find(']')?;
            let status = match &rest[..close] {
                "Excluded" => Exclusion::Excluded,
                "Included" => Exclusion::Included,
                "UNKNOWN" => Exclusion::Unknown,
                _ => return None,
            };
            let path = rest[close + 1..].trim_start();
            if path.is_empty() {
                return None;
            }
            Some((PathBuf::from(path), status))
        })
        .collect()
}

/// Classify `paths` with batched `tmutil isexcluded`. `None` when tmutil could
/// not be run at all (missing, or a blank mock runner) — callers then skip the
/// estimate and suggestions rather than guessing.
///
/// Two macOS behaviours are handled here: directories this process cannot
/// read are marked `Protected` up front (never passed to tmutil), and because
/// `tmutil isexcluded` still aborts at the first privacy-protected argument it
/// missed (exit 80, only the earlier paths reported), a short answer marks the
/// first unreported path `Protected` and resumes with the remainder.
async fn classify(ctx: &ScanCtx, paths: Vec<PathBuf>) -> Option<HashMap<PathBuf, Exclusion>> {
    let mut result: HashMap<PathBuf, Exclusion> = HashMap::new();
    let mut pending: Vec<PathBuf> = Vec::new();
    {
        let paths_probe = paths.clone();
        let protected: HashSet<PathBuf> = tokio::task::spawn_blocking(move || {
            paths_probe
                .into_iter()
                .filter(|p| p.is_dir() && is_permission_denied(p))
                .collect()
        })
        .await
        .unwrap_or_default();
        for p in paths {
            if protected.contains(&p) {
                result.insert(p, Exclusion::Protected);
            } else {
                pending.push(p);
            }
        }
    }

    let mut first_call = true;
    let mut queue: std::collections::VecDeque<Vec<PathBuf>> = pending
        .chunks(ISEXCLUDED_CHUNK)
        .map(|c| c.to_vec())
        .collect();
    while let Some(chunk) = queue.pop_front() {
        if chunk.is_empty() || ctx.cancelled() {
            continue;
        }
        let arg_strings: Vec<String> = chunk
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let mut args: Vec<&str> = vec!["isexcluded"];
        args.extend(arg_strings.iter().map(String::as_str));
        let out = match tokio::time::timeout(
            Duration::from_secs(60),
            ctx.runner.run("tmutil", &args, &ctx.token),
        )
        .await
        {
            Ok(Ok(out)) => out,
            Ok(Err(_)) | Err(_) if first_call => return None,
            Ok(Err(_)) | Err(_) => {
                for p in chunk {
                    result.entry(p).or_insert(Exclusion::Unknown);
                }
                continue;
            }
        };
        first_call = false;

        let parsed = parse_isexcluded(&out.stdout_str());
        let by_path: HashMap<PathBuf, Exclusion> = parsed.iter().cloned().collect();
        let mut reported = 0usize;
        for p in &chunk {
            match by_path.get(p) {
                Some(status) => {
                    result.insert(p.clone(), *status);
                    reported += 1;
                }
                None => break,
            }
        }
        if reported < chunk.len() {
            // tmutil stopped at a path it may not read: mark it, resume after.
            result.insert(chunk[reported].clone(), Exclusion::Protected);
            let rest: Vec<PathBuf> = chunk[reported + 1..].to_vec();
            if !rest.is_empty() {
                queue.push_front(rest);
            }
        }
    }
    Some(result)
}

fn is_permission_denied(p: &Path) -> bool {
    matches!(
        std::fs::read_dir(p),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied
    )
}

/// A suggested-exclusion root: something regenerable or already in the cloud.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Candidate {
    rel: &'static str,
    reason: Reason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason {
    RegenerableCache,
    BuildProducts,
    CloudSynced,
}

impl Reason {
    fn tag(self) -> &'static str {
        match self {
            Reason::RegenerableCache => "regenerable_cache",
            Reason::BuildProducts => "build_products",
            Reason::CloudSynced => "cloud_synced",
        }
    }
}

const CANDIDATES: &[Candidate] = &[
    Candidate {
        rel: "~/.cache",
        reason: Reason::RegenerableCache,
    },
    Candidate {
        rel: "~/.codex",
        reason: Reason::RegenerableCache,
    },
    Candidate {
        rel: "~/.cargo",
        reason: Reason::RegenerableCache,
    },
    Candidate {
        rel: "~/.rustup",
        reason: Reason::RegenerableCache,
    },
    Candidate {
        rel: "~/.npm",
        reason: Reason::RegenerableCache,
    },
    Candidate {
        rel: "~/.nx",
        reason: Reason::RegenerableCache,
    },
    Candidate {
        rel: "~/.bun",
        reason: Reason::RegenerableCache,
    },
    Candidate {
        rel: "~/.gradle",
        reason: Reason::RegenerableCache,
    },
    Candidate {
        rel: "~/.m2",
        reason: Reason::RegenerableCache,
    },
    Candidate {
        rel: "~/.pnpm-store",
        reason: Reason::RegenerableCache,
    },
    Candidate {
        rel: "~/Library/pnpm",
        reason: Reason::RegenerableCache,
    },
    Candidate {
        rel: "~/Library/Caches",
        reason: Reason::RegenerableCache,
    },
    Candidate {
        rel: "~/Library/Developer",
        reason: Reason::BuildProducts,
    },
    Candidate {
        rel: "~/Library/Developer/Xcode/DerivedData",
        reason: Reason::BuildProducts,
    },
    Candidate {
        rel: "~/Library/Developer/CoreSimulator",
        reason: Reason::BuildProducts,
    },
    Candidate {
        rel: "~/Library/Containers/com.docker.docker",
        reason: Reason::RegenerableCache,
    },
    Candidate {
        rel: "~/My Drive",
        reason: Reason::CloudSynced,
    },
    Candidate {
        rel: "~/Google Drive",
        reason: Reason::CloudSynced,
    },
    Candidate {
        rel: "~/Dropbox",
        reason: Reason::CloudSynced,
    },
    Candidate {
        rel: "~/Library/CloudStorage",
        reason: Reason::CloudSynced,
    },
    Candidate {
        rel: "~/Library/Mobile Documents",
        reason: Reason::CloudSynced,
    },
];

#[derive(Clone, Debug)]
struct CandidatePath {
    path: PathBuf,
    candidate: Candidate,
    /// Left out of its parent hub's walk and counted via its own measurement.
    counted_separately: bool,
}

/// Built-in candidates plus the user's `extra_candidates`, expanded against
/// home and filtered to directories that exist.
fn candidate_roots(ctx: &ScanCtx) -> Vec<CandidatePath> {
    let mut out: Vec<CandidatePath> = CANDIDATES
        .iter()
        .map(|c| CandidatePath {
            path: ctx.paths.expand(c.rel),
            candidate: *c,
            counted_separately: false,
        })
        .collect();
    for rel in &ctx.config.time_machine.extra_candidates {
        // Config strings aren't 'static; user extras are labelled as caches.
        out.push(CandidatePath {
            path: ctx.paths.expand(rel),
            candidate: Candidate {
                rel: "",
                reason: Reason::RegenerableCache,
            },
            counted_separately: false,
        });
    }
    out.retain(|c| c.path.is_dir());
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    out
}

/// Hubs are directories whose children are classified individually; every
/// other included directory is sized whole.
fn hubs(system_root: &Path, home: &Path) -> Vec<PathBuf> {
    let lib = home.join("Library");
    let mut v = vec![
        system_root.to_path_buf(),
        system_root.join("Users"),
        system_root.join("private"),
        system_root.join("private/var"),
        home.to_path_buf(),
        lib.clone(),
        lib.join("Application Support"),
        lib.join("Containers"),
        lib.join("Group Containers"),
    ];
    v.dedup();
    v
}

/// Top-level names under `/` that are never part of a backup set and would
/// only cost tmutil calls (other volumes, devfs, the sealed system volume).
const ROOT_SKIP_NAMES: &[&str] = &["Volumes", "dev", "System", "cores", "home", "net"];

/// One hub to size in a single pass, leaving out the children that are
/// excluded, unreadable, hubs of their own, or measured separately.
#[derive(Debug, Clone)]
struct HubWalk {
    hub: PathBuf,
    skip: HashSet<PathBuf>,
}

#[derive(Debug, Default)]
struct Enumeration {
    /// Included hubs, each with the children its walk must not enter.
    hub_walks: Vec<HubWalk>,
    /// Excluded directories under home that no SkipPath covers.
    sticky_excluded: Vec<PathBuf>,
    /// Unreadable directories (privacy-protected): neither classified nor sized.
    protected: Vec<PathBuf>,
    /// Other users' home directories that were not measured.
    other_homes: usize,
    /// Candidates that exist and are currently included.
    included_candidates: Vec<CandidatePath>,
    /// Whether the configured exclusion list was available at all.
    skip_paths_known: bool,
}

impl Enumeration {
    /// How many separately measured pieces make up the estimate.
    fn roots_total(&self) -> usize {
        self.hub_walks.len()
            + self
                .included_candidates
                .iter()
                .filter(|c| c.counted_separately)
                .count()
    }
}

/// Walk the hubs, classify their children, and decide what to size.
async fn enumerate(
    ctx: &ScanCtx,
    system_root: &Path,
    home: &Path,
    skip_paths: &[PathBuf],
    candidates: &[CandidatePath],
) -> Option<Enumeration> {
    use std::os::unix::fs::MetadataExt;

    let hub_set: HashSet<PathBuf> = hubs(system_root, home).into_iter().collect();
    let mut en = Enumeration::default();

    // Gather every directory that needs classifying: hub children (breadth
    // first), configured exclusions, candidates. Children a hub's walk must
    // never enter regardless of classification (other volumes, `/dev`, other
    // users' homes) are recorded as pre-skips.
    let mut to_classify: Vec<PathBuf> = Vec::new();
    let mut hub_children: Vec<(PathBuf, Vec<PathBuf>, HashSet<PathBuf>)> = Vec::new();
    let mut queue: std::collections::VecDeque<PathBuf> =
        [system_root.to_path_buf(), home.to_path_buf()]
            .into_iter()
            .collect();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let users_dir = system_root.join("Users");
    while let Some(hub) = queue.pop_front() {
        if !seen.insert(hub.clone()) || !hub.is_dir() {
            continue;
        }
        let Ok(hub_meta) = std::fs::metadata(&hub) else {
            continue;
        };
        let Ok(rd) = std::fs::read_dir(&hub) else {
            en.protected.push(hub.clone());
            continue;
        };
        let mut children: Vec<PathBuf> = Vec::new();
        let mut pre_skip: HashSet<PathBuf> = HashSet::new();
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() || !meta.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let foreign_volume = meta.dev() != hub_meta.dev();
            let root_noise = hub == system_root && ROOT_SKIP_NAMES.iter().any(|s| name == *s);
            let other_home = hub == users_dir && path != home && name != "Shared";
            if other_home {
                en.other_homes += 1;
            }
            if foreign_volume || root_noise || other_home {
                pre_skip.insert(path);
                continue;
            }
            children.push(path);
        }
        children.sort();
        for child in &children {
            if hub_set.contains(child) {
                queue.push_back(child.clone());
            }
        }
        to_classify.extend(children.iter().cloned());
        hub_children.push((hub, children, pre_skip));
    }
    to_classify.extend(skip_paths.iter().filter(|p| p.is_dir()).cloned());
    to_classify.extend(candidates.iter().map(|c| c.path.clone()));
    to_classify.sort();
    to_classify.dedup();

    let status = classify(ctx, to_classify).await?;

    // Candidates: included, and not nested inside another included candidate.
    let mut included: Vec<CandidatePath> = candidates
        .iter()
        .filter(|c| status.get(&c.path) == Some(&Exclusion::Included))
        .cloned()
        .collect();
    let parents: Vec<PathBuf> = included.iter().map(|c| c.path.clone()).collect();
    included.retain(|c| {
        !parents
            .iter()
            .any(|p| p != &c.path && c.path.starts_with(p))
    });
    // A candidate directly inside a hub is left out of the hub's walk and
    // counted through its own measurement instead (one walk, two roles).
    let candidate_children: HashSet<PathBuf> = included
        .iter()
        .filter(|c| c.path.parent().is_some_and(|p| hub_set.contains(p)))
        .map(|c| c.path.clone())
        .collect();
    for c in &mut included {
        c.counted_separately = candidate_children.contains(&c.path);
    }

    // Build one walk per hub; a hub under an excluded directory contributes
    // nothing at all.
    let mut excluded_dirs: Vec<PathBuf> = Vec::new();
    for (hub, children, mut skip) in hub_children {
        if excluded_dirs.iter().any(|e| hub.starts_with(e)) {
            continue;
        }
        for child in &children {
            match status.get(child).copied().unwrap_or(Exclusion::Unknown) {
                Exclusion::Excluded => {
                    excluded_dirs.push(child.clone());
                    skip.insert(child.clone());
                    if child.starts_with(home) && !skip_paths.iter().any(|sp| child.starts_with(sp))
                    {
                        en.sticky_excluded.push(child.clone());
                    }
                }
                Exclusion::Protected => {
                    en.protected.push(child.clone());
                    skip.insert(child.clone());
                }
                Exclusion::Unknown => {}
                Exclusion::Included => {
                    if hub_set.contains(child) || candidate_children.contains(child) {
                        skip.insert(child.clone());
                    }
                }
            }
        }
        en.hub_walks.push(HubWalk { hub, skip });
    }
    // Hubs that were themselves classified as excluded (e.g. `~/Library` under
    // a SkipPath) were pushed before their status was known: drop them now.
    en.hub_walks
        .retain(|hw| !excluded_dirs.iter().any(|e| hw.hub.starts_with(e)));

    en.included_candidates = included;
    en.sticky_excluded.sort();
    en.protected.sort();
    en.protected.dedup();
    Some(en)
}

// ---------------------------------------------------------------------------
// Stage 5: sizing (one walk per unique path) and the findings it produces
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExclusionKind {
    FixedPath,
    StickyOrDefault,
    MacosDefault,
}

impl ExclusionKind {
    fn tag(self) -> &'static str {
        match self {
            ExclusionKind::FixedPath => "fixed_path",
            ExclusionKind::StickyOrDefault => "sticky_or_default",
            ExclusionKind::MacosDefault => "macos_default",
        }
    }
    fn in_system_settings(self) -> bool {
        matches!(self, ExclusionKind::FixedPath)
    }
}

/// Which findings a measured path feeds. One path can serve several roles at
/// once (an included candidate is also counted into the estimate).
#[derive(Clone, Debug, Default)]
struct Roles {
    /// Counted into the estimate's included bytes.
    estimate_root: bool,
    /// Present for hub walks: children the walk must not enter.
    hub_skip: Option<HashSet<PathBuf>>,
    exclusion: Option<ExclusionKind>,
    candidate: Option<Candidate>,
}

/// Sticky/default exclusions smaller than this are noise (system-managed
/// folders macOS excludes on its own) and are not shown.
const STICKY_EXCLUSION_MIN_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default)]
struct Measured {
    bytes: u64,
    entries: u64,
    complete: bool,
    cached: bool,
    /// The directory itself is unreadable (macOS privacy controls), so the
    /// walk saw nothing — not a real zero.
    protected: bool,
}

/// Running totals behind the estimate finding, shared by the rayon workers.
#[derive(Debug, Default, Clone, Copy)]
struct EstimateTotals {
    included_bytes: u64,
    excluded_bytes: u64,
    roots_done: usize,
    roots_complete: usize,
}

struct EstimateState<'a> {
    home: &'a Path,
    enumeration: &'a Enumeration,
    totals: EstimateTotals,
    quota_bytes: Option<u64>,
    data_used_bytes: Option<u64>,
    finished: bool,
    budget_secs: u64,
    max_entries: u64,
}

impl<'a> EstimateState<'a> {
    fn pending(
        enumeration: &'a Enumeration,
        home: &'a Path,
        quota_bytes: Option<u64>,
        data_used_bytes: Option<u64>,
    ) -> Self {
        EstimateState {
            home,
            enumeration,
            totals: EstimateTotals::default(),
            quota_bytes,
            data_used_bytes,
            finished: false,
            budget_secs: 0,
            max_entries: 0,
        }
    }
}

/// Everything the blocking sizing pass needs, bundled so the worker closure
/// stays readable.
struct SizingShared {
    tx: tokio::sync::mpsc::Sender<ScanEvent>,
    gen: u64,
    token: tokio_util::sync::CancellationToken,
    home: PathBuf,
    cache: HashMap<PathBuf, CachedSize>,
    fresh: Mutex<Vec<(PathBuf, CachedSize)>>,
    totals: Mutex<EstimateTotals>,
    last_emit: Mutex<Instant>,
    enumeration: Option<Enumeration>,
    quota_bytes: Option<u64>,
    data_used_bytes: Option<u64>,
    now_secs: i64,
    ttl_hours: u64,
    /// Reset between the two sizing phases so each gets the full budget.
    deadline: Mutex<Instant>,
    budget_secs: u64,
    max_entries: u64,
    candidate_min_bytes: u64,
}

impl SizingShared {
    fn send(&self, f: Finding) {
        let _ = self.tx.blocking_send(ScanEvent::Finding {
            scanner: ScannerId::TimeMachine,
            gen: self.gen,
            finding: Box::new(f),
        });
    }

    fn cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Measure one path (cache first), never caching partial or zero results:
    /// with an unchanged root mtime a wrong size would be served as fresh for
    /// the whole TTL, and a privacy-protected tree reads as empty.
    fn measure(&self, path: &Path, skip: Option<&HashSet<PathBuf>>) -> Option<Measured> {
        let root_mtime = root_mtime_secs(path);
        // A hub walk's total depends on which children it left out, so it is
        // cached under a key that includes the skip set; a different set of
        // exclusions next run simply misses the cache.
        let cache_key = match skip {
            None => path.to_path_buf(),
            Some(skip) => path.join(format!("#macaudit-tm-hub-{:016x}", skip_set_hash(skip))),
        };
        if let Some(c) = self
            .cache
            .get(&cache_key)
            .filter(|c| c.size > 0 && is_fresh(c, root_mtime, self.now_secs, self.ttl_hours))
        {
            return Some(Measured {
                bytes: c.size,
                complete: true,
                cached: true,
                ..Measured::default()
            });
        }
        let deadline = *self.deadline.lock().unwrap();
        let m = if path.is_dir() && is_permission_denied(path) {
            Measured {
                protected: true,
                ..Measured::default()
            }
        } else if path.is_dir() {
            let empty = HashSet::new();
            let b = crate::scan::sizing::du_blocks_bounded_except(
                path,
                skip.unwrap_or(&empty),
                self.max_entries.max(1),
                deadline,
                &|| self.cancelled(),
            );
            Measured {
                bytes: b.bytes,
                entries: b.entries,
                complete: b.complete,
                ..Measured::default()
            }
        } else {
            Measured {
                bytes: std::fs::metadata(path)
                    .map(|m| on_disk_bytes(&m))
                    .unwrap_or(0),
                entries: 1,
                complete: true,
                ..Measured::default()
            }
        };
        if self.cancelled() {
            return None;
        }
        if m.complete && m.bytes > 0 {
            self.fresh.lock().unwrap().push((
                cache_key,
                CachedSize {
                    size: m.bytes,
                    computed_at: self.now_secs,
                    root_mtime,
                },
            ));
        }
        Some(m)
    }

    fn size_job(&self, path: &Path, roles: &Roles) {
        if self.cancelled() {
            return;
        }
        let Some(measured) = self.measure(path, roles.hub_skip.as_ref()) else {
            return;
        };

        if let Some(kind) = roles.exclusion {
            let show = kind == ExclusionKind::FixedPath
                || measured.bytes >= STICKY_EXCLUSION_MIN_BYTES
                || !measured.complete;
            if show {
                self.send(exclusion_finding(
                    path,
                    &self.home,
                    kind,
                    true,
                    Some(measured),
                ));
            }
        }
        if let Some(c) = roles.candidate {
            if measured.bytes >= self.candidate_min_bytes {
                self.send(candidate_finding(path, &self.home, c, measured));
            }
        }

        let mut t = self.totals.lock().unwrap();
        if roles.exclusion.is_some() {
            t.excluded_bytes = t.excluded_bytes.saturating_add(measured.bytes);
        }
        if roles.estimate_root {
            t.included_bytes = t.included_bytes.saturating_add(measured.bytes);
            t.roots_done += 1;
            if measured.complete {
                t.roots_complete += 1;
            }
            let snapshot = *t;
            drop(t);
            let mut le = self.last_emit.lock().unwrap();
            if le.elapsed() >= ESTIMATE_EMIT_INTERVAL {
                *le = Instant::now();
                drop(le);
                if let Some(en) = &self.enumeration {
                    self.send(estimate_finding(&EstimateState {
                        home: &self.home,
                        enumeration: en,
                        totals: snapshot,
                        quota_bytes: self.quota_bytes,
                        data_used_bytes: self.data_used_bytes,
                        finished: false,
                        budget_secs: self.budget_secs,
                        max_entries: self.max_entries,
                    }));
                }
            }
        }
    }
}

async fn run_sizing(
    ctx: &ScanCtx,
    jobs: BTreeMap<PathBuf, Roles>,
    enumeration: Option<Enumeration>,
    home: &Path,
    quota_bytes: Option<u64>,
    data_used_bytes: Option<u64>,
) {
    let tm_cfg = &ctx.config.time_machine;
    let paths_load = ctx.paths.clone();
    let cache: HashMap<PathBuf, CachedSize> = tokio::task::spawn_blocking(move || {
        SizeCache::open(&size_cache::db_path(&paths_load))
            .and_then(|c| c.load_all())
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let shared = Arc::new(SizingShared {
        tx: ctx.tx.clone(),
        gen: ctx.gen,
        token: ctx.token.clone(),
        home: home.to_path_buf(),
        cache,
        fresh: Mutex::new(Vec::new()),
        totals: Mutex::new(EstimateTotals::default()),
        last_emit: Mutex::new(Instant::now()),
        enumeration,
        quota_bytes,
        data_used_bytes,
        now_secs,
        ttl_hours: ctx.config.scan.size_cache_ttl_hours,
        deadline: Mutex::new(
            Instant::now() + Duration::from_secs(tm_cfg.estimate_budget_secs.max(1)),
        ),
        budget_secs: tm_cfg.estimate_budget_secs,
        max_entries: tm_cfg.estimate_max_entries_per_root,
        candidate_min_bytes: tm_cfg.candidate_min_mb.saturating_mul(1024 * 1024),
    });

    // Two passes: the small, directly user-facing exclusion/candidate walks
    // first, then the big hub walks — so a tight budget starves the estimate,
    // not the "saves X" numbers.
    type Jobs = Vec<(PathBuf, Roles)>;
    let (hubs, small): (Jobs, Jobs) = jobs.into_iter().partition(|(_, r)| r.hub_skip.is_some());
    let worker = {
        let shared = shared.clone();
        tokio::task::spawn_blocking(move || {
            use rayon::iter::{IntoParallelIterator, ParallelIterator};
            for (i, phase) in [small, hubs].into_iter().enumerate() {
                if i > 0 {
                    *shared.deadline.lock().unwrap() =
                        Instant::now() + Duration::from_secs(shared.budget_secs.max(1));
                }
                phase
                    .into_par_iter()
                    .for_each(|(path, roles)| shared.size_job(&path, &roles));
            }
        })
    };
    let _ = worker.await;

    if ctx.cancelled() {
        return;
    }

    // Final, authoritative estimate.
    if let Some(en) = &shared.enumeration {
        let totals = *shared.totals.lock().unwrap();
        ctx.emit(estimate_finding(&EstimateState {
            home,
            enumeration: en,
            totals,
            quota_bytes,
            data_used_bytes,
            finished: true,
            budget_secs: tm_cfg.estimate_budget_secs,
            max_entries: tm_cfg.estimate_max_entries_per_root,
        }))
        .await;
    }

    // Persist freshly measured sizes (best-effort; never load-bearing).
    let entries: Vec<(PathBuf, CachedSize)> = std::mem::take(&mut *shared.fresh.lock().unwrap());
    if !entries.is_empty() {
        let paths_save = ctx.paths.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(mut cache) = SizeCache::open(&size_cache::db_path(&paths_save)) {
                let _ = cache.upsert_batch(&entries);
            }
        })
        .await;
    }
}

fn exclusion_finding(
    path: &Path,
    home: &Path,
    kind: ExclusionKind,
    exists: bool,
    measured: Option<Measured>,
) -> Finding {
    let key = path.to_string_lossy().into_owned();
    let mut f = Finding::new(FindingKind::TmExclusion, &key, abbreviate_home(path, home))
        .path(path.to_path_buf())
        .severity(Severity::Info)
        .provenance(match kind {
            ExclusionKind::FixedPath => {
                "SkipPaths in com.apple.TimeMachine preferences; bounded local directory walk"
            }
            _ => "tmutil isexcluded; bounded local directory walk",
        });
    let mut meta = json!({
        "group": GROUP_EXCLUSIONS,
        "status": if exists { "Excluded" } else { "Excluded (missing)" },
        "exclusion_kind": kind.tag(),
        "in_system_settings": kind.in_system_settings(),
        "exists": exists,
    });
    let origin = match kind {
        ExclusionKind::FixedPath => "listed in System Settings → Time Machine → Options",
        ExclusionKind::StickyOrDefault => {
            "excluded by a per-item attribute or macOS default; not shown in System Settings"
        }
        ExclusionKind::MacosDefault => "excluded by macOS by default; not shown in System Settings",
    };
    let detail = match (exists, measured) {
        (false, _) => {
            format!("Path no longer exists — this exclusion ({origin}) currently has no effect.")
        }
        (true, None) => format!("Measuring how much this exclusion ({origin}) saves…"),
        (true, Some(m)) => {
            let obj = meta.as_object_mut().expect("json object");
            obj.insert("complete".into(), json!(m.complete));
            obj.insert("entries".into(), json!(m.entries));
            obj.insert("size_cached".into(), json!(m.cached));
            if m.protected {
                obj.insert("status".into(), json!("Excluded (protected)"));
                format!("Cannot be measured: macOS privacy controls hide its contents from this process (grant Full Disk Access to size it); this path is {origin}.")
            } else if !m.complete && m.bytes == 0 {
                // The budget ran out before this walk started: no number is
                // better than a misleading "saves 0 B".
                obj.insert("status".into(), json!("Excluded (not measured)"));
                format!("Could not be measured within the sizing budget; this path is {origin}.")
            } else {
                f = f.size(m.bytes);
                let qualifier = if m.complete { "" } else { " at least" };
                format!(
                    "Saves{qualifier} {} on disk from backups ({origin}).",
                    human(m.bytes)
                )
            }
        }
    };
    f.detail(detail).meta(meta)
}

fn candidate_finding(path: &Path, home: &Path, c: Candidate, m: Measured) -> Finding {
    let key = path.to_string_lossy().into_owned();
    let (severity, why) = match c.reason {
        Reason::RegenerableCache => (
            Severity::Attention,
            "a regenerable cache or toolchain — it is rebuilt on demand and only costs backup space and time",
        ),
        Reason::BuildProducts => (
            Severity::Attention,
            "build products and simulator data Xcode regenerates — high churn, no value in a backup",
        ),
        Reason::CloudSynced => (
            Severity::Info,
            "synced to a cloud provider — already stored elsewhere; excluding it is your call",
        ),
    };
    let qualifier = if m.complete { "" } else { "at least " };
    Finding::new(
        FindingKind::TmExclusionCandidate,
        &key,
        abbreviate_home(path, home),
    )
    .path(path.to_path_buf())
    .size(m.bytes)
    .severity(severity)
    .detail(format!(
        "Still backed up: {qualifier}{} of {why}.",
        human(m.bytes)
    ))
    .provenance("tmutil isexcluded; bounded local directory walk")
    .meta(json!({
        "group": GROUP_CANDIDATES,
        "status": "Included",
        "reason": c.reason.tag(),
        "complete": m.complete,
        "entries": m.entries,
        "size_cached": m.cached,
    }))
    .remedy(Remedy::new(
        "Exclude from Time Machine",
        RemedyCommand::Shell {
            program: "tmutil".to_string(),
            args: vec!["addexclusion".to_string(), key.clone()],
        },
    ))
    .remedy(
        Remedy::new(
            "Copy fixed-path exclusion command (shows in System Settings, needs admin)",
            RemedyCommand::CopyToClipboard {
                text: format!(
                    "sudo tmutil addexclusion -p {}",
                    crate::model::shell_quote(&key)
                ),
            },
        )
        .alternative(),
    )
}

fn estimate_unavailable_finding(home: &Path) -> Finding {
    Finding::new(
        FindingKind::TmBackupEstimate,
        "estimate",
        "Backup set estimate unavailable",
    )
    .path(home.to_path_buf())
    .severity(Severity::Info)
    .detail("tmutil could not be run, so paths cannot be classified as included or excluded and the backup set cannot be estimated.")
    .provenance("tmutil isexcluded")
    .meta(json!({ "group": GROUP_BACKUP_SET, "status": "unavailable", "complete": false }))
}

fn estimate_finding(state: &EstimateState<'_>) -> Finding {
    let en = state.enumeration;
    let t = &state.totals;
    let roots_total = en.roots_total();
    let roots_partial =
        t.roots_done.saturating_sub(t.roots_complete) + roots_total.saturating_sub(t.roots_done);
    let roots_skipped = en.protected.len();
    let complete = state.finished && roots_partial == 0;
    let included_bytes = t.included_bytes;
    let fits_quota = state.quota_bytes.map(|q| included_bytes <= q);
    let over_soft_limit = state
        .quota_bytes
        .is_some_and(|q| included_bytes.saturating_mul(10) > q.saturating_mul(9));

    let status = if !state.finished {
        "measuring…"
    } else if complete {
        "complete"
    } else {
        "partial"
    };

    let mut detail = if state.finished {
        format!(
            "{}{} would be backed up ({} excluded)",
            if complete { "" } else { "At least " },
            human(included_bytes),
            human(t.excluded_bytes)
        )
    } else {
        format!(
            "Measuring {roots_total} roots… {} so far",
            human(included_bytes)
        )
    };
    if let Some(q) = state.quota_bytes {
        let verdict = if included_bytes > q {
            "does not fit"
        } else if over_soft_limit {
            "fits, but leaves under 10% headroom for history"
        } else {
            "fits"
        };
        detail.push_str(&format!("; quota {} → {verdict}", human(q)));
    }
    detail.push('.');

    let mut coverage_parts: Vec<String> = vec![format!(
        "Measured {} of {roots_total} roots completely",
        t.roots_complete
    )];
    if roots_partial > 0 {
        coverage_parts.push(format!(
            "{roots_partial} partial (budget {}s per sizing phase / {} entries per root)",
            state.budget_secs, state.max_entries
        ));
    }
    let skipped_paths: Vec<String> = en
        .protected
        .iter()
        .take(MAX_SKIPPED_LISTED)
        .map(|p| abbreviate_home(p, state.home))
        .collect();
    if roots_skipped > 0 {
        coverage_parts.push(format!(
            "{roots_skipped} skipped: protected by macOS privacy controls (grant Full Disk Access to include: {}{})",
            skipped_paths.join(", "),
            if roots_skipped > MAX_SKIPPED_LISTED { ", …" } else { "" }
        ));
    }
    if en.other_homes > 0 {
        coverage_parts.push(format!(
            "{} other user home{} not measured",
            en.other_homes,
            if en.other_homes == 1 { "" } else { "s" }
        ));
    }
    if !en.skip_paths_known {
        coverage_parts.push("configured exclusion list unavailable".to_string());
    }
    coverage_parts.push("sizes may come from the size cache (up to 24h old)".to_string());

    let mut meta = json!({
        "group": GROUP_BACKUP_SET,
        "status": status,
        "included_bytes": included_bytes,
        "excluded_bytes": t.excluded_bytes,
        "roots_total": roots_total,
        "roots_measured": t.roots_complete,
        "roots_partial": roots_partial,
        "roots_skipped": roots_skipped,
        "skipped_paths": skipped_paths,
        "complete": complete,
    });
    let obj = meta.as_object_mut().expect("json object");
    if let Some(d) = state.data_used_bytes {
        obj.insert("data_used_bytes".into(), json!(d));
    }
    if let Some(q) = state.quota_bytes {
        obj.insert("quota_bytes".into(), json!(q));
    }
    if let Some(fits) = fits_quota {
        obj.insert("fits_quota".into(), json!(fits));
    }

    let mut f = Finding::new(
        FindingKind::TmBackupEstimate,
        "estimate",
        "Estimated backup set",
    )
    .path(state.home.to_path_buf())
    .severity(if state.quota_bytes.is_some() && over_soft_limit {
        Severity::Warning
    } else {
        Severity::Info
    })
    .detail(detail)
    .provenance("tmutil isexcluded (batched); bounded local directory walks per hub, skipping excluded and unreadable children; hard links deduplicated per walk")
    .coverage(coverage_parts.join("; ") + ".")
    .meta(meta);
    if state.finished || t.roots_done > 0 {
        f = f.size(included_bytes);
    }
    f
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Order-independent FNV-1a over a skip set, for the hub-walk cache key.
fn skip_set_hash(skip: &HashSet<PathBuf>) -> u64 {
    let mut paths: Vec<&PathBuf> = skip.iter().collect();
    paths.sort();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for p in paths {
        for b in p
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .chain(std::iter::once(&0u8))
        {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

fn human(bytes: u64) -> String {
    humansize::format_size(bytes, humansize::BINARY)
}

/// `/Users/me/dev` → `~/dev`; anything outside home is returned as-is.
fn abbreviate_home(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~/{}", rest.to_string_lossy()),
        Err(_) => path.to_string_lossy().into_owned(),
    }
}

/// Paths macOS excludes on its own (not via SkipPaths or a sticky attribute).
fn is_macos_default_exclusion(path: &Path, home: &Path) -> bool {
    ["Library/Caches", "Library/Logs", ".Trash"]
        .iter()
        .any(|rel| path == home.join(rel))
}

fn days_between(earlier: SystemTime, now: SystemTime) -> u64 {
    now.duration_since(earlier)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}

/// `YYYY-MM-DD HH:MM UTC` — the plist stores UTC and the ui's formatting
/// helpers are behind the `tui` feature, so a tiny civil-date conversion lives
/// here (Howard Hinnant's algorithm).
fn format_time(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanEvent;
    use crate::runner::MockCommandRunner;
    use std::sync::Arc;

    const PREFS_FAILED: &str =
        include_str!("../../tests/fixtures/time_machine/prefs_network_failed.plist");
    const PREFS_LOCAL_OK: &str =
        include_str!("../../tests/fixtures/time_machine/prefs_local_ok.plist");
    const PREFS_NONE: &str = include_str!("../../tests/fixtures/time_machine/prefs_none.plist");
    const DESTINFO_NETWORK: &str =
        include_str!("../../tests/fixtures/time_machine/destinationinfo_network.xml");
    const DESTINFO_EMPTY: &str =
        include_str!("../../tests/fixtures/time_machine/destinationinfo_empty.xml");
    const ISEXCLUDED_HOME: &str =
        include_str!("../../tests/fixtures/time_machine/isexcluded_home.txt");
    const SNAPSHOTS: &str = "\
Snapshots for volume group containing disk /:
com.apple.TimeMachine.2024-06-01-120000.local
com.apple.TimeMachine.2024-06-15-093015.local
";
    const DEST_ID: &str = "146E01E3-B311-4132-9E56-918AA1A95509";

    fn xml(s: &str) -> plist::Value {
        plist::Value::from_reader_xml(std::io::Cursor::new(s.as_bytes())).unwrap()
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }
    // 2026-09-13T22:00:00Z
    const NOW: u64 = 1_789_336_800;

    fn ctx_with(
        mock: MockCommandRunner,
        home: &Path,
        tx: tokio::sync::mpsc::Sender<ScanEvent>,
    ) -> ScanCtx {
        let mut config = crate::config::Config::default();
        config.time_machine.candidate_min_mb = 0;
        ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: Arc::new(config),
            paths: Arc::new(crate::config::Paths::from_home(home)),
            runner: Arc::new(mock),
            current: ScannerId::TimeMachine,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        }
    }

    fn drain(rx: &mut tokio::sync::mpsc::Receiver<ScanEvent>) -> Vec<Finding> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                out.push(*finding);
            }
        }
        out
    }

    /// Findings keyed by id, last emit wins — what the engine's upsert shows.
    fn latest(findings: Vec<Finding>) -> Vec<Finding> {
        let mut map: BTreeMap<u64, Finding> = BTreeMap::new();
        for f in findings {
            map.insert(f.id.0, f);
        }
        map.into_values().collect()
    }

    fn write_file(path: &Path, bytes: usize) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, vec![b'x'; bytes]).unwrap();
    }

    #[test]
    fn parse_prefs_reads_destinations_skip_paths_and_dates() {
        let p = parse_prefs(&xml(PREFS_FAILED));
        assert_eq!(p.auto_backup, Some(true));
        assert_eq!(p.auto_backup_interval, Some(86_400));
        assert_eq!(p.skip_paths.len(), 9);
        assert!(p
            .skip_paths
            .contains(&PathBuf::from("/Users/fixture/Library/Developer")));
        assert_eq!(p.last_destination_id.as_deref(), Some(DEST_ID));
        let d = &p.destinations[0];
        assert_eq!(d.id, DEST_ID);
        assert_eq!(d.result, Some(56));
        assert_eq!(d.quota_gb, Some(499));
        assert_eq!(d.snapshot_dates.len(), 3);
        assert!(d.snapshot_dates.windows(2).all(|w| w[0] <= w[1]));
        assert!(d.bytes_available.unwrap() < d.bytes_used.unwrap());
        assert!(d.network_url.as_deref().unwrap().starts_with("smb://"));
    }

    #[test]
    fn parse_prefs_without_destinations_is_empty() {
        let p = parse_prefs(&xml(PREFS_NONE));
        assert!(p.destinations.is_empty());
        assert!(p.skip_paths.is_empty());
        assert_eq!(p.auto_backup, Some(false));
    }

    #[test]
    fn parse_destinationinfo_reads_mount_and_last_flag() {
        let d = parse_destinationinfo(&xml(DESTINFO_NETWORK));
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].id, DEST_ID);
        assert_eq!(d[0].kind.as_deref(), Some("Network"));
        assert_eq!(d[0].quota_gb, Some(499));
        assert!(d[0].last);
        assert!(parse_destinationinfo(&xml(DESTINFO_EMPTY)).is_empty());
    }

    #[test]
    fn parse_isexcluded_handles_all_three_statuses() {
        let parsed = parse_isexcluded(ISEXCLUDED_HOME);
        assert_eq!(parsed.len(), 8);
        assert_eq!(
            parsed[0],
            (PathBuf::from("/Users/fixture/dev"), Exclusion::Excluded)
        );
        assert_eq!(
            parsed[4],
            (PathBuf::from("/Users/fixture/nope"), Exclusion::Unknown)
        );
        assert_eq!(
            parsed[6],
            (
                PathBuf::from("/Users/fixture/Pictures/Photos Library.photoslibrary"),
                Exclusion::Excluded
            )
        );
        assert!(
            parse_isexcluded("tmutil: isexcluded requires Full Disk Access privileges.\n")
                .is_empty()
        );
    }

    #[test]
    fn destination_with_failed_result_is_warning_with_status() {
        let prefs = parse_prefs(&xml(PREFS_FAILED));
        let info = parse_destinationinfo(&xml(DESTINFO_NETWORK));
        let dests = merge_destinations(Some(&prefs), &info);
        assert_eq!(dests.len(), 1);
        let f = destination_finding(&dests[0], Some(&prefs), at(NOW), 7);
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.meta["status"], "Failed (destination full) · 26d ago");
        assert_eq!(f.meta["result"], 56);
        assert_eq!(f.meta["last_backup_days"], 26);
        assert_eq!(f.meta["backup_count"], 3);
        assert_eq!(f.meta["quota_bytes"], 499_000_000_000u64);
        assert_eq!(f.meta["kind"], "Network");
        assert_eq!(f.meta["mounted"], info[0].mount_point.is_some());
        assert_eq!(f.size_bytes, prefs.destinations[0].bytes_used);
        assert!(f.last_used.is_some());
        assert_eq!(estimate_quota(&dests, Some(&prefs)), Some(499_000_000_000));
    }

    #[test]
    fn healthy_destination_is_info_and_stale_one_is_warning_by_config() {
        let prefs = parse_prefs(&xml(PREFS_LOCAL_OK));
        let dests = merge_destinations(Some(&prefs), &[]);
        let f = destination_finding(&dests[0], Some(&prefs), at(NOW), 7);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.meta["status"], "OK · today");
        assert_eq!(f.meta["kind"], "Local");
        assert!(f.meta.get("quota_bytes").is_none());

        // Same history, judged 20 days later with a 7-day threshold.
        let later = destination_finding(&dests[0], Some(&prefs), at(NOW + 20 * 86_400), 7);
        assert_eq!(later.severity, Severity::Warning);
        assert_eq!(later.meta["status"], "OK · 20d ago");
        // …but fine with a generous threshold.
        let lenient = destination_finding(&dests[0], Some(&prefs), at(NOW + 20 * 86_400), 30);
        assert_eq!(lenient.severity, Severity::Info);
    }

    #[test]
    fn destination_known_only_to_tmutil_reports_missing_history() {
        let info = parse_destinationinfo(&xml(DESTINFO_NETWORK));
        let dests = merge_destinations(None, &info);
        let f = destination_finding(&dests[0], None, at(NOW), 7);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.meta["status"], "configured (history unavailable)");
        assert_eq!(f.meta["prefs_readable"], false);
    }

    #[test]
    fn stale_mount_is_detected_by_device_id() {
        let tmp = tempfile::tempdir().unwrap();
        let volumes = tmp.path().join("Volumes");
        std::fs::create_dir_all(volumes.join("Backups of Fixture’s MacBook Air 1")).unwrap();
        std::fs::create_dir_all(volumes.join("Other Disk")).unwrap();
        let found = stale_mount_findings(&volumes);
        assert_eq!(found.len(), 1);
        let f = &found[0];
        assert_eq!(f.kind, FindingKind::TmStaleMount);
        assert_eq!(f.severity, Severity::Attention);
        assert_eq!(f.meta["status"], "Not mounted");
        assert!(matches!(
            &f.remedies[0].command,
            RemedyCommand::CopyToClipboard { text } if text.starts_with("sudo rmdir ")
        ));
        assert!(f.remedies[1].alternative);
    }

    #[tokio::test]
    async fn classify_resumes_after_a_protected_path() {
        let tmp = tempfile::tempdir().unwrap();
        let mk = |n: &str| {
            let p = tmp.path().join(n);
            std::fs::create_dir_all(&p).unwrap();
            p
        };
        let (a, b, c, d) = (mk("a"), mk("b"), mk("c"), mk("d"));
        let s = |p: &Path| p.to_string_lossy().into_owned();
        // First call: tmutil answers for a and b only — it stopped at c (the
        // real tool exits 80 here; the stdout shape is what matters).
        let first_out = format!("[Included]  {}\n[Excluded]  {}\n", s(&a), s(&b));
        let mock = MockCommandRunner::new()
            .on(
                "tmutil",
                &["isexcluded", &s(&a), &s(&b), &s(&c), &s(&d)],
                &first_out,
            )
            .on(
                "tmutil",
                &["isexcluded", &s(&d)],
                &format!("[Included]  {}\n", s(&d)),
            );
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let ctx = ctx_with(mock, tmp.path(), tx);
        let result = classify(&ctx, vec![a.clone(), b.clone(), c.clone(), d.clone()])
            .await
            .expect("tmutil ran");
        assert_eq!(result[&a], Exclusion::Included);
        assert_eq!(result[&b], Exclusion::Excluded);
        assert_eq!(result[&c], Exclusion::Protected);
        assert_eq!(result[&d], Exclusion::Included);
    }

    #[tokio::test]
    async fn classify_without_tmutil_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let ctx = ctx_with(MockCommandRunner::new(), tmp.path(), tx);
        assert!(classify(&ctx, vec![tmp.path().join("x")]).await.is_none());
    }

    #[tokio::test]
    async fn blank_runner_emits_only_info_and_returns_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let home = root.join("Users/fixture");
        std::fs::create_dir_all(&home).unwrap();
        let scanner = TimeMachineScanner {
            prefs_path: tmp.path().join("missing.plist"),
            volumes_dir: tmp.path().join("Volumes"),
            system_root: root,
            data_mount: "/nowhere".to_string(),
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let ctx = ctx_with(MockCommandRunner::new(), &home, tx);
        scanner.scan(ctx).await.unwrap();
        let findings = drain(&mut rx);
        assert!(!findings.is_empty());
        assert!(
            findings.iter().all(|f| f.severity == Severity::Info),
            "{:?}",
            findings
                .iter()
                .map(|f| (&f.title, f.severity))
                .collect::<Vec<_>>()
        );
        assert!(findings
            .iter()
            .any(|f| f.kind == FindingKind::TmBackupEstimate && f.meta["status"] == "unavailable"));
        assert!(findings
            .iter()
            .any(|f| f.kind == FindingKind::TmDestination && f.meta["status"] == "not configured"));
    }

    /// End to end over a fake root: excluded directories are pruned, included
    /// ones are sized, exclusions report their savings, a candidate gets the
    /// sticky `addexclusion` remedy, and the estimate lands complete.
    #[tokio::test]
    async fn estimate_prunes_excluded_dirs_and_sizes_included_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let home = root.join("Users/fixture");
        write_file(&root.join("Library/Preferences/x.plist"), 64 * 1024);
        write_file(&home.join("Documents/notes.txt"), 300 * 1024);
        write_file(&home.join("dev/proj/main.rs"), 500 * 1024);
        write_file(&home.join(".cargo/registry/blob"), 200 * 1024);
        // Sticky/default exclusions below 10 MiB are hidden as noise, so make
        // this one big enough to show.
        write_file(&home.join("Library/Caches/junk"), 11 * 1024 * 1024);
        write_file(&home.join("Library/Developer/Xcode/thing"), 150 * 1024);
        write_file(&home.join("loose.txt"), 40 * 1024);
        std::fs::create_dir_all(root.join("Users/other")).unwrap();

        // Preferences: `~/dev` is a fixed-path exclusion.
        let prefs_path = tmp.path().join("prefs.plist");
        std::fs::write(
            &prefs_path,
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>AutoBackup</key><integer>1</integer>
<key>SkipPaths</key><array><string>{}</string></array>
<key>Destinations</key><array><dict>
  <key>DestinationID</key><string>{DEST_ID}</string>
  <key>QuotaGB</key><integer>1</integer>
  <key>RESULT</key><integer>0</integer>
  <key>SnapshotDates</key><array><date>2026-09-13T20:00:00Z</date></array>
</dict></array>
</dict></plist>"#,
                home.join("dev").display()
            ),
        )
        .unwrap();

        // Everything the scanner will ask tmutil about, sorted like it does.
        let excluded: HashSet<PathBuf> = [home.join("dev"), home.join("Library/Caches")]
            .into_iter()
            .collect();
        let mut asked: Vec<PathBuf> = vec![
            root.join("Library"),
            root.join("Users"),
            home.clone(),
            root.join("Users/Shared"),
            home.join(".cargo"),
            home.join("Documents"),
            home.join("Library"),
            home.join("dev"),
            home.join("Library/Caches"),
            home.join("Library/Developer"),
        ];
        asked.retain(|p| p.exists());
        asked.sort();
        asked.dedup();
        let strings: Vec<String> = asked
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let mut args: Vec<&str> = vec!["isexcluded"];
        args.extend(strings.iter().map(String::as_str));
        let stdout: String = asked
            .iter()
            .map(|p| {
                format!(
                    "[{}]  {}\n",
                    if excluded.contains(p) {
                        "Excluded"
                    } else {
                        "Included"
                    },
                    p.display()
                )
            })
            .collect();
        let mock = MockCommandRunner::new()
            .on("tmutil", &["listlocalsnapshots", "/"], SNAPSHOTS)
            .on("tmutil", &["destinationinfo", "-X"], DESTINFO_EMPTY)
            .on("tmutil", &args, &stdout);

        let scanner = TimeMachineScanner {
            prefs_path,
            volumes_dir: tmp.path().join("Volumes"),
            system_root: root.clone(),
            data_mount: "/nowhere".to_string(),
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
        let ctx = ctx_with(mock, &home, tx);
        scanner.scan(ctx).await.unwrap();
        let findings = latest(drain(&mut rx));

        let du = |p: &Path| crate::scan::sizing::du_blocks(p, &|| false);
        let expected_included = du(&root.join("Library"))
            + du(&home.join("Documents"))
            + du(&home.join(".cargo"))
            + du(&home.join("Library/Developer"))
            + std::fs::metadata(home.join("loose.txt"))
                .map(|m| on_disk_bytes(&m))
                .unwrap()
            // The scanner's own size cache lives under this fake home.
            + du(&home.join(".local"));
        let expected_excluded = du(&home.join("dev")) + du(&home.join("Library/Caches"));

        let est = findings
            .iter()
            .find(|f| f.kind == FindingKind::TmBackupEstimate)
            .expect("estimate");
        assert_eq!(
            est.meta["status"],
            "complete",
            "{}",
            est.coverage.as_deref().unwrap_or("")
        );
        assert_eq!(est.meta["complete"], true);
        assert_eq!(est.size_bytes, Some(expected_included));
        assert_eq!(est.meta["included_bytes"], expected_included);
        assert_eq!(est.meta["excluded_bytes"], expected_excluded);
        // 4 hub walks (root, Users, home, ~/Library) + 2 candidates measured
        // separately (~/.cargo, ~/Library/Developer).
        assert_eq!(est.meta["roots_total"], 6);
        assert_eq!(est.meta["roots_measured"], 6);
        assert_eq!(est.meta["quota_bytes"], 1_000_000_000u64);
        assert_eq!(est.meta["fits_quota"], true);
        assert!(est
            .coverage
            .as_deref()
            .unwrap()
            .contains("1 other user home"));

        let exclusions: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::TmExclusion)
            .collect();
        assert_eq!(exclusions.len(), 2);
        assert!(exclusions.iter().all(|f| f.severity == Severity::Info));
        let dev = exclusions.iter().find(|f| f.title == "~/dev").unwrap();
        assert_eq!(dev.size_bytes, Some(du(&home.join("dev"))));
        assert_eq!(dev.meta["exclusion_kind"], "fixed_path");
        assert_eq!(dev.meta["in_system_settings"], true);
        let caches = exclusions
            .iter()
            .find(|f| f.title == "~/Library/Caches")
            .unwrap();
        assert_eq!(caches.meta["exclusion_kind"], "macos_default");
        assert_eq!(caches.meta["in_system_settings"], false);

        let cands: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::TmExclusionCandidate)
            .collect();
        // `~/.cargo` and `~/Library/Developer` are both built-in candidates.
        let mut titles: Vec<&str> = cands.iter().map(|f| f.title.as_str()).collect();
        titles.sort();
        assert_eq!(titles, ["~/.cargo", "~/Library/Developer"]);
        let cargo = cands.iter().find(|f| f.title == "~/.cargo").unwrap();
        assert_eq!(cargo.severity, Severity::Attention);
        assert_eq!(cargo.meta["reason"], "regenerable_cache");
        assert!(matches!(
            &cargo.remedies[0].command,
            RemedyCommand::Shell { program, args }
                if program == "tmutil" && args[0] == "addexclusion" && args.len() == 2
        ));
        assert!(!cargo.remedies[0].destructive);
        assert!(cargo.remedies[1].alternative);

        assert_eq!(
            findings
                .iter()
                .filter(|f| f.kind == FindingKind::LocalSnapshot)
                .count(),
            2
        );
        assert!(findings
            .iter()
            .filter(|f| f.kind == FindingKind::LocalSnapshot)
            .all(|f| f.meta["group"] == GROUP_SNAPSHOTS && f.severity == Severity::Reclaimable));
    }

    #[test]
    fn helpers_format_as_expected() {
        assert_eq!(format_time(at(NOW)), "2026-09-13 22:00 UTC");
        assert_eq!(days_between(at(NOW - 3 * 86_400 - 5), at(NOW)), 3);
        assert_eq!(result_label(0), "OK");
        assert_eq!(result_label(56), "destination full");
        assert_eq!(result_label(19), "error 19");
        assert_eq!(
            abbreviate_home(Path::new("/Users/me/dev"), Path::new("/Users/me")),
            "~/dev"
        );
        assert_eq!(
            abbreviate_home(Path::new("/Library"), Path::new("/Users/me")),
            "/Library"
        );
        assert_eq!(gb_to_bytes(499), 499_000_000_000);
    }
}
