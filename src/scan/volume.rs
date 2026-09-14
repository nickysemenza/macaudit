//! Shared volume-capacity helpers, used by both the System scanner and the
//! Time Machine scanner.
//!
//! On-disk sizes (total capacity, free space, and the space already occupied
//! by a specific volume like `/System/Volumes/Data`) come from
//! `diskutil info -plist <mount>`, via the `TotalSize`, `APFSContainerFree`
//! (falling back to `VolumeFreeSpace`), and `CapacityInUse` plist keys.
//! `CapacityInUse` is present for data volumes such as
//! `/System/Volumes/Data` but absent for the boot volume `/`.
//!
//! "Available including purgeable space" is a different, macOS-computed
//! number: `NSURLVolumeAvailableCapacityForImportantUsageKey`, fetched via a
//! JXA (`osascript -l JavaScript`) script because `statfs`-based APIs (and
//! thus `diskutil`) cannot see purgeable space such as local Time Machine
//! snapshots that macOS will reclaim automatically under disk pressure.
//! [`MacosCapacity::purgeable`] (important usage minus physically-free) is an
//! *upper bound* on what deleting local Time Machine snapshots would free —
//! it also includes other purgeable space macOS does not itemize.

use std::time::Duration;

use crate::scan::{run_with_timeout, ScanCtx};

/// Native macOS storage availability includes reclaimable space, such as local
/// Time Machine snapshots. JXA/osascript ships with macOS and avoids compiling
/// Swift on each manual scan.
pub const VOLUME_CAPACITY_SCRIPT: &str = r#"ObjC.import("Foundation"); const url = $.NSURL.fileURLWithPath("/"); function value(key) { const out = Ref(); url.getResourceValueForKeyError(out, key, null); return ObjC.unwrap(out[0]); } JSON.stringify({total:value($.NSURLVolumeTotalCapacityKey), physical:value($.NSURLVolumeAvailableCapacityKey), important:value($.NSURLVolumeAvailableCapacityForImportantUsageKey)});"#;

/// Capacity of one volume as reported by `diskutil info -plist <mount>`.
#[derive(Debug, Clone, Copy)]
pub struct DiskUsage {
    pub capacity: u64,
    pub used: u64,
    pub free: u64,
    /// `CapacityInUse`: present for data volumes (e.g. `/System/Volumes/Data`),
    /// absent for the boot volume `/`.
    pub capacity_in_use: Option<u64>,
}

/// Parse `diskutil info -plist <mount>` XML output into a [`DiskUsage`].
pub fn parse_diskutil_info(input: &str) -> Option<DiskUsage> {
    let value = plist::Value::from_reader_xml(input.as_bytes()).ok()?;
    let dict = value.as_dictionary()?;
    let capacity = dict.get("TotalSize")?.as_unsigned_integer()?;
    let free = dict
        .get("APFSContainerFree")
        .or_else(|| dict.get("VolumeFreeSpace"))?
        .as_unsigned_integer()?;
    let capacity_in_use = dict
        .get("CapacityInUse")
        .and_then(|v| v.as_unsigned_integer());
    Some(DiskUsage {
        capacity,
        used: capacity.saturating_sub(free),
        free,
        capacity_in_use,
    })
}

/// Native macOS "available including purgeable" storage figures, from
/// [`VOLUME_CAPACITY_SCRIPT`].
#[derive(Debug, Clone, Copy)]
pub struct MacosCapacity {
    pub total: u64,
    pub physical: u64,
    pub important: u64,
}

impl MacosCapacity {
    /// Upper bound on space purgeable/reclaimable data (such as local Time
    /// Machine snapshots) is occupying: the gap between what's available
    /// "for important usage" (i.e. including purgeable space) and what's
    /// physically free right now.
    pub fn purgeable(&self) -> u64 {
        self.important.saturating_sub(self.physical)
    }
}

/// Parse the JSON emitted by [`VOLUME_CAPACITY_SCRIPT`].
pub fn parse_macos_capacity(input: &str) -> Option<MacosCapacity> {
    let value: serde_json::Value = serde_json::from_str(input.trim()).ok()?;
    let total = value.get("total")?.as_u64()?;
    let physical = value.get("physical")?.as_u64()?;
    let important = value.get("important")?.as_u64()?;
    (important >= physical && total >= important).then_some(MacosCapacity {
        total,
        physical,
        important,
    })
}

/// Run [`VOLUME_CAPACITY_SCRIPT`] via `osascript` and parse the result.
pub async fn macos_capacity(ctx: &ScanCtx, timeout: Duration) -> Option<MacosCapacity> {
    let out = run_with_timeout(
        ctx,
        "osascript",
        &["-l", "JavaScript", "-e", VOLUME_CAPACITY_SCRIPT],
        timeout,
    )
    .await?;
    parse_macos_capacity(&out.stdout_str())
}

/// Run `diskutil info -plist <mount>` and parse the result.
pub async fn diskutil_info(ctx: &ScanCtx, mount: &str, timeout: Duration) -> Option<DiskUsage> {
    let out = run_with_timeout(ctx, "diskutil", &["info", "-plist", mount], timeout).await?;
    parse_diskutil_info(&out.stdout_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_diskutil_plist_and_rejects_bad_data() {
        let xml = r#"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>TotalSize</key><integer>1000</integer><key>APFSContainerFree</key><integer>250</integer></dict></plist>"#;
        let disk = parse_diskutil_info(xml).unwrap();
        assert_eq!(disk.used, 750);
        assert_eq!(disk.capacity_in_use, None);
        assert!(parse_diskutil_info("nope").is_none());
    }

    #[test]
    fn parses_capacity_in_use_when_present() {
        let xml = r#"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>TotalSize</key><integer>1000</integer><key>APFSContainerFree</key><integer>250</integer><key>CapacityInUse</key><integer>600</integer></dict></plist>"#;
        let disk = parse_diskutil_info(xml).unwrap();
        assert_eq!(disk.capacity_in_use, Some(600));
    }

    #[test]
    fn parses_native_macos_available_capacity() {
        let capacity =
            parse_macos_capacity(r#"{"total":1000,"physical":40,"important":330}"#).unwrap();
        assert_eq!(capacity.important, 330);
        assert_eq!(capacity.purgeable(), 290);
        assert!(parse_macos_capacity(r#"{"total":1000,"physical":40,"important":1200}"#).is_none());
    }
}
