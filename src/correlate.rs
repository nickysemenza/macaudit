//! Cross-scanner joins applied after a full scan collects into a map.
//!
//! STUB owned by lane S1: the real implementation joins unmanaged apps to
//! available brew casks (via `meta`) and launchd orphans to the app inventory.
//! Scanners stay write-only; all correlation happens here so ordering doesn't
//! matter. Kept as a no-op for the skeleton so the engine compiles.

use std::collections::BTreeMap;

use crate::model::{Finding, FindingId};

/// Enrich findings in place using information across scanners. No-op until S1.
pub fn correlate(_findings: &mut BTreeMap<FindingId, Finding>) {
    // S1: apps ↔ brew cask adoption; launchd orphan ↔ app inventory.
}
