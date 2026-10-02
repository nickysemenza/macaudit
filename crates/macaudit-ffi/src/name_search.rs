use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use macaudit::inventory::{MemoryBudget, Reservation};
use macaudit::scan::walk::listing::{self, Kind};

use crate::{queries, TopFile};

pub(crate) struct FileMatches {
    pub files: Vec<TopFile>,
    pub stop_reasons: Vec<String>,
    pub truncated: bool,
}

impl FileMatches {
    fn stop(&mut self, reason: &str) {
        if !self.stop_reasons.iter().any(|existing| existing == reason) {
            self.stop_reasons.push(reason.to_owned());
        }
    }
}

pub(crate) fn files(
    root: &Path,
    needle: &str,
    limit: usize,
    budget: &Arc<MemoryBudget>,
    results_memory: &mut Reservation,
    excludes: &[PathBuf],
    cancelled: &dyn Fn() -> bool,
) -> FileMatches {
    let mut result = FileMatches {
        files: Vec::new(),
        stop_reasons: Vec::new(),
        truncated: false,
    };
    if needle.is_empty() {
        return result;
    }
    let Ok(metadata) = std::fs::symlink_metadata(root) else {
        result.stop("unreadable");
        return result;
    };
    if !metadata.is_dir() {
        result.stop("unreadable");
        return result;
    }
    let root_device = metadata.dev();
    let Ok(mut workspace) = budget.reserve(1024) else {
        result.stop("resource_limited");
        return result;
    };
    if results_memory
        .grow(
            limit
                .saturating_mul(std::mem::size_of::<TopFile>())
                .saturating_mul(2),
        )
        .is_err()
        || result.files.try_reserve_exact(limit).is_err()
    {
        result.stop("resource_limited");
        return result;
    }
    let pending_row_bytes = std::mem::size_of::<(PathBuf, Reservation)>();
    let Ok(mut pending_memory) = budget.reserve(pending_row_bytes.saturating_mul(16)) else {
        result.stop("resource_limited");
        return result;
    };
    let mut pending = Vec::<(PathBuf, Reservation)>::with_capacity(16);
    let mut identities = BTreeSet::new();
    let Ok(root_memory) = budget.reserve(root.as_os_str().len()) else {
        result.stop("resource_limited");
        return result;
    };
    pending.push((root.to_path_buf(), root_memory));
    while let Some((directory, _directory_memory)) = pending.pop() {
        if cancelled() {
            result.stop("cancelled");
            break;
        }
        if excludes
            .iter()
            .any(|excluded| directory.starts_with(excluded))
        {
            result.stop("excluded");
            continue;
        }
        let listing = match listing::list(&directory) {
            Ok(listing) => listing,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::OutOfMemory {
                    result.stop("resource_limited");
                    break;
                }
                result.stop("unreadable");
                continue;
            }
        };
        if listing.dev != root_device {
            result.stop("mounts");
            continue;
        }
        let identity = (listing.dev, listing.ino);
        if identities.contains(&identity) {
            result.stop("aliases");
            continue;
        }
        if workspace.grow(256).is_err() {
            result.stop("resource_limited");
            break;
        }
        identities.insert(identity);
        if listing.errors > 0 {
            result.stop("unreadable");
        }
        for entry in &listing.entries {
            if cancelled() {
                result.stop("cancelled");
                break;
            }
            if entry.dataless {
                result.stop("dataless");
                continue;
            }
            let path_bytes = directory.as_os_str().len() + entry.name.as_bytes().len() + 1;
            let Ok(_entry_memory) = budget.reserve(path_bytes.saturating_mul(8)) else {
                result.stop("resource_limited");
                break;
            };
            let path = directory.join(&entry.name);
            if excludes.iter().any(|excluded| path.starts_with(excluded)) {
                result.stop("excluded");
                continue;
            }
            match entry.kind {
                Kind::Dir => {
                    if entry.mount_point || entry.dev != root_device {
                        result.stop("mounts");
                        continue;
                    }
                    let Ok(path_memory) = budget.reserve(path_bytes) else {
                        result.stop("resource_limited");
                        break;
                    };
                    if pending.len() == pending.capacity() {
                        let next_capacity = pending.capacity().saturating_mul(2);
                        let peak_bytes = next_capacity
                            .saturating_add(pending.capacity())
                            .saturating_mul(pending_row_bytes);
                        if pending_memory.resize(peak_bytes).is_err()
                            || pending
                                .try_reserve_exact(next_capacity - pending.len())
                                .is_err()
                        {
                            result.stop("resource_limited");
                            break;
                        }
                        pending_memory
                            .resize(pending.capacity().saturating_mul(pending_row_bytes))
                            .expect("releasing pending-directory reallocation credit");
                    }
                    pending.push((path, path_memory));
                }
                Kind::File => {
                    let Some(relative) = path.strip_prefix(root).ok().and_then(Path::to_str) else {
                        result.stop("unsupported_paths");
                        continue;
                    };
                    if !relative.to_lowercase().contains(needle) {
                        continue;
                    }
                    if result.files.len() == limit {
                        result.truncated = true;
                        result.stop("truncated");
                        break;
                    }
                    if queries::grow(results_memory, path_bytes).is_err() {
                        result.stop("resource_limited");
                        break;
                    }
                    result.files.push(TopFile {
                        path: path.to_str().unwrap().to_owned(),
                        alloc: entry.alloc,
                    });
                }
                Kind::Other => {}
            }
        }
        if result.truncated
            || result
                .stop_reasons
                .iter()
                .any(|reason| reason == "cancelled" || reason == "resource_limited")
        {
            break;
        }
    }
    result
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn search(root: &Path, needle: &str, limit: usize) -> FileMatches {
        let budget = MemoryBudget::shared();
        let mut memory =
            queries::reserve(&budget, limit, std::mem::size_of::<TopFile>(), 1024).unwrap();
        files(root, needle, limit, &budget, &mut memory, &[], &|| false)
    }

    #[test]
    fn substring_search_matches_names_and_relative_paths_without_following_symlinks() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("projects/demo")).unwrap();
        std::fs::write(home.path().join("projects/demo/Report.csv"), "fixture").unwrap();
        std::fs::write(outside.path().join("Report.csv"), "outside").unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join("alias")).unwrap();
        for needle in ["report.csv", "projects/demo"] {
            let result = search(home.path(), needle, 1000);
            assert_eq!(result.files.len(), 1);
            assert!(result.stop_reasons.is_empty());
        }
    }

    #[test]
    fn filename_results_are_bounded_and_marked_truncated() {
        let home = tempfile::tempdir().unwrap();
        for index in 0..1005 {
            std::fs::write(home.path().join(format!("match-{index}")), "fixture").unwrap();
        }
        let result = search(home.path(), "match-", 1000);
        assert_eq!(result.files.len(), 1000);
        assert!(result.truncated);
        assert_eq!(result.stop_reasons, ["truncated"]);
    }

    #[test]
    fn cancellation_preserves_bounded_partial_results() {
        let home = tempfile::tempdir().unwrap();
        for index in 0..100 {
            std::fs::write(home.path().join(format!("match-{index}")), "fixture").unwrap();
        }
        let budget = MemoryBudget::shared();
        let mut memory =
            queries::reserve(&budget, 1000, std::mem::size_of::<TopFile>(), 1024).unwrap();
        let checks = AtomicUsize::new(0);
        let result = files(
            home.path(),
            "match-",
            1000,
            &budget,
            &mut memory,
            &[],
            &|| checks.fetch_add(1, Ordering::Relaxed) >= 10,
        );
        assert_eq!(result.files.len(), 9);
        assert_eq!(result.stop_reasons, ["cancelled"]);
    }

    #[test]
    fn exclusions_use_path_component_boundaries() {
        let home = tempfile::tempdir().unwrap();
        for folder in ["foo", "foobar"] {
            std::fs::create_dir(home.path().join(folder)).unwrap();
            std::fs::write(home.path().join(folder).join("match"), "fixture").unwrap();
        }
        let budget = MemoryBudget::shared();
        let mut memory =
            queries::reserve(&budget, 1000, std::mem::size_of::<TopFile>(), 1024).unwrap();
        let result = files(
            home.path(),
            "match",
            1000,
            &budget,
            &mut memory,
            &[home.path().join("foo")],
            &|| false,
        );
        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].path.ends_with("foobar/match"));
        assert_eq!(result.stop_reasons, ["excluded"]);
    }

    #[test]
    fn workspace_exhaustion_is_explicit_partial_coverage() {
        let home = tempfile::tempdir().unwrap();
        let budget = MemoryBudget::new(32);
        let mut memory = budget.reserve(0).unwrap();
        let result = files(
            home.path(),
            "match",
            1000,
            &budget,
            &mut memory,
            &[],
            &|| false,
        );
        assert!(result.files.is_empty());
        assert_eq!(result.stop_reasons, ["resource_limited"]);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn wide_directory_pending_capacity_does_not_charge_cumulative_reallocations() {
        let home = tempfile::tempdir().unwrap();
        for index in 0..2048 {
            let directory = home.path().join(format!("folder-{index}"));
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(directory.join("match"), "fixture").unwrap();
        }
        let budget = MemoryBudget::new(4 * 1024 * 1024);
        let mut memory = budget.reserve(0).unwrap();
        let result = files(
            home.path(),
            "no-match",
            1000,
            &budget,
            &mut memory,
            &[],
            &|| false,
        );
        assert!(result.stop_reasons.is_empty());
        assert!(result.files.is_empty());
        assert!(budget.peak() < 2 * 1024 * 1024);
    }
}
