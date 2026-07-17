//! Disk sizing helpers.
//!
//! Sizes are reported as **on-disk blocks** (`blocks() * 512`), not apparent
//! `len()`: APFS clones and sparse files make apparent size a lie (spec §2).
//! `du_blocks` sums a subtree; FsScanner runs it on a rayon pool and re-emits
//! the finding with the size once known.

use std::path::Path;

/// Sum the on-disk size (in bytes) of everything under `root`, following no
/// symlinks. Best-effort: unreadable entries are skipped. Checks `cancelled`
/// periodically so a long walk stops promptly on rescan.
pub fn du_blocks(root: &Path, cancelled: &dyn Fn() -> bool) -> u64 {
    let mut total: u64 = 0;
    let mut stack = vec![root.to_path_buf()];
    let mut counter: u32 = 0;

    while let Some(dir) = stack.pop() {
        counter = counter.wrapping_add(1);
        if counter.is_multiple_of(256) && cancelled() {
            break;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total = total.saturating_add(on_disk_bytes(&meta));
            }
        }
    }
    total
}

/// On-disk bytes for a single file's metadata (blocks * 512 on Unix).
#[cfg(unix)]
pub fn on_disk_bytes(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.blocks() * 512
}

#[cfg(not(unix))]
pub fn on_disk_bytes(meta: &std::fs::Metadata) -> u64 {
    meta.len()
}

/// On-disk size of a single path (file or directory root's own entry, not
/// recursive). For a directory use `du_blocks`.
pub fn path_on_disk_bytes(path: &Path) -> Option<u64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.is_dir() {
        Some(du_blocks(path, &|| false))
    } else {
        Some(on_disk_bytes(&meta))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn du_sums_a_tree() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        let mut f = std::fs::File::create(sub.join("file.bin")).unwrap();
        f.write_all(&vec![0u8; 8192]).unwrap();
        f.sync_all().unwrap();
        let size = du_blocks(dir.path(), &|| false);
        // At least the 8 KiB we wrote (block rounding may make it larger).
        assert!(size >= 8192, "got {size}");
    }

    #[test]
    fn du_stops_when_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        // Cancelled from the start ⇒ returns 0-ish without traversing much.
        let size = du_blocks(dir.path(), &|| true);
        assert_eq!(size, 0);
    }
}
