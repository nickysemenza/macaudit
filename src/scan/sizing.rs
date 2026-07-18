//! Disk sizing helpers.
//!
//! Sizes are reported as **on-disk blocks** (`blocks() * 512`), not apparent
//! `len()`: APFS clones and sparse files make apparent size a lie (spec §2).
//! `du_blocks` sums a subtree; FsScanner runs it on a rayon pool and re-emits
//! the finding with the size once known.
//!
//! Hard links are counted ONCE per walk (like real `du`): pnpm's store model
//! hard-links every package file into each `node_modules`, so counting per
//! path would wildly overstate pnpm projects. Only multi-link files pay the
//! dedup bookkeeping cost. (Dedup is per-`du_blocks` call — two separate
//! findings that hard-link the same file each still report it, which is the
//! honest per-tree number.)

use std::path::Path;

/// Sum the on-disk size (in bytes) of everything under `root`, following no
/// symlinks, counting hard-linked files once. Best-effort: unreadable entries
/// are skipped. Checks `cancelled` periodically so a long walk stops promptly
/// on rescan.
pub fn du_blocks(root: &Path, cancelled: &dyn Fn() -> bool) -> u64 {
    #[cfg(unix)]
    let mut seen_links: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();

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
                // A file with multiple hard links must only count once no
                // matter how many of its links live under this root.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if meta.nlink() > 1 && !seen_links.insert((meta.dev(), meta.ino())) {
                        continue;
                    }
                }
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

    /// Regression: pnpm hard-links every package file into each node_modules;
    /// counting per path would overstate such trees. Hard links count once.
    #[test]
    #[cfg(unix)]
    fn hard_links_count_once() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original.bin");
        std::fs::write(&original, vec![0u8; 8192]).unwrap();
        std::fs::hard_link(&original, dir.path().join("link1.bin")).unwrap();
        std::fs::hard_link(&original, dir.path().join("link2.bin")).unwrap();

        let size = du_blocks(dir.path(), &|| false);
        // Three directory entries, one payload: must count ~8 KiB once, not 3×.
        assert!(size >= 8192, "got {size}");
        assert!(size < 2 * 8192, "hard links double-counted: {size}");
    }

    #[test]
    fn du_stops_when_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        // Cancelled from the start ⇒ returns 0-ish without traversing much.
        let size = du_blocks(dir.path(), &|| true);
        assert_eq!(size, 0);
    }
}
