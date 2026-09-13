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
use std::time::{Duration, Instant};

/// Result from a deliberately bounded directory measurement. `complete` is
/// false when a scan was cancelled, exceeded its entry cap, or hit its shared
/// time budget; callers must surface that fact rather than presenting it as an
/// exact total.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundedSize {
    pub bytes: u64,
    pub entries: u64,
    pub complete: bool,
}

/// Sum the on-disk size (in bytes) of everything under `root`, following no
/// symlinks, counting hard-linked files once. Best-effort: unreadable entries
/// are skipped. Checks `cancelled` periodically so a long walk stops promptly
/// on rescan.
pub fn du_blocks(root: &Path, cancelled: &dyn Fn() -> bool) -> u64 {
    du_blocks_bounded(
        root,
        u64::MAX,
        Instant::now() + Duration::from_secs(365 * 24 * 60 * 60),
        cancelled,
    )
    .bytes
}

/// As `du_blocks`, but with both an entry cap and a deadline. This is used for
/// user-facing disk allocation categories, never as a hidden full-home scan.
pub fn du_blocks_bounded(
    root: &Path,
    max_entries: u64,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> BoundedSize {
    #[cfg(unix)]
    let mut seen_links: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();

    let mut total: u64 = 0;
    let mut entries_seen = 0u64;
    let mut stack = vec![root.to_path_buf()];
    let mut counter: u32 = 0;

    while let Some(dir) = stack.pop() {
        counter = counter.wrapping_add(1);
        if counter.is_multiple_of(256) && (cancelled() || Instant::now() >= deadline) {
            return BoundedSize {
                bytes: total,
                entries: entries_seen,
                complete: false,
            };
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > max_entries || cancelled() || Instant::now() >= deadline {
                return BoundedSize {
                    bytes: total,
                    entries: entries_seen,
                    complete: false,
                };
            }
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
    BoundedSize {
        bytes: total,
        entries: entries_seen,
        complete: true,
    }
}

/// `du_blocks` plus how many of those bytes belong to files that are also
/// hard-linked from *outside* `root` (their `st_nlink` exceeds the links
/// seen inside the walk). Deleting `root` reclaims at most
/// `bytes - externally_linked`. APFS reflink clones are indistinguishable
/// from copies here and are *not* detected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SharedSize {
    pub bytes: u64,
    pub externally_linked: u64,
}

pub fn du_blocks_shared(root: &Path, cancelled: &dyn Fn() -> bool) -> SharedSize {
    #[cfg(unix)]
    {
        use std::collections::HashMap;
        use std::os::unix::fs::MetadataExt;
        // (dev, ino) → (nlink on disk, links seen in this walk, bytes)
        let mut linked: HashMap<(u64, u64), (u64, u64, u64)> = HashMap::new();
        let mut total = 0u64;
        let mut stack = vec![root.to_path_buf()];
        let mut counter = 0u32;
        while let Some(dir) = stack.pop() {
            counter = counter.wrapping_add(1);
            if counter.is_multiple_of(256) && cancelled() {
                break;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                if meta.is_symlink() {
                    continue;
                }
                if meta.is_dir() {
                    stack.push(entry.path());
                    continue;
                }
                let bytes = on_disk_bytes(&meta);
                if meta.nlink() > 1 {
                    let e =
                        linked
                            .entry((meta.dev(), meta.ino()))
                            .or_insert((meta.nlink(), 0, bytes));
                    if e.1 == 0 {
                        total = total.saturating_add(bytes);
                    }
                    e.1 += 1;
                } else {
                    total = total.saturating_add(bytes);
                }
            }
        }
        let externally_linked = linked
            .values()
            .filter(|(nlink, seen, _)| seen < nlink)
            .map(|(_, _, b)| *b)
            .sum();
        SharedSize {
            bytes: total,
            externally_linked,
        }
    }
    #[cfg(not(unix))]
    {
        SharedSize {
            bytes: du_blocks(root, cancelled),
            externally_linked: 0,
        }
    }
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

    /// Refutation of an external-audit claim: `std::fs::DirEntry::metadata()`
    /// does NOT follow symlinks (unlike `fs::metadata` on a path), so the
    /// `is_symlink()` guard works and a symlink pointing at data outside the
    /// tree is never counted or traversed.
    #[test]
    #[cfg(unix)]
    fn symlinks_are_not_followed_or_counted() {
        let outside = tempfile::tempdir().unwrap();
        let big = outside.path().join("big.bin");
        std::fs::write(&big, vec![0u8; 1_000_000]).unwrap();

        let tree = tempfile::tempdir().unwrap();
        std::fs::write(tree.path().join("small.bin"), vec![0u8; 4096]).unwrap();
        std::os::unix::fs::symlink(&big, tree.path().join("link-to-big")).unwrap();
        // Symlinked DIRECTORY must not be descended either (cycle safety).
        std::os::unix::fs::symlink(outside.path(), tree.path().join("link-to-dir")).unwrap();

        let size = du_blocks(tree.path(), &|| false);
        assert!(size >= 4096, "got {size}");
        assert!(
            size < 1_000_000,
            "symlink target was counted/traversed: {size}"
        );
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

    #[test]
    fn bounded_du_reports_incomplete_at_entry_cap() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..10 {
            std::fs::write(dir.path().join(format!("{n}.bin")), vec![0u8; 4096]).unwrap();
        }
        let result = du_blocks_bounded(
            dir.path(),
            3,
            Instant::now() + Duration::from_secs(1),
            &|| false,
        );
        assert!(!result.complete);
        assert!(result.entries > 3);
    }

    #[test]
    fn shared_size_counts_external_hard_links_but_not_internal_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("store");
        let nm = tmp.path().join("node_modules/.pnpm/pkg");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::create_dir_all(&nm).unwrap();
        // 4 KiB file linked from the store (external) …
        let ext = store.join("big");
        std::fs::write(&ext, vec![b'x'; 4096]).unwrap();
        std::fs::hard_link(&ext, nm.join("big")).unwrap();
        // … a file hard-linked twice *inside* the tree (internal only) …
        let inner = nm.join("a");
        std::fs::write(&inner, vec![b'y'; 4096]).unwrap();
        std::fs::hard_link(&inner, nm.join("b")).unwrap();
        // … and a plain file.
        std::fs::write(nm.join("plain"), vec![b'z'; 4096]).unwrap();
        let s = du_blocks_shared(&tmp.path().join("node_modules"), &|| false);
        let ext_bytes = on_disk_bytes(&std::fs::metadata(&ext).unwrap());
        assert_eq!(s.externally_linked, ext_bytes);
        // Internal double link counted once; total = big + a + plain.
        assert_eq!(s.bytes, ext_bytes * 3);
        assert_eq!(
            s.bytes,
            du_blocks(&tmp.path().join("node_modules"), &|| false)
        );
    }
}
