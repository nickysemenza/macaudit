//! Disk sizing helpers.
//!
//! Sizes are reported as **on-disk blocks** (`blocks() * 512`), not apparent
//! `len()`: APFS clones and sparse files make apparent size a lie (spec §2).
//! Every function here is a thin wrapper over `walk::walk` (getattrlistbulk
//! listing, rayon recursion) with the tree discarded — a caller that wants
//! the tree uses `walk` directly.
//!
//! Hard links are counted ONCE per walk (like real `du`): pnpm's store model
//! hard-links every package file into each `node_modules`, so counting per
//! path would wildly overstate pnpm projects. Only multi-link files pay the
//! dedup bookkeeping cost. (Dedup is per-`du_blocks` call — two separate
//! findings that hard-link the same file each still report it, which is the
//! honest per-tree number.)

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::walk::{self, NoVisitor, WalkOptions};

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
/// are skipped. Checks `cancelled` per directory so a long walk stops promptly
/// on rescan.
pub fn du_blocks(root: &Path, cancelled: &(dyn Fn() -> bool + Sync)) -> u64 {
    size(root, WalkOptions::default(), cancelled).bytes
}

/// As `du_blocks`, but with both an entry cap and a deadline. This is used for
/// measurements that must not turn into a hidden full-disk scan.
pub fn du_blocks_bounded(
    root: &Path,
    max_entries: u64,
    deadline: Instant,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> BoundedSize {
    du_blocks_bounded_except(root, &HashSet::new(), max_entries, deadline, cancelled)
}

/// `du_blocks_bounded` that does not descend into any directory in `skip`
/// (compared by exact path). Lets a caller size "everything under here except
/// these children" in one pass — the Time Machine estimate walks a hub while
/// leaving out its excluded, unreadable, and separately-measured children.
pub fn du_blocks_bounded_except(
    root: &Path,
    skip: &HashSet<PathBuf>,
    max_entries: u64,
    deadline: Instant,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> BoundedSize {
    size(
        root,
        WalkOptions {
            excludes: skip.iter().cloned().collect(),
            deadline: Some(deadline),
            max_entries: Some(max_entries),
            ..WalkOptions::default()
        },
        cancelled,
    )
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

pub fn du_blocks_shared(root: &Path, cancelled: &(dyn Fn() -> bool + Sync)) -> SharedSize {
    let r = walk::walk(
        root,
        du_options(WalkOptions::default()),
        &NoVisitor,
        None,
        cancelled,
    );
    SharedSize {
        bytes: r.root.alloc,
        externally_linked: r.externally_linked,
    }
}

/// Totals only: no tree, no per-directory or global largest-file lists.
fn du_options(opts: WalkOptions) -> WalkOptions {
    WalkOptions {
        keep_tree: false,
        per_dir_top: 0,
        top_n: 0,
        threshold: None,
        ..opts
    }
}

fn size(root: &Path, opts: WalkOptions, cancelled: &(dyn Fn() -> bool + Sync)) -> BoundedSize {
    let r = walk::walk(root, du_options(opts), &NoVisitor, None, cancelled);
    BoundedSize {
        bytes: r.root.alloc,
        entries: r.entries,
        complete: r.complete,
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
    use std::time::Duration;

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
