//! Path canonicalisation and byte-sizing for resolver claims (§3): mapping a
//! resolver's raw path (which may point through `/System/Volumes/Data`,
//! `file://` URIs, or a trailing `/.git`) onto the same literal-component
//! form `DirNode::find` expects, and looking up a claimed path's size —
//! directories via the walked tree, individual files (`.crate`s, cacache
//! blobs, `.plist`s, ...) via `lstat`, since the tree has no file nodes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::scan::walk::{DirNode, DirTree};

/// Canonicalise `p` onto the literal-component form `DirNode::find` expects
/// (`walk/mod.rs`'s tree is rooted at the walk's own root, e.g. `/`, with
/// paths matched component-by-component against on-disk directory names):
///
/// - a leading `/System/Volumes/Data` (the APFS data volume's real mount
///   point; `/Users`, `/opt`, ... are firmlinks onto it) is stripped so the
///   result matches the firmlinked path the walk actually recorded;
/// - `/var`, `/tmp`, `/etc` are themselves symlinks to `/private/var`,
///   `/private/tmp`, `/private/etc` — resolvers that build a path by string
///   concatenation (`"/var/..."`) land here, not on the walk's real names;
/// - a trailing `/.git` is stripped so a resolver that points at the git
///   metadata directory itself claims the repo root it belongs to.
pub fn tree_path(p: &Path) -> PathBuf {
    let mut path = match p.strip_prefix("/System/Volumes/Data") {
        Ok(rest) => Path::new("/").join(rest),
        Err(_) => p.to_path_buf(),
    };
    for real in ["/var", "/tmp", "/etc"] {
        if path.starts_with(real) {
            if let Ok(rest) = path.strip_prefix("/") {
                path = Path::new("/private").join(rest);
            }
            break;
        }
    }
    if path.file_name().is_some_and(|n| n == ".git") {
        path.pop();
    }
    path
}

/// Decode a `file://` URI into an absolute path (percent-decoded), the form
/// editor workspace-storage JSON and similar carry their folder in. `None`
/// for anything that isn't a `file://` URI.
pub fn from_file_uri(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    // A `file://` URI may carry an (almost always empty) host before the
    // path; skip straight to the path's leading `/` either way.
    let path_part = if let Some(stripped) = rest.strip_prefix('/') {
        stripped
    } else {
        let slash = rest.find('/')?;
        &rest[slash + 1..]
    };
    Some(PathBuf::from(format!("/{}", percent_decode(path_part))))
}

/// Minimal `%XX` decoder (no `percent-encoding` dependency in this crate).
/// Operates byte-wise so it never has to assume `s`'s existing bytes fall on
/// UTF-8 char boundaries; the assembled bytes are lossily redecoded at the
/// end, same as everywhere else this crate handles untrusted text.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The result of sizing a claimed path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sized {
    /// Found in a walked tree: allocated bytes of the whole subtree.
    Dir(u64),
    /// Not found in any tree, but `lstat` sees a regular file:
    /// `st_blocks * 512`.
    File(u64),
    /// Neither: the path is missing, or it's a directory the walk didn't
    /// reach (unreadable, or outside every configured root) — `bytes` is a
    /// guess (0), and callers must flag the entry `unsized`.
    Unsized,
}

/// Memoised path → size lookup over every walked tree, shared by one
/// `accounting::account` pass. A directory is looked up in each tree in
/// turn (a resolver doesn't know which root's tree a path fell under);
/// anything not found there is `lstat`ed directly, since the tree carries no
/// per-file nodes (`walk/mod.rs`'s `DirNode` doc).
pub struct Sizer<'a> {
    trees: &'a [Arc<DirTree>],
    memo: Mutex<HashMap<PathBuf, Sized>>,
}

impl<'a> Sizer<'a> {
    pub fn new(trees: &'a [Arc<DirTree>]) -> Self {
        Sizer {
            trees,
            memo: Mutex::new(HashMap::new()),
        }
    }

    /// Size `path` (already expected to be in `tree_path` form — callers
    /// that haven't canonicalised yet should do so before calling this, so
    /// the memo key matches across resolvers claiming the same resource
    /// through different raw spellings).
    pub fn bytes_of(&self, path: &Path) -> Sized {
        if let Some(cached) = self.memo.lock().unwrap().get(path) {
            return *cached;
        }
        let result = self.compute(path);
        self.memo.lock().unwrap().insert(path.to_path_buf(), result);
        result
    }

    fn compute(&self, path: &Path) -> Sized {
        if let Some(node) = node_at(self.trees, path) {
            return if node.errors > 0 && node.alloc == 0 {
                Sized::Unsized
            } else {
                Sized::Dir(node.alloc)
            };
        }
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.is_file() => Sized::File(crate::scan::sizing::on_disk_bytes(&meta)),
            _ => Sized::Unsized,
        }
    }
}

/// The `DirNode` at `path` in whichever walked tree reached it (a resolver
/// doesn't know which root's tree a path fell under, so every tree is tried
/// in turn) — the shared lookup every subtree walk in this crate uses to
/// traverse *directory* structure for free (`DirNode` has no file entries;
/// callers still need one `listing::list` per directory they want filenames
/// for).
pub fn node_at<'t>(trees: &'t [Arc<DirTree>], path: &Path) -> Option<&'t DirNode> {
    for tree in trees {
        if let Some(node) = tree.node.find(&tree.root, path) {
            return Some(node);
        }
    }
    None
}

/// Total allocated bytes across every walked root — the denominator for
/// `FootprintSet::attributed_total`'s coverage fraction.
pub fn disk_total(trees: &[Arc<DirTree>]) -> u64 {
    trees.iter().map(|t| t.bytes).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::walk::DirNode;
    use std::time::{Duration, SystemTime};

    #[test]
    fn tree_path_strips_the_data_volume_prefix() {
        assert_eq!(
            tree_path(Path::new("/System/Volumes/Data/Users/dev/proj")),
            PathBuf::from("/Users/dev/proj")
        );
    }

    #[test]
    fn tree_path_maps_var_tmp_etc_to_private() {
        assert_eq!(
            tree_path(Path::new("/var/db/timezone")),
            PathBuf::from("/private/var/db/timezone")
        );
        assert_eq!(
            tree_path(Path::new("/tmp/x")),
            PathBuf::from("/private/tmp/x")
        );
        assert_eq!(
            tree_path(Path::new("/etc/hosts")),
            PathBuf::from("/private/etc/hosts")
        );
        // Already canonical: no double-mapping.
        assert_eq!(
            tree_path(Path::new("/private/var/db/timezone")),
            PathBuf::from("/private/var/db/timezone")
        );
    }

    #[test]
    fn tree_path_does_not_mistake_a_longer_name_for_the_prefix() {
        // `/variant` must not be treated as `/var/iant`.
        assert_eq!(
            tree_path(Path::new("/variant/x")),
            PathBuf::from("/variant/x")
        );
    }

    #[test]
    fn tree_path_strips_a_trailing_dot_git() {
        assert_eq!(
            tree_path(Path::new("/Users/dev/proj/.git")),
            PathBuf::from("/Users/dev/proj")
        );
    }

    #[test]
    fn tree_path_combines_data_volume_and_dot_git() {
        assert_eq!(
            tree_path(Path::new("/System/Volumes/Data/Users/dev/proj/.git")),
            PathBuf::from("/Users/dev/proj")
        );
    }

    #[test]
    fn file_uri_is_percent_decoded() {
        assert_eq!(
            from_file_uri("file:///Users/dev/My%20Project"),
            Some(PathBuf::from("/Users/dev/My Project"))
        );
        // Empty-host form (`file://` immediately followed by the path).
        assert_eq!(from_file_uri("file:///a/b"), Some(PathBuf::from("/a/b")));
        assert_eq!(from_file_uri("https://example.com"), None);
    }

    fn leaf(name: &str, alloc: u64, errors: u64) -> DirNode {
        DirNode {
            name: name.into(),
            alloc,
            apparent: alloc,
            files: if alloc > 0 { 1 } else { 0 },
            dirs: 0,
            errors,
            children: Box::new([]),
        }
    }

    fn tiny_tree(root: &str, children: Vec<DirNode>) -> Arc<DirTree> {
        let mut root_node = DirNode {
            name: root.into(),
            ..DirNode::default()
        };
        for c in &children {
            root_node.alloc += c.alloc;
            root_node.apparent += c.apparent;
            root_node.files += c.files;
            root_node.dirs += 1;
        }
        root_node.children = children.into_boxed_slice();
        Arc::new(DirTree {
            root: PathBuf::from(root),
            files: root_node.files,
            dirs: root_node.dirs,
            bytes: root_node.alloc,
            errors: root_node.errors,
            node: root_node,
            top_files: Vec::new(),
            complete: true,
            scanned_at: SystemTime::now(),
            elapsed: Duration::from_millis(1),
        })
    }

    #[test]
    fn node_at_finds_a_path_in_any_tree_and_none_outside_every_tree() {
        let a = tiny_tree("/a", vec![leaf("x", 100, 0)]);
        let b = tiny_tree("/b", vec![leaf("y", 250, 0)]);
        let trees = [a, b];
        assert_eq!(
            node_at(&trees, Path::new("/a/x")).map(|n| n.alloc),
            Some(100)
        );
        assert_eq!(
            node_at(&trees, Path::new("/b/y")).map(|n| n.alloc),
            Some(250)
        );
        assert!(node_at(&trees, Path::new("/nowhere")).is_none());
    }

    #[test]
    fn bytes_of_finds_a_directory_in_the_tree() {
        let tree = tiny_tree("/home/dev", vec![leaf("proj", 500, 0)]);
        let sizer = Sizer::new(std::slice::from_ref(&tree));
        assert_eq!(sizer.bytes_of(Path::new("/home/dev/proj")), Sized::Dir(500));
        // The root itself is also resolvable.
        assert_eq!(sizer.bytes_of(Path::new("/home/dev")), Sized::Dir(500));
    }

    #[test]
    fn bytes_of_flags_an_unreadable_tree_entry_as_unsized() {
        let tree = tiny_tree("/home/dev", vec![leaf("locked", 0, 3)]);
        let sizer = Sizer::new(std::slice::from_ref(&tree));
        assert_eq!(
            sizer.bytes_of(Path::new("/home/dev/locked")),
            Sized::Unsized
        );
    }

    #[test]
    fn bytes_of_falls_back_to_lstat_for_a_file_outside_every_tree() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), vec![0u8; 9000]).unwrap();
        let trees: Vec<Arc<DirTree>> = Vec::new();
        let sizer = Sizer::new(&trees);
        match sizer.bytes_of(tmp.path()) {
            Sized::File(bytes) => assert!(bytes >= 9000, "expected at least the file's own bytes"),
            other => panic!("expected File(_), got {other:?}"),
        }
    }

    #[test]
    fn bytes_of_flags_a_dir_missing_from_every_tree_as_unsized() {
        let tmp = tempfile::tempdir().unwrap();
        let trees: Vec<Arc<DirTree>> = Vec::new();
        let sizer = Sizer::new(&trees);
        assert_eq!(sizer.bytes_of(tmp.path()), Sized::Unsized);
    }

    #[test]
    fn bytes_of_flags_a_missing_path_as_unsized() {
        let trees: Vec<Arc<DirTree>> = Vec::new();
        let sizer = Sizer::new(&trees);
        assert_eq!(
            sizer.bytes_of(Path::new("/definitely/not/a/real/path")),
            Sized::Unsized
        );
    }

    #[test]
    fn bytes_of_is_memoised() {
        let tree = tiny_tree("/home/dev", vec![leaf("proj", 500, 0)]);
        let sizer = Sizer::new(std::slice::from_ref(&tree));
        assert_eq!(sizer.bytes_of(Path::new("/home/dev/proj")), Sized::Dir(500));
        assert_eq!(sizer.memo.lock().unwrap().len(), 1);
        assert_eq!(sizer.bytes_of(Path::new("/home/dev/proj")), Sized::Dir(500));
        assert_eq!(sizer.memo.lock().unwrap().len(), 1);
    }

    #[test]
    fn disk_total_sums_every_tree() {
        let a = tiny_tree("/a", vec![leaf("x", 100, 0)]);
        let b = tiny_tree("/b", vec![leaf("y", 250, 0)]);
        assert_eq!(disk_total(&[a, b]), 350);
    }
}
