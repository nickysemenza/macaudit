//! Project discovery over the whole-disk walk: git repo roots (from the Git
//! section's snapshot, already vendor-filtered), linked worktrees
//! (`<repo>/.git/worktrees/*/gitdir`), and manifest-only projects swept from
//! the home subtree and matched against `PROJECT_MARKERS`.

use std::path::{Path, PathBuf};

use crate::attribution::model::ResolveEnv;
use crate::attribution::paths::node_at;
use crate::model::{FindingKind, ScannerId};
use crate::scan::global_tools::projects::{PROJECT_MARKERS, SKIP_DIRS};
use crate::scan::walk::listing::{self, Kind};
use crate::scan::walk::DirNode;

use super::{Project, ProjectIndex, ARTIFACT_DIR_NAMES};

/// Manifest-only projects are swept no deeper than this many path
/// components below `$HOME`.
const MAX_SWEEP_DEPTH: usize = 6;
/// `listing::list` calls the manifest sweep is willing to spend — a live
/// syscall per candidate directory, unlike the tree-only traversal choosing
/// which directories are candidates.
const MAX_CANDIDATES: usize = 2000;

/// Discover every project reachable from the current snapshots: git repo
/// roots and their linked worktrees, then manifest-only projects from the
/// home subtree (skipping anything under a root already found), with every
/// project's `names`/`bundle_ids` filled in.
pub fn discover(env: &ResolveEnv<'_>) -> ProjectIndex {
    let mut projects = git_projects(env);

    let exclude: Vec<PathBuf> = projects
        .iter()
        .flat_map(|p| std::iter::once(p.root.clone()).chain(p.worktrees.iter().cloned()))
        .collect();
    projects.extend(manifest_projects(env, &exclude));

    for project in &mut projects {
        super::names::collect(project, env);
    }
    projects.sort_by(|a, b| a.root.cmp(&b.root));
    ProjectIndex::new(projects)
}

/// One `Project` per `GitRepo` finding from the Git section's latest
/// snapshot (already vendor-filtered — see `scan::git`), with its linked
/// worktrees resolved.
fn git_projects(env: &ResolveEnv<'_>) -> Vec<Project> {
    let mut out = Vec::new();
    for finding in env.findings(ScannerId::Git) {
        if finding.kind != FindingKind::GitRepo {
            continue;
        }
        let Some(root) = finding.path.clone() else {
            continue;
        };
        let worktrees = linked_worktrees(&root);
        let basename = basename_of(&root);
        out.push(Project {
            root,
            name: basename.clone(),
            worktrees,
            names: vec![basename],
            bundle_ids: Vec::new(),
            is_git: true,
        });
    }
    out
}

fn basename_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// `<repo>/.git/worktrees/*/gitdir` → checkout directories, skipping any
/// whose checkout no longer exists (a worktree removed with `git worktree
/// remove --force` outside macaudit's view, or one never fully cleaned up).
fn linked_worktrees(root: &Path) -> Vec<PathBuf> {
    let worktrees_dir = root.join(".git/worktrees");
    let Ok(dir_listing) = listing::list(&worktrees_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in &dir_listing.entries {
        if entry.kind != Kind::Dir {
            continue;
        }
        let admin_dir = worktrees_dir.join(&entry.name);
        let Ok(content) = std::fs::read_to_string(admin_dir.join("gitdir")) else {
            continue;
        };
        let Some(checkout) = checkout_from_gitdir(&content, &admin_dir) else {
            continue;
        };
        if checkout.exists() {
            out.push(checkout);
        }
    }
    out
}

/// Parse a worktree's `gitdir` file content into its checkout directory: the
/// file holds the path to the checkout's `.git` file (which itself points
/// back at `admin_dir`), absolute in every `git` version observed in
/// practice but relative-to-`admin_dir` per the on-disk format git also
/// accepts — so both are handled. Pure so the two shapes get a direct test
/// instead of a tempdir fixture.
fn checkout_from_gitdir(content: &str, admin_dir: &Path) -> Option<PathBuf> {
    let raw = content.trim();
    if raw.is_empty() {
        return None;
    }
    let mut git_path = PathBuf::from(raw);
    if git_path.is_relative() {
        git_path = admin_dir.join(git_path);
    }
    let checkout = if git_path.file_name().is_some_and(|n| n == ".git") {
        git_path.parent()?.to_path_buf()
    } else {
        git_path
    };
    Some(checkout)
}

/// Sweep `$HOME`'s walked subtree for manifest-only projects: directories
/// matching `PROJECT_MARKERS` that aren't already inside a discovered git
/// root or worktree. A directory tree walk (`DirNode::children`, free —
/// already in memory) chooses which directories to look at; each one costs
/// exactly one live `listing::list` to check its filenames, since `DirNode`
/// tracks subdirectories but never individual files.
fn manifest_projects(env: &ResolveEnv<'_>, exclude: &[PathBuf]) -> Vec<Project> {
    let home = env.paths.home.clone();
    let Some(home_node) = node_at(env.trees, &home) else {
        return Vec::new();
    };

    let mut projects = Vec::new();
    let mut checked = 0usize;
    let mut stack: Vec<(PathBuf, &DirNode, usize)> = vec![(home, home_node, 0)];
    while let Some((path, node, depth)) = stack.pop() {
        if checked >= MAX_CANDIDATES {
            break;
        }
        if exclude.iter().any(|root| path.starts_with(root)) {
            // Already covered by a git root/worktree — nothing under it is
            // a separate project (monorepo sub-packages fold into it).
            continue;
        }

        checked += 1;
        if let Ok(dir_listing) = listing::list(&path) {
            let has_marker = dir_listing.entries.iter().any(|e| {
                e.kind != Kind::Dir && PROJECT_MARKERS.iter().any(|m| e.name.to_str() == Some(*m))
            });
            if has_marker {
                let basename = basename_of(&path);
                projects.push(Project {
                    root: path,
                    name: basename.clone(),
                    worktrees: Vec::new(),
                    names: vec![basename],
                    bundle_ids: Vec::new(),
                    is_git: false,
                });
                // A manifest inside a manifest folds into the outer one —
                // don't look any deeper under a project we just found.
                continue;
            }
        }

        if depth >= MAX_SWEEP_DEPTH {
            continue;
        }
        for child in node.children.iter() {
            let name = &*child.name;
            if name.starts_with('.')
                || name == "Library"
                || SKIP_DIRS.contains(&name)
                || ARTIFACT_DIR_NAMES.contains(&name)
                || is_package_dir(name)
            {
                continue;
            }
            stack.push((path.join(name), child, depth + 1));
        }
    }
    projects
}

/// A directory macOS (or Xcode) treats as an opaque package — never a
/// project of our own. A small local copy of `scan::fs`'s (private)
/// `PACKAGE_EXTENSIONS`/`package_extension`, since discovery only needs to
/// recognise the common project-adjacent ones, not the full data-library
/// list that module also carries.
const LOCAL_PACKAGE_EXTENSIONS: &[&str] = &[
    "app",
    "appex",
    "framework",
    "bundle",
    "plugin",
    "kext",
    "xpc",
    "prefpane",
    "qlgenerator",
    "mdimporter",
    "saver",
    "xcodeproj",
    "xcworkspace",
    "playground",
    "docset",
    "dsym",
    "pkg",
    "mpkg",
];

pub(crate) fn is_package_dir(name: &str) -> bool {
    match name.rsplit_once('.') {
        Some((_, ext)) => {
            let ext = ext.to_ascii_lowercase();
            LOCAL_PACKAGE_EXTENSIONS.iter().any(|e| *e == ext)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkout_from_gitdir_handles_an_absolute_path() {
        let admin = Path::new("/Users/dev/proj/.git/worktrees/feature-x");
        let got = checkout_from_gitdir("/Users/dev/proj-worktrees/feature-x/.git\n", admin);
        assert_eq!(
            got,
            Some(PathBuf::from("/Users/dev/proj-worktrees/feature-x"))
        );
    }

    #[test]
    fn checkout_from_gitdir_resolves_a_relative_path_against_the_admin_dir() {
        let admin = Path::new("/Users/dev/proj/.git/worktrees/feature-x");
        let got = checkout_from_gitdir("../../../../proj-worktrees/feature-x/.git", admin);
        // Not canonicalised (no filesystem access in a pure parser) — just
        // joined onto the admin dir, same as the non-relative case's input.
        assert_eq!(
            got,
            Some(PathBuf::from(
                "/Users/dev/proj/.git/worktrees/feature-x/../../../../proj-worktrees/feature-x"
            ))
        );
    }

    #[test]
    fn checkout_from_gitdir_rejects_empty_content() {
        assert_eq!(checkout_from_gitdir("\n", Path::new("/x")), None);
    }

    #[test]
    fn is_package_dir_matches_known_extensions_case_insensitively() {
        assert!(is_package_dir("Foo.APP"));
        assert!(is_package_dir("Bar.xcodeproj"));
        assert!(!is_package_dir("not-a-package"));
        assert!(!is_package_dir("weird."));
    }
}
