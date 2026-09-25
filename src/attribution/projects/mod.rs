//! Project discovery: git repo roots, manifest-only projects, and worktrees
//! (`discovery.rs`), the name extraction that backs the name-match evidence
//! tier (`names.rs`), and one resolver per resource kind (`resolvers/`).

pub mod discovery;
pub mod names;
pub mod resolvers;

use std::path::{Path, PathBuf};

/// One discovered project: a non-vendored git repo root, or a manifest-only
/// directory (`PROJECT_MARKERS`) not inside any repo. Worktrees and
/// monorepo sub-packages fold into this; a separate clone is its own project.
#[derive(Clone, Debug, PartialEq)]
pub struct Project {
    pub root: PathBuf,
    pub name: String,
    /// Checkout dirs of `git worktree`s linked to this project's repo.
    pub worktrees: Vec<PathBuf>,
    /// Every name this project is known by (dir basename, package.json name,
    /// Cargo.toml package/bin names, ...) — the name-match evidence tier
    /// matches against these.
    pub names: Vec<String>,
    /// Bundle ids declared by this project (Xcode products), for the
    /// simulator-data join.
    pub bundle_ids: Vec<String>,
    pub is_git: bool,
}

/// Every discovered project for one resolve pass, queryable by path.
#[derive(Default)]
pub struct ProjectIndex {
    projects: Vec<Project>,
}

impl ProjectIndex {
    pub fn new(projects: Vec<Project>) -> Self {
        ProjectIndex { projects }
    }

    pub fn projects(&self) -> &[Project] {
        &self.projects
    }

    /// The project that owns `path`: longest-prefix match over every root
    /// and worktree checkout (a worktree checkout resolves to its *main*
    /// project, since a `Project`'s own `worktrees` are its linked
    /// checkouts, not separate `Project`s).
    pub fn owner_of(&self, path: &Path) -> Option<&Project> {
        let mut best: Option<(&Project, usize)> = None;
        for project in &self.projects {
            let candidates = std::iter::once(project.root.as_path())
                .chain(project.worktrees.iter().map(PathBuf::as_path));
            for candidate in candidates {
                if !path.starts_with(candidate) {
                    continue;
                }
                let depth = candidate.components().count();
                if best.is_none_or(|(_, best_depth)| depth > best_depth) {
                    best = Some((project, depth));
                }
            }
        }
        best.map(|(project, _)| project)
    }
}

/// Directory names that hold build output or vendored dependencies rather
/// than project sources — pruned from every subtree sweep this module does
/// (the manifest-only discovery sweep, and `names.rs`'s Cargo.toml/pbxproj
/// search) so a vendored copy is never mistaken for a project — or a
/// manifest — of its own.
pub(crate) const ARTIFACT_DIR_NAMES: &[&str] = &[
    "node_modules",
    "target",
    ".venv",
    "venv",
    "build",
    "dist",
    "Pods",
    "__pycache__",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn project(root: &str, worktrees: &[&str]) -> Project {
        Project {
            root: PathBuf::from(root),
            name: root.rsplit('/').next().unwrap_or(root).to_string(),
            worktrees: worktrees.iter().map(PathBuf::from).collect(),
            names: Vec::new(),
            bundle_ids: Vec::new(),
            is_git: true,
        }
    }

    #[test]
    fn owner_of_matches_the_longest_prefix() {
        let index = ProjectIndex::new(vec![
            project("/Users/dev/dev", &[]),
            project("/Users/dev/dev/cubby", &[]),
        ]);
        // Both "/Users/dev/dev" and "/Users/dev/dev/cubby" are prefixes of
        // this path; the deeper (more specific) one must win.
        let owner = index
            .owner_of(Path::new("/Users/dev/dev/cubby/apps/api"))
            .expect("owner found");
        assert_eq!(owner.root, PathBuf::from("/Users/dev/dev/cubby"));
    }

    #[test]
    fn owner_of_folds_a_worktree_checkout_into_its_main_project() {
        let index = ProjectIndex::new(vec![project(
            "/Users/dev/dev/cubby",
            &["/Users/dev/dev/cubby-worktrees/feature-x"],
        )]);
        let owner = index
            .owner_of(Path::new(
                "/Users/dev/dev/cubby-worktrees/feature-x/src/main.rs",
            ))
            .expect("owner found");
        assert_eq!(owner.root, PathBuf::from("/Users/dev/dev/cubby"));
    }

    #[test]
    fn owner_of_is_none_outside_every_project() {
        let index = ProjectIndex::new(vec![project("/Users/dev/dev/cubby", &[])]);
        assert!(index.owner_of(Path::new("/Users/dev/other")).is_none());
    }
}
