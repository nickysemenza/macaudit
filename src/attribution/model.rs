//! Core domain types for the attribution axes (Projects, App Storage): what a
//! resolver claims about a path, what accounting turns claims into per-owner
//! numbers, and the environment resolvers read from.
//!
//! FFI-shaped on purpose: no tuples, no `&'static str` payloads on anything
//! that crosses to Swift. The FFI mirror (`crates/macaudit-ffi`) swaps
//! `PathBuf` for `String`; everything else copies field-for-field.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{Config, Paths};
use crate::model::{Finding, FindingId, ScannerId};
use crate::runner::CommandRunner;
use crate::scan::walk::DirTree;

use super::bus::Snapshot;

/// The sentinel owner key a resolver uses to mean "I looked, and nothing
/// claims this" — `accounting::account` routes any claim whose owner is
/// exactly this string into `FootprintSet::unattributed` instead of trying
/// to find it a `Footprint` row, using the claim's `evidence` as the entry's
/// `reason`.
pub const UNATTRIBUTED_OWNER: &str = "unattributed";

/// Sentinel owner key for claims made by an *ecosystem pass* rather than by
/// a project: resources that exist whether or not any project uses them
/// (the default rustup toolchain, simulator runtimes, Homebrew core). They
/// must be claimed exactly once, not once per project, so a resolver's
/// `baseline(env)` pass claims them under this key with `.baseline(eco)`.
/// `accounting::account` never gives this key a `Footprint` row and never
/// counts it toward an ecosystem's owner count; membership in an ecosystem
/// comes only from real owners' claims tagged via `.ecosystem(eco)`.
pub const BASELINE_OWNER: &str = "baseline";

/// Which attribution lens a `FootprintSet` belongs to.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Axis {
    Projects,
    AppStorage,
}

impl Axis {
    /// Every axis, for iteration.
    pub const ALL: &'static [Axis] = &[Axis::Projects, Axis::AppStorage];

    pub fn label(self) -> &'static str {
        match self {
            Axis::Projects => "Projects",
            Axis::AppStorage => "App Storage",
        }
    }

    /// Lowercase form used by the `macaudit footprints --axis` CLI flag.
    pub fn slug(self) -> &'static str {
        match self {
            Axis::Projects => "projects",
            Axis::AppStorage => "apps",
        }
    }

    /// Parse a `--axis` value (accepts a couple of friendly spellings).
    pub fn parse(s: &str) -> Option<Axis> {
        match s.trim().to_ascii_lowercase().as_str() {
            "projects" | "project" => Some(Axis::Projects),
            "apps" | "app" | "app_storage" | "appstorage" => Some(Axis::AppStorage),
            _ => None,
        }
    }

    /// The scanner section that produces this axis's findings.
    pub fn scanner(self) -> ScannerId {
        match self {
            Axis::Projects => ScannerId::Projects,
            Axis::AppStorage => ScannerId::AppStorage,
        }
    }
}

/// What sort of thing owns a `Footprint`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum OwnerKind {
    Project,
    App,
    Formula,
    Homebrew,
    Tool,
    /// The synthetic "shared by every project/app of an ecosystem" owner.
    Baseline,
    /// The synthetic "could not be linked to anything" owner.
    Unattributed,
}

impl OwnerKind {
    pub fn label(self) -> &'static str {
        match self {
            OwnerKind::Project => "Project",
            OwnerKind::App => "App",
            OwnerKind::Formula => "Formula",
            OwnerKind::Homebrew => "Homebrew",
            OwnerKind::Tool => "Tool",
            OwnerKind::Baseline => "Baseline",
            OwnerKind::Unattributed => "Unattributed",
        }
    }
}

/// One row's identity: `key` is the stable, axis-specific identity a
/// resolver's claims are grouped by (a project root path, an app bundle id,
/// `"formula:<name>"`, `"tool:<name>"`, or `"homebrew"`).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Owner {
    pub key: String,
    pub kind: OwnerKind,
    pub name: String,
    pub path: Option<PathBuf>,
}

/// What resource an entry represents — the breakdown axis within one owner.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    WorkingTree,
    Artifacts,
    Worktree,
    PackageCache,
    Toolchain,
    Xcode,
    Simulator,
    Docker,
    AgentState,
    EditorState,
    ProjectCache,
    AppBundle,
    Container,
    GroupContainer,
    AppSupport,
    Cache,
    Preferences,
    Logs,
    WebData,
    SavedState,
    DotDir,
    Data,
    Other,
}

impl EntryKind {
    pub const ALL: &'static [EntryKind] = &[
        EntryKind::WorkingTree,
        EntryKind::Artifacts,
        EntryKind::Worktree,
        EntryKind::PackageCache,
        EntryKind::Toolchain,
        EntryKind::Xcode,
        EntryKind::Simulator,
        EntryKind::Docker,
        EntryKind::AgentState,
        EntryKind::EditorState,
        EntryKind::ProjectCache,
        EntryKind::AppBundle,
        EntryKind::Container,
        EntryKind::GroupContainer,
        EntryKind::AppSupport,
        EntryKind::Cache,
        EntryKind::Preferences,
        EntryKind::Logs,
        EntryKind::WebData,
        EntryKind::SavedState,
        EntryKind::DotDir,
        EntryKind::Data,
        EntryKind::Other,
    ];

    pub fn label(self) -> &'static str {
        match self {
            EntryKind::WorkingTree => "Working tree",
            EntryKind::Artifacts => "Artifacts",
            EntryKind::Worktree => "Worktree",
            EntryKind::PackageCache => "Package cache",
            EntryKind::Toolchain => "Toolchain",
            EntryKind::Xcode => "Xcode",
            EntryKind::Simulator => "Simulator",
            EntryKind::Docker => "Docker",
            EntryKind::AgentState => "Agent state",
            EntryKind::EditorState => "Editor state",
            EntryKind::ProjectCache => "Project cache",
            EntryKind::AppBundle => "App bundle",
            EntryKind::Container => "Container",
            EntryKind::GroupContainer => "Group container",
            EntryKind::AppSupport => "App support",
            EntryKind::Cache => "Cache",
            EntryKind::Preferences => "Preferences",
            EntryKind::Logs => "Logs",
            EntryKind::WebData => "Web data",
            EntryKind::SavedState => "Saved state",
            EntryKind::DotDir => "Dot dir",
            EntryKind::Data => "Data",
            EntryKind::Other => "Other",
        }
    }
}

/// How confident a claim linking a path to an owner is — shown to users
/// verbatim (`label()`), and ordered strongest-first so `EvidenceTier::min()`
/// over an owner's entries gives its best evidence.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTier {
    Exact,
    NameMatch,
    Observed,
    EcosystemDefault,
    Curated,
}

impl EvidenceTier {
    pub fn label(self) -> &'static str {
        match self {
            EvidenceTier::Exact => "exact",
            EvidenceTier::NameMatch => "name match",
            EvidenceTier::Observed => "observed",
            EvidenceTier::EcosystemDefault => "ecosystem default",
            EvidenceTier::Curated => "curated",
        }
    }
}

/// One accounted path under an owner (or under Baseline/Unattributed):
/// `bytes` is the nesting-adjusted figure that sums correctly with siblings;
/// `raw_bytes` is what the path itself measures before any subtraction.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct FootprintEntry {
    pub path: PathBuf,
    pub kind: EntryKind,
    pub bytes: u64,
    pub raw_bytes: u64,
    /// Owner keys touching this path — `len() > 1` means shared.
    pub owners: Vec<String>,
    pub tier: EvidenceTier,
    /// Human explanation of the link, e.g. "Cargo.lock in recipebridge/".
    pub evidence: String,
    pub label: String,
    pub baseline: bool,
    /// An APFS reflink clone of a package-manager store (e.g. pnpm's
    /// `node_modules/.pnpm`) — counted in reach, never in exclusive.
    pub clone_of_store: bool,
    /// A Docker-reported size that never contributes to disk totals.
    pub virtual_bytes: bool,
    /// The path wasn't found in any walked tree — `bytes` is a guess (0).
    /// `unsized` is a reserved keyword, hence the raw identifier.
    pub r#unsized: bool,
    /// The claim's target no longer exists (e.g. stale DerivedData).
    pub stale: bool,
    pub finding: Option<FindingId>,
    /// Why an Unattributed entry couldn't be linked.
    pub reason: Option<String>,
}

/// One resource-kind bucket within an owner's breakdown.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct FootprintGroup {
    pub kind: EntryKind,
    pub bytes: u64,
    pub entries: Vec<FootprintEntry>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ProcKind {
    Shell,
    Server,
    Other,
}

/// A live process whose cwd is inside a project.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Proc {
    pub pid: u32,
    pub name: String,
    pub kind: ProcKind,
    pub cwd: PathBuf,
}

/// One owner's row: the exclusive/shared/reach/baseline-share numbers plus
/// its breakdown.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Footprint {
    pub finding: FindingId,
    pub owner: Owner,
    /// Bytes only this owner touches (non-baseline, non-clone, non-virtual).
    pub exclusive: u64,
    /// This owner's 1/N slice of multi-owner entries.
    pub shared: u64,
    /// Everything this owner touches, including baseline/shared.
    pub reach: u64,
    /// This owner's 1/N_eco slice of baseline entries.
    pub baseline_share: u64,
    pub groups: Vec<FootprintGroup>,
    pub worktrees: Vec<PathBuf>,
    pub processes: Vec<Proc>,
    pub ports: Vec<u16>,
    /// Whether an APFS-clone note should be shown for this owner.
    pub clone_note: bool,
}

/// One axis's whole scan output: every owner's footprint plus the
/// synthetic Baseline/Unattributed rows and coverage totals.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct FootprintSet {
    pub axis: Axis,
    pub gen: u64,
    pub footprints: Vec<Footprint>,
    pub baseline: Vec<FootprintEntry>,
    pub unattributed: Vec<FootprintEntry>,
    pub disk_total: u64,
    pub attributed_total: u64,
    /// Dependency sections that weren't available (missing/cancelled) when
    /// this set was computed — surfaced in the coverage bucket row.
    pub missing_deps: Vec<ScannerId>,
}

/// What one resolver claims about one path, before accounting turns claims
/// into `FootprintEntry`/`Footprint`s (nesting, shares, exclusive/reach).
/// Not FFI-shaped — internal to a single resolve pass, never persisted or
/// sent to Swift.
#[derive(Clone, PartialEq, Debug)]
pub struct Claim {
    pub path: PathBuf,
    pub owner: String,
    pub kind: EntryKind,
    pub tier: EvidenceTier,
    pub evidence: String,
    pub label: String,
    pub baseline: bool,
    /// Which ecosystem this claim places its owner in (`"node"`, `"rust"`,
    /// ...). Set by `.ecosystem(eco)` on ordinary claims (a `Cargo.lock`
    /// claim makes the project a Rust project) and by `.baseline(eco)` on
    /// baseline ones; `accounting` divides each baseline entry by how many
    /// real owners carry the same tag anywhere in their claims.
    pub ecosystem: Option<&'static str>,
    pub clone_of_store: bool,
    pub virtual_bytes: bool,
    /// Override `bytes_of(path)` — used when a Finding already measured the
    /// path more precisely (e.g. an artifact's `size_bytes` minus hard-link
    /// sharing) than a fresh tree lookup would.
    pub raw_bytes_override: Option<u64>,
    pub finding: Option<FindingId>,
    pub stale: bool,
}

impl Claim {
    pub fn new(
        path: impl Into<PathBuf>,
        owner: impl Into<String>,
        kind: EntryKind,
        tier: EvidenceTier,
        evidence: impl Into<String>,
    ) -> Self {
        Claim {
            path: path.into(),
            owner: owner.into(),
            kind,
            tier,
            evidence: evidence.into(),
            label: String::new(),
            baseline: false,
            ecosystem: None,
            clone_of_store: false,
            virtual_bytes: false,
            raw_bytes_override: None,
            finding: None,
            stale: false,
        }
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    pub fn baseline(mut self, ecosystem: &'static str) -> Self {
        self.baseline = true;
        self.ecosystem = Some(ecosystem);
        self
    }

    /// Tag an ordinary (non-baseline) claim with the ecosystem it proves
    /// membership of, so the owner shares that ecosystem's baseline entries.
    pub fn ecosystem(mut self, ecosystem: &'static str) -> Self {
        self.ecosystem = Some(ecosystem);
        self
    }

    pub fn clone_of_store(mut self) -> Self {
        self.clone_of_store = true;
        self
    }

    pub fn virtual_bytes(mut self) -> Self {
        self.virtual_bytes = true;
        self
    }

    pub fn raw_bytes_override(mut self, bytes: u64) -> Self {
        self.raw_bytes_override = Some(bytes);
        self
    }

    pub fn finding(mut self, id: FindingId) -> Self {
        self.finding = Some(id);
        self
    }

    pub fn stale(mut self) -> Self {
        self.stale = true;
        self
    }
}

/// Everything a resolver needs: the dependency sections' latest snapshots
/// (via `findings`), the walked trees (for `paths::bytes_of`), and a
/// memoised file-head reader for manifest parsing.
pub struct ResolveEnv<'a> {
    pub paths: &'a Paths,
    pub config: &'a Config,
    pub trees: &'a [std::sync::Arc<DirTree>],
    pub snapshots: &'a HashMap<ScannerId, Snapshot>,
    pub runner: &'a dyn CommandRunner,
    head_cache: RefCell<HashMap<PathBuf, Option<String>>>,
}

impl<'a> ResolveEnv<'a> {
    pub fn new(
        paths: &'a Paths,
        config: &'a Config,
        trees: &'a [std::sync::Arc<DirTree>],
        snapshots: &'a HashMap<ScannerId, Snapshot>,
        runner: &'a dyn CommandRunner,
    ) -> Self {
        ResolveEnv {
            paths,
            config,
            trees,
            snapshots,
            runner,
            head_cache: RefCell::new(HashMap::new()),
        }
    }

    /// A dependency section's findings from its latest valid snapshot — empty
    /// when that section is in `FootprintSet::missing_deps`.
    pub fn findings(&self, id: ScannerId) -> &[Finding] {
        self.snapshots
            .get(&id)
            .map(|s| s.findings.as_slice())
            .unwrap_or(&[])
    }

    /// The first `max_bytes` of a file, decoded lossily as UTF-8. Memoised
    /// per path for the lifetime of this env (one resolve pass reads the
    /// same manifest from multiple resolvers). `None` when the file can't be
    /// read.
    pub fn read_head(&self, path: &Path, max_bytes: usize) -> Option<String> {
        if let Some(cached) = self.head_cache.borrow().get(path) {
            return cached.clone();
        }
        let result = read_head_bytes(path, max_bytes);
        self.head_cache
            .borrow_mut()
            .insert(path.to_path_buf(), result.clone());
        result
    }
}

fn read_head_bytes(path: &Path, max_bytes: usize) -> Option<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; max_bytes];
    let n = file.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn axis_slug_round_trips_through_parse() {
        for axis in Axis::ALL {
            assert_eq!(Axis::parse(axis.slug()), Some(*axis));
        }
        assert_eq!(Axis::parse("nope"), None);
    }

    #[test]
    fn evidence_tier_orders_strongest_first() {
        assert!(EvidenceTier::Exact < EvidenceTier::Curated);
        let tiers = [
            EvidenceTier::Curated,
            EvidenceTier::Exact,
            EvidenceTier::Observed,
        ];
        assert_eq!(tiers.iter().min(), Some(&EvidenceTier::Exact));
    }

    #[test]
    fn claim_builder_sets_optional_fields() {
        let claim = Claim::new(
            "/Users/x/proj",
            "proj-owner",
            EntryKind::WorkingTree,
            EvidenceTier::Exact,
            "repo root",
        )
        .label("Working tree")
        .clone_of_store()
        .stale();
        assert_eq!(claim.label, "Working tree");
        assert!(claim.clone_of_store);
        assert!(claim.stale);
        assert!(!claim.baseline);
        assert_eq!(claim.ecosystem, None);
    }

    #[test]
    fn read_head_is_memoised_and_missing_file_is_none() {
        let paths = Paths::from_home("/tmp/macaudit-attribution-model-test-home");
        let config = Config::default();
        let trees: Vec<std::sync::Arc<DirTree>> = Vec::new();
        let snapshots: HashMap<ScannerId, Snapshot> = HashMap::new();
        let runner = crate::runner::MockCommandRunner::new();
        let env = ResolveEnv::new(&paths, &config, &trees, &snapshots, &runner);
        assert_eq!(
            env.read_head(Path::new("/definitely/not/a/real/path"), 64),
            None
        );
        let tmp = std::env::temp_dir().join("macaudit-attribution-model-test.txt");
        std::fs::write(&tmp, "hello world").unwrap();
        assert_eq!(env.read_head(&tmp, 5), Some("hello".to_string()));
        // Memoised: rewriting the file must not change the cached answer.
        std::fs::write(&tmp, "goodbye").unwrap();
        assert_eq!(env.read_head(&tmp, 5), Some("hello".to_string()));
        let _ = std::fs::remove_file(&tmp);
    }
}
