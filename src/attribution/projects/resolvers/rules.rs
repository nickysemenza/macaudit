//! THE TABLE: every project-resolver rule, as data. Three row shapes —
//! `Lookup` (a project file/field → keys → paths under `~`), `ReverseLink`
//! (something under `~` that names a project path, scanned once per scan,
//! not once per project), `Baseline` (an ecosystem-wide resource claimed
//! once under `BASELINE_OWNER`) — `apply.rs` is the one evaluator for all
//! three. Named derive fns a row needs live in `derive.rs`; the handful of
//! joins that need a findings snapshot rather than a walk of `~` (Fs
//! artifacts, Docker, live processes) live in `joins.rs` instead of here.

use std::path::{Path, PathBuf};

use crate::attribution::model::{EntryKind, EvidenceTier, ResolveEnv};
use crate::attribution::projects::Project;
use crate::model::{FindingKind, ScannerId};

use super::parsers;

// ---------------------------------------------------------------------
// Row shapes
// ---------------------------------------------------------------------

/// A small bitset of row-level modifiers, spelled out at each call site
/// (`rules::CLONE_OF_STORE`, ...) rather than hidden behind a builder.
pub type Flags = u8;
pub const NONE: Flags = 0;
/// The claimed path is an APFS reflink clone of a package-manager store —
/// counted in reach, never exclusive (`Claim::clone_of_store`).
pub const CLONE_OF_STORE: Flags = 1 << 0;
/// Match directory-entry names case-insensitively (SwiftPM lower-cases its
/// cache directory names regardless of the resolved package identity's
/// casing).
pub const CASE_INSENSITIVE: Flags = 1 << 1;
/// Before matching, normalise a bare version directory name (`20.11.0`) to
/// carry the `v` prefix nvm/fnm's own directories already have
/// (`v20.11.0`) — volta/mise/pnpm install dirs are bare.
pub const V_PREFIX: Flags = 1 << 2;

/// One resolved key from a `Trigger`: a package/module identity (`name`,
/// `version`) plus `extra` for anything else a `Target` needs (a git
/// checkout's basename, a redirected target-dir's raw string value).
#[derive(Clone, Debug, Default)]
pub struct Key {
    pub name: String,
    pub version: String,
    pub extra: Option<String>,
}

/// Project file/field → keys → paths under `~`.
pub struct Lookup {
    /// Row identity — read back by `tests::lookup_row_ids_are_unique_and_nonempty`
    /// and useful in a debugger; never read by the evaluator itself.
    #[allow(dead_code)]
    pub id: &'static str,
    pub ecosystem: Option<&'static str>,
    pub trigger: Trigger,
    pub target: Target,
    pub kind: EntryKind,
    pub tier: EvidenceTier,
    /// Evidence template: `{file}` `{rel}` `{name}` `{version}` `{key}`.
    pub evidence: &'static str,
    /// Label template: `{name}` `{version}` `{key}` `{basename}` `{file}`.
    pub label: &'static str,
    pub flags: Flags,
}

pub enum Trigger {
    /// Fires once, with one empty `Key` (rows that derive everything from
    /// `project`/`env` directly — the Claude CLI cache directory).
    Always,
    /// Fires when `<root>/<rel>` exists — one empty `Key`.
    Exists(&'static str),
    /// The first source that yields a value `normalise` accepts wins.
    Pin {
        sources: &'static [PinSource],
        normalise: fn(&str) -> Option<String>,
    },
    /// `find` locates one or more manifest files; `parse` extracts zero or
    /// more `Key`s from each one's content.
    Manifest {
        find: Find,
        parse: fn(&str) -> Vec<Key>,
    },
    /// One `Key` per entry in `project.names`/`project.bundle_ids`.
    Field(ProjectField),
}

pub enum Find {
    /// `<project root>/<name>`, read head capped at `cap` bytes.
    Root(&'static str, usize),
    /// Every `<name>` file found by walking the project's subtree (via the
    /// walked tree + one `listing::list` per directory), pruning hidden and
    /// `ARTIFACT_DIR_NAMES` directories; each match's head capped at `cap`
    /// bytes.
    Subtree {
        names: &'static [&'static str],
        depth: usize,
        cap: usize,
    },
}

/// `env.read_head`'s cap for a small manifest (`package.json`, `Brewfile`,
/// `Package.resolved`, `.cargo/config.toml`, a shell/make file, ...).
pub const MANIFEST_CAP: usize = 256 * 1024;
/// `env.read_head`'s cap for a lockfile, which can run into the low
/// megabytes for a large monorepo (`Cargo.lock`, `package-lock.json`,
/// `yarn.lock`, `bun.lock`, `go.sum`).
pub const LOCKFILE_CAP: usize = 8 * 1024 * 1024;

pub enum PinSource {
    /// The first non-empty, non-`#`/`[`-prefixed line of this project-root
    /// file.
    Line(&'static str),
    /// A `key = "value"` / `key value` line in this project-root file
    /// (`parsers::key_value_field`) — despite the name this also covers
    /// asdf/mise's space-separated `.tool-versions` shape.
    TomlKey(&'static str, &'static str),
    /// A dotted JSON path into this project-root file (`package.json`'s
    /// `volta.node`).
    JsonPath(&'static str, &'static [&'static str]),
}

pub enum ProjectField {
    Names,
    BundleIds,
}

pub enum Target {
    /// Templated path candidates, each checked with `exists()`. A `*`
    /// component expands over one directory listing (every match tried).
    Path(&'static [&'static str]),
    /// One directory listing, entries whose name matches `prefix` (after
    /// template substitution) selected by `select`.
    Match {
        dirs: &'static [&'static str],
        prefix: &'static str,
        select: Select,
    },
    /// A Finding from another section's snapshot names the path (Brewfile →
    /// Cellar path / cask `app_paths`).
    Finding {
        scanner: ScannerId,
        kind: FindingKind,
        /// Meta keys tried in order for a match against `Key::name`.
        key_meta: &'static [&'static str],
        path: PathFrom,
    },
    /// Escape hatch for anything that needs real code (npm cacache, Go's
    /// module-path escaping, `CARGO_TARGET_DIR` expansion, ...) — named fns
    /// in `derive.rs`, so the table still says what each row does.
    Derive(fn(&Key, &Project, &ResolveEnv<'_>) -> Vec<PathBuf>),
}

pub enum PathFrom {
    Path,
    AppPaths,
}

/// How to pick among `Target::Match`'s candidates. Spelled out per row —
/// there is no crate-wide default. (No row currently needs `Last`; `First`
/// and `MaxSemver` cover every row today — add it back the day one does.)
pub enum Select {
    /// Every match is its own claim (cache entries).
    All,
    /// `parsers::newest_matching_version` — node/python pins, the rust
    /// toolchain.
    MaxSemver,
    /// The first listing match, alphabetically (SwiftPM's one repo cache
    /// per dependency).
    First,
}

/// Something under `~` that names a project path — evaluated once per scan
/// (not once per project; see `model.rs`'s `BASELINE_OWNER` doc for why
/// once-per-project rescanning is a bug, not just slow).
pub struct ReverseLink {
    /// Row identity — read back by `tests::reverse_link_row_ids_are_unique_and_nonempty`
    /// and useful in a debugger; never read by the evaluator itself.
    #[allow(dead_code)]
    pub id: &'static str,
    pub ecosystem: Option<&'static str>,
    pub kind: EntryKind,
    pub tier: EvidenceTier,
    pub evidence: &'static str,
    pub label: &'static str,
    pub scan: Scan,
    pub extract: Extract,
    pub matcher: Matcher,
    pub claim: ClaimAt,
    /// When the extracted path no longer exists: `UNATTRIBUTED_OWNER` with
    /// this evidence template (`{path}`), `.stale()`.
    pub stale: Option<&'static str>,
    pub fallback: Option<Fallback>,
}

pub enum Scan {
    /// Every directory found under `roots` (`{a,b,c}` alternation and a `*`
    /// component both expand at scan time) at exactly `depth`, skipping any
    /// whose name is in `skip`.
    Dirs {
        roots: &'static [&'static str],
        depth: usize,
        skip: &'static [&'static str],
    },
    /// Every file under `roots` whose name matches `name` (a leading/
    /// trailing `*` allowed; `None` matches every file), walked to
    /// unbounded depth, capped at `cap` files total across every root.
    Files {
        roots: &'static [&'static str],
        name: Option<&'static str>,
        cap: usize,
    },
}

pub enum Extract {
    /// A `.plist` file inside the scanned entry (a directory).
    PlistKey {
        file: &'static str,
        key: &'static str,
    },
    /// A JSON file inside the scanned entry; the first key in `keys` present
    /// is read as a `file://` URI.
    JsonUri {
        file: &'static str,
        keys: &'static [&'static str],
    },
    /// The scanned entry is a directory: read up to `max_files` of its
    /// `.jsonl` children (or, if the entry is itself a file, that file
    /// directly) for the first `"cwd":"…"` field within `head` bytes.
    JsonlCwd { max_files: usize, head: usize },
    /// Every symlink directly inside `<entry>/<subdir>`, resolved to an
    /// absolute target.
    SymlinkTargets { subdir: &'static str },
    /// Escape hatch (simulator container bundle ids: a metadata plist, or a
    /// fallback into the `.app`'s own `Info.plist`).
    Fn(fn(&Path) -> Option<Extracted>),
}

/// One extraction result: the path to match against a project (or bundle
/// id), plus optional extra text for the row's label template.
pub struct Extracted {
    pub path: PathBuf,
    pub label_extra: Option<String>,
}

pub enum Matcher {
    /// `paths::tree_path(extracted)` starts with a project's root or any of
    /// its worktrees (`ProjectIndex::owner_of`).
    PathUnderProject,
    /// `extracted`'s path field is actually a bundle id, matched against
    /// every project's `bundle_ids` (exact, or `<id>.<extension>`).
    BundleId,
}

pub enum ClaimAt {
    /// Claim the scanned entry itself.
    Entry,
    /// Claim the scanned entry's parent (pnpm: the store version dir that
    /// contains the matching `projects/` symlink, not the symlink itself).
    Parent,
}

pub enum Fallback {
    /// When no `cwd` was found in the entry at all, still claim it if its
    /// directory name is the project's Claude-encoded path (or an extension
    /// of it).
    EncodedProjectDir,
}

/// An ecosystem-wide resource, claimed once under `BASELINE_OWNER`.
pub struct Baseline {
    pub ecosystem: &'static str,
    /// `~`-relative or absolute; a `*` inside one component (whole,
    /// `prefix*`, `*suffix`, or `*mid*`) globs one directory listing at that
    /// position. `{value}` is replaced by `Source::FromFile`'s parsed value
    /// (the only row that needs it: rustup's default toolchain).
    pub path: &'static str,
    pub kind: EntryKind,
    pub label: Label,
    pub evidence: &'static str,
    pub source: Source,
    /// Entry names skipped outright (agents: `~/.claude/projects`, which has
    /// its own `ReverseLink` row instead).
    pub exclude: &'static [&'static str],
}

pub enum Label {
    Static(&'static str),
    Basename,
    Fn(fn(&Path) -> String),
}

pub enum Source {
    /// Always claimed, if `path` exists.
    Fixed,
    /// `path`'s `{value}` placeholder comes from parsing this project-root-
    /// independent file (rustup's `settings.toml`).
    FromFile {
        file: &'static str,
        parse: fn(&str) -> Option<String>,
    },
    /// The claim's path comes from a Finding in another section's snapshot
    /// (Homebrew's default `node`), not from `path` at all.
    FromFinding {
        scanner: ScannerId,
        kind: FindingKind,
        name: &'static str,
    },
}

// ---------------------------------------------------------------------
// LOOKUP
// ---------------------------------------------------------------------

pub const LOOKUP: &[Lookup] = &[
    // --- node ---------------------------------------------------------
    Lookup {
        id: "pnpm-clone",
        ecosystem: Some("node"),
        trigger: Trigger::Exists("node_modules/.pnpm"),
        // Empty template list: claim exactly the path `Trigger::Exists`
        // already checked, not a separately-templated location.
        target: Target::Path(&[]),
        kind: EntryKind::Artifacts,
        tier: EvidenceTier::Exact,
        evidence: "node_modules/.pnpm is a reflink clone of the pnpm store",
        label: "node_modules/.pnpm (clone of store)",
        flags: CLONE_OF_STORE,
    },
    Lookup {
        id: "npm-cacache",
        ecosystem: Some("node"),
        trigger: Trigger::Manifest {
            find: Find::Root("package-lock.json", LOCKFILE_CAP),
            parse: |text| {
                parsers::package_lock(text)
                    .into_iter()
                    .map(|p| Key {
                        name: p.name,
                        version: p.version,
                        extra: None,
                    })
                    .collect()
            },
        },
        target: Target::Derive(derive::npm_cacache),
        kind: EntryKind::PackageCache,
        tier: EvidenceTier::Exact,
        evidence: "package-lock.json",
        label: "{name} {version}",
        flags: NONE,
    },
    Lookup {
        id: "yarn-berry",
        ecosystem: Some("node"),
        trigger: Trigger::Manifest {
            find: Find::Root("yarn.lock", LOCKFILE_CAP),
            parse: |text| {
                parsers::yarn_berry(text)
                    .into_iter()
                    .map(|(name, version)| Key {
                        name,
                        version,
                        extra: None,
                    })
                    .collect()
            },
        },
        target: Target::Match {
            dirs: &["~/Library/Caches/Yarn/berry/cache"],
            prefix: "{name-flat}-npm-{version}-",
            select: Select::All,
        },
        kind: EntryKind::PackageCache,
        tier: EvidenceTier::Exact,
        evidence: "yarn.lock",
        label: "{name} {version}",
        flags: NONE,
    },
    Lookup {
        id: "bun",
        ecosystem: Some("node"),
        trigger: Trigger::Manifest {
            find: Find::Root("bun.lock", LOCKFILE_CAP),
            parse: |text| {
                parsers::bun_lock(text)
                    .into_iter()
                    .map(|(name, version)| Key {
                        name,
                        version,
                        extra: None,
                    })
                    .collect()
            },
        },
        target: Target::Match {
            dirs: &["~/.bun/install/cache"],
            prefix: "{name}@{version}",
            select: Select::All,
        },
        kind: EntryKind::PackageCache,
        tier: EvidenceTier::Exact,
        evidence: "bun.lock",
        label: "{name} {version}",
        flags: NONE,
    },
    // `bun.lockb` (the pre-text binary lockfile) carries no parseable
    // package list, so this claims the whole shared cache at
    // ecosystem-default tier rather than individual entries; accounting
    // dedupes by path when a project also has a text `bun.lock`.
    Lookup {
        id: "bun-lockb",
        ecosystem: Some("node"),
        trigger: Trigger::Exists("bun.lockb"),
        target: Target::Path(&["~/.bun/install/cache"]),
        kind: EntryKind::PackageCache,
        tier: EvidenceTier::EcosystemDefault,
        evidence: "bun.lockb present",
        label: "bun cache",
        flags: NONE,
    },
    Lookup {
        id: "node-pin",
        ecosystem: Some("node"),
        trigger: Trigger::Pin {
            sources: &[
                PinSource::Line(".nvmrc"),
                PinSource::Line(".node-version"),
                PinSource::TomlKey(".tool-versions", "nodejs"),
                PinSource::TomlKey(".mise.toml", "node"),
                PinSource::TomlKey("mise.toml", "node"),
                PinSource::JsonPath("package.json", &["volta", "node"]),
            ],
            normalise: parsers::normalise_node_pin,
        },
        target: Target::Match {
            dirs: &[
                "~/.nvm/versions/node",
                "~/.fnm/node-versions",
                "~/.volta/tools/image/node",
                "~/.local/share/mise/installs/node",
                "~/Library/pnpm/nodejs",
            ],
            prefix: "",
            select: Select::MaxSemver,
        },
        kind: EntryKind::Toolchain,
        tier: EvidenceTier::Exact,
        evidence: "node version pin",
        label: "node {basename}",
        flags: V_PREFIX,
    },
    // --- rust -----------------------------------------------------------
    Lookup {
        id: "cargo-registry",
        ecosystem: Some("rust"),
        trigger: Trigger::Manifest {
            find: Find::Subtree {
                names: &["Cargo.lock"],
                depth: 5,
                cap: LOCKFILE_CAP,
            },
            parse: parsers::cargo_lock_registry,
        },
        target: Target::Path(&[
            "~/.cargo/registry/cache/*/{name}-{version}.crate",
            "~/.cargo/registry/src/*/{name}-{version}",
        ]),
        kind: EntryKind::PackageCache,
        tier: EvidenceTier::Exact,
        evidence: "{relfile}",
        label: "{name} {version}",
        flags: NONE,
    },
    Lookup {
        id: "cargo-git",
        ecosystem: Some("rust"),
        trigger: Trigger::Manifest {
            find: Find::Subtree {
                names: &["Cargo.lock"],
                depth: 5,
                cap: LOCKFILE_CAP,
            },
            parse: parsers::cargo_lock_git,
        },
        target: Target::Match {
            dirs: &["~/.cargo/git/checkouts", "~/.cargo/git/db"],
            prefix: "{basename}-",
            select: Select::All,
        },
        kind: EntryKind::PackageCache,
        tier: EvidenceTier::NameMatch,
        evidence: "{relfile}",
        label: "{name} {version}",
        flags: NONE,
    },
    Lookup {
        id: "rust-toolchain",
        ecosystem: Some("rust"),
        trigger: Trigger::Pin {
            sources: &[
                PinSource::TomlKey("rust-toolchain.toml", "channel"),
                PinSource::Line("rust-toolchain.toml"),
                PinSource::TomlKey("rust-toolchain", "channel"),
                PinSource::Line("rust-toolchain"),
            ],
            normalise: parsers::identity,
        },
        target: Target::Match {
            dirs: &["~/.rustup/toolchains"],
            prefix: "",
            select: Select::MaxSemver,
        },
        kind: EntryKind::Toolchain,
        tier: EvidenceTier::Exact,
        evidence: "rust-toolchain pins {key}",
        label: "{basename}",
        flags: NONE,
    },
    Lookup {
        id: "cargo-target-config",
        ecosystem: Some("rust"),
        trigger: Trigger::Manifest {
            find: Find::Root(".cargo/config.toml", MANIFEST_CAP),
            parse: |text| {
                parsers::cargo_config_target_dir(text)
                    .map(|dir| Key {
                        name: dir,
                        version: String::new(),
                        extra: None,
                    })
                    .into_iter()
                    .collect()
            },
        },
        target: Target::Derive(derive::cargo_target_dir),
        kind: EntryKind::Artifacts,
        tier: EvidenceTier::Exact,
        evidence: "target-dir in .cargo/config.toml",
        label: "{basename}",
        flags: NONE,
    },
    Lookup {
        id: "cargo-target-scripts",
        ecosystem: Some("rust"),
        trigger: Trigger::Manifest {
            find: Find::Root("package.json", MANIFEST_CAP),
            parse: |text| {
                parsers::cargo_target_dirs_in_package_json_scripts(text)
                    .into_iter()
                    .map(|dir| Key {
                        name: dir,
                        version: String::new(),
                        extra: None,
                    })
                    .collect()
            },
        },
        target: Target::Derive(derive::cargo_target_dir),
        kind: EntryKind::Artifacts,
        tier: EvidenceTier::Exact,
        evidence: "CARGO_TARGET_DIR in package.json",
        label: "{basename}",
        flags: NONE,
    },
    Lookup {
        id: "cargo-target-shell",
        ecosystem: Some("rust"),
        trigger: Trigger::Manifest {
            find: Find::Subtree {
                names: &["Makefile", "justfile", ".env", ".env.*", "*.sh"],
                depth: 4,
                cap: MANIFEST_CAP,
            },
            parse: |text| {
                parsers::extract_cargo_target_dir(text)
                    .into_iter()
                    .map(|dir| Key {
                        name: dir,
                        version: String::new(),
                        extra: None,
                    })
                    .collect()
            },
        },
        target: Target::Derive(derive::cargo_target_dir),
        kind: EntryKind::Artifacts,
        tier: EvidenceTier::Exact,
        evidence: "CARGO_TARGET_DIR in {relfile}",
        label: "{basename}",
        flags: NONE,
    },
    // --- go ---------------------------------------------------------
    Lookup {
        id: "go-sum",
        ecosystem: Some("go"),
        trigger: Trigger::Manifest {
            find: Find::Root("go.sum", LOCKFILE_CAP),
            parse: parsers::go_sum,
        },
        target: Target::Derive(derive::go_module_cache),
        kind: EntryKind::PackageCache,
        tier: EvidenceTier::Exact,
        evidence: "go.sum",
        label: "{name} {version}",
        flags: NONE,
    },
    // --- python -------------------------------------------------------
    Lookup {
        id: "python-pin-uv",
        ecosystem: Some("python"),
        trigger: Trigger::Pin {
            sources: &[PinSource::Line(".python-version")],
            normalise: parsers::identity,
        },
        target: Target::Match {
            dirs: &["~/.local/share/uv/python"],
            prefix: "cpython-",
            select: Select::MaxSemver,
        },
        kind: EntryKind::Toolchain,
        tier: EvidenceTier::Exact,
        evidence: ".python-version pin",
        label: "Python {key} (uv)",
        flags: NONE,
    },
    Lookup {
        id: "python-pin-pyenv",
        ecosystem: Some("python"),
        trigger: Trigger::Pin {
            sources: &[PinSource::Line(".python-version")],
            normalise: parsers::identity,
        },
        target: Target::Match {
            dirs: &["~/.pyenv/versions"],
            prefix: "",
            select: Select::MaxSemver,
        },
        kind: EntryKind::Toolchain,
        tier: EvidenceTier::Exact,
        evidence: ".python-version pin",
        label: "Python {key} (pyenv)",
        flags: NONE,
    },
    Lookup {
        id: "uv-cache",
        ecosystem: Some("python"),
        trigger: Trigger::Exists("uv.lock"),
        target: Target::Path(&["~/.cache/uv"]),
        kind: EntryKind::PackageCache,
        tier: EvidenceTier::EcosystemDefault,
        evidence: "uv.lock present",
        label: "uv cache",
        flags: NONE,
    },
    Lookup {
        id: "poetry-cache",
        ecosystem: Some("python"),
        trigger: Trigger::Exists("poetry.lock"),
        target: Target::Path(&["~/Library/Caches/pypoetry"]),
        kind: EntryKind::PackageCache,
        tier: EvidenceTier::EcosystemDefault,
        evidence: "poetry.lock present",
        label: "Poetry cache",
        flags: NONE,
    },
    // --- swift ----------------------------------------------------------
    Lookup {
        id: "swiftpm",
        ecosystem: Some("swift"),
        trigger: Trigger::Manifest {
            find: Find::Root("Package.resolved", MANIFEST_CAP),
            parse: |text| {
                parsers::package_resolved(text)
                    .into_iter()
                    .filter_map(|pin| {
                        let basename = parsers::swiftpm_repo_basename(&pin.location)?;
                        Some(Key {
                            name: pin.identity,
                            version: String::new(),
                            extra: Some(basename),
                        })
                    })
                    .collect()
            },
        },
        target: Target::Match {
            dirs: &["~/Library/Caches/org.swift.swiftpm/repositories"],
            prefix: "{basename}-",
            select: Select::First,
        },
        kind: EntryKind::PackageCache,
        tier: EvidenceTier::Exact,
        evidence: "Package.resolved",
        label: "{name}",
        flags: CASE_INSENSITIVE,
    },
    // Xcode-driven SwiftPM: `Package.resolved` inside an `.xcodeproj`'s or
    // `.xcworkspace`'s `xcshareddata/swiftpm` — same target, a different
    // manifest search. `.build/checkouts` inside the project itself is
    // already claimed as an artifact by `joins::artifacts`.
    Lookup {
        id: "swiftpm-xcode",
        ecosystem: Some("swift"),
        trigger: Trigger::Manifest {
            find: Find::Subtree {
                names: &["Package.resolved"],
                depth: 2,
                cap: MANIFEST_CAP,
            },
            parse: |text| {
                parsers::package_resolved(text)
                    .into_iter()
                    .filter_map(|pin| {
                        let basename = parsers::swiftpm_repo_basename(&pin.location)?;
                        Some(Key {
                            name: pin.identity,
                            version: String::new(),
                            extra: Some(basename),
                        })
                    })
                    .collect()
            },
        },
        target: Target::Match {
            dirs: &["~/Library/Caches/org.swift.swiftpm/repositories"],
            prefix: "{basename}-",
            select: Select::First,
        },
        kind: EntryKind::PackageCache,
        tier: EvidenceTier::Exact,
        evidence: "{relfile}",
        label: "{name}",
        flags: CASE_INSENSITIVE,
    },
    // --- brew -------------------------------------------------------
    Lookup {
        id: "brewfile-formula",
        ecosystem: None, // brew rows tag nothing: there's no brew baseline.
        trigger: Trigger::Manifest {
            find: Find::Root("Brewfile", MANIFEST_CAP),
            parse: |text| {
                parsers::brewfile(text)
                    .into_iter()
                    .filter(|(kind, _)| matches!(kind, parsers::BrewEntryKind::Formula))
                    .map(|(_, name)| Key {
                        name,
                        version: String::new(),
                        extra: None,
                    })
                    .collect()
            },
        },
        target: Target::Finding {
            scanner: ScannerId::Brew,
            kind: FindingKind::BrewFormula,
            key_meta: &["name"],
            path: PathFrom::Path,
        },
        kind: EntryKind::Toolchain,
        tier: EvidenceTier::Exact,
        evidence: "Brewfile",
        label: "brew {name}",
        flags: NONE,
    },
    Lookup {
        id: "brewfile-cask",
        ecosystem: None,
        trigger: Trigger::Manifest {
            find: Find::Root("Brewfile", MANIFEST_CAP),
            parse: |text| {
                parsers::brewfile(text)
                    .into_iter()
                    .filter(|(kind, _)| matches!(kind, parsers::BrewEntryKind::Cask))
                    .map(|(_, name)| Key {
                        name,
                        version: String::new(),
                        extra: None,
                    })
                    .collect()
            },
        },
        target: Target::Finding {
            scanner: ScannerId::Brew,
            kind: FindingKind::BrewCask,
            key_meta: &["token", "name"],
            path: PathFrom::AppPaths,
        },
        kind: EntryKind::AppBundle,
        tier: EvidenceTier::Exact,
        evidence: "Brewfile",
        label: "brew {name}",
        flags: NONE,
    },
    // --- caches -----------------------------------------------------
    Lookup {
        id: "project-name-cache",
        ecosystem: None,
        trigger: Trigger::Field(ProjectField::Names),
        target: Target::Derive(derive::project_name_cache),
        kind: EntryKind::ProjectCache,
        tier: EvidenceTier::NameMatch,
        evidence: "named after project ({key})",
        label: "{basename}",
        flags: NONE,
    },
    Lookup {
        id: "bundle-id-container",
        ecosystem: None,
        trigger: Trigger::Field(ProjectField::BundleIds),
        target: Target::Path(&["~/Library/Containers/{key}"]),
        kind: EntryKind::Container,
        tier: EvidenceTier::Exact,
        evidence: "bundle id from project.pbxproj",
        label: "{key}",
        flags: NONE,
    },
    Lookup {
        id: "bundle-id-cache",
        ecosystem: None,
        trigger: Trigger::Field(ProjectField::BundleIds),
        target: Target::Path(&["~/Library/Caches/{key}"]),
        kind: EntryKind::Cache,
        tier: EvidenceTier::Exact,
        evidence: "bundle id from project.pbxproj",
        label: "{key}",
        flags: NONE,
    },
    Lookup {
        id: "bundle-id-http-storage",
        ecosystem: None,
        trigger: Trigger::Field(ProjectField::BundleIds),
        target: Target::Path(&["~/Library/HTTPStorages/{key}"]),
        kind: EntryKind::WebData,
        tier: EvidenceTier::Exact,
        evidence: "bundle id from project.pbxproj",
        label: "{key}",
        flags: NONE,
    },
    Lookup {
        id: "bundle-id-preferences",
        ecosystem: None,
        trigger: Trigger::Field(ProjectField::BundleIds),
        target: Target::Path(&["~/Library/Preferences/{key}.plist"]),
        kind: EntryKind::Preferences,
        tier: EvidenceTier::Exact,
        evidence: "bundle id from project.pbxproj",
        label: "{key}",
        flags: NONE,
    },
    Lookup {
        id: "bundle-id-webkit",
        ecosystem: None,
        trigger: Trigger::Field(ProjectField::BundleIds),
        target: Target::Path(&["~/Library/WebKit/{key}"]),
        kind: EntryKind::WebData,
        tier: EvidenceTier::Exact,
        evidence: "bundle id from project.pbxproj",
        label: "{key}",
        flags: NONE,
    },
    Lookup {
        id: "bundle-id-saved-state",
        ecosystem: None,
        trigger: Trigger::Field(ProjectField::BundleIds),
        target: Target::Path(&["~/Library/Saved Application State/{key}.savedState"]),
        kind: EntryKind::SavedState,
        tier: EvidenceTier::Exact,
        evidence: "bundle id from project.pbxproj",
        label: "{key}",
        flags: NONE,
    },
    // --- editors ------------------------------------------------------
    Lookup {
        id: "jetbrains",
        ecosystem: None,
        trigger: Trigger::Field(ProjectField::Names),
        target: Target::Derive(derive::jetbrains_dirs),
        kind: EntryKind::EditorState,
        tier: EvidenceTier::NameMatch,
        evidence: "JetBrains cache named after {key}",
        label: "{basename}",
        flags: NONE,
    },
    // --- agents (Claude/Codex) -----------------------------------------
    // A `Lookup`, not a `ReverseLink`, but grouped with the other agent
    // rows for locality: it's a fixed, per-project encoded path, not
    // something discovered by scanning `~/.claude`.
    Lookup {
        id: "claude-cli-cache",
        ecosystem: Some("agents"),
        trigger: Trigger::Always,
        target: Target::Derive(derive::claude_cli_cache),
        kind: EntryKind::AgentState,
        tier: EvidenceTier::Exact,
        evidence: "Claude Code CLI cache",
        label: "Claude Code CLI cache",
        flags: NONE,
    },
];

// ---------------------------------------------------------------------
// REVERSE
// ---------------------------------------------------------------------

/// Directories skipped inside `DerivedData` — shared module/SDK caches
/// rather than one project's build output; claimed once by the
/// `derived-data-caches` baseline rows instead.
pub const GLOBAL_DERIVED_DATA_DIRS: &[&str] = &[
    "ModuleCache.noindex",
    "SDKStatCaches.noindex",
    "SymbolCache.noindex",
    "CompilationCache.noindex",
    "SDKExplicitPrecompiledModules",
];

pub const REVERSE: &[ReverseLink] = &[
    ReverseLink {
        id: "derived-data",
        ecosystem: Some("xcode"),
        kind: EntryKind::Xcode,
        tier: EvidenceTier::Exact,
        evidence: "DerivedData WorkspacePath",
        label: "DerivedData {basename}",
        scan: Scan::Dirs {
            roots: &["~/Library/Developer/Xcode/DerivedData"],
            depth: 1,
            skip: GLOBAL_DERIVED_DATA_DIRS,
        },
        extract: Extract::PlistKey {
            file: "info.plist",
            key: "WorkspacePath",
        },
        matcher: Matcher::PathUnderProject,
        claim: ClaimAt::Entry,
        stale: Some("workspace deleted: {path}"),
        fallback: None,
    },
    ReverseLink {
        id: "vscode-workspaces",
        ecosystem: None,
        kind: EntryKind::EditorState,
        tier: EvidenceTier::Exact,
        evidence: "workspace.json",
        label: "VS Code workspace storage",
        scan: Scan::Dirs {
            roots: &["~/Library/Application Support/{Code,Code - Insiders,Cursor,Antigravity,VSCodium}/User/workspaceStorage"],
            depth: 1,
            skip: &[],
        },
        extract: Extract::JsonUri {
            file: "workspace.json",
            keys: &["folder", "workspace"],
        },
        matcher: Matcher::PathUnderProject,
        claim: ClaimAt::Entry,
        stale: None,
        fallback: None,
    },
    ReverseLink {
        id: "claude-sessions",
        ecosystem: Some("agents"),
        kind: EntryKind::AgentState,
        tier: EvidenceTier::Exact,
        evidence: "Claude Code session cwd",
        label: "Claude Code sessions",
        scan: Scan::Dirs {
            roots: &["~/.claude/projects"],
            depth: 1,
            skip: &[],
        },
        extract: Extract::JsonlCwd {
            max_files: 5,
            head: 64 * 1024,
        },
        matcher: Matcher::PathUnderProject,
        claim: ClaimAt::Entry,
        stale: Some("session cwd no longer exists: {path}"),
        fallback: Some(Fallback::EncodedProjectDir),
    },
    ReverseLink {
        id: "codex-sessions",
        ecosystem: Some("agents"),
        kind: EntryKind::AgentState,
        tier: EvidenceTier::Exact,
        evidence: "Codex session cwd",
        label: "Codex session",
        scan: Scan::Files {
            roots: &["~/.codex/sessions", "~/.codex/archived_sessions"],
            name: Some("rollout-*.jsonl"),
            cap: 5000,
        },
        extract: Extract::JsonlCwd {
            max_files: 1,
            head: 16 * 1024,
        },
        matcher: Matcher::PathUnderProject,
        claim: ClaimAt::Entry,
        stale: None,
        fallback: None,
    },
    ReverseLink {
        id: "pnpm-store",
        ecosystem: Some("node"),
        kind: EntryKind::PackageCache,
        tier: EvidenceTier::Exact,
        evidence: "pnpm store links this project",
        label: "pnpm store {basename}",
        // The store layout nests the `projects/` symlink farm one level
        // deeper than the version dir itself (`store/<v>/projects` *or*
        // `store/<v>/<v2>/projects`) — both depths are listed as candidate
        // `projects` dirs directly (`depth: 0`: the glob-resolved roots
        // *are* the scanned entries; most won't exist, and `SymlinkTargets`
        // skips those the same way any other missing directory is skipped).
        scan: Scan::Dirs {
            roots: &[
                "~/Library/pnpm/store/*/projects",
                "~/Library/pnpm/store/*/*/projects",
                "~/.local/share/pnpm/store/*/projects",
                "~/.local/share/pnpm/store/*/*/projects",
                "~/.pnpm-store/*/projects",
                "~/.pnpm-store/*/*/projects",
            ],
            depth: 0,
            skip: &[],
        },
        extract: Extract::SymlinkTargets { subdir: "" },
        matcher: Matcher::PathUnderProject,
        // Claim the version dir — the scanned entry's parent, since the
        // entry is the `projects/` dir itself.
        claim: ClaimAt::Parent,
        stale: None,
        fallback: None,
    },
    ReverseLink {
        id: "simulator-containers",
        ecosystem: Some("xcode"),
        kind: EntryKind::Simulator,
        tier: EvidenceTier::Exact,
        evidence: "installed in simulator {device}",
        label: "{bundle_id} on {device}",
        scan: Scan::Dirs {
            roots: &[
                "~/Library/Developer/CoreSimulator/Devices/*/data/Containers/Bundle/Application",
                "~/Library/Developer/CoreSimulator/Devices/*/data/Containers/Data/Application",
            ],
            depth: 1,
            skip: &[],
        },
        extract: Extract::Fn(derive::container_bundle_id),
        matcher: Matcher::BundleId,
        claim: ClaimAt::Entry,
        stale: None,
        fallback: None,
    },
];

// ---------------------------------------------------------------------
// BASELINE
// ---------------------------------------------------------------------

pub const BASELINE: &[Baseline] = &[
    // --- node -----------------------------------------------------------
    Baseline {
        ecosystem: "node",
        path: "~/Library/Caches/pnpm/dlx",
        kind: EntryKind::PackageCache,
        label: Label::Static("pnpm dlx cache"),
        evidence: "pnpm ecosystem resource",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "node",
        path: "~/Library/pnpm/global",
        kind: EntryKind::PackageCache,
        label: Label::Static("pnpm global"),
        evidence: "pnpm ecosystem resource",
        source: Source::Fixed,
        exclude: &[],
    },
    // pnpm's per-registry metadata caches — `Library/Caches/pnpm/metadata*`
    // and `.../v*` — aren't fixed names, hence the glob.
    Baseline {
        ecosystem: "node",
        path: "~/Library/Caches/pnpm/metadata*",
        kind: EntryKind::PackageCache,
        label: Label::Basename,
        evidence: "pnpm ecosystem resource",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "node",
        path: "~/Library/Caches/pnpm/v*",
        kind: EntryKind::PackageCache,
        label: Label::Basename,
        evidence: "pnpm ecosystem resource",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "node",
        path: "~/.npm/_cacache/index-v5",
        kind: EntryKind::PackageCache,
        label: Label::Static("npm cache index"),
        evidence: "node ecosystem resource",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "node",
        path: "~/.npm/_logs",
        kind: EntryKind::Logs,
        label: Label::Static("npm logs"),
        evidence: "node ecosystem resource",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "node",
        path: "~/.bun/install/cache",
        kind: EntryKind::PackageCache,
        label: Label::Static("bun cache"),
        evidence: "node ecosystem resource",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "node",
        path: "", // the finding's own path, not this field
        kind: EntryKind::Toolchain,
        label: Label::Static("node (Homebrew default)"),
        evidence: "Homebrew default node",
        source: Source::FromFinding {
            scanner: ScannerId::Brew,
            kind: FindingKind::BrewFormula,
            name: "node",
        },
        exclude: &[],
    },
    // --- rust -------------------------------------------------------
    Baseline {
        ecosystem: "rust",
        path: "~/.rustup/toolchains/{value}",
        kind: EntryKind::Toolchain,
        label: Label::Basename,
        evidence: "default rustup toolchain",
        source: Source::FromFile {
            file: "~/.rustup/settings.toml",
            parse: parsers::default_toolchain,
        },
        exclude: &[],
    },
    Baseline {
        ecosystem: "rust",
        path: "~/.rustup/downloads",
        kind: EntryKind::Toolchain,
        label: Label::Static("rustup downloads"),
        evidence: "rust ecosystem resource",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "rust",
        path: "~/.rustup/tmp",
        kind: EntryKind::Toolchain,
        label: Label::Static("rustup tmp"),
        evidence: "rust ecosystem resource",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "rust",
        path: "~/.cargo/registry/index",
        kind: EntryKind::PackageCache,
        label: Label::Static("cargo registry index"),
        evidence: "rust ecosystem resource",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "rust",
        path: "~/.cargo/bin",
        kind: EntryKind::PackageCache,
        label: Label::Static("cargo bin"),
        evidence: "rust ecosystem resource",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "rust",
        path: "~/.cargo/git/db",
        kind: EntryKind::PackageCache,
        label: Label::Static("cargo git db"),
        evidence: "rust ecosystem resource",
        source: Source::Fixed,
        exclude: &[],
    },
    // --- go -----------------------------------------------------------
    Baseline {
        ecosystem: "go",
        path: "~/Library/Caches/go-build",
        kind: EntryKind::Cache,
        label: Label::Static("go-build"),
        evidence: "Go build cache",
        source: Source::Fixed,
        exclude: &[],
    },
    // --- python -------------------------------------------------------
    Baseline {
        ecosystem: "python",
        path: "~/Library/Caches/pip",
        kind: EntryKind::Cache,
        label: Label::Static("pip cache"),
        evidence: "python ecosystem cache",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "python",
        path: "~/.cache/pip",
        kind: EntryKind::Cache,
        label: Label::Static("pip cache"),
        evidence: "python ecosystem cache",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "python",
        path: "~/Library/Application Support/virtualenv",
        kind: EntryKind::Cache,
        label: Label::Static("virtualenv support"),
        evidence: "python ecosystem cache",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "python",
        path: "~/.local/pipx",
        kind: EntryKind::Cache,
        label: Label::Static("pipx"),
        evidence: "python ecosystem cache",
        source: Source::Fixed,
        exclude: &[],
    },
    // --- swift ----------------------------------------------------------
    Baseline {
        ecosystem: "swift",
        path: "~/Library/Caches/org.swift.swiftpm/manifests",
        kind: EntryKind::PackageCache,
        label: Label::Static("SwiftPM manifests"),
        evidence: "SwiftPM manifest cache",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "swift",
        path: "~/Library/org.swift.swiftpm",
        kind: EntryKind::PackageCache,
        label: Label::Static("SwiftPM"),
        evidence: "SwiftPM shared state",
        source: Source::Fixed,
        exclude: &[],
    },
    // --- xcode ------------------------------------------------------
    Baseline {
        ecosystem: "xcode",
        path: "~/Library/Developer/Xcode/DerivedData/ModuleCache.noindex",
        kind: EntryKind::Xcode,
        label: Label::Static("ModuleCache.noindex"),
        evidence: "Xcode module/SDK cache",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "xcode",
        path: "~/Library/Developer/Xcode/DerivedData/SDKStatCaches.noindex",
        kind: EntryKind::Xcode,
        label: Label::Static("SDKStatCaches.noindex"),
        evidence: "Xcode module/SDK cache",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "xcode",
        path: "~/Library/Developer/Xcode/DerivedData/SymbolCache.noindex",
        kind: EntryKind::Xcode,
        label: Label::Static("SymbolCache.noindex"),
        evidence: "Xcode module/SDK cache",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "xcode",
        path: "~/Library/Developer/Xcode/DerivedData/CompilationCache.noindex",
        kind: EntryKind::Xcode,
        label: Label::Static("CompilationCache.noindex"),
        evidence: "Xcode module/SDK cache",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "xcode",
        path: "~/Library/Developer/Xcode/DerivedData/SDKExplicitPrecompiledModules",
        kind: EntryKind::Xcode,
        label: Label::Static("SDKExplicitPrecompiledModules"),
        evidence: "Xcode module/SDK cache",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "xcode",
        path: "~/Library/Developer/Xcode/UserData",
        kind: EntryKind::Xcode,
        label: Label::Static("Xcode UserData"),
        evidence: "ecosystem default",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "xcode",
        path: "~/Library/Developer/CoreSimulator/Caches",
        kind: EntryKind::Simulator,
        label: Label::Static("Simulator caches"),
        evidence: "ecosystem default",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "xcode",
        path: "~/Library/Developer/XCPGDevices",
        kind: EntryKind::Simulator,
        label: Label::Static("XCPG devices"),
        evidence: "ecosystem default",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "xcode",
        path: "~/Library/Developer/CoreSimulator/Images",
        kind: EntryKind::Simulator,
        label: Label::Static("Simulator images"),
        evidence: "ecosystem default",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "xcode",
        path: "/Library/Developer/CoreSimulator/Volumes",
        kind: EntryKind::Simulator,
        label: Label::Static("Simulator runtimes"),
        evidence: "ecosystem default",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "xcode",
        path: "~/Library/Developer/Xcode/*DeviceSupport",
        kind: EntryKind::Xcode,
        label: Label::Basename,
        evidence: "Xcode device support",
        source: Source::Fixed,
        exclude: &[],
    },
    // --- simulator ----------------------------------------------------
    Baseline {
        ecosystem: "xcode",
        path: "~/Library/Developer/CoreSimulator/Devices/*",
        kind: EntryKind::Simulator,
        label: Label::Fn(derive::simulator_device_label),
        evidence: "simulator device",
        source: Source::Fixed,
        exclude: &[],
    },
    // --- agents -------------------------------------------------------
    Baseline {
        ecosystem: "agents",
        path: "~/.claude/*",
        kind: EntryKind::AgentState,
        label: Label::Fn(derive::claude_state_label),
        evidence: "Claude Code state",
        source: Source::Fixed,
        exclude: &["projects"],
    },
    Baseline {
        ecosystem: "agents",
        path: "~/.codex/*.sqlite*",
        kind: EntryKind::AgentState,
        label: Label::Basename,
        evidence: "Codex state",
        source: Source::Fixed,
        exclude: &[],
    },
    Baseline {
        ecosystem: "agents",
        path: "~/.codex/logs*",
        kind: EntryKind::AgentState,
        label: Label::Basename,
        evidence: "Codex state",
        source: Source::Fixed,
        exclude: &[],
    },
    // --- docker -------------------------------------------------------
    Baseline {
        ecosystem: "docker",
        path: "~/Library/Containers/com.docker.docker",
        kind: EntryKind::Docker,
        label: Label::Static("Docker Desktop VM disk (allocated)"),
        evidence: "Docker Desktop VM disk",
        source: Source::Fixed,
        exclude: &[],
    },
];

pub(super) mod derive {
    include!("derive.rs");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn lookup_row_ids_are_unique_and_nonempty() {
        let mut seen = HashSet::new();
        for row in LOOKUP {
            assert!(!row.id.is_empty(), "row has an empty id");
            assert!(seen.insert(row.id), "duplicate LOOKUP row id: {}", row.id);
        }
    }

    #[test]
    fn reverse_link_row_ids_are_unique_and_nonempty() {
        let mut seen = HashSet::new();
        for row in REVERSE {
            assert!(!row.id.is_empty(), "row has an empty id");
            assert!(seen.insert(row.id), "duplicate REVERSE row id: {}", row.id);
        }
    }
}
