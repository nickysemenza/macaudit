//! Core domain types — the universal currency every scanner produces and every
//! sink consumes. These are **frozen contracts**: parallel implementation lanes
//! depend on them, so changes here ripple everywhere. Append-only during fan-out.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// Stable identity for a Finding across runs — a hash of (kind tag, canonical
/// key). The same artifact/app/daemon must produce the same id every scan,
/// INCLUDING across macaudit rebuilds with different Rust toolchains — which
/// is why this uses a pinned FNV-1a implementation rather than
/// `DefaultHasher` (whose algorithm is deliberately unspecified between
/// releases). Changing this function changes every finding's identity across
/// runs — do not do so without a deliberate migration decision.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct FindingId(pub u64);

/// FNV-1a 64-bit, fixed constants — stable forever by construction.
fn fnv1a_64(chunks: &[&[u8]]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for chunk in chunks {
        for &b in *chunk {
            h ^= b as u64;
            h = h.wrapping_mul(PRIME);
        }
        // Separator byte so ("ab","c") never collides with ("a","bc").
        h ^= 0xff;
        h = h.wrapping_mul(PRIME);
    }
    h
}

impl FindingId {
    /// Build a stable id from a kind and a canonical key (path or name).
    pub fn new(kind: FindingKind, key: &str) -> Self {
        FindingId(fnv1a_64(&[kind.tag().as_bytes(), key.as_bytes()]))
    }
}

impl std::fmt::Display for FindingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Which scanner a finding belongs to. Also the sidebar section key. The
/// canonical list lives in `registry::REGISTRY`; `ALL` must stay in sync (a
/// P0 test enforces this).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ScannerId {
    System,
    Apps,
    Brew,
    Tools,
    Fs,
    /// One row per discovered project (git repo root or manifest-only dir) —
    /// exclusive/shared/reach across everything the project touches.
    Projects,
    /// One row per `.app`/Homebrew formula/global tool owner — the iOS
    /// "Settings › Storage" view for the Mac.
    AppStorage,
    Launchd,
    ShellEnv,
    Runtimes,
    Docker,
    Ports,
    Git,
    Simulator,
    /// USB-connected iPhones/iPads (libimobiledevice).
    Ios,
    SshKeys,
    TimeMachine,
}

impl ScannerId {
    /// Every variant, in display order. Keep in sync with the enum.
    pub const ALL: &'static [ScannerId] = &[
        ScannerId::System,
        ScannerId::Apps,
        ScannerId::Brew,
        ScannerId::Tools,
        ScannerId::Fs,
        ScannerId::Projects,
        ScannerId::AppStorage,
        ScannerId::Launchd,
        ScannerId::ShellEnv,
        ScannerId::Runtimes,
        ScannerId::Docker,
        ScannerId::Ports,
        ScannerId::Git,
        ScannerId::Simulator,
        ScannerId::Ios,
        ScannerId::SshKeys,
        ScannerId::TimeMachine,
    ];

    /// Lowercase slug used for `--section` parsing and serde.
    pub fn slug(self) -> &'static str {
        match self {
            ScannerId::System => "system",
            ScannerId::Apps => "apps",
            ScannerId::Brew => "brew",
            ScannerId::Tools => "tools",
            ScannerId::Fs => "fs",
            ScannerId::Projects => "projects",
            ScannerId::AppStorage => "app_storage",
            ScannerId::Launchd => "launchd",
            ScannerId::ShellEnv => "shell_env",
            ScannerId::Runtimes => "runtimes",
            ScannerId::Docker => "docker",
            ScannerId::Ports => "ports",
            ScannerId::Git => "git",
            ScannerId::Simulator => "simulator",
            ScannerId::Ios => "ios",
            ScannerId::SshKeys => "ssh_keys",
            ScannerId::TimeMachine => "time_machine",
        }
    }

    /// Parse a slug (accepts a few friendly aliases) for the CLI `--section`.
    pub fn parse_slug(s: &str) -> Option<ScannerId> {
        let s = s.trim().to_ascii_lowercase();
        Some(match s.as_str() {
            "system" | "health" | "resource_health" => ScannerId::System,
            "apps" | "app" => ScannerId::Apps,
            "brew" | "homebrew" => ScannerId::Brew,
            "tools" | "global_tools" | "globals" | "dev_tools" => ScannerId::Tools,
            "fs" | "disk" => ScannerId::Fs,
            "projects" | "project" => ScannerId::Projects,
            "app_storage" | "apps_storage" | "footprint" | "footprints" => ScannerId::AppStorage,
            "launchd" | "daemons" => ScannerId::Launchd,
            "shell_env" | "shell" | "shellenv" | "env" => ScannerId::ShellEnv,
            "runtimes" | "runtime" => ScannerId::Runtimes,
            "docker" => ScannerId::Docker,
            "ports" | "port" => ScannerId::Ports,
            "git" => ScannerId::Git,
            "simulator" | "sim" | "simulators" => ScannerId::Simulator,
            "ios" | "idevice" | "iphone" | "ipad" => ScannerId::Ios,
            "ssh_keys" | "ssh" | "keys" => ScannerId::SshKeys,
            "time_machine" | "tm" | "snapshots" | "tmutil" => ScannerId::TimeMachine,
            _ => return None,
        })
    }
}

/// What sort of thing a finding describes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Point-in-time host metric such as CPU load or memory pressure.
    SystemMetric,
    /// A process consuming CPU or resident memory at scan time.
    ProcessResource,
    /// A bounded, durable disk-allocation category (for example `~/dev`).
    DiskCategory,
    App,
    /// One discovered project row (Projects axis).
    Project,
    /// One owner row (App Storage axis): app bundle, formula, Homebrew
    /// itself, or global tool.
    AppOwner,
    /// A synthetic Baseline/Unattributed/Coverage row for the Projects axis.
    ProjectBucket,
    /// A synthetic Baseline/Unattributed/Coverage row for the App Storage
    /// axis.
    AppStorageBucket,
    BrewFormula,
    BrewCask,
    /// One installation of a globally installed developer tool (npm/pnpm/
    /// cargo/pipx/uv/pip/bun), keyed by manager + installation root + name.
    GlobalTool,
    /// Which executable a command name resolves to in the user's login shell
    /// versus MacAudit's own process, with every candidate on `$PATH`.
    CommandResolution,
    /// Coverage/completeness report for the Global Tools scan (one finding).
    ToolCoverage,
    BuildArtifact,
    CacheDir,
    LaunchdItem,
    PathEntry,
    RuntimeVersion,
    DockerObject,
    PortListener,
    GitRepo,
    Simulator,
    /// A USB-connected iOS device: capacity, free, purgeable, app totals.
    IosDevice,
    /// One app installed on a connected iOS device, with bundle and data size.
    IosApp,
    SshKey,
    IosBackup,
    /// A Time Machine local (APFS) snapshot on the boot volume.
    LocalSnapshot,
    /// A single loose file over the configured size threshold.
    LargeFile,
    /// One configured Time Machine backup destination and its health.
    TmDestination,
    /// A path Time Machine skips (System Settings list, sticky attribute, or
    /// macOS default), sized so the saving is visible.
    TmExclusion,
    /// A regenerable or cloud-synced directory that is still being backed up.
    TmExclusionCandidate,
    /// The measured, exclusion-aware estimate of the whole backup set (one).
    TmBackupEstimate,
    /// A leftover `/Volumes/Backups of …` directory that is not a mount point.
    TmStaleMount,
    /// Purgeable space on the boot volume — the upper bound held by local
    /// snapshots (one).
    TmPurgeable,
}

impl FindingKind {
    /// The scanner that produces this kind of finding. Every kind maps to
    /// exactly one section — used to bucket a `Finding` back into its sidebar
    /// section (a `Finding` carries its kind, not its originating
    /// `ScannerId`).
    pub fn scanner(self) -> ScannerId {
        match self {
            FindingKind::SystemMetric | FindingKind::ProcessResource => ScannerId::System,
            FindingKind::DiskCategory => ScannerId::Fs,
            FindingKind::App => ScannerId::Apps,
            FindingKind::Project | FindingKind::ProjectBucket => ScannerId::Projects,
            FindingKind::AppOwner | FindingKind::AppStorageBucket => ScannerId::AppStorage,
            FindingKind::BrewFormula | FindingKind::BrewCask => ScannerId::Brew,
            FindingKind::GlobalTool
            | FindingKind::CommandResolution
            | FindingKind::ToolCoverage => ScannerId::Tools,
            FindingKind::BuildArtifact
            | FindingKind::CacheDir
            | FindingKind::IosBackup
            | FindingKind::LargeFile => ScannerId::Fs,
            FindingKind::LaunchdItem => ScannerId::Launchd,
            FindingKind::PathEntry => ScannerId::ShellEnv,
            FindingKind::RuntimeVersion => ScannerId::Runtimes,
            FindingKind::DockerObject => ScannerId::Docker,
            FindingKind::PortListener => ScannerId::Ports,
            FindingKind::GitRepo => ScannerId::Git,
            FindingKind::Simulator => ScannerId::Simulator,
            FindingKind::IosDevice | FindingKind::IosApp => ScannerId::Ios,
            FindingKind::SshKey => ScannerId::SshKeys,
            FindingKind::LocalSnapshot
            | FindingKind::TmDestination
            | FindingKind::TmExclusion
            | FindingKind::TmExclusionCandidate
            | FindingKind::TmBackupEstimate
            | FindingKind::TmStaleMount
            | FindingKind::TmPurgeable => ScannerId::TimeMachine,
        }
    }

    /// Every kind, for tag lookups and exhaustive tests.
    pub const ALL: &'static [FindingKind] = &[
        FindingKind::SystemMetric,
        FindingKind::ProcessResource,
        FindingKind::DiskCategory,
        FindingKind::App,
        FindingKind::Project,
        FindingKind::AppOwner,
        FindingKind::ProjectBucket,
        FindingKind::AppStorageBucket,
        FindingKind::BrewFormula,
        FindingKind::BrewCask,
        FindingKind::GlobalTool,
        FindingKind::CommandResolution,
        FindingKind::ToolCoverage,
        FindingKind::BuildArtifact,
        FindingKind::CacheDir,
        FindingKind::LaunchdItem,
        FindingKind::PathEntry,
        FindingKind::RuntimeVersion,
        FindingKind::DockerObject,
        FindingKind::PortListener,
        FindingKind::GitRepo,
        FindingKind::Simulator,
        FindingKind::IosDevice,
        FindingKind::IosApp,
        FindingKind::SshKey,
        FindingKind::IosBackup,
        FindingKind::LocalSnapshot,
        FindingKind::LargeFile,
        FindingKind::TmDestination,
        FindingKind::TmExclusion,
        FindingKind::TmExclusionCandidate,
        FindingKind::TmBackupEstimate,
        FindingKind::TmStaleMount,
        FindingKind::TmPurgeable,
    ];

    /// Inverse of `tag()` — parses a persisted `kind` string back to its enum.
    pub fn from_tag(tag: &str) -> Option<FindingKind> {
        FindingKind::ALL.iter().copied().find(|k| k.tag() == tag)
    }

    /// A stable string tag for id hashing (independent of enum layout).
    pub fn tag(self) -> &'static str {
        match self {
            FindingKind::SystemMetric => "system_metric",
            FindingKind::ProcessResource => "process_resource",
            FindingKind::DiskCategory => "disk_category",
            FindingKind::App => "app",
            FindingKind::Project => "project",
            FindingKind::AppOwner => "app_owner",
            FindingKind::ProjectBucket => "project_bucket",
            FindingKind::AppStorageBucket => "app_storage_bucket",
            FindingKind::BrewFormula => "brew_formula",
            FindingKind::BrewCask => "brew_cask",
            FindingKind::GlobalTool => "global_tool",
            FindingKind::CommandResolution => "command_resolution",
            FindingKind::ToolCoverage => "tool_coverage",
            FindingKind::BuildArtifact => "build_artifact",
            FindingKind::CacheDir => "cache_dir",
            FindingKind::LaunchdItem => "launchd_item",
            FindingKind::PathEntry => "path_entry",
            FindingKind::RuntimeVersion => "runtime_version",
            FindingKind::DockerObject => "docker_object",
            FindingKind::PortListener => "port_listener",
            FindingKind::GitRepo => "git_repo",
            FindingKind::Simulator => "simulator",
            FindingKind::IosDevice => "ios_device",
            FindingKind::IosApp => "ios_app",
            FindingKind::SshKey => "ssh_key",
            FindingKind::IosBackup => "ios_backup",
            FindingKind::LocalSnapshot => "local_snapshot",
            FindingKind::LargeFile => "large_file",
            FindingKind::TmDestination => "tm_destination",
            FindingKind::TmExclusion => "tm_exclusion",
            FindingKind::TmExclusionCandidate => "tm_exclusion_candidate",
            FindingKind::TmBackupEstimate => "tm_backup_estimate",
            FindingKind::TmStaleMount => "tm_stale_mount",
            FindingKind::TmPurgeable => "tm_purgeable",
        }
    }
}

/// Severity, ordered from least to most attention-demanding. `Reclaimable`
/// means "safe to delete, will free space"; `Warning` means "look at this".
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum Severity {
    #[default]
    Info,
    Attention,
    Reclaimable,
    Warning,
}

/// One executable action a user can take against a finding. The command is
/// always derived from the scan — never free-form input.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Remedy {
    pub label: String,
    pub command: RemedyCommand,
    pub reclaims_bytes: Option<u64>,
    pub destructive: bool,
    /// An alternative to the finding's primary remedy (a launcher-only
    /// removal, a health probe). Never auto-selected for batch execution; the
    /// user picks it explicitly in the detail pane.
    #[serde(default)]
    pub alternative: bool,
    /// What must still be true at execution time for this remedy to be safe.
    /// Evaluated by the cleanup preflight; `None` means "no ownership
    /// guard" (the pre-existing Disk/launchd remedies).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<Guard>,
}

impl Remedy {
    /// A primary remedy with no guard. Builder methods add the rest.
    pub fn new(label: impl Into<String>, command: RemedyCommand) -> Self {
        Remedy {
            label: label.into(),
            command,
            reclaims_bytes: None,
            destructive: false,
            alternative: false,
            guard: None,
        }
    }

    pub fn destructive(mut self) -> Self {
        self.destructive = true;
        self
    }

    pub fn alternative(mut self) -> Self {
        self.alternative = true;
        self
    }

    pub fn reclaims(mut self, bytes: Option<u64>) -> Self {
        self.reclaims_bytes = bytes;
        self
    }

    pub fn guard(mut self, guard: Guard) -> Self {
        self.guard = Some(guard);
        self
    }
}

/// Ownership/identity facts a destructive remedy depends on. The cleanup
/// preflight re-checks them against a fresh scan right before execution and
/// refuses the action when they no longer hold, so a stale selection can never
/// remove something other than what the user reviewed.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Guard {
    /// A Homebrew formula: still installed at this version, and (when
    /// required) nothing outside the batch still depends on it.
    BrewFormula {
        full_name: String,
        expected_version: Option<String>,
        require_no_retained_dependents: bool,
    },
    /// A Homebrew cask: still installed at this version.
    BrewCask {
        token: String,
        expected_version: Option<String>,
    },
    /// A manager-owned installation: still present at the same root/version,
    /// and the manager program used to remove it still exists.
    ToolInstall {
        manager: String,
        identity_key: String,
        root: PathBuf,
        expected_version: Option<String>,
        program_must_exist: Option<PathBuf>,
    },
    /// A launcher (symlink/shim) owned by one installation: still points where
    /// it did when scanned (or is still dangling, when that is the reason it
    /// is being removed).
    Launcher {
        path: PathBuf,
        expected_target: Option<PathBuf>,
        expect_dangling: bool,
        owner_key: String,
    },
    /// A pip-installed package in a specific site-packages: still present,
    /// still `INSTALLER: pip`, not Homebrew-owned, interpreter still exists.
    PipPackage {
        site: PathBuf,
        name: String,
        interpreter: PathBuf,
    },
}

/// The concrete thing a remedy does. Every path/arg comes from the scan itself.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemedyCommand {
    /// Move a path to the Trash (default for deletions; `--rm` swaps for real rm).
    Trash { path: PathBuf },
    /// Run a subprocess, e.g. `brew upgrade x`. Every arg is scan-derived.
    Shell { program: String, args: Vec<String> },
    /// `open -R <path>` — reveal in Finder.
    RevealInFinder { path: PathBuf },
    /// Put text on the clipboard (for things we won't run ourselves, e.g. `kill <pid>`).
    CopyToClipboard { text: String },
    /// A bounded, non-destructive health probe (`<tool> --version`), run only
    /// when the user explicitly asks; killed after `timeout_secs`.
    Probe {
        program: String,
        args: Vec<String>,
        timeout_secs: u64,
    },
}

impl RemedyCommand {
    /// The literal command string shown to the user — the tool must never run
    /// anything the user hasn't seen verbatim.
    pub fn rendered(&self) -> String {
        match self {
            RemedyCommand::Trash { path } => {
                format!("trash {}", shell_quote(&path.display().to_string()))
            }
            RemedyCommand::Shell { program, args } => {
                let mut s = program.clone();
                for a in args {
                    s.push(' ');
                    s.push_str(&shell_quote(a));
                }
                s
            }
            RemedyCommand::RevealInFinder { path } => {
                format!("open -R {}", shell_quote(&path.display().to_string()))
            }
            RemedyCommand::CopyToClipboard { text } => format!("pbcopy <<< {}", shell_quote(text)),
            RemedyCommand::Probe {
                program,
                args,
                timeout_secs,
            } => {
                let mut s = format!("timeout {timeout_secs} {}", shell_quote(program));
                for a in args {
                    s.push(' ');
                    s.push_str(&shell_quote(a));
                }
                s
            }
        }
    }
}

/// The group a finding belongs to: `meta.group` VERBATIM when a scanner sets
/// it (scanners choose display-ready labels — "node_modules" must not become
/// "Node Modules"), else the finding's kind tag prettified.
pub fn group_key(f: &Finding) -> String {
    f.meta
        .get("group")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| group_label(f.kind.tag()))
}

/// Human label for a kind-tag fallback key: underscores → spaces, title-cased.
pub fn group_label(key: &str) -> String {
    key.split('_')
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Minimal shell quoting for *display* (not execution — execution passes argv
/// arrays, never a shell string).
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '~' | '=' | ':' | ',')
        })
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// The universal currency: every scanner produces Findings.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Finding {
    /// Stable across runs — hash of (kind, canonical path/name).
    pub id: FindingId,
    pub kind: FindingKind,
    /// Short human title, e.g. "node_modules — cubby/app".
    pub title: String,
    /// Human-readable elaboration.
    pub detail: String,
    pub path: Option<PathBuf>,
    /// On-disk bytes (blocks*512), not apparent len. `None` while sizing is pending.
    pub size_bytes: Option<u64>,
    /// Staleness signal: project mtime, git date, or atime.
    #[serde(default)]
    pub last_used: Option<SystemTime>,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub remedies: Vec<Remedy>,
    /// How this value was collected (command or bounded local walk).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
    /// Scope/completeness note for estimates, especially bounded disk sizing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<String>,
    /// Scanner-specific extras (version, arch, cask name, …).
    #[serde(default)]
    pub meta: serde_json::Value,
}

impl Finding {
    /// Construct a finding with a stable id derived from `kind` + `key`.
    pub fn new(kind: FindingKind, key: &str, title: impl Into<String>) -> Self {
        Finding {
            id: FindingId::new(kind, key),
            kind,
            title: title.into(),
            detail: String::new(),
            path: None,
            size_bytes: None,
            last_used: None,
            severity: Severity::Info,
            remedies: Vec::new(),
            provenance: None,
            coverage: None,
            meta: serde_json::Value::Null,
        }
    }

    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = d.into();
        self
    }
    pub fn path(mut self, p: impl Into<PathBuf>) -> Self {
        self.path = Some(p.into());
        self
    }
    pub fn size(mut self, bytes: u64) -> Self {
        self.size_bytes = Some(bytes);
        self
    }
    pub fn severity(mut self, s: Severity) -> Self {
        self.severity = s;
        self
    }
    pub fn remedy(mut self, r: Remedy) -> Self {
        self.remedies.push(r);
        self
    }
    pub fn last_used(mut self, t: SystemTime) -> Self {
        self.last_used = Some(t);
        self
    }
    pub fn meta(mut self, m: serde_json::Value) -> Self {
        self.meta = m;
        self
    }
    pub fn provenance(mut self, value: impl Into<String>) -> Self {
        self.provenance = Some(value.into());
        self
    }
    pub fn coverage(mut self, value: impl Into<String>) -> Self {
        self.coverage = Some(value.into());
        self
    }

    /// A `meta` field as a string, or `None` when absent or not a string.
    pub fn meta_str(&self, key: &str) -> Option<&str> {
        self.meta.get(key).and_then(|v| v.as_str())
    }

    /// A `meta` field as an unsigned integer, or `None` when absent or not
    /// representable as one.
    pub fn meta_u64(&self, key: &str) -> Option<u64> {
        self.meta.get(key).and_then(|v| v.as_u64())
    }

    /// A `meta` array field's string elements, dropping any non-string
    /// entries — empty (not `None`) when the key is absent, since callers
    /// treat "no array" and "empty array" the same way.
    pub fn meta_strs(&self, key: &str) -> Vec<String> {
        self.meta
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Events streamed from scanners to the UI / headless collector over an mpsc
/// channel. Lifecycle events (`Started`/`Finished`/`Failed`) are emitted by the
/// engine wrapper, not by scanners; scanners send only `Progress`/`Finding`.
#[derive(Clone, Debug)]
pub enum ScanEvent {
    Started {
        scanner: ScannerId,
        gen: u64,
    },
    Progress {
        scanner: ScannerId,
        gen: u64,
        msg: String,
        done: u64,
        total: Option<u64>,
    },
    Finding {
        scanner: ScannerId,
        gen: u64,
        finding: Box<Finding>,
    },
    Finished {
        scanner: ScannerId,
        gen: u64,
        duration: Duration,
    },
    Failed {
        scanner: ScannerId,
        gen: u64,
        error: String,
    },
    /// The directory tree of one walked root, for drill-down views. Emitted
    /// by the Disk section once per root after its walk completes.
    DirTree {
        scanner: ScannerId,
        gen: u64,
        tree: Arc<crate::scan::walk::DirTree>,
    },
    /// One attribution axis's whole scan output, emitted once by
    /// `ProjectsScanner`/`AppStorageScanner` after their per-owner findings.
    Footprints {
        scanner: ScannerId,
        gen: u64,
        set: Arc<crate::attribution::model::FootprintSet>,
    },
}

impl ScanEvent {
    pub fn scanner(&self) -> ScannerId {
        match self {
            ScanEvent::Started { scanner, .. }
            | ScanEvent::Progress { scanner, .. }
            | ScanEvent::Finding { scanner, .. }
            | ScanEvent::Finished { scanner, .. }
            | ScanEvent::Failed { scanner, .. }
            | ScanEvent::DirTree { scanner, .. }
            | ScanEvent::Footprints { scanner, .. } => *scanner,
        }
    }

    pub fn generation(&self) -> u64 {
        match self {
            ScanEvent::Started { gen, .. }
            | ScanEvent::Progress { gen, .. }
            | ScanEvent::Finding { gen, .. }
            | ScanEvent::Finished { gen, .. }
            | ScanEvent::Failed { gen, .. }
            | ScanEvent::DirTree { gen, .. }
            | ScanEvent::Footprints { gen, .. } => *gen,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_round_trips_through_its_tag() {
        for k in FindingKind::ALL {
            assert_eq!(FindingKind::from_tag(k.tag()), Some(*k));
        }
        assert_eq!(FindingKind::from_tag("nope"), None);
    }

    #[test]
    fn group_label_title_cases_underscored_key() {
        assert_eq!(group_label("brew_formula"), "Brew Formula");
    }

    #[test]
    fn finding_id_is_stable_across_construction() {
        let a = FindingId::new(FindingKind::BuildArtifact, "/Users/x/proj/node_modules");
        let b = FindingId::new(FindingKind::BuildArtifact, "/Users/x/proj/node_modules");
        assert_eq!(a, b);
    }

    /// Golden value: the id algorithm defines a finding's identity across
    /// runs. If this test fails, every finding's id has changed — do not
    /// "fix" the assertion without a deliberate migration decision.
    #[test]
    fn finding_id_algorithm_is_pinned() {
        assert_eq!(
            FindingId::new(FindingKind::App, "/Applications/Foo.app").0,
            0xf0197d6fd8a33708
        );
    }

    #[test]
    fn finding_id_differs_by_kind_and_key() {
        let a = FindingId::new(FindingKind::BuildArtifact, "/p");
        let b = FindingId::new(FindingKind::CacheDir, "/p");
        let c = FindingId::new(FindingKind::BuildArtifact, "/q");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn scanner_id_all_matches_slug_roundtrip() {
        for id in ScannerId::ALL {
            assert_eq!(ScannerId::parse_slug(id.slug()), Some(*id));
        }
    }

    #[test]
    fn finding_serde_roundtrip() {
        let f = Finding::new(FindingKind::App, "/Applications/Foo.app", "Foo")
            .detail("an app")
            .path("/Applications/Foo.app")
            .size(1234)
            .severity(Severity::Attention)
            .remedy(Remedy {
                label: "Reveal in Finder".into(),
                command: RemedyCommand::RevealInFinder {
                    path: "/Applications/Foo.app".into(),
                },
                reclaims_bytes: None,
                destructive: false,
                alternative: false,
                guard: None,
            });
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn old_finding_json_without_optional_fields_loads() {
        let f = Finding::new(FindingKind::App, "/Applications/Foo.app", "Foo");
        let mut json = serde_json::to_value(f).unwrap();
        let object = json.as_object_mut().unwrap();
        object.remove("provenance");
        object.remove("coverage");
        let restored: Finding = serde_json::from_value(json).unwrap();
        assert!(restored.provenance.is_none());
        assert!(restored.coverage.is_none());
    }

    #[test]
    fn old_remedy_json_without_guard_or_alternative_loads() {
        // JSON persisted before the cleanup work carries remedies with only
        // the four original fields; they must keep deserialising as primary,
        // unguarded remedies.
        let json = serde_json::json!({
            "label": "Move to Trash",
            "command": { "type": "trash", "path": "/tmp/x" },
            "reclaims_bytes": 12,
            "destructive": true
        });
        let r: Remedy = serde_json::from_value(json).unwrap();
        assert!(!r.alternative);
        assert!(r.guard.is_none());
        // And a guard round-trips with its tag.
        let g = Remedy::new(
            "Uninstall",
            RemedyCommand::Shell {
                program: "pipx".into(),
                args: vec!["uninstall".into(), "x".into()],
            },
        )
        .destructive()
        .guard(Guard::ToolInstall {
            manager: "pipx".into(),
            identity_key: "pipx:/v:x".into(),
            root: PathBuf::from("/v"),
            expected_version: Some("1.0".into()),
            program_must_exist: None,
        });
        let v = serde_json::to_value(&g).unwrap();
        assert_eq!(v["guard"]["kind"], "tool_install");
        let back: Remedy = serde_json::from_value(v).unwrap();
        assert_eq!(back, g);
    }

    #[test]
    fn probe_renders_with_timeout_prefix() {
        let c = RemedyCommand::Probe {
            program: "/usr/local/bin/eslint".into(),
            args: vec!["--version".into()],
            timeout_secs: 5,
        };
        assert_eq!(c.rendered(), "timeout 5 /usr/local/bin/eslint --version");
        assert_eq!(serde_json::to_value(&c).unwrap()["type"], "probe");
    }

    #[test]
    fn remedy_command_serde_tagged() {
        let c = RemedyCommand::Shell {
            program: "brew".into(),
            args: vec!["upgrade".into(), "ripgrep".into()],
        };
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["type"], "shell");
        assert_eq!(json["program"], "brew");
    }

    #[test]
    fn rendered_command_quotes_spaces() {
        let c = RemedyCommand::Trash {
            path: "/Users/x/My Stuff/target".into(),
        };
        assert_eq!(c.rendered(), "trash '/Users/x/My Stuff/target'");
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Reclaimable < Severity::Warning);
    }

    #[test]
    fn meta_accessors_read_typed_fields_and_default_on_absence() {
        let f = Finding::new(FindingKind::App, "/x", "x").meta(serde_json::json!({
            "name": "ripgrep",
            "size_bytes": 42u64,
            "tags": ["a", "b", 3],
        }));
        assert_eq!(f.meta_str("name"), Some("ripgrep"));
        assert_eq!(f.meta_str("missing"), None);
        assert_eq!(f.meta_u64("size_bytes"), Some(42));
        assert_eq!(f.meta_u64("name"), None);
        assert_eq!(f.meta_strs("tags"), vec!["a".to_string(), "b".to_string()]);
        assert_eq!(f.meta_strs("missing"), Vec::<String>::new());
    }
}
