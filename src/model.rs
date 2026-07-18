//! Core domain types — the universal currency every scanner produces and every
//! sink consumes. These are **frozen contracts**: parallel implementation lanes
//! depend on them, so changes here ripple everywhere. Append-only during fan-out.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// Stable identity for a Finding across runs — a hash of (kind tag, canonical
/// key). This is what makes snapshot diffing (§8) work: the same
/// artifact/app/daemon must produce the same id every scan, INCLUDING across
/// macaudit rebuilds with different Rust toolchains — which is why this uses a
/// pinned FNV-1a implementation rather than `DefaultHasher` (whose algorithm is
/// deliberately unspecified between releases). Changing this function is a
/// snapshot-format break: every stored finding would diff as removed+added.
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
    Apps,
    Brew,
    Fs,
    Launchd,
    ShellEnv,
    Runtimes,
    Docker,
    Ports,
    Git,
    Simulator,
    SshKeys,
    TmSnapshots,
}

impl ScannerId {
    /// Every variant, in display order. Keep in sync with the enum.
    pub const ALL: &'static [ScannerId] = &[
        ScannerId::Apps,
        ScannerId::Brew,
        ScannerId::Fs,
        ScannerId::Launchd,
        ScannerId::ShellEnv,
        ScannerId::Runtimes,
        ScannerId::Docker,
        ScannerId::Ports,
        ScannerId::Git,
        ScannerId::Simulator,
        ScannerId::SshKeys,
        ScannerId::TmSnapshots,
    ];

    /// Lowercase slug used for `--section` parsing and serde.
    pub fn slug(self) -> &'static str {
        match self {
            ScannerId::Apps => "apps",
            ScannerId::Brew => "brew",
            ScannerId::Fs => "fs",
            ScannerId::Launchd => "launchd",
            ScannerId::ShellEnv => "shell_env",
            ScannerId::Runtimes => "runtimes",
            ScannerId::Docker => "docker",
            ScannerId::Ports => "ports",
            ScannerId::Git => "git",
            ScannerId::Simulator => "simulator",
            ScannerId::SshKeys => "ssh_keys",
            ScannerId::TmSnapshots => "tm_snapshots",
        }
    }

    /// Parse a slug (accepts a few friendly aliases) for the CLI `--section`.
    pub fn parse_slug(s: &str) -> Option<ScannerId> {
        let s = s.trim().to_ascii_lowercase();
        Some(match s.as_str() {
            "apps" | "app" => ScannerId::Apps,
            "brew" | "homebrew" => ScannerId::Brew,
            "fs" | "disk" => ScannerId::Fs,
            "launchd" | "daemons" => ScannerId::Launchd,
            "shell_env" | "shell" | "shellenv" | "env" => ScannerId::ShellEnv,
            "runtimes" | "runtime" => ScannerId::Runtimes,
            "docker" => ScannerId::Docker,
            "ports" | "port" => ScannerId::Ports,
            "git" => ScannerId::Git,
            "simulator" | "sim" | "simulators" => ScannerId::Simulator,
            "ssh_keys" | "ssh" | "keys" => ScannerId::SshKeys,
            "tm_snapshots" | "snapshots" | "tmutil" => ScannerId::TmSnapshots,
            _ => return None,
        })
    }
}

/// What sort of thing a finding describes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    App,
    BrewFormula,
    BrewCask,
    BuildArtifact,
    CacheDir,
    LaunchdItem,
    PathEntry,
    RuntimeVersion,
    DockerObject,
    PortListener,
    GitRepo,
    Simulator,
    SshKey,
    IosBackup,
    LocalSnapshot,
    /// A single loose file over the configured size threshold.
    LargeFile,
}

impl FindingKind {
    /// The scanner that produces this kind of finding. Every kind maps to
    /// exactly one section — used to bucket snapshot findings back into sidebar
    /// sections for Δ badges (a stored `Finding` carries its kind, not its
    /// originating `ScannerId`).
    pub fn scanner(self) -> ScannerId {
        match self {
            FindingKind::App => ScannerId::Apps,
            FindingKind::BrewFormula | FindingKind::BrewCask => ScannerId::Brew,
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
            FindingKind::SshKey => ScannerId::SshKeys,
            FindingKind::LocalSnapshot => ScannerId::TmSnapshots,
        }
    }

    /// A stable string tag for id hashing (independent of enum layout).
    pub fn tag(self) -> &'static str {
        match self {
            FindingKind::App => "app",
            FindingKind::BrewFormula => "brew_formula",
            FindingKind::BrewCask => "brew_cask",
            FindingKind::BuildArtifact => "build_artifact",
            FindingKind::CacheDir => "cache_dir",
            FindingKind::LaunchdItem => "launchd_item",
            FindingKind::PathEntry => "path_entry",
            FindingKind::RuntimeVersion => "runtime_version",
            FindingKind::DockerObject => "docker_object",
            FindingKind::PortListener => "port_listener",
            FindingKind::GitRepo => "git_repo",
            FindingKind::Simulator => "simulator",
            FindingKind::SshKey => "ssh_key",
            FindingKind::IosBackup => "ios_backup",
            FindingKind::LocalSnapshot => "local_snapshot",
            FindingKind::LargeFile => "large_file",
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
        }
    }
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
}

impl ScanEvent {
    pub fn scanner(&self) -> ScannerId {
        match self {
            ScanEvent::Started { scanner, .. }
            | ScanEvent::Progress { scanner, .. }
            | ScanEvent::Finding { scanner, .. }
            | ScanEvent::Finished { scanner, .. }
            | ScanEvent::Failed { scanner, .. } => *scanner,
        }
    }

    pub fn generation(&self) -> u64 {
        match self {
            ScanEvent::Started { gen, .. }
            | ScanEvent::Progress { gen, .. }
            | ScanEvent::Finding { gen, .. }
            | ScanEvent::Finished { gen, .. }
            | ScanEvent::Failed { gen, .. } => *gen,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_id_is_stable_across_construction() {
        let a = FindingId::new(FindingKind::BuildArtifact, "/Users/x/proj/node_modules");
        let b = FindingId::new(FindingKind::BuildArtifact, "/Users/x/proj/node_modules");
        assert_eq!(a, b);
    }

    /// Golden value: the id algorithm is part of the snapshot format. If this
    /// test fails, every stored snapshot will diff as fully removed+added —
    /// do not "fix" the assertion without a deliberate migration decision.
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
            });
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
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
}
