//! Shared vocabulary for the Global Tools scan. Every struct here serialises
//! straight into `Finding.meta`, so field names are the JSON contract the
//! presenter, the CLI and snapshots read. Unknown facts are `None` (JSON
//! `null`), never a default value.

use std::path::PathBuf;

use serde::Serialize;
use serde_json::Value;

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Manager {
    Npm,
    Pnpm,
    Cargo,
    Pipx,
    Uv,
    Pip,
    Bun,
}

impl Manager {
    pub const ALL: &'static [Manager] = &[
        Manager::Npm,
        Manager::Pnpm,
        Manager::Cargo,
        Manager::Pipx,
        Manager::Uv,
        Manager::Pip,
        Manager::Bun,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            Manager::Npm => "npm",
            Manager::Pnpm => "pnpm",
            Manager::Cargo => "cargo",
            Manager::Pipx => "pipx",
            Manager::Uv => "uv",
            Manager::Pip => "pip",
            Manager::Bun => "bun",
        }
    }
}

/// The interpreter/runtime an installation needs to run.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct RuntimeRef {
    pub kind: &'static str,
    pub path: Option<PathBuf>,
    pub version: Option<String>,
    /// `None` when no path is known to check.
    pub exists: Option<bool>,
    pub source: String,
}

/// A command the package declares it exports.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct DeclaredCommand {
    pub name: String,
    pub declared_target: Option<String>,
}

/// Who owns a launcher or a PATH candidate.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Ownership {
    ThisInstall,
    OtherTool {
        manager: String,
        identity_key: String,
    },
    HomebrewCask {
        token: String,
    },
    HomebrewFormula {
        name: String,
    },
    RustupProxy,
    /// A pnpm-managed shim in the pnpm home that is not tied to a package
    /// (pnpm itself, node, npm, npx).
    PnpmHome,
    Unknown,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherKind {
    Symlink,
    ShShim,
    RegularBinary,
    Script,
}

/// Something on disk that starts a tool: a symlink, a shim script, or the
/// binary itself.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Launcher {
    pub path: PathBuf,
    pub kind: LauncherKind,
    /// Declared target (symlink value or shim's referenced file), resolved
    /// to an absolute path when possible.
    pub target: Option<PathBuf>,
    /// `None` when there is no target to check (a regular binary).
    pub target_exists: Option<bool>,
    pub owner: Ownership,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Evidence {
    pub kind: &'static str,
    pub source: String,
    pub summary: String,
    pub confidence: Confidence,
}

#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub struct Completeness {
    pub level: &'static str,
    pub missing: Vec<String>,
}

impl Completeness {
    pub fn full() -> Self {
        Completeness {
            level: "full",
            missing: Vec::new(),
        }
    }

    pub fn partial(missing: impl Into<String>) -> Self {
        Completeness {
            level: "partial",
            missing: vec![missing.into()],
        }
    }

    pub fn add(&mut self, missing: impl Into<String>) {
        self.level = "partial";
        self.missing.push(missing.into());
    }
}

/// Evidence-backed classification. Precedence when several apply:
/// broken > required > orphan > duplicate/shadowed > project alternative >
/// review. Never derived from age, absence of history, or "global".
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Classification {
    Broken { reason: String },
    Duplicate { peers: Vec<String> },
    Shadowed { by: PathBuf, owner: Ownership },
    ProjectAlternative { projects: Vec<String> },
    Required { by: Vec<String> },
    Orphan { confirmed_by: String },
    Review { reason: String },
}

impl Classification {
    pub fn slug(&self) -> &'static str {
        match self {
            Classification::Broken { .. } => "broken",
            Classification::Duplicate { .. } => "duplicate",
            Classification::Shadowed { .. } => "shadowed",
            Classification::ProjectAlternative { .. } => "project_alternative",
            Classification::Required { .. } => "required",
            Classification::Orphan { .. } => "orphan",
            Classification::Review { .. } => "review",
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            Classification::Broken { .. } => 0,
            Classification::Required { .. } => 1,
            Classification::Orphan { .. } => 2,
            Classification::Duplicate { .. } => 3,
            Classification::Shadowed { .. } => 4,
            Classification::ProjectAlternative { .. } => 5,
            Classification::Review { .. } => 6,
        }
    }
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathStatus {
    /// The user's login shell runs this installation's copy.
    Active,
    /// Only this process resolves it (login-shell PATH unavailable).
    ActiveInProcessOnly,
    /// Another copy wins command resolution in the login shell.
    Shadowed,
    NotOnPath,
    Unknown,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Candidate {
    pub path: PathBuf,
    pub target: Option<PathBuf>,
    pub owner: Ownership,
}

/// How one command name resolves for one installation.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Resolution {
    pub user_shell: Option<PathBuf>,
    pub process: Option<PathBuf>,
    pub status: PathStatus,
    pub shadowed_by: Option<PathBuf>,
    pub candidates: Vec<Candidate>,
}

/// The exact removal plan for an installation.
#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub struct Removal {
    /// Manager-native uninstall (`program`, `args`).
    pub native: Option<NativeCommand>,
    /// Launchers owned by this installation that can be trashed on their own.
    pub launcher_only: Vec<PathBuf>,
    pub refusals: Vec<String>,
    pub follow_up: Vec<String>,
    /// A command MacAudit will not run itself (interpreter only inferred);
    /// offered as copy-to-clipboard.
    pub suggested_command: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct NativeCommand {
    pub program: String,
    pub args: Vec<String>,
    /// The program must exist at this path for the remedy to be offered.
    #[serde(skip)]
    pub program_path: Option<PathBuf>,
}

/// One installation of one package by one manager at one root.
#[derive(Serialize, Clone, Debug)]
pub struct ToolInstall {
    pub manager: Manager,
    pub layout: Option<String>,
    pub name: String,
    pub version: Option<String>,
    /// Identity root — stable across reinstalls (for pnpm's hashed layout the
    /// symlink path, not the timestamped real dir).
    pub root: PathBuf,
    pub root_realpath: Option<PathBuf>,
    pub install_dir: Option<PathBuf>,
    pub runtime: Option<RuntimeRef>,
    pub commands: Vec<DeclaredCommand>,
    pub launchers: Vec<Launcher>,
    /// Launchers for this tool's command names that belong to someone else.
    pub foreign_launchers: Vec<Launcher>,
    pub evidence: Vec<Evidence>,
    pub completeness: Completeness,
    /// `Some(reason)` ⇒ never offer a destructive remedy.
    pub protected: Option<String>,
    pub size_bytes: Option<u64>,
    pub removal: Removal,
    pub manager_extra: Value,
}

impl ToolInstall {
    pub fn new(manager: Manager, root: PathBuf, name: impl Into<String>) -> Self {
        ToolInstall {
            manager,
            layout: None,
            name: name.into(),
            version: None,
            root,
            root_realpath: None,
            install_dir: None,
            runtime: None,
            commands: Vec::new(),
            launchers: Vec::new(),
            foreign_launchers: Vec::new(),
            evidence: Vec::new(),
            completeness: Completeness::full(),
            protected: None,
            size_bytes: None,
            removal: Removal::default(),
            manager_extra: Value::Object(Default::default()),
        }
    }

    /// `{manager}:{root}:{name}` — the finding key. Never embeds a version.
    pub fn identity_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.manager.slug(),
            self.root.display(),
            self.name
        )
    }

    pub fn evidence(
        &mut self,
        kind: &'static str,
        source: impl Into<String>,
        summary: impl Into<String>,
        confidence: Confidence,
    ) {
        self.evidence.push(Evidence {
            kind,
            source: source.into(),
            summary: summary.into(),
            confidence,
        });
    }

    pub fn command_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.commands.iter().map(|c| c.name.clone()).collect();
        for l in &self.launchers {
            if let Some(n) = l.path.file_name().and_then(|n| n.to_str()) {
                names.push(n.to_string());
            }
        }
        names.sort();
        names.dedup();
        names
    }
}

/// Outcome of one manager probe.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ManagerStatus {
    Ok { detail: Option<String> },
    Absent,
    Partial { missing: Vec<String> },
    Failed { error: String },
}

#[derive(Default)]
pub struct ProbeResult {
    pub installs: Vec<ToolInstall>,
    pub status: Option<ManagerStatus>,
}

impl ProbeResult {
    pub fn absent() -> Self {
        ProbeResult {
            installs: Vec::new(),
            status: Some(ManagerStatus::Absent),
        }
    }
}
