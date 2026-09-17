//! FFI mirrors of the engine's types and the conversions between them.
//!
//! Every record here is a value copied across the boundary; nothing in Swift
//! holds a reference into engine memory. `Finding.meta` is the one field that
//! crosses as JSON text — it is scanner-specific `serde_json::Value` and has
//! no fixed shape to mirror. Paths cross as strings (UniFFI has no path type).

use std::path::Path;
use std::time::SystemTime;

use macaudit::attribution::model as attrib;
use macaudit::brewgraph::RemovalPreview;
use macaudit::cleanup::{self, PreflightReport};
use macaudit::config::DeleteMode as CoreDeleteMode;
use macaudit::model::{self, FindingId, ScannerId};
use macaudit::registry::{self, ViewKind as CoreViewKind};
use macaudit::remedy::PlannedAction;
use macaudit::scan::walk::{BigFile, DirNodeSummary};

/// One sidebar section; mirrors `ScannerId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum SectionId {
    System,
    Apps,
    Brew,
    Tools,
    Fs,
    Projects,
    AppStorage,
    Launchd,
    ShellEnv,
    Runtimes,
    Docker,
    Ports,
    Git,
    Simulator,
    Ios,
    SshKeys,
    TimeMachine,
}

impl From<ScannerId> for SectionId {
    fn from(id: ScannerId) -> Self {
        match id {
            ScannerId::System => SectionId::System,
            ScannerId::Apps => SectionId::Apps,
            ScannerId::Brew => SectionId::Brew,
            ScannerId::Tools => SectionId::Tools,
            ScannerId::Fs => SectionId::Fs,
            ScannerId::Projects => SectionId::Projects,
            ScannerId::AppStorage => SectionId::AppStorage,
            ScannerId::Launchd => SectionId::Launchd,
            ScannerId::ShellEnv => SectionId::ShellEnv,
            ScannerId::Runtimes => SectionId::Runtimes,
            ScannerId::Docker => SectionId::Docker,
            ScannerId::Ports => SectionId::Ports,
            ScannerId::Git => SectionId::Git,
            ScannerId::Simulator => SectionId::Simulator,
            ScannerId::Ios => SectionId::Ios,
            ScannerId::SshKeys => SectionId::SshKeys,
            ScannerId::TimeMachine => SectionId::TimeMachine,
        }
    }
}

impl From<SectionId> for ScannerId {
    fn from(id: SectionId) -> Self {
        match id {
            SectionId::System => ScannerId::System,
            SectionId::Apps => ScannerId::Apps,
            SectionId::Brew => ScannerId::Brew,
            SectionId::Tools => ScannerId::Tools,
            SectionId::Fs => ScannerId::Fs,
            SectionId::Projects => ScannerId::Projects,
            SectionId::AppStorage => ScannerId::AppStorage,
            SectionId::Launchd => ScannerId::Launchd,
            SectionId::ShellEnv => ScannerId::ShellEnv,
            SectionId::Runtimes => ScannerId::Runtimes,
            SectionId::Docker => ScannerId::Docker,
            SectionId::Ports => ScannerId::Ports,
            SectionId::Git => ScannerId::Git,
            SectionId::Simulator => ScannerId::Simulator,
            SectionId::Ios => ScannerId::Ios,
            SectionId::SshKeys => ScannerId::SshKeys,
            SectionId::TimeMachine => ScannerId::TimeMachine,
        }
    }
}

/// How a section's findings are primarily presented.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ViewKind {
    Overview,
    Tree,
    Table,
}

impl From<CoreViewKind> for ViewKind {
    fn from(v: CoreViewKind) -> Self {
        match v {
            CoreViewKind::Overview => ViewKind::Overview,
            CoreViewKind::Tree => ViewKind::Tree,
            CoreViewKind::Table => ViewKind::Table,
        }
    }
}

/// Static metadata for one section, from `registry::REGISTRY` (sidebar order).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SectionMeta {
    pub id: SectionId,
    pub slug: String,
    pub title: String,
    pub short_title: String,
    pub view: ViewKind,
}

pub fn sections() -> Vec<SectionMeta> {
    registry::REGISTRY
        .iter()
        .map(|m| SectionMeta {
            id: m.id.into(),
            slug: m.id.slug().to_string(),
            title: m.title.to_string(),
            short_title: m.short_title.to_string(),
            view: m.view.into(),
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Severity {
    Info,
    Attention,
    Reclaimable,
    Warning,
}

impl From<model::Severity> for Severity {
    fn from(s: model::Severity) -> Self {
        match s {
            model::Severity::Info => Severity::Info,
            model::Severity::Attention => Severity::Attention,
            model::Severity::Reclaimable => Severity::Reclaimable,
            model::Severity::Warning => Severity::Warning,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FindingKind {
    SystemMetric,
    ProcessResource,
    DiskCategory,
    App,
    Project,
    AppOwner,
    ProjectBucket,
    AppStorageBucket,
    BrewFormula,
    BrewCask,
    GlobalTool,
    CommandResolution,
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
    IosDevice,
    IosApp,
    SshKey,
    IosBackup,
    LocalSnapshot,
    LargeFile,
    TmDestination,
    TmExclusion,
    TmExclusionCandidate,
    TmBackupEstimate,
    TmStaleMount,
    TmPurgeable,
}

impl From<model::FindingKind> for FindingKind {
    fn from(k: model::FindingKind) -> Self {
        use model::FindingKind as K;
        match k {
            K::SystemMetric => FindingKind::SystemMetric,
            K::ProcessResource => FindingKind::ProcessResource,
            K::DiskCategory => FindingKind::DiskCategory,
            K::App => FindingKind::App,
            K::Project => FindingKind::Project,
            K::AppOwner => FindingKind::AppOwner,
            K::ProjectBucket => FindingKind::ProjectBucket,
            K::AppStorageBucket => FindingKind::AppStorageBucket,
            K::BrewFormula => FindingKind::BrewFormula,
            K::BrewCask => FindingKind::BrewCask,
            K::GlobalTool => FindingKind::GlobalTool,
            K::CommandResolution => FindingKind::CommandResolution,
            K::ToolCoverage => FindingKind::ToolCoverage,
            K::BuildArtifact => FindingKind::BuildArtifact,
            K::CacheDir => FindingKind::CacheDir,
            K::LaunchdItem => FindingKind::LaunchdItem,
            K::PathEntry => FindingKind::PathEntry,
            K::RuntimeVersion => FindingKind::RuntimeVersion,
            K::DockerObject => FindingKind::DockerObject,
            K::PortListener => FindingKind::PortListener,
            K::GitRepo => FindingKind::GitRepo,
            K::Simulator => FindingKind::Simulator,
            K::IosDevice => FindingKind::IosDevice,
            K::IosApp => FindingKind::IosApp,
            K::SshKey => FindingKind::SshKey,
            K::IosBackup => FindingKind::IosBackup,
            K::LocalSnapshot => FindingKind::LocalSnapshot,
            K::LargeFile => FindingKind::LargeFile,
            K::TmDestination => FindingKind::TmDestination,
            K::TmExclusion => FindingKind::TmExclusion,
            K::TmExclusionCandidate => FindingKind::TmExclusionCandidate,
            K::TmBackupEstimate => FindingKind::TmBackupEstimate,
            K::TmStaleMount => FindingKind::TmStaleMount,
            K::TmPurgeable => FindingKind::TmPurgeable,
        }
    }
}

/// The concrete thing a remedy does. Every path/arg comes from the scan.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RemedyCommand {
    Trash {
        path: String,
    },
    Shell {
        program: String,
        args: Vec<String>,
    },
    RevealInFinder {
        path: String,
    },
    CopyToClipboard {
        text: String,
    },
    Probe {
        program: String,
        args: Vec<String>,
        timeout_secs: u64,
    },
}

impl From<&model::RemedyCommand> for RemedyCommand {
    fn from(c: &model::RemedyCommand) -> Self {
        use model::RemedyCommand as C;
        match c {
            C::Trash { path } => RemedyCommand::Trash {
                path: path_string(path),
            },
            C::Shell { program, args } => RemedyCommand::Shell {
                program: program.clone(),
                args: args.clone(),
            },
            C::RevealInFinder { path } => RemedyCommand::RevealInFinder {
                path: path_string(path),
            },
            C::CopyToClipboard { text } => RemedyCommand::CopyToClipboard { text: text.clone() },
            C::Probe {
                program,
                args,
                timeout_secs,
            } => RemedyCommand::Probe {
                program: program.clone(),
                args: args.clone(),
                timeout_secs: *timeout_secs,
            },
        }
    }
}

/// One action a user can take against a finding. `rendered` is the literal
/// command string the user must see before it runs.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Remedy {
    pub label: String,
    pub command: RemedyCommand,
    pub rendered: String,
    pub reclaims_bytes: Option<u64>,
    pub destructive: bool,
    pub alternative: bool,
    pub has_guard: bool,
}

impl From<&model::Remedy> for Remedy {
    fn from(r: &model::Remedy) -> Self {
        Remedy {
            label: r.label.clone(),
            command: (&r.command).into(),
            rendered: r.command.rendered(),
            reclaims_bytes: r.reclaims_bytes,
            destructive: r.destructive,
            alternative: r.alternative,
            has_guard: r.guard.is_some(),
        }
    }
}

/// A scan result. `id` is the engine's stable `FindingId` — the handle Swift
/// sends back to mark, plan and execute. `group` is the tree bucket
/// (`model::group_key`), `section` the sidebar section the kind belongs to.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Finding {
    pub id: u64,
    pub kind: FindingKind,
    pub section: SectionId,
    pub group: String,
    pub title: String,
    pub detail: String,
    pub path: Option<String>,
    pub size_bytes: Option<u64>,
    pub last_used: Option<SystemTime>,
    pub severity: Severity,
    pub remedies: Vec<Remedy>,
    pub provenance: Option<String>,
    pub coverage: Option<String>,
    /// Scanner-specific extras as a JSON document (`{}` when absent).
    pub meta_json: String,
}

impl From<&model::Finding> for Finding {
    fn from(f: &model::Finding) -> Self {
        Finding {
            id: f.id.0,
            kind: f.kind.into(),
            section: f.kind.scanner().into(),
            group: model::group_key(f),
            title: f.title.clone(),
            detail: f.detail.clone(),
            path: f.path.as_deref().map(path_string),
            size_bytes: f.size_bytes,
            last_used: f.last_used,
            severity: f.severity.into(),
            remedies: f.remedies.iter().map(Remedy::from).collect(),
            provenance: f.provenance.clone(),
            coverage: f.coverage.clone(),
            meta_json: if f.meta.is_null() {
                "{}".to_string()
            } else {
                f.meta.to_string()
            },
        }
    }
}

pub fn findings(iter: impl IntoIterator<Item = model::Finding>) -> Vec<Finding> {
    iter.into_iter().map(|f| Finding::from(&f)).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DeleteMode {
    Trash,
    Rm,
}

impl From<CoreDeleteMode> for DeleteMode {
    fn from(m: CoreDeleteMode) -> Self {
        match m {
            CoreDeleteMode::Trash => DeleteMode::Trash,
            CoreDeleteMode::Rm => DeleteMode::Rm,
        }
    }
}

/// Streaming scan progress. Findings arrive in batches per section; the
/// session has already applied them, so `findings(section)` always agrees
/// with what the listener has seen. `Correlated`/`Enriched` upsert findings
/// the engine rewrote after the scanners finished (cask ↔ app labelling,
/// network catalog matches).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ScanEvent {
    SectionStarted {
        section: SectionId,
        gen: u64,
    },
    Progress {
        section: SectionId,
        gen: u64,
        msg: String,
        done: u64,
        total: Option<u64>,
    },
    Findings {
        section: SectionId,
        gen: u64,
        findings: Vec<Finding>,
    },
    SectionFinished {
        section: SectionId,
        gen: u64,
        duration_ms: u64,
    },
    SectionFailed {
        section: SectionId,
        gen: u64,
        error: String,
    },
    Correlated {
        gen: u64,
        findings: Vec<Finding>,
    },
    Enriched {
        gen: u64,
        findings: Vec<Finding>,
    },
}

/// What Swift sends back to plan a batch: a finding plus (optionally) which
/// of its remedies. `None` applies the engine's default rule
/// (`remedy::execution_remedies`): all primary destructive remedies, else the
/// first primary shell command, else the first primary remedy.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Selection {
    pub finding_id: u64,
    pub remedy_index: Option<u32>,
}

/// A planned action as shown to the user before and during execution.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PlannedActionView {
    pub finding_id: u64,
    pub label: String,
    pub rendered: String,
    pub destructive: bool,
    pub reclaims_bytes: Option<u64>,
}

impl From<&PlannedAction> for PlannedActionView {
    fn from(a: &PlannedAction) -> Self {
        PlannedActionView {
            finding_id: a.finding_id.0,
            label: a.label.clone(),
            rendered: a.rendered.clone(),
            destructive: a.destructive,
            reclaims_bytes: a.reclaims_bytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RefusedAction {
    pub action: PlannedActionView,
    pub reason: String,
}

impl From<&cleanup::Refused> for RefusedAction {
    fn from(r: &cleanup::Refused) -> Self {
        RefusedAction {
            action: (&r.action).into(),
            reason: r.reason.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BlockedPackage {
    pub name: String,
    pub retained_by: Vec<String>,
}

/// What removing the selected Homebrew packages would do to the dependency
/// graph (`brewgraph::RemovalPreview`).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BrewImpact {
    pub removable: Vec<String>,
    pub blocked: Vec<BlockedPackage>,
    pub newly_orphaned: Vec<String>,
    pub confirmed_orphans: Vec<String>,
    pub uncertain_orphans: Vec<String>,
    pub bytes_selected: Option<u64>,
    pub bytes_with_orphans: Option<u64>,
    pub caveats: Vec<String>,
}

impl From<&RemovalPreview> for BrewImpact {
    fn from(p: &RemovalPreview) -> Self {
        BrewImpact {
            removable: p.removable.clone(),
            blocked: p
                .blocked
                .iter()
                .map(|(name, by)| BlockedPackage {
                    name: name.clone(),
                    retained_by: by.clone(),
                })
                .collect(),
            newly_orphaned: p.newly_orphaned.clone(),
            confirmed_orphans: p.confirmed_orphans.clone(),
            uncertain_orphans: p.uncertain_orphans.clone(),
            bytes_selected: p.bytes_selected,
            bytes_with_orphans: p.bytes_with_orphans,
            caveats: p.caveats.clone(),
        }
    }
}

/// The confirm-dialog model: what the batch will run, what was refused and
/// why, and the human summaries the static preflight produced.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PlanSummary {
    pub actions: Vec<PlannedActionView>,
    pub refused: Vec<RefusedAction>,
    pub removed: Vec<String>,
    pub remaining: Vec<String>,
    pub follow_up: Vec<String>,
    pub impact: Option<BrewImpact>,
    pub delete_mode: DeleteMode,
    /// Sections the batch touches — rescanned once it has run.
    pub affected: Vec<SectionId>,
}

pub fn plan_summary(
    report: &PreflightReport,
    delete_mode: CoreDeleteMode,
    affected: &[ScannerId],
) -> PlanSummary {
    PlanSummary {
        actions: report.ok.iter().map(PlannedActionView::from).collect(),
        refused: report.refused.iter().map(RefusedAction::from).collect(),
        removed: report.removed.clone(),
        remaining: report.remaining.clone(),
        follow_up: report.follow_up.clone(),
        impact: report.brew_preview.as_ref().map(BrewImpact::from),
        delete_mode: delete_mode.into(),
        affected: affected.iter().map(|s| SectionId::from(*s)).collect(),
    }
}

/// Cleanup progress, in order: the refreshed preflight (which may refuse
/// more), one Started/Done pair per action, Executed, Verifying, Finished.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ExecEvent {
    PreflightDone {
        ok: Vec<PlannedActionView>,
        refused: Vec<RefusedAction>,
    },
    ActionStarted {
        index: u32,
    },
    ActionDone {
        index: u32,
        ok: bool,
        message: String,
    },
    Executed {
        cancelled: Vec<PlannedActionView>,
        /// Sections the engine is rescanning now that the batch has run, and
        /// the generation those scans report under (None when nothing was
        /// affected).
        rescanning: Vec<SectionId>,
        rescan_gen: Option<u64>,
    },
    Verifying,
    Finished {
        summary: String,
        report_path: Option<String>,
        /// The full `CleanupReport` as JSON, for the detail/report view.
        report_json: String,
    },
}

impl From<cleanup::ExecEvent> for ExecEvent {
    fn from(ev: cleanup::ExecEvent) -> Self {
        use cleanup::ExecEvent as E;
        match ev {
            E::PreflightDone(report) => ExecEvent::PreflightDone {
                ok: report.ok.iter().map(PlannedActionView::from).collect(),
                refused: report.refused.iter().map(RefusedAction::from).collect(),
            },
            E::ActionStarted(i) => ExecEvent::ActionStarted { index: i as u32 },
            E::ActionDone(i, result) => {
                let (ok, message) = match result {
                    Ok(m) => (true, m),
                    Err(e) => (false, e),
                };
                ExecEvent::ActionDone {
                    index: i as u32,
                    ok,
                    message,
                }
            }
            E::Executed { cancelled } => ExecEvent::Executed {
                cancelled: cancelled.iter().map(PlannedActionView::from).collect(),
                rescanning: Vec::new(),
                rescan_gen: None,
            },
            E::Verifying => ExecEvent::Verifying,
            E::Finished(report) => ExecEvent::Finished {
                summary: report.summary(),
                report_path: report.audit_path.as_deref().map(path_string),
                report_json: serde_json::to_string(&*report).unwrap_or_default(),
            },
        }
    }
}

pub fn finding_id(id: u64) -> FindingId {
    FindingId(id)
}

fn path_string(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// One of a directory's largest own files (absolute path).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TopFile {
    pub path: String,
    pub alloc: u64,
}

impl From<&BigFile> for TopFile {
    fn from(f: &BigFile) -> Self {
        TopFile {
            path: path_string(&f.path),
            alloc: f.alloc,
        }
    }
}

/// One directory in the Disk tree, flat (no nested children) — the UI
/// queries one level at a time via `Engine::dir_children`/`dir_subtree`.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DirEntry {
    pub path: String,
    pub name: String,
    pub alloc: u64,
    pub apparent: u64,
    pub files: u64,
    pub dirs: u64,
    pub errors: u64,
    /// Whether this directory has any subdirectories (`child_count > 0`).
    pub has_children: bool,
}

impl From<&DirNodeSummary> for DirEntry {
    fn from(s: &DirNodeSummary) -> Self {
        DirEntry {
            path: path_string(&s.path),
            name: s.name.clone(),
            alloc: s.alloc,
            apparent: s.apparent,
            files: s.files,
            dirs: s.dirs,
            errors: s.errors,
            has_children: s.child_count > 0,
        }
    }
}

/// Summary counters for one walked root — the Disk section's header/status.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DirTreeStats {
    pub root: String,
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub errors: u64,
    pub complete: bool,
    pub elapsed_ms: u64,
}

// ---- Attribution axes (Projects / App Storage) ----
//
// FFI mirrors of `macaudit::attribution::model`. Everything here is a value
// copy: `Engine::footprint`/`footprint_buckets` build these from a read lock
// over `Shared.footprints`, so nothing here borrows engine memory. Enum
// variant order matches the core enums exactly (`attrib::*`).

/// Which attribution lens a `Footprint`/`FootprintBuckets` belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum Axis {
    Projects,
    AppStorage,
}

impl From<attrib::Axis> for Axis {
    fn from(a: attrib::Axis) -> Self {
        match a {
            attrib::Axis::Projects => Axis::Projects,
            attrib::Axis::AppStorage => Axis::AppStorage,
        }
    }
}

impl From<Axis> for attrib::Axis {
    fn from(a: Axis) -> Self {
        match a {
            Axis::Projects => attrib::Axis::Projects,
            Axis::AppStorage => attrib::Axis::AppStorage,
        }
    }
}

/// What sort of thing owns a `Footprint`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OwnerKind {
    Project,
    App,
    Formula,
    Homebrew,
    Tool,
    Baseline,
    Unattributed,
}

impl From<attrib::OwnerKind> for OwnerKind {
    fn from(k: attrib::OwnerKind) -> Self {
        match k {
            attrib::OwnerKind::Project => OwnerKind::Project,
            attrib::OwnerKind::App => OwnerKind::App,
            attrib::OwnerKind::Formula => OwnerKind::Formula,
            attrib::OwnerKind::Homebrew => OwnerKind::Homebrew,
            attrib::OwnerKind::Tool => OwnerKind::Tool,
            attrib::OwnerKind::Baseline => OwnerKind::Baseline,
            attrib::OwnerKind::Unattributed => OwnerKind::Unattributed,
        }
    }
}

/// What resource an entry represents — the breakdown axis within one owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
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

impl From<attrib::EntryKind> for EntryKind {
    fn from(k: attrib::EntryKind) -> Self {
        match k {
            attrib::EntryKind::WorkingTree => EntryKind::WorkingTree,
            attrib::EntryKind::Artifacts => EntryKind::Artifacts,
            attrib::EntryKind::Worktree => EntryKind::Worktree,
            attrib::EntryKind::PackageCache => EntryKind::PackageCache,
            attrib::EntryKind::Toolchain => EntryKind::Toolchain,
            attrib::EntryKind::Xcode => EntryKind::Xcode,
            attrib::EntryKind::Simulator => EntryKind::Simulator,
            attrib::EntryKind::Docker => EntryKind::Docker,
            attrib::EntryKind::AgentState => EntryKind::AgentState,
            attrib::EntryKind::EditorState => EntryKind::EditorState,
            attrib::EntryKind::ProjectCache => EntryKind::ProjectCache,
            attrib::EntryKind::AppBundle => EntryKind::AppBundle,
            attrib::EntryKind::Container => EntryKind::Container,
            attrib::EntryKind::GroupContainer => EntryKind::GroupContainer,
            attrib::EntryKind::AppSupport => EntryKind::AppSupport,
            attrib::EntryKind::Cache => EntryKind::Cache,
            attrib::EntryKind::Preferences => EntryKind::Preferences,
            attrib::EntryKind::Logs => EntryKind::Logs,
            attrib::EntryKind::WebData => EntryKind::WebData,
            attrib::EntryKind::SavedState => EntryKind::SavedState,
            attrib::EntryKind::DotDir => EntryKind::DotDir,
            attrib::EntryKind::Data => EntryKind::Data,
            attrib::EntryKind::Other => EntryKind::Other,
        }
    }
}

/// How confident a claim linking a path to an owner is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum EvidenceTier {
    Exact,
    NameMatch,
    Observed,
    EcosystemDefault,
    Curated,
}

impl From<attrib::EvidenceTier> for EvidenceTier {
    fn from(t: attrib::EvidenceTier) -> Self {
        match t {
            attrib::EvidenceTier::Exact => EvidenceTier::Exact,
            attrib::EvidenceTier::NameMatch => EvidenceTier::NameMatch,
            attrib::EvidenceTier::Observed => EvidenceTier::Observed,
            attrib::EvidenceTier::EcosystemDefault => EvidenceTier::EcosystemDefault,
            attrib::EvidenceTier::Curated => EvidenceTier::Curated,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ProcKind {
    Shell,
    Server,
    Other,
}

impl From<attrib::ProcKind> for ProcKind {
    fn from(k: attrib::ProcKind) -> Self {
        match k {
            attrib::ProcKind::Shell => ProcKind::Shell,
            attrib::ProcKind::Server => ProcKind::Server,
            attrib::ProcKind::Other => ProcKind::Other,
        }
    }
}

/// One row's identity: `key` is the stable, axis-specific identity a
/// resolver's claims are grouped by.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Owner {
    pub key: String,
    pub kind: OwnerKind,
    pub name: String,
    pub path: Option<String>,
}

impl From<&attrib::Owner> for Owner {
    fn from(o: &attrib::Owner) -> Self {
        Owner {
            key: o.key.clone(),
            kind: o.kind.into(),
            name: o.name.clone(),
            path: o.path.as_deref().map(path_string),
        }
    }
}

/// A live process whose cwd is inside a project.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Proc {
    pub pid: u32,
    pub name: String,
    pub kind: ProcKind,
    pub cwd: String,
}

impl From<&attrib::Proc> for Proc {
    fn from(p: &attrib::Proc) -> Self {
        Proc {
            pid: p.pid,
            name: p.name.clone(),
            kind: p.kind.into(),
            cwd: path_string(&p.cwd),
        }
    }
}

/// One accounted path under an owner (or under Baseline/Unattributed).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FootprintEntry {
    pub path: String,
    pub kind: EntryKind,
    pub bytes: u64,
    pub raw_bytes: u64,
    /// Owner keys touching this path — `len() > 1` means shared.
    pub owners: Vec<String>,
    pub tier: EvidenceTier,
    pub evidence: String,
    pub label: String,
    pub baseline: bool,
    pub clone_of_store: bool,
    pub virtual_bytes: bool,
    /// `unsized` is a reserved word in Rust, hence the raw identifier; the
    /// generated Swift sees the plain field name `unsized`.
    pub r#unsized: bool,
    pub stale: bool,
    pub finding: Option<u64>,
    pub reason: Option<String>,
}

impl From<&attrib::FootprintEntry> for FootprintEntry {
    fn from(e: &attrib::FootprintEntry) -> Self {
        FootprintEntry {
            path: path_string(&e.path),
            kind: e.kind.into(),
            bytes: e.bytes,
            raw_bytes: e.raw_bytes,
            owners: e.owners.clone(),
            tier: e.tier.into(),
            evidence: e.evidence.clone(),
            label: e.label.clone(),
            baseline: e.baseline,
            clone_of_store: e.clone_of_store,
            virtual_bytes: e.virtual_bytes,
            r#unsized: e.r#unsized,
            stale: e.stale,
            finding: e.finding.map(|id| id.0),
            reason: e.reason.clone(),
        }
    }
}

/// One resource-kind bucket within an owner's breakdown.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FootprintGroup {
    pub kind: EntryKind,
    pub bytes: u64,
    pub entries: Vec<FootprintEntry>,
}

impl From<&attrib::FootprintGroup> for FootprintGroup {
    fn from(g: &attrib::FootprintGroup) -> Self {
        FootprintGroup {
            kind: g.kind.into(),
            bytes: g.bytes,
            entries: g.entries.iter().map(FootprintEntry::from).collect(),
        }
    }
}

/// One owner's row: the exclusive/shared/reach/baseline-share numbers plus
/// its breakdown. Fetched on demand via `Engine::footprint(finding_id)`
/// rather than carried in the `Finding` — the entry list can be large.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Footprint {
    pub finding: u64,
    pub owner: Owner,
    pub exclusive: u64,
    pub shared: u64,
    pub reach: u64,
    pub baseline_share: u64,
    pub groups: Vec<FootprintGroup>,
    pub worktrees: Vec<String>,
    pub processes: Vec<Proc>,
    pub ports: Vec<u16>,
    pub clone_note: bool,
}

impl From<&attrib::Footprint> for Footprint {
    fn from(f: &attrib::Footprint) -> Self {
        Footprint {
            finding: f.finding.0,
            owner: Owner::from(&f.owner),
            exclusive: f.exclusive,
            shared: f.shared,
            reach: f.reach,
            baseline_share: f.baseline_share,
            groups: f.groups.iter().map(FootprintGroup::from).collect(),
            worktrees: f.worktrees.iter().map(|p| path_string(p)).collect(),
            processes: f.processes.iter().map(Proc::from).collect(),
            ports: f.ports.clone(),
            clone_note: f.clone_note,
        }
    }
}

/// One axis's coverage: the synthetic Baseline/Unattributed rows and totals.
/// Per-owner footprints are not repeated here — fetch those individually via
/// `Engine::footprint(finding_id)`.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FootprintBuckets {
    pub axis: Axis,
    pub baseline: Vec<FootprintEntry>,
    pub unattributed: Vec<FootprintEntry>,
    pub disk_total: u64,
    pub attributed_total: u64,
    pub missing_deps: Vec<SectionId>,
}

impl From<&attrib::FootprintSet> for FootprintBuckets {
    fn from(set: &attrib::FootprintSet) -> Self {
        FootprintBuckets {
            axis: set.axis.into(),
            baseline: set.baseline.iter().map(FootprintEntry::from).collect(),
            unattributed: set.unattributed.iter().map(FootprintEntry::from).collect(),
            disk_total: set.disk_total,
            attributed_total: set.attributed_total,
            missing_deps: set
                .missing_deps
                .iter()
                .map(|d| SectionId::from(*d))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use macaudit::fake;

    #[test]
    fn axis_round_trips_through_ffi_and_back() {
        for axis in attrib::Axis::ALL {
            let ffi: Axis = (*axis).into();
            let back: attrib::Axis = ffi.into();
            assert_eq!(back, *axis);
        }
    }

    #[test]
    fn entry_kind_maps_every_core_variant() {
        // The `From<attrib::EntryKind> for EntryKind` match has no wildcard
        // arm, so this is really enforced at compile time (a new core
        // variant without a matching FFI arm fails to build); iterating
        // `ALL` here just exercises every arm at runtime too.
        for kind in attrib::EntryKind::ALL {
            let _ffi: EntryKind = (*kind).into();
        }
    }

    #[test]
    fn section_ids_round_trip_over_every_scanner() {
        for id in ScannerId::ALL {
            let ffi: SectionId = (*id).into();
            let back: ScannerId = ffi.into();
            assert_eq!(back, *id);
        }
        let metas = sections();
        assert_eq!(metas.len(), registry::REGISTRY.len());
        for (m, r) in metas.iter().zip(registry::REGISTRY) {
            assert_eq!(m.slug, r.id.slug());
            assert_eq!(m.title, r.title);
        }
    }

    #[test]
    fn finding_maps_field_by_field_and_meta_round_trips() {
        let source = fake::fixtures(ScannerId::Tools)
            .into_iter()
            .find(|f| f.remedies.iter().any(|r| r.guard.is_some()))
            .expect("a Tools fixture with a guarded remedy");
        let ffi = Finding::from(&source);
        assert_eq!(ffi.id, source.id.0);
        assert_eq!(ffi.section, SectionId::Tools);
        assert_eq!(ffi.title, source.title);
        assert_eq!(ffi.detail, source.detail);
        assert_eq!(
            ffi.path,
            source
                .path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
        );
        assert_eq!(ffi.size_bytes, source.size_bytes);
        assert_eq!(ffi.last_used, source.last_used);
        assert_eq!(ffi.group, model::group_key(&source));
        assert_eq!(ffi.remedies.len(), source.remedies.len());
        for (a, b) in ffi.remedies.iter().zip(&source.remedies) {
            assert_eq!(a.label, b.label);
            assert_eq!(a.rendered, b.command.rendered());
            assert_eq!(a.destructive, b.destructive);
            assert_eq!(a.alternative, b.alternative);
            assert_eq!(a.has_guard, b.guard.is_some());
        }
        let meta: serde_json::Value = serde_json::from_str(&ffi.meta_json).unwrap();
        assert_eq!(meta, source.meta);
    }

    #[test]
    fn null_meta_becomes_empty_object() {
        let f = model::Finding::new(model::FindingKind::LargeFile, "/x", "x");
        assert_eq!(Finding::from(&f).meta_json, "{}");
    }

    #[test]
    fn every_remedy_command_variant_maps() {
        use model::RemedyCommand as C;
        let cases = vec![
            C::Trash {
                path: "/a b".into(),
            },
            C::Shell {
                program: "brew".into(),
                args: vec!["uninstall".into(), "x".into()],
            },
            C::RevealInFinder { path: "/r".into() },
            C::CopyToClipboard {
                text: "kill 1".into(),
            },
            C::Probe {
                program: "node".into(),
                args: vec!["--version".into()],
                timeout_secs: 5,
            },
        ];
        for c in cases {
            let ffi = RemedyCommand::from(&c);
            match (&c, &ffi) {
                (C::Trash { path }, RemedyCommand::Trash { path: p }) => {
                    assert_eq!(p, &path.to_string_lossy())
                }
                (
                    C::Shell { program, args },
                    RemedyCommand::Shell {
                        program: p,
                        args: a,
                    },
                ) => {
                    assert_eq!((p, a), (program, args))
                }
                (C::RevealInFinder { path }, RemedyCommand::RevealInFinder { path: p }) => {
                    assert_eq!(p, &path.to_string_lossy())
                }
                (C::CopyToClipboard { text }, RemedyCommand::CopyToClipboard { text: t }) => {
                    assert_eq!(t, text)
                }
                (
                    C::Probe {
                        program,
                        args,
                        timeout_secs,
                    },
                    RemedyCommand::Probe {
                        program: p,
                        args: a,
                        timeout_secs: t,
                    },
                ) => assert_eq!((p, a, t), (program, args, timeout_secs)),
                other => panic!("variant changed shape: {other:?}"),
            }
        }
    }

    #[test]
    fn dir_entry_maps_field_by_field() {
        let summary = DirNodeSummary {
            name: "dev".to_string(),
            path: std::path::PathBuf::from("/Users/dev/dev"),
            alloc: 45 * 1024 * 1024 * 1024,
            apparent: 45 * 1024 * 1024 * 1024,
            files: 16_210,
            dirs: 2_222,
            errors: 3,
            child_count: 4,
            children: Vec::new(),
        };
        let entry = DirEntry::from(&summary);
        assert_eq!(entry.path, "/Users/dev/dev");
        assert_eq!(entry.name, "dev");
        assert_eq!(entry.alloc, summary.alloc);
        assert_eq!(entry.apparent, summary.apparent);
        assert_eq!(entry.files, summary.files);
        assert_eq!(entry.dirs, summary.dirs);
        assert_eq!(entry.errors, summary.errors);
        assert!(entry.has_children);

        let mut leaf = summary;
        leaf.child_count = 0;
        assert!(!DirEntry::from(&leaf).has_children);
    }
}
