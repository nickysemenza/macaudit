//! FFI mirrors of the engine's types and the conversions between them.
//!
//! Every record here is a value copied across the boundary; nothing in Swift
//! holds a reference into engine memory. `Finding.meta` is the one field that
//! crosses as JSON text — it is scanner-specific `serde_json::Value` and has
//! no fixed shape to mirror. Paths cross as strings (UniFFI has no path type).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use macaudit::brewgraph::RemovalPreview;
use macaudit::cleanup::{self, PreflightReport};
use macaudit::config::DeleteMode as CoreDeleteMode;
use macaudit::model::{self, FindingId, ScannerId};
use macaudit::registry::{self, ViewKind as CoreViewKind};
use macaudit::remedy::PlannedAction;
use macaudit::snapshot;

/// One sidebar section; mirrors `ScannerId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum SectionId {
    System,
    Apps,
    Brew,
    Tools,
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

impl From<ScannerId> for SectionId {
    fn from(id: ScannerId) -> Self {
        match id {
            ScannerId::System => SectionId::System,
            ScannerId::Apps => SectionId::Apps,
            ScannerId::Brew => SectionId::Brew,
            ScannerId::Tools => SectionId::Tools,
            ScannerId::Fs => SectionId::Fs,
            ScannerId::Launchd => SectionId::Launchd,
            ScannerId::ShellEnv => SectionId::ShellEnv,
            ScannerId::Runtimes => SectionId::Runtimes,
            ScannerId::Docker => SectionId::Docker,
            ScannerId::Ports => SectionId::Ports,
            ScannerId::Git => SectionId::Git,
            ScannerId::Simulator => SectionId::Simulator,
            ScannerId::SshKeys => SectionId::SshKeys,
            ScannerId::TmSnapshots => SectionId::TmSnapshots,
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
            SectionId::Launchd => ScannerId::Launchd,
            SectionId::ShellEnv => ScannerId::ShellEnv,
            SectionId::Runtimes => ScannerId::Runtimes,
            SectionId::Docker => ScannerId::Docker,
            SectionId::Ports => ScannerId::Ports,
            SectionId::Git => ScannerId::Git,
            SectionId::Simulator => ScannerId::Simulator,
            SectionId::SshKeys => ScannerId::SshKeys,
            SectionId::TmSnapshots => ScannerId::TmSnapshots,
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
    SshKey,
    IosBackup,
    LocalSnapshot,
    LargeFile,
}

impl From<model::FindingKind> for FindingKind {
    fn from(k: model::FindingKind) -> Self {
        use model::FindingKind as K;
        match k {
            K::SystemMetric => FindingKind::SystemMetric,
            K::ProcessResource => FindingKind::ProcessResource,
            K::DiskCategory => FindingKind::DiskCategory,
            K::App => FindingKind::App,
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
            K::SshKey => FindingKind::SshKey,
            K::IosBackup => FindingKind::IosBackup,
            K::LocalSnapshot => FindingKind::LocalSnapshot,
            K::LargeFile => FindingKind::LargeFile,
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
    pub ephemeral: bool,
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
            ephemeral: f.snapshot_policy == model::SnapshotPolicy::Ephemeral,
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
    /// A full scan completed and was persisted (or not — see `message`).
    SnapshotSaved {
        id: Option<i64>,
        message: String,
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
        /// Sections the engine is rescanning now that the batch has run.
        rescanning: Vec<SectionId>,
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

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SnapshotMeta {
    pub id: i64,
    pub created_at: SystemTime,
    pub machine: String,
    pub finding_count: u64,
    pub total_bytes: u64,
}

impl From<&snapshot::SnapshotMeta> for SnapshotMeta {
    fn from(m: &snapshot::SnapshotMeta) -> Self {
        SnapshotMeta {
            id: m.id,
            created_at: UNIX_EPOCH + Duration::from_secs(m.created_at.max(0) as u64),
            machine: m.machine.clone(),
            finding_count: m.finding_count.max(0) as u64,
            total_bytes: m.total_bytes.max(0) as u64,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GrownFinding {
    pub finding: Finding,
    pub old_bytes: u64,
    pub new_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FindingChange {
    pub finding: Finding,
    pub field: String,
    pub old: String,
    pub new: String,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SnapshotDiff {
    pub added: Vec<Finding>,
    pub removed: Vec<Finding>,
    pub grown: Vec<GrownFinding>,
    pub changed: Vec<FindingChange>,
}

impl From<snapshot::SnapshotDiff> for SnapshotDiff {
    fn from(d: snapshot::SnapshotDiff) -> Self {
        SnapshotDiff {
            added: findings(d.added),
            removed: findings(d.removed),
            grown: d
                .grown
                .iter()
                .map(|(f, old, new)| GrownFinding {
                    finding: f.into(),
                    old_bytes: *old,
                    new_bytes: *new,
                })
                .collect(),
            changed: d
                .changed
                .iter()
                .map(|c| FindingChange {
                    finding: (&c.finding).into(),
                    field: c.field.clone(),
                    old: c.old.clone(),
                    new: c.new.clone(),
                })
                .collect(),
        }
    }
}

/// Per-section counts from the latest saved snapshot, for Δ badges.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SectionBaseline {
    pub section: SectionId,
    pub finding_count: u64,
    pub reclaimable_bytes: u64,
}

pub fn finding_id(id: u64) -> FindingId {
    FindingId(id)
}

fn path_string(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use macaudit::fake;

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
}
