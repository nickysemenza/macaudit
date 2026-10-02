//! Ownership-aware cleanup: preflight, ordered execution, verification and
//! an audit trail, layered on top of `remedy::RemedyEngine` (which still runs
//! each exact command the user saw).
//!
//! Two preflights guard every batch:
//!
//! - `preflight_static` runs the moment the user opens the confirm dialog:
//!   the targets must still be in the current findings, no two actions may
//!   hit one target, and Homebrew packages must not still be needed by
//!   anything outside the batch (computed on the in-memory graph).
//! - `preflight_refresh` runs after the user confirms, right before
//!   anything executes: every `Guard` is re-checked against fresh data (one
//!   `brew info` for all Homebrew targets, a fresh manager probe for tools,
//!   `readlink` for launchers, the dist-info for pip packages). Anything
//!   stale, ambiguous or now-foreign is refused and reported, never run.
//!
//! Execution order is dependents-before-dependencies for Homebrew, then
//! manager-native uninstalls, then launcher-only removals. Broad
//! `brew autoremove` is refused because its targets are dynamic. Cancellation
//! stops *between* actions — an in-flight `brew uninstall` is never killed
//! halfway. Afterwards the
//! inventory is captured again, `brew autoremove --dry-run` is re-run when
//! Homebrew changed, retained tools related to the batch get bounded
//! `--version` probes (run before and after, so a failure that already
//! existed is reported as pre-existing, not as a regression). Reports stay
//! in memory, and existing report files are never touched. Versions are
//! recorded for reinstall guidance; no rollback is claimed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::brewgraph::{parse_autoremove_dry_run, BrewGraph, InfoRoot, RemovalPreview};
use crate::config::{Config, DeleteMode, Paths};
use crate::model::{Finding, FindingId, FindingKind, Guard, RemedyCommand};
use crate::remedy::{ClipboardOps, PlannedAction, RemedyEngine, TrashOps};
use crate::runner::CommandRunner;
use crate::scan::global_tools::{self, launchers, pymeta, shellpath::ShellPath, ProbeCtx};

const BREW_TIMEOUT: Duration = Duration::from_secs(90);
const AUTOREMOVE_REFUSAL: &str = "brew autoremove has dynamic targets that cannot be bound to the confirmed findings; select individual package removals instead";

fn protected_metadata<T>(operation: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let _materialization =
        crate::scan::walk::listing::MaterializationGuard::enter().map_err(|error| {
            format!("cannot protect cleanup metadata from materialization: {error}")
        })?;
    operation()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Refused {
    pub action: PlannedAction,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PreflightReport {
    /// Actions that passed, in execution order.
    pub ok: Vec<PlannedAction>,
    pub refused: Vec<Refused>,
    /// Human summary: what the batch removes.
    pub removed: Vec<String>,
    /// Things explicitly preserved (foreign launchers, retained dependents).
    pub remaining: Vec<String>,
    pub follow_up: Vec<String>,
    #[serde(skip)]
    pub brew_preview: Option<RemovalPreview>,
    #[serde(skip)]
    pub identities: TargetIdentities,
}

#[derive(Clone, Debug, Default)]
pub struct TargetIdentities(BTreeMap<String, Vec<PhysicalTarget>>);

#[derive(Clone, Debug, PartialEq, Eq)]
struct PhysicalTarget {
    path: PathBuf,
    resolved: PathBuf,
    device: u64,
    inode: u64,
    file_type: u32,
    link: Option<PathBuf>,
    created: Option<SystemTime>,
}

impl PhysicalTarget {
    fn capture(path: &Path) -> Result<Self, String> {
        protected_metadata(|| Self::capture_protected(path))
    }

    fn capture_protected(path: &Path) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt;

        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(format!(
                "cleanup target must be an absolute path: {}",
                path.display()
            ));
        }
        let name = path
            .file_name()
            .ok_or_else(|| "refusing filesystem root cleanup".to_string())?;
        let parent = path
            .parent()
            .ok_or_else(|| "cleanup target has no parent".to_string())?;
        let resolved = std::fs::canonicalize(parent)
            .map_err(|error| format!("cannot resolve target parent {}: {error}", parent.display()))?
            .join(name);
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            format!("cannot identify cleanup target {}: {error}", path.display())
        })?;
        #[cfg(target_os = "macos")]
        {
            use std::os::macos::fs::MetadataExt;
            if metadata.st_flags() & 0x4000_0000 != 0 {
                return Err(format!(
                    "dataless cleanup target is unavailable: {}",
                    path.display()
                ));
            }
        }
        let link = if metadata.file_type().is_symlink() {
            Some(std::fs::read_link(path).map_err(|error| error.to_string())?)
        } else {
            None
        };
        Ok(Self {
            path: path.to_path_buf(),
            resolved,
            device: metadata.dev(),
            inode: metadata.ino(),
            file_type: metadata.mode() & 0o170_000_u32,
            link,
            created: metadata.created().ok(),
        })
    }

    fn verify(&self) -> Result<(), String> {
        if Self::capture(&self.path)? != *self {
            return Err(format!(
                "physical cleanup target replaced since confirmation: {}",
                self.path.display()
            ));
        }
        Ok(())
    }

    fn overlaps(&self, other: &Self) -> bool {
        (self.device == other.device && self.inode == other.inode)
            || self.resolved.starts_with(&other.resolved)
            || other.resolved.starts_with(&self.resolved)
    }
}

fn physical_targets(
    action: &PlannedAction,
    finding: &Finding,
) -> Result<Vec<PhysicalTarget>, String> {
    if !action.destructive {
        return Ok(Vec::new());
    }
    let _materialization = crate::scan::walk::listing::MaterializationGuard::enter()
        .map_err(|error| format!("cannot protect cleanup target metadata: {error}"))?;
    let mut paths = BTreeSet::new();
    match &action.command {
        RemedyCommand::Trash { path } => {
            paths.insert(path.clone());
        }
        RemedyCommand::Shell { program, args }
            if Path::new(program)
                .file_name()
                .is_some_and(|name| name == "rm") =>
        {
            for argument in args.iter().filter(|argument| !argument.starts_with('-')) {
                paths.insert(PathBuf::from(argument));
            }
            if paths.is_empty() {
                return Err("permanent deletion has no identifiable target".into());
            }
        }
        _ => {}
    }
    if let Some(path) = &finding.path {
        paths.insert(path.clone());
        if !deletes_path(action) {
            paths.insert(std::fs::canonicalize(path).map_err(|error| {
                format!(
                    "cannot identify cleanup target referent {}: {error}",
                    path.display()
                )
            })?);
        }
    }
    match &action.guard {
        Some(Guard::BrewFormula { .. }) if finding.path.is_none() => {
            return Err("cannot identify the physical Homebrew installation".into());
        }
        Some(Guard::BrewCask { .. }) => {
            paths.extend(
                str_list(&finding.meta, "app_paths")
                    .into_iter()
                    .map(PathBuf::from),
            );
            if let Some(binaries) = finding.meta.get("binaries").and_then(Value::as_array) {
                paths.extend(binaries.iter().filter_map(|binary| {
                    binary
                        .get("target")
                        .and_then(Value::as_str)
                        .map(PathBuf::from)
                }));
            }
            if paths.is_empty() {
                return Err("cannot identify the physical Homebrew cask artifacts".into());
            }
        }
        Some(Guard::ToolInstall { root, .. }) => {
            paths.insert(root.clone());
            paths.insert(std::fs::canonicalize(root).map_err(|error| {
                format!(
                    "cannot identify installation root {}: {error}",
                    root.display()
                )
            })?);
        }
        Some(Guard::Launcher { path, .. }) => {
            paths.insert(path.clone());
        }
        Some(Guard::PipPackage { site, name, .. }) => {
            let expected = pymeta::normalize_name(name);
            let metadata = pymeta::site_dist_infos(site)
                .into_iter()
                .find(|metadata| metadata.normalized == expected)
                .ok_or_else(|| format!("cannot identify package {name} in {}", site.display()))?;
            paths.insert(metadata.dir);
        }
        _ => {}
    }
    paths
        .iter()
        .map(|path| PhysicalTarget::capture(path))
        .collect()
}

fn deletes_path(action: &PlannedAction) -> bool {
    matches!(&action.command, RemedyCommand::Trash { .. })
        || matches!(&action.command, RemedyCommand::Shell { program, .. } if Path::new(program).file_name().is_some_and(|name| name == "rm"))
}

fn action_is_current(action: &PlannedAction, finding: &Finding) -> bool {
    finding.remedies.iter().any(|remedy| {
        [DeleteMode::Trash, DeleteMode::Rm].into_iter().any(|mode| {
            let expected = RemedyEngine::new(mode).plan_one(finding.id, remedy);
            expected == *action
        })
    })
}

fn filter_brew_dependencies(report: &mut PreflightReport, graph: &BrewGraph) {
    loop {
        let selected = report.ok.iter().filter_map(brew_target).collect();
        let preview = graph.removal_preview(&selected);
        let mut changed = false;
        report.ok.retain(|action| {
            let Some(target) = brew_target(action) else {
                return true;
            };
            let key = graph.resolve(&target).unwrap_or(target.clone());
            let reason = if let Some((_, dependents)) =
                preview.blocked.iter().find(|(name, _)| name == &key)
            {
                Some(format!(
                    "blocked: still needed by {}",
                    dependents.join(", ")
                ))
            } else if preview.unknown.contains(&target) {
                Some(format!("ambiguous or unknown package name {target}"))
            } else {
                None
            };
            if let Some(reason) = reason {
                report.refused.push(Refused {
                    action: action.clone(),
                    reason,
                });
                changed = true;
                false
            } else {
                true
            }
        });
        if !changed {
            report.brew_preview = Some(preview);
            return;
        }
    }
}

fn is_brew_autoremove(a: &PlannedAction) -> bool {
    matches!(&a.command, RemedyCommand::Shell { program, args } if program == "brew" && args.first().map(String::as_str) == Some("autoremove"))
}

fn brew_target(a: &PlannedAction) -> Option<String> {
    match &a.guard {
        Some(Guard::BrewFormula { full_name, .. }) => Some(full_name.clone()),
        Some(Guard::BrewCask { token, .. }) => Some(token.clone()),
        _ => None,
    }
}

/// Group key for "if this fails, skip the rest of the same target".
fn owner_key(a: &PlannedAction) -> String {
    match &a.guard {
        Some(Guard::BrewFormula { full_name, .. }) => format!("brew:{full_name}"),
        Some(Guard::BrewCask { token, .. }) => format!("cask:{token}"),
        Some(Guard::ToolInstall { identity_key, .. }) => identity_key.clone(),
        Some(Guard::Launcher { owner_key, .. }) => owner_key.clone(),
        Some(Guard::PipPackage { site, name, .. }) => format!("pip:{}:{name}", site.display()),
        None => format!("finding:{}", a.finding_id),
    }
}

fn phase(a: &PlannedAction) -> u8 {
    if is_brew_autoremove(a) {
        return 4;
    }
    match (&a.guard, &a.command) {
        (Some(Guard::BrewFormula { .. }) | Some(Guard::BrewCask { .. }), _) => 0,
        (Some(Guard::ToolInstall { .. }) | Some(Guard::PipPackage { .. }), _) => 1,
        (Some(Guard::Launcher { .. }), _) => 2,
        (
            None,
            RemedyCommand::CopyToClipboard { .. }
            | RemedyCommand::RevealInFinder { .. }
            | RemedyCommand::Probe { .. },
        ) => 5,
        (None, _) => 3,
    }
}

/// Order: brew (dependents first, per the preview), tools, launchers,
/// other destructive actions, `brew autoremove`, non-destructive extras.
fn order_actions(
    actions: Vec<PlannedAction>,
    preview: Option<&RemovalPreview>,
) -> Vec<PlannedAction> {
    let position = |a: &PlannedAction| -> usize {
        preview
            .and_then(|p| {
                let target = brew_target(a)?;
                p.order
                    .iter()
                    .position(|n| n == &target || n == &format!("cask:{target}"))
            })
            .unwrap_or(usize::MAX)
    };
    let mut v: Vec<(u8, usize, usize, PlannedAction)> = actions
        .into_iter()
        .enumerate()
        .map(|(i, a)| (phase(&a), position(&a), i, a))
        .collect();
    v.sort_by_key(|a| (a.0, a.1, a.2));
    v.into_iter().map(|(_, _, _, a)| a).collect()
}

fn str_list(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    x.as_str()
                        .map(str::to_string)
                        .or_else(|| x.get("path").and_then(|p| p.as_str()).map(str::to_string))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// In-memory preflight against the findings the user is looking at.
pub fn preflight_static(
    actions: &[PlannedAction],
    current: &BTreeMap<FindingId, Finding>,
) -> PreflightReport {
    let mut report = PreflightReport::default();
    let mut ok: Vec<PlannedAction> = Vec::new();
    let mut seen_commands: BTreeSet<String> = BTreeSet::new();
    let mut selected_targets: Vec<(FindingId, bool, PhysicalTarget)> = Vec::new();
    let brew_findings = current
        .values()
        .filter(|f| matches!(f.kind, FindingKind::BrewFormula | FindingKind::BrewCask));
    let graph = BrewGraph::from_findings(brew_findings);
    let selected: BTreeSet<String> = actions.iter().filter_map(brew_target).collect();
    let preview = (!selected.is_empty()).then(|| graph.removal_preview(&selected));

    for a in actions {
        let Some(f) = current.get(&a.finding_id) else {
            report.refused.push(Refused {
                action: a.clone(),
                reason: "target no longer present in the latest scan".into(),
            });
            continue;
        };
        if !seen_commands.insert(a.rendered.clone()) {
            report.refused.push(Refused {
                action: a.clone(),
                reason: "duplicate target in this batch".into(),
            });
            continue;
        }
        if !action_is_current(a, f) {
            report.refused.push(Refused {
                action: a.clone(),
                reason: "remedy changed or is not authorized by the current finding".into(),
            });
            continue;
        }
        if a.destructive && is_brew_autoremove(a) {
            report.refused.push(Refused {
                action: a.clone(),
                reason: AUTOREMOVE_REFUSAL.into(),
            });
            continue;
        }
        let targets = match physical_targets(a, f) {
            Ok(targets) => targets,
            Err(reason) => {
                report.refused.push(Refused {
                    action: a.clone(),
                    reason,
                });
                continue;
            }
        };
        if targets.iter().any(|target| {
            selected_targets
                .iter()
                .any(|(finding_id, deletes, existing)| {
                    (*finding_id != a.finding_id || (*deletes && deletes_path(a)))
                        && target.overlaps(existing)
                })
        }) {
            report.refused.push(Refused {
                action: a.clone(),
                reason: "overlapping physical targets in this batch".into(),
            });
            continue;
        }
        if let Some(target) = brew_target(a) {
            if let Some(p) = &preview {
                let key = graph.resolve(&target).unwrap_or(target.clone());
                if let Some((_, deps)) = p.blocked.iter().find(|(n, _)| n == &key) {
                    report.refused.push(Refused {
                        action: a.clone(),
                        reason: format!("blocked: still needed by {}", deps.join(", ")),
                    });
                    report
                        .remaining
                        .extend(deps.iter().map(|d| format!("{d} (still needs {target})")));
                    continue;
                }
                if p.unknown.contains(&target) {
                    report.refused.push(Refused {
                        action: a.clone(),
                        reason: format!("ambiguous or unknown package name {target}"),
                    });
                    continue;
                }
            }
        }
        report.removed.push(match &a.command {
            RemedyCommand::Trash { path } => format!("{} (launcher {})", f.title, path.display()),
            _ => format!("{} — {}", f.title, a.label),
        });
        // Preserved launchers and manager-specific follow-ups from the finding.
        for l in str_list(&f.meta, "foreign_launchers") {
            report
                .remaining
                .push(format!("{l} (owned by another installation; preserved)"));
        }
        if let Some(removal) = f.meta.get("removal") {
            for fu in str_list(removal, "follow_up") {
                if !report.follow_up.contains(&fu) {
                    report.follow_up.push(fu);
                }
            }
        }
        selected_targets.extend(
            targets
                .iter()
                .cloned()
                .map(|target| (a.finding_id, deletes_path(a), target)),
        );
        report.identities.0.insert(a.rendered.clone(), targets);
        ok.push(a.clone());
    }
    if let Some(p) = &preview {
        if !p.newly_orphaned.is_empty() {
            report.follow_up.push(format!(
                "predicted to become unneeded after removal: {} — review with `brew autoremove --dry-run`",
                p.newly_orphaned.join(", ")
            ));
        }
        if !p.uncertain_orphans.is_empty() {
            report.follow_up.push(format!(
                "origin unknown, may become unneeded: {}",
                p.uncertain_orphans.join(", ")
            ));
        }
        for (pkg, deps) in &p.blocked {
            let _ = (pkg, deps);
        }
    }
    report.ok = order_actions(ok, preview.as_ref());
    report.brew_preview = preview;
    if report.ok.iter().any(|action| brew_target(action).is_some()) {
        filter_brew_dependencies(&mut report, &graph);
    }
    report
}

/// Everything the refreshing preflight needs to run.
pub struct ExecDeps {
    pub runner: Arc<dyn CommandRunner>,
    pub trash: Arc<dyn TrashOps>,
    pub clipboard: Arc<dyn ClipboardOps>,
    pub paths: Arc<Paths>,
    pub config: Arc<Config>,
    pub delete_mode: DeleteMode,
}

async fn fresh_brew_graph(deps: &ExecDeps, token: &CancellationToken) -> Option<BrewGraph> {
    let run = deps
        .runner
        .run("brew", &["info", "--json=v2", "--installed"], token);
    let out = tokio::time::timeout(BREW_TIMEOUT, run).await.ok()?.ok()?;
    if !out.success() {
        return None;
    }
    let info: InfoRoot = serde_json::from_str(&out.stdout_str()).ok()?;
    Some(BrewGraph::from_info(&info, None))
}

fn probe_ctx_for<'a>(paths: &'a Paths, config: &'a Config, shell: &'a ShellPath) -> ProbeCtx<'a> {
    let brew_prefix = config
        .tools
        .homebrew_prefix
        .as_ref()
        .map(|p| paths.expand(p))
        .filter(|p| p.join("Cellar").is_dir() || p.join("lib").is_dir())
        .or_else(crate::scan::brew::brew_prefix);
    ProbeCtx {
        paths,
        config: &config.tools,
        shell,
        brew_prefix,
        extra_npm_prefixes: Vec::new(),
    }
}

/// A point-in-time inventory of every tool installation (filesystem-only),
/// keyed by identity.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Inventory {
    pub items: BTreeMap<String, InventoryItem>,
    pub brew: BTreeMap<String, Option<String>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct InventoryItem {
    pub manager: String,
    pub name: String,
    pub version: Option<String>,
    /// (launcher path, target exists)
    pub launchers: Vec<(PathBuf, Option<bool>)>,
    pub interpreter_ok: Option<bool>,
    pub commands: Vec<String>,
}

pub fn capture_inventory(paths: &Paths, config: &Config, brew: Option<&BrewGraph>) -> Inventory {
    let Ok(_materialization) = crate::scan::walk::listing::MaterializationGuard::enter() else {
        return Inventory::default();
    };
    let shell = ShellPath::default();
    let cx = probe_ctx_for(paths, config, &shell);
    let mut inv = Inventory::default();
    for (_, r) in global_tools::run_probes(&cx) {
        for t in r.installs {
            inv.items.insert(
                t.identity_key(),
                InventoryItem {
                    manager: t.manager.slug().to_string(),
                    name: t.name.clone(),
                    version: t.version.clone(),
                    launchers: t
                        .launchers
                        .iter()
                        .map(|l| (l.path.clone(), l.target_exists))
                        .collect(),
                    interpreter_ok: t.runtime.as_ref().and_then(|r| r.exists),
                    commands: t.command_names(),
                },
            );
        }
    }
    if let Some(g) = brew {
        for n in g.nodes().filter(|n| !n.stub) {
            inv.brew.insert(n.id.clone(), n.version.clone());
        }
    }
    inv
}

fn check_launcher(
    path: &Path,
    expected_target: Option<&Path>,
    expect_dangling: bool,
) -> Result<(), String> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Err("launcher no longer exists".into());
    };
    if meta.file_type().is_symlink() {
        let actual = launchers::read_link_abs(path);
        if let Some(exp) = expected_target {
            if actual.as_deref() != Some(exp) {
                return Err(format!(
                    "launcher now points at {} (expected {})",
                    actual
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "?".into()),
                    exp.display()
                ));
            }
        }
        let (_, _, exists) = launchers::follow_chain(path);
        if expect_dangling && exists {
            return Err("launcher target exists again; it is no longer dangling".into());
        }
        Ok(())
    } else if let Some(l) = launchers::inspect(path) {
        if let Some(exp) = expected_target {
            if l.target.as_deref() != Some(exp) {
                return Err(format!(
                    "shim now launches {} (expected {})",
                    l.target
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "?".into()),
                    exp.display()
                ));
            }
        }
        Ok(())
    } else {
        Err("launcher is not a symlink or shim any more".into())
    }
}

/// Re-check every guard against fresh data right before execution.
pub async fn preflight_refresh(
    actions: &[PlannedAction],
    deps: &ExecDeps,
    token: &CancellationToken,
) -> (PreflightReport, Option<BrewGraph>) {
    let needs_brew = actions.iter().any(|a| brew_target(a).is_some());
    let graph = if needs_brew {
        fresh_brew_graph(deps, token).await
    } else {
        None
    };
    let selected: BTreeSet<String> = actions.iter().filter_map(brew_target).collect();
    let preview = match (&graph, selected.is_empty()) {
        (Some(g), false) => Some(g.removal_preview(&selected)),
        _ => None,
    };
    let needs_tools = actions
        .iter()
        .any(|a| matches!(a.guard, Some(Guard::ToolInstall { .. })));
    let inventory = if needs_tools {
        let paths = deps.paths.clone();
        let config = deps.config.clone();
        tokio::task::spawn_blocking(move || capture_inventory(&paths, &config, None))
            .await
            .unwrap_or_default()
    } else {
        Inventory::default()
    };

    let mut report = PreflightReport::default();
    let mut ok = Vec::new();
    for a in actions {
        if a.destructive && is_brew_autoremove(a) {
            report.refused.push(Refused {
                action: a.clone(),
                reason: AUTOREMOVE_REFUSAL.into(),
            });
            continue;
        }
        let verdict: Result<(), String> = protected_metadata(|| match &a.guard {
            None => Ok(()),
            Some(Guard::BrewFormula {
                full_name,
                expected_version,
                require_no_retained_dependents,
            }) => match &graph {
                None => Err(
                    "could not refresh `brew info`; refusing to act on stale Homebrew data".into(),
                ),
                Some(g) => match g.node(full_name) {
                    None => Err(format!("{full_name} is no longer installed")),
                    Some(n) => {
                        if expected_version.is_some() && n.version != *expected_version {
                            Err(format!(
                                "version changed since the scan: {} → {}",
                                expected_version.clone().unwrap_or_default(),
                                n.version.clone().unwrap_or_else(|| "?".into())
                            ))
                        } else if *require_no_retained_dependents {
                            match preview
                                .as_ref()
                                .and_then(|p| p.blocked.iter().find(|(x, _)| x == &n.id))
                            {
                                Some((_, d)) => Err(format!("still needed by {}", d.join(", "))),
                                None => Ok(()),
                            }
                        } else {
                            Ok(())
                        }
                    }
                },
            },
            Some(Guard::BrewCask {
                token: t,
                expected_version,
            }) => match &graph {
                None => Err(
                    "could not refresh `brew info`; refusing to act on stale Homebrew data".into(),
                ),
                Some(g) => match g.node(t) {
                    None => Err(format!("cask {t} is no longer installed")),
                    Some(n) if expected_version.is_some() && n.version != *expected_version => {
                        Err(format!(
                            "version changed since the scan: {} → {}",
                            expected_version.clone().unwrap_or_default(),
                            n.version.clone().unwrap_or_else(|| "?".into())
                        ))
                    }
                    Some(_) => Ok(()),
                },
            },
            Some(Guard::ToolInstall {
                identity_key,
                expected_version,
                program_must_exist,
                ..
            }) => match inventory.items.get(identity_key) {
                None => {
                    Err("installation no longer present (removed or moved since the scan)".into())
                }
                Some(item) => {
                    if expected_version.is_some() && item.version != *expected_version {
                        Err(format!(
                            "version changed since the scan: {} → {}",
                            expected_version.clone().unwrap_or_default(),
                            item.version.clone().unwrap_or_else(|| "?".into())
                        ))
                    } else if let Some(p) = program_must_exist.as_ref().filter(|p| !p.exists()) {
                        Err(format!("manager program {} is missing", p.display()))
                    } else {
                        Ok(())
                    }
                }
            },
            Some(Guard::Launcher {
                path,
                expected_target,
                expect_dangling,
                ..
            }) => check_launcher(path, expected_target.as_deref(), *expect_dangling),
            Some(Guard::PipPackage {
                site,
                name,
                interpreter,
            }) => {
                let want = pymeta::normalize_name(name);
                match pymeta::site_dist_infos(site)
                    .into_iter()
                    .find(|d| d.normalized == want)
                {
                    None => Err(format!(
                        "{name} is no longer installed in {}",
                        site.display()
                    )),
                    Some(d) => {
                        if d.link_target
                            .as_deref()
                            .and_then(launchers::owner_from_path)
                            .is_some()
                            || d.installer.as_deref() == Some("brew")
                        {
                            Err("package is now Homebrew-owned; refusing pip uninstall".into())
                        } else if d.installer.as_deref() != Some("pip") {
                            Err(format!(
                                "INSTALLER is now {}",
                                d.installer.clone().unwrap_or_else(|| "(absent)".into())
                            ))
                        } else if !interpreter.exists() {
                            Err(format!("interpreter {} is missing", interpreter.display()))
                        } else {
                            Ok(())
                        }
                    }
                }
            }
        });
        match verdict {
            Ok(()) => ok.push(a.clone()),
            Err(reason) => report.refused.push(Refused {
                action: a.clone(),
                reason,
            }),
        }
    }
    report.ok = order_actions(ok, preview.as_ref());
    report.brew_preview = preview;
    if let Some(graph) = &graph {
        filter_brew_dependencies(&mut report, graph);
        report.ok = order_actions(std::mem::take(&mut report.ok), report.brew_preview.as_ref());
    }
    (report, graph)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Ok,
    RemovedAsExpected,
    StillPresent,
    PreExistingFailure,
    Regression,
    Skipped,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Verification {
    pub key: String,
    pub name: String,
    pub check: String,
    pub before: Option<bool>,
    pub after: Option<bool>,
    pub verdict: Verdict,
    pub detail: Option<String>,
}

fn item_healthy(i: &InventoryItem) -> bool {
    i.launchers.iter().all(|(_, ok)| *ok != Some(false)) && i.interpreter_ok != Some(false)
}

/// Compare inventories: removed targets must be gone; everything else must
/// be no worse than before. `probes_before/after` hold `--version` results.
pub fn verify(
    before: &Inventory,
    after: &Inventory,
    targets: &BTreeSet<String>,
    probes_before: &BTreeMap<String, bool>,
    probes_after: &BTreeMap<String, bool>,
) -> Vec<Verification> {
    let mut out = Vec::new();
    for (key, item) in &before.items {
        if targets.contains(key) {
            let present = after.items.contains_key(key);
            out.push(Verification {
                key: key.clone(),
                name: item.name.clone(),
                check: "removed".into(),
                before: Some(true),
                after: Some(present),
                verdict: if present {
                    Verdict::StillPresent
                } else {
                    Verdict::RemovedAsExpected
                },
                detail: item.version.clone().map(|v| format!("was {v}")),
            });
            continue;
        }
        let Some(now) = after.items.get(key) else {
            out.push(Verification {
                key: key.clone(),
                name: item.name.clone(),
                check: "still installed".into(),
                before: Some(true),
                after: Some(false),
                verdict: Verdict::Regression,
                detail: Some("installation disappeared although it was not a target".into()),
            });
            continue;
        };
        let (b, a) = (item_healthy(item), item_healthy(now));
        out.push(Verification {
            key: key.clone(),
            name: item.name.clone(),
            check: "launchers + interpreter".into(),
            before: Some(b),
            after: Some(a),
            verdict: match (b, a) {
                (_, true) => Verdict::Ok,
                (false, false) => Verdict::PreExistingFailure,
                (true, false) => Verdict::Regression,
            },
            detail: None,
        });
        if let Some(pa) = probes_after.get(key) {
            let pb = probes_before.get(key).copied();
            out.push(Verification {
                key: key.clone(),
                name: item.name.clone(),
                check: "--version probe".into(),
                before: pb,
                after: Some(*pa),
                verdict: match (pb, *pa) {
                    (_, true) => Verdict::Ok,
                    (Some(false), false) => Verdict::PreExistingFailure,
                    (Some(true), false) => Verdict::Regression,
                    (None, false) => Verdict::Regression,
                },
                detail: None,
            });
        }
    }
    for key in targets {
        if !before.items.contains_key(key) && !key.starts_with("brew:") && !key.starts_with("cask:")
        {
            out.push(Verification {
                key: key.clone(),
                name: key.clone(),
                check: "removed".into(),
                before: Some(false),
                after: Some(after.items.contains_key(key)),
                verdict: Verdict::Skipped,
                detail: Some("target was not in the pre-cleanup inventory".into()),
            });
        }
    }
    out
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ActionResult {
    pub action: PlannedAction,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CleanupReport {
    pub started_at: i64,
    pub finished_at: i64,
    pub delete_mode: String,
    pub executed: Vec<ActionResult>,
    pub failed: Vec<ActionResult>,
    pub cancelled: Vec<PlannedAction>,
    /// Refused by either preflight (with reasons).
    pub refused: Vec<Refused>,
    pub verification: Vec<Verification>,
    pub before: Inventory,
    pub after: Inventory,
    /// `brew autoremove --dry-run` after the batch (None = not run/unknown).
    pub brew_autoremove_after: Option<Vec<String>>,
    pub note: String,
    pub audit_path: Option<PathBuf>,
}

impl CleanupReport {
    pub fn summary(&self) -> String {
        let regressions = self
            .verification
            .iter()
            .filter(|v| v.verdict == Verdict::Regression)
            .count();
        let preexisting = self
            .verification
            .iter()
            .filter(|v| v.verdict == Verdict::PreExistingFailure)
            .count();
        format!(
            "cleanup: {} ran, {} failed, {} cancelled, {} refused; verification: {} regression(s), {} pre-existing failure(s)",
            self.executed.len(),
            self.failed.len(),
            self.cancelled.len(),
            self.refused.len(),
            regressions,
            preexisting
        )
    }
}

/// Progress events for the TUI.
#[derive(Debug)]
pub enum ExecEvent {
    PreflightDone(Box<PreflightReport>),
    ActionStarted(usize),
    ActionDone(usize, Result<String, String>),
    Executed { cancelled: Vec<PlannedAction> },
    Verifying,
    Finished(Box<CleanupReport>),
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Retained tool installations worth probing after the batch: those that
/// share a command name with a removed tool or are listed as its peers.
fn related_retained(
    current: &BTreeMap<FindingId, Finding>,
    targets: &BTreeSet<String>,
) -> Vec<(String, PathBuf)> {
    let mut removed_cmds: BTreeSet<String> = BTreeSet::new();
    let mut peers: BTreeSet<String> = BTreeSet::new();
    for f in current
        .values()
        .filter(|f| f.kind == FindingKind::GlobalTool)
    {
        let key = f
            .meta
            .get("identity_key")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if targets.contains(key) {
            for c in f
                .meta
                .get("commands")
                .and_then(|c| c.as_array())
                .into_iter()
                .flatten()
            {
                if let Some(n) = c.get("name").and_then(|n| n.as_str()) {
                    removed_cmds.insert(n.to_string());
                }
            }
            for c in f
                .meta
                .get("classifications")
                .and_then(|c| c.as_array())
                .into_iter()
                .flatten()
            {
                for p in str_list(c, "peers") {
                    peers.insert(p);
                }
            }
        }
    }
    let mut out = Vec::new();
    for f in current
        .values()
        .filter(|f| f.kind == FindingKind::GlobalTool)
    {
        let key = f
            .meta
            .get("identity_key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if targets.contains(&key) || key.is_empty() {
            continue;
        }
        let cmds: Vec<String> = f
            .meta
            .get("commands")
            .and_then(|c| c.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.get("name").and_then(|n| n.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let related = peers.contains(&key) || cmds.iter().any(|c| removed_cmds.contains(c));
        if !related {
            continue;
        }
        // First launcher whose target exists is the probe target.
        let launcher = f
            .meta
            .get("launchers")
            .and_then(|l| l.as_array())
            .and_then(|a| {
                a.iter()
                    .find(|l| l.get("target_exists").and_then(|e| e.as_bool()) != Some(false))
                    .and_then(|l| l.get("path").and_then(|p| p.as_str()))
                    .map(PathBuf::from)
            });
        if let Some(p) = launcher {
            out.push((key, p));
        }
    }
    out
}

async fn run_probes(
    deps: &ExecDeps,
    related: &[(String, PathBuf)],
    token: &CancellationToken,
) -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    let limit = deps.config.tools.verify_limit;
    for (key, path) in related.iter().take(limit) {
        let p = path.display().to_string();
        let run = deps.runner.run(&p, &["--version"], token);
        let ok = matches!(
            tokio::time::timeout(Duration::from_secs(deps.config.tools.verify_timeout_secs), run).await,
            Ok(Ok(o)) if o.success()
        );
        out.insert(key.clone(), ok);
    }
    out
}

pub async fn run_batch(
    actions: Vec<PlannedAction>,
    current: BTreeMap<FindingId, Finding>,
    deps: ExecDeps,
    tx: mpsc::Sender<ExecEvent>,
    stop: CancellationToken,
) -> CleanupReport {
    let confirmed = PreflightReport {
        refused: actions
            .into_iter()
            .map(|action| Refused {
                action,
                reason: "cleanup requires the original confirmation-time target snapshot; use run_confirmed_batch".into(),
            })
            .collect(),
        ..PreflightReport::default()
    };
    run_confirmed_batch(confirmed, current, deps, tx, stop).await
}

pub async fn run_confirmed_batch(
    confirmed: PreflightReport,
    current: BTreeMap<FindingId, Finding>,
    deps: ExecDeps,
    tx: mpsc::Sender<ExecEvent>,
    stop: CancellationToken,
) -> CleanupReport {
    let started_at = now_secs();
    let token = CancellationToken::new();
    let mut refused = confirmed.refused;
    let mut eligible = Vec::new();
    for action in &confirmed.ok {
        let verdict = current
            .get(&action.finding_id)
            .filter(|finding| action_is_current(action, finding))
            .ok_or_else(|| "remedy is no longer authorized by the current finding".to_string())
            .and_then(|_| {
                confirmed
                    .identities
                    .0
                    .get(&action.rendered)
                    .ok_or_else(|| "cleanup plan has no physical target snapshot".to_string())
            })
            .and_then(|targets| targets.iter().try_for_each(PhysicalTarget::verify));
        match verdict {
            Ok(()) => eligible.push(action.clone()),
            Err(reason) => refused.push(Refused {
                action: action.clone(),
                reason,
            }),
        }
    }
    let (mut report, graph_before) = preflight_refresh(&eligible, &deps, &token).await;
    report.refused.extend(refused);
    let _ = tx
        .send(ExecEvent::PreflightDone(Box::new(report.clone())))
        .await;

    let targets: BTreeSet<String> = report.ok.iter().map(owner_key).collect();
    let paths = deps.paths.clone();
    let config = deps.config.clone();
    let graph_for_inv = graph_before.clone();
    let before = tokio::task::spawn_blocking(move || {
        capture_inventory(&paths, &config, graph_for_inv.as_ref())
    })
    .await
    .unwrap_or_default();
    let related = if deps.config.tools.verify_after_cleanup {
        related_retained(&current, &targets)
    } else {
        Vec::new()
    };
    let probes_before = run_probes(&deps, &related, &token).await;

    let engine = RemedyEngine::new(deps.delete_mode);
    let mut executed = Vec::new();
    let mut failed = Vec::new();
    let mut cancelled = Vec::new();
    let mut failed_keys: BTreeSet<String> = BTreeSet::new();
    let mut brew_touched = false;
    let mut removed_brew = BTreeSet::new();
    let ordered = std::mem::take(&mut report.ok);
    for (i, a) in ordered.iter().enumerate() {
        if stop.is_cancelled() {
            cancelled.push(a.clone());
            continue;
        }
        let key = owner_key(a);
        if failed_keys.contains(&key) {
            failed.push(ActionResult {
                action: a.clone(),
                message: "skipped: an earlier action on the same installation failed".into(),
            });
            continue;
        }
        if let (Some(target), Some(graph)) = (brew_target(a), &graph_before) {
            let name = graph.resolve(&target).unwrap_or(target);
            let retained: Vec<_> = graph
                .dependents(&name)
                .into_iter()
                .filter(|dependent| !removed_brew.contains(dependent))
                .collect();
            if !retained.is_empty() {
                report.refused.push(Refused {
                    action: a.clone(),
                    reason: format!(
                        "blocked: dependent removal did not complete: {}",
                        retained.join(", ")
                    ),
                });
                failed_keys.insert(key);
                continue;
            }
        }
        let _ = tx.send(ExecEvent::ActionStarted(i)).await;
        if stop.is_cancelled() {
            cancelled.push(a.clone());
            continue;
        }
        let identities = confirmed.identities.0.get(&a.rendered).unwrap();
        if let Err(reason) = identities.iter().try_for_each(PhysicalTarget::verify) {
            let _ = tx.send(ExecEvent::ActionDone(i, Err(reason.clone()))).await;
            report.refused.push(Refused {
                action: a.clone(),
                reason,
            });
            failed_keys.insert(key);
            continue;
        }
        // Fresh token: an in-flight command is never killed by Esc.
        let result = engine
            .execute(
                a,
                deps.runner.as_ref(),
                deps.trash.as_ref(),
                deps.clipboard.as_ref(),
                &CancellationToken::new(),
            )
            .await;
        match result {
            Ok(msg) => {
                if let (Some(target), Some(graph)) = (brew_target(a), &graph_before) {
                    removed_brew.insert(graph.resolve(&target).unwrap_or(target));
                }
                if brew_target(a).is_some() || is_brew_autoremove(a) {
                    brew_touched = true;
                }
                executed.push(ActionResult {
                    action: a.clone(),
                    message: msg.clone(),
                });
                let _ = tx.send(ExecEvent::ActionDone(i, Ok(msg))).await;
            }
            Err(e) => {
                failed_keys.insert(key);
                let msg = e.to_string();
                failed.push(ActionResult {
                    action: a.clone(),
                    message: msg.clone(),
                });
                let _ = tx.send(ExecEvent::ActionDone(i, Err(msg))).await;
            }
        }
    }
    let _ = tx
        .send(ExecEvent::Executed {
            cancelled: cancelled.clone(),
        })
        .await;
    let _ = tx.send(ExecEvent::Verifying).await;

    // Fresh Homebrew view after the batch so follow-up dependency cleanup
    // is offered from current data.
    let mut brew_autoremove_after = None;
    let graph_after = if brew_touched {
        let run = deps
            .runner
            .run("brew", &["autoremove", "--dry-run"], &token);
        if let Ok(Ok(o)) = tokio::time::timeout(BREW_TIMEOUT, run).await {
            if o.success() {
                brew_autoremove_after = Some(
                    parse_autoremove_dry_run(&o.stdout_str())
                        .into_iter()
                        .collect(),
                );
            }
        }
        fresh_brew_graph(&deps, &token).await
    } else {
        graph_before.clone()
    };
    let paths = deps.paths.clone();
    let config = deps.config.clone();
    let after = tokio::task::spawn_blocking(move || {
        capture_inventory(&paths, &config, graph_after.as_ref())
    })
    .await
    .unwrap_or_default();
    let probes_after = run_probes(&deps, &related, &token).await;
    let mut verification = verify(&before, &after, &targets, &probes_before, &probes_after);
    for t in &targets {
        if let Some(name) = t.strip_prefix("brew:").or_else(|| t.strip_prefix("cask:")) {
            let present_after = after
                .brew
                .keys()
                .any(|k| k == name || k == &format!("cask:{name}"));
            verification.push(Verification {
                key: t.clone(),
                name: name.to_string(),
                check: "removed".into(),
                before: Some(
                    before
                        .brew
                        .keys()
                        .any(|k| k == name || k == &format!("cask:{name}")),
                ),
                after: Some(present_after),
                verdict: if present_after {
                    Verdict::StillPresent
                } else {
                    Verdict::RemovedAsExpected
                },
                detail: before
                    .brew
                    .get(name)
                    .cloned()
                    .flatten()
                    .map(|v| format!("was {v}")),
            });
        }
    }

    let out = CleanupReport {
        started_at,
        finished_at: now_secs(),
        delete_mode: match deps.delete_mode {
            DeleteMode::Trash => "trash".into(),
            DeleteMode::Rm => "rm".into(),
        },
        executed,
        failed,
        cancelled,
        refused: report.refused.clone(),
        verification,
        before,
        after,
        brew_autoremove_after,
        note:
            "No rollback is available. Recorded versions are guidance for a manual reinstall only."
                .into(),
        audit_path: None,
    };
    let _ = tx.send(ExecEvent::Finished(Box::new(out.clone()))).await;
    out
}

/// Sections a batch touches, for the post-cleanup rescan.
pub fn affected_sections(
    actions: &[PlannedAction],
    current: &BTreeMap<FindingId, Finding>,
) -> Vec<crate::model::ScannerId> {
    let mut out: Vec<crate::model::ScannerId> = Vec::new();
    for a in actions {
        if let Some(f) = current.get(&a.finding_id) {
            let s = f.kind.scanner();
            if !out.contains(&s) {
                out.push(s);
            }
        }
        if a.guard.is_some() {
            for s in [
                crate::model::ScannerId::Tools,
                crate::model::ScannerId::ShellEnv,
            ] {
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
        if brew_target(a).is_some() || is_brew_autoremove(a) {
            let s = crate::model::ScannerId::Brew;
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Remedy, Severity};
    use crate::runner::MockCommandRunner;
    use std::sync::Mutex;

    struct FakeTrash(Mutex<Vec<PathBuf>>);
    impl TrashOps for FakeTrash {
        fn trash(&self, path: &Path) -> anyhow::Result<()> {
            if !path.exists() && !path.is_symlink() {
                anyhow::bail!("no such path");
            }
            self.0.lock().unwrap().push(path.to_path_buf());
            Ok(())
        }
    }
    struct NoClipboard;
    impl ClipboardOps for NoClipboard {
        fn copy(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn brew_finding(
        home: &Path,
        name: &str,
        on_request: bool,
        deps: &[&str],
        dependents: &[&str],
    ) -> Finding {
        let cellar = home.join("Cellar").join(name);
        std::fs::create_dir_all(&cellar).unwrap();
        let mut f = Finding::new(FindingKind::BrewFormula, name, name).path(cellar).meta(serde_json::json!({
            "name": name, "full_name": name, "version": "1.0", "installed_on_request": on_request,
            "dependencies": deps, "dependents": dependents, "autoremove_candidate": false,
        }));
        if dependents.is_empty() {
            f = f.remedy(
                Remedy::new(
                    "Uninstall formula",
                    RemedyCommand::Shell {
                        program: "brew".into(),
                        args: vec!["uninstall".into(), name.into()],
                    },
                )
                .destructive()
                .guard(Guard::BrewFormula {
                    full_name: name.into(),
                    expected_version: Some("1.0".into()),
                    require_no_retained_dependents: true,
                }),
            );
        }
        f
    }

    fn plan(f: &Finding, idx: usize) -> PlannedAction {
        RemedyEngine::new(DeleteMode::Trash).plan_one(f.id, &f.remedies[idx])
    }

    #[test]
    fn static_preflight_refuses_stale_duplicate_and_blocked() {
        let home = tempfile::tempdir().unwrap();
        // app (requested) → lib (dependency); app2 (requested) → lib.
        let app = brew_finding(home.path(), "app", true, &["lib"], &[]);
        let app2 = brew_finding(home.path(), "app2", true, &["lib"], &[]);
        let mut lib = brew_finding(home.path(), "lib", false, &[], &["app", "app2"]);
        // Give lib an (unsafe) uninstall remedy to prove preflight blocks it.
        lib = lib.remedy(
            Remedy::new(
                "Uninstall formula",
                RemedyCommand::Shell {
                    program: "brew".into(),
                    args: vec!["uninstall".into(), "lib".into()],
                },
            )
            .destructive()
            .guard(Guard::BrewFormula {
                full_name: "lib".into(),
                expected_version: None,
                require_no_retained_dependents: true,
            }),
        );
        let gone = Finding::new(FindingKind::BuildArtifact, "/x/target", "target").remedy(
            Remedy::new(
                "Trash",
                RemedyCommand::Trash {
                    path: "/x/target".into(),
                },
            )
            .destructive(),
        );
        let mut current = BTreeMap::new();
        for f in [&app, &app2, &lib] {
            current.insert(f.id, f.clone());
        }
        let actions = vec![plan(&app, 0), plan(&app, 0), plan(&lib, 0), plan(&gone, 0)];
        let r = preflight_static(&actions, &current);
        assert_eq!(r.ok.len(), 1);
        assert_eq!(r.ok[0].rendered, "brew uninstall app");
        let reasons: Vec<&str> = r.refused.iter().map(|x| x.reason.as_str()).collect();
        assert!(reasons.iter().any(|x| x.contains("duplicate target")));
        assert!(reasons.iter().any(|x| x.contains("still needed by app2")));
        assert!(reasons.iter().any(|x| x.contains("no longer present")));
        // lib is still needed by app2 even after app goes: not an orphan.
        assert!(r.brew_preview.as_ref().unwrap().newly_orphaned.is_empty());

        // Removing both apps orphans lib, ordered dependents-first, and says so.
        let r = preflight_static(&[plan(&app2, 0), plan(&app, 0)], &current);
        assert_eq!(
            r.ok.iter().map(|a| a.rendered.clone()).collect::<Vec<_>>(),
            ["brew uninstall app", "brew uninstall app2"]
        );
        assert!(r
            .follow_up
            .iter()
            .any(|f| f.contains("lib") && f.contains("autoremove")));
    }

    #[test]
    fn ordering_puts_brew_first_then_tools_launchers_and_autoremove_last() {
        let mk = |label: &str, cmd: RemedyCommand, guard: Option<Guard>| PlannedAction {
            finding_id: FindingId::new(FindingKind::GlobalTool, label),
            label: label.into(),
            rendered: cmd.rendered(),
            command: cmd,
            destructive: true,
            reclaims_bytes: None,
            guard,
        };
        let launcher = mk(
            "l",
            RemedyCommand::Trash { path: "/l".into() },
            Some(Guard::Launcher {
                path: "/l".into(),
                expected_target: None,
                expect_dangling: false,
                owner_key: "k".into(),
            }),
        );
        let auto = mk(
            "a",
            RemedyCommand::Shell {
                program: "brew".into(),
                args: vec!["autoremove".into()],
            },
            None,
        );
        let tool = mk(
            "t",
            RemedyCommand::Shell {
                program: "npm".into(),
                args: vec!["uninstall".into(), "-g".into(), "x".into()],
            },
            Some(Guard::ToolInstall {
                manager: "npm".into(),
                identity_key: "k".into(),
                root: "/r".into(),
                expected_version: None,
                program_must_exist: None,
            }),
        );
        let brew = mk(
            "b",
            RemedyCommand::Shell {
                program: "brew".into(),
                args: vec!["uninstall".into(), "wget".into()],
            },
            Some(Guard::BrewFormula {
                full_name: "wget".into(),
                expected_version: None,
                require_no_retained_dependents: true,
            }),
        );
        let plain = mk("p", RemedyCommand::Trash { path: "/p".into() }, None);
        let ordered = order_actions(vec![launcher, auto, plain, tool, brew], None);
        let labels: Vec<&str> = ordered.iter().map(|a| a.label.as_str()).collect();
        assert_eq!(labels, ["b", "t", "l", "p", "a"]);
    }

    fn deps_with(mock: MockCommandRunner, home: &Path, trash: Arc<FakeTrash>) -> ExecDeps {
        let mut config = Config::default();
        config.tools.include_apple_python = false;
        config.tools.homebrew_prefix = Some(home.join("nope").display().to_string());
        config.tools.verify_after_cleanup = true;
        ExecDeps {
            runner: Arc::new(mock),
            trash,
            clipboard: Arc::new(NoClipboard),
            paths: Arc::new(Paths::from_home(home)),
            config: Arc::new(config),
            delete_mode: DeleteMode::Trash,
        }
    }

    #[tokio::test]
    async fn refresh_preflight_refuses_changed_launcher_and_stale_versions() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let bin = home.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink("../lib/x/cli.js", bin.join("x")).unwrap(); // dangling
        std::os::unix::fs::symlink("../lib/y/cli.js", bin.join("y")).unwrap();
        std::fs::create_dir_all(home.join("lib/y")).unwrap();
        std::fs::write(home.join("lib/y/cli.js"), "").unwrap();
        let mk_launcher = |name: &str, expect_dangling: bool| PlannedAction {
            finding_id: FindingId::new(FindingKind::GlobalTool, name),
            label: name.into(),
            command: RemedyCommand::Trash {
                path: bin.join(name),
            },
            rendered: format!("trash {}", bin.join(name).display()),
            destructive: true,
            reclaims_bytes: None,
            guard: Some(Guard::Launcher {
                path: bin.join(name),
                expected_target: Some(launchers::normalize(
                    &home.join(format!("lib/{name}/cli.js")),
                )),
                expect_dangling,
                owner_key: "k".into(),
            }),
        };
        // brew guard with a version that changed since the scan.
        let brew = PlannedAction {
            finding_id: FindingId::new(FindingKind::BrewFormula, "wget"),
            label: "Uninstall".into(),
            command: RemedyCommand::Shell {
                program: "brew".into(),
                args: vec!["uninstall".into(), "wget".into()],
            },
            rendered: "brew uninstall wget".into(),
            destructive: true,
            reclaims_bytes: None,
            guard: Some(Guard::BrewFormula {
                full_name: "wget".into(),
                expected_version: Some("1.0".into()),
                require_no_retained_dependents: true,
            }),
        };
        let mock = MockCommandRunner::new().on(
            "brew",
            &["info", "--json=v2", "--installed"],
            r#"{"formulae": [{"name": "wget", "full_name": "wget", "installed": [{"version": "2.0", "installed_on_request": true, "runtime_dependencies": []}], "linked_keg": "2.0"}], "casks": []}"#,
        );
        let trash = Arc::new(FakeTrash(Mutex::new(vec![])));
        let deps = deps_with(mock, home, trash);
        let actions = vec![mk_launcher("x", true), mk_launcher("y", true), brew];
        let (r, _) = preflight_refresh(&actions, &deps, &CancellationToken::new()).await;
        assert_eq!(r.ok.len(), 1);
        assert_eq!(r.ok[0].label, "x");
        let reasons: Vec<&str> = r.refused.iter().map(|x| x.reason.as_str()).collect();
        assert!(
            reasons.iter().any(|x| x.contains("no longer dangling")),
            "{reasons:?}"
        );
        assert!(
            reasons
                .iter()
                .any(|x| x.contains("version changed since the scan: 1.0 → 2.0")),
            "{reasons:?}"
        );
    }

    #[tokio::test]
    async fn batch_runs_in_order_skips_refused_reports_partial_failure_and_cancellation() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let bin = home.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink("../lib/x/cli.js", bin.join("x")).unwrap();
        // Two brew targets: `wget` fine, `broken` exits non-zero; one launcher.
        let mut current = BTreeMap::new();
        let wget = brew_finding(home, "wget", true, &[], &[]);
        let broken = brew_finding(home, "broken", true, &[], &[]);
        let tool = Finding::new(FindingKind::GlobalTool, "npm:/r:x", "x")
            .meta(serde_json::json!({ "identity_key": "npm:/r:x", "commands": [{"name": "x"}], "launchers": [], "classifications": [] }))
            .remedy(
                Remedy::new("Remove launcher x only", RemedyCommand::Trash { path: bin.join("x") })
                    .destructive()
                    .guard(Guard::Launcher { path: bin.join("x"), expected_target: Some(launchers::normalize(&home.join("lib/x/cli.js"))), expect_dangling: true, owner_key: "npm:/r:x".into() }),
            );
        for f in [&wget, &broken, &tool] {
            current.insert(f.id, f.clone());
        }
        let actions = vec![plan(&tool, 0), plan(&broken, 0), plan(&wget, 0)];
        let info = r#"{"formulae": [
            {"name": "wget", "full_name": "wget", "installed": [{"version": "1.0", "installed_on_request": true, "runtime_dependencies": []}], "linked_keg": "1.0"},
            {"name": "broken", "full_name": "broken", "installed": [{"version": "1.0", "installed_on_request": true, "runtime_dependencies": []}], "linked_keg": "1.0"}
        ], "casks": []}"#;
        let mock = MockCommandRunner::new()
            .on("brew", &["info", "--json=v2", "--installed"], info)
            .on("brew", &["uninstall", "wget"], "Uninstalling wget\n")
            .on_fail("brew", &["uninstall", "broken"], 1, "Error: refusing")
            .on(
                "brew",
                &["autoremove", "--dry-run"],
                "==> Would autoremove 1 unneeded formula:\nlibx\n",
            );
        let trash = Arc::new(FakeTrash(Mutex::new(vec![])));
        let deps = deps_with(mock, home, trash.clone());
        let (tx, mut rx) = mpsc::channel(64);
        let confirmed = preflight_static(&actions, &current);
        let report =
            run_confirmed_batch(confirmed, current, deps, tx, CancellationToken::new()).await;
        assert_eq!(report.executed.len(), 2, "{report:?}");
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].message.contains("refusing"));
        assert!(report.cancelled.is_empty());
        assert_eq!(report.brew_autoremove_after, Some(vec!["libx".into()]));
        assert_eq!(trash.0.lock().unwrap().len(), 1);
        // Order: brew before launcher.
        assert!(report.executed[0]
            .action
            .rendered
            .starts_with("brew uninstall"));
        assert!(report.executed[1].action.rendered.starts_with("trash"));
        assert!(report.audit_path.is_none());
        assert!(!Paths::from_home(home).state_dir.exists());
        let json: Value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            json["failed"][0]["action"]["rendered"],
            "brew uninstall broken"
        );
        assert!(json["note"].as_str().unwrap().contains("No rollback"));
        let mut events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }
        assert!(matches!(events.first(), Some(ExecEvent::PreflightDone(_))));
        assert!(matches!(events.last(), Some(ExecEvent::Finished(_))));

        // Cancellation before anything runs: everything is reported cancelled.
        let stop = CancellationToken::new();
        stop.cancel();
        let mock = MockCommandRunner::new().on("brew", &["info", "--json=v2", "--installed"], info);
        let trash2 = Arc::new(FakeTrash(Mutex::new(vec![])));
        let deps = deps_with(mock, home, trash2.clone());
        let (tx, _rx) = mpsc::channel(64);
        let current = BTreeMap::from([(wget.id, wget.clone())]);
        let confirmed = preflight_static(&[plan(&wget, 0)], &current);
        let report = run_confirmed_batch(confirmed, current, deps, tx, stop).await;
        assert_eq!(report.cancelled.len(), 1);
        assert!(report.executed.is_empty());
        assert!(trash2.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cancellation_finishes_active_command_and_skips_next_action() {
        struct CancelDuringUninstall {
            inner: MockCommandRunner,
            stop: CancellationToken,
            uninstalls: std::sync::atomic::AtomicUsize,
        }

        #[async_trait::async_trait]
        impl CommandRunner for CancelDuringUninstall {
            async fn run(
                &self,
                program: &str,
                args: &[&str],
                token: &CancellationToken,
            ) -> anyhow::Result<crate::runner::CmdOutput> {
                if program == "brew" && args.first() == Some(&"uninstall") {
                    self.uninstalls
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    self.stop.cancel();
                    tokio::task::yield_now().await;
                    if token.is_cancelled() {
                        anyhow::bail!("active destructive command was cancelled");
                    }
                }
                self.inner.run(program, args, token).await
            }
        }

        let home = tempfile::tempdir().unwrap();
        let first = brew_finding(home.path(), "alpha", true, &[], &[]);
        let second = brew_finding(home.path(), "beta", true, &[], &[]);
        let current = [first.clone(), second.clone()]
            .into_iter()
            .map(|finding| (finding.id, finding))
            .collect();
        let info = r#"{"formulae":[
            {"name":"alpha","full_name":"alpha","installed":[{"version":"1.0","installed_on_request":true,"runtime_dependencies":[]}],"linked_keg":"1.0"},
            {"name":"beta","full_name":"beta","installed":[{"version":"1.0","installed_on_request":true,"runtime_dependencies":[]}],"linked_keg":"1.0"}
        ],"casks":[]}"#;
        let stop = CancellationToken::new();
        let runner = Arc::new(CancelDuringUninstall {
            inner: MockCommandRunner::new()
                .on("brew", &["info", "--json=v2", "--installed"], info)
                .on("brew", &["uninstall", "alpha"], "removed alpha")
                .on("brew", &["uninstall", "beta"], "removed beta")
                .on("brew", &["autoremove", "--dry-run"], ""),
            stop: stop.clone(),
            uninstalls: std::sync::atomic::AtomicUsize::new(0),
        });
        let trash = Arc::new(FakeTrash(Mutex::new(vec![])));
        let mut deps = deps_with(MockCommandRunner::new(), home.path(), trash);
        deps.runner = runner.clone();
        let (tx, _rx) = mpsc::channel(64);
        let confirmed = preflight_static(&[plan(&first, 0), plan(&second, 0)], &current);
        let report = run_confirmed_batch(confirmed, current, deps, tx, stop).await;
        assert_eq!(
            runner.uninstalls.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(report.executed.len(), 1, "{report:?}");
        assert_eq!(report.executed[0].action.rendered, "brew uninstall alpha");
        assert!(report.failed.is_empty());
        assert_eq!(report.cancelled.len(), 1);
        assert_eq!(report.cancelled[0].rendered, "brew uninstall beta");
        assert!(report.audit_path.is_none());
    }

    #[tokio::test]
    async fn legacy_report_option_never_writes_or_modifies_reports() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        let reports = paths.state_dir.join("cleanup-reports");
        std::fs::create_dir_all(&reports).unwrap();
        let legacy = reports.join("previous.json");
        std::fs::write(&legacy, b"existing report").unwrap();
        let trash = Arc::new(FakeTrash(Mutex::new(vec![])));
        let mut deps = deps_with(MockCommandRunner::new(), home.path(), trash);
        deps.config = Arc::new(toml::from_str("[tools]\nwrite_cleanup_reports = true\n").unwrap());
        let (tx, _rx) = mpsc::channel(64);
        let report = run_batch(vec![], BTreeMap::new(), deps, tx, CancellationToken::new()).await;
        assert!(report.audit_path.is_none());
        assert_eq!(std::fs::read(&legacy).unwrap(), b"existing report");
        assert_eq!(std::fs::read_dir(reports).unwrap().count(), 1);
    }

    #[test]
    fn verification_distinguishes_preexisting_failures_from_regressions() {
        let item = |ok: bool| InventoryItem {
            manager: "pip".into(),
            name: "wheel".into(),
            version: Some("0.47".into()),
            launchers: vec![],
            interpreter_ok: Some(ok),
            commands: vec![],
        };
        let mut before = Inventory::default();
        before.items.insert("pip:/s:wheel".into(), item(false));
        before.items.insert("pip:/s:requests".into(), item(true));
        before.items.insert("pip:/s:good".into(), item(true));
        let mut after = Inventory::default();
        after.items.insert("pip:/s:wheel".into(), item(false));
        after.items.insert("pip:/s:good".into(), item(false));
        let targets: BTreeSet<String> = ["pip:/s:requests".to_string()].into_iter().collect();
        let mut pb = BTreeMap::new();
        pb.insert("pip:/s:good".to_string(), true);
        let mut pa = BTreeMap::new();
        pa.insert("pip:/s:good".to_string(), false);
        let v = verify(&before, &after, &targets, &pb, &pa);
        let by = |k: &str, check: &str| {
            v.iter()
                .find(|x| x.key == k && x.check == check)
                .unwrap()
                .verdict
        };
        assert_eq!(
            by("pip:/s:wheel", "launchers + interpreter"),
            Verdict::PreExistingFailure
        );
        assert_eq!(by("pip:/s:requests", "removed"), Verdict::RemovedAsExpected);
        assert_eq!(
            by("pip:/s:good", "launchers + interpreter"),
            Verdict::Regression
        );
        assert_eq!(by("pip:/s:good", "--version probe"), Verdict::Regression);
    }

    fn path_finding(key: &str, path: &Path) -> Finding {
        Finding::new(FindingKind::BuildArtifact, key, key)
            .path(path.to_path_buf())
            .remedy(
                Remedy::new(
                    "Trash",
                    RemedyCommand::Trash {
                        path: path.to_path_buf(),
                    },
                )
                .destructive(),
            )
    }

    #[test]
    fn cleanup_refuses_nested_alias_and_hardlink_targets() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("parent");
        std::fs::create_dir(&directory).unwrap();
        let child = directory.join("child");
        std::fs::write(&child, "fixture").unwrap();
        let parent = path_finding("parent", &directory);
        let nested = path_finding("child", &child);
        let current = [parent.clone(), nested.clone()]
            .into_iter()
            .map(|finding| (finding.id, finding))
            .collect();
        for actions in [
            vec![plan(&parent, 0), plan(&nested, 0)],
            vec![plan(&nested, 0), plan(&parent, 0)],
        ] {
            let report = preflight_static(&actions, &current);
            assert_eq!(report.ok.len(), 1);
            assert!(report.refused[0].reason.contains("overlapping physical"));
        }
        let alias = temporary.path().join("alias");
        std::os::unix::fs::symlink(&directory, &alias).unwrap();
        let alternate = path_finding("alias", &alias.join("child"));
        let hardlink = temporary.path().join("hardlink");
        std::fs::hard_link(&child, &hardlink).unwrap();
        let linked = path_finding("hardlink", &hardlink);
        for other in [alternate, linked] {
            let current = [nested.clone(), other.clone()]
                .into_iter()
                .map(|finding| (finding.id, finding))
                .collect();
            let report = preflight_static(&[plan(&nested, 0), plan(&other, 0)], &current);
            assert_eq!(report.ok.len(), 1);
            assert_eq!(report.refused.len(), 1);
        }
    }

    #[test]
    fn cleanup_refuses_mixed_trash_and_rm_but_preserves_unload_then_trash() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("fixture.plist");
        std::fs::write(&path, "fixture").unwrap();
        let finding = path_finding("fixture", &path).remedy(
            Remedy::new(
                "Unload",
                RemedyCommand::Shell {
                    program: "launchctl".into(),
                    args: vec!["bootout".into(), "gui/100/fixture".into()],
                },
            )
            .destructive(),
        );
        let current = [(finding.id, finding.clone())].into_iter().collect();
        let permanent =
            RemedyEngine::new(DeleteMode::Rm).plan_one(finding.id, &finding.remedies[0]);
        let report = preflight_static(&[plan(&finding, 0), permanent], &current);
        assert_eq!(report.ok.len(), 1);
        assert!(report.refused[0].reason.contains("overlapping physical"));
        let report = preflight_static(&[plan(&finding, 1), plan(&finding, 0)], &current);
        assert_eq!(report.ok.len(), 2);
        assert!(report.refused.is_empty());
    }

    #[test]
    fn cleanup_refuses_changed_or_unseen_remedies() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("fixture");
        std::fs::write(&path, "fixture").unwrap();
        let finding = path_finding("fixture", &path);
        let mut action = plan(&finding, 0);
        action.command = RemedyCommand::Trash {
            path: temporary.path().join("unseen"),
        };
        action.rendered = action.command.rendered();
        let current = [(finding.id, finding)].into_iter().collect();
        let report = preflight_static(&[action], &current);
        assert!(report.ok.is_empty());
        assert!(report.refused[0].reason.contains("not authorized"));
    }

    #[test]
    fn homebrew_cleanup_refuses_missing_physical_targets() {
        let home = tempfile::tempdir().unwrap();
        let mut formula = brew_finding(home.path(), "formula", true, &[], &[]);
        formula.path = None;
        let cask = Finding::new(FindingKind::BrewCask, "cask", "cask").remedy(
            Remedy::new(
                "Uninstall cask",
                RemedyCommand::Shell {
                    program: "brew".into(),
                    args: vec!["uninstall".into(), "--cask".into(), "cask".into()],
                },
            )
            .destructive()
            .guard(Guard::BrewCask {
                token: "cask".into(),
                expected_version: Some("1.0".into()),
            }),
        );
        let actions = vec![plan(&formula, 0), plan(&cask, 0)];
        let current = BTreeMap::from([(formula.id, formula), (cask.id, cask)]);
        let report = preflight_static(&actions, &current);
        assert!(report.ok.is_empty(), "{report:?}");
        assert_eq!(report.refused.len(), 2);
        assert!(report
            .refused
            .iter()
            .all(|refused| refused.reason.contains("physical Homebrew")));
    }

    #[tokio::test]
    async fn cask_artifacts_are_overlap_and_replacement_guarded() {
        let home = tempfile::tempdir().unwrap();
        let application = home.path().join("App.app");
        let cache = application.join("cache");
        let binary = home.path().join("bin");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(&binary, "original binary").unwrap();
        let cask = Finding::new(FindingKind::BrewCask, "app", "app")
            .meta(serde_json::json!({
                "app_paths": [application],
                "binaries": [{ "source": "app", "target": binary }],
            }))
            .remedy(
                Remedy::new(
                    "Uninstall cask",
                    RemedyCommand::Shell {
                        program: "brew".into(),
                        args: vec!["uninstall".into(), "--cask".into(), "app".into()],
                    },
                )
                .destructive()
                .guard(Guard::BrewCask {
                    token: "app".into(),
                    expected_version: Some("1.0".into()),
                }),
            );
        let nested = path_finding("cache", &cache);
        let current = BTreeMap::from([(cask.id, cask.clone()), (nested.id, nested.clone())]);
        let overlap = preflight_static(&[plan(&cask, 0), plan(&nested, 0)], &current);
        assert_eq!(overlap.ok.len(), 1, "{overlap:?}");
        assert_eq!(overlap.refused.len(), 1);
        assert!(overlap.refused[0].reason.contains("overlapping physical"));
        let confirmed = preflight_static(&[plan(&cask, 0)], &current);
        std::fs::rename(&binary, home.path().join("original-bin")).unwrap();
        std::fs::write(&binary, "replaced binary").unwrap();
        let runner = Arc::new(MockCommandRunner::new());
        let mut deps = deps_with(
            MockCommandRunner::new(),
            home.path(),
            Arc::new(FakeTrash(Mutex::new(Vec::new()))),
        );
        deps.runner = runner.clone();
        let (sender, _receiver) = mpsc::channel(64);
        let report =
            run_confirmed_batch(confirmed, current, deps, sender, CancellationToken::new()).await;
        assert!(report.executed.is_empty());
        assert_eq!(report.refused.len(), 1);
        assert!(report.refused[0].reason.contains("replaced"));
        assert!(runner.calls().is_empty());
        assert_eq!(std::fs::read_to_string(binary).unwrap(), "replaced binary");
    }

    #[tokio::test]
    async fn confirmed_cleanup_refuses_replaced_inode_and_preserves_both_files() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("fixture");
        let original = temporary.path().join("original");
        std::fs::write(&path, "original").unwrap();
        let finding = path_finding("fixture", &path);
        let current = [(finding.id, finding.clone())].into_iter().collect();
        let confirmed = preflight_static(&[plan(&finding, 0)], &current);
        assert_eq!(confirmed.ok.len(), 1);
        std::fs::rename(&path, &original).unwrap();
        std::fs::write(&path, "replacement").unwrap();
        let trash = Arc::new(FakeTrash(Mutex::new(Vec::new())));
        let deps = deps_with(MockCommandRunner::new(), temporary.path(), trash.clone());
        let (sender, _receiver) = mpsc::channel(64);
        let report =
            run_confirmed_batch(confirmed, current, deps, sender, CancellationToken::new()).await;
        assert!(report.executed.is_empty());
        assert!(report.refused[0]
            .reason
            .contains("physical cleanup target replaced"));
        assert!(trash.0.lock().unwrap().is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");
        assert_eq!(std::fs::read_to_string(&original).unwrap(), "original");
    }

    #[test]
    fn confirmation_refuses_redirected_parent_even_for_the_same_inode() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        std::fs::write(first.join("fixture"), "fixture").unwrap();
        std::fs::hard_link(first.join("fixture"), second.join("fixture")).unwrap();
        let alias = temporary.path().join("alias");
        std::os::unix::fs::symlink(&first, &alias).unwrap();
        let target = PhysicalTarget::capture(&alias.join("fixture")).unwrap();
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&second, &alias).unwrap();
        assert!(target.verify().unwrap_err().contains("replaced"));
    }

    #[test]
    fn cleanup_tracks_installation_referent_behind_a_stable_symlink() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("installation");
        std::fs::create_dir(&directory).unwrap();
        let alias = temporary.path().join("alias");
        std::os::unix::fs::symlink(&directory, &alias).unwrap();
        let finding = Finding::new(FindingKind::GlobalTool, "fixture", "fixture")
            .path(alias.clone())
            .remedy(
                Remedy::new(
                    "Uninstall",
                    RemedyCommand::Shell {
                        program: "fixture-manager".into(),
                        args: vec!["uninstall".into(), "fixture".into()],
                    },
                )
                .destructive()
                .guard(Guard::ToolInstall {
                    manager: "fixture".into(),
                    identity_key: "fixture".into(),
                    root: alias.clone(),
                    expected_version: None,
                    program_must_exist: None,
                }),
            );
        let targets = physical_targets(&plan(&finding, 0), &finding).unwrap();
        std::fs::rename(&directory, temporary.path().join("original")).unwrap();
        std::fs::create_dir(&directory).unwrap();
        assert!(PhysicalTarget::capture(&alias).unwrap().verify().is_ok());
        assert!(targets.iter().any(|target| target.verify().is_err()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cleanup_metadata_disables_materialization_and_restores_thread_policy() {
        extern "C" {
            fn getiopolicy_np(policy_type: libc::c_int, scope: libc::c_int) -> libc::c_int;
        }
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("fixture");
        std::fs::write(&path, "fixture").unwrap();
        let previous = unsafe { getiopolicy_np(3, 1) };
        assert!(previous >= 0);
        let target = protected_metadata(|| {
            assert_eq!(unsafe { getiopolicy_np(3, 1) }, 1);
            let target = PhysicalTarget::capture(&path)?;
            assert_eq!(unsafe { getiopolicy_np(3, 1) }, 1);
            Ok(target)
        })
        .unwrap();
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
        target.verify().unwrap();
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
        assert!(
            protected_metadata(|| PhysicalTarget::capture(&temporary.path().join("missing")))
                .is_err()
        );
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
    }

    #[tokio::test]
    async fn cleanup_rechecks_the_next_target_after_an_active_action() {
        struct ReplacingTrash {
            next: PathBuf,
            calls: Mutex<Vec<PathBuf>>,
        }
        impl TrashOps for ReplacingTrash {
            fn trash(&self, path: &Path) -> anyhow::Result<()> {
                let mut calls = self.calls.lock().unwrap();
                calls.push(path.to_path_buf());
                if calls.len() == 1 {
                    std::fs::rename(&self.next, self.next.with_extension("original"))?;
                    std::fs::write(&self.next, "replacement")?;
                }
                Ok(())
            }
        }
        let temporary = tempfile::tempdir().unwrap();
        let first_path = temporary.path().join("aaa");
        let second_path = temporary.path().join("bbb");
        std::fs::write(&first_path, "first").unwrap();
        std::fs::write(&second_path, "second").unwrap();
        let first = path_finding("first", &first_path);
        let second = path_finding("second", &second_path);
        let current = [first.clone(), second.clone()]
            .into_iter()
            .map(|finding| (finding.id, finding))
            .collect();
        let confirmed = preflight_static(&[plan(&first, 0), plan(&second, 0)], &current);
        let trash = Arc::new(ReplacingTrash {
            next: second_path,
            calls: Mutex::new(Vec::new()),
        });
        let mut deps = deps_with(
            MockCommandRunner::new(),
            temporary.path(),
            Arc::new(FakeTrash(Mutex::new(Vec::new()))),
        );
        deps.trash = trash.clone();
        let (sender, _receiver) = mpsc::channel(64);
        let report =
            run_confirmed_batch(confirmed, current, deps, sender, CancellationToken::new()).await;
        assert_eq!(report.executed.len(), 1);
        assert_eq!(report.refused.len(), 1);
        assert_eq!(trash.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn global_cleanup_outside_home_uses_confirmed_finding_targets() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = outside.path().join("global-fixture");
        std::fs::write(&path, "fixture").unwrap();
        let finding = path_finding("global-fixture", &path)
            .meta(serde_json::json!({"context": "audit_host"}));
        let current = [(finding.id, finding.clone())].into_iter().collect();
        let confirmed = preflight_static(&[plan(&finding, 0)], &current);
        let trash = Arc::new(FakeTrash(Mutex::new(Vec::new())));
        let deps = deps_with(MockCommandRunner::new(), home.path(), trash.clone());
        let (sender, _receiver) = mpsc::channel(64);
        let report =
            run_confirmed_batch(confirmed, current, deps, sender, CancellationToken::new()).await;
        assert_eq!(report.executed.len(), 1, "{report:?}");
        assert!(report.refused.is_empty());
        assert_eq!(*trash.0.lock().unwrap(), vec![path.clone()]);
        assert!(path.exists());
    }

    #[tokio::test]
    async fn refused_dependent_removal_blocks_its_dependency() {
        let home = tempfile::tempdir().unwrap();
        let app = brew_finding(home.path(), "app", true, &["lib"], &[]);
        let lib = brew_finding(home.path(), "lib", false, &[], &[]);
        let info = r#"{"formulae":[
            {"name":"app","full_name":"app","installed":[{"version":"2.0","runtime_dependencies":[{"full_name":"lib","declared_directly":true}]}],"linked_keg":"2.0"},
            {"name":"lib","full_name":"lib","installed":[{"version":"1.0","runtime_dependencies":[]}],"linked_keg":"1.0"}
        ],"casks":[]}"#;
        let deps = deps_with(
            MockCommandRunner::new().on("brew", &["info", "--json=v2", "--installed"], info),
            home.path(),
            Arc::new(FakeTrash(Mutex::new(Vec::new()))),
        );
        let (report, _) = preflight_refresh(
            &[plan(&app, 0), plan(&lib, 0)],
            &deps,
            &CancellationToken::new(),
        )
        .await;
        assert!(report.ok.is_empty(), "{report:?}");
        assert_eq!(report.refused.len(), 2);
        assert!(report
            .refused
            .iter()
            .any(|refused| refused.reason.contains("still needed by app")));
    }

    #[tokio::test]
    async fn failed_dependent_uninstall_never_executes_dependency_uninstall() {
        let home = tempfile::tempdir().unwrap();
        let app = brew_finding(home.path(), "app", true, &["lib"], &[]);
        let lib = brew_finding(home.path(), "lib", false, &[], &[]);
        let current = [app.clone(), lib.clone()]
            .into_iter()
            .map(|finding| (finding.id, finding))
            .collect();
        let info = r#"{"formulae":[
            {"name":"app","full_name":"app","installed":[{"version":"1.0","runtime_dependencies":[{"full_name":"lib","declared_directly":true}]}],"linked_keg":"1.0"},
            {"name":"lib","full_name":"lib","installed":[{"version":"1.0","runtime_dependencies":[]}],"linked_keg":"1.0"}
        ],"casks":[]}"#;
        let runner = Arc::new(
            MockCommandRunner::new()
                .on("brew", &["info", "--json=v2", "--installed"], info)
                .on_fail("brew", &["uninstall", "app"], 1, "fixture refusal"),
        );
        let mut deps = deps_with(
            MockCommandRunner::new(),
            home.path(),
            Arc::new(FakeTrash(Mutex::new(Vec::new()))),
        );
        deps.runner = runner.clone();
        let (sender, _receiver) = mpsc::channel(64);
        let confirmed = preflight_static(&[plan(&lib, 0), plan(&app, 0)], &current);
        let report =
            run_confirmed_batch(confirmed, current, deps, sender, CancellationToken::new()).await;
        assert_eq!(report.failed.len(), 1, "{report:?}");
        assert!(report.executed.is_empty());
        assert_eq!(report.refused.len(), 1);
        assert!(report.refused[0]
            .reason
            .contains("dependent removal did not complete"));
        assert!(!runner
            .calls()
            .iter()
            .any(|call| call == &["brew", "uninstall", "lib"]));
    }

    #[tokio::test]
    async fn dynamic_autoremove_is_refused_before_any_command_executes() {
        let home = tempfile::tempdir().unwrap();
        let finding = Finding::new(
            FindingKind::BrewFormula,
            "__autoremove__",
            "Homebrew autoremove candidates",
        )
        .meta(serde_json::json!({ "candidates": ["confirmed-library"] }))
        .remedy(
            Remedy::new(
                "Remove all unneeded dependencies",
                RemedyCommand::Shell {
                    program: "brew".into(),
                    args: vec!["autoremove".into()],
                },
            )
            .destructive(),
        );
        let actions = vec![plan(&finding, 0)];
        let current = BTreeMap::from([(finding.id, finding)]);
        let mut deps = deps_with(
            MockCommandRunner::new(),
            home.path(),
            Arc::new(FakeTrash(Mutex::new(Vec::new()))),
        );
        let runner = Arc::new(MockCommandRunner::new().on("brew", &["autoremove"], "removed"));
        deps.runner = runner.clone();
        let confirmed = preflight_static(&actions, &current);
        assert!(confirmed.ok.is_empty(), "{confirmed:?}");
        assert_eq!(confirmed.refused.len(), 1);
        assert!(confirmed.refused[0].reason.contains("dynamic targets"));
        let (fresh, _) = preflight_refresh(&actions, &deps, &CancellationToken::new()).await;
        assert!(fresh.ok.is_empty(), "{fresh:?}");
        assert_eq!(fresh.refused.len(), 1);
        let (sender, _receiver) = mpsc::channel(64);
        let report =
            run_confirmed_batch(confirmed, current, deps, sender, CancellationToken::new()).await;
        assert!(report.executed.is_empty());
        assert!(report.failed.is_empty());
        assert_eq!(report.refused.len(), 1);
        assert!(runner.calls().is_empty());
    }

    #[tokio::test]
    async fn actions_only_execution_never_recaptures_confirmation_or_runs_commands() {
        let home = tempfile::tempdir().unwrap();
        let finding = brew_finding(home.path(), "formula", true, &[], &[]);
        let actions = vec![plan(&finding, 0)];
        let current = BTreeMap::from([(finding.id, finding)]);
        assert_eq!(preflight_static(&actions, &current).ok.len(), 1);
        let runner =
            Arc::new(MockCommandRunner::new().on("brew", &["uninstall", "formula"], "removed"));
        let trash = Arc::new(FakeTrash(Mutex::new(Vec::new())));
        let mut deps = deps_with(MockCommandRunner::new(), home.path(), trash.clone());
        deps.runner = runner.clone();
        let (sender, _receiver) = mpsc::channel(64);
        let report = run_batch(actions, current, deps, sender, CancellationToken::new()).await;
        assert!(report.executed.is_empty());
        assert!(report.failed.is_empty());
        assert_eq!(report.refused.len(), 1);
        assert!(report.refused[0]
            .reason
            .contains("confirmation-time target snapshot"));
        assert!(runner.calls().is_empty());
        assert!(trash.0.lock().unwrap().is_empty());
    }

    #[test]
    fn affected_sections_cover_tools_shell_and_brew() {
        let f = Finding::new(FindingKind::BrewFormula, "wget", "wget").severity(Severity::Info);
        let mut current = BTreeMap::new();
        current.insert(f.id, f.clone());
        let a = PlannedAction {
            finding_id: f.id,
            label: "x".into(),
            command: RemedyCommand::Shell {
                program: "brew".into(),
                args: vec!["uninstall".into(), "wget".into()],
            },
            rendered: "brew uninstall wget".into(),
            destructive: true,
            reclaims_bytes: None,
            guard: Some(Guard::BrewFormula {
                full_name: "wget".into(),
                expected_version: None,
                require_no_retained_dependents: true,
            }),
        };
        let s = affected_sections(&[a], &current);
        assert!(s.contains(&crate::model::ScannerId::Brew));
        assert!(s.contains(&crate::model::ScannerId::Tools));
    }
}
