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
//! manager-native uninstalls, then launcher-only removals, with
//! `brew autoremove` last. Cancellation stops *between* actions — an
//! in-flight `brew uninstall` is never killed halfway. Afterwards the
//! inventory is captured again, `brew autoremove --dry-run` is re-run when
//! Homebrew changed, retained tools related to the batch get bounded
//! `--version` probes (run before and after, so a failure that already
//! existed is reported as pre-existing, not as a regression), and a JSON
//! report is written under `<state_dir>/cleanup-reports/`. Versions are
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
        let verdict: Result<(), String> = match &a.guard {
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
        };
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

pub fn write_report(paths: &Paths, report: &CleanupReport) -> anyhow::Result<PathBuf> {
    let dir = paths.state_dir.join("cleanup-reports");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", report.started_at));
    std::fs::write(&path, serde_json::to_vec_pretty(report)?)?;
    Ok(path)
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

/// Run a confirmed batch end to end, reporting progress on `tx`. `stop` is
/// checked between actions only.
pub async fn run_batch(
    actions: Vec<PlannedAction>,
    current: BTreeMap<FindingId, Finding>,
    deps: ExecDeps,
    tx: mpsc::Sender<ExecEvent>,
    stop: CancellationToken,
) -> CleanupReport {
    let started_at = now_secs();
    let token = CancellationToken::new();
    let (mut report, graph_before) = preflight_refresh(&actions, &deps, &token).await;
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
        let _ = tx.send(ExecEvent::ActionStarted(i)).await;
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

    let mut out = CleanupReport {
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
    if deps.config.tools.write_cleanup_reports {
        out.audit_path = write_report(&deps.paths, &out).ok();
    }
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

    fn brew_finding(name: &str, on_request: bool, deps: &[&str], dependents: &[&str]) -> Finding {
        let mut f = Finding::new(FindingKind::BrewFormula, name, name).meta(serde_json::json!({
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
        // app (requested) → lib (dependency); app2 (requested) → lib.
        let app = brew_finding("app", true, &["lib"], &[]);
        let app2 = brew_finding("app2", true, &["lib"], &[]);
        let mut lib = brew_finding("lib", false, &[], &["app", "app2"]);
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
        let wget = brew_finding("wget", true, &[], &[]);
        let broken = brew_finding("broken", true, &[], &[]);
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
        let report = run_batch(actions, current, deps, tx, CancellationToken::new()).await;
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
        assert!(report.audit_path.as_ref().unwrap().exists());
        let json: Value =
            serde_json::from_slice(&std::fs::read(report.audit_path.as_ref().unwrap()).unwrap())
                .unwrap();
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
        let report = run_batch(vec![plan(&wget, 0)], BTreeMap::new(), deps, tx, stop).await;
        assert_eq!(report.cancelled.len(), 1);
        assert!(report.executed.is_empty());
        assert!(trash2.0.lock().unwrap().is_empty());
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
