//! Global developer-tool audit: what is installed by npm, pnpm, cargo, pipx,
//! uv, pip and bun; which manager owns each copy; which executable the user's
//! login shell actually runs; and what evidence supports keeping or removing
//! each installation.
//!
//! Scans are filesystem-metadata-first: the only subprocesses are one login
//! shell probe for `$PATH` (plus `dscl` to find that shell) and an optional
//! `npm prefix -g`. Discovered binaries are never executed and Python modules
//! are never imported. Each manager probe degrades independently: a missing
//! manager is `absent`, malformed metadata is `partial`, and neither aborts
//! the section.
//!
//! Findings: one `GlobalTool` per installation (keyed
//! `{manager}:{root}:{name}` so two copies of one package stay distinct and
//! stable across snapshots), one `CommandResolution` per exported command
//! name (login shell vs this process), and one `ToolCoverage` row.

pub mod bun;
pub mod cargo;
pub mod flatyaml;
pub mod history;
pub mod launchers;
pub mod npm;
pub mod pipx;
pub mod pnpm;
pub mod projects;
pub mod pymeta;
pub mod python;
pub mod shellpath;
pub mod types;
pub mod util;
pub mod uv;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::config::{Paths, ToolsConfig};
use crate::model::{Finding, FindingKind, Guard, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::{run_with_timeout, ScanCtx, Scanner};
use shellpath::ShellPath;
use types::*;

/// Everything a manager probe may look at. Probes are synchronous, pure
/// functions of this context (run inside `spawn_blocking`).
pub struct ProbeCtx<'a> {
    pub paths: &'a Paths,
    pub config: &'a ToolsConfig,
    pub shell: &'a ShellPath,
    /// Homebrew prefix with a `Cellar/`, when present.
    pub brew_prefix: Option<PathBuf>,
    /// Extra npm prefixes reported by `npm prefix -g`.
    pub extra_npm_prefixes: Vec<PathBuf>,
}

#[derive(Default)]
pub struct ToolsScanner;

/// Run every manager probe. Pure (filesystem only).
pub fn run_probes(cx: &ProbeCtx) -> Vec<(Manager, ProbeResult)> {
    vec![
        (Manager::Npm, npm::probe(cx)),
        (Manager::Pnpm, pnpm::probe(cx)),
        (Manager::Cargo, cargo::probe(cx)),
        (Manager::Bun, bun::probe(cx)),
        (Manager::Pipx, pipx::probe(cx)),
        (Manager::Uv, uv::probe(cx)),
        (Manager::Pip, python::probe(cx)),
    ]
}

/// One installation after cross-installation analysis.
pub struct Assembled {
    pub install: ToolInstall,
    pub resolution: BTreeMap<String, Resolution>,
    pub classifications: Vec<Classification>,
    pub project_refs: Vec<Value>,
    pub history: Option<Value>,
}

/// Does the globally installed version satisfy a project's declared range?
/// `None` when either side is missing or not comparable.
pub fn range_satisfied(
    manager: Manager,
    installed: Option<&str>,
    declared: Option<&str>,
) -> Option<bool> {
    let installed = installed?;
    let declared = declared?;
    match manager {
        Manager::Npm | Manager::Pnpm | Manager::Bun => {
            let range: node_semver::Range = declared.parse().ok()?;
            let v: node_semver::Version = installed.parse().ok()?;
            Some(range.satisfies(&v))
        }
        Manager::Cargo => {
            let req = semver::VersionReq::parse(declared).ok()?;
            let v = semver::Version::parse(installed).ok()?;
            Some(req.matches(&v))
        }
        _ => {
            // Exact pins only (bootstrap scripts, .tool-versions).
            let d = declared.trim_start_matches(['=', 'v']);
            d.chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
                .then(|| d == installed)
        }
    }
}

/// A command name's resolution across the shell and the process.
pub struct CommandView {
    pub command: String,
    pub user_shell: Option<PathBuf>,
    pub process: Option<PathBuf>,
    /// `None` when the login-shell PATH is unavailable.
    pub differs: Option<bool>,
    pub candidates: Vec<(Candidate, Option<String>)>,
}

fn install_owns(t: &ToolInstall, path: &Path) -> bool {
    let (_, last, _) = launchers::follow_chain(path);
    if t.launchers
        .iter()
        .any(|l| l.path == path || l.target.as_deref() == Some(&last))
    {
        return true;
    }
    if let Some(dir) = &t.install_dir {
        if launchers::under(&last, dir) {
            return true;
        }
    }
    if launchers::under(&last, &t.root) && t.manager != Manager::Pip {
        return true;
    }
    false
}

fn owner_of(
    path: &Path,
    installs: &[ToolInstall],
    me: Option<usize>,
) -> (Ownership, Option<String>) {
    if let Some(i) = me {
        if install_owns(&installs[i], path) {
            return (Ownership::ThisInstall, Some(installs[i].identity_key()));
        }
    }
    for (i, t) in installs.iter().enumerate() {
        if Some(i) == me {
            continue;
        }
        if install_owns(t, path) {
            return (
                Ownership::OtherTool {
                    manager: t.manager.slug().to_string(),
                    identity_key: t.identity_key(),
                },
                Some(t.identity_key()),
            );
        }
    }
    let (_, last, _) = launchers::follow_chain(path);
    if let Some(o) = launchers::owner_from_path(&last).or_else(|| launchers::owner_from_path(path))
    {
        return (o, None);
    }
    if path.to_string_lossy().contains("/Library/pnpm/") {
        return (Ownership::PnpmHome, None);
    }
    (Ownership::Unknown, None)
}

/// Cross-installation analysis: command resolution against both PATHs,
/// duplicate/shadow detection, and evidence-ranked classification.
pub fn assemble(
    installs: Vec<ToolInstall>,
    shell: &ShellPath,
    projects: &projects::ProjectIndex,
    history: Option<&BTreeMap<String, history::HistoryStat>>,
) -> (Vec<Assembled>, Vec<CommandView>) {
    let mut by_cmd: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, t) in installs.iter().enumerate() {
        for c in t.command_names() {
            by_cmd.entry(c).or_default().push(i);
        }
    }
    let mut views: BTreeMap<String, CommandView> = BTreeMap::new();
    let mut out = Vec::new();
    for (i, t) in installs.iter().enumerate() {
        let mut resolution = BTreeMap::new();
        let mut classes: Vec<Classification> = Vec::new();
        let mut shadowed: Option<(PathBuf, Ownership)> = None;
        for cmd in t.command_names() {
            let shell_hit = shell
                .shell_path
                .as_deref()
                .and_then(|p| shellpath::resolve_first(&cmd, p));
            let process_hit = shellpath::resolve_first(&cmd, &shell.process_path);
            let mut cands: Vec<PathBuf> = Vec::new();
            if let Some(p) = &shell.shell_path {
                cands.extend(shellpath::resolve_all(&cmd, p));
            }
            cands.extend(shellpath::resolve_all(&cmd, &shell.process_path));
            let mut seen = BTreeSet::new();
            let candidates: Vec<Candidate> = cands
                .into_iter()
                .filter(|c| seen.insert(c.clone()))
                .map(|c| {
                    let (owner, _) = owner_of(&c, &installs, Some(i));
                    let (first, _, _) = launchers::follow_chain(&c);
                    Candidate {
                        path: c,
                        target: first,
                        owner,
                    }
                })
                .collect();
            let mine = |p: &PathBuf| install_owns(t, p);
            let (status, shadow) = match (&shell.shell_path, &shell_hit, &process_hit) {
                (Some(_), Some(h), _) if mine(h) => (PathStatus::Active, None),
                (Some(_), Some(h), _) => (PathStatus::Shadowed, Some(h.clone())),
                (Some(_), None, _) => (PathStatus::NotOnPath, None),
                (None, _, Some(h)) if mine(h) => (PathStatus::ActiveInProcessOnly, None),
                (None, _, Some(h)) => (PathStatus::Shadowed, Some(h.clone())),
                (None, _, None) => (PathStatus::NotOnPath, None),
            };
            if let Some(by) = &shadow {
                if shadowed.is_none() {
                    let (owner, _) = owner_of(by, &installs, Some(i));
                    shadowed = Some((by.clone(), owner));
                }
            }
            resolution.insert(
                cmd.clone(),
                Resolution {
                    user_shell: shell_hit.clone(),
                    process: process_hit.clone(),
                    status,
                    shadowed_by: shadow,
                    candidates: candidates.clone(),
                },
            );
            views.entry(cmd.clone()).or_insert_with(|| CommandView {
                command: cmd.clone(),
                user_shell: shell_hit.clone(),
                process: process_hit.clone(),
                differs: shell.shell_path.as_ref().map(|_| shell_hit != process_hit),
                candidates: candidates
                    .into_iter()
                    .map(|c| {
                        let (_, key) = owner_of(&c.path, &installs, None);
                        (c, key)
                    })
                    .collect(),
            });
        }
        // Broken: dangling launcher, missing interpreter, missing binary.
        let dangling: Vec<String> = t
            .launchers
            .iter()
            .filter(|l| l.target_exists == Some(false))
            .map(|l| util::file_name(&l.path))
            .collect();
        if !dangling.is_empty() {
            classes.push(Classification::Broken {
                reason: format!(
                    "launcher(s) point at a missing target: {}",
                    dangling.join(", ")
                ),
            });
        }
        if let Some(rt) = &t.runtime {
            if rt.exists == Some(false) {
                classes.push(Classification::Broken {
                    reason: format!(
                        "{} interpreter/runtime missing: {}",
                        rt.kind,
                        rt.path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "(unknown)".into())
                    ),
                });
            }
        }
        if t.manager == Manager::Cargo && !t.commands.is_empty() && t.launchers.is_empty() {
            classes.push(Classification::Broken {
                reason: "installed binaries are missing from cargo's bin dir".into(),
            });
        }
        // Required / protected.
        let required_by: Vec<String> = t
            .manager_extra
            .get("required_by")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if !required_by.is_empty() {
            classes.push(Classification::Required { by: required_by });
        } else if let Some(p) = &t.protected {
            classes.push(Classification::Required {
                by: vec![p.clone()],
            });
        }
        // Duplicate: another installation provides the same command.
        let mut peers: BTreeSet<String> = BTreeSet::new();
        for cmd in t.command_names() {
            for &j in by_cmd.get(&cmd).into_iter().flatten() {
                if j != i && installs[j].manager != Manager::Pip {
                    peers.insert(installs[j].identity_key());
                }
            }
        }
        if !peers.is_empty() && t.manager != Manager::Pip {
            classes.push(Classification::Duplicate {
                peers: peers.into_iter().collect(),
            });
        }
        if let Some((by, owner)) = shadowed {
            classes.push(Classification::Shadowed { by, owner });
        }
        // Project evidence: declarations are evidence; an *installed* local
        // copy (binary present) is an alternative.
        let mut names = t.command_names();
        names.push(t.name.clone());
        let refs = projects.refs_for(&names);
        let mut alt_projects: BTreeSet<String> = BTreeSet::new();
        let project_refs: Vec<Value> = refs
            .iter()
            .map(|r| {
                let installed_alt = r.local_binary.as_ref().map(|b| b.exists).unwrap_or(false);
                if installed_alt {
                    alt_projects.insert(r.project.display().to_string());
                }
                let satisfied = range_satisfied(
                    t.manager,
                    t.version.as_deref(),
                    r.declared_version.as_deref(),
                );
                let mut v = serde_json::to_value(r).unwrap_or(Value::Null);
                if let Some(o) = v.as_object_mut() {
                    o.insert("global_satisfies_declaration".into(), json!(satisfied));
                    o.insert("installed_alternative".into(), json!(installed_alt));
                }
                v
            })
            .collect();
        if !alt_projects.is_empty() {
            classes.push(Classification::ProjectAlternative {
                projects: alt_projects.into_iter().collect(),
            });
        }
        let hist = history.map(|h| {
            let mut m = serde_json::Map::new();
            for n in &names {
                if let Some(st) = h.get(n) {
                    m.insert(n.clone(), serde_json::to_value(st).unwrap_or(Value::Null));
                }
            }
            Value::Object(m)
        });
        if classes.is_empty() {
            classes.push(Classification::Review {
                reason: "no evidence that it is broken, duplicated, shadowed, or required; global installs are not unnecessary by default".into(),
            });
        }
        classes.sort_by_key(|c| c.rank());
        out.push(Assembled {
            install: t.clone(),
            resolution,
            classifications: classes,
            project_refs,
            history: hist,
        });
    }
    (out, views.into_values().collect())
}

fn abbrev(home: &Path, p: &Path) -> String {
    match p.strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => p.display().to_string(),
    }
}

fn group_label(home: &Path, t: &ToolInstall) -> String {
    match (t.manager, &t.layout) {
        (Manager::Pip, Some(layout)) | (Manager::Pnpm, Some(layout)) => {
            format!("{} ({layout})", t.manager.slug())
        }
        (Manager::Npm, _) => {
            let prefix = t
                .manager_extra
                .get("prefix")
                .and_then(|p| p.as_str())
                .map(|p| abbrev(home, Path::new(p)))
                .unwrap_or_else(|| abbrev(home, &t.root));
            format!("npm ({prefix})")
        }
        _ => format!("{} ({})", t.manager.slug(), abbrev(home, &t.root)),
    }
}

fn remedies_for(a: &Assembled, config: &ToolsConfig) -> Vec<Remedy> {
    let t = &a.install;
    let key = t.identity_key();
    let mut out = Vec::new();
    let broken = a
        .classifications
        .iter()
        .any(|c| matches!(c, Classification::Broken { .. }));
    if t.protected.is_none() {
        if let Some(native) = &t.removal.native {
            let guard = if t.manager == Manager::Pip {
                Guard::PipPackage {
                    site: t.root.clone(),
                    name: t.name.clone(),
                    interpreter: t
                        .runtime
                        .as_ref()
                        .and_then(|r| r.path.clone())
                        .unwrap_or_default(),
                }
            } else {
                Guard::ToolInstall {
                    manager: t.manager.slug().to_string(),
                    identity_key: key.clone(),
                    root: t.root.clone(),
                    expected_version: t.version.clone(),
                    program_must_exist: native.program_path.clone(),
                }
            };
            out.push(
                Remedy::new(
                    format!("Uninstall via {}", t.manager.slug()),
                    RemedyCommand::Shell {
                        program: native.program.clone(),
                        args: native.args.clone(),
                    },
                )
                .destructive()
                .reclaims(t.size_bytes)
                .guard(guard),
            );
        }
        let native_present = t.removal.native.is_some();
        for path in &t.removal.launcher_only {
            let l = t.launchers.iter().find(|l| &l.path == path);
            let mut r = Remedy::new(
                format!("Remove launcher {} only", util::file_name(path)),
                RemedyCommand::Trash { path: path.clone() },
            )
            .destructive()
            .guard(Guard::Launcher {
                path: path.clone(),
                expected_target: l.and_then(|l| l.target.clone()),
                expect_dangling: l.map(|l| l.target_exists == Some(false)).unwrap_or(false),
                owner_key: key.clone(),
            });
            // Launcher-only removal is the primary action only when the
            // package itself is gone (dangling) and nothing native exists.
            if native_present || !broken {
                r = r.alternative();
            }
            out.push(r);
        }
        if let Some(cmd) = &t.removal.suggested_command {
            out.push(Remedy::new(
                "Copy uninstall command (not run by MacAudit)",
                RemedyCommand::CopyToClipboard { text: cmd.clone() },
            ));
        }
    }
    for l in &t.launchers {
        if l.target_exists != Some(false) {
            out.push(
                Remedy::new(
                    format!("Verify {} (--version)", util::file_name(&l.path)),
                    RemedyCommand::Probe {
                        program: l.path.display().to_string(),
                        args: vec!["--version".into()],
                        timeout_secs: config.verify_timeout_secs,
                    },
                )
                .alternative(),
            );
        }
    }
    out
}

fn install_finding(
    home: &Path,
    a: &Assembled,
    config: &ToolsConfig,
    project_coverage: &Value,
) -> Finding {
    let t = &a.install;
    let primary = a
        .classifications
        .first()
        .expect("at least one classification");
    let severity = match primary {
        Classification::Broken { .. }
        | Classification::Duplicate { .. }
        | Classification::Shadowed { .. } => Severity::Attention,
        Classification::Orphan { .. } => Severity::Reclaimable,
        _ => Severity::Info,
    };
    let summary = match primary {
        Classification::Broken { reason } => reason.clone(),
        Classification::Duplicate { peers } => format!("also provided by {}", peers.join(", ")),
        Classification::Shadowed { by, .. } => {
            format!("{} wins command resolution", abbrev(home, by))
        }
        Classification::ProjectAlternative { projects } => {
            format!("project-managed copy in {}", projects.join(", "))
        }
        Classification::Required { by } => format!("required by {}", by.join(", ")),
        Classification::Orphan { confirmed_by } => format!("no longer needed ({confirmed_by})"),
        Classification::Review { reason } => reason.clone(),
    };
    let detail = format!(
        "{} — {}{}",
        primary.slug().replace('_', "-"),
        summary,
        if t.completeness.level == "full" {
            ""
        } else {
            " (partial metadata)"
        }
    );
    let mut meta = serde_json::to_value(t).unwrap_or(Value::Null);
    if let Some(obj) = meta.as_object_mut() {
        obj.insert("identity_key".into(), json!(t.identity_key()));
        obj.insert(
            "resolution".into(),
            serde_json::to_value(&a.resolution).unwrap_or(Value::Null),
        );
        obj.insert(
            "classifications".into(),
            serde_json::to_value(&a.classifications).unwrap_or(Value::Null),
        );
        obj.insert("primary_classification".into(), json!(primary.slug()));
        obj.insert("project_refs".into(), Value::Array(a.project_refs.clone()));
        obj.insert("project_coverage".into(), project_coverage.clone());
        obj.insert("history".into(), a.history.clone().unwrap_or(Value::Null));
        obj.insert("group".into(), json!(group_label(home, t)));
    }
    let mut f = Finding::new(FindingKind::GlobalTool, &t.identity_key(), t.name.clone())
        .detail(detail)
        .severity(severity)
        .provenance(format!(
            "{} metadata + launcher inspection; command resolution via login shell PATH",
            t.manager.slug()
        ))
        .meta(meta);
    if let Some(dir) = t.install_dir.clone().or_else(|| Some(t.root.clone())) {
        f = f.path(dir);
    }
    if let Some(size) = t.size_bytes {
        f = f.size(size);
    }
    if t.completeness.level != "full" {
        f = f.coverage(t.completeness.missing.join("; "));
    }
    for r in remedies_for(a, config) {
        f = f.remedy(r);
    }
    f
}

fn command_finding(home: &Path, shell: &ShellPath, v: &CommandView) -> Finding {
    let differs = v.differs.unwrap_or(false);
    let shell_name = shell.shell_name().unwrap_or("login shell");
    let detail = match (&v.user_shell, &v.process, v.differs) {
        (Some(s), Some(p), Some(true)) => format!(
            "{shell_name} runs {} but this process resolves {}",
            abbrev(home, s),
            abbrev(home, p)
        ),
        (Some(s), None, Some(true)) => format!(
            "{shell_name} runs {}; this process cannot resolve it",
            abbrev(home, s)
        ),
        (None, Some(p), Some(true)) => format!(
            "not on the {shell_name} PATH; this process resolves {}",
            abbrev(home, p)
        ),
        (Some(s), _, _) => format!("{shell_name} and this process both run {}", abbrev(home, s)),
        (None, Some(p), _) => format!(
            "login-shell PATH unavailable; this process resolves {}",
            abbrev(home, p)
        ),
        (None, None, _) => "not resolvable on either PATH".to_string(),
    };
    let mut f = Finding::new(FindingKind::CommandResolution, &v.command, v.command.clone())
        .detail(detail)
        .severity(if differs { Severity::Attention } else { Severity::Info })
        .provenance(if shell.shell_path.is_some() {
            format!("{} (starting the login shell runs its startup files); process PATH", shell.source)
        } else {
            "process PATH only".to_string()
        })
        .meta(json!({
            "command": v.command,
            "user_shell": shell.login_shell.as_ref().map(|p| json!({ "shell": shell.shell_name(), "path": p })),
            "user_resolution": v.user_shell,
            "process_resolution": v.process,
            "differs": v.differs,
            "candidates": v.candidates.iter().map(|(c, key)| json!({ "path": c.path, "target": c.target, "owner": c.owner, "installation": key })).collect::<Vec<_>>(),
            "group": "Command resolution",
        }));
    if let Some(p) = v.user_shell.clone().or_else(|| v.process.clone()) {
        f = f.path(p);
    }
    f
}

fn coverage_finding(
    shell: &ShellPath,
    statuses: &[(Manager, Option<ManagerStatus>)],
    projects: &Value,
    history_enabled: bool,
) -> Finding {
    let mut managers = serde_json::Map::new();
    let mut parts = Vec::new();
    for (m, st) in statuses {
        let st = st.clone().unwrap_or(ManagerStatus::Absent);
        parts.push(format!(
            "{} {}",
            m.slug(),
            match &st {
                ManagerStatus::Ok { .. } => "ok",
                ManagerStatus::Absent => "absent",
                ManagerStatus::Partial { .. } => "partial",
                ManagerStatus::Failed { .. } => "failed",
            }
        ));
        managers.insert(
            m.slug().to_string(),
            serde_json::to_value(st).unwrap_or(Value::Null),
        );
    }
    let shell_summary = match (&shell.login_shell, &shell.shell_path) {
        (Some(s), Some(p)) => format!(
            "{} PATH read ({} entries)",
            shell.shell_name().unwrap_or(&s.display().to_string()),
            p.len()
        ),
        (Some(s), None) => format!("{} PATH unavailable; process PATH used", s.display()),
        (None, _) => "login shell unknown; process PATH used".to_string(),
    };
    Finding::new(
        FindingKind::ToolCoverage,
        "__coverage__",
        "Global tools coverage",
    )
    .detail(format!("{} · {shell_summary}", parts.join(" · ")))
    .severity(Severity::Info)
    .provenance(format!(
        "filesystem metadata; {}",
        if shell.shell_path.is_some() {
            shell.source.clone()
        } else {
            "process PATH".into()
        }
    ))
    .coverage(format!(
        "{}{}",
        shellpath::DISCLOSURE,
        if history_enabled {
            " Shell history evidence: aggregated counts only."
        } else {
            " Shell history evidence disabled."
        }
    ))
    .meta(json!({
        "managers": managers,
        "shell": {
            "login_shell": shell.login_shell,
            "source": shell.source,
            "entries": shell.shell_path.as_ref().map(|p| p.len()),
            "process_entries": shell.process_path.len(),
            "notes": shell.notes,
            "disclosure": shellpath::DISCLOSURE,
        },
        "projects": projects,
        "history": { "enabled": history_enabled },
        "group": "Coverage",
    }))
}

#[async_trait]
impl Scanner for ToolsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Tools
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        ctx.progress("login shell PATH", 0, None).await;
        let shell = shellpath::detect(&ctx).await;
        let config = ctx.config.tools.clone();
        let brew_prefix = config
            .homebrew_prefix
            .as_ref()
            .map(|p| ctx.paths.expand(p))
            .filter(|p| p.join("Cellar").is_dir() || p.join("lib").is_dir())
            .or_else(crate::scan::brew::brew_prefix);
        // `npm prefix -g` is just one more candidate prefix; a missing npm
        // costs nothing.
        let mut extra_npm_prefixes = Vec::new();
        if let Some(out) =
            run_with_timeout(&ctx, "npm", &["prefix", "-g"], Duration::from_secs(10)).await
        {
            let line = out.stdout_str().trim().to_string();
            if !line.is_empty() {
                extra_npm_prefixes.push(PathBuf::from(line));
            }
        }
        ctx.progress("manager metadata", 1, None).await;
        let paths = ctx.paths.clone();
        let shell_for_probe = shell.clone();
        let cfg = config.clone();
        let home_for_probe = ctx.paths.home.clone();
        let (results, project_index, history) = tokio::task::spawn_blocking(move || {
            let cx = ProbeCtx {
                paths: &paths,
                config: &cfg,
                shell: &shell_for_probe,
                brew_prefix,
                extra_npm_prefixes,
            };
            let results = run_probes(&cx);
            let index = projects::index(&cx);
            let history = cfg.shell_history_evidence.then(|| {
                let known: BTreeSet<String> = results
                    .iter()
                    .flat_map(|(_, r)| r.installs.iter().flat_map(|t| t.command_names()))
                    .collect();
                history::aggregate(&home_for_probe, &known)
            });
            (results, index, history)
        })
        .await
        .unwrap_or_else(|_| (Vec::new(), projects::ProjectIndex::default(), None));
        if ctx.cancelled() {
            return Ok(());
        }
        let statuses: Vec<(Manager, Option<ManagerStatus>)> = results
            .iter()
            .map(|(m, r)| (*m, r.status.clone()))
            .collect();
        let installs: Vec<ToolInstall> =
            results.into_iter().flat_map(|(_, r)| r.installs).collect();
        ctx.progress("command resolution + project evidence", 2, None)
            .await;
        let shell_c = shell.clone();
        let project_coverage = project_index.coverage_json();
        let (assembled, views) = tokio::task::spawn_blocking(move || {
            assemble(installs, &shell_c, &project_index, history.as_ref())
        })
        .await
        .unwrap_or_else(|_| (Vec::new(), Vec::new()));
        let total = (assembled.len() + views.len()) as u64;
        let mut done = 0u64;
        let home = ctx.paths.home.clone();
        for a in &assembled {
            if ctx.cancelled() {
                return Ok(());
            }
            done += 1;
            ctx.progress(
                format!("{} {}", a.install.manager.slug(), a.install.name),
                done,
                Some(total),
            )
            .await;
            ctx.emit(install_finding(&home, a, &config, &project_coverage))
                .await;
        }
        for v in &views {
            ctx.emit(command_finding(&home, &shell, v)).await;
        }
        ctx.emit(coverage_finding(
            &shell,
            &statuses,
            &project_coverage,
            config.shell_history_evidence,
        ))
        .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanEvent;
    use crate::runner::MockCommandRunner;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    fn exe(p: &Path) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A HOME mirroring the audited Mac across every manager.
    fn mk_home(home: &Path) -> PathBuf {
        let prefix = home.join("opt/homebrew");
        npm::tests::mk_prefix(&prefix);
        pnpm::tests::mk_pnpm_home(&home.join("Library/pnpm"));
        cargo::tests::mk_cargo_home(&home.join(".cargo"));
        let py13 = home.join("opt/python@3.13/bin/python3.13");
        pipx::tests::mk_pipx_venv(home, "rendercv", "1.17.0", &["rendercv"], &py13, false);
        pipx::tests::mk_pipx_venv(home, "mcp-proxy", "0.11.0", &["mcp-proxy"], &py13, false);
        uv::tests::mk_uv_tool(
            home,
            "mcp-proxy",
            "0.12.0",
            &[("mcp-proxy", true), ("mcp-reverse-proxy", false)],
            &prefix.join("opt/python@3.14/bin"),
        );
        python::tests::mk_brew_python(&prefix);
        projects::tests::mk_projects(&home.join("dev"));
        // Cask-owned codex launcher shadowing npm's codex in the shell PATH.
        let cask_bin = prefix.join("Caskroom/codex/0.153.4/bin/codex");
        exe(&cask_bin);
        std::fs::remove_file(prefix.join("bin/codex")).unwrap();
        std::os::unix::fs::symlink(&cask_bin, prefix.join("bin/codex")).unwrap();
        // npm's wasm-pack 0.13.1 wins over cargo's 0.14.0 in the shell PATH.
        prefix
    }

    fn shell_for(home: &Path, prefix: &Path) -> ShellPath {
        ShellPath {
            login_shell: Some(PathBuf::from("/opt/homebrew/bin/fish")),
            shell_path: Some(vec![
                home.join("Library/pnpm/bin"),
                home.join(".local/bin"),
                prefix.join("bin"),
                home.join(".cargo/bin"),
            ]),
            process_path: vec![
                home.join("Library/pnpm"),
                prefix.join("bin"),
                home.join(".cargo/bin"),
            ],
            source: "fish -lc 'string join : $PATH'".into(),
            notes: vec![],
        }
    }

    #[test]
    fn assemble_detects_duplicates_shadowing_and_shell_process_differences() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let prefix = mk_home(home);
        let paths = Paths::from_home(home);
        let config = ToolsConfig {
            include_apple_python: false,
            homebrew_prefix: Some(prefix.display().to_string()),
            ..Default::default()
        };
        let shell = shell_for(home, &prefix);
        let cx = ProbeCtx {
            paths: &paths,
            config: &config,
            shell: &shell,
            brew_prefix: Some(prefix.clone()),
            extra_npm_prefixes: vec![],
        };
        let installs: Vec<ToolInstall> = run_probes(&cx)
            .into_iter()
            .flat_map(|(_, r)| r.installs)
            .collect();
        let idx = projects::index_roots(&[home.join("dev")], 4, Duration::from_secs(5));
        let (assembled, views) = assemble(installs, &shell, &idx, None);
        let find = |m: Manager, n: &str| {
            assembled
                .iter()
                .find(|a| a.install.manager == m && a.install.name == n)
                .unwrap_or_else(|| panic!("{n}"))
        };

        // npm codex: the cask binary wins in the shell → shadowed by a cask.
        let codex = find(Manager::Npm, "@openai/codex");
        assert_eq!(codex.resolution["codex"].status, PathStatus::Shadowed);
        assert!(
            matches!(codex.classifications[0], Classification::Shadowed { owner: Ownership::HomebrewCask { ref token }, .. } if token == "codex")
        );

        // wasm-pack: npm and cargo both provide it; npm's copy is first on
        // the shell PATH so cargo's is shadowed by the npm install.
        let cargo_wp = find(Manager::Cargo, "wasm-pack");
        let npm_wp = find(Manager::Npm, "wasm-pack");
        assert!(cargo_wp.classifications.iter().any(|c| matches!(c, Classification::Duplicate { peers } if peers.contains(&npm_wp.install.identity_key()))));
        assert!(cargo_wp.classifications.iter().any(|c| matches!(c, Classification::Shadowed { owner: Ownership::OtherTool { ref manager, .. }, .. } if manager == "npm")));
        assert_eq!(npm_wp.resolution["wasm-pack"].status, PathStatus::Active);

        // pnpm wrangler resolves in fish but not in the process PATH.
        let wr = find(Manager::Pnpm, "wrangler");
        assert_eq!(wr.resolution["wrangler"].status, PathStatus::Active);
        assert!(wr.resolution["wrangler"].process.is_none());
        let view = views.iter().find(|v| v.command == "wrangler").unwrap();
        assert_eq!(view.differs, Some(true));

        // Dangling pn/pnpx launchers → broken; pipx venvs on a removed
        // python → broken; uv mcp-proxy shares a command with pipx's copy.
        assert!(matches!(
            find(Manager::Npm, "pnpm").classifications[0],
            Classification::Broken { .. }
        ));
        assert!(matches!(
            find(Manager::Pipx, "rendercv").classifications[0],
            Classification::Broken { .. }
        ));
        let uv_mp = find(Manager::Uv, "mcp-proxy");
        assert!(uv_mp
            .classifications
            .iter()
            .any(|c| matches!(c, Classification::Duplicate { .. })));
        assert_eq!(uv_mp.resolution["mcp-proxy"].status, PathStatus::Active);
        let pipx_mp = find(Manager::Pipx, "mcp-proxy");
        assert_eq!(pipx_mp.resolution["mcp-proxy"].status, PathStatus::Shadowed);
        assert!(pipx_mp.resolution["mcp-proxy"].shadowed_by.is_some());

        // Project evidence: cubby has knip installed locally → the (fake)
        // global knip would be a project alternative; playwright is only
        // declared. Checked via a synthetic npm install of each.
        let ga_refs = &find(Manager::Pip, "google_auth").project_refs;
        assert!(ga_refs.is_empty());

        // Homebrew-owned python package is required (by requests) and stays protected.
        let certifi = find(Manager::Pip, "certifi");
        assert!(matches!(
            certifi.classifications[0],
            Classification::Required { .. }
        ));
        // A plain manual pip install with no other evidence is Review, not
        // reclaimable.
        let ga = find(Manager::Pip, "google_auth");
        assert!(matches!(
            ga.classifications[0],
            Classification::Review { .. }
        ));
    }

    #[test]
    fn project_alternative_requires_an_installed_local_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let dev = tmp.path().join("dev");
        projects::tests::mk_projects(&dev);
        let idx = projects::index_roots(std::slice::from_ref(&dev), 4, Duration::from_secs(5));
        let mk = |name: &str, version: &str| {
            let mut t = ToolInstall::new(
                Manager::Npm,
                tmp.path().join("prefix/lib/node_modules"),
                name,
            );
            t.version = Some(version.into());
            t.commands.push(DeclaredCommand {
                name: name.into(),
                declared_target: None,
            });
            t
        };
        let shell = ShellPath::default();
        let (assembled, _) = assemble(
            vec![mk("knip", "6.30.0"), mk("playwright", "1.62.1")],
            &shell,
            &idx,
            None,
        );
        let knip = &assembled[0];
        assert!(
            matches!(&knip.classifications[0], Classification::ProjectAlternative { projects } if projects[0].ends_with("cubby"))
        );
        let dev_ref = knip
            .project_refs
            .iter()
            .find(|r| r["kind"] == "dev_dependency")
            .unwrap();
        assert_eq!(dev_ref["installed_alternative"], true);
        assert_eq!(dev_ref["local_binary"]["version"], "6.32.0");
        // 6.30.0 does not satisfy ^6.32.0.
        assert_eq!(dev_ref["global_satisfies_declaration"], false);

        // playwright is declared but has no local binary: evidence only.
        let pw = &assembled[1];
        assert!(matches!(
            pw.classifications[0],
            Classification::Review { .. }
        ));
        assert!(!pw.project_refs.is_empty());
        assert!(pw
            .project_refs
            .iter()
            .all(|r| r["installed_alternative"] == false));
        assert_eq!(
            range_satisfied(Manager::Npm, Some("1.62.1"), Some("^1.62.1")),
            Some(true)
        );
        assert_eq!(
            range_satisfied(Manager::Cargo, Some("0.14.0"), Some("^0.13")),
            Some(false)
        );
        assert_eq!(
            range_satisfied(Manager::Pipx, Some("0.65.0"), Some("0.65.0")),
            Some(true)
        );
        assert_eq!(range_satisfied(Manager::Pipx, None, Some("1")), None);
    }

    #[tokio::test]
    async fn scanner_emits_findings_with_stable_ids_remedies_and_coverage() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let prefix = mk_home(home);
        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
        let mut config = crate::config::Config::default();
        config.tools.include_apple_python = false;
        config.tools.homebrew_prefix = Some(prefix.display().to_string());
        let mock = MockCommandRunner::new()
            .on(
                "dscl",
                &[
                    ".",
                    "-read",
                    &format!("/Users/{}", home.file_name().unwrap().to_str().unwrap()),
                    "UserShell",
                ],
                "UserShell: /opt/homebrew/bin/fish\n",
            )
            .on(
                "/opt/homebrew/bin/fish",
                &["-lc", "string join : $PATH"],
                &format!(
                    "{}:{}:{}\n",
                    home.join("Library/pnpm/bin").display(),
                    home.join(".local/bin").display(),
                    prefix.join("bin").display()
                ),
            );
        let ctx = ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: Arc::new(config),
            paths: Arc::new(Paths::from_home(home)),
            runner: Arc::new(mock),
            current: ScannerId::Tools,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        ToolsScanner.scan(ctx).await.unwrap();
        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        let tools: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::GlobalTool)
            .collect();
        assert!(tools.len() >= 12, "{}", tools.len());
        let ids: BTreeSet<_> = tools.iter().map(|f| f.id).collect();
        assert_eq!(ids.len(), tools.len(), "identity keys must be unique");

        let claw = tools.iter().find(|f| f.title == "clawhub").unwrap();
        assert_eq!(claw.meta["layout"], "legacy-5");
        assert_eq!(
            claw.remedies[0].command.rendered().split(' ').nth(1),
            Some("remove")
        );
        assert!(matches!(
            claw.remedies[0].guard,
            Some(Guard::ToolInstall { .. })
        ));
        // Launcher-only removal exists but is an alternative while the
        // native uninstall is available.
        assert!(claw
            .remedies
            .iter()
            .any(|r| matches!(r.command, RemedyCommand::Trash { .. }) && r.alternative));

        let pn = tools
            .iter()
            .find(|f| f.title == "pnpm" && f.meta["manager"] == "npm")
            .unwrap();
        assert_eq!(pn.meta["primary_classification"], "broken");
        // With no package left, trashing the dangling launchers is primary.
        assert!(pn
            .remedies
            .iter()
            .any(|r| matches!(r.command, RemedyCommand::Trash { .. })
                && !r.alternative
                && matches!(
                    r.guard,
                    Some(Guard::Launcher {
                        expect_dangling: true,
                        ..
                    })
                )));

        let requests = tools.iter().find(|f| f.title == "requests").unwrap();
        assert!(requests.remedies[0]
            .command
            .rendered()
            .contains("--break-system-packages requests"));
        assert!(matches!(
            requests.remedies[0].guard,
            Some(Guard::PipPackage { .. })
        ));
        let certifi = tools.iter().find(|f| f.title == "certifi").unwrap();
        assert!(certifi.remedies.is_empty());
        assert_eq!(certifi.meta["group"], "pip (homebrew-3.14)");

        // The process PATH here is the real one (not injectable in-process),
        // so only shell-side facts are asserted: the tmp shim wins in fish.
        let cmds: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::CommandResolution)
            .collect();
        let wr = cmds.iter().find(|f| f.title == "wrangler").unwrap();
        assert_eq!(wr.meta["user_shell"]["shell"], "fish");
        assert!(wr.meta["user_resolution"]
            .as_str()
            .unwrap()
            .ends_with("Library/pnpm/bin/wrangler"));
        assert_eq!(wr.meta["differs"], true);
        assert_eq!(wr.severity, Severity::Attention);

        let cov = findings
            .iter()
            .find(|f| f.kind == FindingKind::ToolCoverage)
            .unwrap();
        assert_eq!(cov.meta["managers"]["bun"]["status"], "absent");
        assert_eq!(cov.meta["managers"]["pnpm"]["status"], "ok");
        assert_eq!(cov.meta["shell"]["login_shell"], "/opt/homebrew/bin/fish");
        assert!(cov
            .coverage
            .as_deref()
            .unwrap()
            .contains("startup configuration"));
    }

    #[tokio::test]
    async fn blank_runner_and_empty_home_still_produce_coverage() {
        let tmp = tempfile::tempdir().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let mut config = crate::config::Config::default();
        config.tools.include_apple_python = false;
        config.tools.homebrew_prefix = Some(tmp.path().join("nope").display().to_string());
        let ctx = ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: Arc::new(config),
            paths: Arc::new(Paths::from_home(tmp.path())),
            runner: Arc::new(MockCommandRunner::new()),
            current: ScannerId::Tools,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        // Drain while scanning: the scanner also resolves commands on the
        // *host's* PATH, so on a machine with many tools installed (CI
        // runners) it emits more events than the channel holds and would
        // block forever if the receiver only started after `scan` returned.
        let scan = tokio::spawn(async move { ToolsScanner.scan(ctx).await });
        let mut findings = Vec::new();
        while let Some(ev) = rx.recv().await {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        scan.await.unwrap().unwrap();
        let cov = findings
            .iter()
            .find(|f| f.kind == FindingKind::ToolCoverage)
            .unwrap();
        assert!(
            cov.meta["shell"]["login_shell"].is_null() || cov.meta["shell"]["entries"].is_null()
        );
    }
}
