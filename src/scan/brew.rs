//! BrewScanner — Homebrew inventory, dependency graph, and removal evidence.
//!
//! Three bounded `brew` processes per scan (brew's Ruby startup is ~1s each):
//!
//! - `brew info --json=v2 --installed` — formulae *and* casks in one call:
//!   versions, aliases, each install receipt's `runtime_dependencies`
//!   (what this build actually links, with `declared_directly`), the
//!   `installed_on_request` origin flag, cask `depends_on` and `artifacts`.
//! - `brew outdated --json=v2` — newer versions available.
//! - `brew autoremove --dry-run` — Homebrew's own list of no-longer-needed
//!   dependencies. Read-only; the *confirmed* orphan signal.
//!
//! The graph itself lives in `crate::brewgraph`. Origin comes from Homebrew's
//! flag, never from `brew leaves`: a leaf is a structural fact, not "the user
//! asked for it". Missing flags are reported as unknown.
//!
//! Degradation: if `brew info` fails but `brew list` works, formulae/casks
//! are still reported (version only, `completeness: partial`, no graph). If
//! nothing works, one Info finding says Homebrew was not found.
//!
//! Remedies: `brew upgrade` for outdated packages (non-destructive), and
//! `brew uninstall` only for packages nothing else installed depends on
//! (guarded, never `--ignore-dependencies`). The synthetic
//! `__autoremove__` finding carries `brew autoremove` when the dry-run lists
//! candidates.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::brewgraph::{parse_autoremove_dry_run, BrewGraph, InfoRoot, InstallReason, NodeKind};
use crate::model::{Finding, FindingKind, Guard, Remedy, RemedyCommand, ScannerId, Severity};
use crate::runner::CmdOutput;
use crate::scan::sizing::du_blocks;
use crate::scan::{run_with_timeout, ScanCtx, Scanner};
use crate::size_cache::{self, is_fresh, root_mtime_secs, CachedSize, SizeCache};

const BREW_TIMEOUT: Duration = Duration::from_secs(90);
const SIZE_CONCURRENCY: usize = 4;

#[derive(Default)]
pub struct BrewScanner;

/// Run a `brew` subcommand; `None` on spawn failure, nonzero exit, or timeout.
async fn brew(ctx: &ScanCtx, args: &[&str]) -> Option<CmdOutput> {
    run_with_timeout(ctx, "brew", args, BREW_TIMEOUT).await
}

async fn emit_brew_not_found(ctx: &ScanCtx) {
    ctx.emit(
        Finding::new(FindingKind::BrewFormula, "brew-not-found", "Homebrew not found")
            .detail("`brew` is not installed, not on PATH, or a required command failed; skipping the Homebrew scan.")
            .severity(Severity::Info),
    )
    .await;
}

/// Parse `brew list --formula --versions` / `brew list --cask --versions`
/// output: one `<name> <version...>` per line; the last token is the version.
fn parse_name_versions(stdout: &str) -> Vec<(String, String)> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next()?;
            let version = parts.last().unwrap_or("").to_string();
            Some((name.to_string(), version))
        })
        .collect()
}

#[derive(Deserialize, Default)]
struct OutdatedRoot {
    #[serde(default)]
    formulae: Vec<OutdatedEntry>,
    #[serde(default)]
    casks: Vec<OutdatedEntry>,
}

#[derive(Deserialize)]
struct OutdatedEntry {
    name: String,
    current_version: String,
}

/// The Homebrew prefix whose `Cellar/` exists (`$HOMEBREW_PREFIX`, then the
/// two standard locations). `None` means sizes stay unknown.
pub fn brew_prefix() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("HOMEBREW_PREFIX") {
        candidates.push(PathBuf::from(p));
    }
    candidates.push(PathBuf::from("/opt/homebrew"));
    candidates.push(PathBuf::from("/usr/local"));
    candidates.into_iter().find(|p| p.join("Cellar").is_dir())
}

fn origin_group(reason: InstallReason, autoremove: bool) -> &'static str {
    if autoremove {
        "Autoremove candidates"
    } else {
        match reason {
            InstallReason::Requested => "Explicitly installed",
            InstallReason::DependencyOnly => "Installed as dependency",
            InstallReason::Unknown => "Unknown origin",
        }
    }
}

fn upgrade_remedy(current: &str, args: Vec<String>) -> Remedy {
    Remedy::new(
        format!("Upgrade to {current}"),
        RemedyCommand::Shell {
            program: "brew".to_string(),
            args,
        },
    )
}

/// Build the finding for one formula from the graph.
fn formula_finding(graph: &BrewGraph, id: &str, prefix: Option<&Path>) -> Finding {
    let node = graph.get(id).expect("id from graph");
    let reason = node.reason();
    let auto = graph.autoremove.as_ref().map(|set| set.contains(id));
    let is_leaf = graph.is_leaf(id);
    let dependencies = graph.direct_deps(id);
    let dependents = graph.direct_dependents(id);
    let deps_transitive: Vec<String> = graph
        .transitive_deps(id)
        .into_iter()
        .filter(|(n, _)| !dependencies.contains(n))
        .map(|(n, _)| n)
        .collect();
    let dependents_transitive: Vec<String> = graph
        .transitive_dependents(id)
        .into_iter()
        .filter(|(n, _)| !dependents.contains(n))
        .map(|(n, _)| n)
        .collect();
    let cask_dependents = graph.cask_dependents(id);
    let why = graph.why_installed(id);
    let preview = graph.removal_preview(&[id.to_string()].into_iter().collect());
    let blocked_by: Vec<String> = preview
        .blocked
        .iter()
        .find(|(n, _)| n == id)
        .map(|(_, deps)| deps.clone())
        .unwrap_or_default();
    let removable = blocked_by.is_empty();

    let version = node.version.clone().unwrap_or_default();
    let mut detail = format!(
        "{} — {}",
        reason.label(),
        if version.is_empty() {
            "unknown version"
        } else {
            &version
        }
    );
    if is_leaf {
        detail.push_str(" · leaf");
    }
    if auto == Some(true) {
        detail.push_str(" · brew autoremove candidate");
    }
    if node.outdated {
        if let Some(cur) = &node.current_version {
            detail.push_str(&format!(" · {cur} available"));
        }
    }

    let severity = if auto == Some(true) {
        Severity::Reclaimable
    } else if node.outdated {
        Severity::Attention
    } else {
        Severity::Info
    };

    let cellar = prefix.map(|p| p.join("Cellar").join(&node.name));
    let mut f = Finding::new(FindingKind::BrewFormula, id, node.name.clone())
        .detail(detail)
        .severity(severity)
        .provenance("brew info --json=v2 --installed (install receipt runtime_dependencies); brew autoremove --dry-run")
        .meta(json!({
            "name": node.name,
            "full_name": id,
            "tap": node.tap,
            "aliases": node.aliases,
            "version": node.version,
            "install_reason": reason.label(),
            "installed_on_request": node.installed_on_request,
            "installed_as_dependency": node.installed_as_dependency,
            "is_leaf": is_leaf,
            "pinned": node.pinned,
            "outdated": node.outdated,
            "current_version": node.current_version,
            "dependencies": dependencies,
            "dependents": dependents,
            "dependencies_transitive": deps_transitive,
            "dependents_transitive": dependents_transitive,
            "cask_dependents": cask_dependents,
            "dependency_source": node.dependency_source.map(|s| s.label()),
            "why_installed": why,
            "autoremove_candidate": auto,
            "removal_preview": {
                "removable": removable,
                "blocked_by": blocked_by,
                "would_orphan": preview.newly_orphaned,
                "confirmed_orphans": preview.confirmed_orphans,
                "uncertain_orphans": preview.uncertain_orphans,
            },
            "graph_caveats": graph.caveats,
            "completeness": "full",
            "group": origin_group(reason, auto == Some(true)),
        }));
    if let Some(cellar) = cellar {
        f = f.path(cellar);
    }
    if node.outdated {
        if let Some(cur) = &node.current_version {
            f = f.remedy(upgrade_remedy(
                cur,
                vec!["upgrade".into(), node.name.clone()],
            ));
        }
    }
    if removable && !node.pinned {
        f = f.remedy(
            Remedy::new(
                "Uninstall formula",
                RemedyCommand::Shell {
                    program: "brew".to_string(),
                    args: vec!["uninstall".to_string(), id.to_string()],
                },
            )
            .destructive()
            .guard(Guard::BrewFormula {
                full_name: id.to_string(),
                expected_version: node.version.clone(),
                require_no_retained_dependents: true,
            }),
        );
    }
    f
}

fn cask_finding(graph: &BrewGraph, info: &InfoRoot, id: &str) -> Finding {
    let node = graph.get(id).expect("id from graph");
    let token = node.name.clone();
    let cask = info.casks.iter().find(|c| c.token == token);
    let app_paths = cask.map(|c| c.app_paths()).unwrap_or_default();
    let binaries: Vec<serde_json::Value> = cask
        .map(|c| {
            c.binaries()
                .into_iter()
                .map(|(source, target)| json!({ "source": source, "target": target }))
                .collect()
        })
        .unwrap_or_default();
    let formula_deps: Vec<String> = graph
        .direct_deps(id)
        .into_iter()
        .filter(|d| !d.starts_with("cask:"))
        .collect();
    let cask_deps: Vec<String> = graph
        .direct_deps(id)
        .into_iter()
        .filter_map(|d| d.strip_prefix("cask:").map(str::to_string))
        .collect();
    let cask_dependents: Vec<String> = graph
        .direct_dependents(id)
        .into_iter()
        .filter_map(|d| d.strip_prefix("cask:").map(str::to_string))
        .collect();
    let version = node.version.clone().unwrap_or_default();
    let mut detail = format!(
        "cask — {}",
        if version.is_empty() {
            "unknown version"
        } else {
            &version
        }
    );
    if node.outdated {
        if let Some(cur) = &node.current_version {
            detail.push_str(&format!(" · {cur} available"));
        }
    }
    let mut f = Finding::new(FindingKind::BrewCask, &token, token.clone())
        .detail(detail)
        .severity(if node.outdated {
            Severity::Attention
        } else {
            Severity::Info
        })
        .provenance("brew info --json=v2 --installed")
        .meta(json!({
            "token": token,
            "name": token,
            "version": node.version,
            "app_paths": app_paths,
            "binaries": binaries,
            "depends_on": { "formula": formula_deps, "cask": cask_deps },
            "cask_dependents": cask_dependents,
            "outdated": node.outdated,
            "current_version": node.current_version,
            "completeness": "full",
            "group": "Casks",
        }));
    if node.outdated {
        if let Some(cur) = &node.current_version {
            f = f.remedy(upgrade_remedy(
                cur,
                vec!["upgrade".into(), "--cask".into(), token.clone()],
            ));
        }
    }
    if cask_dependents.is_empty() {
        f = f.remedy(
            Remedy::new(
                "Uninstall cask",
                RemedyCommand::Shell {
                    program: "brew".to_string(),
                    args: vec!["uninstall".to_string(), "--cask".to_string(), token.clone()],
                },
            )
            .destructive()
            .guard(Guard::BrewCask {
                token: token.clone(),
                expected_version: node.version.clone(),
            }),
        );
    }
    f
}

/// Formula/cask findings from `brew list` only — used when `brew info` is
/// unavailable. No graph, no origin, no dependents: everything unknown.
async fn emit_partial_from_list(ctx: &ScanCtx, formula_out: &CmdOutput) {
    let cask_out = brew(ctx, &["list", "--cask", "--versions"]).await;
    let note = "brew info --json=v2 --installed failed; inventory from brew list only (no dependency data, origin unknown)";
    for (name, version) in parse_name_versions(&formula_out.stdout_str()) {
        ctx.emit(
            Finding::new(FindingKind::BrewFormula, &name, name.clone())
                .detail(format!("unknown — {version}"))
                .severity(Severity::Info)
                .provenance("brew list --formula --versions")
                .coverage(note)
                .meta(json!({
                    "name": name, "full_name": name, "version": version,
                    "install_reason": "unknown", "installed_on_request": null,
                    "installed_as_dependency": null, "is_leaf": null,
                    "autoremove_candidate": null, "dependency_source": null,
                    "outdated": false, "current_version": null,
                    "completeness": "partial", "group": "Unknown origin",
                })),
        )
        .await;
    }
    if let Some(out) = cask_out {
        for (token, version) in parse_name_versions(&out.stdout_str()) {
            ctx.emit(
                Finding::new(FindingKind::BrewCask, &token, token.clone())
                    .detail(format!("cask — {version}"))
                    .severity(Severity::Info)
                    .provenance("brew list --cask --versions")
                    .coverage(note)
                    .meta(json!({
                        "token": token, "name": token, "version": version,
                        "app_paths": [], "binaries": [], "outdated": false,
                        "current_version": null, "completeness": "partial", "group": "Casks",
                    })),
            )
            .await;
        }
    }
}

#[async_trait]
impl Scanner for BrewScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Brew
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        ctx.progress("brew info", 0, None).await;
        let info_out = brew(&ctx, &["info", "--json=v2", "--installed"]).await;
        let info: Option<InfoRoot> = info_out
            .as_ref()
            .and_then(|o| serde_json::from_str(&o.stdout_str()).ok());
        let Some(info) = info else {
            // Degrade: `brew list` still gives an inventory; nothing ⇒ not found.
            match brew(&ctx, &["list", "--formula", "--versions"]).await {
                Some(out) => emit_partial_from_list(&ctx, &out).await,
                None => emit_brew_not_found(&ctx).await,
            }
            return Ok(());
        };

        ctx.progress("brew outdated / autoremove --dry-run", 1, None)
            .await;
        let outdated: OutdatedRoot = brew(&ctx, &["outdated", "--json=v2"])
            .await
            .and_then(|o| serde_json::from_str(&o.stdout_str()).ok())
            .unwrap_or_default();
        let autoremove: Option<BTreeSet<String>> = brew(&ctx, &["autoremove", "--dry-run"])
            .await
            .map(|o| parse_autoremove_dry_run(&o.stdout_str()));
        let autoremove_known = autoremove.is_some();

        let mut graph = BrewGraph::from_info(&info, autoremove);
        for e in &outdated.formulae {
            if let Some(id) = graph.resolve(&e.name) {
                graph.set_current_version(&id, Some(e.current_version.clone()));
            }
        }
        for e in &outdated.casks {
            let id = format!("cask:{}", e.name);
            graph.set_current_version(&id, Some(e.current_version.clone()));
        }

        // Cellar sizes: cached when fresh, else measured concurrently and
        // re-emitted (same upsert rule as Disk/Git).
        let prefix = brew_prefix();
        let paths_load = ctx.paths.clone();
        let cache: Arc<HashMap<PathBuf, CachedSize>> = Arc::new(
            tokio::task::spawn_blocking(move || {
                SizeCache::open(&size_cache::db_path(&paths_load))
                    .and_then(|c| c.load_all())
                    .unwrap_or_default()
            })
            .await
            .unwrap_or_default(),
        );
        let fresh: Arc<Mutex<Vec<(PathBuf, CachedSize)>>> = Arc::new(Mutex::new(Vec::new()));
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let ttl_hours = ctx.config.scan.size_cache_ttl_hours;

        let formula_ids: Vec<String> = graph
            .nodes()
            .filter(|n| n.kind == NodeKind::Formula && !n.stub)
            .map(|n| n.id.clone())
            .collect();
        let cask_ids: Vec<String> = graph
            .nodes()
            .filter(|n| n.kind == NodeKind::Cask)
            .map(|n| n.id.clone())
            .collect();
        let total = (formula_ids.len() + cask_ids.len()) as u64;
        let mut done = 0u64;

        // Pre-fill cached sizes so shared-dependency totals are right on the
        // first emit; measured sizes arrive as re-emits.
        let mut to_measure: Vec<(String, PathBuf, i64)> = Vec::new();
        if let Some(prefix) = &prefix {
            for id in &formula_ids {
                let node = graph.get(id).unwrap();
                let Some(version) = node.version.clone() else {
                    continue;
                };
                let keg = prefix.join("Cellar").join(&node.name).join(&version);
                if !keg.is_dir() {
                    continue;
                }
                let mtime = root_mtime_secs(&keg);
                match cache
                    .get(&keg)
                    .copied()
                    .filter(|c| is_fresh(c, mtime, now_secs, ttl_hours))
                {
                    Some(c) => graph.set_size(id, Some(c.size)),
                    None => to_measure.push((id.clone(), keg, mtime)),
                }
            }
        }

        let graph = Arc::new(graph);
        for id in &formula_ids {
            if ctx.cancelled() {
                break;
            }
            done += 1;
            ctx.progress(format!("brew formula {id}"), done, Some(total))
                .await;
            let mut f = formula_finding(&graph, id, prefix.as_deref());
            if let Some(size) = graph.get(id).and_then(|n| n.size_bytes) {
                f = f.size(size);
                if let Some(obj) = f.meta.as_object_mut() {
                    obj.insert("size_cached".into(), json!(true));
                }
            }
            ctx.emit(f).await;
        }
        for id in &cask_ids {
            if ctx.cancelled() {
                break;
            }
            done += 1;
            ctx.progress(format!("brew cask {id}"), done, Some(total))
                .await;
            ctx.emit(cask_finding(&graph, &info, id)).await;
        }

        // Autoremove summary row.
        if let Some(set) = &graph.autoremove {
            if !set.is_empty() {
                let names: Vec<String> = set.iter().cloned().collect();
                ctx.emit(
                    Finding::new(
                        FindingKind::BrewFormula,
                        "__autoremove__",
                        "Homebrew autoremove candidates",
                    )
                    .detail(format!(
                        "{} formula(e) Homebrew reports as no longer needed: {}",
                        names.len(),
                        names.join(", ")
                    ))
                    .severity(Severity::Reclaimable)
                    .provenance("brew autoremove --dry-run")
                    .meta(json!({ "candidates": names, "source": "brew autoremove --dry-run", "group": "Autoremove candidates" }))
                    .remedy(
                        Remedy::new(
                            "Remove all unneeded dependencies",
                            RemedyCommand::Shell {
                                program: "brew".into(),
                                args: vec!["autoremove".into()],
                            },
                        )
                        .destructive(),
                    ),
                )
                .await;
            }
        } else if !autoremove_known {
            ctx.emit(
                Finding::new(
                    FindingKind::BrewFormula,
                    "__autoremove__",
                    "Homebrew autoremove candidates",
                )
                .detail("unknown — `brew autoremove --dry-run` could not be run")
                .severity(Severity::Info)
                .provenance("brew autoremove --dry-run (failed)")
                .meta(json!({ "candidates": null, "source": "brew autoremove --dry-run", "group": "Autoremove candidates" })),
            )
            .await;
        }

        // Measure uncached kegs and re-emit with sizes.
        if !to_measure.is_empty() && !ctx.cancelled() {
            let sem = Arc::new(Semaphore::new(SIZE_CONCURRENCY));
            let mut set: JoinSet<(String, PathBuf, i64, u64)> = JoinSet::new();
            for (id, keg, mtime) in to_measure {
                let permit = sem.clone().acquire_owned().await?;
                let token = ctx.token.clone();
                set.spawn(async move {
                    let _permit = permit;
                    let du_root = keg.clone();
                    let t = token.clone();
                    let size = tokio::task::spawn_blocking(move || {
                        du_blocks(&du_root, &|| t.is_cancelled())
                    })
                    .await
                    .unwrap_or(0);
                    (id, keg, mtime, size)
                });
            }
            let mut sizes: BTreeMap<String, u64> = BTreeMap::new();
            while let Some(Ok((id, keg, mtime, size))) = set.join_next().await {
                if ctx.cancelled() {
                    break;
                }
                sizes.insert(id, size);
                fresh.lock().unwrap().push((
                    keg,
                    CachedSize {
                        size,
                        computed_at: now_secs,
                        root_mtime: mtime,
                    },
                ));
            }
            if !ctx.cancelled() {
                let mut sized = (*graph).clone();
                for (id, size) in &sizes {
                    sized.set_size(id, Some(*size));
                }
                for id in sizes.keys() {
                    ctx.emit(formula_finding(&sized, id, prefix.as_deref()).size(sizes[id]))
                        .await;
                }
                let entries: Vec<(PathBuf, CachedSize)> =
                    std::mem::take(&mut *fresh.lock().unwrap());
                if !entries.is_empty() {
                    let paths_save = ctx.paths.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        SizeCache::open(&size_cache::db_path(&paths_save))
                            .and_then(|mut c| c.upsert_batch(&entries))
                    })
                    .await;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanEvent;
    use crate::runner::MockCommandRunner;

    /// wget (requested, outdated) → libidn2, openssl@3; ripgrep (requested)
    /// → pcre2; pcre2/libidn2/openssl@3 dependency-only; oldlib has no flag;
    /// pdftk cask → openjdk (dependency-only); vscode cask with a binary.
    pub(crate) const INFO_JSON: &str = r#"{
      "formulae": [
        {"name": "wget", "full_name": "wget", "tap": "homebrew/core", "aliases": [], "oldnames": [],
         "dependencies": ["libidn2", "openssl@3"], "pinned": false, "outdated": true, "linked_keg": "1.21.3",
         "installed": [{"version": "1.21.3", "installed_on_request": true,
           "runtime_dependencies": [
             {"full_name": "libidn2", "version": "2.3.7", "declared_directly": true},
             {"full_name": "libunistring", "version": "1.2", "declared_directly": false},
             {"full_name": "openssl@3", "version": "3.3.1", "declared_directly": true}
           ]}]},
        {"name": "libidn2", "full_name": "libidn2", "aliases": [], "oldnames": [], "dependencies": ["libunistring"],
         "linked_keg": "2.3.7", "installed": [{"version": "2.3.7", "installed_on_request": false,
           "runtime_dependencies": [{"full_name": "libunistring", "version": "1.2", "declared_directly": true}]}]},
        {"name": "libunistring", "full_name": "libunistring", "aliases": [], "oldnames": [], "dependencies": [],
         "linked_keg": "1.2", "installed": [{"version": "1.2", "installed_on_request": false, "runtime_dependencies": []}]},
        {"name": "openssl@3", "full_name": "openssl@3", "aliases": ["openssl"], "oldnames": [], "dependencies": [],
         "linked_keg": "3.3.1", "installed": [{"version": "3.3.1", "installed_on_request": false, "runtime_dependencies": []}]},
        {"name": "ripgrep", "full_name": "ripgrep", "aliases": ["rg"], "oldnames": [], "dependencies": ["pcre2"],
         "linked_keg": "14.1.0", "installed": [{"version": "14.1.0", "installed_on_request": true,
           "runtime_dependencies": [{"full_name": "pcre2", "version": "10.43", "declared_directly": true}]}]},
        {"name": "pcre2", "full_name": "pcre2", "aliases": [], "oldnames": [], "dependencies": [],
         "linked_keg": "10.43", "installed": [{"version": "10.43", "installed_on_request": false, "runtime_dependencies": []}]},
        {"name": "oldlib", "full_name": "oldlib", "aliases": [], "oldnames": [], "dependencies": [],
         "linked_keg": "0.1", "installed": [{"version": "0.1"}]},
        {"name": "openjdk", "full_name": "openjdk", "aliases": [], "oldnames": [], "dependencies": [],
         "linked_keg": null, "installed": [{"version": "21", "installed_on_request": false, "runtime_dependencies": []}]}
      ],
      "casks": [
        {"token": "visual-studio-code", "full_token": "visual-studio-code", "name": ["Visual Studio Code"],
         "installed": "1.85.0", "outdated": false, "depends_on": {},
         "artifacts": [{"app": ["Visual Studio Code.app"]}, {"binary": ["bin/code", {"target": "/opt/homebrew/bin/code"}]}]},
        {"token": "slack", "full_token": "slack", "name": ["Slack"], "installed": "4.35.0", "outdated": true,
         "depends_on": {}, "artifacts": [{"app": ["Slack.app"]}]},
        {"token": "pdftk-java", "full_token": "pdftk-java", "name": ["PDFtk"], "installed": "3.3.3", "outdated": false,
         "depends_on": {"formula": ["openjdk"]}, "artifacts": []}
      ]
    }"#;

    const OUTDATED_JSON: &str = r#"{
      "formulae": [{"name": "wget", "installed_versions": ["1.21.3"], "current_version": "1.21.4", "pinned": false, "pinned_version": null}],
      "casks": [{"name": "slack", "installed_versions": "4.35.0", "current_version": "4.36.0"}]
    }"#;

    fn mock_full() -> MockCommandRunner {
        MockCommandRunner::new()
            .on("brew", &["info", "--json=v2", "--installed"], INFO_JSON)
            .on("brew", &["outdated", "--json=v2"], OUTDATED_JSON)
            .on("brew", &["autoremove", "--dry-run"], "")
    }

    async fn run_scan(mock: Arc<MockCommandRunner>) -> Vec<Finding> {
        let tmp = tempfile::tempdir().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let ctx = ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: Arc::new(crate::config::Config::default()),
            paths: Arc::new(crate::config::Paths::from_home(tmp.path())),
            runner: mock,
            current: ScannerId::Brew,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        BrewScanner.scan(ctx).await.unwrap();
        let mut findings = vec![];
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        findings
    }

    fn by_title<'a>(fs: &'a [Finding], t: &str) -> &'a Finding {
        fs.iter()
            .find(|f| f.title == t)
            .unwrap_or_else(|| panic!("no finding {t}"))
    }

    #[tokio::test]
    async fn single_info_call_replaces_legacy_commands() {
        let mock = Arc::new(mock_full());
        let findings = run_scan(mock.clone()).await;
        let calls = mock.calls();
        assert!(calls
            .iter()
            .any(|c| c[..] == ["brew", "info", "--json=v2", "--installed"]));
        assert!(calls
            .iter()
            .any(|c| c[..] == ["brew", "autoremove", "--dry-run"]));
        assert!(!calls
            .iter()
            .any(|c| c.iter().any(|a| a == "leaves" || a == "deps")));
        let formulae = findings
            .iter()
            .filter(|f| f.kind == FindingKind::BrewFormula && !f.title.starts_with("Homebrew"))
            .count();
        let casks = findings
            .iter()
            .filter(|f| f.kind == FindingKind::BrewCask)
            .count();
        assert_eq!(formulae, 8);
        assert_eq!(casks, 3);
    }

    #[tokio::test]
    async fn leaf_is_not_requested_and_origin_comes_from_receipt() {
        let findings = run_scan(Arc::new(mock_full())).await;
        // openjdk: leaf among formulae but installed as a dependency (of a cask).
        let openjdk = by_title(&findings, "openjdk");
        assert_eq!(openjdk.meta["install_reason"], "dependency");
        assert_eq!(openjdk.meta["installed_on_request"], false);
        assert_eq!(openjdk.meta["is_leaf"], false); // the cask needs it
        assert_eq!(openjdk.meta["cask_dependents"], json!(["cask:pdftk-java"]));
        assert_eq!(openjdk.meta["group"], "Installed as dependency");
        assert!(openjdk.detail.starts_with("dependency —"));

        let ripgrep = by_title(&findings, "ripgrep");
        assert_eq!(ripgrep.meta["install_reason"], "requested");
        assert_eq!(ripgrep.meta["is_leaf"], true);
        assert_eq!(ripgrep.meta["group"], "Explicitly installed");
        assert_eq!(ripgrep.meta["aliases"], json!(["rg"]));

        // No flag at all ⇒ unknown, not guessed from leaf-ness.
        let oldlib = by_title(&findings, "oldlib");
        assert_eq!(oldlib.meta["install_reason"], "unknown");
        assert!(oldlib.meta["installed_on_request"].is_null());
        assert_eq!(oldlib.meta["group"], "Unknown origin");
        assert_eq!(oldlib.meta["dependency_source"], "formula_declaration");
    }

    #[tokio::test]
    async fn direct_and_transitive_relationships_are_separated() {
        let findings = run_scan(Arc::new(mock_full())).await;
        let wget = by_title(&findings, "wget");
        assert_eq!(wget.meta["dependencies"], json!(["libidn2", "openssl@3"]));
        assert_eq!(
            wget.meta["dependencies_transitive"],
            json!(["libunistring"])
        );
        assert_eq!(wget.meta["dependency_source"], "installed_runtime");
        let libunistring = by_title(&findings, "libunistring");
        assert_eq!(libunistring.meta["dependents"], json!(["libidn2"]));
        assert_eq!(libunistring.meta["dependents_transitive"], json!(["wget"]));
        assert_eq!(
            libunistring.meta["why_installed"]["requested_roots"],
            json!(["wget"])
        );
    }

    #[tokio::test]
    async fn uninstall_remedy_only_without_retained_dependents() {
        let findings = run_scan(Arc::new(mock_full())).await;
        let wget = by_title(&findings, "wget");
        let rendered: Vec<String> = wget.remedies.iter().map(|r| r.command.rendered()).collect();
        assert_eq!(rendered, ["brew upgrade wget", "brew uninstall wget"]);
        assert!(wget.remedies[1].destructive);
        assert!(matches!(
            wget.remedies[1].guard,
            Some(Guard::BrewFormula {
                require_no_retained_dependents: true,
                ..
            })
        ));
        assert_eq!(
            wget.meta["removal_preview"]["would_orphan"],
            json!(["libidn2", "libunistring", "openssl@3"])
        );

        // openssl@3 is needed by wget: no uninstall remedy, blocked_by lists it.
        let openssl = by_title(&findings, "openssl@3");
        assert!(openssl.remedies.is_empty());
        assert_eq!(openssl.meta["removal_preview"]["removable"], false);
        assert_eq!(
            openssl.meta["removal_preview"]["blocked_by"],
            json!(["wget"])
        );
    }

    #[tokio::test]
    async fn outdated_cask_gets_upgrade_and_binary_artifacts_recorded() {
        let findings = run_scan(Arc::new(mock_full())).await;
        let slack = by_title(&findings, "slack");
        assert_eq!(
            slack.remedies[0].command.rendered(),
            "brew upgrade --cask slack"
        );
        assert_eq!(slack.severity, Severity::Attention);
        let vscode = by_title(&findings, "visual-studio-code");
        assert_eq!(
            vscode.meta["app_paths"],
            json!(["/Applications/Visual Studio Code.app"])
        );
        assert_eq!(
            vscode.meta["binaries"][0]["target"],
            "/opt/homebrew/bin/code"
        );
        let pdftk = by_title(&findings, "pdftk-java");
        assert_eq!(pdftk.meta["depends_on"]["formula"], json!(["openjdk"]));
        assert_eq!(
            pdftk.remedies.last().unwrap().command.rendered(),
            "brew uninstall --cask pdftk-java"
        );
    }

    #[tokio::test]
    async fn autoremove_candidates_are_confirmed_orphans() {
        let mock = MockCommandRunner::new()
            .on("brew", &["info", "--json=v2", "--installed"], INFO_JSON)
            .on("brew", &["outdated", "--json=v2"], OUTDATED_JSON)
            .on(
                "brew",
                &["autoremove", "--dry-run"],
                "==> Would autoremove 1 unneeded formula:\noldlib\n",
            );
        let findings = run_scan(Arc::new(mock)).await;
        let oldlib = by_title(&findings, "oldlib");
        assert_eq!(oldlib.meta["autoremove_candidate"], true);
        assert_eq!(oldlib.meta["group"], "Autoremove candidates");
        assert_eq!(oldlib.severity, Severity::Reclaimable);
        let summary = by_title(&findings, "Homebrew autoremove candidates");
        assert_eq!(summary.meta["candidates"], json!(["oldlib"]));
        assert_eq!(summary.remedies[0].command.rendered(), "brew autoremove");
        // Others are explicitly not candidates (known false, not null).
        assert_eq!(
            by_title(&findings, "pcre2").meta["autoremove_candidate"],
            false
        );
    }

    #[tokio::test]
    async fn autoremove_failure_is_unknown_not_none() {
        let mock = MockCommandRunner::new()
            .on("brew", &["info", "--json=v2", "--installed"], INFO_JSON)
            .on("brew", &["outdated", "--json=v2"], OUTDATED_JSON);
        let findings = run_scan(Arc::new(mock)).await;
        assert!(by_title(&findings, "pcre2").meta["autoremove_candidate"].is_null());
        let summary = by_title(&findings, "Homebrew autoremove candidates");
        assert!(summary.remedies.is_empty());
        assert!(summary.detail.contains("unknown"));
    }

    #[tokio::test]
    async fn info_failure_falls_back_to_list_partial() {
        let mock = MockCommandRunner::new()
            .on(
                "brew",
                &["list", "--formula", "--versions"],
                "wget 1.21.4\nripgrep 14.1.0\n",
            )
            .on("brew", &["list", "--cask", "--versions"], "slack 4.35.0\n");
        let findings = run_scan(Arc::new(mock)).await;
        assert_eq!(findings.len(), 3);
        let wget = by_title(&findings, "wget");
        assert_eq!(wget.meta["completeness"], "partial");
        assert_eq!(wget.meta["install_reason"], "unknown");
        assert!(wget.meta["is_leaf"].is_null());
        assert!(wget.remedies.is_empty());
        assert!(wget
            .coverage
            .as_deref()
            .unwrap()
            .contains("no dependency data"));
    }

    #[tokio::test]
    async fn missing_brew_emits_single_info_finding_and_returns_ok() {
        let findings = run_scan(Arc::new(MockCommandRunner::new())).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Homebrew not found");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn parse_name_versions_takes_last_token() {
        let v = parse_name_versions("wget 1.21.3 1.21.4\nrg 14\n");
        assert_eq!(
            v,
            vec![("wget".into(), "1.21.4".into()), ("rg".into(), "14".into())]
        );
    }
}
