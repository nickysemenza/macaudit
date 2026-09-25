//! Attribution axes: two lenses over the whole-disk walk that answer "what
//! is `<project>` costing me" and "what is `<app>` costing me" instead of
//! "what is on my disk".
//!
//! - `model.rs` — the domain types (`Claim`, `Footprint`, `FootprintSet`,
//!   `ResolveEnv`, ...).
//! - `bus.rs` — `ScanBus`, letting the two scanners below wait on other
//!   sections' latest results without the engine's `plan()` knowing about it.
//! - `paths.rs` / `accounting.rs` — pure path/byte-accounting logic.
//! - `lsof.rs` — one cached `lsof` snapshot shared by both axes' live-process
//!   joins.
//! - `projects/` — project discovery, naming, and one resolver per resource
//!   kind.
//! - `apps/` — app-axis owner discovery, entitlements, candidates, linker
//!   tiers, and the curated tables.
//! - `testutil.rs` (test-only) — a shared `ResolveEnv` fixture for resolver/
//!   accounting/model unit tests.

pub mod accounting;
pub mod apps;
pub mod bus;
pub mod lsof;
pub mod model;
pub mod paths;
pub mod projects;
#[cfg(test)]
pub(crate) mod testutil;

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;

use crate::model::{Finding, ScanEvent, ScannerId};
use crate::scan::{ScanCtx, Scanner};

use bus::ScanBus;
use model::{Axis, Claim, Footprint, FootprintEntry, FootprintSet, Owner, OwnerKind, ResolveEnv};

/// Sections the Projects axis waits on before resolving.
pub const PROJECT_DEPS: &[ScannerId] = &[
    ScannerId::Fs,
    ScannerId::Git,
    ScannerId::Docker,
    ScannerId::Simulator,
    ScannerId::Ports,
    ScannerId::Tools,
    ScannerId::Brew,
    ScannerId::Apps,
];

/// Sections the App Storage axis waits on before resolving.
pub const APP_STORAGE_DEPS: &[ScannerId] = &[
    ScannerId::Fs,
    ScannerId::Apps,
    ScannerId::Brew,
    ScannerId::Tools,
];

/// The dependency sections one attribution scanner waits on — empty for
/// every non-attribution section. Used by headless dep expansion
/// (`engine::expand_deps`) so `macaudit scan --section projects` fetches its
/// dependencies without the TUI/FFI ever auto-adding sections.
pub fn deps_of(id: ScannerId) -> &'static [ScannerId] {
    match id {
        ScannerId::Projects => PROJECT_DEPS,
        ScannerId::AppStorage => APP_STORAGE_DEPS,
        _ => &[],
    }
}

/// The Projects axis scanner: one row per discovered project.
pub struct ProjectsScanner {
    bus: Arc<ScanBus>,
}

impl ProjectsScanner {
    pub fn new(bus: Arc<ScanBus>) -> Self {
        ProjectsScanner { bus }
    }
}

#[async_trait]
impl Scanner for ProjectsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Projects
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        run(&ctx, &self.bus, Axis::Projects, PROJECT_DEPS).await
    }
}

/// The App Storage axis scanner: one row per app/formula/tool owner.
pub struct AppStorageScanner {
    bus: Arc<ScanBus>,
}

impl AppStorageScanner {
    pub fn new(bus: Arc<ScanBus>) -> Self {
        AppStorageScanner { bus }
    }
}

#[async_trait]
impl Scanner for AppStorageScanner {
    fn id(&self) -> ScannerId {
        ScannerId::AppStorage
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        run(&ctx, &self.bus, Axis::AppStorage, APP_STORAGE_DEPS).await
    }
}

/// Shared body for both axis scanners: wait on dependencies, build the
/// `ResolveEnv`, discover owners, resolve claims, account for them, emit one
/// Finding per owner plus the three bucket rows, then publish the
/// `FootprintSet` itself as a `ScanEvent::Footprints`.
async fn run(
    ctx: &ScanCtx,
    bus: &Arc<ScanBus>,
    axis: Axis,
    deps: &'static [ScannerId],
) -> anyhow::Result<()> {
    let snapshots = bus.wait_for(deps, ctx.gen, &ctx.token).await;
    let missing_deps: Vec<ScannerId> = deps
        .iter()
        .copied()
        .filter(|d| !snapshots.contains_key(d))
        .collect();
    // Everything below is synchronous CPU + small-file I/O over the
    // snapshots (lockfile parsing, plist reads, `lsof`), so it runs off the
    // async runtime. The snapshots are moved in; the ctx handles are Arcs.
    let (paths, config, runner) = (ctx.paths.clone(), ctx.config.clone(), ctx.runner.clone());
    let gen = ctx.gen;
    let set = tokio::task::spawn_blocking(move || {
        let trees: Vec<Arc<crate::scan::walk::DirTree>> = snapshots
            .values()
            .flat_map(|s| s.dir_trees.iter().cloned())
            .collect();
        let env = ResolveEnv::new(&paths, &config, &trees, &snapshots, runner.as_ref());
        resolve_axis(axis, &env)
    })
    .await?;
    // `resolve_axis`'s resolve pass has no way to know this scan's
    // generation or which dependency sections came back missing — both are
    // only known here, before the pass even starts. Reconstructed rather
    // than assigned in place, so there is exactly one place that ever sets
    // them, not a mutation bolted on after the fact.
    let set = FootprintSet {
        gen,
        missing_deps,
        ..set
    };

    emit_set(ctx, &set).await;
    let _ = ctx
        .tx
        .send(ScanEvent::Footprints {
            scanner: ctx.current,
            gen: ctx.gen,
            set: Arc::new(set),
        })
        .await;
    Ok(())
}

/// One axis's whole resolve pass: discover owners, collect every claim
/// (per-owner resolvers plus the once-per-scan ecosystem/baseline pass),
/// account for them, then attach the non-byte facts (worktrees, live
/// processes, listening ports) that accounting doesn't model.
fn resolve_axis(axis: Axis, env: &ResolveEnv<'_>) -> FootprintSet {
    match axis {
        Axis::Projects => {
            let index = projects::discovery::discover(env);
            let owners: Vec<Owner> = index.projects().iter().map(project_owner).collect();
            let mut claims: Vec<Claim> = index
                .projects()
                .iter()
                .flat_map(|p| projects::resolvers::all(p, env))
                .collect();
            claims.extend(projects::resolvers::all_baseline(env, &index));
            let mut set = accounting::account(claims, &owners, env, axis);
            for project in index.projects() {
                let Some(fp) = set
                    .footprints
                    .iter_mut()
                    .find(|fp| fp.owner.key == project_owner(project).key)
                else {
                    continue;
                };
                fp.worktrees = project.worktrees.clone();
                let (processes, ports) = projects::resolvers::processes_for(project, env);
                fp.processes = processes;
                fp.ports = ports;
            }
            set
        }
        Axis::AppStorage => {
            let (owners, claims) = apps::resolve(env);
            accounting::account(claims, &owners, env, axis)
        }
    }
}

/// A project's owner identity: keyed by its root path (what every project
/// resolver uses as the claim owner), named after the directory.
fn project_owner(project: &projects::Project) -> Owner {
    Owner {
        key: project.root.to_string_lossy().into_owned(),
        kind: OwnerKind::Project,
        name: project.name.clone(),
        path: Some(project.root.clone()),
    }
}

/// Turn a `FootprintSet` into its Finding representations: one per owner
/// (`Project`/`AppOwner`) plus the three synthetic bucket rows (baseline,
/// unattributed, coverage).
async fn emit_set(ctx: &ScanCtx, set: &FootprintSet) {
    for fp in &set.footprints {
        ctx.emit(footprint_finding(set.axis, fp)).await;
    }
    for f in bucket_findings(set) {
        ctx.emit(f).await;
    }
}

/// One `Footprint`'s Finding representation. `pub(crate)` so `fake.rs` can
/// build its fixtures from the exact same code path as the real emitter —
/// the fake `Footprints` event and the fake `Project`/`AppOwner` findings
/// must carry identical ids.
pub(crate) fn footprint_finding(axis: Axis, fp: &Footprint) -> Finding {
    let kind = axis.finding_kind();
    let by_kind: Vec<serde_json::Value> = fp
        .groups
        .iter()
        .map(|g| json!({"kind": g.kind.label(), "bytes": g.bytes}))
        .collect();
    let top_tier = fp
        .groups
        .iter()
        .flat_map(|g| &g.entries)
        .map(|e| e.tier)
        .min()
        .map(|t| t.label());
    // No `owner_key` (Swift sorts Name by title, not this) and no `group`
    // (this axis is a `ViewKind::Table`, never grouped — see
    // `present::attribution_owner_detail`'s doc for the detail-pane side of
    // this; Swift stops reading `Finding.group` for these two kinds too).
    let mut finding = Finding::new(kind, &fp.owner.key, fp.owner.name.clone())
        .size(fp.exclusive + fp.shared)
        .meta(json!({
            "owner_kind": fp.owner.kind.label(),
            "exclusive": fp.exclusive,
            "shared": fp.shared,
            "reach": fp.reach,
            "baseline_share": fp.baseline_share,
            "by_kind": by_kind,
            "worktrees": fp.worktrees.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "process_count": fp.processes.len(),
            "ports": fp.ports,
            "top_tier": top_tier,
            "clone_note": fp.clone_note,
        }));
    if let Some(path) = &fp.owner.path {
        finding = finding.path(path.clone());
    }
    finding
}

/// The three synthetic bucket rows (baseline, unattributed, coverage) for
/// one `FootprintSet`. `pub(crate)` for the same reason as
/// `footprint_finding` — `fake.rs` reuses it verbatim.
pub(crate) fn bucket_findings(set: &FootprintSet) -> [Finding; 3] {
    let kind = set.axis.bucket_kind();
    let prefix = set.axis.scanner().slug();

    let baseline = Finding::new(kind, &format!("{prefix}:baseline"), "Baseline")
        .detail(
            "Ecosystem-wide resources shared by every project/app of that \
             kind — never counted in anyone's exclusive total.",
        )
        .size(entries_total(&set.baseline))
        .meta(json!({ "entry_count": set.baseline.len(), "group": "Coverage" }));

    let unattributed = Finding::new(kind, &format!("{prefix}:unattributed"), "Unattributed")
        .detail("Disk usage this axis could not link to an owner.")
        .size(entries_total(&set.unattributed))
        .meta(json!({ "entry_count": set.unattributed.len(), "group": "Coverage" }));

    let coverage = Finding::new(kind, &format!("{prefix}:coverage"), "Coverage")
        .detail("How much of the disk this axis accounts for.")
        .meta(json!({
            "disk_total": set.disk_total,
            "attributed_total": set.attributed_total,
            "missing_deps": set.missing_deps.iter().map(|d| d.slug()).collect::<Vec<_>>(),
            "group": "Coverage",
        }));

    [baseline, unattributed, coverage]
}

fn entries_total(entries: &[FootprintEntry]) -> u64 {
    entries.iter().map(|e| e.bytes).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deps_of_only_the_two_attribution_scanners_are_non_empty() {
        for id in ScannerId::ALL {
            match id {
                ScannerId::Projects => assert_eq!(deps_of(*id), PROJECT_DEPS),
                ScannerId::AppStorage => assert_eq!(deps_of(*id), APP_STORAGE_DEPS),
                _ => assert!(deps_of(*id).is_empty(), "{id:?} should have no deps"),
            }
        }
    }
}
