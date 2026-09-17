//! One resolver per resource kind ; each turns a `Project`
//! plus the shared `ResolveEnv` into zero or more `Claim`s. `all()` runs
//! every resolver over one project, in the table's order; `all_baseline()`
//! runs each resolver's once-per-scan ecosystem pass.

pub mod agents;
pub mod artifacts;
pub mod brew;
pub mod caches;
pub mod docker;
pub mod editors;
pub mod go;
pub mod node;
pub mod procs;
pub mod python;
pub mod rust;
pub mod simulator;
pub mod swiftpm;
pub mod xcode;

use super::Project;
use crate::attribution::model::{Claim, ResolveEnv};

/// Run every ecosystem's `baseline(env)` pass once per scan (never per
/// project — see `model.rs`'s `BASELINE_OWNER` doc). Each resolver lane
/// appends its own ecosystem's call here as it lands; not every resolver
/// has a `baseline` (e.g. `procs`, `artifacts`), so this list is shorter
/// than `all()`'s.
pub fn all_baseline(env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut claims = Vec::new();
    claims.extend(node::baseline(env));
    claims.extend(rust::baseline(env));
    claims.extend(go::baseline(env));
    claims.extend(python::baseline(env));
    claims.extend(docker::baseline(env));
    claims.extend(xcode::baseline(env));
    claims.extend(simulator::baseline(env));
    claims.extend(swiftpm::baseline(env));
    claims.extend(agents::baseline(env));
    claims
}

/// Run every resolver over one project, in table order (§5).
pub fn all(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut claims = Vec::new();
    claims.extend(artifacts::resolve(project, env));
    claims.extend(node::resolve(project, env));
    claims.extend(rust::resolve(project, env));
    claims.extend(go::resolve(project, env));
    claims.extend(python::resolve(project, env));
    claims.extend(xcode::resolve(project, env));
    claims.extend(simulator::resolve(project, env));
    claims.extend(swiftpm::resolve(project, env));
    claims.extend(docker::resolve(project, env));
    claims.extend(agents::resolve(project, env));
    claims.extend(editors::resolve(project, env));
    claims.extend(brew::resolve(project, env));
    claims.extend(caches::resolve(project, env));
    claims.extend(procs::resolve(project, env));
    claims
}
