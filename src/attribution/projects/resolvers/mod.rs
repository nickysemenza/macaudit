//! Every project resolver, as a table (§Part A of the resolver-matrix plan):
//! `rules.rs` is the data — three row shapes (`Lookup`, `ReverseLink`,
//! `Baseline`) covering every ecosystem this crate resolves — `apply.rs` is
//! the one evaluator for all three, `parsers.rs` holds the pure text
//! parsers the rows reference, and `joins.rs` holds the handful of claim
//! sources that need a findings snapshot rather than a walk of `~` (Fs
//! artifacts, Docker, live processes).
//!
//! `all()` resolves one project; `all_baseline()` runs once per scan, not
//! once per project (see `model.rs`'s `BASELINE_OWNER` doc).

mod apply;
mod joins;
mod parsers;
mod rules;

pub use joins::processes_for;

use crate::attribution::model::{Claim, ResolveEnv};

use super::{Project, ProjectIndex};

/// Run every resolver over one project.
pub fn all(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let mut claims = joins::artifacts(project, env);
    claims.extend(apply::lookups(project, env));
    claims.extend(joins::docker(project, env));
    claims
}

/// Run every once-per-scan ecosystem pass: reverse-links (DerivedData,
/// editor workspace storage, agent sessions, pnpm store, simulator
/// containers), fixed ecosystem baselines, and unlinked Docker objects.
pub fn all_baseline(env: &ResolveEnv<'_>, index: &ProjectIndex) -> Vec<Claim> {
    let mut claims = apply::reverse_links(env, index);
    claims.extend(apply::baselines(env));
    claims.extend(joins::docker_unlinked(env));
    claims
}
