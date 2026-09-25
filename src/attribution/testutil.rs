//! Shared test fixture for resolver/accounting/model unit tests: a
//! `ResolveEnv` built from fake `Paths`/`Config`, empty walked trees and
//! scanner snapshots, and a `MockCommandRunner`, plus a `claim` builder for
//! the common "one path, one owner, a fixed raw size" shape most tests want.
//! Replaces the near-identical private `Fixture` structs `accounting.rs`,
//! `entitlements.rs`, and `model.rs` each hand-rolled.

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::{Config, Paths};
use crate::model::ScannerId;
use crate::runner::MockCommandRunner;
use crate::scan::walk::DirTree;

use super::bus::Snapshot;
use super::model::{Claim, EntryKind, EvidenceTier, ResolveEnv};

pub(crate) struct EnvFixture {
    pub paths: Paths,
    pub config: Config,
    pub trees: Vec<Arc<DirTree>>,
    pub snapshots: HashMap<ScannerId, Snapshot>,
    pub runner: MockCommandRunner,
}

impl EnvFixture {
    pub fn new() -> Self {
        EnvFixture {
            paths: Paths::from_home("/tmp/macaudit-attribution-test-home"),
            config: Config::default(),
            trees: Vec::new(),
            snapshots: HashMap::new(),
            runner: MockCommandRunner::new(),
        }
    }

    pub fn env(&self) -> ResolveEnv<'_> {
        ResolveEnv::new(
            &self.paths,
            &self.config,
            &self.trees,
            &self.snapshots,
            &self.runner,
        )
    }
}

impl Default for EnvFixture {
    fn default() -> Self {
        Self::new()
    }
}

/// A claim with an overridden raw size — the shape almost every accounting
/// test wants, without threading a `Sizer`/walked tree through the test.
pub(crate) fn claim(path: &str, owner: &str, kind: EntryKind, bytes: u64) -> Claim {
    Claim::new(path, owner, kind, EvidenceTier::Exact, "test").raw_bytes_override(bytes)
}
