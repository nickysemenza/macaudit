//! Scanner trait, execution context, and the module tree of concrete scanners.
//!
//! **Contract for implementation lanes:** a scanner depends only on the frozen
//! types re-exported here plus `crate::model`, `crate::config`, `crate::runner`.
//! It sends `Progress`/`Finding` events; it must NOT send `Started`/`Finished`/
//! `Failed` (the engine wrapper does that). A scanner touches only its own
//! `src/scan/<name>.rs` file and its own `tests/fixtures/<name>/` directory.

pub mod pipe;
pub mod sizing;

// Concrete scanners (stubs until their lane lands).
pub mod apps;
pub mod brew;
pub mod docker;
pub mod fs;
pub mod git;
pub mod global_tools;
pub mod launchd;
pub mod ports;
pub mod runtimes;
pub mod shell_env;
pub mod simulator;
pub mod ssh_keys;
pub mod system;
pub mod time_machine;
pub mod volume;

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, Paths};
use crate::model::{Finding, ScanEvent, ScannerId};
use crate::runner::CommandRunner;
use crate::scan::pipe::{RepoReceiver, RepoSender};

/// Everything a scanner needs to do its work and report back. Cloneable so a
/// scanner can hand copies to spawned sub-tasks (the sizing pool, etc.).
#[derive(Clone)]
pub struct ScanCtx {
    pub tx: mpsc::Sender<ScanEvent>,
    pub token: CancellationToken,
    pub gen: u64,
    pub config: Arc<Config>,
    pub paths: Arc<Paths>,
    pub runner: Arc<dyn CommandRunner>,
    /// The scanner this context belongs to. The engine stamps it before calling
    /// `scan` (via `with_current`); `emit`/`progress` tag events with it.
    pub current: ScannerId,
    /// Present only for FsScanner: send discovered repo roots to GitScanner.
    pub repo_tx: Option<RepoSender>,
    /// Present only for GitScanner: receive repo roots from FsScanner.
    /// `Arc<Mutex<_>>` because `ScanCtx` is `Clone` but a receiver is not.
    pub repo_rx: Option<Arc<tokio::sync::Mutex<RepoReceiver>>>,
    /// When true, FsScanner should discover `.git` roots (feed the pipe) but skip
    /// emitting disk findings — used when `git` is requested without `disk`.
    pub fs_discovery_only: bool,
}

impl ScanCtx {
    /// Internal: engine stamps the owning scanner id before calling `scan`.
    pub fn with_current(mut self, id: ScannerId) -> Self {
        self.current = id;
        self
    }

    /// Emit a finding for this scanner+generation. Ignores send errors (receiver
    /// gone ⇒ shutting down).
    pub async fn emit(&self, finding: Finding) {
        let _ = self
            .tx
            .send(ScanEvent::Finding {
                scanner: self.current,
                gen: self.gen,
                finding: Box::new(finding),
            })
            .await;
    }

    /// Report progress.
    pub async fn progress(&self, msg: impl Into<String>, done: u64, total: Option<u64>) {
        let _ = self
            .tx
            .send(ScanEvent::Progress {
                scanner: self.current,
                gen: self.gen,
                msg: msg.into(),
                done,
                total,
            })
            .await;
    }

    /// Whether the current scan generation has been cancelled.
    pub fn cancelled(&self) -> bool {
        self.token.is_cancelled()
    }
}

/// Run a command with a hard deadline. `None` when it could not be spawned,
/// exited non-zero, or ran past `timeout` — callers treat every one of those
/// as "this data source is unavailable" and degrade to partial results.
pub async fn run_with_timeout(
    ctx: &ScanCtx,
    program: &str,
    args: &[&str],
    timeout: std::time::Duration,
) -> Option<crate::runner::CmdOutput> {
    match tokio::time::timeout(timeout, ctx.runner.run(program, args, &ctx.token)).await {
        Ok(Ok(out)) if out.success() => Some(out),
        _ => None,
    }
}

/// A scanner: produces findings for one section.
#[async_trait]
pub trait Scanner: Send + Sync {
    fn id(&self) -> ScannerId;
    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()>;
}
