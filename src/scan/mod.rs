//! Scanner trait, execution context, and the module tree of concrete scanners.
//!
//! **Contract for implementation lanes:** a scanner depends only on the frozen
//! types re-exported here plus `crate::model`, `crate::config`, `crate::runner`.
//! It sends `Progress`/`Finding` events; it must NOT send `Started`/`Finished`/
//! `Failed` (the engine wrapper does that). A scanner touches only its own
//! `src/scan/<name>.rs` file and its own `tests/fixtures/<name>/` directory.

pub mod pipe;
pub mod sizing;
pub mod walk;

// Concrete scanners (stubs until their lane lands).
pub mod apps;
pub mod brew;
pub mod docker;
pub mod fs;
pub mod git;
pub mod global_tools;
pub mod ios;
pub mod launchd;
pub mod ports;
pub mod runtimes;
pub mod shell_env;
pub mod simulator;
pub mod ssh_keys;
pub mod system;
pub mod tcc;
pub mod time_machine;
pub mod volume;

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, Paths};
use crate::model::{Finding, ScanEvent, ScannerId};
use crate::runner::CommandRunner;
use crate::scan::pipe::{RepoReceiver, RepoSender};

/// The first `max_bytes` of a file, decoded lossily as UTF-8. Loops until
/// EOF or the cap rather than trusting a single `read()` call, which on some
/// filesystems/kernels can return fewer bytes than requested even when more
/// remain (a short read used to silently truncate the attribution crate's
/// manifest parsing). `None` when the file can't be opened at all; an empty
/// file is `Some(String::new())`.
pub fn read_head(path: &Path, max_bytes: usize) -> Option<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; max_bytes];
    let mut total = 0;
    while total < max_bytes {
        match file.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => break,
        }
    }
    buf.truncate(total);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

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

/// Outcome of a bounded command run, for scanners that must tell "the tool
/// is not installed" (offer an install hint) apart from "it ran and failed"
/// (show its stderr) — `run_with_timeout` folds both into `None`.
#[derive(Debug)]
pub enum CmdOutcome {
    Ok(crate::runner::CmdOutput),
    /// Could not be spawned — in practice, the binary is not on `$PATH`.
    NotInstalled(String),
    /// Ran and exited non-zero.
    Failed(crate::runner::CmdOutput),
    TimedOut,
}

pub async fn run_classified(
    ctx: &ScanCtx,
    program: &str,
    args: &[&str],
    timeout: std::time::Duration,
) -> CmdOutcome {
    match tokio::time::timeout(timeout, ctx.runner.run(program, args, &ctx.token)).await {
        Err(_) => CmdOutcome::TimedOut,
        Ok(Err(e)) => CmdOutcome::NotInstalled(e.to_string()),
        Ok(Ok(out)) if out.success() => CmdOutcome::Ok(out),
        Ok(Ok(out)) => CmdOutcome::Failed(out),
    }
}

/// A scanner: produces findings for one section.
#[async_trait]
pub trait Scanner: Send + Sync {
    fn id(&self) -> ScannerId;
    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_head_reads_up_to_the_cap_and_none_for_a_missing_file() {
        let tmp = std::env::temp_dir().join("macaudit-scan-read-head-test.txt");
        std::fs::write(&tmp, "hello world").unwrap();
        assert_eq!(read_head(&tmp, 5), Some("hello".to_string()));
        assert_eq!(read_head(&tmp, 100), Some("hello world".to_string()));
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(
            read_head(Path::new("/definitely/not/a/real/path"), 64),
            None
        );
    }
}
