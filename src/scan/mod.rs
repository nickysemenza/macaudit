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
use crate::model::{Finding, FindingKind, ScanEvent, ScannerId, Severity};
use crate::runner::{is_resource_limit, CommandError, CommandRunner};
use crate::scan::pipe::{RepoReceiver, RepoSender};

/// The first `max_bytes` of a file, decoded lossily as UTF-8. Loops until
/// EOF or the cap rather than trusting a single `read()` call, which on some
/// filesystems/kernels can return fewer bytes than requested even when more
/// remain (a short read used to silently truncate the attribution crate's
/// manifest parsing). `None` when the file can't be opened at all; an empty
/// file is `Some(String::new())`.
pub fn read_head(path: &Path, max_bytes: usize) -> Option<String> {
    use std::io::Read;
    let _materialization = walk::listing::MaterializationGuard::enter().ok()?;
    let _memory = crate::inventory::MemoryBudget::shared()
        .reserve(max_bytes.checked_mul(3)?)
        .ok()?;
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

pub async fn run_command(
    ctx: &ScanCtx,
    program: &str,
    args: &[&str],
    timeout: std::time::Duration,
) -> Result<crate::runner::CmdOutput, CommandError> {
    let token = ctx.token.child_token();
    let command = ctx.runner.run(program, args, &token);
    tokio::pin!(command);
    let result = tokio::select! {
        biased;
        result = &mut command => result,
        _ = tokio::time::sleep(timeout) => {
            token.cancel();
            let result = command.await;
            if let Err(error) = result {
                if is_resource_limit(&error) {
                    return Err(CommandError::ResourceLimit(error));
                }
            }
            return Err(CommandError::TimedOut);
        }
    };
    result.map_err(|error| {
        if is_resource_limit(&error) {
            CommandError::ResourceLimit(error)
        } else if ctx.cancelled()
            || error.chain().any(|cause| {
                matches!(
                    cause.downcast_ref::<CommandError>(),
                    Some(CommandError::Cancelled)
                )
            })
        {
            CommandError::Cancelled
        } else if error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound)
        }) {
            CommandError::NotFound(program.to_string())
        } else {
            CommandError::Unavailable(error)
        }
    })
}

pub async fn report_command_error(ctx: &ScanCtx, program: &str, error: &CommandError) {
    if matches!(error, CommandError::Cancelled) {
        return;
    }
    if matches!(error, CommandError::ResourceLimit(_)) {
        ctx.token.cancel();
    }
    let kind = match ctx.current {
        ScannerId::System => FindingKind::SystemMetric,
        ScannerId::Fs => FindingKind::DiskCategory,
        ScannerId::Apps => FindingKind::App,
        ScannerId::Projects => FindingKind::ProjectBucket,
        ScannerId::AppStorage => FindingKind::AppStorageBucket,
        ScannerId::Brew => FindingKind::BrewFormula,
        ScannerId::Tools => FindingKind::ToolCoverage,
        ScannerId::Launchd => FindingKind::LaunchdItem,
        ScannerId::ShellEnv => FindingKind::PathEntry,
        ScannerId::Runtimes => FindingKind::RuntimeVersion,
        ScannerId::Docker => FindingKind::DockerObject,
        ScannerId::Ports => FindingKind::PortListener,
        ScannerId::Git => FindingKind::GitRepo,
        ScannerId::Simulator => FindingKind::Simulator,
        ScannerId::Ios => FindingKind::IosDevice,
        ScannerId::SshKeys => FindingKind::SshKey,
        ScannerId::TimeMachine => FindingKind::LocalSnapshot,
    };
    let error_kind = match error {
        CommandError::ResourceLimit(_) => "resource_limit",
        CommandError::TimedOut => "timed_out",
        CommandError::NotFound(_) => "not_installed",
        _ => "unavailable",
    };
    let detail: String = error.to_string().chars().take(4096).collect();
    let finding = Finding::new(kind, &format!("__command_coverage__:{program}"), format!("{program} data unavailable"))
        .severity(Severity::Attention)
        .detail(detail)
        .meta(serde_json::json!({"context":"audit_host", "complete":false, "group":"Coverage", "error_kind":error_kind}));
    if matches!(error, CommandError::ResourceLimit(_)) {
        let _ = ctx.tx.try_send(ScanEvent::Finding {
            scanner: ctx.current,
            gen: ctx.gen,
            finding: Box::new(finding),
        });
    } else {
        tokio::select! {
            _ = ctx.token.cancelled() => {},
            _ = ctx.emit(finding) => {},
        }
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
    match run_command(ctx, program, args, timeout).await {
        Ok(out) if out.success() => Some(out),
        Ok(out) => {
            let error = CommandError::Unavailable(anyhow::anyhow!(
                "{program} exited with status {}",
                out.status
            ));
            report_command_error(ctx, program, &error).await;
            None
        }
        Err(error) => {
            report_command_error(ctx, program, &error).await;
            None
        }
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
    Unavailable(CommandError),
}

pub async fn run_classified(
    ctx: &ScanCtx,
    program: &str,
    args: &[&str],
    timeout: std::time::Duration,
) -> CmdOutcome {
    match run_command(ctx, program, args, timeout).await {
        Err(error) => {
            report_command_error(ctx, program, &error).await;
            match error {
                CommandError::NotFound(program) => CmdOutcome::NotInstalled(program),
                CommandError::TimedOut => CmdOutcome::TimedOut,
                error => CmdOutcome::Unavailable(error),
            }
        }
        Ok(out) if out.success() => CmdOutcome::Ok(out),
        Ok(out) => {
            report_command_error(
                ctx,
                program,
                &CommandError::Unavailable(anyhow::anyhow!(
                    "{program} exited with status {}",
                    out.status
                )),
            )
            .await;
            CmdOutcome::Failed(out)
        }
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

    struct FailureRunner(std::io::ErrorKind);

    #[async_trait]
    impl CommandRunner for FailureRunner {
        async fn run(
            &self,
            _program: &str,
            _args: &[&str],
            _token: &CancellationToken,
        ) -> anyhow::Result<crate::runner::CmdOutput> {
            if self.0 == std::io::ErrorKind::OutOfMemory {
                Err(
                    anyhow::Error::new(crate::inventory::InventoryError::ResourceLimit)
                        .context("capture refused"),
                )
            } else {
                Err(std::io::Error::from(self.0).into())
            }
        }
    }

    fn context(
        home: &Path,
        runner: Arc<dyn CommandRunner>,
    ) -> (ScanCtx, mpsc::Receiver<ScanEvent>) {
        let (tx, rx) = mpsc::channel(32);
        (
            ScanCtx {
                tx,
                token: CancellationToken::new(),
                gen: 1,
                config: Arc::new(Config::default()),
                paths: Arc::new(Paths::from_home(home)),
                runner,
                current: ScannerId::Brew,
                repo_tx: None,
                repo_rx: None,
                fs_discovery_only: false,
            },
            rx,
        )
    }

    #[tokio::test]
    async fn resource_errors_are_typed_and_report_incomplete_coverage() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, mut rx) = context(
            tmp.path(),
            Arc::new(FailureRunner(std::io::ErrorKind::OutOfMemory)),
        );
        let outcome = run_classified(&ctx, "fixture", &[], std::time::Duration::from_secs(1)).await;
        assert!(matches!(
            outcome,
            CmdOutcome::Unavailable(CommandError::ResourceLimit(_))
        ));
        assert!(ctx.cancelled());
        let ScanEvent::Finding { finding, .. } = rx.try_recv().unwrap() else {
            panic!("missing coverage")
        };
        assert_eq!(finding.meta["complete"], false);
        assert_eq!(finding.meta["error_kind"], "resource_limit");
        assert_eq!(finding.meta["context"], "audit_host");
    }

    #[tokio::test]
    async fn resource_error_is_not_optional_success_or_missing_brew() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = Arc::new(FailureRunner(std::io::ErrorKind::OutOfMemory));
        let (ctx, mut rx) = context(tmp.path(), runner.clone());
        assert!(
            run_with_timeout(&ctx, "fixture", &[], std::time::Duration::from_secs(1))
                .await
                .is_none()
        );
        assert!(ctx.cancelled());
        let ScanEvent::Finding { finding, .. } = rx.try_recv().unwrap() else {
            panic!("missing coverage")
        };
        assert_eq!(finding.meta["error_kind"], "resource_limit");
        let (ctx, mut rx) = context(tmp.path(), runner);
        let error = brew::BrewScanner.scan(ctx).await.unwrap_err();
        assert!(crate::runner::is_resource_limit(&error));
        while let Ok(event) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = event {
                assert_ne!(finding.title, "Homebrew not found");
                assert_eq!(finding.meta["complete"], false);
            }
        }
    }

    #[tokio::test]
    async fn resource_error_retires_git_even_when_discovery_sender_stays_open() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut ctx, mut events) = context(
            tmp.path(),
            Arc::new(FailureRunner(std::io::ErrorKind::OutOfMemory)),
        );
        let (sender, receiver) = pipe::repo_channel();
        sender
            .send(pipe::RepoDiscovery {
                root: tmp.path().join("repo"),
            })
            .unwrap();
        ctx.current = ScannerId::Git;
        ctx.repo_rx = Some(Arc::new(tokio::sync::Mutex::new(receiver)));
        let error =
            tokio::time::timeout(std::time::Duration::from_secs(1), git::GitScanner.scan(ctx))
                .await
                .unwrap()
                .unwrap_err();
        assert!(crate::runner::is_resource_limit(&error));
        let mut coverage = false;
        while let Ok(event) = events.try_recv() {
            if let ScanEvent::Finding { finding, .. } = event {
                coverage |= finding.meta["error_kind"] == "resource_limit"
                    && finding.meta["complete"] == false;
            }
        }
        assert!(coverage);
        drop(sender);
    }

    #[tokio::test]
    async fn resource_error_does_not_wait_for_a_full_event_queue() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, _events) = context(
            tmp.path(),
            Arc::new(FailureRunner(std::io::ErrorKind::OutOfMemory)),
        );
        for _ in 0..ctx.tx.max_capacity() {
            ctx.tx
                .try_send(ScanEvent::Progress {
                    scanner: ctx.current,
                    gen: ctx.gen,
                    msg: "fixture".into(),
                    done: 0,
                    total: None,
                })
                .unwrap();
        }
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_classified(&ctx, "fixture", &[], std::time::Duration::from_secs(1)),
        )
        .await
        .unwrap();
        assert!(matches!(
            outcome,
            CmdOutcome::Unavailable(CommandError::ResourceLimit(_))
        ));
        assert!(ctx.cancelled());
    }

    #[tokio::test]
    async fn only_missing_executable_is_not_installed() {
        let tmp = tempfile::tempdir().unwrap();
        for error in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied,
        ] {
            let (ctx, _rx) = context(tmp.path(), Arc::new(FailureRunner(error)));
            let outcome =
                run_classified(&ctx, "fixture", &[], std::time::Duration::from_secs(1)).await;
            assert_eq!(
                matches!(outcome, CmdOutcome::NotInstalled(_)),
                error == std::io::ErrorKind::NotFound
            );
        }
    }

    struct RetirementRunner(Arc<std::sync::atomic::AtomicBool>);

    #[async_trait]
    impl CommandRunner for RetirementRunner {
        async fn run(
            &self,
            _program: &str,
            _args: &[&str],
            token: &CancellationToken,
        ) -> anyhow::Result<crate::runner::CmdOutput> {
            token.cancelled().await;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            self.0.store(true, std::sync::atomic::Ordering::Release);
            Err(CommandError::Cancelled.into())
        }
    }

    #[tokio::test]
    async fn deadline_waits_for_retirement_without_cancelling_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let retired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (ctx, _rx) = context(tmp.path(), Arc::new(RetirementRunner(retired.clone())));
        let result = run_command(&ctx, "fixture", &[], std::time::Duration::from_millis(1)).await;
        assert!(matches!(result, Err(CommandError::TimedOut)));
        assert!(retired.load(std::sync::atomic::Ordering::Acquire));
        assert!(!ctx.cancelled());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn deadline_kills_spawned_descendants() {
        let tmp = tempfile::tempdir().unwrap();
        let sentinel = tmp.path().join("escaped");
        let (ctx, _rx) = context(tmp.path(), Arc::new(crate::runner::RealCommandRunner));
        let result = run_command(
            &ctx,
            "/bin/sh",
            &[
                "-c",
                "(sleep 1; printf escaped > \"$1\") & wait",
                "fixture",
                sentinel.to_str().unwrap(),
            ],
            std::time::Duration::from_millis(100),
        )
        .await;
        assert!(matches!(result, Err(CommandError::TimedOut)));
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        assert!(!sentinel.exists());
    }

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
