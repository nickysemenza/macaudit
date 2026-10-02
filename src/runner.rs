//! The universal subprocess seam.
//!
//! Every scanner that shells out does so through `CommandRunner`, so unit tests
//! inject `MockCommandRunner` with checked-in fixture output and never touch the
//! real machine. `RealCommandRunner` runs `tokio::process` and is cancellable.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use crate::inventory::{InventoryError, MemoryBudget, Reservation};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const CAPTURE_RESERVATION_BYTES: usize = MAX_OUTPUT_BYTES * 2 + 64 * 1024 + 512;
const MAX_ARGUMENT_BYTES: usize = 1024 * 1024;
const MAX_ARGUMENTS: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("subprocess cancelled")]
    Cancelled,
    #[error("subprocess deadline exceeded")]
    TimedOut,
    #[error("executable not found: {0}")]
    NotFound(String),
    #[error("resource limit: {0:#}")]
    ResourceLimit(#[source] anyhow::Error),
    #[error("subprocess unavailable: {0:#}")]
    Unavailable(#[source] anyhow::Error),
}

pub fn is_resource_limit(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<InventoryError>() == Some(&InventoryError::ResourceLimit)
            || matches!(
                cause.downcast_ref::<CommandError>(),
                Some(CommandError::ResourceLimit(_))
            )
    })
}

struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(unix)]
struct ProcessGroup(Option<libc::pid_t>);

#[cfg(unix)]
impl ProcessGroup {
    fn kill(&mut self) {
        if let Some(pid) = self.0.take() {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
}

#[cfg(unix)]
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.kill();
    }
}

#[derive(Clone, Debug)]
pub struct CapturedBytes {
    data: Arc<CommandBuffer>,
}

#[derive(Debug)]
struct CommandBuffer {
    bytes: Vec<u8>,
    decoded: Option<DecodedText>,
    _memory: Arc<Reservation>,
}

#[derive(Debug)]
struct DecodedText {
    text: String,
    _memory: Reservation,
}

impl CapturedBytes {
    fn fixture(source: impl AsRef<[u8]>) -> Self {
        let source = source.as_ref();
        let budget = MemoryBudget::shared();
        let memory = budget
            .reserve(source.len() + 128)
            .expect("fixture output fits memory budget");
        let decoded = decode_output(source, &budget).expect("fixture decoding fits memory budget");
        Self {
            data: Arc::new(CommandBuffer {
                bytes: source.to_vec(),
                decoded,
                _memory: Arc::new(memory),
            }),
        }
    }

    fn text(&self) -> &str {
        match &self.data.decoded {
            Some(decoded) => &decoded.text,
            None => std::str::from_utf8(&self.data.bytes).expect("capture validated UTF-8"),
        }
    }
}

fn decode_output(
    bytes: &[u8],
    budget: &Arc<MemoryBudget>,
) -> Result<Option<DecodedText>, InventoryError> {
    if std::str::from_utf8(bytes).is_ok() {
        return Ok(None);
    }
    let mut length = 0usize;
    for chunk in bytes.utf8_chunks() {
        length = length
            .checked_add(chunk.valid().len())
            .and_then(|length| length.checked_add(if chunk.invalid().is_empty() { 0 } else { 3 }))
            .ok_or(InventoryError::ResourceLimit)?;
    }
    let memory = budget.reserve(
        length
            .checked_add(std::mem::size_of::<DecodedText>() + 128)
            .ok_or(InventoryError::ResourceLimit)?,
    )?;
    let mut text = String::new();
    text.try_reserve_exact(length)
        .map_err(|_| InventoryError::ResourceLimit)?;
    for chunk in bytes.utf8_chunks() {
        text.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            text.push('\u{fffd}');
        }
    }
    Ok(Some(DecodedText {
        text,
        _memory: memory,
    }))
}

fn argument_reservation(
    program: &str,
    args: &[&str],
    budget: &Arc<MemoryBudget>,
) -> Result<Reservation, InventoryError> {
    if args.len() > MAX_ARGUMENTS {
        return Err(InventoryError::ResourceLimit);
    }
    let bytes = args
        .iter()
        .try_fold(program.len(), |bytes, argument| {
            bytes.checked_add(argument.len() + 1)
        })
        .filter(|bytes| *bytes <= MAX_ARGUMENT_BYTES)
        .ok_or(InventoryError::ResourceLimit)?;
    let bytes = bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add((args.len() + 1) * 128 + 4096))
        .ok_or(InventoryError::ResourceLimit)?;
    budget.reserve(bytes)
}

impl Deref for CapturedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data.bytes
    }
}

impl AsRef<[u8]> for CapturedBytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

/// Captured output of a finished subprocess.
#[derive(Clone, Debug)]
pub struct CmdOutput {
    pub status: i32,
    pub stdout: CapturedBytes,
    pub stderr: CapturedBytes,
}

impl CmdOutput {
    pub fn stdout_str(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.stdout.text())
    }
    pub fn stderr_str(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.stderr.text())
    }
    pub fn success(&self) -> bool {
        self.status == 0
    }
}

/// Run a program to completion and capture its output. Implementors must be
/// cheap to `Arc`-share across scanner tasks.
#[async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        token: &CancellationToken,
    ) -> anyhow::Result<CmdOutput>;
}

pub struct BoundedCommandRunner {
    inner: Arc<dyn CommandRunner>,
    permits: tokio::sync::Semaphore,
}

impl BoundedCommandRunner {
    pub fn new(inner: Arc<dyn CommandRunner>) -> Self {
        Self {
            inner,
            permits: tokio::sync::Semaphore::new(2),
        }
    }
}

#[async_trait]
impl CommandRunner for BoundedCommandRunner {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        token: &CancellationToken,
    ) -> anyhow::Result<CmdOutput> {
        let queued = Instant::now();
        let _permit = tokio::select! {
            biased;
            _ = token.cancelled() => {
                tracing::debug!(program, permit_wait_ms = queued.elapsed().as_secs_f64() * 1000.0, "subprocess queue cancelled");
                return Err(CommandError::Cancelled.into());
            },
            permit = self.permits.acquire() => permit?,
        };
        tracing::debug!(
            program,
            permit_wait_ms = queued.elapsed().as_secs_f64() * 1000.0,
            "subprocess admitted"
        );
        let started = Instant::now();
        let result = self.inner.run(program, args, token).await;
        tracing::debug!(
            program,
            duration_ms = started.elapsed().as_secs_f64() * 1000.0,
            cancelled = token.is_cancelled(),
            success = result.is_ok(),
            stdout_bytes = result
                .as_ref()
                .map(|output| output.stdout.len())
                .unwrap_or_default(),
            stderr_bytes = result
                .as_ref()
                .map(|output| output.stderr.len())
                .unwrap_or_default(),
            status = result.as_ref().ok().map(|output| output.status),
            "subprocess completed"
        );
        result
    }
}

/// Real subprocess execution via tokio. Killed if the scan generation is cancelled.
pub struct RealCommandRunner;

#[async_trait]
impl CommandRunner for RealCommandRunner {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        token: &CancellationToken,
    ) -> anyhow::Result<CmdOutput> {
        static PERMITS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
        run_supervised(
            program,
            args,
            token,
            MemoryBudget::shared(),
            PERMITS
                .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2)))
                .clone(),
        )
        .await
    }
}

async fn run_supervised(
    program: &str,
    args: &[&str],
    token: &CancellationToken,
    budget: Arc<MemoryBudget>,
    permits: Arc<tokio::sync::Semaphore>,
) -> anyhow::Result<CmdOutput> {
    let queued = Instant::now();
    let permit = tokio::select! {
        biased;
        _ = token.cancelled() => {
            tracing::debug!(program, permit_wait_ms = queued.elapsed().as_secs_f64() * 1000.0, "global subprocess queue cancelled");
            return Err(CommandError::Cancelled.into());
        },
        permit = permits.acquire_owned() => permit?,
    };
    tracing::debug!(
        program,
        permit_wait_ms = queued.elapsed().as_secs_f64() * 1000.0,
        "global subprocess admitted"
    );

    let arguments = argument_reservation(program, args, &budget)?;
    let memory = Arc::new(budget.reserve(CAPTURE_RESERVATION_BYTES)?);
    let program = program.to_string();
    let args: Vec<String> = args
        .iter()
        .map(|argument| (*argument).to_string())
        .collect();
    let token = token.child_token();
    let _cancel = CancelOnDrop(token.clone());
    tokio::spawn(async move {
        let _permit = permit;
        let _arguments = arguments;
        execute_owned(program, args, token, memory).await
    })
    .await?
}

async fn execute_owned(
    program: String,
    args: Vec<String>,
    token: CancellationToken,
    memory: Arc<Reservation>,
) -> anyhow::Result<CmdOutput> {
    use tokio::process::Command;
    anyhow::ensure!(!token.is_cancelled(), CommandError::Cancelled);
    let mut cmd = Command::new(program);
    cmd.args(&args);
    cmd.kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    if std::path::Path::new(cmd.as_std().get_program()).file_name()
        == Some(std::ffi::OsStr::new("git"))
    {
        cmd.env("GIT_OPTIONAL_LOCKS", "0");
    }
    if std::path::Path::new(cmd.as_std().get_program()).file_name()
        == Some(std::ffi::OsStr::new("brew"))
    {
        cmd.env("HOMEBREW_NO_AUTO_UPDATE", "1");
        cmd.env("HOMEBREW_NO_BOOTSNAP", "1");
    }
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let started = Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|error| anyhow::Error::new(error).context("failed to spawn subprocess"))?;
    #[cfg(unix)]
    let mut group = ProcessGroup(Some(
        child.id().expect("spawned child has a pid") as libc::pid_t
    ));
    tracing::debug!(pid = child.id(), "subprocess spawned");

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let total = Arc::new(AtomicUsize::new(0));
    let result = {
        let capture = async {
            let (stdout, stderr) = tokio::try_join!(
                capture_output(stdout, memory.clone(), total.clone()),
                capture_output(stderr, memory.clone(), total.clone()),
            )?;
            let status = child.wait().await?;
            #[cfg(unix)]
            {
                group.0 = None;
            }
            Ok(CmdOutput {
                status: status.code().unwrap_or(-1),
                stdout,
                stderr,
            })
        };
        tokio::pin!(capture);
        tokio::select! {
            biased;
            _ = token.cancelled() => Err(CommandError::Cancelled.into()),
            result = &mut capture => result,
        }
    };
    if result.is_err() {
        tracing::debug!(
            cancelled = token.is_cancelled(),
            output_bytes = total.load(Ordering::Acquire),
            "subprocess stop requested"
        );
        #[cfg(unix)]
        group.kill();
        let killed = child.kill().await.is_ok();
        let reaped = child.wait().await.is_ok();
        tracing::debug!(killed, reaped, "subprocess retirement completed");
    }
    tracing::debug!(
        duration_ms = started.elapsed().as_secs_f64() * 1000.0,
        output_bytes = total.load(Ordering::Acquire),
        success = result.is_ok(),
        "subprocess capture completed"
    );
    result
}

async fn capture_output(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    memory: Arc<Reservation>,
    total: Arc<AtomicUsize>,
) -> anyhow::Result<CapturedBytes> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        total
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |bytes| {
                bytes
                    .checked_add(count)
                    .filter(|bytes| *bytes <= MAX_OUTPUT_BYTES)
            })
            .map_err(|_| {
                anyhow::anyhow!(InventoryError::ResourceLimit)
                    .context("subprocess output exceeds 32 MiB")
            })?;
        bytes
            .try_reserve_exact(count)
            .map_err(|_| InventoryError::ResourceLimit)?;
        bytes.extend_from_slice(&buffer[..count]);
    }
    let decoded = decode_output(&bytes, &MemoryBudget::shared())?;
    Ok(CapturedBytes {
        data: Arc::new(CommandBuffer {
            bytes,
            decoded,
            _memory: memory,
        }),
    })
}

/// Deterministic runner for tests. Built with the `on`/`on_fail` builder;
/// unmatched invocations return an error naming the exact (program, args) so a
/// missing fixture is loud rather than silently empty.
#[derive(Default)]
pub struct MockCommandRunner {
    responses: HashMap<Vec<String>, CmdOutput>,
    calls: Mutex<Vec<Vec<String>>>,
}

impl MockCommandRunner {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(program: &str, args: &[&str]) -> Vec<String> {
        let mut k = Vec::with_capacity(args.len() + 1);
        k.push(program.to_string());
        k.extend(args.iter().map(|a| a.to_string()));
        k
    }

    /// Register a successful response for an exact (program, args) invocation.
    pub fn on(mut self, program: &str, args: &[&str], stdout: &str) -> Self {
        self.responses.insert(
            Self::key(program, args),
            CmdOutput {
                status: 0,
                stdout: CapturedBytes::fixture(stdout.as_bytes()),
                stderr: CapturedBytes::fixture(Vec::new()),
            },
        );
        self
    }

    /// Register a failing response.
    pub fn on_fail(mut self, program: &str, args: &[&str], status: i32, stderr: &str) -> Self {
        self.responses.insert(
            Self::key(program, args),
            CmdOutput {
                status,
                stdout: CapturedBytes::fixture(Vec::new()),
                stderr: CapturedBytes::fixture(stderr.as_bytes()),
            },
        );
        self
    }

    /// The invocations that were actually made, in order, as `[program, args...]`.
    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl CommandRunner for MockCommandRunner {
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        _token: &CancellationToken,
    ) -> anyhow::Result<CmdOutput> {
        let key = Self::key(program, args);
        self.calls.lock().unwrap().push(key.clone());
        match self.responses.get(&key) {
            Some(out) => Ok(out.clone()),
            None => anyhow::bail!("MockCommandRunner: no response registered for {:?}", key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn wait_until(mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[cfg(unix)]
    async fn owned_group_stops(drop_future: bool) {
        let tmp = tempfile::tempdir().unwrap();
        let sentinel = tmp.path().join("descendant-wrote");
        let pids = tmp.path().join("pids");
        let budget = MemoryBudget::new(CAPTURE_RESERVATION_BYTES + 1024 * 1024);
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let token = CancellationToken::new();
        let task = tokio::spawn({
            let token = token.clone();
            let budget = budget.clone();
            let permits = permits.clone();
            let sentinel = sentinel.clone();
            let pids = pids.clone();
            async move {
                run_supervised("/bin/sh", &["-c", "(sleep 1; printf escaped > \"$1\") & printf '%s %s\\n' \"$$\" \"$!\" > \"$2\"; wait", "fixture", sentinel.to_str().unwrap(), pids.to_str().unwrap()], &token, budget, permits).await
            }
        });
        wait_until(|| {
            std::fs::read_to_string(&pids).is_ok_and(|text| text.split_whitespace().count() == 2)
        })
        .await;
        let pid: libc::pid_t = std::fs::read_to_string(&pids)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(permits.available_permits(), 0);
        assert!(budget.used() > MAX_OUTPUT_BYTES);
        if drop_future {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            token.cancel();
            assert!(task
                .await
                .unwrap()
                .unwrap_err()
                .downcast_ref::<CommandError>()
                .is_some_and(|error| matches!(error, CommandError::Cancelled)));
        }
        wait_until(|| budget.used() == 0 && permits.available_permits() == 1).await;
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        assert!(!sentinel.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_kills_descendants_and_reaps_before_releasing_accounting() {
        owned_group_stops(false).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_run_future_retires_owned_group_and_reservations() {
        owned_group_stops(true).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unrelated_cleanup_stop_does_not_kill_active_command() {
        let stop_between_actions = CancellationToken::new();
        let active = CancellationToken::new();
        let task = tokio::spawn(async move {
            RealCommandRunner
                .run("/bin/sh", &["-c", "sleep 0.05; printf finished"], &active)
                .await
        });
        stop_between_actions.cancel();
        let output = task.await.unwrap().unwrap();
        assert!(output.success());
        assert_eq!(output.stdout_str(), "finished");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn git_and_brew_subprocesses_inherit_stateless_policy() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        for (program, script, expected) in [
            ("git", "#!/bin/sh\nprintf '%s' \"$GIT_OPTIONAL_LOCKS\"\n", "0"),
            ("brew", "#!/bin/sh\nprintf '%s %s' \"$HOMEBREW_NO_AUTO_UPDATE\" \"$HOMEBREW_NO_BOOTSNAP\"\n", "1 1"),
        ] {
            let path = tmp.path().join(program);
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            let output = RealCommandRunner.run(path.to_str().unwrap(), &[], &CancellationToken::new()).await.unwrap();
            assert!(output.success());
            assert_eq!(output.stdout_str(), expected);
        }
    }

    #[test]
    fn lossy_decoding_reserves_before_allocation_and_is_shared() {
        let source = b"a\xff\xe2\x82\xf0\x9f\xa6\x80";
        let empty = MemoryBudget::new(1);
        assert_eq!(
            decode_output(source, &empty).unwrap_err(),
            InventoryError::ResourceLimit
        );
        assert_eq!(empty.used(), 0);
        let budget = MemoryBudget::new(4096);
        let decoded = decode_output(source, &budget).unwrap();
        let output = CapturedBytes {
            data: Arc::new(CommandBuffer {
                bytes: source.to_vec(),
                decoded,
                _memory: Arc::new(budget.reserve(source.len() + 128).unwrap()),
            }),
        };
        let cloned = output.clone();
        assert_eq!(output.text(), String::from_utf8_lossy(source));
        assert_eq!(output.text().as_ptr(), cloned.text().as_ptr());
        drop(output);
        assert!(budget.used() > 0);
        drop(cloned);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn argument_bytes_and_count_fail_before_copying_or_spawning() {
        let budget = MemoryBudget::new(8 * 1024 * 1024);
        let oversized = "x".repeat(MAX_ARGUMENT_BYTES + 1);
        assert!(argument_reservation(&oversized, &[], &budget).is_err());
        assert!(argument_reservation("echo", &vec![""; MAX_ARGUMENTS + 1], &budget).is_err());
        assert_eq!(budget.used(), 0);
        let memory = argument_reservation("echo", &["small"], &budget).unwrap();
        assert!(memory.bytes() >= "echosmall".len());
        drop(memory);
        assert_eq!(budget.used(), 0);
    }

    struct GatedRunner {
        started: AtomicUsize,
        active: AtomicUsize,
        peak: AtomicUsize,
        entered: tokio::sync::Semaphore,
        release: tokio::sync::Semaphore,
    }

    impl GatedRunner {
        fn new() -> Self {
            Self {
                started: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                entered: tokio::sync::Semaphore::new(0),
                release: tokio::sync::Semaphore::new(0),
            }
        }
    }

    #[async_trait]
    impl CommandRunner for GatedRunner {
        async fn run(
            &self,
            _program: &str,
            _args: &[&str],
            _token: &CancellationToken,
        ) -> anyhow::Result<CmdOutput> {
            self.started.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            self.entered.add_permits(1);
            self.release.acquire().await?.forget();
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(CmdOutput {
                status: 0,
                stdout: CapturedBytes::fixture(Vec::new()),
                stderr: CapturedBytes::fixture(Vec::new()),
            })
        }
    }

    #[tokio::test]
    async fn limits_concurrent_subprocesses_to_two() {
        let inner = Arc::new(GatedRunner::new());
        let runner = Arc::new(BoundedCommandRunner::new(inner.clone()));
        let mut tasks = Vec::new();
        for _ in 0..6 {
            let runner = runner.clone();
            tasks.push(tokio::spawn(async move {
                runner.run("fixture", &[], &CancellationToken::new()).await
            }));
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            inner.entered.acquire_many(2),
        )
        .await
        .unwrap()
        .unwrap()
        .forget();
        tokio::task::yield_now().await;
        assert_eq!(inner.started.load(Ordering::SeqCst), 2);
        inner.release.add_permits(6);
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(inner.started.load(Ordering::SeqCst), 6);
        assert_eq!(inner.peak.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cancellation_while_queued_does_not_launch_subprocess() {
        let inner = Arc::new(GatedRunner::new());
        let runner = Arc::new(BoundedCommandRunner::new(inner.clone()));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let runner = runner.clone();
            tasks.push(tokio::spawn(async move {
                runner.run("fixture", &[], &CancellationToken::new()).await
            }));
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            inner.entered.acquire_many(2),
        )
        .await
        .unwrap()
        .unwrap()
        .forget();
        let token = CancellationToken::new();
        let queued = tokio::spawn({
            let token = token.clone();
            let runner = runner.clone();
            async move { runner.run("queued", &[], &token).await }
        });
        token.cancel();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), queued)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(inner.started.load(Ordering::SeqCst), 2);
        inner.release.add_permits(2);
        for task in tasks {
            task.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn mock_returns_registered_output() {
        let r = MockCommandRunner::new().on("brew", &["leaves"], "ripgrep\nfd\n");
        let out = r
            .run("brew", &["leaves"], &CancellationToken::new())
            .await
            .unwrap();
        assert!(out.success());
        assert_eq!(out.stdout_str(), "ripgrep\nfd\n");
        assert_eq!(
            r.calls(),
            vec![vec!["brew".to_string(), "leaves".to_string()]]
        );
    }

    #[tokio::test]
    async fn mock_unmatched_is_loud() {
        let r = MockCommandRunner::new();
        let err = r
            .run("git", &["status"], &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no response registered"));
    }

    #[tokio::test]
    async fn real_runner_runs_echo() {
        let r = RealCommandRunner;
        let out = r
            .run("echo", &["hi"], &CancellationToken::new())
            .await
            .unwrap();
        assert!(out.success());
        assert_eq!(out.stdout_str().trim(), "hi");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn subprocess_requires_reallocation_peak_credit_before_spawning() {
        let fixture = tempfile::tempdir().unwrap();
        let sentinel = fixture.path().join("spawned");
        let budget = MemoryBudget::new(MAX_OUTPUT_BYTES + 1024 * 1024);
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let error = run_supervised(
            "/bin/sh",
            &[
                "-c",
                "printf spawned > \"$1\"",
                "fixture",
                sentinel.to_str().unwrap(),
            ],
            &CancellationToken::new(),
            budget.clone(),
            permits.clone(),
        )
        .await
        .unwrap_err();
        assert!(is_resource_limit(&error));
        assert!(!sentinel.exists());
        assert_eq!(budget.used(), 0);
        assert_eq!(permits.available_permits(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn capture_peak_credit_survives_until_the_last_output_clone_drops() {
        let budget = MemoryBudget::new(CAPTURE_RESERVATION_BYTES + 1024 * 1024);
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let output = run_supervised(
            "/bin/sh",
            &["-c", "printf output; printf error >&2"],
            &CancellationToken::new(),
            budget.clone(),
            permits.clone(),
        )
        .await
        .unwrap();
        assert!(output.success());
        assert_eq!(output.stdout_str(), "output");
        assert_eq!(output.stderr_str(), "error");
        assert_eq!(budget.used(), CAPTURE_RESERVATION_BYTES);
        assert_eq!(permits.available_permits(), 1);
        let retained_bytes = budget.used();
        let cloned = output.stdout.clone();
        assert_eq!(cloned.as_ptr(), output.stdout.as_ptr());
        drop(output);
        assert_eq!(budget.used(), retained_bytes);
        drop(cloned);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn capture_accepts_the_exact_shared_output_limit() {
        let budget = MemoryBudget::new(CAPTURE_RESERVATION_BYTES);
        let memory = Arc::new(budget.reserve(CAPTURE_RESERVATION_BYTES).unwrap());
        let total = Arc::new(AtomicUsize::new(MAX_OUTPUT_BYTES - 1));
        let output = capture_output(&b"x"[..], memory.clone(), total.clone())
            .await
            .unwrap();
        assert_eq!(&*output, b"x");
        assert_eq!(total.load(Ordering::Acquire), MAX_OUTPUT_BYTES);
        let error = capture_output(&b"y"[..], memory.clone(), total)
            .await
            .unwrap_err();
        assert!(is_resource_limit(&error));
        drop(memory);
        assert_eq!(budget.used(), CAPTURE_RESERVATION_BYTES);
        drop(output);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn oversized_pipe_output_fails_without_materializing_more_than_cap() {
        let budget = MemoryBudget::new(MAX_OUTPUT_BYTES + 128);
        let memory = Arc::new(budget.reserve(MAX_OUTPUT_BYTES + 128).unwrap());
        let total = Arc::new(AtomicUsize::new(MAX_OUTPUT_BYTES - 1));
        let error = capture_output(&b"too large"[..], memory, total)
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<InventoryError>().is_some());
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn output_clone_keeps_reservation_without_cloning_payload() {
        let budget = MemoryBudget::new(1024);
        let output = capture_output(
            &b"hello"[..],
            Arc::new(budget.reserve(1024).unwrap()),
            Arc::new(AtomicUsize::new(0)),
        )
        .await
        .unwrap();
        let cloned = output.clone();
        assert_eq!(output.as_ptr(), cloned.as_ptr());
        drop(output);
        assert_eq!(budget.used(), 1024);
        drop(cloned);
        assert_eq!(budget.used(), 0);
    }
}
