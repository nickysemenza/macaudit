//! The universal subprocess seam.
//!
//! Every scanner that shells out does so through `CommandRunner`, so unit tests
//! inject `MockCommandRunner` with checked-in fixture output and never touch the
//! real machine. `RealCommandRunner` runs `tokio::process` and is cancellable.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

/// Captured output of a finished subprocess.
#[derive(Clone, Debug)]
pub struct CmdOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl CmdOutput {
    pub fn stdout_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.stdout)
    }
    pub fn stderr_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.stderr)
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
        use tokio::process::Command;

        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.kill_on_drop(true);
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn `{program}`: {e}"))?;

        // `wait_with_output` consumes the child; pin it so the cancel arm can
        // return without also borrowing `child`. `kill_on_drop(true)` means the
        // dropped future reaps the process on cancellation.
        let wait = child.wait_with_output();
        tokio::pin!(wait);

        tokio::select! {
            _ = token.cancelled() => {
                anyhow::bail!("`{program}` cancelled");
            }
            out = &mut wait => {
                let out = out.map_err(|e| anyhow::anyhow!("`{program}` failed: {e}"))?;
                Ok(CmdOutput {
                    status: out.status.code().unwrap_or(-1),
                    stdout: out.stdout,
                    stderr: out.stderr,
                })
            }
        }
    }
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
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
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
                stdout: Vec::new(),
                stderr: stderr.as_bytes().to_vec(),
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
}
