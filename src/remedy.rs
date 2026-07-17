//! Remedy planning and execution.
//!
//! `plan` turns findings' remedies into `PlannedAction`s carrying the exact
//! command string the user will see — the tool never runs anything unseen
//! (spec §4). `execute` runs one action. Dry-run (planning without executing) is
//! the test seam: assert the rendered strings, never touch the machine.
//!
//! Deletions default to Trash; `delete_mode = "rm"` rewrites them to `rm -rf`.

use std::path::Path;

use tokio_util::sync::CancellationToken;

use crate::config::DeleteMode;
use crate::model::{FindingId, Remedy, RemedyCommand};
use crate::runner::CommandRunner;

/// A single, fully-resolved action ready to show and (optionally) run.
#[derive(Clone, Debug, PartialEq)]
pub struct PlannedAction {
    pub finding_id: FindingId,
    pub label: String,
    /// The effective command (Trash may have been rewritten to `rm -rf`).
    pub command: RemedyCommand,
    /// The literal string shown to the user.
    pub rendered: String,
    pub destructive: bool,
    pub reclaims_bytes: Option<u64>,
}

/// Abstraction over the `trash` crate so tests don't move real files.
pub trait TrashOps: Send + Sync {
    fn trash(&self, path: &Path) -> anyhow::Result<()>;
}

/// Production trashing via the `trash` crate.
pub struct RealTrash;

impl TrashOps for RealTrash {
    fn trash(&self, path: &Path) -> anyhow::Result<()> {
        trash::delete(path).map_err(|e| anyhow::anyhow!("trash failed: {e}"))
    }
}

/// Abstraction over the system clipboard so tests don't touch it.
pub trait ClipboardOps: Send + Sync {
    fn copy(&self, text: &str) -> anyhow::Result<()>;
}

/// Production clipboard via `pbcopy` (macOS). Spawns the process directly with
/// piped stdin — `CommandRunner` deliberately has no stdin support and doesn't
/// need it for anything else.
pub struct RealClipboard;

impl ClipboardOps for RealClipboard {
    fn copy(&self, text: &str) -> anyhow::Result<()> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new("pbcopy")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn pbcopy: {e}"))?;
        child
            .stdin
            .as_mut()
            .expect("stdin was piped")
            .write_all(text.as_bytes())?;
        let status = child.wait()?;
        if !status.success() {
            anyhow::bail!("pbcopy exited with {status}");
        }
        Ok(())
    }
}

pub struct RemedyEngine {
    pub delete_mode: DeleteMode,
}

impl RemedyEngine {
    pub fn new(delete_mode: DeleteMode) -> Self {
        RemedyEngine { delete_mode }
    }

    /// Resolve one remedy into a `PlannedAction`, applying the delete mode.
    pub fn plan_one(&self, finding_id: FindingId, remedy: &Remedy) -> PlannedAction {
        let command = match (&remedy.command, self.delete_mode) {
            // In rm mode a Trash becomes a literal `rm -rf`.
            (RemedyCommand::Trash { path }, DeleteMode::Rm) => RemedyCommand::Shell {
                program: "rm".into(),
                args: vec!["-rf".into(), path.display().to_string()],
            },
            (cmd, _) => cmd.clone(),
        };
        PlannedAction {
            finding_id,
            label: remedy.label.clone(),
            rendered: command.rendered(),
            destructive: remedy.destructive,
            reclaims_bytes: remedy.reclaims_bytes,
            command,
        }
    }

    /// Plan a batch of (finding, remedy) pairs.
    pub fn plan(&self, items: &[(FindingId, Remedy)]) -> Vec<PlannedAction> {
        items.iter().map(|(id, r)| self.plan_one(*id, r)).collect()
    }

    /// Execute one planned action, returning a human-readable activity-log line.
    pub async fn execute(
        &self,
        action: &PlannedAction,
        runner: &dyn CommandRunner,
        trash: &dyn TrashOps,
        clipboard: &dyn ClipboardOps,
        token: &CancellationToken,
    ) -> anyhow::Result<String> {
        match &action.command {
            RemedyCommand::Trash { path } => {
                trash.trash(path)?;
                Ok(format!("Trashed {}", path.display()))
            }
            RemedyCommand::Shell { program, args } => {
                let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
                let out = runner.run(program, &arg_refs, token).await?;
                if out.success() {
                    Ok(format!("Ran: {}", action.rendered))
                } else {
                    anyhow::bail!(
                        "`{}` exited {}: {}",
                        action.rendered,
                        out.status,
                        out.stderr_str().trim()
                    )
                }
            }
            RemedyCommand::RevealInFinder { path } => {
                let p = path.display().to_string();
                runner.run("open", &["-R", &p], token).await?;
                Ok(format!("Revealed {}", path.display()))
            }
            RemedyCommand::CopyToClipboard { text } => {
                // This variant is for things we deliberately won't run (e.g.
                // `kill <pid>`): put the text on the clipboard so the user can
                // paste and run it themselves.
                clipboard.copy(text)?;
                Ok(format!("Copied to clipboard: {text}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FindingKind;
    use std::sync::Mutex;

    fn fid() -> FindingId {
        FindingId::new(FindingKind::BuildArtifact, "/p/target")
    }

    #[test]
    fn trash_mode_renders_trash() {
        let eng = RemedyEngine::new(DeleteMode::Trash);
        let r = Remedy {
            label: "Delete".into(),
            command: RemedyCommand::Trash {
                path: "/p/target".into(),
            },
            reclaims_bytes: Some(10),
            destructive: true,
        };
        let a = eng.plan_one(fid(), &r);
        assert_eq!(a.rendered, "trash /p/target");
        assert!(a.destructive);
    }

    #[test]
    fn rm_mode_rewrites_trash_to_rm() {
        let eng = RemedyEngine::new(DeleteMode::Rm);
        let r = Remedy {
            label: "Delete".into(),
            command: RemedyCommand::Trash {
                path: "/p/My Target".into(),
            },
            reclaims_bytes: None,
            destructive: true,
        };
        let a = eng.plan_one(fid(), &r);
        assert_eq!(a.rendered, "rm -rf '/p/My Target'");
        assert!(matches!(a.command, RemedyCommand::Shell { .. }));
    }

    struct FakeTrash(Mutex<Vec<String>>);
    impl TrashOps for FakeTrash {
        fn trash(&self, path: &Path) -> anyhow::Result<()> {
            self.0.lock().unwrap().push(path.display().to_string());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeClipboard(Mutex<Vec<String>>);
    impl ClipboardOps for FakeClipboard {
        fn copy(&self, text: &str) -> anyhow::Result<()> {
            self.0.lock().unwrap().push(text.to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn execute_trash_uses_trashops_not_fs() {
        let eng = RemedyEngine::new(DeleteMode::Trash);
        let r = Remedy {
            label: "Delete".into(),
            command: RemedyCommand::Trash {
                path: "/p/target".into(),
            },
            reclaims_bytes: None,
            destructive: true,
        };
        let a = eng.plan_one(fid(), &r);
        let trash = FakeTrash(Mutex::new(vec![]));
        let runner = crate::runner::MockCommandRunner::new();
        let line = eng
            .execute(
                &a,
                &runner,
                &trash,
                &FakeClipboard::default(),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(line.contains("Trashed"));
        assert_eq!(
            trash.0.lock().unwrap().as_slice(),
            &["/p/target".to_string()]
        );
    }

    #[tokio::test]
    async fn execute_shell_runs_via_runner() {
        let eng = RemedyEngine::new(DeleteMode::Trash);
        let r = Remedy {
            label: "Upgrade".into(),
            command: RemedyCommand::Shell {
                program: "brew".into(),
                args: vec!["upgrade".into(), "ripgrep".into()],
            },
            reclaims_bytes: None,
            destructive: false,
        };
        let a = eng.plan_one(fid(), &r);
        let runner =
            crate::runner::MockCommandRunner::new().on("brew", &["upgrade", "ripgrep"], "");
        let trash = FakeTrash(Mutex::new(vec![]));
        let line = eng
            .execute(
                &a,
                &runner,
                &trash,
                &FakeClipboard::default(),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(line.contains("Ran: brew upgrade ripgrep"));
    }

    #[tokio::test]
    async fn execute_copy_uses_clipboard_ops() {
        let eng = RemedyEngine::new(DeleteMode::Trash);
        let r = Remedy {
            label: "Copy kill".into(),
            command: RemedyCommand::CopyToClipboard {
                text: "kill 1234".into(),
            },
            reclaims_bytes: None,
            destructive: false,
        };
        let a = eng.plan_one(fid(), &r);
        let clip = FakeClipboard::default();
        let line = eng
            .execute(
                &a,
                &crate::runner::MockCommandRunner::new(),
                &FakeTrash(Mutex::new(vec![])),
                &clip,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(line.contains("Copied to clipboard"));
        assert_eq!(
            clip.0.lock().unwrap().as_slice(),
            &["kill 1234".to_string()]
        );
    }
}
