//! The user's *login shell* PATH versus this process's PATH, and command
//! resolution against either. The agent/app that launches MacAudit often has
//! a different PATH than the interactive shell (on the audited Mac, fish
//! resolved `pnpm` and Codex differently than the process did), so nothing
//! here assumes they match.
//!
//! Reading the login shell's PATH starts that shell, which executes its
//! startup files — disclosed on the coverage finding and in the README. No
//! rc file is read or displayed.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use crate::config::Paths;
use crate::scan::{run_with_timeout, ScanCtx};

pub const DISCLOSURE: &str =
    "Reading the login shell's PATH starts that shell (fish/zsh/bash -l), which executes its startup configuration.";

const SHELL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize, Clone, Debug, Default)]
pub struct ShellPath {
    pub login_shell: Option<PathBuf>,
    /// `None` when the login shell could not be probed.
    pub shell_path: Option<Vec<PathBuf>>,
    pub process_path: Vec<PathBuf>,
    pub source: String,
    pub notes: Vec<String>,
}

impl ShellPath {
    pub fn shell_name(&self) -> Option<&str> {
        self.login_shell
            .as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
    }

    /// Entries on the login-shell PATH that this process lacks, and vice versa.
    pub fn diff(&self) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let Some(shell) = &self.shell_path else {
            return (Vec::new(), Vec::new());
        };
        let only_shell = shell
            .iter()
            .filter(|p| !self.process_path.contains(p))
            .cloned()
            .collect();
        let only_process = self
            .process_path
            .iter()
            .filter(|p| !shell.contains(p))
            .cloned()
            .collect();
        (only_shell, only_process)
    }
}

/// Parse `dscl . -read /Users/<user> UserShell` output.
pub fn parse_user_shell(stdout: &str) -> Option<PathBuf> {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("UserShell:"))
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| !p.as_os_str().is_empty())
}

/// The PATH-printing invocation for a shell, by basename.
pub fn path_probe_args(shell_name: &str) -> Option<Vec<&'static str>> {
    match shell_name {
        "fish" => Some(vec!["-lc", "string join : $PATH"]),
        "zsh" => Some(vec!["-ilc", "echo $PATH"]),
        "bash" => Some(vec!["-ilc", "echo $PATH"]),
        _ => None,
    }
}

pub fn split_path(line: &str) -> Vec<PathBuf> {
    line.split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Detect the login shell and read its PATH (bounded). Never fails: every
/// gap becomes a note and `shell_path: None`.
pub async fn detect(ctx: &ScanCtx) -> ShellPath {
    let mut out = ShellPath {
        process_path: Paths::process_path(),
        ..Default::default()
    };
    let user = ctx.paths.user_name();
    let mut shell: Option<PathBuf> = None;
    if let Some(user) = &user {
        let record = format!("/Users/{user}");
        if let Some(o) = run_with_timeout(
            ctx,
            "dscl",
            &[".", "-read", &record, "UserShell"],
            SHELL_TIMEOUT,
        )
        .await
        {
            shell = parse_user_shell(&o.stdout_str());
        }
    }
    if shell.is_none() {
        shell = Paths::env_shell();
        if shell.is_some() {
            out.notes
                .push("login shell taken from $SHELL (directory services unavailable)".into());
        }
    }
    out.login_shell = shell.clone();
    let Some(shell) = shell else {
        out.notes
            .push("login shell unknown; using the process PATH only".into());
        out.source = "process PATH".into();
        return out;
    };
    let name = shell
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    let Some(args) = path_probe_args(&name) else {
        out.notes.push(format!(
            "unsupported login shell {name}; using the process PATH only"
        ));
        out.source = "process PATH".into();
        return out;
    };
    let program = shell.to_string_lossy().to_string();
    out.source = format!("{program} {}", args.join(" "));
    match run_with_timeout(ctx, &program, &args, SHELL_TIMEOUT).await {
        Some(o) => {
            let stdout = o.stdout_str();
            let line = stdout
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("");
            let entries = split_path(line.trim());
            if entries.is_empty() {
                out.notes.push(format!("{name} printed an empty PATH"));
            } else {
                out.shell_path = Some(entries);
            }
        }
        None => out.notes.push(format!(
            "could not start {name} to read its PATH (timeout or failure)"
        )),
    }
    out
}

/// Every executable named `name` on `dirs`, in PATH order. Dangling links
/// are skipped, matching what a shell's lookup would execute.
pub fn resolve_all(name: &str, dirs: &[PathBuf]) -> Vec<PathBuf> {
    let joined: OsString = std::env::join_paths(dirs.iter()).unwrap_or_default();
    match which::which_in_all(name, Some(joined), Path::new("/")) {
        Ok(iter) => iter.collect(),
        Err(_) => Vec::new(),
    }
}

pub fn resolve_first(name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    resolve_all(name, dirs).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn parses_dscl_and_probe_args() {
        assert_eq!(
            parse_user_shell("UserShell: /opt/homebrew/bin/fish\n"),
            Some(PathBuf::from("/opt/homebrew/bin/fish"))
        );
        assert_eq!(parse_user_shell("garbage"), None);
        assert_eq!(
            path_probe_args("fish").unwrap(),
            ["-lc", "string join : $PATH"]
        );
        assert_eq!(path_probe_args("zsh").unwrap(), ["-ilc", "echo $PATH"]);
        assert!(path_probe_args("nu").is_none());
    }

    #[test]
    fn resolves_in_path_order_and_skips_dangling() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let exe = b.join("tool");
        std::fs::write(&exe, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("/nonexistent/tool", a.join("tool")).unwrap();
        let hits = resolve_all("tool", &[a.clone(), b.clone()]);
        assert_eq!(hits, vec![exe.clone()]);
        assert_eq!(resolve_first("tool", &[b.clone(), a]), Some(exe));
        assert!(resolve_all("missing", &[b]).is_empty());
    }

    #[test]
    fn diff_reports_shell_only_entries() {
        let sp = ShellPath {
            login_shell: Some("/opt/homebrew/bin/fish".into()),
            shell_path: Some(vec![
                "/u/Library/pnpm/bin".into(),
                "/opt/homebrew/bin".into(),
            ]),
            process_path: vec!["/u/Library/pnpm".into(), "/opt/homebrew/bin".into()],
            source: String::new(),
            notes: vec![],
        };
        let (only_shell, only_process) = sp.diff();
        assert_eq!(only_shell, vec![PathBuf::from("/u/Library/pnpm/bin")]);
        assert_eq!(only_process, vec![PathBuf::from("/u/Library/pnpm")]);
        assert_eq!(sp.shell_name(), Some("fish"));
    }
}
