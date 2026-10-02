//! Inherited process PATH and filesystem-only executable resolution.
//! Automatic scans never launch a shell or execute user startup files.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::Paths;
use crate::scan::ScanCtx;

pub const DISCLOSURE: &str =
    "Automatic scans use inherited process PATH and filesystem metadata; user shell startup configuration is not executed.";

#[derive(Serialize, Clone, Debug, Default)]
pub struct ShellPath {
    pub login_shell: Option<PathBuf>,
    /// Optional explicitly supplied shell PATH; automatic detection leaves it unset.
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

pub fn split_path(line: &str) -> Vec<PathBuf> {
    line.split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

pub fn path_probe_args(_shell_name: &str) -> Option<Vec<&'static str>> {
    None
}

/// Read inherited environment metadata without starting any subprocess.
pub async fn detect(_ctx: &ScanCtx) -> ShellPath {
    ShellPath {
        login_shell: Paths::env_shell(),
        shell_path: None,
        process_path: Paths::process_path(),
        source: "process PATH".into(),
        notes: Vec::new(),
    }
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
    fn automatic_shell_startup_probes_are_disabled() {
        for shell in ["fish", "zsh", "bash", "sh"] {
            assert!(path_probe_args(shell).is_none());
        }
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
