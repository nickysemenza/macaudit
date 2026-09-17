//! Configuration and path resolution.
//!
//! `Paths` is the **single** place that reads the environment for HOME. Every
//! scanner resolves user paths through it, so tests can redirect the whole tool
//! at a fixture HOME by setting `$MACAUDIT_HOME` (spec §9). No scanner should
//! read `$HOME` or use `directories` directly.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Resolved filesystem locations. Constructed once and shared via `Arc`.
#[derive(Clone, Debug)]
pub struct Paths {
    /// The user's home directory (or the `$MACAUDIT_HOME` override in tests).
    pub home: PathBuf,
    /// `~/.config/macaudit`
    pub config_dir: PathBuf,
    /// `~/.local/state/macaudit`
    pub state_dir: PathBuf,
    /// `~/Library/Caches/macaudit` (etag caches etc., v1.1)
    pub cache_dir: PathBuf,
}

impl Paths {
    /// Resolve paths, honoring `$MACAUDIT_HOME` (test seam) then `$HOME`.
    /// Errors when neither is set — falling back to `/` would make the default
    /// scan walk the entire filesystem.
    pub fn resolve() -> anyhow::Result<Self> {
        let home = std::env::var_os("MACAUDIT_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .ok_or_else(|| anyhow::anyhow!("neither $MACAUDIT_HOME nor $HOME is set"))?;
        Ok(Self::from_home(home))
    }

    /// Build all derived paths from a home directory. Used by `resolve()` and
    /// directly by tests with a tempdir.
    pub fn from_home(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        Paths {
            config_dir: home.join(".config/macaudit"),
            state_dir: home.join(".local/state/macaudit"),
            cache_dir: home.join("Library/Caches/macaudit"),
            home,
        }
    }

    /// Expand a leading `~` against this home; absolute paths pass through;
    /// relative paths are joined onto home (never the process cwd — config
    /// values must not change meaning based on where macaudit was launched).
    pub fn expand(&self, p: &str) -> PathBuf {
        if let Some(rest) = p.strip_prefix("~/") {
            self.home.join(rest)
        } else if p == "~" {
            self.home.clone()
        } else {
            let pb = PathBuf::from(p);
            if pb.is_absolute() {
                pb
            } else {
                self.home.join(pb)
            }
        }
    }

    /// Default filesystem walk roots when config doesn't specify any.
    pub fn default_roots(&self) -> Vec<PathBuf> {
        vec![self.home.clone()]
    }

    /// The `$PATH` of *this* process, split into entries. Kept here so the
    /// environment is read in exactly one module; scanners compare it against
    /// the user's login-shell PATH rather than assuming they match.
    pub fn process_path() -> Vec<PathBuf> {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default()
    }

    /// The login shell advertised to this process (`$SHELL`), if any. Only a
    /// fallback — the directory-services record is authoritative.
    pub fn env_shell() -> Option<PathBuf> {
        std::env::var_os("SHELL").map(PathBuf::from)
    }

    /// The account name derived from the home directory (`/Users/<name>`).
    pub fn user_name(&self) -> Option<String> {
        self.home
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
    }

    /// Path to the config file.
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// Adopt the login shell's PATH into this process, returning the entries
    /// that were added. A GUI app launched from Finder inherits launchd's
    /// minimal PATH (`/usr/bin:/bin:/usr/sbin:/sbin`), so `brew`, `docker`,
    /// `rustup`… would silently resolve to nothing and whole sections would
    /// come back empty. Runs `$SHELL -lc 'echo $PATH'` under a bound (the same
    /// disclosure the Shell scanner makes: this executes the shell's startup
    /// files); when that fails, falls back to the well-known tool prefixes.
    /// Entries are appended, never prepended — the process's own PATH keeps
    /// precedence.
    pub fn adopt_login_shell_path(&self) -> Vec<PathBuf> {
        let probed = Self::env_shell().and_then(|sh| login_shell_path(&sh, LOGIN_SHELL_TIMEOUT));
        let extra = probed.unwrap_or_else(|| {
            vec![
                PathBuf::from("/opt/homebrew/bin"),
                PathBuf::from("/usr/local/bin"),
                self.home.join(".cargo/bin"),
            ]
        });
        let current = Self::process_path();
        let added: Vec<PathBuf> = merge_path(&current, &extra);
        if !added.is_empty() {
            let mut all = current;
            all.extend(added.iter().cloned());
            if let Ok(joined) = std::env::join_paths(&all) {
                std::env::set_var("PATH", joined);
            }
        }
        added
    }
}

const LOGIN_SHELL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The entries of `extra` that `current` lacks, in order, without duplicates.
fn merge_path(current: &[PathBuf], extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut added: Vec<PathBuf> = Vec::new();
    for p in extra {
        if !current.contains(p) && !added.contains(p) {
            added.push(p.clone());
        }
    }
    added
}

/// Ask a login shell for its PATH, bounded by `timeout`. `None` when the
/// shell is unknown to `path_probe_args`, fails to spawn, exits non-zero,
/// prints nothing, or overruns the deadline (it is killed).
fn login_shell_path(shell: &Path, timeout: std::time::Duration) -> Option<Vec<PathBuf>> {
    use crate::scan::global_tools::shellpath::{path_probe_args, split_path};
    use std::process::{Command, Stdio};

    let name = shell.file_name()?.to_str()?;
    let args = path_probe_args(name)?;
    let mut child = Command::new(shell)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                break;
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = String::new();
    use std::io::Read;
    child.stdout.take()?.read_to_string(&mut out).ok()?;
    let line = out.lines().last()?.trim();
    let entries = split_path(line);
    (!entries.is_empty()).then_some(entries)
}

/// User configuration, loaded from `config.toml`. All fields optional with
/// sensible defaults so a missing/partial file still works.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    pub scan: ScanConfig,
    pub artifacts: ArtifactsConfig,
    pub behavior: BehaviorConfig,
    pub network: NetworkConfig,
    pub tools: ToolsConfig,
    pub time_machine: TimeMachineConfig,
}

/// Global developer-tool audit (`[tools]`). Every path is tilde-expanded at
/// use; every knob defaults to the layout the managers use on macOS.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolsConfig {
    /// Opt in to aggregated shell-history evidence (counts and last-used
    /// dates per command only — raw history lines are never stored or shown).
    pub shell_history_evidence: bool,
    /// Repository roots to correlate against. Empty ⇒ `scan.roots` ⇒ `[home]`.
    pub project_roots: Vec<String>,
    /// How deep below a root to look for project manifests.
    pub project_max_depth: usize,
    /// Time budget for project correlation; exceeding it marks coverage truncated.
    pub project_time_budget_secs: u64,
    /// After a cleanup, run bounded `--version` probes on retained tools related
    /// to the batch (duplicates, shadow peers, dependents).
    pub verify_after_cleanup: bool,
    /// Maximum number of probes per cleanup.
    pub verify_limit: usize,
    /// Per-probe timeout.
    pub verify_timeout_secs: u64,
    /// Persist a JSON audit report of every cleanup under
    /// `<state_dir>/cleanup-reports/`.
    pub write_cleanup_reports: bool,
    /// Additional npm global prefixes to inspect (besides the well-known ones).
    pub extra_npm_prefixes: Vec<String>,
    pub pnpm_home: String,
    pub cargo_home: String,
    pub pipx_home: String,
    pub uv_tool_dir: String,
    pub bun_home: String,
    /// Additional Python site-packages directories to inventory.
    pub python_sites: Vec<String>,
    /// Inventory Apple's `/Library/Python` sites (never offers remedies there).
    pub include_apple_python: bool,
    /// Override the Homebrew prefix (default: `$HOMEBREW_PREFIX`, then
    /// `/opt/homebrew`, then `/usr/local`, whichever has a `Cellar/`).
    pub homebrew_prefix: Option<String>,
}

impl Default for ToolsConfig {
    fn default() -> Self {
        ToolsConfig {
            shell_history_evidence: false,
            project_roots: Vec::new(),
            project_max_depth: 6,
            project_time_budget_secs: 10,
            verify_after_cleanup: true,
            verify_limit: 25,
            verify_timeout_secs: 5,
            write_cleanup_reports: true,
            extra_npm_prefixes: Vec::new(),
            pnpm_home: "~/Library/pnpm".to_string(),
            cargo_home: "~/.cargo".to_string(),
            pipx_home: "~/.local/pipx".to_string(),
            uv_tool_dir: "~/.local/share/uv/tools".to_string(),
            bun_home: "~/.bun".to_string(),
            python_sites: Vec::new(),
            include_apple_python: true,
            homebrew_prefix: None,
        }
    }
}

/// Time Machine backup audit (`[time_machine]`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct TimeMachineConfig {
    /// Days since the last successful backup before a destination is flagged.
    pub stale_backup_days: u64,
    /// Wall-clock budget, in seconds, for each of the two sizing phases
    /// (exclusions/candidates first, then the backup-set hubs).
    pub estimate_budget_secs: u64,
    /// Per-root entry cap for the bounded directory walk.
    pub estimate_max_entries_per_root: u64,
    /// Suggested exclusions smaller than this are not shown (MiB).
    pub candidate_min_mb: u64,
    /// Extra "~/…" or absolute roots to consider as exclusion candidates.
    pub extra_candidates: Vec<String>,
}

impl Default for TimeMachineConfig {
    fn default() -> Self {
        TimeMachineConfig {
            stale_backup_days: 7,
            estimate_budget_secs: 60,
            estimate_max_entries_per_root: 5_000_000,
            candidate_min_mb: 100,
            extra_candidates: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Filesystem walk roots (tilde-expanded at use). Empty ⇒ `[home]`.
    pub roots: Vec<String>,
    /// Never descend into these (tilde-expanded).
    pub ignore: Vec<String>,
    /// Loose files larger than this are flagged.
    pub large_file_threshold_gb: f64,
    /// How long a cached artifact size stays fresh before it's re-measured.
    pub size_cache_ttl_hours: u64,
}

/// Network policy (spec M7). All network access is optional and degrades
/// silently: `--offline`/`offline = true` disables everything.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Disable all network access.
    pub offline: bool,
    /// Refresh the cask catalog at most this often (ETag-revalidated).
    pub catalog_max_age_days: u64,
    /// Max GitHub release lookups that may hit the network per scan.
    pub github_max_checks_per_scan: usize,
    /// How long a cached GitHub release result stays fresh.
    pub github_cache_ttl_hours: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            offline: false,
            catalog_max_age_days: 7,
            github_max_checks_per_scan: 10,
            github_cache_ttl_hours: 72,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct ArtifactsConfig {
    /// User-extensible artifact rules: a directory name plus a required sibling marker.
    pub extra: Vec<ArtifactRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactRule {
    pub dir: String,
    pub marker: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct BehaviorConfig {
    /// "trash" | "rm"
    pub delete_mode: DeleteMode,
    /// Staleness badge threshold in days.
    pub stale_after_days: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeleteMode {
    Trash,
    Rm,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            roots: Vec::new(),
            ignore: Vec::new(),
            large_file_threshold_gb: 1.0,
            size_cache_ttl_hours: 24,
        }
    }
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        BehaviorConfig {
            delete_mode: DeleteMode::Trash,
            stale_after_days: 90,
        }
    }
}

impl Config {
    /// Load config from the given file, returning defaults if it doesn't exist.
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(toml::from_str(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Large-file threshold in bytes.
    pub fn large_file_threshold_bytes(&self) -> u64 {
        (self.scan.large_file_threshold_gb * 1024.0 * 1024.0 * 1024.0) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_honor_override() {
        let p = Paths::from_home("/tmp/fixture");
        assert_eq!(p.home, PathBuf::from("/tmp/fixture"));
        assert_eq!(
            p.config_file(),
            PathBuf::from("/tmp/fixture/.config/macaudit/config.toml")
        );
    }

    #[test]
    fn expand_tilde() {
        let p = Paths::from_home("/home/u");
        assert_eq!(p.expand("~/code"), PathBuf::from("/home/u/code"));
        assert_eq!(p.expand("~"), PathBuf::from("/home/u"));
        assert_eq!(p.expand("/abs"), PathBuf::from("/abs"));
    }

    #[test]
    fn default_config_parses_and_missing_file_is_default() {
        let c = Config::load(Path::new("/nonexistent/xyz/config.toml")).unwrap();
        assert_eq!(c.behavior.delete_mode, DeleteMode::Trash);
        assert_eq!(c.behavior.stale_after_days, 90);
    }

    #[test]
    fn partial_config_merges_defaults() {
        let text = r#"
            [behavior]
            delete_mode = "rm"
        "#;
        let c: Config = toml::from_str(text).unwrap();
        assert_eq!(c.behavior.delete_mode, DeleteMode::Rm);
        assert_eq!(c.behavior.stale_after_days, 90); // default preserved
    }

    #[test]
    fn partial_time_machine_config_merges_defaults() {
        let text = r#"
            [time_machine]
            stale_backup_days = 3
        "#;
        let c: Config = toml::from_str(text).unwrap();
        assert_eq!(c.time_machine.stale_backup_days, 3);
        assert_eq!(c.time_machine.estimate_budget_secs, 60);
        assert_eq!(c.time_machine.estimate_max_entries_per_root, 5_000_000);
        assert_eq!(c.time_machine.candidate_min_mb, 100);
        assert!(c.time_machine.extra_candidates.is_empty());

        assert_eq!(Config::default().time_machine.candidate_min_mb, 100);
    }

    /// A stub "zsh" that prints a fixed PATH regardless of its arguments.
    fn stub_shell(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let sh = dir.join("zsh");
        std::fs::write(&sh, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&sh, std::fs::Permissions::from_mode(0o755)).unwrap();
        sh
    }

    #[test]
    fn login_shell_path_reads_last_line_of_probe_output() {
        let dir = tempfile::tempdir().unwrap();
        let sh = stub_shell(dir.path(), "echo noise\necho /opt/homebrew/bin:/usr/bin:");
        let got = login_shell_path(&sh, std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(
            got,
            vec![
                PathBuf::from("/opt/homebrew/bin"),
                PathBuf::from("/usr/bin")
            ]
        );
    }

    #[test]
    fn login_shell_path_none_on_failure_unknown_shell_or_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let failing = stub_shell(dir.path(), "exit 3");
        assert!(login_shell_path(&failing, std::time::Duration::from_secs(5)).is_none());

        let unknown = dir.path().join("nushell");
        std::fs::copy(&failing, &unknown).unwrap();
        assert!(login_shell_path(&unknown, std::time::Duration::from_secs(5)).is_none());

        let slow = stub_shell(dir.path(), "sleep 5; echo /late");
        let t = std::time::Instant::now();
        assert!(login_shell_path(&slow, std::time::Duration::from_millis(100)).is_none());
        assert!(
            t.elapsed() < std::time::Duration::from_secs(3),
            "must kill the probe"
        );
    }

    #[test]
    fn merge_path_appends_only_missing_entries() {
        let cur = vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")];
        let extra = vec![
            PathBuf::from("/bin"),
            PathBuf::from("/opt/homebrew/bin"),
            PathBuf::from("/opt/homebrew/bin"),
        ];
        assert_eq!(
            merge_path(&cur, &extra),
            vec![PathBuf::from("/opt/homebrew/bin")]
        );
    }
}
