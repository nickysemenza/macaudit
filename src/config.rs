//! Configuration and path resolution.
//!
//! `Paths` is the **single** place that reads the environment for HOME. Every
//! scanner resolves user paths through it, so tests can redirect the whole tool
//! at a fixture HOME by setting `$MACAUDIT_HOME` (spec §10). No scanner should
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

    /// Path to the snapshot history database.
    pub fn history_db(&self) -> PathBuf {
        self.state_dir.join("history.db")
    }
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
        assert_eq!(
            p.history_db(),
            PathBuf::from("/tmp/fixture/.local/state/macaudit/history.db")
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
}
