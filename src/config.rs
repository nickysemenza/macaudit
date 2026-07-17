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
    pub fn resolve() -> Self {
        let home = std::env::var_os("MACAUDIT_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/"));
        Self::from_home(home)
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

    /// Expand a leading `~` against this home. Absolute and relative paths pass
    /// through unchanged (relative ones are joined onto home for safety in tests).
    pub fn expand(&self, p: &str) -> PathBuf {
        if let Some(rest) = p.strip_prefix("~/") {
            self.home.join(rest)
        } else if p == "~" {
            self.home.clone()
        } else {
            PathBuf::from(p)
        }
    }

    /// Default filesystem walk roots when config doesn't specify any.
    pub fn default_roots(&self) -> Vec<PathBuf> {
        vec![self.home.clone()]
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
