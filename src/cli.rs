//! Command-line surface (spec §5). The default (no subcommand) launches the TUI;
//! subcommands drive the same engine headlessly.

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

use crate::model::ScannerId;

#[derive(Parser, Debug)]
#[command(
    name = "macaudit",
    version = env!("MACAUDIT_VERSION"),
    about = "A 'why is my Mac like this' audit TUI"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// One readable disk root; defaults to HOME. Supports ~ and cwd-relative paths.
    #[arg(long, global = true)]
    pub root: Option<PathBuf>,

    /// Read settings from this explicit input file. Never creates or edits it.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Use synthetic findings instead of real scanners (architecture demo/testing).
    #[arg(long, global = true)]
    pub fake: bool,

    /// Delete for real (`rm -rf`) instead of moving to Trash. Off by default.
    #[arg(long, global = true)]
    pub rm: bool,

    /// Disable all network access (cask-catalog matching + release checks).
    #[arg(long, global = true)]
    pub offline: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run a scan and print findings (machine-readable with `--json`).
    Scan(ScanArgs),
    /// Print the destructive remedy commands a clean would run.
    Clean(CleanArgs),
    /// Global developer tools: list installations across managers, or verify them.
    Tools(ToolsArgs),
    /// Homebrew dependency questions: why is X installed / what does X need.
    #[command(subcommand)]
    Brew(BrewCmd),
    /// Attribution axes: per-project or per-app disk footprints.
    Footprints(FootprintsArgs),
}

#[derive(clap::Args, Debug)]
pub struct ScanArgs {
    /// Filter displayed sections (e.g. `apps,disk,brew`); every audit still runs.
    #[arg(long, value_delimiter = ',')]
    pub section: Vec<String>,

    /// Emit run metadata and separate disk / audit-host findings as JSON.
    #[arg(long)]
    pub json: bool,
}

impl Cli {
    pub fn run_request(
        &self,
        home: &Path,
        cwd: &Path,
    ) -> anyhow::Result<crate::engine::RunRequest> {
        let selected_root = crate::engine::RunRequest::resolve_root(
            self.root.as_deref().unwrap_or(home),
            home,
            cwd,
        )?;
        Ok(crate::engine::RunRequest {
            selected_root,
            options: crate::engine::RunOptions {
                offline: self.offline,
            },
        })
    }
}

#[derive(clap::Args, Debug)]
pub struct CleanArgs {
    /// Only print commands; never execute (currently the only supported mode).
    #[arg(long)]
    pub dry_run: bool,

    /// Restrict to sections, comma-separated. Default: all.
    #[arg(long, value_delimiter = ',')]
    pub section: Vec<String>,

    /// Only these findings (identity keys or titles, comma-separated), e.g.
    /// `npm:/opt/homebrew/lib/node_modules:eslint` or `wget`. Without it,
    /// Brew/Tools rows are listed only when evidence suggests removal.
    #[arg(long, value_delimiter = ',')]
    pub select: Vec<String>,

    /// Emit `{actions, refused, impact, reclaimable_bytes}` as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args, Debug)]
pub struct ToolsArgs {
    #[command(subcommand)]
    pub cmd: Option<ToolsCmd>,

    /// Emit the `global_tool` findings as JSON.
    #[arg(long)]
    pub json: bool,

    /// Only these managers (npm, pnpm, cargo, pipx, uv, pip, bun).
    #[arg(long, value_delimiter = ',')]
    pub manager: Vec<String>,

    /// Only these classifications (broken, duplicate, shadowed,
    /// project_alternative, required, orphan, review).
    #[arg(long, value_delimiter = ',')]
    pub class: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum ToolsCmd {
    /// Run bounded `--version` probes on every tool launcher (explicit,
    /// never part of a scan).
    Verify {
        #[arg(long)]
        json: bool,
        /// Maximum number of probes.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand, Debug)]
pub enum BrewCmd {
    /// Why is this formula/cask installed — what needs it, up to the
    /// explicitly installed roots.
    Why {
        name: String,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 8)]
        max_depth: u16,
    },
    /// What does this formula/cask need (direct, then transitive).
    Deps {
        name: String,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 8)]
        max_depth: u16,
    },
}

#[derive(clap::Args, Debug)]
pub struct FootprintsArgs {
    /// Restrict to one axis (`projects` or `apps`). Default: both.
    #[arg(long)]
    pub axis: Option<String>,

    /// Emit the `FootprintSet`(s) as JSON.
    #[arg(long)]
    pub json: bool,
}

impl ScanArgs {
    /// Resolve the requested sections, or all of them when none specified.
    /// Errors on an unknown slug.
    pub fn sections(&self) -> anyhow::Result<Vec<ScannerId>> {
        resolve_sections(&self.section)
    }
}

impl CleanArgs {
    pub fn sections(&self) -> anyhow::Result<Vec<ScannerId>> {
        resolve_sections(&self.section)
    }
}

impl FootprintsArgs {
    /// The requested axes, or both when `--axis` is absent. Errors on an
    /// unknown value.
    pub fn axes(&self) -> anyhow::Result<Vec<crate::attribution::model::Axis>> {
        use crate::attribution::model::Axis;
        match &self.axis {
            None => Ok(Axis::ALL.to_vec()),
            Some(s) => Axis::parse(s)
                .map(|a| vec![a])
                .ok_or_else(|| anyhow::anyhow!("unknown axis: {s}")),
        }
    }
}

fn resolve_sections(slugs: &[String]) -> anyhow::Result<Vec<ScannerId>> {
    if slugs.is_empty() {
        return Ok(ScannerId::ALL.to_vec());
    }
    let mut out = Vec::new();
    for s in slugs {
        match ScannerId::parse_slug(s) {
            Some(id) => {
                if !out.contains(&id) {
                    out.push(id);
                }
            }
            None => anyhow::bail!("unknown section: {s}"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_defaults_to_home_and_resolves_relative_and_tilde() {
        let home = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        std::fs::create_dir(cwd.path().join("chosen")).unwrap();
        let default = Cli::try_parse_from(["macaudit"]).unwrap();
        assert!(default.config.is_none());
        assert_eq!(
            default
                .run_request(home.path(), cwd.path())
                .unwrap()
                .selected_root,
            home.path().canonicalize().unwrap()
        );
        let relative = Cli::try_parse_from(["macaudit", "scan", "--root", "chosen"]).unwrap();
        assert_eq!(
            relative
                .run_request(home.path(), cwd.path())
                .unwrap()
                .selected_root,
            cwd.path().join("chosen").canonicalize().unwrap()
        );
        let tilde =
            Cli::try_parse_from(["macaudit", "--root", "~", "--config", "custom.toml"]).unwrap();
        assert_eq!(
            tilde
                .run_request(home.path(), cwd.path())
                .unwrap()
                .selected_root,
            home.path().canonicalize().unwrap()
        );
        assert_eq!(tilde.config, Some(PathBuf::from("custom.toml")));
    }

    #[test]
    fn root_contract_rejects_multiple_roots_and_persistence_flags() {
        for args in [
            vec!["macaudit", "--root", "/", "--root", "/tmp"],
            vec!["macaudit", "--cache", "cache.db"],
            vec!["macaudit", "--report", "report.json"],
            vec!["macaudit", "config", "edit"],
            vec!["macaudit", "config", "path"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        let home = tempfile::tempdir().unwrap();
        let invalid = Cli::try_parse_from(["macaudit", "--root", "does-not-exist"]).unwrap();
        assert!(invalid.run_request(home.path(), home.path()).is_err());
    }

    #[test]
    fn empty_sections_means_all() {
        let a = ScanArgs {
            section: vec![],
            json: false,
        };
        assert_eq!(a.sections().unwrap(), ScannerId::ALL.to_vec());
    }

    #[test]
    fn slugs_resolve_with_aliases() {
        let a = ScanArgs {
            section: vec!["disk".into(), "apps".into()],
            json: false,
        };
        assert_eq!(a.sections().unwrap(), vec![ScannerId::Fs, ScannerId::Apps]);
    }

    #[test]
    fn unknown_slug_errors() {
        let a = ScanArgs {
            section: vec!["nope".into()],
            json: false,
        };
        assert!(a.sections().is_err());
    }

    #[test]
    fn footprints_axis_defaults_to_both() {
        let a = FootprintsArgs {
            axis: None,
            json: false,
        };
        assert_eq!(
            a.axes().unwrap(),
            crate::attribution::model::Axis::ALL.to_vec()
        );
    }

    #[test]
    fn footprints_axis_parses_apps() {
        let a = FootprintsArgs {
            axis: Some("apps".into()),
            json: false,
        };
        assert_eq!(
            a.axes().unwrap(),
            vec![crate::attribution::model::Axis::AppStorage]
        );
    }

    #[test]
    fn footprints_unknown_axis_errors() {
        let a = FootprintsArgs {
            axis: Some("nope".into()),
            json: false,
        };
        assert!(a.axes().is_err());
    }
}
