//! Command-line surface (spec §5). The default (no subcommand) launches the TUI;
//! subcommands drive the same engine headlessly.

use clap::{Parser, Subcommand};

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
    /// Show or edit configuration.
    #[command(subcommand)]
    Config(ConfigCmd),
}

#[derive(clap::Args, Debug)]
pub struct ScanArgs {
    /// Restrict to sections, comma-separated (e.g. `apps,disk,brew`). Default: all.
    #[arg(long, value_delimiter = ',')]
    pub section: Vec<String>,

    /// Emit `Vec<Finding>` as JSON.
    #[arg(long)]
    pub json: bool,
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

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Print the config file path.
    Path,
    /// Open the config file in `$EDITOR`.
    Edit,
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
}
