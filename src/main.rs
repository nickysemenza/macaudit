//! Thin binary: parse the CLI and dispatch to the library. All real work lives
//! in `macaudit::*` so it's testable without a terminal.

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;

use macaudit::cli::{
    BrewCmd, CleanArgs, Cli, Command, ConfigCmd, FootprintsArgs, ScanArgs, ToolsArgs, ToolsCmd,
};
use macaudit::config::{Config, DeleteMode, Paths};
use macaudit::engine::{Mode, ScannerManager};
use macaudit::model::ScannerId;
use macaudit::output;
use macaudit::runner::{CommandRunner, RealCommandRunner};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // A scan must never mutate Homebrew state: `brew outdated` triggers brew's
    // auto-update unless this is set. Applies to every child process we spawn.
    std::env::set_var("HOMEBREW_NO_AUTO_UPDATE", "1");

    let paths = Arc::new(Paths::resolve()?);
    let mut config = Config::load(&paths.config_file()).context("loading config")?;
    if cli.rm {
        config.behavior.delete_mode = DeleteMode::Rm;
    }
    if cli.offline {
        config.network.offline = true;
    }
    let config = Arc::new(config);
    let runner: Arc<dyn CommandRunner> = Arc::new(RealCommandRunner);
    let mode = if cli.fake { Mode::Fake } else { Mode::Real };

    let mut manager = ScannerManager::new(config.clone(), paths.clone(), runner, mode);
    // Network enrichment only when online and scanning for real — synthetic
    // findings don't need the cask catalog.
    if !config.network.offline && mode == Mode::Real {
        manager = manager.with_fetcher(Arc::new(macaudit::net::ReqwestFetcher::new()));
    }
    let manager = Arc::new(manager);

    match cli.command {
        None => {
            // Default: launch the TUI.
            macaudit::ui::run(manager).await
        }
        Some(Command::Scan(args)) => run_scan(&manager, &args).await,
        Some(Command::Clean(args)) => run_clean(&manager, &args).await,
        Some(Command::Tools(args)) => run_tools(&manager, &args).await,
        Some(Command::Brew(cmd)) => run_brew(&manager, cmd).await,
        Some(Command::Config(cmd)) => run_config(&paths, cmd),
        Some(Command::Footprints(args)) => run_footprints(&manager, &args).await,
    }
}

/// Keep only findings belonging to a section the user actually asked for.
/// `run_to_completion` silently expands `requested` with attribution
/// dependencies (Fs, Git, ...) so the two axis scanners have something to
/// resolve against; callers that print findings must undo that expansion so
/// `--section projects` prints Projects findings, not also Fs/Git/....
fn filter_to_requested(
    findings: std::collections::BTreeMap<macaudit::model::FindingId, macaudit::model::Finding>,
    requested: &[ScannerId],
) -> std::collections::BTreeMap<macaudit::model::FindingId, macaudit::model::Finding> {
    findings
        .into_iter()
        .filter(|(_, f)| requested.contains(&f.kind.scanner()))
        .collect()
}

async fn run_scan(manager: &ScannerManager, args: &ScanArgs) -> anyhow::Result<()> {
    let sections = args.sections()?;
    let outcome = manager.run_to_completion(&sections).await;
    warn_failures(&outcome.failures);
    let findings = filter_to_requested(outcome.findings, &sections);
    if args.json {
        println!("{}", output::findings_to_json(&findings)?);
    } else {
        for f in findings.values() {
            let size = f
                .size_bytes
                .map(|b| humansize::format_size(b, humansize::BINARY))
                .unwrap_or_else(|| "-".to_string());
            println!("[{}] {:>10}  {}", f.severity_label(), size, f.title);
        }
        println!("\n{} findings", findings.len());
    }
    Ok(())
}

async fn run_footprints(manager: &ScannerManager, args: &FootprintsArgs) -> anyhow::Result<()> {
    let axes = args.axes()?;
    let sections: Vec<ScannerId> = axes.iter().map(|a| a.scanner()).collect();
    let outcome = manager.run_to_completion(&sections).await;
    warn_failures(&outcome.failures);
    let sets: Vec<&macaudit::attribution::model::FootprintSet> = outcome
        .footprints
        .iter()
        .map(|s| s.as_ref())
        .filter(|s| axes.contains(&s.axis))
        .collect();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&sets)?);
    } else {
        for set in &sets {
            println!("== {} ==", set.axis.label());
            for fp in &set.footprints {
                println!(
                    "{:<32} excl {:>10}  shared {:>10}  reach {:>10}",
                    fp.owner.name,
                    humansize::format_size(fp.exclusive, humansize::BINARY),
                    humansize::format_size(fp.shared, humansize::BINARY),
                    humansize::format_size(fp.reach, humansize::BINARY),
                );
            }
            let baseline_bytes: u64 = set.baseline.iter().map(|e| e.bytes).sum();
            println!(
                "baseline {} of {} on disk, {} unattributed, missing deps: {:?}",
                humansize::format_size(baseline_bytes, humansize::BINARY),
                humansize::format_size(set.disk_total, humansize::BINARY),
                set.unattributed.len(),
                set.missing_deps,
            );
        }
    }
    Ok(())
}

/// Surface failed sections on stderr — stdout stays machine-readable.
fn warn_failures(failures: &[(ScannerId, String)]) {
    for (id, err) in failures {
        eprintln!("warning: {} scan failed: {err}", id.slug());
    }
}

async fn run_clean(manager: &ScannerManager, args: &CleanArgs) -> anyhow::Result<()> {
    if !args.dry_run {
        anyhow::bail!("only --dry-run is supported from the CLI; use the TUI to execute remedies");
    }
    let sections = args.sections()?;
    let outcome = manager.run_to_completion(&sections).await;
    warn_failures(&outcome.failures);
    let findings = filter_to_requested(outcome.findings, &sections);
    if args.json {
        println!(
            "{}",
            output::dry_run_json(&findings, manager.delete_mode(), &args.select)?
        );
    } else {
        print!(
            "{}",
            output::dry_run_report_selected(&findings, manager.delete_mode(), &args.select)
        );
    }
    Ok(())
}

async fn run_tools(manager: &ScannerManager, args: &ToolsArgs) -> anyhow::Result<()> {
    let outcome = manager.run_to_completion(&[ScannerId::Tools]).await;
    warn_failures(&outcome.failures);
    match &args.cmd {
        Some(ToolsCmd::Verify { json, limit }) => {
            let results = verify_tools(manager, &outcome.findings, *limit).await;
            if *json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                for r in &results {
                    println!(
                        "{:<10} {:<28} {}  {}",
                        r["status"].as_str().unwrap_or("?"),
                        r["command"].as_str().unwrap_or("?"),
                        r["path"].as_str().unwrap_or("?"),
                        r["output"].as_str().or(r["error"].as_str()).unwrap_or("")
                    );
                }
                println!("\n{} probe(s)", results.len());
            }
            Ok(())
        }
        None => {
            let tools: Vec<&macaudit::model::Finding> = outcome
                .findings
                .values()
                .filter(|f| f.kind == macaudit::model::FindingKind::GlobalTool)
                .filter(|f| {
                    args.manager.is_empty()
                        || args.manager.iter().any(|m| {
                            f.meta.get("manager").and_then(|v| v.as_str()) == Some(m.as_str())
                        })
                })
                .filter(|f| {
                    args.class.is_empty()
                        || args.class.iter().any(|c| {
                            f.meta
                                .get("primary_classification")
                                .and_then(|v| v.as_str())
                                == Some(c.replace('-', "_").as_str())
                        })
                })
                .collect();
            if args.json {
                println!("{}", serde_json::to_string_pretty(&tools)?);
            } else {
                print!("{}", output::tools_table(&tools));
            }
            Ok(())
        }
    }
}

/// Explicit, bounded `--version` probes of every tool launcher whose target
/// exists. Never part of a scan.
async fn verify_tools(
    manager: &ScannerManager,
    findings: &std::collections::BTreeMap<macaudit::model::FindingId, macaudit::model::Finding>,
    limit: usize,
) -> Vec<serde_json::Value> {
    let runner = manager.runner();
    let timeout = std::time::Duration::from_secs(manager.config().tools.verify_timeout_secs);
    let token = tokio_util::sync::CancellationToken::new();
    let mut out = Vec::new();
    for f in findings
        .values()
        .filter(|f| f.kind == macaudit::model::FindingKind::GlobalTool)
    {
        for r in &f.remedies {
            if out.len() >= limit {
                break;
            }
            let macaudit::model::RemedyCommand::Probe { program, args, .. } = &r.command else {
                continue;
            };
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let started = std::time::Instant::now();
            let result =
                tokio::time::timeout(timeout, runner.run(program, &arg_refs, &token)).await;
            let (status, output, error) = match result {
                Err(_) => (
                    "timeout",
                    None,
                    Some(format!("no answer within {}s", timeout.as_secs())),
                ),
                Ok(Err(e)) => ("failed", None, Some(e.to_string())),
                Ok(Ok(o)) if o.success() => (
                    "ok",
                    Some(
                        o.stdout_str()
                            .lines()
                            .find(|l| !l.trim().is_empty())
                            .unwrap_or("")
                            .trim()
                            .to_string(),
                    ),
                    None,
                ),
                Ok(Ok(o)) => (
                    "failed",
                    None,
                    Some(format!("exit {}: {}", o.status, o.stderr_str().trim())),
                ),
            };
            out.push(serde_json::json!({
                "tool": f.meta.get("identity_key").cloned().unwrap_or(serde_json::Value::Null),
                "command": program.rsplit('/').next().unwrap_or(program),
                "path": program,
                "status": status,
                "output": output,
                "error": error,
                "elapsed_ms": started.elapsed().as_millis() as u64,
            }));
        }
    }
    out
}

async fn run_brew(manager: &ScannerManager, cmd: BrewCmd) -> anyhow::Result<()> {
    let outcome = manager.run_to_completion(&[ScannerId::Brew]).await;
    warn_failures(&outcome.failures);
    let graph = macaudit::brewgraph::BrewGraph::from_findings(outcome.findings.values());
    let (name, dir, json, max_depth) = match cmd {
        BrewCmd::Why {
            name,
            json,
            max_depth,
        } => (
            name,
            macaudit::brewgraph::Direction::Reverse,
            json,
            max_depth,
        ),
        BrewCmd::Deps {
            name,
            json,
            max_depth,
        } => (
            name,
            macaudit::brewgraph::Direction::Forward,
            json,
            max_depth,
        ),
    };
    if graph.resolve(&name).is_none() {
        anyhow::bail!("unknown or ambiguous package: {name}");
    }
    if json {
        println!("{}", output::brew_tree_json(&graph, &name, dir, max_depth)?);
    } else {
        print!("{}", output::brew_tree_text(&graph, &name, dir, max_depth));
    }
    Ok(())
}

fn run_config(paths: &Paths, cmd: ConfigCmd) -> anyhow::Result<()> {
    match cmd {
        ConfigCmd::Path => {
            println!("{}", paths.config_file().display());
        }
        ConfigCmd::Edit => {
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
            let path = paths.config_file();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let status = std::process::Command::new(editor).arg(&path).status()?;
            if !status.success() {
                anyhow::bail!("editor exited with failure");
            }
        }
    }
    Ok(())
}
