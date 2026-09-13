//! Thin binary: parse the CLI and dispatch to the library. All real work lives
//! in `macaudit::*` so it's testable without a terminal.

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;

use macaudit::cli::{
    BrewCmd, CleanArgs, Cli, Command, ConfigCmd, ScanArgs, SnapshotCmd, ToolsArgs, ToolsCmd,
};
use macaudit::config::{Config, DeleteMode, Paths};
use macaudit::engine::{Mode, ScannerManager};
use macaudit::model::ScannerId;
use macaudit::runner::{CommandRunner, RealCommandRunner};
use macaudit::{output, snapshot};

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
        Some(Command::Snapshot(cmd)) => run_snapshot(&manager, &paths, cmd).await,
        Some(Command::Config(cmd)) => run_config(&paths, cmd),
    }
}

async fn run_scan(manager: &ScannerManager, args: &ScanArgs) -> anyhow::Result<()> {
    let sections = args.sections()?;
    let outcome = manager.run_to_completion(&sections).await;
    warn_failures(&outcome.failures);
    if args.json {
        println!("{}", output::findings_to_json(&outcome.findings)?);
    } else {
        for f in outcome.findings.values() {
            let size = f
                .size_bytes
                .map(|b| humansize::format_size(b, humansize::BINARY))
                .unwrap_or_else(|| "-".to_string());
            println!("[{}] {:>10}  {}", f.severity_label(), size, f.title);
        }
        println!("\n{} findings", outcome.findings.len());
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
    if args.json {
        println!(
            "{}",
            output::dry_run_json(&outcome.findings, manager.delete_mode(), &args.select)?
        );
    } else {
        print!(
            "{}",
            output::dry_run_report_selected(&outcome.findings, manager.delete_mode(), &args.select)
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

async fn run_snapshot(
    manager: &ScannerManager,
    paths: &Paths,
    cmd: SnapshotCmd,
) -> anyhow::Result<()> {
    let mut store = snapshot::SnapshotStore::open(&paths.history_db())?;
    match cmd {
        SnapshotCmd::Save => {
            let outcome = manager.run_to_completion(ScannerId::ALL).await;
            if !outcome.failures.is_empty() {
                // A partial snapshot would make the next diff report whole
                // sections as removed — refuse rather than silently mislead.
                let failed: Vec<&str> = outcome.failures.iter().map(|(id, _)| id.slug()).collect();
                warn_failures(&outcome.failures);
                anyhow::bail!(
                    "not saving a partial snapshot: {} section(s) failed ({})",
                    outcome.failures.len(),
                    failed.join(", ")
                );
            }
            let id = store.save(&snapshot::machine_name(), &outcome.findings)?;
            println!("saved snapshot #{id} ({} findings)", outcome.findings.len());
        }
        SnapshotCmd::List => {
            for m in store.list()? {
                println!(
                    "#{:<4} {}  {} findings  {}",
                    m.id,
                    m.machine,
                    m.finding_count,
                    humansize::format_size(m.total_bytes.max(0) as u64, humansize::BINARY)
                );
            }
        }
        SnapshotCmd::Diff { a, b, json } => {
            let list = store.list()?;
            let (a, b) = match (a, b) {
                (Some(a), Some(b)) => (a, b),
                (Some(_), None) | (None, Some(_)) => {
                    anyhow::bail!("snapshot diff takes two ids or none (none = latest two)")
                }
                (None, None) if list.len() >= 2 => (list[1].id, list[0].id),
                _ => anyhow::bail!("need at least two snapshots (or specify ids) to diff"),
            };
            let d = store.diff(a, b)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "a": a, "b": b,
                        "added": d.added, "removed": d.removed,
                        "grown": d.grown.iter().map(|(f, o, n)| serde_json::json!({ "finding": f, "old": o, "new": n })).collect::<Vec<_>>(),
                        "changed": d.changed,
                    }))?
                );
                return Ok(());
            }
            println!("diff #{a} → #{b}:");
            println!(
                "  {} added, {} removed, {} grown, {} changed",
                d.added.len(),
                d.removed.len(),
                d.grown.len(),
                d.changed.len()
            );
            for f in &d.added {
                println!("  + {}", f.title);
            }
            for f in &d.removed {
                println!("  - {}", f.title);
            }
            for (f, o, n) in &d.grown {
                println!(
                    "  ↑ {} {} → {}",
                    f.title,
                    humansize::format_size(*o, humansize::BINARY),
                    humansize::format_size(*n, humansize::BINARY)
                );
            }
            for c in &d.changed {
                println!("  ~ {} {}: {} → {}", c.finding.title, c.field, c.old, c.new);
            }
        }
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
