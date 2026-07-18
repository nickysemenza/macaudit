//! Thin binary: parse the CLI and dispatch to the library. All real work lives
//! in `macaudit::*` so it's testable without a terminal.

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;

use macaudit::cli::{CleanArgs, Cli, Command, ConfigCmd, ScanArgs, SnapshotCmd};
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
    print!(
        "{}",
        output::dry_run_report(&outcome.findings, manager.delete_mode())
    );
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
        SnapshotCmd::Diff { a, b } => {
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
            println!("diff #{a} → #{b}:");
            println!(
                "  {} added, {} removed, {} grown",
                d.added.len(),
                d.removed.len(),
                d.grown.len()
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
