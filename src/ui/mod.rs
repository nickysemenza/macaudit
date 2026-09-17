//! Terminal setup/teardown and the async event loop.
//!
//! The loop `tokio::select!`s over crossterm's async `EventStream`, the
//! `ScanEvent` channel, and a ~30fps draw tick. It performs NO blocking I/O —
//! scanners run as tasks and report over the channel.

pub mod app;
pub mod fmt;
pub mod keys;
pub mod theme;

mod activity;
mod browse;
mod cleanup_view;
mod confirm;
mod deps;
mod detail;
mod help;
mod layout;
mod marking;
mod mouse;
mod nav;
mod overview;
mod present;
mod rows;
mod sidebar;
mod state;
mod statusbar;
mod tree;
mod view;

#[cfg(test)]
mod render_tests;
#[cfg(test)]
mod testutil;

use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream};
use crossterm::execute;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::cleanup::{self, ExecDeps, ExecEvent};
use crate::engine::ScannerManager;
use crate::model::{Finding, FindingKind, ScanEvent, ScannerId};
use crate::remedy::{RealClipboard, RealTrash};
use crate::ui::app::{AppState, RescanRequest};

/// Run the TUI to completion. Owns the manager and the app state, wiring
/// keypresses to rescans and scan events to the reducer.
pub async fn run(manager: Arc<ScannerManager>) -> anyhow::Result<()> {
    let mut terminal = ratatui::init();
    // Capture mouse so the sidebar (and any future hit-testable widget) is
    // clickable. Best-effort: a terminal that rejects it just leaves the TUI
    // keyboard-only. Disabled again before restore so the shell's own mouse
    // behavior (text selection, scroll) returns intact.
    let _ = execute!(std::io::stdout(), EnableMouseCapture);
    let result = run_loop(&mut terminal, manager).await;
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    result
}

async fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    manager: Arc<ScannerManager>,
) -> anyhow::Result<()> {
    let (tx, mut rx) = mpsc::channel::<ScanEvent>(1024);
    // Async network-enrichment results: (gen, enriched App findings).
    let (enrich_tx, mut enrich_rx) = mpsc::channel::<(u64, Vec<Finding>)>(4);
    // Cleanup progress from the spawned batch task.
    let (exec_tx, mut exec_rx) = mpsc::channel::<ExecEvent>(64);
    // Stop token of the running batch (Esc cancels the remaining actions).
    let mut cleanup_stop: Option<CancellationToken> = None;
    // Sections to rescan once the running batch has executed.
    let mut cleanup_affected: Vec<ScannerId> = Vec::new();
    let mut app = AppState::default();
    app.set_delete_mode(manager.delete_mode());

    // Kick off an initial full scan.
    let all = ScannerId::ALL.to_vec();
    // Generation for which correlation has already run (0 = never).
    let mut correlated_gen: u64 = 0;
    let gen = manager.start(&tx, &all);
    let mut full_scan_gen = gen;
    app.begin_scan(gen, &all);

    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(33));

    loop {
        terminal.draw(|f| app.draw(f))?;

        tokio::select! {
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) if key.kind == crossterm::event::KeyEventKind::Press => {
                        if let Some(action) = keys::map(key) {
                            app.handle(action);
                        }
                    }
                    Some(Ok(Event::Mouse(me))) => {
                        app.handle_mouse(me);
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e.into()),
                    None => break,
                }
            }
            maybe_scan = rx.recv() => {
                // Some(ev): apply it. None: all senders dropped mid-idle; keep the
                // UI alive for interaction (a rescan re-spawns senders).
                if let Some(ev) = maybe_scan {
                    app.apply(ev);
                }
            }
            maybe_enriched = enrich_rx.recv() => {
                // Network enrichment landed: upsert (stale generations are
                // dropped inside apply_enriched).
                if let Some((gen, findings)) = maybe_enriched {
                    let n = findings.len();
                    app.apply_enriched(gen, findings);
                    if n > 0 {
                        app.push_activity(format!("catalog: enriched {n} app findings"));
                    }
                }
            }
            maybe_exec = exec_rx.recv() => {
                if let Some(ev) = maybe_exec {
                    let executed = matches!(ev, ExecEvent::Executed { .. });
                    let finished = matches!(ev, ExecEvent::Finished(_));
                    app.apply_exec(ev);
                    if executed && !cleanup_affected.is_empty() {
                        // Re-check the touched sections now that the batch
                        // has run; stale marks/previews are dropped as the
                        // new findings land.
                        let affected = std::mem::take(&mut cleanup_affected);
                        let gen = manager.start(&tx, &affected);
                        app.begin_scan(gen, &affected);
                        if affected.iter().any(|s| state::CORRELATED_SECTIONS.contains(s)) {
                            full_scan_gen = gen;
                        }
                    }
                    if finished {
                        cleanup_stop = None;
                    }
                }
            }
            _ = tick.tick() => {
                app.tick = app.tick.wrapping_add(1);
            }
        }

        // Once Apps + Brew both reach terminal state, run cross-scanner
        // correlation (cask-managed labeling) so the TUI sees correlated
        // findings, matching the headless path. Then kick the async network
        // half (catalog matching + release checks) in the background; results
        // arrive on `enrich_rx`. Once per generation.
        if correlated_gen != full_scan_gen && app.sections_terminal(state::CORRELATED_SECTIONS) {
            correlated_gen = full_scan_gen;
            app.correlate_now();

            if let Some(fetcher) = manager.fetcher() {
                let mut map = app.apps_brew_findings();
                let paths = manager.paths();
                let config = manager.config();
                let etx = enrich_tx.clone();
                let gen = full_scan_gen;
                tokio::spawn(async move {
                    let token = CancellationToken::new();
                    crate::net::enrich(&mut map, Some(fetcher), &paths, &config, &token).await;
                    // Ship back only findings enrichment actually touched
                    // (catalog matches carry `available_cask`; the GitHub pass
                    // only runs on those same matches).
                    let changed: Vec<Finding> = map
                        .into_values()
                        .filter(|f| {
                            f.kind == FindingKind::App && f.meta.get("available_cask").is_some()
                        })
                        .collect();
                    let _ = etx.send((gen, changed)).await;
                });
            }
        }

        // Service a requested rescan. Per-section generations mean a targeted
        // rescan cancels ONLY the requested sections.
        if let Some(req) = app.pending_rescan.take() {
            let sections: Vec<ScannerId> = match req {
                RescanRequest::All => ScannerId::ALL.to_vec(),
                RescanRequest::Section(id) => vec![id],
            };
            let gen = manager.start(&tx, &sections);
            app.begin_scan(gen, &sections);
            if matches!(req, RescanRequest::All) {
                full_scan_gen = gen;
            } else if sections
                .iter()
                .any(|s| state::CORRELATED_SECTIONS.contains(s))
            {
                // Rescanning Apps/Brew invalidates correlation for the new data.
                full_scan_gen = gen;
            }
        }

        // Service a confirmed batch: spawn `cleanup::run_batch`, which
        // re-checks every target, runs the exact commands in dependency
        // order, verifies retained tools and writes the audit report. The
        // loop keeps drawing (and can stop the batch between actions).
        if let Some(req) = app.pending_execute.take() {
            let stop = CancellationToken::new();
            cleanup_stop = Some(stop.clone());
            cleanup_affected = req.affected.clone();
            let deps = ExecDeps {
                runner: manager.runner(),
                trash: Arc::new(RealTrash),
                clipboard: Arc::new(RealClipboard),
                paths: manager.paths(),
                config: manager.config(),
                delete_mode: manager.delete_mode(),
            };
            let current = app.all_findings();
            let etx = exec_tx.clone();
            tokio::spawn(async move {
                cleanup::run_batch(req.actions, current, deps, etx, stop).await;
            });
        }
        if app.pending_cancel_cleanup {
            app.pending_cancel_cleanup = false;
            if let Some(stop) = &cleanup_stop {
                stop.cancel();
                app.push_activity("cleanup: stopping after the current action".to_string());
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}
