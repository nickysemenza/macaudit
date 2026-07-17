//! Terminal setup/teardown and the async event loop.
//!
//! The loop `tokio::select!`s over crossterm's async `EventStream`, the
//! `ScanEvent` channel, and a ~30fps draw tick. It performs NO blocking I/O —
//! scanners run as tasks and report over the channel.

pub mod app;
pub mod keys;
pub mod theme;

mod activity;
mod confirm;
mod detail;
mod help;
mod sidebar;
mod statusbar;
mod table;
mod tree;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{Event, EventStream};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::engine::ScannerManager;
use crate::model::{Finding, FindingKind, ScanEvent, ScannerId, Severity};
use crate::remedy::{RealClipboard, RealTrash, RemedyEngine};
use crate::snapshot::{self, SnapshotStore};
use crate::ui::app::{AppState, RescanRequest};

/// Run the TUI to completion. Owns the manager and the app state, wiring
/// keypresses to rescans and scan events to the reducer.
pub async fn run(manager: Arc<ScannerManager>) -> anyhow::Result<()> {
    let mut terminal = ratatui::init();
    let result = run_loop(&mut terminal, manager).await;
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
    let mut app = AppState::default();
    app.set_delete_mode(manager.delete_mode());
    app.set_baseline(load_baseline(&manager));

    // Kick off an initial full scan.
    let all = ScannerId::ALL.to_vec();
    let mut active_scan = all.clone();
    let mut scan_saved = false;
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
            _ = tick.tick() => {
                app.tick = app.tick.wrapping_add(1);
            }
        }

        // Once Apps + Brew both reach terminal state, run cross-scanner
        // correlation (cask-managed labeling) so the TUI — and the snapshot
        // auto-saved below — see correlated findings, matching the headless
        // path. Then kick the async network half (catalog matching + release
        // checks) in the background; results arrive on `enrich_rx`. Once per
        // generation.
        if correlated_gen != full_scan_gen
            && app.sections_terminal(&[ScannerId::Apps, ScannerId::Brew])
        {
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

        // Auto-save a snapshot when a full scan completes (spec §8) — cheap, and
        // makes `snapshot diff` useful without ceremony. Only full scans, once.
        if !scan_saved
            && active_scan.len() == ScannerId::ALL.len()
            && app.scan_complete(&active_scan)
        {
            scan_saved = true;
            match save_snapshot(&manager, &app) {
                Ok(id) => app.push_activity(format!("saved snapshot #{id}")),
                Err(e) => app.push_activity(format!("snapshot save failed: {e}")),
            }
        }

        // Service a requested rescan. Per-section generations mean a targeted
        // rescan cancels ONLY the requested sections; an in-flight full scan
        // keeps running, so its auto-snapshot bookkeeping must survive — only
        // `R` (rescan all) resets it.
        if let Some(req) = app.pending_rescan.take() {
            let sections: Vec<ScannerId> = match req {
                RescanRequest::All => ScannerId::ALL.to_vec(),
                RescanRequest::Section(id) => vec![id],
            };
            let gen = manager.start(&tx, &sections);
            app.begin_scan(gen, &sections);
            if matches!(req, RescanRequest::All) {
                active_scan = sections;
                scan_saved = false;
                full_scan_gen = gen;
            } else if sections
                .iter()
                .any(|s| matches!(s, ScannerId::Apps | ScannerId::Brew))
            {
                // Rescanning Apps/Brew invalidates correlation for the new data.
                full_scan_gen = gen;
            }
        }

        // Service a confirmed batch of remedies: execute each (Trash via the
        // trash crate, Shell/Reveal via the runner), stream results into the
        // activity log, then targeted-rescan the affected sections so their
        // findings re-check. Execution is awaited inline; remedies are fast
        // (trash is instant) and user-initiated, so briefly pausing input is
        // acceptable for v1.
        if let Some(actions) = app.pending_execute.take() {
            let engine = RemedyEngine::new(manager.delete_mode());
            let runner = manager.runner();
            let token = CancellationToken::new();
            let mut affected: Vec<ScannerId> = Vec::new();
            for a in &actions {
                if let Some(sec) = app.section_of(a.finding_id) {
                    if !affected.contains(&sec) {
                        affected.push(sec);
                    }
                }
                match engine
                    .execute(a, runner.as_ref(), &RealTrash, &RealClipboard, &token)
                    .await
                {
                    Ok(line) => app.push_activity(line),
                    Err(e) => app.push_activity(format!("error: {} — {e}", a.rendered)),
                }
            }
            if !affected.is_empty() {
                let gen = manager.start(&tx, &affected);
                app.begin_scan(gen, &affected);
                // A targeted rescan is not a full snapshot; don't auto-save it.
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

/// Load the most recent snapshot's per-section (count, reclaimable-bytes)
/// baseline for Δ badges. Best-effort: any failure yields an empty baseline.
fn load_baseline(manager: &ScannerManager) -> HashMap<ScannerId, (usize, u64)> {
    let mut base: HashMap<ScannerId, (usize, u64)> = HashMap::new();
    let Ok(store) = SnapshotStore::open(&manager.paths().history_db()) else {
        return base;
    };
    if let Ok(Some(findings)) = store.latest_findings() {
        for f in findings {
            let entry = base.entry(f.kind.scanner()).or_insert((0, 0));
            entry.0 += 1;
            if f.severity == Severity::Reclaimable {
                entry.1 += f.size_bytes.unwrap_or(0);
            }
        }
    }
    base
}

/// Persist the current findings as a snapshot.
fn save_snapshot(manager: &ScannerManager, app: &AppState) -> anyhow::Result<i64> {
    let mut store = SnapshotStore::open(&manager.paths().history_db())?;
    store.save(&snapshot::machine_name(), &app.all_findings())
}
