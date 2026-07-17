//! Terminal setup/teardown and the async event loop.
//!
//! The loop `tokio::select!`s over crossterm's async `EventStream`, the
//! `ScanEvent` channel, and a ~30fps draw tick. It performs NO blocking I/O —
//! scanners run as tasks and report over the channel.
//!
//! Lane U extends `app.rs` (widgets, confirm dialog, activity log); this file is
//! the reference loop that keeps the whole thing compiling against ratatui 0.30.

pub mod app;
pub mod keys;
pub mod theme;

use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{Event, EventStream};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

use crate::engine::ScannerManager;
use crate::model::{ScanEvent, ScannerId};
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
    let mut app = AppState::default();

    // Kick off an initial full scan.
    let all = ScannerId::ALL.to_vec();
    let gen = manager.start(&tx, &all);
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
            _ = tick.tick() => {
                app.tick = app.tick.wrapping_add(1);
            }
        }

        // Service a requested rescan (new generation cancels the old).
        if let Some(req) = app.pending_rescan.take() {
            let sections: Vec<ScannerId> = match req {
                RescanRequest::All => ScannerId::ALL.to_vec(),
                RescanRequest::Section(id) => vec![id],
            };
            let gen = manager.start(&tx, &sections);
            app.begin_scan(gen, &sections);
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}
