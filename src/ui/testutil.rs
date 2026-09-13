//! Test-only helpers shared by the `AppState` reducer tests, split across
//! `state.rs`/`view.rs`/`nav.rs`/`marking.rs`/`mouse.rs`/`render_tests.rs`.

use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScanEvent, ScannerId};
use crate::ui::app::AppState;

pub(crate) fn finding_event(gen: u64, id_key: &str, size: Option<u64>) -> ScanEvent {
    let mut f = Finding::new(FindingKind::App, id_key, id_key);
    f.size_bytes = size;
    ScanEvent::Finding {
        scanner: ScannerId::Apps,
        gen,
        finding: Box::new(f),
    }
}

pub(crate) fn finding_with_remedy(gen: u64, key: &str) -> ScanEvent {
    let f = Finding::new(FindingKind::App, key, key)
        .size(100)
        .remedy(Remedy {
            label: "Delete".into(),
            command: RemedyCommand::Trash { path: key.into() },
            reclaims_bytes: Some(100),
            destructive: true,
        });
    ScanEvent::Finding {
        scanner: ScannerId::Apps,
        gen,
        finding: Box::new(f),
    }
}

/// `AppState::default()` expecting `gen` for every section, so tests that
/// need to accept events can do so for any scanner.
pub(crate) fn app_with_gen(gen: u64) -> AppState {
    let mut app = AppState::default();
    for id in ScannerId::ALL {
        app.expected_gen.insert(*id, gen);
    }
    // Most reducer fixtures below emit App findings; keep those tests about
    // the tree behavior rather than the Resource Health default selection.
    app.select_section(1);
    app
}

pub(crate) fn left_click(column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column,
        row,
        modifiers: crossterm::event::KeyModifiers::NONE,
    }
}

/// Draw `app` into a fresh `TestBackend` of size `w`×`h` and return the
/// rendered buffer's text (ratatui's `TestBackend` implements `Display`).
pub(crate) fn render(app: &mut AppState, w: u16, h: u16) -> String {
    let backend = ratatui::backend::TestBackend::new(w, h);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    terminal.backend().to_string()
}
