//! Render tests: `AppState::draw` must not panic in any mode, and three
//! golden frames pin the visual layout so unintended changes show up in
//! review. Declared as `#[cfg(test)] mod render_tests;` in `ui/mod.rs`.
//!
//! Goldens use the `--fake` fixtures and avoid sections whose cells depend
//! on the wall clock (Disk/Git show "last used" dates). To update after an
//! intentional change: `INSTA_UPDATE=always cargo test render_tests`.

use std::time::Duration;

use crate::fake;
use crate::model::{ScanEvent, ScannerId};
use crate::ui::app::{AppState, Mode};
use crate::ui::keys::Action;
use crate::ui::layout::DetailMode;
use crate::ui::testutil::{app_with_gen, finding_with_remedy, render};

#[test]
fn draw_smoke_test_across_modes() {
    let mut app = app_with_gen(1);
    app.apply(finding_with_remedy(1, "/Applications/Old.app"));
    app.detail_mode = DetailMode::ForceOn;
    app.push_activity("did a thing".into());

    render(&mut app, 100, 40); // normal, detail pane + activity log

    app.handle(Action::Char('/'));
    render(&mut app, 100, 40); // filter input in the statusbar

    app.handle(Action::Esc);
    app.handle(Action::Down); // Apps is Tree view: row 0 is the group header
    app.handle(Action::Char(' '));
    app.handle(Action::Char('x'));
    assert_eq!(app.mode, Mode::Confirm, "confirm dialog should have opened");
    render(&mut app, 100, 40); // confirm modal

    app.handle(Action::Char('n')); // cancel back to Normal
    app.handle(Action::Char('?'));
    assert_eq!(app.mode, Mode::Help, "help overlay should have opened");
    render(&mut app, 100, 40); // help modal

    // Every width tier renders.
    app.handle(Action::Esc);
    for w in [60, 80, 119, 120, 200] {
        render(&mut app, w, 30);
    }
}

/// An app with every section fully scanned from the fake fixtures.
fn app_with_fixtures() -> AppState {
    let mut app = app_with_gen(1);
    for id in ScannerId::ALL {
        for f in fake::fixtures(*id) {
            app.apply(ScanEvent::Finding {
                scanner: *id,
                gen: 1,
                finding: Box::new(f),
            });
        }
        app.apply(ScanEvent::Finished {
            scanner: *id,
            gen: 1,
            duration: Duration::from_millis(10),
        });
    }
    app
}

#[test]
fn golden_overview() {
    let mut app = app_with_fixtures();
    app.handle(Action::Char('1'));
    insta::assert_snapshot!(render(&mut app, 150, 44));
}

#[test]
fn golden_apps_tree() {
    let mut app = app_with_fixtures();
    app.handle(Action::Char('2'));
    app.handle(Action::Down);
    insta::assert_snapshot!(render(&mut app, 150, 44));
}

#[test]
fn golden_daemons_table_with_detail() {
    let mut app = app_with_fixtures();
    app.handle(Action::Char('5'));
    app.handle(Action::Down);
    app.handle(Action::Down);
    insta::assert_snapshot!(render(&mut app, 160, 44));
}
