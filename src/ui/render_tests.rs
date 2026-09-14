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
fn golden_time_machine_tree_with_detail() {
    let mut app = app_with_fixtures();
    let idx = crate::registry::REGISTRY
        .iter()
        .position(|s| s.id == ScannerId::TimeMachine)
        .unwrap();
    app.handle(Action::JumpSection(idx));
    app.detail_mode = DetailMode::ForceOn;
    app.handle(Action::Down);
    insta::assert_snapshot!(render(&mut app, 160, 44));
}

#[test]
fn golden_daemons_table_with_detail() {
    let mut app = app_with_fixtures();
    app.handle(Action::Char('6'));
    app.handle(Action::Down);
    app.handle(Action::Down);
    insta::assert_snapshot!(render(&mut app, 160, 44));
}

#[test]
fn draw_smoke_test_cleanup_modes_and_explorer() {
    use crate::cleanup::{ExecEvent, PreflightReport};
    let mut app = app_with_fixtures();
    // Brew explorer: expand the first explicitly installed formula both ways.
    app.handle(Action::Char('3'));
    app.handle(Action::Down);
    app.handle(Action::Down);
    app.handle(Action::Char('z'));
    render(&mut app, 150, 44);
    app.handle(Action::Char('d'));
    render(&mut app, 150, 44);
    // Mark wget and walk preview → confirm → cleanup → report.
    let idx = app
        .rows_titles()
        .iter()
        .position(|t| t.as_deref() == Some("wget"))
        .unwrap();
    app.handle(Action::SelectRow(idx));
    app.handle(Action::Char(' '));
    assert_eq!(app.marked_total().0, 1);
    app.handle(Action::Char('v'));
    assert_eq!(app.mode, Mode::Preview);
    render(&mut app, 150, 44);
    render(&mut app, 60, 20);
    app.handle(Action::Char('x'));
    assert_eq!(app.mode, Mode::Confirm);
    render(&mut app, 150, 44);
    app.handle(Action::Char('y'));
    assert_eq!(app.mode, Mode::Cleanup);
    let req = app.pending_execute.take().unwrap();
    app.apply_exec(ExecEvent::PreflightDone(Box::new(PreflightReport {
        ok: req.actions,
        ..Default::default()
    })));
    app.apply_exec(ExecEvent::ActionStarted(0));
    render(&mut app, 150, 44);
    render(&mut app, 60, 20);
    app.apply_exec(ExecEvent::ActionDone(0, Err("brew said no".into())));
    app.apply_exec(ExecEvent::Executed { cancelled: vec![] });
    app.apply_exec(ExecEvent::Finished(Box::default()));
    assert_eq!(app.mode, Mode::Report);
    render(&mut app, 150, 44);
    render(&mut app, 60, 20);
    // Tools and Shell trees with the detail pane.
    app.handle(Action::Esc);
    app.detail_mode = DetailMode::ForceOn;
    app.handle(Action::Char('4'));
    app.handle(Action::Down);
    render(&mut app, 150, 44);
    app.handle(Action::Char('7'));
    app.handle(Action::Down);
    render(&mut app, 150, 44);
}

#[test]
fn golden_brew_explorer_reverse() {
    let mut app = app_with_fixtures();
    app.detail_mode = DetailMode::ForceOn;
    app.handle(Action::Char('3'));
    app.handle(Action::Char('d')); // why is X installed
                                   // Installed as dependency → openssl@3 → expand: python@3.14, wget.
    let idx = app
        .rows_titles()
        .iter()
        .position(|t| t.as_deref() == Some("openssl@3"))
        .unwrap();
    app.handle(Action::SelectRow(idx));
    app.handle(Action::Char('z'));
    app.handle(Action::Down);
    insta::assert_snapshot!(render(&mut app, 160, 44));
}

#[test]
fn golden_tools_tree_with_detail() {
    let mut app = app_with_fixtures();
    app.detail_mode = DetailMode::ForceOn;
    app.handle(Action::Char('4'));
    app.handle(Action::Down);
    app.handle(Action::Down);
    insta::assert_snapshot!(render(&mut app, 160, 44));
}

#[test]
fn golden_confirm_with_impact() {
    let mut app = app_with_fixtures();
    app.handle(Action::Char('3'));
    // Mark wget (explicitly installed); openssl@3 is still needed and
    // carries no uninstall remedy, so marking it plans nothing.
    let mark = |app: &mut AppState, title: &str| {
        let rows = app.rows_titles();
        let idx = rows
            .iter()
            .position(|t| t.as_deref() == Some(title))
            .unwrap();
        app.handle(Action::SelectRow(idx));
        app.handle(Action::Char(' '));
    };
    mark(&mut app, "wget");
    mark(&mut app, "openssl@3");
    app.handle(Action::Char('x'));
    assert_eq!(app.mode, Mode::Confirm);
    insta::assert_snapshot!(render(&mut app, 160, 44));
}
