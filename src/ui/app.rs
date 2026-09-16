//! `AppState` and its reducer. The reducer is deliberately pure (no I/O) and
//! independent of the event loop so it can be unit-tested directly.
//!
//! Rendering is split across sibling modules (`sidebar`, `rows`, `overview`,
//! `detail`, `confirm`, `activity`, `statusbar`); this file owns the struct
//! definition, mode dispatch, and the top-level `draw()`. The reducer itself
//! is further split by concern:
//! - `state.rs`: scan-event ingestion (`apply`, `begin_scan`, ...) and
//!   section-status read-only queries.
//! - `view.rs`: read-only row/selection queries (sort, filter, tree
//!   flattening, "what's under the cursor").
//! - `nav.rs`: cursor movement, section switching, and the Normal/Filter/Help
//!   mode reducers.
//! - `marking.rs`: batch-remedy marking and the Confirm mode reducer.
//! - `mouse.rs`: sidebar click routing.
//!
//! Keys route through four modal states (`Mode`): `Normal` is the default
//! navigation/action surface, `Filter` turns every printable key into text
//! input for the `/` search box, `Confirm` is the batch-execute dialog
//! opened by `x` — only `y`/`enter`/`n`/`esc` do anything there — and `Help`
//! is the `?` keybindings overlay, where only `?`/`esc`/`q`/`enter` (plus
//! ctrl-c, which always quits) do anything.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::Frame;

use crate::config::DeleteMode;
use crate::model::{Finding, FindingId, ScannerId};
use crate::registry::{self, ViewKind};
use crate::remedy::PlannedAction;
use crate::ui::keys::Action;
use crate::ui::layout::{self, DetailMode, Hit, RailMode, Viewport};
use crate::ui::present::{CellCtx, SortSpec};
use crate::ui::rows::{self, RowsView};
use crate::ui::{activity, cleanup_view, confirm, detail, help, overview, sidebar, statusbar};

/// Per-section scan status shown in the sidebar.
#[derive(Clone, Debug, PartialEq)]
pub enum SectionStatus {
    Idle,
    Scanning {
        done: u64,
        total: Option<u64>,
        msg: String,
    },
    Done {
        duration: Duration,
    },
    Failed {
        error: String,
    },
}

/// Which key-input surface is active. Keys mean different things in each —
/// see the module doc comment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Filter,
    Confirm,
    /// The `?` keybindings overlay.
    Help,
    /// `v`: impact preview of everything marked (Homebrew orphans, launchers
    /// preserved, follow-ups) before opening the confirm dialog.
    Preview,
    /// A confirmed batch is running; Esc stops after the current action.
    Cleanup,
    /// The completion report of the last cleanup (`c` reopens it).
    Report,
}

/// What the confirm dialog shows: the actions that passed the in-memory
/// preflight (in execution order), the ones it refused with reasons, and
/// the batch's impact.
#[derive(Clone, Debug, Default)]
pub struct ConfirmModel {
    pub actions: Vec<PlannedAction>,
    pub refused: Vec<crate::cleanup::Refused>,
    pub removed: Vec<String>,
    pub remaining: Vec<String>,
    pub follow_up: Vec<String>,
    pub impact: Option<crate::brewgraph::RemovalPreview>,
    pub scroll: u16,
}

/// A confirmed batch handed to the loop for asynchronous execution.
#[derive(Clone, Debug)]
pub struct CleanupRequest {
    pub actions: Vec<PlannedAction>,
    pub affected: Vec<ScannerId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CleanupPhase {
    Preflight,
    Executing { idx: usize, total: usize },
    Verifying,
    Done,
}

/// Progress of the running (or just finished) cleanup, fed by `ExecEvent`s.
#[derive(Clone, Debug)]
pub struct CleanupRun {
    pub phase: CleanupPhase,
    /// Actions as confirmed; replaced by the refreshed preflight's order.
    pub actions: Vec<PlannedAction>,
    pub refused: Vec<crate::cleanup::Refused>,
    pub results: std::collections::BTreeMap<usize, Result<String, String>>,
    pub cancelled: Vec<PlannedAction>,
    pub cancel_requested: bool,
    pub affected: Vec<ScannerId>,
    pub report: Option<crate::cleanup::CleanupReport>,
}

pub struct AppState {
    /// Findings per section, upserted by stable id (last write wins — this is the
    /// invariant that makes deferred size updates correct).
    pub(super) findings: HashMap<ScannerId, BTreeMap<FindingId, Finding>>,
    pub(super) status: HashMap<ScannerId, SectionStatus>,
    pub(super) marked: HashSet<FindingId>,

    pub(super) selected_section: usize,
    pub(super) selected_row: usize,
    /// Per-section sort overrides; a section absent here uses its
    /// presenter's default. Keyed per section so "sort by Port" can't leak
    /// onto Apps.
    pub(super) sort: HashMap<ScannerId, SortSpec>,
    pub(super) show_system: bool,
    /// Detail pane visibility policy; the effective answer for the current
    /// width lives in `viewport.detail_visible` after each draw.
    pub(crate) detail_mode: DetailMode,
    /// Vertical scroll offset (lines) of the detail pane. Reset to 0 whenever
    /// the selection or section changes, or the pane is toggled — a stale
    /// scroll position on a freshly-selected finding would just look broken.
    pub(crate) detail_scroll: u16,

    pub(crate) mode: Mode,
    /// Substring filter (case-insensitive, matched against title/path).
    pub(crate) filter: String,
    /// Tree groups the user has explicitly collapsed, keyed by
    /// (section, group key) so collapsing in one section doesn't affect
    /// another.
    pub(super) collapsed_groups: HashSet<(ScannerId, String)>,
    /// The confirm dialog's model while `mode == Confirm`.
    pub(super) confirm: Option<ConfirmModel>,
    /// The user's explicit remedy choice per finding (`e` cycles); absent ⇒
    /// the primary remedies.
    pub(super) remedy_choice: HashMap<FindingId, usize>,
    /// The cleanup in progress / just finished, for the progress and report
    /// overlays.
    pub(crate) cleanup: Option<CleanupRun>,
    /// Set by Esc during a cleanup; the loop cancels the batch's stop token.
    pub pending_cancel_cleanup: bool,
    /// Scroll offset of the preview/report overlays.
    pub(crate) overlay_scroll: u16,
    /// Brew explorer direction (`d` toggles).
    pub(super) deps_direction: crate::brewgraph::Direction,
    /// Explorer nodes the user expanded, keyed by direction-prefixed path.
    pub(super) expanded_nodes: HashSet<String>,
    /// Cached Homebrew graph built from the Brew findings, tagged with the
    /// Brew map version it was built from.
    pub(super) brew_graph:
        std::cell::RefCell<Option<(u64, std::rc::Rc<crate::brewgraph::BrewGraph>)>>,
    /// Bumped on every Brew map mutation so the cached graph is rebuilt.
    pub(super) brew_version: u64,
    /// Delete mode used when planning remedies. Defaults to `Trash`, matching
    /// `Config::default()` — see the module-level contract-friction note in
    /// the lane report: `AppState` has no path to the real `Config` because
    /// `ScannerManager` doesn't expose one and `ui::run`'s signature is
    /// frozen, so this can't be wired to `--rm` today.
    pub(super) delete_mode: DeleteMode,
    pub(crate) activity: Vec<String>,

    /// Per-section generation whose events we accept (exact match — see
    /// `apply`). Absent ⇒ no scan has been requested for that section yet;
    /// its events are dropped.
    pub(super) expected_gen: HashMap<ScannerId, u64>,
    pub tick: usize,
    pub should_quit: bool,
    /// Set when the user requests a rescan; the loop consumes and clears it.
    pub pending_rescan: Option<RescanRequest>,
    /// Set when the confirm dialog is accepted; the loop consumes and clears
    /// it, running the batch asynchronously (see `cleanup::run_batch`).
    pub pending_execute: Option<CleanupRequest>,

    /// Geometry from the last `draw`: hit regions for the mouse, the main
    /// panel's scroll offset and page size, and which panes are visible.
    pub(super) viewport: Viewport,
    /// Most recent left-click (time + what it hit), for double-click
    /// detection.
    pub(super) last_click: Option<(Instant, Hit)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescanRequest {
    Section(ScannerId),
    All,
}

impl Default for AppState {
    fn default() -> Self {
        let status = ScannerId::ALL
            .iter()
            .map(|id| (*id, SectionStatus::Idle))
            .collect();
        AppState {
            findings: HashMap::new(),
            status,
            marked: HashSet::new(),
            selected_section: 0,
            selected_row: 0,
            sort: HashMap::new(),
            show_system: false,
            detail_mode: DetailMode::Auto,
            detail_scroll: 0,
            mode: Mode::Normal,
            filter: String::new(),
            collapsed_groups: HashSet::new(),
            confirm: None,
            remedy_choice: HashMap::new(),
            cleanup: None,
            pending_cancel_cleanup: false,
            overlay_scroll: 0,
            deps_direction: crate::brewgraph::Direction::Forward,
            expanded_nodes: HashSet::new(),
            brew_graph: std::cell::RefCell::new(None),
            brew_version: 0,
            delete_mode: DeleteMode::Trash,
            activity: Vec::new(),
            expected_gen: HashMap::new(),
            tick: 0,
            should_quit: false,
            pending_rescan: None,
            pending_execute: None,
            viewport: Viewport::default(),
            last_click: None,
        }
    }
}

impl AppState {
    // ---- reducer entry point ----

    /// Handle a semantic action. Returns nothing; the loop reads `should_quit`,
    /// `pending_rescan`, and `pending_execute` afterward.
    pub fn handle(&mut self, action: Action) {
        match self.mode {
            Mode::Normal => self.handle_normal(action),
            Mode::Filter => self.handle_filter(action),
            Mode::Confirm => self.handle_confirm(action),
            Mode::Help => self.handle_help(action),
            Mode::Preview => self.handle_preview(action),
            Mode::Cleanup => self.handle_cleanup(action),
            Mode::Report => self.handle_report(action),
        }
    }

    // ---- rendering ----

    /// Render the whole UI, recording this frame's geometry in `viewport`.
    pub fn draw(&mut self, frame: &mut Frame) {
        let mut vp = Viewport::new(self.viewport.row_offset);
        self.draw_into(frame, &mut vp);
        self.viewport = vp;
    }

    fn draw_into(&self, frame: &mut Frame, vp: &mut Viewport) {
        let area = frame.area();
        let rail = RailMode::for_width(area.width);
        vp.detail_visible = layout::detail_visible(self.detail_mode, area.width);

        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(rail.width()), Constraint::Min(20)])
            .split(area);

        if rail != RailMode::Hidden {
            sidebar::draw(self, frame, cols[0], rail, vp);
        }

        let activity_h = activity::height_for(&self.activity);
        let mut vconstraints = vec![Constraint::Min(3)];
        if activity_h > 0 {
            vconstraints.push(Constraint::Length(activity_h));
        }
        vconstraints.push(Constraint::Length(1));
        let main = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vconstraints)
            .split(cols[1]);

        // The Overview has no selectable rows, so a detail pane there would
        // only squeeze its cards.
        let show_detail = vp.detail_visible
            && registry::section(self.selected_section_id()).view != ViewKind::Overview;
        if show_detail {
            let split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Min(30), layout::detail_constraint(area.width)])
                .split(main[0]);
            self.draw_main_panel(frame, split[0], vp);
            vp.push(split[1], Hit::Detail);
            let chosen = self
                .selected_finding()
                .and_then(|f| self.remedy_choice_for(f.id));
            detail::draw(
                frame,
                split[1],
                self.selected_finding(),
                self.selected_section_id(),
                self.delete_mode,
                self.detail_scroll,
                chosen,
            );
        } else {
            self.draw_main_panel(frame, main[0], vp);
        }

        let statusbar_area = if activity_h > 0 {
            activity::draw(frame, main[1], &self.activity);
            main[2]
        } else {
            main[1]
        };
        statusbar::draw(self, frame, statusbar_area, rail, vp);

        match self.mode {
            Mode::Confirm => {
                if let Some(model) = &self.confirm {
                    confirm::draw(frame, area, model, self.delete_mode);
                }
            }
            Mode::Help => help::draw(frame, area),
            Mode::Preview => cleanup_view::draw_preview(self, frame, area),
            Mode::Cleanup => cleanup_view::draw_progress(self, frame, area),
            Mode::Report => cleanup_view::draw_report(self, frame, area),
            _ => {}
        }
    }

    fn draw_main_panel(&self, frame: &mut Frame, area: Rect, vp: &mut Viewport) {
        let id = self.selected_section_id();
        let section = registry::section(id);
        vp.push(area, Hit::MainPanel);
        if section.view == ViewKind::Overview {
            overview::draw(self, frame, area, vp);
            return;
        }
        let rows = self.rows();
        let total = self.section_count(id);
        let shown = rows
            .iter()
            .filter(|r| {
                matches!(
                    r,
                    rows::RenderRow::Item { .. } | rows::RenderRow::Node { depth: 1, .. }
                )
            })
            .count();
        let mut title = if self.filter.is_empty() {
            format!("{} · {total}", section.title)
        } else {
            format!("{} · {shown}/{total} · /{}", section.title, self.filter)
        };
        if id == ScannerId::Brew {
            title.push_str(match self.deps_direction() {
                crate::brewgraph::Direction::Forward => " · needs (d: needed-by)",
                crate::brewgraph::Direction::Reverse => " · needed by (d: needs)",
            });
        }
        let is_scanning = matches!(self.status_of(id), SectionStatus::Scanning { .. });
        let empty_message = if is_scanning {
            "scanning…"
        } else if !self.filter.is_empty() {
            "no matches"
        } else {
            "nothing found"
        };
        rows::draw(
            frame,
            area,
            RowsView {
                title: &title,
                presenter: self.presenter(),
                rows: &rows,
                ctx: CellCtx {
                    is_scanning,
                    now: std::time::SystemTime::now(),
                },
                selected: self.selected_row,
                sort: self.sort(),
                is_marked: |fid| self.marked.contains(&fid),
                empty_message,
            },
            vp,
        );
    }
}
