//! `AppState` and its reducer. The reducer is deliberately pure (no I/O) and
//! independent of the event loop so it can be unit-tested directly.
//!
//! Rendering is split across sibling modules (`sidebar`, `table`, `tree`,
//! `detail`, `confirm`, `activity`, `statusbar`); this file owns state,
//! the key-action reducer, and orchestrates `draw()` by handing each pane
//! its slice of state.
//!
//! Keys route through four modal states (`Mode`): `Normal` is the default
//! navigation/action surface, `Filter` turns every printable key into text
//! input for the `/` search box, `Confirm` is the batch-execute dialog
//! opened by `x` — only `y`/`enter`/`n`/`esc` do anything there — and `Help`
//! is the `?` keybindings overlay, where only `?`/`esc`/`q`/`enter` (plus
//! ctrl-c, which always quits) do anything.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::Frame;

use crate::config::DeleteMode;
use crate::model::{Finding, FindingId, FindingKind, Remedy, ScanEvent, ScannerId, Severity};
use crate::registry::{self, ViewKind};
use crate::remedy::{PlannedAction, RemedyEngine};
use crate::ui::keys::Action;
use crate::ui::tree::TreeRow;
use crate::ui::{activity, confirm, detail, help, sidebar, statusbar, table, tree};

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

/// How the current section's rows are ordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    SizeDesc,
    Title,
    Severity,
}

impl Sort {
    fn next(self) -> Sort {
        match self {
            Sort::SizeDesc => Sort::Title,
            Sort::Title => Sort::Severity,
            Sort::Severity => Sort::SizeDesc,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Sort::SizeDesc => "size",
            Sort::Title => "name",
            Sort::Severity => "severity",
        }
    }
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
}

pub struct AppState {
    /// Findings per section, upserted by stable id (last write wins — this is the
    /// invariant that makes deferred size updates correct).
    findings: HashMap<ScannerId, BTreeMap<FindingId, Finding>>,
    status: HashMap<ScannerId, SectionStatus>,
    marked: HashSet<FindingId>,

    selected_section: usize,
    selected_row: usize,
    sort: Sort,
    show_system: bool,
    pub show_detail: bool,
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
    collapsed_groups: HashSet<(ScannerId, String)>,
    /// The planned actions currently shown in the confirm dialog.
    confirm_actions: Vec<PlannedAction>,
    /// Delete mode used when planning remedies. Defaults to `Trash`, matching
    /// `Config::default()` — see the module-level contract-friction note in
    /// the lane report: `AppState` has no path to the real `Config` because
    /// `ScannerManager` doesn't expose one and `ui::run`'s signature is
    /// frozen, so this can't be wired to `--rm` today.
    delete_mode: DeleteMode,
    pub(crate) activity: Vec<String>,

    /// Per-section baseline (count, reclaimable bytes) from the most recent
    /// snapshot at startup, used to render "Δ since last snapshot" badges.
    baseline: HashMap<ScannerId, (usize, u64)>,

    /// Per-section generation whose events we accept (exact match — see
    /// `apply`). Absent ⇒ no scan has been requested for that section yet;
    /// its events are dropped.
    expected_gen: HashMap<ScannerId, u64>,
    pub tick: usize,
    pub should_quit: bool,
    /// Set when the user requests a rescan; the loop consumes and clears it.
    pub pending_rescan: Option<RescanRequest>,
    /// Set when the confirm dialog is accepted; the loop consumes and clears
    /// it, executing (or, pre-Phase-2, just logging) each action.
    pub pending_execute: Option<Vec<PlannedAction>>,
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
            sort: Sort::SizeDesc,
            show_system: false,
            show_detail: false,
            detail_scroll: 0,
            mode: Mode::Normal,
            filter: String::new(),
            collapsed_groups: HashSet::new(),
            confirm_actions: Vec::new(),
            delete_mode: DeleteMode::Trash,
            activity: Vec::new(),
            baseline: HashMap::new(),
            expected_gen: HashMap::new(),
            tick: 0,
            should_quit: false,
            pending_rescan: None,
            pending_execute: None,
        }
    }
}

impl AppState {
    pub fn selected_section_id(&self) -> ScannerId {
        ScannerId::ALL[self.selected_section]
    }

    pub(crate) fn selected_section_index(&self) -> usize {
        self.selected_section
    }

    /// Set the delete mode used when planning remedies (wired from `Config` by
    /// the run loop, honoring `--rm`).
    pub fn set_delete_mode(&mut self, mode: DeleteMode) {
        self.delete_mode = mode;
    }

    /// Install the per-section baseline (count, reclaimable bytes) from the most
    /// recent snapshot so the sidebar can show Δ badges.
    pub fn set_baseline(&mut self, baseline: HashMap<ScannerId, (usize, u64)>) {
        self.baseline = baseline;
    }

    /// Δ in reclaimable bytes for a section vs the last snapshot, if a baseline
    /// exists and the section has finished scanning. `None` ⇒ no badge.
    pub(crate) fn section_reclaimable_delta(&self, id: ScannerId) -> Option<i64> {
        if !matches!(self.status_of(id), SectionStatus::Done { .. }) {
            return None;
        }
        let (_, base) = self.baseline.get(&id)?;
        let now = self.section_reclaimable(id);
        let delta = now as i64 - *base as i64;
        if delta == 0 {
            None
        } else {
            Some(delta)
        }
    }

    /// Which section currently holds a finding, for post-remedy targeted rescan.
    pub fn section_of(&self, id: FindingId) -> Option<ScannerId> {
        self.findings
            .iter()
            .find(|(_, m)| m.contains_key(&id))
            .map(|(s, _)| *s)
    }

    /// A flat snapshot of every current finding, keyed by id — for `snapshot save`.
    pub fn all_findings(&self) -> BTreeMap<FindingId, Finding> {
        let mut out = BTreeMap::new();
        for m in self.findings.values() {
            for (id, f) in m {
                out.insert(*id, f.clone());
            }
        }
        out
    }

    /// Whether every section in `sections` has reached a terminal status
    /// (Done or Failed) — i.e. the scan is complete.
    pub fn scan_complete(&self, sections: &[ScannerId]) -> bool {
        self.sections_terminal(sections)
    }

    /// Sections among `sections` whose latest scan FAILED.
    pub fn failed_sections(&self, sections: &[ScannerId]) -> Vec<ScannerId> {
        sections
            .iter()
            .copied()
            .filter(|id| matches!(self.status_of(*id), SectionStatus::Failed { .. }))
            .collect()
    }

    /// Whether every listed section is Done or Failed.
    pub fn sections_terminal(&self, sections: &[ScannerId]) -> bool {
        sections.iter().all(|id| {
            matches!(
                self.status_of(*id),
                SectionStatus::Done { .. } | SectionStatus::Failed { .. }
            )
        })
    }

    /// A merged snapshot of the Apps + Brew section maps — the input to both
    /// sync correlation and the async network-enrichment task.
    pub fn apps_brew_findings(&self) -> BTreeMap<FindingId, Finding> {
        let mut merged: BTreeMap<FindingId, Finding> = BTreeMap::new();
        for id in [ScannerId::Apps, ScannerId::Brew] {
            if let Some(map) = self.findings.get(&id) {
                for (fid, f) in map {
                    merged.insert(*fid, f.clone());
                }
            }
        }
        merged
    }

    /// Run cross-scanner correlation over the in-memory findings (the TUI
    /// equivalent of the headless path's `correlate()` call): merge the Apps +
    /// Brew section maps, correlate, write mutated findings back to their
    /// sections. Sync and cheap (hundreds of items); call once both sections
    /// are terminal so cask labels appear in the TUI and in auto-saved
    /// snapshots.
    pub fn correlate_now(&mut self) {
        let mut merged = self.apps_brew_findings();
        if merged.is_empty() {
            return;
        }
        crate::correlate::correlate(&mut merged);
        for (fid, f) in merged {
            self.findings
                .entry(f.kind.scanner())
                .or_default()
                .insert(fid, f);
        }
    }

    /// Upsert a batch of enriched findings (async network enrichment results)
    /// for generation `gen`. Batches from superseded generations are dropped:
    /// every enriched finding's section must still expect `gen`.
    pub fn apply_enriched(&mut self, gen: u64, findings: Vec<Finding>) {
        for f in findings {
            let section = f.kind.scanner();
            if self.expected_gen.get(&section) == Some(&gen) {
                self.findings.entry(section).or_default().insert(f.id, f);
            }
        }
    }

    /// Append a line to the activity log (capped so it can't grow unbounded
    /// across a long session).
    pub fn push_activity(&mut self, line: String) {
        self.activity.push(line);
        if self.activity.len() > 200 {
            self.activity.remove(0);
        }
    }

    /// Apply a scan event. Accepts an event only when its gen EXACTLY matches
    /// the section's expected gen — `<` drops superseded/cancelled runs, and
    /// `>` drops runs the UI never requested for that section (the discovery-
    /// only Fs helper spawned by a git-only rescan, whose `Started{Fs}` would
    /// otherwise wipe the Disk pane). This is the sole mutation path for
    /// findings; upsert-by-id keeps sizes/dedup correct.
    pub fn apply(&mut self, ev: ScanEvent) {
        if self.expected_gen.get(&ev.scanner()) != Some(&ev.generation()) {
            return;
        }
        match ev {
            ScanEvent::Started { scanner, .. } => {
                self.findings.entry(scanner).or_default().clear();
                self.status.insert(
                    scanner,
                    SectionStatus::Scanning {
                        done: 0,
                        total: None,
                        msg: String::new(),
                    },
                );
            }
            ScanEvent::Progress {
                scanner,
                msg,
                done,
                total,
                ..
            } => {
                self.status
                    .insert(scanner, SectionStatus::Scanning { done, total, msg });
            }
            ScanEvent::Finding {
                scanner, finding, ..
            } => {
                self.findings
                    .entry(scanner)
                    .or_default()
                    .insert(finding.id, *finding);
            }
            ScanEvent::Finished {
                scanner, duration, ..
            } => {
                self.status
                    .insert(scanner, SectionStatus::Done { duration });
            }
            ScanEvent::Failed { scanner, error, .. } => {
                self.status.insert(scanner, SectionStatus::Failed { error });
            }
        }
    }

    /// Reset the given sections to Scanning-pending and register `gen` as their
    /// expected generation. Callers pass the *requested* set, never the
    /// engine's planned set (the discovery-only Fs helper must stay
    /// unexpected so its events are dropped).
    pub fn begin_scan(&mut self, gen: u64, sections: &[ScannerId]) {
        for id in sections {
            self.expected_gen.insert(*id, gen);
        }
        for id in sections {
            self.findings.entry(*id).or_default().clear();
            self.status.insert(
                *id,
                SectionStatus::Scanning {
                    done: 0,
                    total: None,
                    msg: String::new(),
                },
            );
        }
    }

    // ---- read-only helpers used by the reducer and by sibling render modules ----

    pub(crate) fn status_of(&self, id: ScannerId) -> SectionStatus {
        self.status.get(&id).cloned().unwrap_or(SectionStatus::Idle)
    }

    pub(crate) fn section_count(&self, id: ScannerId) -> usize {
        self.findings.get(&id).map(|m| m.len()).unwrap_or(0)
    }

    pub(crate) fn section_reclaimable(&self, id: ScannerId) -> u64 {
        self.findings
            .get(&id)
            .map(|m| {
                m.values()
                    .filter(|f| f.severity == Severity::Reclaimable)
                    .filter_map(|f| f.size_bytes)
                    .sum()
            })
            .unwrap_or(0)
    }

    pub(crate) fn marked_total(&self) -> (usize, u64) {
        let mut count = 0;
        let mut bytes = 0;
        for map in self.findings.values() {
            for f in map.values() {
                if self.marked.contains(&f.id) {
                    count += 1;
                    bytes += f.size_bytes.unwrap_or(0);
                }
            }
        }
        (count, bytes)
    }

    pub(crate) fn sort_label(&self) -> &'static str {
        self.sort.label()
    }

    fn is_tree_view(&self) -> bool {
        matches!(
            registry::section(self.selected_section_id()).view,
            ViewKind::Tree
        )
    }

    /// Findings for the selected section, ordered by the current sort, with
    /// System apps and the `/` filter applied.
    fn visible_findings(&self) -> Vec<&Finding> {
        let id = self.selected_section_id();
        let Some(map) = self.findings.get(&id) else {
            return Vec::new();
        };
        let needle = self.filter.to_lowercase();
        let mut rows: Vec<&Finding> = map
            .values()
            .filter(|f| self.show_system || !is_system_app(f))
            .filter(|f| needle.is_empty() || matches_filter(f, &needle))
            .collect();
        match self.sort {
            // Tie-break by title so size-less sections (Apps/Brew) read
            // alphabetically under the default sort instead of map-order.
            Sort::SizeDesc => rows.sort_by(|a, b| {
                b.size_bytes
                    .unwrap_or(0)
                    .cmp(&a.size_bytes.unwrap_or(0))
                    .then_with(|| a.title.cmp(&b.title))
            }),
            Sort::Title => rows.sort_by(|a, b| a.title.cmp(&b.title)),
            Sort::Severity => rows.sort_by(|a, b| {
                b.severity
                    .cmp(&a.severity)
                    .then_with(|| a.title.cmp(&b.title))
            }),
        }
        rows
    }

    /// The flattened tree rows for the selected section (Tree-view sections
    /// only; callers should check `is_tree_view()` first if it matters).
    fn tree_rows(&self) -> Vec<TreeRow<'_>> {
        let id = self.selected_section_id();
        let findings = self.visible_findings();
        tree::build_rows(findings.into_iter(), |key| {
            self.collapsed_groups.contains(&(id, key.to_string()))
        })
    }

    fn row_count(&self) -> usize {
        if self.is_tree_view() {
            self.tree_rows().len()
        } else {
            self.visible_findings().len()
        }
    }

    /// The Finding under the cursor, whether we're in table or tree view (in
    /// tree view, `None` when the cursor is on a group header).
    fn selected_finding(&self) -> Option<&Finding> {
        if self.is_tree_view() {
            match self.tree_rows().into_iter().nth(self.selected_row) {
                Some(TreeRow::Item(f)) => Some(f),
                _ => None,
            }
        } else {
            self.visible_findings().into_iter().nth(self.selected_row)
        }
    }

    // ---- reducer ----

    /// Handle a semantic action. Returns nothing; the loop reads `should_quit`,
    /// `pending_rescan`, and `pending_execute` afterward.
    pub fn handle(&mut self, action: Action) {
        match self.mode {
            Mode::Normal => self.handle_normal(action),
            Mode::Filter => self.handle_filter(action),
            Mode::Confirm => self.handle_confirm(action),
            Mode::Help => self.handle_help(action),
        }
    }

    fn handle_normal(&mut self, action: Action) {
        match action {
            Action::CtrlC => self.should_quit = true,
            Action::Char('q') | Action::Esc => self.should_quit = true,
            Action::Up | Action::Char('k') => self.move_up(),
            Action::Down | Action::Char('j') => self.move_down(),
            Action::Tab => self.next_section(),
            Action::BackTab => self.prev_section(),
            Action::Left => self.on_left(),
            Action::Right => self.on_right(),
            Action::Char(' ') => self.toggle_mark_selected(),
            Action::Enter => self.on_enter(),
            Action::Char('x') => self.open_confirm(),
            Action::Char('r') => {
                self.pending_rescan = Some(RescanRequest::Section(self.selected_section_id()));
            }
            Action::Char('R') => self.pending_rescan = Some(RescanRequest::All),
            Action::Char('/') => self.mode = Mode::Filter,
            Action::Char('s') => self.sort = self.sort.next(),
            Action::Char('h') => self.show_system = !self.show_system,
            Action::Char('?') => self.mode = Mode::Help,
            Action::PageDown if self.show_detail => {
                self.detail_scroll = self.detail_scroll.saturating_add(5);
            }
            Action::PageUp if self.show_detail => {
                self.detail_scroll = self.detail_scroll.saturating_sub(5);
            }
            _ => {}
        }
    }

    /// `Mode::Help`: only closing keys (and ctrl-c, handled above every
    /// mode) do anything — everything else, including the letters that are
    /// shortcuts in Normal mode, is swallowed so the overlay can't silently
    /// mutate state while it's up.
    fn handle_help(&mut self, action: Action) {
        match action {
            Action::CtrlC => self.should_quit = true,
            Action::Char('?') | Action::Esc | Action::Char('q') | Action::Enter => {
                self.mode = Mode::Normal;
            }
            _ => {}
        }
    }

    fn handle_filter(&mut self, action: Action) {
        match action {
            Action::CtrlC => self.should_quit = true,
            Action::Char(c) => {
                self.filter.push(c);
                self.selected_row = 0;
            }
            Action::Backspace => {
                self.filter.pop();
                self.selected_row = 0;
            }
            Action::Enter => self.mode = Mode::Normal,
            Action::Esc => {
                self.filter.clear();
                self.mode = Mode::Normal;
                self.selected_row = 0;
            }
            _ => {}
        }
    }

    fn handle_confirm(&mut self, action: Action) {
        match action {
            Action::CtrlC => self.should_quit = true,
            Action::Char('y') | Action::Enter => {
                self.pending_execute = Some(std::mem::take(&mut self.confirm_actions));
                self.marked.clear();
                self.mode = Mode::Normal;
            }
            Action::Char('n') | Action::Esc => {
                self.confirm_actions.clear();
                self.mode = Mode::Normal;
            }
            _ => {}
        }
    }

    fn move_down(&mut self) {
        let n = self.row_count();
        if n > 0 {
            self.selected_row = (self.selected_row + 1).min(n - 1);
        }
        self.detail_scroll = 0;
    }

    fn move_up(&mut self) {
        self.selected_row = self.selected_row.saturating_sub(1);
        self.detail_scroll = 0;
    }

    fn next_section(&mut self) {
        self.selected_section = (self.selected_section + 1) % ScannerId::ALL.len();
        self.selected_row = 0;
        self.detail_scroll = 0;
    }

    fn prev_section(&mut self) {
        self.selected_section =
            (self.selected_section + ScannerId::ALL.len() - 1) % ScannerId::ALL.len();
        self.selected_row = 0;
        self.detail_scroll = 0;
    }

    /// Left: in tree view, collapse the group under the cursor; otherwise
    /// (table view, or the cursor is on a leaf item) switch to the previous
    /// section.
    fn on_left(&mut self) {
        if self.is_tree_view() {
            if let Some(TreeRow::Group { key, .. }) = self.tree_rows().get(self.selected_row) {
                self.collapsed_groups
                    .insert((self.selected_section_id(), key.clone()));
                return;
            }
        }
        self.prev_section();
    }

    /// Right: in tree view, expand the group under the cursor; otherwise
    /// switch to the next section. Mirror of `on_left`.
    fn on_right(&mut self) {
        if self.is_tree_view() {
            if let Some(TreeRow::Group { key, .. }) = self.tree_rows().get(self.selected_row) {
                self.collapsed_groups
                    .remove(&(self.selected_section_id(), key.clone()));
                return;
            }
        }
        self.next_section();
    }

    /// Enter: on a tree group header, toggle expand/collapse; otherwise
    /// toggle the detail pane (spec §4).
    fn on_enter(&mut self) {
        if self.is_tree_view() {
            if let Some(TreeRow::Group { key, .. }) = self.tree_rows().get(self.selected_row) {
                let entry = (self.selected_section_id(), key.clone());
                if !self.collapsed_groups.remove(&entry) {
                    self.collapsed_groups.insert(entry);
                }
                return;
            }
        }
        self.show_detail = !self.show_detail;
        self.detail_scroll = 0;
    }

    fn toggle_mark_selected(&mut self) {
        if let Some(id) = self.selected_finding().map(|f| f.id) {
            if !self.marked.insert(id) {
                self.marked.remove(&id);
            }
        }
    }

    /// Gather marked findings' primary remedies, plan them via `RemedyEngine`,
    /// and open the confirm dialog. No-op if nothing marked has an
    /// executable remedy.
    fn open_confirm(&mut self) {
        if self.marked.is_empty() {
            return;
        }
        let items: Vec<(FindingId, Remedy)> = self
            .findings
            .values()
            .flat_map(|m| m.values())
            .filter(|f| self.marked.contains(&f.id))
            .flat_map(|f| {
                execution_remedies(f)
                    .into_iter()
                    .map(|r| (f.id, r.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        if items.is_empty() {
            return;
        }
        let engine = RemedyEngine::new(self.delete_mode);
        self.confirm_actions = engine.plan(&items);
        self.mode = Mode::Confirm;
    }

    // ---- rendering ----

    /// Render the whole UI.
    pub fn draw(&self, frame: &mut Frame) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(24), Constraint::Min(20)])
            .split(frame.area());

        sidebar::draw(self, frame, cols[0]);

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

        if self.show_detail {
            let split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(main[0]);
            self.draw_main_panel(frame, split[0]);
            detail::draw(
                frame,
                split[1],
                self.selected_finding(),
                self.delete_mode,
                self.detail_scroll,
            );
        } else {
            self.draw_main_panel(frame, main[0]);
        }

        let statusbar_area = if activity_h > 0 {
            activity::draw(frame, main[1], &self.activity);
            main[2]
        } else {
            main[1]
        };
        statusbar::draw(self, frame, statusbar_area);

        if self.mode == Mode::Confirm {
            confirm::draw(frame, frame.area(), &self.confirm_actions, self.delete_mode);
        }
        if self.mode == Mode::Help {
            help::draw(frame, frame.area());
        }
    }

    fn draw_main_panel(&self, frame: &mut Frame, area: Rect) {
        let id = self.selected_section_id();
        let title = registry::section(id).title;
        match registry::section(id).view {
            ViewKind::Table => {
                let rows = self.visible_findings();
                let is_scanning = matches!(self.status_of(id), SectionStatus::Scanning { .. });
                table::draw(
                    frame,
                    area,
                    title,
                    &rows,
                    |fid| self.marked.contains(&fid),
                    self.selected_row,
                    is_scanning,
                );
            }
            ViewKind::Tree => {
                let rows = self.tree_rows();
                tree::draw(
                    frame,
                    area,
                    title,
                    &rows,
                    |fid| self.marked.contains(&fid),
                    self.selected_row,
                );
            }
        }
    }
}

/// The remedies to plan when a finding is marked for batch execution:
///
/// - ALL destructive remedies, in emission order — multi-step workflows like
///   launchd's "bootout, THEN trash the plist" execute as an ordered sequence
///   (previously only the first ever ran and the trash was unreachable).
/// - Else the first Shell remedy — an actionable command like
///   `brew install --adopt` must not lose to an earlier Reveal-in-Finder.
/// - Else the first remedy, if any (reveal/copy-only findings).
fn execution_remedies(f: &Finding) -> Vec<&Remedy> {
    let destructive: Vec<&Remedy> = f.remedies.iter().filter(|r| r.destructive).collect();
    if !destructive.is_empty() {
        return destructive;
    }
    if let Some(shell) = f
        .remedies
        .iter()
        .find(|r| matches!(r.command, crate::model::RemedyCommand::Shell { .. }))
    {
        return vec![shell];
    }
    f.remedies.first().into_iter().collect()
}

fn matches_filter(f: &Finding, needle: &str) -> bool {
    f.title.to_lowercase().contains(needle)
        || f.path
            .as_ref()
            .map(|p| p.display().to_string().to_lowercase().contains(needle))
            .unwrap_or(false)
}

/// Whether a finding is a System app (hidden unless `h` toggled). Heuristic on
/// path; the real classification lives in AppsScanner's meta.
fn is_system_app(f: &Finding) -> bool {
    // Scoped to App findings: other sections (e.g. Ports) legitimately carry
    // /System/… binary paths and must not vanish behind the `h` toggle.
    f.kind == FindingKind::App
        && f.path
            .as_ref()
            .map(|p| p.starts_with("/System/"))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FindingKind, RemedyCommand};

    fn finding_event(gen: u64, id_key: &str, size: Option<u64>) -> ScanEvent {
        let mut f = Finding::new(FindingKind::App, id_key, id_key);
        f.size_bytes = size;
        ScanEvent::Finding {
            scanner: ScannerId::Apps,
            gen,
            finding: Box::new(f),
        }
    }

    fn finding_with_remedy(gen: u64, key: &str) -> ScanEvent {
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
    fn app_with_gen(gen: u64) -> AppState {
        let mut app = AppState::default();
        for id in ScannerId::ALL {
            app.expected_gen.insert(*id, gen);
        }
        app
    }

    #[test]
    fn upsert_dedups_by_id() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/a", None));
        app.apply(finding_event(1, "/a", Some(999))); // same id, now sized
        let map = app.findings.get(&ScannerId::Apps).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.values().next().unwrap().size_bytes, Some(999));
    }

    #[test]
    fn stale_generation_dropped() {
        let mut app = app_with_gen(2);
        app.apply(finding_event(1, "/old", Some(1))); // stale gen
        assert_eq!(app.section_count(ScannerId::Apps), 0);
    }

    #[test]
    fn per_section_staleness_exact_match() {
        let mut app = AppState::default();
        app.begin_scan(2, &[ScannerId::Apps]);
        app.apply(finding_event(1, "/older", Some(1))); // gen < expected: dropped
        app.apply(finding_event(3, "/newer", Some(1))); // gen > expected: dropped
        app.apply(finding_event(2, "/right", Some(1))); // exact: applied
        assert_eq!(app.section_count(ScannerId::Apps), 1);
    }

    #[test]
    fn section_rescan_keeps_other_sections_events() {
        // The headline regression: rescanning Ports must not orphan the rest of
        // an in-flight full scan.
        let mut app = AppState::default();
        app.begin_scan(1, ScannerId::ALL);
        app.begin_scan(2, &[ScannerId::Ports]);

        // Old-gen events from the still-running full scan keep landing.
        app.apply(finding_event(1, "/apps-item", Some(1)));
        app.apply(ScanEvent::Finished {
            scanner: ScannerId::Brew,
            gen: 1,
            duration: Duration::from_secs(1),
        });
        app.apply(ScanEvent::Finished {
            scanner: ScannerId::Ports,
            gen: 2,
            duration: Duration::from_secs(1),
        });

        assert_eq!(
            app.section_count(ScannerId::Apps),
            1,
            "full-scan finding kept"
        );
        assert!(
            matches!(app.status_of(ScannerId::Brew), SectionStatus::Done { .. }),
            "old code left Brew stuck Scanning"
        );
        assert!(matches!(
            app.status_of(ScannerId::Ports),
            SectionStatus::Done { .. }
        ));
    }

    #[test]
    fn git_rescan_discovery_fs_does_not_clobber_disk() {
        let mut app = AppState::default();
        app.begin_scan(1, ScannerId::ALL);
        // Disk finishes with findings.
        let mut f = Finding::new(FindingKind::BuildArtifact, "/p/node_modules", "nm");
        f.size_bytes = Some(10);
        app.apply(ScanEvent::Finding {
            scanner: ScannerId::Fs,
            gen: 1,
            finding: Box::new(f),
        });
        app.apply(ScanEvent::Finished {
            scanner: ScannerId::Fs,
            gen: 1,
            duration: Duration::from_secs(1),
        });

        // Git-only rescan: engine spawns a discovery-only Fs at gen 2, whose
        // Started{Fs} previously wiped the Disk pane.
        app.begin_scan(2, &[ScannerId::Git]);
        app.apply(ScanEvent::Started {
            scanner: ScannerId::Fs,
            gen: 2,
        });

        assert_eq!(app.section_count(ScannerId::Fs), 1, "Disk findings wiped");
        assert!(matches!(
            app.status_of(ScannerId::Fs),
            SectionStatus::Done { .. }
        ));
    }

    #[test]
    fn double_rescan_drops_old_run_events() {
        let mut app = AppState::default();
        app.begin_scan(1, &[ScannerId::Apps]);
        app.begin_scan(2, &[ScannerId::Apps]);
        app.apply(finding_event(1, "/from-old-run", Some(1))); // dropped
        app.apply(finding_event(2, "/from-new-run", Some(1))); // kept
        let map = app.findings.get(&ScannerId::Apps).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.values().next().unwrap().title, "/from-new-run");
    }

    #[test]
    fn correlate_now_marks_installed_cask_apps() {
        let mut app = app_with_gen(1);
        let cask = Finding::new(FindingKind::BrewCask, "slack", "slack")
            .meta(serde_json::json!({"token": "slack", "app_paths": ["/Applications/Slack.app"]}));
        let mut a = Finding::new(FindingKind::App, "/Applications/Slack.app", "Slack")
            .path("/Applications/Slack.app")
            .meta(serde_json::json!({"classification": "unmanaged", "group": "Unmanaged"}));
        a.severity = Severity::Attention;
        app.apply(ScanEvent::Finding {
            scanner: ScannerId::Brew,
            gen: 1,
            finding: Box::new(cask),
        });
        app.apply(ScanEvent::Finding {
            scanner: ScannerId::Apps,
            gen: 1,
            finding: Box::new(a.clone()),
        });

        app.correlate_now();

        let apps = app.findings.get(&ScannerId::Apps).unwrap();
        let updated = apps.get(&a.id).unwrap();
        assert_eq!(updated.meta["group"], "Homebrew Cask");
        assert_eq!(updated.meta["managed_by_cask"], "slack");
    }

    #[test]
    fn apply_enriched_respects_generation() {
        let mut app = AppState::default();
        app.begin_scan(2, &[ScannerId::Apps]);
        let f = Finding::new(FindingKind::App, "/Applications/X.app", "X");
        app.apply_enriched(1, vec![f.clone()]); // stale batch dropped
        assert_eq!(app.section_count(ScannerId::Apps), 0);
        app.apply_enriched(2, vec![f]); // current batch applied
        assert_eq!(app.section_count(ScannerId::Apps), 1);
    }

    #[test]
    fn marking_toggles() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/a", Some(10)));
        // Apps is a Tree-view section: row 0 is the group header, row 1 is
        // the finding itself.
        app.handle(Action::Down);
        app.handle(Action::Char(' '));
        assert_eq!(app.marked_total().0, 1);
        app.handle(Action::Char(' '));
        assert_eq!(app.marked_total().0, 0);
    }

    #[test]
    fn rescan_section_requested() {
        let mut app = AppState::default();
        app.handle(Action::Char('R'));
        assert_eq!(app.pending_rescan, Some(RescanRequest::All));
    }

    #[test]
    fn tab_and_backtab_cycle_sections() {
        let mut app = AppState::default();
        let start = app.selected_section_index();
        app.handle(Action::Tab);
        assert_eq!(
            app.selected_section_index(),
            (start + 1) % ScannerId::ALL.len()
        );
        app.handle(Action::BackTab);
        assert_eq!(app.selected_section_index(), start);
    }

    #[test]
    fn q_quits_in_normal_mode_but_is_text_in_filter_mode() {
        let mut app = AppState::default();
        app.handle(Action::Char('/'));
        app.handle(Action::Char('q'));
        assert!(!app.should_quit);
        assert_eq!(app.filter, "q");
        app.handle(Action::Esc);
        app.handle(Action::Char('q'));
        assert!(app.should_quit);
    }

    #[test]
    fn filter_narrows_visible_rows_by_title_substring() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/alpha", Some(1)));
        app.apply(finding_event(1, "/beta", Some(1)));
        assert_eq!(app.visible_findings().len(), 2);
        app.filter = "alph".to_string();
        assert_eq!(app.visible_findings().len(), 1);
        assert_eq!(app.visible_findings()[0].title, "/alpha");
    }

    #[test]
    fn filter_mode_captures_shortcut_letters_as_text() {
        let mut app = AppState::default();
        app.handle(Action::Char('/'));
        assert_eq!(app.mode, Mode::Filter);
        for c in ['j', 'k', 'q', ' ', 'x'] {
            app.handle(Action::Char(c));
        }
        assert_eq!(app.filter, "jkq x");
        app.handle(Action::Enter);
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(app.filter, "jkq x"); // Enter applies without clearing
    }

    #[test]
    fn filter_esc_clears_and_exits() {
        let mut app = AppState::default();
        app.handle(Action::Char('/'));
        app.handle(Action::Char('a'));
        app.handle(Action::Esc);
        assert_eq!(app.mode, Mode::Normal);
        assert!(app.filter.is_empty());
    }

    #[test]
    fn confirm_flow_produces_pending_execute() {
        let mut app = app_with_gen(1);
        app.apply(finding_with_remedy(1, "/Applications/Old.app"));
        app.handle(Action::Down); // Apps is Tree view: row 0 is the group header
        app.handle(Action::Char(' ')); // mark the only row
        assert_eq!(app.marked_total().0, 1);

        app.handle(Action::Char('x')); // open confirm
        assert_eq!(app.mode, Mode::Confirm);
        assert_eq!(app.confirm_actions.len(), 1);
        assert!(app.confirm_actions[0].rendered.contains("trash"));

        app.handle(Action::Char('y')); // confirm
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(app.marked_total().0, 0); // cleared after queuing
        let actions = app.pending_execute.take().expect("pending_execute set");
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn confirm_cancel_leaves_marks_and_sets_no_pending_execute() {
        let mut app = app_with_gen(1);
        app.apply(finding_with_remedy(1, "/Applications/Old.app"));
        app.handle(Action::Down); // Apps is Tree view: row 0 is the group header
        app.handle(Action::Char(' '));
        app.handle(Action::Char('x'));
        app.handle(Action::Char('n'));
        assert_eq!(app.mode, Mode::Normal);
        assert!(app.pending_execute.is_none());
        assert_eq!(app.marked_total().0, 1); // still marked, nothing executed
    }

    #[test]
    fn tree_expand_collapse_via_left_right() {
        let mut app = app_with_gen(1);
        // Apps (index 0) is a Tree-view section; both findings fall back to
        // the same "app" group since neither sets meta.group.
        app.apply(finding_event(1, "/App1", Some(10)));
        app.apply(finding_event(1, "/App2", Some(20)));
        assert_eq!(app.tree_rows().len(), 3); // 1 group header + 2 items

        app.handle(Action::Left); // cursor is on the group header -> collapse
        assert_eq!(app.tree_rows().len(), 1);

        app.handle(Action::Right); // expand again
        assert_eq!(app.tree_rows().len(), 3);

        app.handle(Action::Enter); // enter also toggles a group header
        assert_eq!(app.tree_rows().len(), 1);
    }

    #[test]
    fn sidebar_status_transitions_scanning_done_failed() {
        let mut app = app_with_gen(1);
        assert_eq!(app.status_of(ScannerId::Apps), SectionStatus::Idle);

        app.apply(ScanEvent::Started {
            scanner: ScannerId::Apps,
            gen: 1,
        });
        assert!(matches!(
            app.status_of(ScannerId::Apps),
            SectionStatus::Scanning { .. }
        ));

        app.apply(ScanEvent::Finished {
            scanner: ScannerId::Apps,
            gen: 1,
            duration: Duration::from_secs(1),
        });
        assert!(matches!(
            app.status_of(ScannerId::Apps),
            SectionStatus::Done { .. }
        ));

        app.apply(ScanEvent::Started {
            scanner: ScannerId::Brew,
            gen: 1,
        });
        app.apply(ScanEvent::Failed {
            scanner: ScannerId::Brew,
            gen: 1,
            error: "boom".into(),
        });
        assert!(matches!(
            app.status_of(ScannerId::Brew),
            SectionStatus::Failed { .. }
        ));
    }

    #[test]
    fn draw_smoke_test_across_modes() {
        let mut app = app_with_gen(1);
        app.apply(finding_with_remedy(1, "/Applications/Old.app"));
        app.show_detail = true;
        app.push_activity("did a thing".into());

        let backend = ratatui::backend::TestBackend::new(100, 40);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();

        terminal.draw(|f| app.draw(f)).unwrap(); // normal, detail pane + activity log

        app.handle(Action::Char('/'));
        terminal.draw(|f| app.draw(f)).unwrap(); // filter input in the statusbar

        app.handle(Action::Esc);
        app.handle(Action::Down); // Apps is Tree view: row 0 is the group header
        app.handle(Action::Char(' '));
        app.handle(Action::Char('x'));
        assert_eq!(app.mode, Mode::Confirm, "confirm dialog should have opened");
        terminal.draw(|f| app.draw(f)).unwrap(); // confirm modal

        app.handle(Action::Char('n')); // cancel back to Normal
        app.handle(Action::Char('?'));
        assert_eq!(app.mode, Mode::Help, "help overlay should have opened");
        terminal.draw(|f| app.draw(f)).unwrap(); // help modal
    }

    #[test]
    fn question_mark_opens_help_and_esc_closes_it() {
        let mut app = AppState::default();
        assert_eq!(app.mode, Mode::Normal);

        app.handle(Action::Char('?'));
        assert_eq!(app.mode, Mode::Help);

        app.handle(Action::Esc);
        assert_eq!(app.mode, Mode::Normal);
    }

    #[test]
    fn help_mode_also_closes_on_q_enter_or_question_mark() {
        for closer in [Action::Char('q'), Action::Enter, Action::Char('?')] {
            let mut app = AppState::default();
            app.handle(Action::Char('?'));
            assert_eq!(app.mode, Mode::Help);
            app.handle(closer);
            assert_eq!(app.mode, Mode::Normal, "{closer:?} should close Help");
        }
    }

    #[test]
    fn help_mode_swallows_shortcut_keys_without_mutating_state() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/a", Some(10)));
        app.apply(finding_event(1, "/b", Some(20)));
        let row_before = app.selected_row;
        let filter_before = app.filter.clone();
        let marked_before = app.marked_total();

        app.handle(Action::Char('?'));
        assert_eq!(app.mode, Mode::Help);

        // Keys that are shortcuts elsewhere must be no-ops while Help is up.
        for action in [
            Action::Char('j'),
            Action::Down,
            Action::Char(' '),
            Action::Char('x'),
            Action::Char('/'),
            Action::Char('s'),
            Action::Char('h'),
            Action::Char('r'),
        ] {
            app.handle(action);
        }

        assert_eq!(
            app.mode,
            Mode::Help,
            "still in Help — nothing should escape it"
        );
        assert_eq!(app.selected_row, row_before, "selection must not move");
        assert_eq!(app.filter, filter_before, "filter must not change");
        assert_eq!(app.marked_total(), marked_before, "marks must not change");
        assert!(app.pending_rescan.is_none(), "no rescan should be queued");
    }

    #[test]
    fn ctrl_c_quits_even_while_help_is_open() {
        let mut app = AppState::default();
        app.handle(Action::Char('?'));
        assert_eq!(app.mode, Mode::Help);
        app.handle(Action::CtrlC);
        assert!(app.should_quit);
    }

    #[test]
    fn page_down_up_scroll_detail_only_when_open() {
        let mut app = AppState::default();
        assert!(!app.show_detail);

        // Detail pane closed: PageDown/PageUp are no-ops.
        app.handle(Action::PageDown);
        assert_eq!(app.detail_scroll, 0);

        app.show_detail = true;
        app.handle(Action::PageDown);
        assert_eq!(app.detail_scroll, 5);
        app.handle(Action::PageDown);
        assert_eq!(app.detail_scroll, 10);
        app.handle(Action::PageUp);
        assert_eq!(app.detail_scroll, 5);

        // Saturates at 0 rather than underflowing.
        app.handle(Action::PageUp);
        app.handle(Action::PageUp);
        assert_eq!(app.detail_scroll, 0);
    }

    #[test]
    fn detail_scroll_resets_on_selection_and_section_change() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/a", Some(10)));
        app.apply(finding_event(1, "/b", Some(20)));
        app.show_detail = true;
        app.detail_scroll = 15;

        app.handle(Action::Down); // moves selection within the section
        assert_eq!(app.detail_scroll, 0, "moving selection resets scroll");

        app.detail_scroll = 15;
        app.handle(Action::Tab); // switches section
        assert_eq!(app.detail_scroll, 0, "switching section resets scroll");

        app.detail_scroll = 15;
        app.handle(Action::Enter); // toggles the detail pane closed
        assert!(!app.show_detail);
        assert_eq!(app.detail_scroll, 0, "toggling detail resets scroll");
    }
}
