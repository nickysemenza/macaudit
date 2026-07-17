//! `AppState` and its reducer. The reducer is deliberately pure (no I/O) and
//! independent of the event loop so it can be unit-tested directly. Lane U
//! extends the rendering (tree view, detail pane, confirm dialog, activity log);
//! the skeleton renders a sidebar + a sortable table + a bottom bar.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, Row, Table, TableState};
use ratatui::Frame;

use crate::model::{Finding, FindingId, ScanEvent, ScannerId, Severity};
use crate::registry;
use crate::ui::keys::Action;
use crate::ui::theme;

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

    /// The generation whose events we accept; stale events are dropped.
    pub current_gen: u64,
    pub tick: usize,
    pub should_quit: bool,
    /// Set when the user requests a rescan; the loop consumes and clears it.
    pub pending_rescan: Option<RescanRequest>,
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
            current_gen: 0,
            tick: 0,
            should_quit: false,
            pending_rescan: None,
        }
    }
}

impl AppState {
    pub fn selected_section_id(&self) -> ScannerId {
        ScannerId::ALL[self.selected_section]
    }

    /// Apply a scan event. Drops events from stale generations. This is the sole
    /// mutation path for findings; upsert-by-id keeps sizes/dedup correct.
    pub fn apply(&mut self, ev: ScanEvent) {
        if ev.generation() != self.current_gen {
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

    /// Reset section statuses to Scanning-pending for a fresh generation.
    pub fn begin_scan(&mut self, gen: u64, sections: &[ScannerId]) {
        self.current_gen = gen;
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

    /// Findings for the selected section, ordered by the current sort, with
    /// System apps optionally hidden.
    fn visible_rows(&self) -> Vec<&Finding> {
        let id = self.selected_section_id();
        let Some(map) = self.findings.get(&id) else {
            return Vec::new();
        };
        let mut rows: Vec<&Finding> = map
            .values()
            .filter(|f| self.show_system || !is_system_app(f))
            .collect();
        match self.sort {
            Sort::SizeDesc => {
                rows.sort_by(|a, b| b.size_bytes.unwrap_or(0).cmp(&a.size_bytes.unwrap_or(0)))
            }
            Sort::Title => rows.sort_by(|a, b| a.title.cmp(&b.title)),
            Sort::Severity => rows.sort_by(|a, b| b.severity.cmp(&a.severity)),
        }
        rows
    }

    /// Handle a semantic action. Returns nothing; the loop reads `should_quit`
    /// and `pending_rescan` afterward.
    pub fn handle(&mut self, action: Action) {
        match action {
            Action::Quit => self.should_quit = true,
            Action::Down => {
                let n = self.visible_rows().len();
                if n > 0 {
                    self.selected_row = (self.selected_row + 1).min(n - 1);
                }
            }
            Action::Up => {
                self.selected_row = self.selected_row.saturating_sub(1);
            }
            Action::NextSection => {
                self.selected_section = (self.selected_section + 1) % ScannerId::ALL.len();
                self.selected_row = 0;
            }
            Action::PrevSection => {
                self.selected_section =
                    (self.selected_section + ScannerId::ALL.len() - 1) % ScannerId::ALL.len();
                self.selected_row = 0;
            }
            Action::Mark => {
                if let Some(f) = self.visible_rows().get(self.selected_row) {
                    let id = f.id;
                    if !self.marked.insert(id) {
                        self.marked.remove(&id);
                    }
                }
            }
            Action::Detail => self.show_detail = !self.show_detail,
            Action::ToggleSystem => self.show_system = !self.show_system,
            Action::CycleSort => self.sort = self.sort.next(),
            Action::RescanSection => {
                self.pending_rescan = Some(RescanRequest::Section(self.selected_section_id()));
            }
            Action::RescanAll => self.pending_rescan = Some(RescanRequest::All),
            // Filter and Execute are wired by lane U / Phase 2.
            Action::Filter | Action::Execute => {}
        }
    }

    fn section_count(&self, id: ScannerId) -> usize {
        self.findings.get(&id).map(|m| m.len()).unwrap_or(0)
    }

    fn section_reclaimable(&self, id: ScannerId) -> u64 {
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

    fn marked_total(&self) -> (usize, u64) {
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

    /// Render the whole UI.
    pub fn draw(&self, frame: &mut Frame) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(24), Constraint::Min(20)])
            .split(frame.area());

        self.draw_sidebar(frame, cols[0]);

        let main = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(1)])
            .split(cols[1]);

        if self.show_detail {
            let split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(main[0]);
            self.draw_table(frame, split[0]);
            self.draw_detail(frame, split[1]);
        } else {
            self.draw_table(frame, main[0]);
        }
        self.draw_statusbar(frame, main[1]);
    }

    fn draw_sidebar(&self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = registry::REGISTRY
            .iter()
            .enumerate()
            .map(|(i, meta)| {
                let status = self
                    .status
                    .get(&meta.id)
                    .cloned()
                    .unwrap_or(SectionStatus::Idle);
                let glyph = match &status {
                    SectionStatus::Idle => " ".to_string(),
                    SectionStatus::Scanning { .. } => theme::spinner(self.tick).to_string(),
                    SectionStatus::Done { .. } => "✓".to_string(),
                    SectionStatus::Failed { .. } => "⚠".to_string(),
                };
                let count = self.section_count(meta.id);
                let reclaim = self.section_reclaimable(meta.id);
                let suffix = if matches!(status, SectionStatus::Done { .. }) && count > 0 {
                    if reclaim > 0 {
                        format!(
                            "{count} · {}",
                            humansize::format_size(reclaim, humansize::BINARY)
                        )
                    } else {
                        format!("{count}")
                    }
                } else {
                    String::new()
                };
                let selected = i == self.selected_section;
                let style = if selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(vec![
                    Span::raw(format!("{glyph} ")),
                    Span::raw(format!("{:<10}", meta.title)),
                    Span::styled(suffix, Style::default().fg(Color::DarkGray)),
                ]))
                .style(style)
            })
            .collect();
        let list =
            List::new(items).block(Block::default().borders(Borders::ALL).title(" macaudit "));
        frame.render_widget(list, area);
    }

    fn draw_table(&self, frame: &mut Frame, area: Rect) {
        let id = self.selected_section_id();
        let title = format!(" {} ", registry::section(id).title);
        let rows = self.visible_rows();
        let table_rows: Vec<Row> = rows
            .iter()
            .map(|f| {
                let mark = if self.marked.contains(&f.id) {
                    "●"
                } else {
                    " "
                };
                let size = f
                    .size_bytes
                    .map(|b| humansize::format_size(b, humansize::BINARY))
                    .unwrap_or_else(|| "…".to_string());
                Row::new(vec![
                    Cell::from(mark),
                    Cell::from(f.title.clone()),
                    Cell::from(size),
                    Cell::from(Span::styled(
                        severity_label(f.severity),
                        Style::default().fg(theme::severity_color(f.severity)),
                    )),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(2),
            Constraint::Min(20),
            Constraint::Length(12),
            Constraint::Length(12),
        ];
        let table = Table::new(table_rows, widths)
            .header(
                Row::new(vec!["", "Name", "Size", "Severity"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .block(Block::default().borders(Borders::ALL).title(title))
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        let mut ts = TableState::default();
        if !rows.is_empty() {
            ts.select(Some(self.selected_row.min(rows.len() - 1)));
        }
        frame.render_stateful_widget(table, area, &mut ts);
    }

    fn draw_detail(&self, frame: &mut Frame, area: Rect) {
        let rows = self.visible_rows();
        let block = Block::default().borders(Borders::ALL).title(" Detail ");
        let text: Vec<Line> = match rows.get(self.selected_row) {
            None => vec![Line::from("No selection")],
            Some(f) => {
                let mut lines = vec![
                    Line::from(Span::styled(
                        f.title.clone(),
                        Style::default().add_modifier(Modifier::BOLD),
                    )),
                    Line::from(f.detail.clone()),
                ];
                if let Some(p) = &f.path {
                    lines.push(Line::from(format!("path: {}", p.display())));
                }
                if let Some(b) = f.size_bytes {
                    lines.push(Line::from(format!(
                        "size: {}",
                        humansize::format_size(b, humansize::BINARY)
                    )));
                }
                if !f.remedies.is_empty() {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "Remedies:",
                        Style::default().add_modifier(Modifier::BOLD),
                    )));
                    for r in &f.remedies {
                        let color = if r.destructive {
                            Color::Red
                        } else {
                            Color::Green
                        };
                        lines.push(Line::from(vec![
                            Span::raw(format!("  {} — ", r.label)),
                            Span::styled(r.command.rendered(), Style::default().fg(color)),
                        ]));
                    }
                }
                lines
            }
        };
        frame.render_widget(ratatui::widgets::Paragraph::new(text).block(block), area);
    }

    fn draw_statusbar(&self, frame: &mut Frame, area: Rect) {
        let (n, bytes) = self.marked_total();
        let left = format!(
            " jk:nav  tab:section  space:mark  enter:detail  x:exec  r/R:rescan  s:sort({})  h:sys  q:quit",
            self.sort.label()
        );
        let right = format!(
            "Selected: {n} items · {} ",
            humansize::format_size(bytes, humansize::BINARY)
        );
        let bar = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(10), Constraint::Length(right.len() as u16)])
            .split(area);
        frame.render_widget(
            ratatui::widgets::Paragraph::new(left)
                .style(Style::default().bg(Color::DarkGray).fg(Color::White)),
            bar[0],
        );
        frame.render_widget(
            ratatui::widgets::Paragraph::new(right)
                .style(Style::default().bg(Color::DarkGray).fg(Color::White)),
            bar[1],
        );
    }
}

fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "info",
        Severity::Attention => "attention",
        Severity::Reclaimable => "reclaim",
        Severity::Warning => "warning",
    }
}

/// Whether a finding is a System app (hidden unless `h` toggled). Heuristic on
/// path; the real classification lives in AppsScanner's meta.
fn is_system_app(f: &Finding) -> bool {
    f.path
        .as_ref()
        .map(|p| p.starts_with("/System/"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FindingKind;

    fn finding_event(gen: u64, id_key: &str, size: Option<u64>) -> ScanEvent {
        let mut f = Finding::new(FindingKind::App, id_key, id_key);
        f.size_bytes = size;
        ScanEvent::Finding {
            scanner: ScannerId::Apps,
            gen,
            finding: Box::new(f),
        }
    }

    #[test]
    fn upsert_dedups_by_id() {
        let mut app = AppState::default();
        app.current_gen = 1;
        app.apply(finding_event(1, "/a", None));
        app.apply(finding_event(1, "/a", Some(999))); // same id, now sized
        let map = app.findings.get(&ScannerId::Apps).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.values().next().unwrap().size_bytes, Some(999));
    }

    #[test]
    fn stale_generation_dropped() {
        let mut app = AppState::default();
        app.current_gen = 2;
        app.apply(finding_event(1, "/old", Some(1))); // stale gen
        assert_eq!(app.section_count(ScannerId::Apps), 0);
    }

    #[test]
    fn marking_toggles() {
        let mut app = AppState::default();
        app.current_gen = 1;
        app.apply(finding_event(1, "/a", Some(10)));
        app.handle(Action::Mark);
        assert_eq!(app.marked_total().0, 1);
        app.handle(Action::Mark);
        assert_eq!(app.marked_total().0, 0);
    }

    #[test]
    fn rescan_section_requested() {
        let mut app = AppState::default();
        app.handle(Action::RescanAll);
        assert_eq!(app.pending_rescan, Some(RescanRequest::All));
    }
}
