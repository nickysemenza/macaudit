//! Per-section presentation: which columns a section's rows have, how each
//! cell is derived from a `Finding`, and which columns sort. One file per
//! scanner so the presentation of a section lives next to nothing else —
//! when `scan/launchd.rs` changes a meta key, `present/launchd.rs` is the
//! only other place to touch.
//!
//! Kept out of `registry.rs` on purpose: the registry is consumed by the
//! engine and CLI, and these types drag in ratatui.

mod apps;
mod brew;
mod disk;
mod docker;
mod git;
mod launchd;
mod ports;
mod runtimes;
mod shell;
mod simulator;
mod ssh_keys;
mod tm_snapshots;

use std::borrow::Cow;
use std::collections::HashSet;
use std::time::SystemTime;

use ratatui::layout::{Alignment, Constraint};
use ratatui::style::{Color, Style};
use serde_json::Value;

use crate::model::{Finding, ScannerId};
use crate::ui::{fmt, theme};

/// Globally unique column identities. Sorting is keyed by these, so a header
/// click on "Size" in one section can't be confused with "Size" in another
/// only because both spell it the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ColumnId {
    Name,
    Path,
    Size,
    Age,
    Version,
    Classification,
    Arch,
    Status,
    Deps,
    Domain,
    Running,
    Program,
    ShadowedBy,
    Manager,
    Runtime,
    Default,
    Count,
    Active,
    Reclaimable,
    Port,
    Pid,
    Command,
    User,
    Host,
    Branch,
    State,
    KeyType,
    Bits,
    Config,
    Date,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortDir {
    Asc,
    Desc,
}

impl SortDir {
    pub fn flip(self) -> SortDir {
        match self {
            SortDir::Asc => SortDir::Desc,
            SortDir::Desc => SortDir::Asc,
        }
    }
    pub fn arrow(self) -> &'static str {
        match self {
            SortDir::Asc => "↑",
            SortDir::Desc => "↓",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortBy {
    Column(ColumnId),
    /// Not a column: severity paints the primary cell instead of taking width.
    Severity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SortSpec {
    pub by: SortBy,
    pub dir: SortDir,
}

impl SortSpec {
    pub const fn col(id: ColumnId, dir: SortDir) -> SortSpec {
        SortSpec {
            by: SortBy::Column(id),
            dir,
        }
    }
}

/// A sortable projection of one cell. Variant order is irrelevant in
/// practice: a column always yields one variant, so comparisons stay within
/// it. `None` sorts last regardless of direction.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SortKey {
    Bytes(u64),
    Int(i64),
    Text(String),
    Time(Option<SystemTime>),
    Bool(bool),
    None,
}

/// Per-draw inputs a cell may need beyond the finding itself.
pub struct CellCtx {
    /// The section is still scanning: a missing size is pending (`…`), not
    /// absent.
    pub is_scanning: bool,
    pub now: SystemTime,
}

pub struct CellText {
    pub text: String,
    pub style: Style,
}

pub type CellFn = fn(&Finding, &CellCtx) -> CellText;
pub type SortKeyFn = fn(&Finding) -> SortKey;

pub struct Column {
    pub id: ColumnId,
    pub header: &'static str,
    pub width: Constraint,
    pub align: Alignment,
    /// Exactly one per section: gets the tree indent, severity color, and
    /// the group label on header rows.
    pub primary: bool,
    /// Long values keep their tail (`…/usda-api/.wrangler`) rather than their
    /// head — right for paths, wrong for names.
    pub middle_ellipsis: bool,
    pub cell: CellFn,
    pub sort_key: Option<SortKeyFn>,
    /// Direction a header click starts with: biggest/newest first for sizes
    /// and times, A→Z for text.
    pub natural: SortDir,
}

impl Column {
    pub const fn new(id: ColumnId, header: &'static str, width: Constraint, cell: CellFn) -> Self {
        Column {
            id,
            header,
            width,
            align: Alignment::Left,
            primary: false,
            middle_ellipsis: false,
            cell,
            sort_key: None,
            natural: SortDir::Asc,
        }
    }
    pub const fn primary(mut self) -> Self {
        self.primary = true;
        self
    }
    pub const fn right(mut self) -> Self {
        self.align = Alignment::Right;
        self
    }
    pub const fn middle(mut self) -> Self {
        self.middle_ellipsis = true;
        self
    }
    pub const fn sortable(mut self, key: SortKeyFn, natural: SortDir) -> Self {
        self.sort_key = Some(key);
        self.natural = natural;
        self
    }
}

/// One line-ish unit of the detail pane.
#[derive(Clone, Debug, PartialEq)]
pub enum Field {
    /// `label: value`.
    Kv {
        label: Cow<'static, str>,
        value: String,
        style: Option<Style>,
    },
    /// Free text, wrapped.
    Text(String),
    /// A remedy: its label, then the literal command that would run.
    Command {
        label: String,
        rendered: String,
        destructive: bool,
    },
    Header(&'static str),
    Blank,
}

pub fn kv(label: impl Into<Cow<'static, str>>, value: impl Into<String>) -> Field {
    Field::Kv {
        label: label.into(),
        value: value.into(),
        style: None,
    }
}

pub fn kv_styled(
    label: impl Into<Cow<'static, str>>,
    value: impl Into<String>,
    color: Color,
) -> Field {
    Field::Kv {
        label: label.into(),
        value: value.into(),
        style: Some(Style::default().fg(color)),
    }
}

/// A finding's `meta` with bookkeeping of which keys a section's detail fn
/// consumed, so the generic fallback can render the rest and a scanner
/// adding a key never disappears silently.
pub struct MetaView<'a> {
    value: &'a Value,
    used: HashSet<&'a str>,
}

impl<'a> MetaView<'a> {
    pub fn new(value: &'a Value) -> Self {
        MetaView {
            value,
            used: HashSet::new(),
        }
    }

    fn take(&mut self, key: &'a str) -> Option<&'a Value> {
        let v = self.value.get(key)?;
        self.used.insert(key);
        Some(v)
    }

    pub fn str(&mut self, key: &'a str) -> Option<&'a str> {
        self.take(key)?.as_str()
    }
    pub fn bool(&mut self, key: &'a str) -> Option<bool> {
        self.take(key)?.as_bool()
    }
    pub fn u64(&mut self, key: &'a str) -> Option<u64> {
        self.take(key)?.as_u64()
    }
    pub fn f64(&mut self, key: &'a str) -> Option<f64> {
        self.take(key)?.as_f64()
    }
    /// A byte count, humanized.
    pub fn bytes(&mut self, key: &'a str) -> Option<String> {
        self.u64(key).map(fmt::bytes)
    }
    /// A string array, as display strings.
    pub fn list(&mut self, key: &'a str) -> Option<Vec<String>> {
        Some(
            self.take(key)?
                .as_array()?
                .iter()
                .map(value_to_string)
                .collect(),
        )
    }
    /// Consume a key without rendering it (already shown elsewhere).
    pub fn skip(&mut self, key: &'a str) {
        self.used.insert(key);
    }
    /// Keys the section's detail fn did not consume, in key order.
    pub fn remaining(&self) -> Vec<(&'a str, &'a Value)> {
        self.value
            .as_object()
            .map(|m| {
                m.iter()
                    .filter(|(k, _)| !self.used.contains(k.as_str()))
                    .map(|(k, v)| (k.as_str(), v))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// `yes`/`no`.
pub fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// A `Kv` if the key is present as a string.
pub fn kv_str(view: &mut MetaView<'_>, key: &'static str, label: &'static str) -> Option<Field> {
    view.str(key).map(|v| kv(label, v))
}

/// A `Kv` if the key is present as a bool.
pub fn kv_bool(view: &mut MetaView<'_>, key: &'static str, label: &'static str) -> Option<Field> {
    view.bool(key).map(|b| kv(label, yes_no(b)))
}

/// A `Kv` if the key is present as an integer.
pub fn kv_u64(view: &mut MetaView<'_>, key: &'static str, label: &'static str) -> Option<Field> {
    view.u64(key).map(|n| kv(label, n.to_string()))
}

/// A `Kv` listing a string array (up to 8, then `+N more`).
pub fn kv_list(view: &mut MetaView<'_>, key: &'static str, label: &'static str) -> Option<Field> {
    let items = view.list(key)?;
    if items.is_empty() {
        return None;
    }
    Some(kv(label, join_limited(&items)))
}

fn join_limited(items: &[String]) -> String {
    const MAX: usize = 8;
    if items.len() <= MAX {
        items.join(", ")
    } else {
        format!("{} +{} more", items[..MAX].join(", "), items.len() - MAX)
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "—".to_string(),
        other => other.to_string(),
    }
}

/// Render leftover meta keys generically: `snake_case` → "Snake case", and
/// values formatted by what the key name says they are.
pub fn generic_fields(remaining: &[(&str, &Value)]) -> Vec<Field> {
    remaining
        .iter()
        .map(|(key, value)| {
            let label = prettify_key(key);
            let text = match value {
                Value::Null => "—".to_string(),
                Value::Bool(b) => yes_no(*b).to_string(),
                Value::Number(n) => {
                    if let Some(b) = n.as_u64().filter(|_| key.ends_with("_bytes")) {
                        fmt::bytes(b)
                    } else if let Some(ms) = n.as_f64().filter(|_| key.ends_with("_ms")) {
                        format!("{ms:.0} ms")
                    } else if let Some(d) = n.as_u64().filter(|_| key.ends_with("_days")) {
                        format!("{d} days")
                    } else if let Some(p) = n.as_f64().filter(|_| key.ends_with("_percent")) {
                        format!("{p:.0}%")
                    } else {
                        n.to_string()
                    }
                }
                Value::String(s) => s.clone(),
                Value::Array(a) => {
                    let items: Vec<String> = a.iter().map(value_to_string).collect();
                    join_limited(&items)
                }
                Value::Object(_) => value.to_string(),
            };
            kv(label, text)
        })
        .collect()
}

fn prettify_key(key: &str) -> String {
    let mut out = key.replace('_', " ");
    if let Some(first) = out.get(..1) {
        let upper = first.to_uppercase();
        out.replace_range(..1, &upper);
    }
    out
}

/// Section-specific detail rows for a finding's meta. Whatever the fn does
/// not consume is appended generically, so these only need to handle keys
/// that deserve a better label or format than the fallback gives.
pub type DetailFn = fn(&Finding, &mut MetaView<'_>) -> Vec<Field>;

fn no_detail(_: &Finding, _: &mut MetaView<'_>) -> Vec<Field> {
    Vec::new()
}

pub struct SectionPresenter {
    pub columns: &'static [Column],
    pub default_sort: SortSpec,
    pub detail: DetailFn,
}

impl SectionPresenter {
    pub fn column(&self, id: ColumnId) -> Option<&'static Column> {
        self.columns.iter().find(|c| c.id == id)
    }
    /// Sortable columns in display order — the `s` key cycles through these,
    /// then Severity, then back to the default.
    pub fn sortable(&self) -> impl Iterator<Item = &'static Column> {
        self.columns.iter().filter(|c| c.sort_key.is_some())
    }
    /// The next sort after `current` in the `s` cycle.
    pub fn next_sort(&self, current: SortSpec) -> SortSpec {
        let mut cycle: Vec<SortSpec> = vec![self.default_sort];
        cycle.extend(
            self.sortable()
                .map(|c| SortSpec::col(c.id, c.natural))
                .filter(|s| *s != self.default_sort),
        );
        cycle.push(SortSpec {
            by: SortBy::Severity,
            dir: SortDir::Desc,
        });
        let pos = cycle
            .iter()
            .position(|s| s.by == current.by)
            .map(|i| (i + 1) % cycle.len())
            .unwrap_or(0);
        cycle[pos]
    }
    /// What a click on column `id`'s header does to `current`.
    pub fn click_sort(&self, current: SortSpec, id: ColumnId) -> SortSpec {
        let Some(col) = self.column(id) else {
            return current;
        };
        if col.sort_key.is_none() {
            return current;
        }
        if current.by == SortBy::Column(id) {
            SortSpec {
                by: current.by,
                dir: current.dir.flip(),
            }
        } else {
            SortSpec::col(id, col.natural)
        }
    }
    /// Header label for a sort, e.g. `Size↓`.
    pub fn sort_label(&self, sort: SortSpec) -> String {
        let name = match sort.by {
            SortBy::Column(id) => self.column(id).map(|c| c.header).unwrap_or("?"),
            SortBy::Severity => "severity",
        };
        format!("{name}{}", sort.dir.arrow())
    }
}

/// Sections with no row presentation (the Overview).
static NONE: SectionPresenter = SectionPresenter {
    columns: &[],
    default_sort: SortSpec::col(ColumnId::Name, SortDir::Asc),
    detail: no_detail,
};

pub fn presenter(id: ScannerId) -> &'static SectionPresenter {
    match id {
        ScannerId::System => &NONE,
        ScannerId::Apps => &apps::PRESENTER,
        ScannerId::Brew => &brew::PRESENTER,
        ScannerId::Fs => &disk::PRESENTER,
        ScannerId::Launchd => &launchd::PRESENTER,
        ScannerId::ShellEnv => &shell::PRESENTER,
        ScannerId::Runtimes => &runtimes::PRESENTER,
        ScannerId::Docker => &docker::PRESENTER,
        ScannerId::Ports => &ports::PRESENTER,
        ScannerId::Git => &git::PRESENTER,
        ScannerId::Simulator => &simulator::PRESENTER,
        ScannerId::SshKeys => &ssh_keys::PRESENTER,
        ScannerId::TmSnapshots => &tm_snapshots::PRESENTER,
    }
}

// ---- shared cell/key helpers for the per-section files ----

pub(super) fn plain(text: impl Into<String>) -> CellText {
    CellText {
        text: text.into(),
        style: Style::default(),
    }
}

pub(super) fn dim(text: impl Into<String>) -> CellText {
    CellText {
        text: text.into(),
        style: Style::default().fg(Color::DarkGray),
    }
}

pub(super) fn colored(text: impl Into<String>, color: Color) -> CellText {
    CellText {
        text: text.into(),
        style: Style::default().fg(color),
    }
}

pub(super) fn meta_str<'a>(f: &'a Finding, key: &str) -> Option<&'a str> {
    f.meta.get(key).and_then(|v| v.as_str())
}

pub(super) fn meta_bool(f: &Finding, key: &str) -> Option<bool> {
    f.meta.get(key).and_then(|v| v.as_bool())
}

pub(super) fn meta_u64(f: &Finding, key: &str) -> Option<u64> {
    f.meta.get(key).and_then(|v| v.as_u64())
}

pub(super) fn meta_f64(f: &Finding, key: &str) -> Option<f64> {
    f.meta.get(key).and_then(|v| v.as_f64())
}

/// Length of a meta array, or 0.
pub(super) fn meta_len(f: &Finding, key: &str) -> usize {
    f.meta
        .get(key)
        .and_then(|v| v.as_array())
        .map_or(0, |a| a.len())
}

// Standard cells.

/// The finding's title, colored by severity — the usual primary cell.
pub(super) fn name_cell(f: &Finding, _: &CellCtx) -> CellText {
    colored(f.title.clone(), theme::severity_color(f.severity))
}

pub(super) fn path_cell(f: &Finding, _: &CellCtx) -> CellText {
    dim(f.path.as_deref().map(fmt::abbrev_home).unwrap_or_default())
}

pub(super) fn size_cell(f: &Finding, ctx: &CellCtx) -> CellText {
    plain(fmt::bytes_opt(f.size_bytes, ctx.is_scanning))
}

/// How long since `last_used`, compact (`3d ago`).
pub(super) fn age_cell(f: &Finding, ctx: &CellCtx) -> CellText {
    dim(f
        .last_used
        .map(|t| fmt::humanize_ago(t, ctx.now))
        .unwrap_or_default())
}

/// A ✓ when the flag is set, else blank.
pub(super) fn check(flag: bool) -> CellText {
    if flag {
        colored("✓", Color::Green)
    } else {
        plain("")
    }
}

// Standard sort keys.

pub(super) fn key_title(f: &Finding) -> SortKey {
    SortKey::Text(f.title.to_lowercase())
}

pub(super) fn key_size(f: &Finding) -> SortKey {
    SortKey::Bytes(f.size_bytes.unwrap_or(0))
}

pub(super) fn key_age(f: &Finding) -> SortKey {
    // Newest first under Desc; never-used sinks to the end either way.
    match f.last_used {
        Some(t) => SortKey::Time(Some(t)),
        None => SortKey::None,
    }
}

pub(super) fn key_path(f: &Finding) -> SortKey {
    match &f.path {
        Some(p) => SortKey::Text(p.display().to_string().to_lowercase()),
        None => SortKey::None,
    }
}

/// Text key over a meta string field.
pub(super) fn key_meta_text(f: &Finding, key: &str) -> SortKey {
    match meta_str(f, key) {
        Some(s) => SortKey::Text(s.to_lowercase()),
        None => SortKey::None,
    }
}

pub(super) fn key_meta_int(f: &Finding, key: &str) -> SortKey {
    match f.meta.get(key).and_then(|v| v.as_i64()) {
        Some(n) => SortKey::Int(n),
        None => SortKey::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_fields_format_by_key_suffix_and_track_consumption() {
        let meta = serde_json::json!({
            "rss_bytes": 1048576u64,
            "median_ms": 1450.4,
            "age_days": 12,
            "cpu_percent": 33.3,
            "dirty": true,
            "deps": ["a", "b"],
            "label": "x"
        });
        let mut view = MetaView::new(&meta);
        assert_eq!(view.str("label"), Some("x"));
        let rest = generic_fields(&view.remaining());
        let texts: Vec<String> = rest
            .iter()
            .map(|f| match f {
                Field::Kv { label, value, .. } => format!("{label}={value}"),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(
            texts,
            [
                "Age days=12 days",
                "Cpu percent=33%",
                "Deps=a, b",
                "Dirty=yes",
                "Median ms=1450 ms",
                "Rss bytes=1 MiB",
            ]
        );
    }

    #[test]
    fn every_section_has_exactly_one_primary_and_unique_column_ids() {
        for id in ScannerId::ALL {
            let p = presenter(*id);
            if p.columns.is_empty() {
                continue; // Overview
            }
            let primaries = p.columns.iter().filter(|c| c.primary).count();
            assert_eq!(primaries, 1, "{id:?} should have one primary column");
            let ids: HashSet<ColumnId> = p.columns.iter().map(|c| c.id).collect();
            assert_eq!(
                ids.len(),
                p.columns.len(),
                "{id:?} has duplicate column ids"
            );
            // The default sort must be something the section can actually sort by.
            if let SortBy::Column(c) = p.default_sort.by {
                assert!(
                    p.column(c).and_then(|c| c.sort_key).is_some(),
                    "{id:?} default sort column {c:?} is not sortable"
                );
            }
        }
    }

    #[test]
    fn s_cycle_visits_every_sortable_column_then_severity_then_wraps() {
        let p = presenter(ScannerId::Git);
        let sortable = p.sortable().count();
        let mut seen = vec![p.default_sort];
        let mut cur = p.default_sort;
        for _ in 0..sortable + 1 {
            cur = p.next_sort(cur);
            seen.push(cur);
        }
        assert_eq!(cur, p.default_sort, "cycle wraps to the default");
        assert!(seen.iter().any(|s| s.by == SortBy::Severity));
        assert_eq!(seen.len() - 1, sortable + 1, "each stop visited once");
    }

    #[test]
    fn header_click_sets_natural_direction_then_flips() {
        let p = presenter(ScannerId::Git);
        let s1 = p.click_sort(p.default_sort, ColumnId::Branch);
        assert_eq!(s1, SortSpec::col(ColumnId::Branch, SortDir::Asc));
        let s2 = p.click_sort(s1, ColumnId::Branch);
        assert_eq!(s2, SortSpec::col(ColumnId::Branch, SortDir::Desc));
        // Unsortable / unknown columns leave the sort alone.
        assert_eq!(p.click_sort(s2, ColumnId::Port), s2);
    }
}
