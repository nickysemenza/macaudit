//! Per-section presentation: which columns a section's rows have, how each
//! cell is derived from a `Finding`, and which columns sort. One file per
//! scanner so the presentation of a section lives next to nothing else —
//! when `scan/launchd.rs` changes a meta key, `present/launchd.rs` is the
//! only other place to touch.
//!
//! Kept out of `registry.rs` on purpose: the registry is consumed by the
//! engine and CLI, and these types drag in ratatui.

mod app_storage;
mod apps;
mod brew;
mod disk;
mod docker;
mod git;
mod ios;
mod launchd;
mod ports;
mod projects;
mod runtimes;
mod shell;
mod simulator;
mod ssh_keys;
mod time_machine;
mod tools;

use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

use ratatui::layout::{Alignment, Constraint};
use ratatui::style::{Color, Style};
use serde_json::Value;

// `Axis` crosses into `present::projects`/`present::app_storage` (both call
// `attribution_detail(f, m, Axis::…)`), so it's re-exported via `pub(super)
// use` — a plain `use` here would stay private to this module and not reach
// children through their `use super::*;`. `FootprintEntry`/`FootprintSet`/
// `ProcKind` are only named inside this file's own detail-building code.
pub(super) use crate::attribution::model::Axis;
use crate::attribution::model::{FootprintEntry, FootprintSet, ProcKind};
use crate::model::{Finding, FindingKind, ScannerId};
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
    /// iOS app bundle size.
    AppBytes,
    /// iOS app data (documents, caches, downloads) size.
    DataBytes,
    /// Projects/App Storage: this owner's 1/N slice of multi-owner entries.
    Shared,
    /// Projects/App Storage: everything this owner touches, shared and
    /// baseline included.
    Reach,
    /// Projects: linked worktree count.
    Worktrees,
    /// Projects: live processes whose cwd is inside the project.
    Procs,
    /// Projects: listening ports joined to a process inside the project.
    Ports,
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

/// Per-draw context a section's detail fn may need beyond the finding and
/// its meta. Today that's only the attribution axes' full `FootprintSet`s
/// (`meta` deliberately stays summary-only — see the struct's field doc) —
/// every other section's detail fn ignores it. Threaded from `AppState` at
/// the single call site (`ui/detail.rs::build_with_choice`, called from
/// `app.rs` where `self.footprints` is in hand) rather than looked up via a
/// thread-local, so the data a detail fn renders is exactly what was in
/// scope when it was called.
pub struct DetailCtx<'a> {
    /// The latest `FootprintSet` per attribution axis — the source for the
    /// Projects/App Storage detail pane's "Top entries", "Processes", and
    /// the bucket rows' "Baseline"/"Unattributed" entry lists, none of which
    /// fit in `meta` without blowing up the FFI's `meta_json` (see the
    /// attribution plan §4).
    pub footprints: &'a BTreeMap<Axis, Arc<FootprintSet>>,
}

/// Section-specific detail rows for a finding's meta. Whatever the fn does
/// not consume is appended generically, so these only need to handle keys
/// that deserve a better label or format than the fallback gives.
pub type DetailFn = fn(&Finding, &mut MetaView<'_>, &DetailCtx) -> Vec<Field>;

fn no_detail(_: &Finding, _: &mut MetaView<'_>, _: &DetailCtx) -> Vec<Field> {
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
        ScannerId::Projects => &projects::PRESENTER,
        ScannerId::AppStorage => &app_storage::PRESENTER,
        ScannerId::Launchd => &launchd::PRESENTER,
        ScannerId::ShellEnv => &shell::PRESENTER,
        ScannerId::Runtimes => &runtimes::PRESENTER,
        ScannerId::Docker => &docker::PRESENTER,
        ScannerId::Ports => &ports::PRESENTER,
        ScannerId::Git => &git::PRESENTER,
        ScannerId::Simulator => &simulator::PRESENTER,
        ScannerId::Ios => &ios::PRESENTER,
        ScannerId::SshKeys => &ssh_keys::PRESENTER,
        ScannerId::TimeMachine => &time_machine::PRESENTER,
        ScannerId::Tools => &tools::PRESENTER,
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
    f.meta_str(key)
}

pub(super) fn meta_bool(f: &Finding, key: &str) -> Option<bool> {
    f.meta.get(key).and_then(|v| v.as_bool())
}

pub(super) fn meta_u64(f: &Finding, key: &str) -> Option<u64> {
    f.meta_u64(key)
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

/// A byte-valued meta field as a sort key (`None` when the field is absent,
/// e.g. a bucket row that has no `exclusive`/`shared`/`reach`).
pub(super) fn key_meta_bytes(f: &Finding, key: &str) -> SortKey {
    match meta_u64(f, key) {
        Some(b) => SortKey::Bytes(b),
        None => SortKey::None,
    }
}

/// The length of a meta array field as a sort key (`None`, not `0`, when the
/// field itself is absent — so rows without the concept at all sort behind
/// rows that have zero of it).
pub(super) fn key_meta_array_len(f: &Finding, key: &str) -> SortKey {
    match f.meta.get(key).and_then(|v| v.as_array()) {
        Some(a) => SortKey::Int(a.len() as i64),
        None => SortKey::None,
    }
}

/// A count cell: blank at zero, dim otherwise — used for the small integer
/// columns (worktrees, processes, ports) that would otherwise clutter a
/// table of mostly-zero rows.
pub(super) fn count_cell(n: usize) -> CellText {
    if n == 0 {
        plain("")
    } else {
        dim(n.to_string())
    }
}

// ---- Projects / App Storage: shared presentation ----
//
// The two attribution axes (`present::projects`, `present::app_storage`)
// share their Excl/Shared/Reach columns, the dim treatment of the three
// synthetic bucket rows (Baseline/Unattributed/Coverage — sorted to the
// bottom of every column, not just the default one), and the whole detail
// pane layout. Kept here instead of duplicated in both files.
//
// The detail pane's "Top entries", "Processes", and the bucket rows'
// "Baseline"/"Unattributed" entry lists need the full `Footprint`/
// `FootprintSet` (`meta` deliberately stays summary-only, see `DetailCtx`'s
// doc) — supplied via `DetailCtx`, threaded through from `AppState.
// footprints` at the single `DetailFn` call site.

/// A one-line footprint bar: `▮` cells for exclusive, `▯` for shared, `·`
/// for baseline share. The bar's length is this owner's `reach` scaled
/// against `max_reach` (the largest reach in the section), so bars are
/// comparable at a glance; `width` is the length the largest owner's bar
/// would reach. Never panics on `max_reach == 0` or an all-zero owner —
/// both just render an empty bar.
pub(super) fn bar(
    exclusive: u64,
    shared: u64,
    baseline_share: u64,
    max_reach: u64,
    width: usize,
) -> String {
    if width == 0 || max_reach == 0 {
        return String::new();
    }
    let reach = exclusive
        .saturating_add(shared)
        .saturating_add(baseline_share);
    if reach == 0 {
        return String::new();
    }
    let filled = ((reach as f64 / max_reach as f64) * width as f64).round() as usize;
    let filled = filled.clamp(1, width);

    // Cumulative rounding: each boundary is the running total's share of
    // `filled`, rounded independently, so the bar's visible length always
    // matches `filled` exactly (the last boundary is `filled` itself) —
    // no separate remainder-distribution pass needed.
    let total = reach as f64;
    let b1 = (((exclusive as f64) / total) * filled as f64).round() as usize;
    let b1 = b1.min(filled);
    let b2 = ((((exclusive + shared) as f64) / total) * filled as f64).round() as usize;
    let b2 = b2.clamp(b1, filled);
    let b3 = filled;

    let mut s = String::with_capacity(filled);
    for _ in 0..b1 {
        s.push('▮');
    }
    for _ in b1..b2 {
        s.push('▯');
    }
    for _ in b2..b3 {
        s.push('·');
    }
    s
}

/// The three synthetic bucket rows both attribution axes emit
/// (`FindingKind::ProjectBucket` / `AppStorageBucket`): Baseline,
/// Unattributed, Coverage. Rendered dim in the Name column and sorted to
/// the bottom under every sortable column, not just the default one.
pub(super) fn is_attribution_bucket(f: &Finding) -> bool {
    matches!(
        f.kind,
        FindingKind::ProjectBucket | FindingKind::AppStorageBucket
    )
}

pub(super) fn bucket_aware_name_cell(f: &Finding, ctx: &CellCtx) -> CellText {
    if is_attribution_bucket(f) {
        dim(f.title.clone())
    } else {
        name_cell(f, ctx)
    }
}

pub(super) fn key_name_bucket_last(f: &Finding) -> SortKey {
    if is_attribution_bucket(f) {
        SortKey::None
    } else {
        key_title(f)
    }
}

fn meta_bytes_cell(f: &Finding, key: &str, ctx: &CellCtx) -> CellText {
    plain(fmt::bytes_opt(meta_u64(f, key), ctx.is_scanning))
}
pub(super) fn excl_cell(f: &Finding, ctx: &CellCtx) -> CellText {
    meta_bytes_cell(f, "exclusive", ctx)
}
pub(super) fn shared_cell(f: &Finding, ctx: &CellCtx) -> CellText {
    meta_bytes_cell(f, "shared", ctx)
}
pub(super) fn reach_cell(f: &Finding, ctx: &CellCtx) -> CellText {
    meta_bytes_cell(f, "reach", ctx)
}
pub(super) fn key_excl(f: &Finding) -> SortKey {
    key_meta_bytes(f, "exclusive")
}
pub(super) fn key_shared(f: &Finding) -> SortKey {
    key_meta_bytes(f, "shared")
}
pub(super) fn key_reach(f: &Finding) -> SortKey {
    key_meta_bytes(f, "reach")
}

const CLONE_NOTE: &str = "node_modules is an APFS clone of the pnpm store — those bytes are \
     shared with the store, not freed by deleting node_modules.";

fn proc_kind_label(kind: ProcKind) -> &'static str {
    match kind {
        ProcKind::Shell => "shell",
        ProcKind::Server => "server",
        ProcKind::Other => "other",
    }
}

/// One `FootprintEntry` as detail-pane fields: `bytes  tier  label [badges]`
/// then, on a second dim line, the evidence that linked it.
fn entry_fields(e: &FootprintEntry) -> Vec<Field> {
    let mut badges = Vec::new();
    if e.stale {
        badges.push("stale");
    }
    if e.clone_of_store {
        badges.push("clone");
    }
    if e.virtual_bytes {
        badges.push("virtual");
    }
    if e.r#unsized {
        badges.push("unsized");
    }
    let suffix = if badges.is_empty() {
        String::new()
    } else {
        format!(" [{}]", badges.join(" "))
    };
    let mut fields = vec![kv(
        format!("{}  {}", fmt::bytes(e.bytes), e.tier.label()),
        format!("{}{suffix}", e.label),
    )];
    if !e.evidence.is_empty() {
        fields.push(kv_styled("  ↳", e.evidence.clone(), Color::DarkGray));
    }
    fields
}

/// Shared detail body for the Projects and App Storage presenters — the
/// four numbers, the bar, the by-kind breakdown, top entries, worktrees/
/// processes/ports and the APFS-clone note for an owner row; coverage/
/// baseline/unattributed for the three bucket rows.
pub(super) fn attribution_detail(
    f: &Finding,
    m: &mut MetaView<'_>,
    axis: Axis,
    ctx: &DetailCtx,
) -> Vec<Field> {
    if is_attribution_bucket(f) {
        attribution_bucket_detail(f, m, axis, ctx)
    } else {
        attribution_owner_detail(f, m, axis, ctx)
    }
}

fn attribution_owner_detail(
    f: &Finding,
    m: &mut MetaView<'_>,
    axis: Axis,
    ctx: &DetailCtx,
) -> Vec<Field> {
    let mut out = Vec::new();
    let exclusive = m.u64("exclusive").unwrap_or(0);
    let shared = m.u64("shared").unwrap_or(0);
    let reach = m.u64("reach").unwrap_or(0);
    let baseline_share = m.u64("baseline_share").unwrap_or(0);
    out.push(kv(
        "Exclusive",
        format!("{} — only this owner touches it", fmt::bytes(exclusive)),
    ));
    out.push(kv(
        "Shared",
        format!(
            "{} — this owner's slice of paths more than one owner touches",
            fmt::bytes(shared)
        ),
    ));
    out.push(kv(
        "Reach",
        format!(
            "{} — everything this owner touches, shared and baseline included",
            fmt::bytes(reach)
        ),
    ));
    out.push(kv(
        "Baseline share",
        format!(
            "{} — this owner's slice of ecosystem-wide resources",
            fmt::bytes(baseline_share)
        ),
    ));
    out.extend(kv_str(m, "top_tier", "Best evidence"));

    let set = ctx.footprints.get(&axis);
    if let Some(set) = set {
        let max_reach = set
            .footprints
            .iter()
            .map(|fp| fp.reach)
            .max()
            .unwrap_or(0)
            .max(1);
        let bar = bar(exclusive, shared, baseline_share, max_reach, 40);
        if !bar.is_empty() {
            out.push(Field::Text(bar));
        }
    }

    if let Some(by_kind) = f.meta.get("by_kind").and_then(|v| v.as_array()) {
        if !by_kind.is_empty() {
            out.push(Field::Blank);
            out.push(Field::Header("By kind"));
            for row in by_kind {
                let kind = row.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
                let bytes = row.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                out.push(kv(kind.to_string(), fmt::bytes(bytes)));
            }
        }
    }
    m.skip("by_kind");

    // The `Footprints` event for this axis arrives in the same generation as
    // its findings, so by the time an owner row exists to select, `ctx.
    // footprints` already holds its `FootprintSet` — `fp` is always `Some`
    // in practice. The worktrees/process_count/ports/clone_note meta keys
    // stay on the Finding only so the table's own cells (which never see
    // `DetailCtx`) can render without it; the detail pane always prefers the
    // full `Footprint` below.
    m.skip("worktrees");
    m.skip("process_count");
    m.skip("ports");
    m.skip("clone_note");
    let fp = set.and_then(|s| s.footprints.iter().find(|fp| fp.finding == f.id));
    if let Some(fp) = fp {
        let mut entries: Vec<&FootprintEntry> = fp.groups.iter().flat_map(|g| &g.entries).collect();
        entries.sort_by_key(|e| std::cmp::Reverse(e.bytes));
        if !entries.is_empty() {
            out.push(Field::Blank);
            out.push(Field::Header("Top entries"));
            for e in entries.into_iter().take(15) {
                out.extend(entry_fields(e));
            }
        }
        if !fp.worktrees.is_empty() {
            out.push(Field::Blank);
            out.push(Field::Header("Worktrees"));
            for w in &fp.worktrees {
                out.push(Field::Text(format!("  {}", fmt::abbrev_home(w))));
            }
        }
        if !fp.processes.is_empty() {
            out.push(Field::Blank);
            out.push(Field::Header("Processes"));
            for p in &fp.processes {
                out.push(kv(
                    format!("  {}", p.pid),
                    format!("{} — {}", p.name, proc_kind_label(p.kind)),
                ));
            }
        }
        if !fp.ports.is_empty() {
            let ports = fp
                .ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            out.push(kv("Ports", ports));
        }
        if fp.clone_note {
            out.push(Field::Blank);
            out.push(Field::Text(CLONE_NOTE.to_string()));
        }
    }
    out
}

/// Detail for the three synthetic bucket rows: Coverage shows
/// `attributed_total / disk_total` and which dependency sections were
/// missing; Baseline/Unattributed list their entries (with `reason` for
/// Unattributed) from the cached `FootprintSet` — `meta` only carries their
/// count.
fn attribution_bucket_detail(
    f: &Finding,
    m: &mut MetaView<'_>,
    axis: Axis,
    ctx: &DetailCtx,
) -> Vec<Field> {
    let mut out = Vec::new();
    m.skip("group");
    if f.title == "Coverage" {
        let disk_total = m.u64("disk_total").unwrap_or(0);
        let attributed_total = m.u64("attributed_total").unwrap_or(0);
        let pct = if disk_total > 0 {
            attributed_total as f64 / disk_total as f64 * 100.0
        } else {
            0.0
        };
        out.push(kv(
            "Attributed",
            format!(
                "{} / {} ({pct:.0}%)",
                fmt::bytes(attributed_total),
                fmt::bytes(disk_total)
            ),
        ));
        if let Some(missing) = m.list("missing_deps") {
            if !missing.is_empty() {
                let labels: Vec<String> = missing
                    .iter()
                    .map(|s| format!("{} not scanned", prettify_key(s)))
                    .collect();
                out.push(kv_styled(
                    "Missing dependencies",
                    labels.join(", "),
                    Color::Yellow,
                ));
            }
        }
        return out;
    }

    m.skip("entry_count");
    let entries = ctx.footprints.get(&axis).map(|set| {
        if f.title == "Baseline" {
            set.baseline.clone()
        } else {
            set.unattributed.clone()
        }
    });
    match entries {
        Some(entries) if !entries.is_empty() => {
            let mut sorted: Vec<&FootprintEntry> = entries.iter().collect();
            sorted.sort_by_key(|e| std::cmp::Reverse(e.bytes));
            for e in sorted.into_iter().take(30) {
                out.extend(entry_fields(e));
                if let Some(reason) = &e.reason {
                    out.push(kv_styled("  reason", reason.clone(), Color::Yellow));
                }
            }
        }
        Some(_) => out.push(Field::Text("No entries.".to_string())),
        None => out.push(Field::Text(
            "Not yet available — rescan this section.".to_string(),
        )),
    }
    out
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

    #[test]
    fn bar_scales_by_reach_and_splits_by_component() {
        // Half the section's max reach, all exclusive: half the bar, all ▮.
        assert_eq!(bar(50, 0, 0, 100, 20), "▮".repeat(10));
        // A mix of all three components splits proportionally, largest
        // remainder first, and the bar's length still matches exactly.
        let mixed = bar(6, 3, 1, 10, 10);
        assert_eq!(mixed.chars().count(), 10);
        assert_eq!(mixed.chars().filter(|c| *c == '▮').count(), 6);
        assert_eq!(mixed.chars().filter(|c| *c == '▯').count(), 3);
        assert_eq!(mixed.chars().filter(|c| *c == '·').count(), 1);
        // Never panics on zero — just renders nothing.
        assert_eq!(bar(0, 0, 0, 100, 20), "");
        assert_eq!(bar(10, 0, 0, 0, 20), "");
        assert_eq!(bar(10, 0, 0, 100, 0), "");
        // A tiny non-zero owner still shows at least one cell rather than
        // rounding away to nothing.
        assert_eq!(bar(1, 0, 0, 1_000_000, 20), "▮");
    }

    #[test]
    fn attribution_bucket_rows_are_recognised_and_sort_last() {
        let bucket = Finding::new(FindingKind::ProjectBucket, "projects:baseline", "Baseline");
        let owner = Finding::new(FindingKind::Project, "/x", "x");
        assert!(is_attribution_bucket(&bucket));
        assert!(!is_attribution_bucket(&owner));
        assert_eq!(key_name_bucket_last(&bucket), SortKey::None);
        assert_ne!(key_name_bucket_last(&owner), SortKey::None);
    }
}
