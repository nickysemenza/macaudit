//! Read-only view-state queries: which section is selected, the sorted/
//! filtered rows for the current section (flat table or flattened tree), and
//! the finding under the cursor. Kept separate from `state.rs` (scan-event
//! ingestion) and `nav.rs` (cursor movement) since everything here only ever
//! *reads* `AppState`.

use std::cmp::Ordering;

use crate::model::{Finding, FindingKind, ScannerId};
use crate::registry::{self, ViewKind};
use crate::ui::app::AppState;
use crate::ui::present::{self, SectionPresenter, SortBy, SortDir, SortSpec};
use crate::ui::rows::RenderRow;
use crate::ui::tree;

impl AppState {
    pub fn selected_section_id(&self) -> ScannerId {
        ScannerId::ALL[self.selected_section]
    }

    pub(crate) fn selected_section_index(&self) -> usize {
        self.selected_section
    }

    pub(super) fn presenter(&self) -> &'static SectionPresenter {
        present::presenter(self.selected_section_id())
    }

    /// The active sort for the selected section (its default until changed).
    pub(super) fn sort(&self) -> SortSpec {
        self.sort
            .get(&self.selected_section_id())
            .copied()
            .unwrap_or(self.presenter().default_sort)
    }

    pub(super) fn set_sort(&mut self, sort: SortSpec) {
        self.sort.insert(self.selected_section_id(), sort);
        self.selected_row = 0;
        self.viewport.row_offset = 0;
    }

    pub(crate) fn sort_label(&self) -> String {
        self.presenter().sort_label(self.sort())
    }

    pub(super) fn is_tree_view(&self) -> bool {
        matches!(
            registry::section(self.selected_section_id()).view,
            ViewKind::Tree
        )
    }

    /// Findings for the selected section, ordered by the current sort, with
    /// System apps, zero-byte rows, and the `/` filter applied.
    pub(super) fn visible_findings(&self) -> Vec<&Finding> {
        let id = self.selected_section_id();
        let Some(map) = self.findings.get(&id) else {
            return Vec::new();
        };
        let needle = self.filter.to_lowercase();
        let mut rows: Vec<&Finding> = map
            .values()
            .filter(|f| self.show_system || !is_system_app(f))
            // A sized-but-empty artifact is noise, not a cleanup target.
            .filter(|f| f.size_bytes != Some(0))
            .filter(|f| needle.is_empty() || matches_filter(f, &needle))
            .collect();
        let sort = self.sort();
        let presenter = self.presenter();
        rows.sort_by(|a, b| compare(presenter, sort, a, b));
        rows
    }

    /// The navigable rows for the selected section: group headers + indented
    /// items for tree sections, flat items otherwise. `selected_row` indexes
    /// this list.
    pub(super) fn rows(&self) -> Vec<RenderRow<'_>> {
        let findings = self.visible_findings();
        let id = self.selected_section_id();
        if id == ScannerId::Brew {
            let graph = self.brew_graph();
            return crate::ui::deps::build_explorer_rows(
                &graph,
                &findings,
                self.deps_direction,
                &|key| self.collapsed_groups.contains(&(id, key.to_string())),
                &|key| self.expanded_nodes.contains(key),
            );
        }
        if self.is_tree_view() {
            tree::build_rows(findings.into_iter(), |key| {
                self.collapsed_groups.contains(&(id, key.to_string()))
            })
        } else {
            findings
                .into_iter()
                .map(|f| RenderRow::Item { f, depth: 0 })
                .collect()
        }
    }

    pub(super) fn row_count(&self) -> usize {
        self.rows().len()
    }

    /// The Finding under the cursor (`None` on a tree group header or an
    /// explorer placeholder).
    pub(super) fn selected_finding(&self) -> Option<&Finding> {
        match self.rows().into_iter().nth(self.selected_row) {
            Some(RenderRow::Item { f, .. }) => Some(f),
            Some(RenderRow::Node { f, .. }) => f,
            _ => None,
        }
    }

    /// The Homebrew graph for the explorer and previews, rebuilt only when
    /// the Brew findings changed.
    pub(crate) fn brew_graph(&self) -> std::rc::Rc<crate::brewgraph::BrewGraph> {
        if let Some((v, g)) = self.brew_graph.borrow().as_ref() {
            if *v == self.brew_version {
                return g.clone();
            }
        }
        let graph = std::rc::Rc::new(crate::brewgraph::BrewGraph::from_findings(
            self.findings
                .get(&ScannerId::Brew)
                .into_iter()
                .flat_map(|m| m.values()),
        ));
        *self.brew_graph.borrow_mut() = Some((self.brew_version, graph.clone()));
        graph
    }

    pub(crate) fn deps_direction(&self) -> crate::brewgraph::Direction {
        self.deps_direction
    }

    /// Row titles in display order (tests): group keys, finding titles, node names.
    #[cfg(test)]
    pub(crate) fn rows_titles(&self) -> Vec<Option<String>> {
        self.rows()
            .into_iter()
            .map(|r| match r {
                RenderRow::Group { .. } => None,
                RenderRow::Item { f, .. } => Some(f.title.clone()),
                RenderRow::Node { name, .. } => Some(name),
            })
            .collect()
    }
}

/// Order two findings under `sort`. Rows whose key is `SortKey::None` go last
/// in either direction; ties break by title so the order is stable and reads
/// alphabetically.
fn compare(presenter: &SectionPresenter, sort: SortSpec, a: &Finding, b: &Finding) -> Ordering {
    let primary = match sort.by {
        SortBy::Severity => directed(a.severity.cmp(&b.severity), sort.dir),
        SortBy::Column(id) => match presenter.column(id).and_then(|c| c.sort_key) {
            Some(key) => {
                let (ka, kb) = (key(a), key(b));
                match (ka == present::SortKey::None, kb == present::SortKey::None) {
                    (true, true) => Ordering::Equal,
                    (true, false) => Ordering::Greater,
                    (false, true) => Ordering::Less,
                    (false, false) => directed(ka.cmp(&kb), sort.dir),
                }
            }
            None => Ordering::Equal,
        },
    };
    primary.then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
}

fn directed(ord: Ordering, dir: SortDir) -> Ordering {
    match dir {
        SortDir::Asc => ord,
        SortDir::Desc => ord.reverse(),
    }
}

fn matches_filter(f: &Finding, needle: &str) -> bool {
    f.title.to_lowercase().contains(needle)
        || f.path
            .as_ref()
            .map(|p| p.display().to_string().to_lowercase().contains(needle))
            .unwrap_or(false)
        || searchable_meta(f)
            .iter()
            .any(|s| s.to_lowercase().contains(needle))
}

/// Meta strings worth filtering on: group, manager, package/command names,
/// aliases — so `/eslint` finds the tool whose *command* is eslint.
fn searchable_meta(f: &Finding) -> Vec<String> {
    let mut out = Vec::new();
    for key in [
        "group",
        "manager",
        "name",
        "command",
        "layout",
        "primary_classification",
    ] {
        if let Some(s) = f.meta.get(key).and_then(|v| v.as_str()) {
            out.push(s.to_string());
        }
    }
    if let Some(cmds) = f.meta.get("commands").and_then(|v| v.as_array()) {
        for c in cmds {
            if let Some(n) = c.get("name").and_then(|n| n.as_str()) {
                out.push(n.to_string());
            }
        }
    }
    if let Some(aliases) = f.meta.get("aliases").and_then(|v| v.as_array()) {
        for a in aliases {
            if let Some(n) = a.as_str() {
                out.push(n.to_string());
            }
        }
    }
    out
}

/// Whether a finding is a System app (hidden unless `H` toggled). Heuristic on
/// path; the real classification lives in AppsScanner's meta.
fn is_system_app(f: &Finding) -> bool {
    // Scoped to App findings: other sections (e.g. Ports) legitimately carry
    // /System/… binary paths and must not vanish behind the `H` toggle.
    f.kind == FindingKind::App
        && f.path
            .as_ref()
            .map(|p| p.starts_with("/System/"))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use crate::model::{Finding, FindingKind, ScanEvent, ScannerId};
    use crate::ui::keys::Action;
    use crate::ui::present::{ColumnId, SortDir, SortSpec};
    use crate::ui::testutil::*;

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
    fn zero_byte_rows_are_hidden_but_unsized_rows_stay() {
        let mut app = app_with_gen(1);
        app.apply(finding_event(1, "/empty", Some(0)));
        app.apply(finding_event(1, "/unsized", None));
        app.apply(finding_event(1, "/real", Some(5)));
        let titles: Vec<&str> = app
            .visible_findings()
            .iter()
            .map(|f| f.title.as_str())
            .collect();
        assert_eq!(titles, ["/real", "/unsized"]);
    }

    fn git_repo(gen: u64, name: &str, size: u64, branch: &str) -> ScanEvent {
        let f = Finding::new(FindingKind::GitRepo, name, name)
            .size(size)
            .meta(serde_json::json!({ "branch": branch, "dirty": false }));
        ScanEvent::Finding {
            scanner: ScannerId::Git,
            gen,
            finding: Box::new(f),
        }
    }

    #[test]
    fn sort_is_per_section_and_s_cycles_through_columns() {
        let mut app = app_with_gen(1);
        app.handle(Action::JumpSection(12)); // Git (index 12 — after Fs, Projects, AppStorage)
        app.apply(git_repo(1, "b-small", 1, "main"));
        app.apply(git_repo(1, "a-big", 100, "zeta"));
        app.apply(git_repo(1, "c-mid", 50, "alpha"));

        // Default: size desc.
        let names = |app: &crate::ui::app::AppState| -> Vec<String> {
            app.visible_findings()
                .iter()
                .map(|f| f.title.clone())
                .collect()
        };
        assert_eq!(names(&app), ["a-big", "c-mid", "b-small"]);
        assert_eq!(app.sort_label(), ".git size↓");

        // `s` moves to the next sortable column (Repo, A→Z).
        app.handle(Action::Char('s'));
        assert_eq!(names(&app), ["a-big", "b-small", "c-mid"]);

        // Header click on Branch sorts A→Z, again flips.
        // Branches: c-mid=alpha, b-small=main, a-big=zeta.
        app.handle(Action::SortBy(ColumnId::Branch));
        assert_eq!(names(&app), ["c-mid", "b-small", "a-big"]);
        assert_eq!(app.sort(), SortSpec::col(ColumnId::Branch, SortDir::Asc));
        app.handle(Action::SortBy(ColumnId::Branch));
        assert_eq!(names(&app), ["a-big", "b-small", "c-mid"]);

        // Another section is untouched by Git's sort.
        app.handle(Action::Char('5')); // Disk
        assert_eq!(app.sort_label(), "Size↓");
    }
}
