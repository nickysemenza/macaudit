//! Tree grouping for `ViewKind::Tree` sections (Apps, Brew).
//!
//! Findings are bucketed into named groups — a scanner-supplied
//! `meta.group` string when present, else the `FindingKind` tag as a
//! reasonable default bucket — and each group is independently collapsible.
//! `enter`/`right` expands a group, `left` collapses it; `h` stays reserved
//! for the System-apps visibility toggle (spec §4).

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

use crate::model::{Finding, FindingId, Severity};
use crate::ui::theme;

/// One flattened, navigable row in the tree: either a group header or a leaf
/// finding. `selected_row` in `AppState` indexes into a `Vec<TreeRow>`
/// exactly like it indexes into the flat table rows.
#[derive(Clone, Debug)]
pub enum TreeRow<'a> {
    Group {
        key: String,
        count: usize,
        reclaimable_bytes: u64,
        expanded: bool,
    },
    Item(&'a Finding),
}

/// The group a finding belongs to: `meta.group` when a scanner sets it, else
/// the finding's kind tag.
pub fn group_key(f: &Finding) -> String {
    f.meta
        .get("group")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| f.kind.tag().to_string())
}

/// Human label for a group key: underscores → spaces, title-cased.
pub fn group_label(key: &str) -> String {
    key.split('_')
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Build the flattened row list from a set of findings, respecting which
/// groups are currently collapsed. Groups are sorted by key; items within a
/// group are sorted by title.
pub fn build_rows<'a>(
    findings: impl Iterator<Item = &'a Finding>,
    is_collapsed: impl Fn(&str) -> bool,
) -> Vec<TreeRow<'a>> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        groups.entry(group_key(f)).or_default().push(f);
    }
    let mut rows = Vec::new();
    for (key, mut items) in groups {
        items.sort_by(|a, b| a.title.cmp(&b.title));
        let reclaimable_bytes = items
            .iter()
            .filter(|f| f.severity == Severity::Reclaimable)
            .filter_map(|f| f.size_bytes)
            .sum();
        let expanded = !is_collapsed(&key);
        rows.push(TreeRow::Group {
            key: key.clone(),
            count: items.len(),
            reclaimable_bytes,
            expanded,
        });
        if expanded {
            rows.extend(items.into_iter().map(TreeRow::Item));
        }
    }
    rows
}

/// Render the tree as a `List`, highlighting `selected`.
pub fn draw(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    rows: &[TreeRow],
    is_marked: impl Fn(FindingId) -> bool,
    selected: usize,
) {
    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| match row {
            TreeRow::Group {
                key,
                count,
                reclaimable_bytes,
                expanded,
            } => {
                let glyph = if *expanded {
                    theme::EXPANDED
                } else {
                    theme::COLLAPSED
                };
                let size = if *reclaimable_bytes > 0 {
                    format!(
                        " · {}",
                        humansize::format_size(*reclaimable_bytes, humansize::BINARY)
                    )
                } else {
                    String::new()
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{glyph} "), Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{} ({count}){size}", group_label(key)),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]))
            }
            TreeRow::Item(f) => {
                let mark = if is_marked(f.id) { theme::MARK } else { " " };
                // Apps/Brew items have no size concept — show it only if present
                // (blank, not a perpetual `…`).
                let size = f
                    .size_bytes
                    .map(|b| humansize::format_size(b, humansize::BINARY))
                    .unwrap_or_default();
                ListItem::new(Line::from(vec![
                    Span::raw(format!("    {mark} ")),
                    Span::raw(format!("{:<32}", f.title)),
                    Span::styled(size, Style::default().fg(theme::severity_color(f.severity))),
                ]))
            }
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {title} ")),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut state = ListState::default();
    if !rows.is_empty() {
        state.select(Some(selected.min(rows.len() - 1)));
    }
    frame.render_stateful_widget(list, area, &mut state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FindingKind;

    fn finding(kind: FindingKind, key: &str, title: &str) -> Finding {
        Finding::new(kind, key, title)
    }

    #[test]
    fn groups_by_meta_group_when_present() {
        let mut a = finding(FindingKind::App, "/a", "A");
        a.meta = serde_json::json!({"group": "unmanaged"});
        let mut b = finding(FindingKind::App, "/b", "B");
        b.meta = serde_json::json!({"group": "system"});
        assert_eq!(group_key(&a), "unmanaged");
        assert_eq!(group_key(&b), "system");
    }

    #[test]
    fn falls_back_to_kind_tag_without_meta_group() {
        let a = finding(FindingKind::BrewFormula, "/a", "A");
        assert_eq!(group_key(&a), "brew_formula");
    }

    #[test]
    fn build_rows_nests_items_under_expanded_group_only() {
        let a = finding(FindingKind::App, "/a", "A");
        let b = finding(FindingKind::App, "/b", "B");
        let findings = [&a, &b];
        let expanded_rows = build_rows(findings.iter().copied(), |_| false);
        assert_eq!(expanded_rows.len(), 3); // 1 group header + 2 items

        let collapsed_rows = build_rows(findings.iter().copied(), |_| true);
        assert_eq!(collapsed_rows.len(), 1); // just the header
        assert!(matches!(
            collapsed_rows[0],
            TreeRow::Group {
                expanded: false,
                ..
            }
        ));
    }

    #[test]
    fn group_label_title_cases_underscored_key() {
        assert_eq!(group_label("brew_formula"), "Brew Formula");
    }
}
