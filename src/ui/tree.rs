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

/// The group a finding belongs to: `meta.group` VERBATIM when a scanner sets
/// it (scanners choose display-ready labels — "node_modules" must not become
/// "Node Modules"), else the finding's kind tag prettified.
pub fn group_key(f: &Finding) -> String {
    f.meta
        .get("group")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| group_label(f.kind.tag()))
}

/// Human label for a kind-tag fallback key: underscores → spaces, title-cased.
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
/// group KEEP the caller's order (the reducer already applied the active
/// sort — size/name/severity — and re-sorting here would silently ignore it).
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
    for (key, items) in groups {
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
                        // group_key is already the display label.
                        format!("{key} ({count}){size}"),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]))
            }
            TreeRow::Item(f) => {
                let mark = if is_marked(f.id) { theme::MARK } else { " " };
                // Some tree items have no size concept (apps/brew) — show it
                // only if present (blank, not a perpetual `…`).
                let size = f
                    .size_bytes
                    .map(|b| humansize::format_size(b, humansize::BINARY))
                    .unwrap_or_default();
                let mut spans = vec![
                    Span::raw(format!("    {mark} ")),
                    Span::raw(format!("{:<32}", f.title)),
                    Span::styled(
                        format!("{size:>10}  "),
                        Style::default().fg(theme::severity_color(f.severity)),
                    ),
                    Span::styled(
                        super::table::abbrev_path(f),
                        Style::default().fg(Color::DarkGray),
                    ),
                ];
                if let Some(badge) = cask_badge(f) {
                    spans.push(Span::styled(
                        badge,
                        Style::default().fg(theme::severity_color(Severity::Attention)),
                    ));
                }
                ListItem::new(Line::from(spans))
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

/// Warning badge for an app the cask catalog says could be brew-managed
/// (`meta.available_cask` from network enrichment): the user can swap it to
/// Homebrew with the adopt remedy shown in the detail pane / confirm dialog.
pub fn cask_badge(f: &Finding) -> Option<String> {
    let token = f.meta.get("available_cask")?.as_str()?;
    Some(format!("  ⚠ brew cask available: {token}"))
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
    fn falls_back_to_prettified_kind_tag_without_meta_group() {
        let a = finding(FindingKind::BrewFormula, "/a", "A");
        assert_eq!(group_key(&a), "Brew Formula");
    }

    #[test]
    fn meta_group_is_verbatim_never_title_cased() {
        // Scanners pick display-ready labels; "node_modules" must not be
        // mangled into "Node Modules".
        let mut f = finding(FindingKind::BuildArtifact, "/p/node_modules", "nm");
        f.meta = serde_json::json!({"group": "node_modules"});
        assert_eq!(group_key(&f), "node_modules");
    }

    #[test]
    fn build_rows_preserves_caller_order_within_groups() {
        // The reducer sorts (e.g. size desc); build_rows must not re-sort.
        let mut big = finding(FindingKind::BuildArtifact, "/p/big", "zzz-big");
        big.meta = serde_json::json!({"group": "node_modules"});
        big.size_bytes = Some(100);
        let mut small = finding(FindingKind::BuildArtifact, "/p/small", "aaa-small");
        small.meta = serde_json::json!({"group": "node_modules"});
        small.size_bytes = Some(1);
        // Caller order: big first (size desc), despite 'zzz' > 'aaa'.
        let ordered = [&big, &small];
        let rows = build_rows(ordered.iter().copied(), |_| false);
        match (&rows[1], &rows[2]) {
            (TreeRow::Item(first), TreeRow::Item(second)) => {
                assert_eq!(first.title, "zzz-big");
                assert_eq!(second.title, "aaa-small");
            }
            other => panic!("unexpected rows: {other:?}"),
        }
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

    #[test]
    fn cask_badge_only_for_catalog_matches() {
        let mut matched = finding(FindingKind::App, "/Applications/Slack.app", "Slack");
        matched.meta = serde_json::json!({
            "classification": "unmanaged",
            "available_cask": "slack"
        });
        assert_eq!(
            cask_badge(&matched).as_deref(),
            Some("  ⚠ brew cask available: slack")
        );

        let unmatched = finding(FindingKind::App, "/Applications/Bespoke.app", "Bespoke");
        assert_eq!(cask_badge(&unmatched), None);

        // Malformed meta (non-string) must not badge or panic.
        let mut weird = finding(FindingKind::App, "/Applications/W.app", "W");
        weird.meta = serde_json::json!({ "available_cask": 42 });
        assert_eq!(cask_badge(&weird), None);
    }
}
