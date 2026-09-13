//! Tree grouping for `ViewKind::Tree` sections (Apps, Brew, Disk).
//!
//! Findings are bucketed into named groups — a scanner-supplied
//! `meta.group` string when present, else the `FindingKind` tag as a
//! reasonable default bucket — and each group is independently collapsible.
//! `z` (or `enter` on the header) toggles a group; `←/→` never touch the
//! tree — they always switch sections. Rendering is `rows::draw`.

use std::collections::BTreeMap;

use crate::model::{Finding, Severity};
use crate::ui::rows::RenderRow;

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
/// groups are currently collapsed. Groups are ordered by total bytes (biggest
/// first — a disk view should lead with what's eating the disk), then by
/// key for size-less sections; items within a group KEEP the caller's order
/// (the reducer already applied the active sort, and re-sorting here would
/// silently ignore it).
pub fn build_rows<'a>(
    findings: impl Iterator<Item = &'a Finding>,
    is_collapsed: impl Fn(&str) -> bool,
) -> Vec<RenderRow<'a>> {
    let mut groups: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        groups.entry(group_key(f)).or_default().push(f);
    }
    let mut ordered: Vec<(String, Vec<&Finding>)> = groups.into_iter().collect();
    ordered
        .sort_by(|(ka, a), (kb, b)| total_bytes(b).cmp(&total_bytes(a)).then_with(|| ka.cmp(kb)));

    let mut rows = Vec::new();
    for (key, items) in ordered {
        let reclaimable_bytes = items
            .iter()
            .filter(|f| f.severity == Severity::Reclaimable)
            .filter_map(|f| f.size_bytes)
            .sum();
        let expanded = !is_collapsed(&key);
        rows.push(RenderRow::Group {
            key,
            count: items.len(),
            reclaimable_bytes,
            expanded,
        });
        if expanded {
            rows.extend(items.into_iter().map(|f| RenderRow::Item { f, depth: 1 }));
        }
    }
    rows
}

fn total_bytes(items: &[&Finding]) -> u64 {
    items.iter().filter_map(|f| f.size_bytes).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FindingKind;

    fn finding(kind: FindingKind, key: &str, title: &str) -> Finding {
        Finding::new(kind, key, title)
    }

    fn rows<'a>(findings: &[&'a Finding], collapsed: bool) -> Vec<RenderRow<'a>> {
        build_rows(findings.iter().copied(), |_| collapsed)
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
        let rows = rows(&[&big, &small], false);
        match (&rows[1], &rows[2]) {
            (RenderRow::Item { f: first, .. }, RenderRow::Item { f: second, .. }) => {
                assert_eq!(first.title, "zzz-big");
                assert_eq!(second.title, "aaa-small");
            }
            other => panic!("unexpected rows: {other:?}"),
        }
    }

    #[test]
    fn build_rows_orders_groups_by_total_bytes_then_key() {
        let mut tiny = finding(FindingKind::BuildArtifact, "/p/a", "a");
        tiny.meta = serde_json::json!({"group": ".wrangler"});
        tiny.size_bytes = Some(1);
        let mut huge = finding(FindingKind::LargeFile, "/p/b", "b");
        huge.meta = serde_json::json!({"group": "Large files"});
        huge.size_bytes = Some(1 << 30);
        let x = finding(FindingKind::App, "/x", "x");
        let y = finding(FindingKind::BrewCask, "/y", "y");
        let rows = rows(&[&tiny, &huge, &y, &x], true);
        let order: Vec<&str> = rows
            .iter()
            .map(|r| match r {
                RenderRow::Group { key, .. } => key.as_str(),
                _ => unreachable!(),
            })
            .collect();
        // Sized groups biggest first; size-less groups alphabetical after.
        assert_eq!(order, ["Large files", ".wrangler", "App", "Brew Cask"]);
    }

    #[test]
    fn build_rows_nests_items_under_expanded_group_only() {
        let a = finding(FindingKind::App, "/a", "A");
        let b = finding(FindingKind::App, "/b", "B");
        let expanded_rows = rows(&[&a, &b], false);
        assert_eq!(expanded_rows.len(), 3); // 1 group header + 2 items

        let collapsed_rows = rows(&[&a, &b], true);
        assert_eq!(collapsed_rows.len(), 1); // just the header
        assert!(matches!(
            collapsed_rows[0],
            RenderRow::Group {
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
