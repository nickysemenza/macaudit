//! Time Machine: backup health (destination status, stale local mounts), the
//! current backup-set estimate, exclusions with the space they save,
//! suggested exclusions, and local APFS snapshots with a purgeable-space
//! upper bound. Tree grouped by `meta.group` ("Backup", "Backup set",
//! "Exclusions", "Suggested exclusions", "Local snapshots").

use ratatui::layout::Constraint;

use super::*;
use crate::model::{FindingKind, Severity};

fn status(f: &Finding, _: &CellCtx) -> CellText {
    let text = meta_str(f, "status").unwrap_or("");
    match f.severity {
        Severity::Warning | Severity::Attention => colored(text, theme::severity_color(f.severity)),
        _ => dim(text),
    }
}

fn key_status(f: &Finding) -> SortKey {
    key_meta_text(f, "status")
}

/// `complete`/`entries`/`size_cached` — the same "how thorough was this
/// measurement" trio shown for disk categories (see `present/disk.rs`).
/// Shared by exclusions, exclusion candidates and the backup-set estimate,
/// the only kinds that carry it.
fn push_measurement(out: &mut Vec<Field>, m: &mut MetaView<'_>) {
    if let Some(complete) = m.bool("complete") {
        out.push(kv(
            "Measurement",
            if complete {
                "complete"
            } else {
                "bounded (partial)"
            },
        ));
    }
    out.extend(kv_u64(m, "entries", "Entries measured"));
    out.extend(kv_bool(m, "size_cached", "Size from cache"));
}

fn exclusion_kind_label(s: &str) -> String {
    match s {
        "fixed_path" => "System Settings list".to_string(),
        "sticky_or_default" => "sticky attribute or macOS default".to_string(),
        "macos_default" => "macOS default".to_string(),
        other => other.to_string(),
    }
}

fn exclusion_reason_label(s: &str) -> String {
    match s {
        "regenerable_cache" => "regenerable cache".to_string(),
        "build_products" => "build products".to_string(),
        "cloud_synced" => "synced to a cloud provider".to_string(),
        other => other.to_string(),
    }
}

/// `auto_backup_interval_secs` as whole hours or whole days, whichever is
/// exact; falls back to raw seconds for anything odd.
fn humanize_interval_secs(secs: u64) -> String {
    if secs > 0 && secs.is_multiple_of(86400) {
        let days = secs / 86400;
        format!("{days} day{}", if days == 1 { "" } else { "s" })
    } else if secs > 0 && secs.is_multiple_of(3600) {
        let hours = secs / 3600;
        format!("{hours} hour{}", if hours == 1 { "" } else { "s" })
    } else {
        format!("{secs}s")
    }
}

fn detail(f: &Finding, m: &mut MetaView<'_>, _ctx: &DetailCtx) -> Vec<Field> {
    let mut out = Vec::new();
    m.skip("group");
    m.skip("status");

    match f.kind {
        FindingKind::LocalSnapshot => {
            out.extend(kv_str(m, "date", "Created"));
            out.extend(kv_str(m, "name", "Snapshot name"));
        }

        FindingKind::TmPurgeable => {
            out.extend(
                m.bytes("macos_available_bytes")
                    .map(|s| kv("Available incl. purgeable", s)),
            );
            out.extend(m.bytes("apfs_free_bytes").map(|s| kv("Free (APFS)", s)));
            out.extend(kv_u64(m, "snapshot_count", "Local snapshots"));
        }

        FindingKind::TmDestination => {
            out.extend(kv_str(m, "result_label", "Last result"));
            if let Some(result) = f.meta.get("result").and_then(|v| v.as_i64()) {
                out.push(kv("Result code", result.to_string()));
                m.skip("result");
            }
            out.extend(kv_str(m, "last_backup", "Last backup"));
            if let Some(days) = m.u64("last_backup_days") {
                out.push(kv("Backup age", format!("{days} days ago")));
            }
            out.extend(kv_str(m, "oldest_backup", "Oldest backup"));
            out.extend(kv_u64(m, "backup_count", "Backups kept"));
            out.extend(kv_u64(m, "attempt_count", "Attempts"));
            out.extend(kv_str(m, "last_attempt", "Last attempt"));
            out.extend(kv_bool(m, "auto_backup", "Automatic backups"));
            if let Some(secs) = m.u64("auto_backup_interval_secs") {
                out.push(kv("Backup interval", humanize_interval_secs(secs)));
            }
            out.extend(m.bytes("quota_bytes").map(|s| kv("Quota", s)));
            out.extend(m.bytes("bytes_used").map(|s| kv("Used on destination", s)));
            out.extend(
                m.bytes("bytes_available")
                    .map(|s| kv("Free on destination", s)),
            );
            out.extend(kv_bool(m, "mounted", "Mounted"));
            out.extend(kv_str(m, "network_url", "URL"));
            out.extend(kv_str(m, "kind", "Kind"));
            out.extend(kv_str(m, "destination_id", "Destination ID"));
            out.extend(kv_bool(m, "prefs_readable", "Preferences readable"));
        }

        FindingKind::TmStaleMount => {}

        FindingKind::TmExclusion => {
            if let Some(kind) = m.str("exclusion_kind") {
                out.push(kv("Exclusion type", exclusion_kind_label(kind)));
            }
            out.extend(kv_bool(m, "in_system_settings", "Shown in System Settings"));
            out.extend(kv_bool(m, "exists", "Exists"));
            push_measurement(&mut out, m);
        }

        FindingKind::TmExclusionCandidate => {
            if let Some(reason) = m.str("reason") {
                out.push(kv("Why", exclusion_reason_label(reason)));
            }
            push_measurement(&mut out, m);
        }

        FindingKind::TmBackupEstimate => {
            out.extend(
                m.bytes("included_bytes")
                    .map(|s| kv("Would be backed up", s)),
            );
            out.extend(m.bytes("excluded_bytes").map(|s| kv("Excluded", s)));
            out.extend(
                m.bytes("data_used_bytes")
                    .map(|s| kv("Data volume used", s)),
            );
            out.extend(m.bytes("quota_bytes").map(|s| kv("Quota", s)));
            out.extend(kv_bool(m, "fits_quota", "Fits quota"));
            out.extend(kv_u64(m, "roots_total", "Roots"));
            out.extend(kv_u64(m, "roots_measured", "Measured completely"));
            out.extend(kv_u64(m, "roots_partial", "Partial"));
            out.extend(kv_u64(m, "roots_skipped", "Skipped"));
            out.extend(kv_list(m, "skipped_paths", "Skipped (protected)"));
            push_measurement(&mut out, m);
        }

        // Not a Time Machine kind; nothing extra to add.
        _ => {}
    }

    out.extend(generic_fields(&m.remaining()));
    out
}

static COLUMNS: &[Column] = &[
    Column::new(ColumnId::Name, "Name", Constraint::Fill(2), name_cell)
        .primary()
        .sortable(key_title, SortDir::Asc),
    Column::new(ColumnId::Size, "Size", Constraint::Length(10), size_cell)
        .right()
        .sortable(key_size, SortDir::Desc),
    Column::new(ColumnId::Status, "Status", Constraint::Length(26), status)
        .sortable(key_status, SortDir::Asc),
    Column::new(ColumnId::Path, "Path", Constraint::Fill(3), path_cell)
        .middle()
        .sortable(key_path, SortDir::Asc),
];

pub static PRESENTER: SectionPresenter = SectionPresenter {
    columns: COLUMNS,
    default_sort: SortSpec::col(ColumnId::Size, SortDir::Desc),
    detail,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    fn ctx() -> CellCtx {
        CellCtx {
            is_scanning: false,
            now: std::time::SystemTime::now(),
        }
    }

    fn finding(kind: FindingKind, severity: Severity, meta: serde_json::Value) -> Finding {
        Finding::new(kind, "key", "title")
            .severity(severity)
            .meta(meta)
    }

    #[test]
    fn status_cell_renders_meta_status() {
        let f = finding(
            FindingKind::TmDestination,
            Severity::Info,
            serde_json::json!({ "status": "OK · 3h ago" }),
        );
        let cell = status(&f, &ctx());
        assert_eq!(cell.text, "OK · 3h ago");
    }

    #[test]
    fn detail_renders_bounded_partial_for_incomplete_measurement() {
        let f = finding(
            FindingKind::TmExclusionCandidate,
            Severity::Attention,
            serde_json::json!({
                "group": "Suggested exclusions",
                "status": "Included",
                "reason": "build_products",
                "complete": false,
                "entries": 12,
            }),
        );
        let mut view = MetaView::new(&f.meta);
        let footprints = BTreeMap::new();
        let fields = detail(
            &f,
            &mut view,
            &DetailCtx {
                footprints: &footprints,
            },
        );
        assert!(fields.contains(&kv("Measurement", "bounded (partial)")));
    }

    #[test]
    fn warning_finding_status_cell_uses_warning_color() {
        let f = finding(
            FindingKind::TmDestination,
            Severity::Warning,
            serde_json::json!({ "status": "Failed (destination full) · 27d ago" }),
        );
        let cell = status(&f, &ctx());
        assert_eq!(cell.style.fg, Some(Color::Red));
    }

    #[test]
    fn info_finding_status_cell_is_dim() {
        let f = finding(
            FindingKind::TmPurgeable,
            Severity::Info,
            serde_json::json!({ "status": "upper bound" }),
        );
        let cell = status(&f, &ctx());
        assert_eq!(cell.style.fg, Some(Color::DarkGray));
    }
}
