//! Machine-readable output for headless commands.

use std::collections::BTreeMap;

use crate::config::DeleteMode;
use crate::model::{Finding, FindingId};
use crate::remedy::RemedyEngine;

/// Serialize findings as a JSON array (`Vec<Finding>`), sorted by id for stable
/// output. This is the contract behind `macaudit scan --json` (spec §5).
pub fn findings_to_json(findings: &BTreeMap<FindingId, Finding>) -> anyhow::Result<String> {
    let list: Vec<&Finding> = findings.values().collect();
    Ok(serde_json::to_string_pretty(&list)?)
}

/// Human-readable dry-run listing of the remedy commands that `clean` would run,
/// running nothing (spec §5 `clean --dry-run`).
///
/// Commands are rendered through `RemedyEngine` with the active `delete_mode`, so
/// under `--rm` the preview shows the literal `rm -rf …` that would actually run
/// — never `trash …` for an operation that is really irreversible.
pub fn dry_run_report(findings: &BTreeMap<FindingId, Finding>, delete_mode: DeleteMode) -> String {
    use std::fmt::Write;
    let engine = RemedyEngine::new(delete_mode);
    let mut out = String::new();
    let mut n = 0usize;
    let mut reclaim: u64 = 0;
    for f in findings.values() {
        for r in &f.remedies {
            if r.destructive {
                let action = engine.plan_one(f.id, r);
                let _ = writeln!(out, "# {}  ({})", f.title, f.severity_label());
                let _ = writeln!(out, "{}", action.rendered);
                n += 1;
                reclaim += r.reclaims_bytes.unwrap_or(0);
            }
        }
    }
    let human = humansize::format_size(reclaim, humansize::BINARY);
    let _ = writeln!(
        out,
        "\n# {n} destructive remed{} — up to {human} reclaimable",
        if n == 1 { "y" } else { "ies" }
    );
    out
}

impl Finding {
    /// Lowercase severity label for reports.
    pub fn severity_label(&self) -> &'static str {
        match self.severity {
            crate::model::Severity::Info => "info",
            crate::model::Severity::Attention => "attention",
            crate::model::Severity::Reclaimable => "reclaimable",
            crate::model::Severity::Warning => "warning",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FindingKind, Remedy, RemedyCommand, Severity};

    fn sample() -> BTreeMap<FindingId, Finding> {
        let mut m = BTreeMap::new();
        let f = Finding::new(
            FindingKind::BuildArtifact,
            "/p/node_modules",
            "node_modules",
        )
        .size(1000)
        .severity(Severity::Reclaimable)
        .remedy(Remedy {
            label: "Trash".into(),
            command: RemedyCommand::Trash {
                path: "/p/node_modules".into(),
            },
            reclaims_bytes: Some(1000),
            destructive: true,
        });
        m.insert(f.id, f);
        m
    }

    #[test]
    fn json_is_an_array() {
        let json = findings_to_json(&sample()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array());
        assert_eq!(v[0]["kind"], "build_artifact");
    }

    #[test]
    fn dry_run_lists_command_verbatim() {
        let report = dry_run_report(&sample(), DeleteMode::Trash);
        assert!(report.contains("trash /p/node_modules"));
        assert!(report.contains("destructive remedy"));
    }

    #[test]
    fn dry_run_rm_mode_shows_rm_not_trash() {
        // The whole point of the dry run is an honest preview: in --rm mode it
        // must show the literal `rm -rf`, never `trash`.
        let report = dry_run_report(&sample(), DeleteMode::Rm);
        assert!(report.contains("rm -rf /p/node_modules"), "got: {report}");
        assert!(!report.contains("trash /p/node_modules"));
    }
}
