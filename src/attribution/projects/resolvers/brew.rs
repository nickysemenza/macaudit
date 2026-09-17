//! Brewfile-listed formulae, joined to their Cellar paths via the Brew
//! snapshot; casks joined to their `.app` bundle. No baseline: an
//! individually-listed formula/cask is exact evidence, not ecosystem
//! baggage.

use std::path::PathBuf;

use serde_json::Value;

use super::super::Project;
use crate::attribution::model::{Claim, EntryKind, EvidenceTier, ResolveEnv};
use crate::model::{Finding, FindingKind, ScannerId};

/// `env.read_head`'s cap for a `Brewfile` — a very long one still fits
/// comfortably.
const MAX_BREWFILE_BYTES: usize = 256 * 1024;

pub fn resolve(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let Some(text) = env.read_head(&project.root.join("Brewfile"), MAX_BREWFILE_BYTES) else {
        return Vec::new();
    };
    let owner = project.root.to_string_lossy().into_owned();
    let mut claims = Vec::new();

    for (kind, name) in parse_brewfile(&text) {
        match kind {
            BrewEntryKind::Formula => {
                let Some(finding) = find_formula_finding(env, &name) else {
                    continue;
                };
                let Some(path) = &finding.path else { continue };
                claims.push(
                    Claim::new(
                        path.clone(),
                        owner.clone(),
                        EntryKind::Toolchain,
                        EvidenceTier::Exact,
                        "Brewfile",
                    )
                    .label(format!("brew {name}"))
                    .finding(finding.id)
                    .ecosystem("brew"),
                );
            }
            BrewEntryKind::Cask => {
                let Some(finding) = find_cask_finding(env, &name) else {
                    continue;
                };
                for app_path in cask_app_paths(finding) {
                    claims.push(
                        Claim::new(
                            app_path,
                            owner.clone(),
                            EntryKind::AppBundle,
                            EvidenceTier::Exact,
                            "Brewfile",
                        )
                        .label(format!("brew {name}"))
                        .finding(finding.id)
                        .ecosystem("brew"),
                    );
                }
            }
        }
    }
    claims
}

enum BrewEntryKind {
    Formula,
    Cask,
}

/// `brew "name"` / `cask "name"` lines — `tap`/`mas`/anything else ignored.
fn parse_brewfile(text: &str) -> Vec<(BrewEntryKind, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = parse_brewfile_directive(line, "brew") {
            out.push((BrewEntryKind::Formula, name));
        } else if let Some(name) = parse_brewfile_directive(line, "cask") {
            out.push((BrewEntryKind::Cask, name));
        }
    }
    out
}

/// `<keyword> "name"` / `<keyword> 'name'`, with a required word boundary
/// after the keyword so `brewsomething` doesn't match `brew`.
fn parse_brewfile_directive(line: &str, keyword: &str) -> Option<String> {
    let rest = line.strip_prefix(keyword)?;
    let rest = rest.strip_prefix(' ')?;
    let rest = rest.trim_start();
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let after = &rest[quote.len_utf8()..];
    let end = after.find(quote)?;
    Some(after[..end].to_string())
}

fn find_formula_finding<'a>(env: &'a ResolveEnv<'_>, name: &str) -> Option<&'a Finding> {
    env.findings(ScannerId::Brew).iter().find(|f| {
        f.kind == FindingKind::BrewFormula
            && f.meta.get("name").and_then(Value::as_str) == Some(name)
    })
}

fn find_cask_finding<'a>(env: &'a ResolveEnv<'_>, name: &str) -> Option<&'a Finding> {
    env.findings(ScannerId::Brew).iter().find(|f| {
        f.kind == FindingKind::BrewCask
            && (f.meta.get("token").and_then(Value::as_str) == Some(name)
                || f.meta.get("name").and_then(Value::as_str) == Some(name))
    })
}

fn cask_app_paths(finding: &Finding) -> Vec<PathBuf> {
    finding
        .meta
        .get("app_paths")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_brew_and_cask_directives_and_ignores_others() {
        let text = "tap \"homebrew/cask\"\nbrew \"ripgrep\"\ncask 'visual-studio-code'\nmas \"Xcode\", id: 497799835\n";
        let entries: Vec<(bool, String)> = parse_brewfile(text)
            .into_iter()
            .map(|(kind, name)| (matches!(kind, BrewEntryKind::Formula), name))
            .collect();
        assert_eq!(
            entries,
            vec![
                (true, "ripgrep".to_string()),
                (false, "visual-studio-code".to_string()),
            ]
        );
    }

    #[test]
    fn does_not_confuse_brewfoo_with_brew() {
        assert!(parse_brewfile_directive("brewfoo \"x\"", "brew").is_none());
    }
}
