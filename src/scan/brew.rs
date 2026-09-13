//! BrewScanner — lane S1.
//!
//! Shells out to `brew` exactly once per subcommand (brew's Ruby startup is
//! ~1s each — see spec §3.2) and builds the formula dependency tree, the
//! outdated set, and the cask → `.app` artifact map entirely in-process:
//!
//! - `brew list --formula --versions` / `brew list --cask --versions` — the
//!   installed inventory + versions.
//! - `brew leaves` — the authoritative "no dependents, user-requested" set.
//! - `brew outdated --json=v2` — formulae/casks with a newer version available.
//! - `brew deps --installed` — declared deps per formula (plain text, portable
//!   across brew versions), used to invert the graph into a `dependents` list.
//! - `brew info --json=v2 --installed --cask` — cask metadata + `artifacts`,
//!   from which `.app` install paths are extracted into `meta.app_paths` so
//!   `correlate.rs` can join them against AppsScanner's Unmanaged bucket.
//!
//! If `brew` is missing or any required call fails, this scanner emits a
//! single Info finding and returns `Ok(())` — a missing Homebrew install is
//! not a scan failure.
//!
//! Implementation contract: depend only on the frozen types (Finding,
//! FindingKind, Remedy, RemedyCommand, Severity, ScanEvent, ScannerId, Scanner,
//! ScanCtx, CommandRunner, Config, Paths). Send Progress/Finding only. Touch
//! only this file and tests/fixtures/brew/.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::runner::CmdOutput;
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct BrewScanner;

/// Run a `brew` subcommand; `None` on spawn failure or nonzero exit — the
/// caller decides whether that means "Homebrew isn't installed".
async fn brew(ctx: &ScanCtx, args: &[&str]) -> Option<CmdOutput> {
    match ctx.runner.run("brew", args, &ctx.token).await {
        Ok(out) if out.success() => Some(out),
        _ => None,
    }
}

async fn emit_brew_not_found(ctx: &ScanCtx) {
    ctx.emit(
        Finding::new(FindingKind::BrewFormula, "brew-not-found", "Homebrew not found")
            .detail("`brew` is not installed, not on PATH, or a required command failed; skipping the Homebrew scan.")
            .severity(Severity::Info),
    )
    .await;
}

/// Parse `brew list --formula --versions` / `brew list --cask --versions`
/// output: one `<name> <version...>` per line. The last whitespace-separated
/// token is taken as the installed version (multi-version lines are rare but
/// possible for formulae with several installed versions side by side).
fn parse_name_versions(stdout: &str) -> Vec<(String, String)> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next()?.to_string();
            let version = parts.last().unwrap_or_default().to_string();
            Some((name, version))
        })
        .collect()
}

/// Parse `brew leaves` output: one formula name per line.
fn parse_leaves(stdout: &str) -> BTreeSet<String> {
    stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

#[derive(Debug, Deserialize)]
struct OutdatedRoot {
    #[serde(default)]
    formulae: Vec<OutdatedFormula>,
    #[serde(default)]
    casks: Vec<OutdatedCask>,
}

#[derive(Debug, Deserialize)]
struct OutdatedFormula {
    name: String,
    current_version: String,
}

#[derive(Debug, Deserialize)]
struct OutdatedCask {
    name: String,
    current_version: String,
}

/// Parse plain-text `brew deps --installed` output — one line per installed
/// formula in the form `name: dep1 dep2 …` (deps may be empty) — into a map of
/// formula name → its direct dependencies.
fn parse_deps_plain(stdout: &str) -> BTreeMap<String, Vec<String>> {
    stdout
        .lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            let deps = rest.split_whitespace().map(str::to_string).collect();
            Some((name.to_string(), deps))
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct CaskInfoRoot {
    #[serde(default)]
    casks: Vec<CaskInfo>,
}

#[derive(Debug, Deserialize)]
struct CaskInfo {
    token: String,
    #[serde(default)]
    artifacts: Vec<serde_json::Value>,
}

impl CaskInfo {
    /// Extract `.app` names from the `artifacts` array (each entry may be
    /// `{"app": ["Foo.app"]}` among other artifact kinds we don't care about)
    /// and resolve them to full `/Applications/<name>` paths.
    fn app_paths(&self) -> Vec<String> {
        let mut out = Vec::new();
        for artifact in &self.artifacts {
            if let Some(apps) = artifact.get("app").and_then(|v| v.as_array()) {
                for app in apps {
                    if let Some(name) = app.as_str() {
                        out.push(format!("/Applications/{name}"));
                    }
                }
            }
        }
        out
    }
}

#[async_trait]
impl Scanner for BrewScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Brew
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        // Primary probe: if `brew list --formula` can't run at all, brew isn't
        // usable — emit the single "not found" finding and stop.
        let Some(formula_out) = brew(&ctx, &["list", "--formula", "--versions"]).await else {
            emit_brew_not_found(&ctx).await;
            return Ok(());
        };
        // Auxiliary data. Each degrades to empty if that particular command
        // isn't supported by the installed brew version (e.g. Homebrew 6.x
        // rejects `deps --installed --json`), rather than aborting the scan.
        let cask_out = brew(&ctx, &["list", "--cask", "--versions"]).await;
        let leaves_out = brew(&ctx, &["leaves"]).await;
        let outdated_out = brew(&ctx, &["outdated", "--json=v2"]).await;
        // Plain-text `deps --installed` (lines of `formula: dep1 dep2 …`) is the
        // form supported across brew versions; `--json=v2` is not accepted here.
        let deps_out = brew(&ctx, &["deps", "--installed"]).await;
        let cask_info_out = brew(&ctx, &["info", "--json=v2", "--installed", "--cask"]).await;

        let formulae = parse_name_versions(&formula_out.stdout_str());
        let casks = cask_out
            .as_ref()
            .map(|o| parse_name_versions(&o.stdout_str()))
            .unwrap_or_default();
        let leaves = leaves_out
            .as_ref()
            .map(|o| parse_leaves(&o.stdout_str()))
            .unwrap_or_default();

        let outdated: OutdatedRoot = outdated_out
            .as_ref()
            .and_then(|o| serde_json::from_str(&o.stdout_str()).ok())
            .unwrap_or(OutdatedRoot {
                formulae: Vec::new(),
                casks: Vec::new(),
            });
        let outdated_formulae: BTreeMap<String, String> = outdated
            .formulae
            .into_iter()
            .map(|f| (f.name, f.current_version))
            .collect();
        let outdated_casks: BTreeMap<String, String> = outdated
            .casks
            .into_iter()
            .map(|c| (c.name, c.current_version))
            .collect();

        let deps: BTreeMap<String, Vec<String>> = deps_out
            .as_ref()
            .map(|o| parse_deps_plain(&o.stdout_str()))
            .unwrap_or_default();

        // Invert the dep graph: for every formula, who depends on it.
        let mut dependents: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (name, dep_list) in &deps {
            for dep in dep_list {
                dependents
                    .entry(dep.clone())
                    .or_default()
                    .insert(name.clone());
            }
        }

        let cask_info: CaskInfoRoot = cask_info_out
            .as_ref()
            .and_then(|o| serde_json::from_str(&o.stdout_str()).ok())
            .unwrap_or(CaskInfoRoot { casks: Vec::new() });
        let cask_app_paths: BTreeMap<String, Vec<String>> = cask_info
            .casks
            .iter()
            .map(|c| (c.token.clone(), c.app_paths()))
            .collect();

        let total = (formulae.len() + casks.len()) as u64;
        let mut done = 0u64;

        for (name, version) in &formulae {
            if ctx.cancelled() {
                break;
            }
            done += 1;
            ctx.progress(format!("brew formula {name}"), done, Some(total))
                .await;

            let is_leaf = leaves.contains(name);
            let deps_list: Vec<String> = deps.get(name).cloned().unwrap_or_default();
            let dependents_list: Vec<String> = dependents
                .get(name)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect();
            let is_outdated = outdated_formulae.contains_key(name);
            let current_version = outdated_formulae.get(name).cloned();

            let mut finding = Finding::new(FindingKind::BrewFormula, name, name.clone())
                .detail(format!(
                    "{} — {}",
                    if is_leaf { "leaf" } else { "dependency" },
                    version
                ))
                .severity(if is_outdated {
                    Severity::Attention
                } else {
                    Severity::Info
                })
                .meta(json!({
                    "name": name,
                    "version": version,
                    "is_leaf": is_leaf,
                    "dependencies": deps_list,
                    "dependents": dependents_list,
                    "outdated": is_outdated,
                    "current_version": current_version,
                }));

            if is_outdated {
                finding = finding.remedy(Remedy {
                    label: format!("Upgrade to {}", current_version.clone().unwrap_or_default()),
                    command: RemedyCommand::Shell {
                        program: "brew".to_string(),
                        args: vec!["upgrade".to_string(), name.clone()],
                    },
                    reclaims_bytes: None,
                    destructive: false,
                    alternative: false,
                    guard: None,
                });
            }

            ctx.emit(finding).await;
        }

        for (token, version) in &casks {
            if ctx.cancelled() {
                break;
            }
            done += 1;
            ctx.progress(format!("brew cask {token}"), done, Some(total))
                .await;

            let is_outdated = outdated_casks.contains_key(token);
            let current_version = outdated_casks.get(token).cloned();
            let app_paths = cask_app_paths.get(token).cloned().unwrap_or_default();

            let mut finding = Finding::new(FindingKind::BrewCask, token, token.clone())
                .detail(format!("cask — {version}"))
                .severity(if is_outdated {
                    Severity::Attention
                } else {
                    Severity::Info
                })
                .meta(json!({
                    "token": token,
                    "name": token,
                    "version": version,
                    "app_paths": app_paths,
                    "outdated": is_outdated,
                    "current_version": current_version,
                }));

            if is_outdated {
                finding = finding.remedy(Remedy {
                    label: format!("Upgrade to {}", current_version.clone().unwrap_or_default()),
                    command: RemedyCommand::Shell {
                        program: "brew".to_string(),
                        args: vec!["upgrade".to_string(), "--cask".to_string(), token.clone()],
                    },
                    reclaims_bytes: None,
                    destructive: false,
                    alternative: false,
                    guard: None,
                });
            }

            ctx.emit(finding).await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanEvent;
    use crate::runner::MockCommandRunner;

    fn mock_full() -> MockCommandRunner {
        MockCommandRunner::new()
            .on("brew", &["list", "--formula", "--versions"], "wget 1.21.4\nripgrep 14.1.0\n")
            .on("brew", &["list", "--cask", "--versions"], "visual-studio-code 1.85.0\nslack 4.35.0\n")
            .on("brew", &["leaves"], "ripgrep\n")
            .on(
                "brew",
                &["outdated", "--json=v2"],
                r#"{
                  "formulae": [
                    {"name": "wget", "installed_versions": ["1.21.3"], "current_version": "1.21.4", "pinned": false, "pinned_version": null}
                  ],
                  "casks": [
                    {"name": "slack", "installed_versions": "4.35.0", "current_version": "4.36.0"}
                  ]
                }"#,
            )
            .on(
                "brew",
                &["deps", "--installed"],
                "wget: libidn2 openssl@3\nlibidn2: \nopenssl@3: \nripgrep: pcre2\npcre2: \n",
            )
            .on(
                "brew",
                &["info", "--json=v2", "--installed", "--cask"],
                r#"{
                  "formulae": [],
                  "casks": [
                    {
                      "token": "visual-studio-code",
                      "full_token": "visual-studio-code",
                      "name": ["Visual Studio Code"],
                      "version": "1.85.0",
                      "artifacts": [
                        {"app": ["Visual Studio Code.app"]},
                        {"binary": "code"}
                      ]
                    },
                    {
                      "token": "slack",
                      "full_token": "slack",
                      "name": ["Slack"],
                      "version": "4.35.0",
                      "artifacts": [
                        {"app": ["Slack.app"]}
                      ]
                    }
                  ]
                }"#,
            )
    }

    async fn run_scan(mock: MockCommandRunner) -> Vec<Finding> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let ctx = ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: std::sync::Arc::new(crate::config::Config::default()),
            paths: std::sync::Arc::new(crate::config::Paths::from_home("/tmp/fh")),
            runner: std::sync::Arc::new(mock),
            current: ScannerId::Brew,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        BrewScanner.scan(ctx).await.unwrap();
        let mut findings = vec![];
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        findings
    }

    #[tokio::test]
    async fn emits_formula_and_cask_findings() {
        let findings = run_scan(mock_full()).await;
        let formulae: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::BrewFormula)
            .collect();
        let casks: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::BrewCask)
            .collect();
        assert_eq!(formulae.len(), 2);
        assert_eq!(casks.len(), 2);
    }

    #[tokio::test]
    async fn marks_leaves_vs_dependencies() {
        let findings = run_scan(mock_full()).await;
        let ripgrep = findings.iter().find(|f| f.title == "ripgrep").unwrap();
        assert_eq!(ripgrep.meta["is_leaf"], true);

        // libidn2/openssl@3 aren't in the installed-formula list (only wget,
        // ripgrep are), so we just check wget's declared deps are captured.
        let wget = findings.iter().find(|f| f.title == "wget").unwrap();
        assert_eq!(wget.meta["is_leaf"], false);
        assert_eq!(wget.meta["dependencies"], json!(["libidn2", "openssl@3"]));
    }

    #[tokio::test]
    async fn outdated_formula_gets_upgrade_remedy() {
        let findings = run_scan(mock_full()).await;
        let wget = findings.iter().find(|f| f.title == "wget").unwrap();
        assert_eq!(wget.meta["outdated"], true);
        assert!(wget.remedies.iter().any(|r| matches!(
            &r.command,
            RemedyCommand::Shell { program, args } if program == "brew" && args == &vec!["upgrade".to_string(), "wget".to_string()]
        )));
    }

    #[tokio::test]
    async fn outdated_cask_gets_upgrade_remedy() {
        let findings = run_scan(mock_full()).await;
        let slack = findings.iter().find(|f| f.title == "slack").unwrap();
        assert_eq!(slack.meta["outdated"], true);
        assert!(slack.remedies.iter().any(|r| matches!(
            &r.command,
            RemedyCommand::Shell { program, args } if program == "brew" && args == &vec!["upgrade".to_string(), "--cask".to_string(), "slack".to_string()]
        )));
    }

    #[tokio::test]
    async fn cask_records_app_paths() {
        let findings = run_scan(mock_full()).await;
        let vscode = findings
            .iter()
            .find(|f| f.title == "visual-studio-code")
            .unwrap();
        assert_eq!(
            vscode.meta["app_paths"],
            json!(["/Applications/Visual Studio Code.app"])
        );
    }

    #[tokio::test]
    async fn missing_brew_emits_single_info_finding_and_returns_ok() {
        let mock = MockCommandRunner::new().on_fail(
            "brew",
            &["list", "--formula", "--versions"],
            127,
            "brew: command not found",
        );
        let findings = run_scan(mock).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].title, "Homebrew not found");
    }

    #[test]
    fn parse_deps_plain_handles_empty_and_multi() {
        let map = parse_deps_plain("wget: libidn2 openssl@3\nripgrep: \nfoo:\n");
        assert_eq!(map["wget"], vec!["libidn2", "openssl@3"]);
        assert!(map["ripgrep"].is_empty());
        assert!(map["foo"].is_empty());
    }

    /// Regression: a single auxiliary command failing (here `brew deps`, which
    /// Homebrew 6.x rejects with `--json`) must NOT make the scanner declare
    /// Homebrew missing — it degrades and still emits formula findings.
    #[tokio::test]
    async fn auxiliary_command_failure_still_reports_formulae() {
        let mock = mock_full().on_fail("brew", &["deps", "--installed"], 1, "Usage: brew deps");
        let findings = run_scan(mock).await;
        assert!(
            findings.iter().any(|f| f.title == "wget"),
            "should still report formulae when deps fails"
        );
        assert!(
            !findings.iter().any(|f| f.title == "Homebrew not found"),
            "must not claim brew is missing on an auxiliary failure"
        );
    }
}
