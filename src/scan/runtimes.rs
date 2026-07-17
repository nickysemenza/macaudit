//! RuntimesScanner — detects language version managers (nvm/fnm/volta/mise/
//! asdf/pyenv/rustup) by their well-known directories, lists installed
//! toolchain versions with per-version on-disk size, flags when the same
//! runtime is managed by more than one tool, and flags rustup toolchains
//! that aren't the active default.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde_json::json;

use crate::model::{Finding, FindingKind, ScannerId, Severity};
use crate::scan::sizing::du_blocks;
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct RuntimesScanner;

#[async_trait]
impl Scanner for RuntimesScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Runtimes
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        let mut runtime_managers: HashMap<String, HashSet<String>> = HashMap::new();

        // nvm: ~/.nvm/versions/node/vX.Y.Z
        let nvm_dir = ctx.paths.expand("~/.nvm");
        if nvm_dir.is_dir() {
            scan_versions_dir(
                &ctx,
                "nvm",
                "node",
                &nvm_dir.join("versions/node"),
                &mut runtime_managers,
            )
            .await;
        }

        // fnm: ~/.fnm/node-versions/<v> or ~/Library/Application Support/fnm/node-versions/<v>
        for cand in [
            ctx.paths.expand("~/.fnm"),
            ctx.paths.expand("~/Library/Application Support/fnm"),
        ] {
            if cand.is_dir() {
                scan_versions_dir(
                    &ctx,
                    "fnm",
                    "node",
                    &cand.join("node-versions"),
                    &mut runtime_managers,
                )
                .await;
                break;
            }
        }

        // volta: ~/.volta/tools/image/node/<v>
        let volta_dir = ctx.paths.expand("~/.volta");
        if volta_dir.is_dir() {
            scan_versions_dir(
                &ctx,
                "volta",
                "node",
                &volta_dir.join("tools/image/node"),
                &mut runtime_managers,
            )
            .await;
        }

        // mise: ~/.local/share/mise/installs/<runtime>/<v> (or legacy ~/.mise)
        for cand in [
            ctx.paths.expand("~/.local/share/mise"),
            ctx.paths.expand("~/.mise"),
        ] {
            if cand.is_dir() {
                scan_multi_runtime_manager(
                    &ctx,
                    "mise",
                    &cand.join("installs"),
                    &mut runtime_managers,
                )
                .await;
                break;
            }
        }

        // asdf: ~/.asdf/installs/<plugin>/<v>
        let asdf_dir = ctx.paths.expand("~/.asdf");
        if asdf_dir.is_dir() {
            scan_multi_runtime_manager(
                &ctx,
                "asdf",
                &asdf_dir.join("installs"),
                &mut runtime_managers,
            )
            .await;
        }

        // pyenv: ~/.pyenv/versions/<v>
        let pyenv_dir = ctx.paths.expand("~/.pyenv");
        if pyenv_dir.is_dir() {
            scan_versions_dir(
                &ctx,
                "pyenv",
                "python",
                &pyenv_dir.join("versions"),
                &mut runtime_managers,
            )
            .await;
        }

        // rustup: ~/.rustup/toolchains/<name>, cross-referenced against
        // `rustup toolchain list` for the active default.
        scan_rustup(&ctx, &mut runtime_managers).await;

        // Flag runtimes managed by more than one tool.
        let mut runtimes: Vec<&String> = runtime_managers.keys().collect();
        runtimes.sort();
        for runtime in runtimes {
            let managers = &runtime_managers[runtime];
            if managers.len() > 1 {
                let mut mgr_list: Vec<&String> = managers.iter().collect();
                mgr_list.sort();
                let mgr_names = mgr_list
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                let key = format!("conflict:{runtime}");
                let finding = Finding::new(
                    FindingKind::RuntimeVersion,
                    &key,
                    format!("Multiple version managers for {runtime}"),
                )
                .detail(format!(
                    "{runtime} is managed by more than one tool ({mgr_names}) — `which {runtime}` \
                     results depend on shell PATH order, which is a common source of confusion."
                ))
                .severity(Severity::Attention)
                .meta(json!({ "runtime": runtime, "managers": mgr_list }));
                ctx.emit(finding).await;
            }
        }

        Ok(())
    }
}

/// List version directories directly under `versions_dir` (each a leaf
/// version like `v18.16.0` or `20.5.0`) and emit one Info finding per
/// version with its on-disk size.
async fn scan_versions_dir(
    ctx: &ScanCtx,
    manager: &str,
    runtime: &str,
    versions_dir: &Path,
    runtime_managers: &mut HashMap<String, HashSet<String>>,
) {
    let Ok(entries) = std::fs::read_dir(versions_dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    paths.sort();
    if paths.is_empty() {
        return;
    }
    runtime_managers
        .entry(runtime.to_string())
        .or_default()
        .insert(manager.to_string());

    for path in paths {
        if ctx.cancelled() {
            break;
        }
        let version = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let size = du_blocks(&path, &|| ctx.token.is_cancelled());
        let key = path.to_string_lossy().to_string();

        let finding = Finding::new(
            FindingKind::RuntimeVersion,
            &key,
            format!("{manager} {runtime} {version}"),
        )
        .detail(format!("{version} — {size} bytes on disk"))
        .path(path.clone())
        .size(size)
        .severity(Severity::Info)
        .meta(json!({
            "manager": manager,
            "runtime": runtime,
            "version": version,
            "size_bytes": size,
        }));
        ctx.emit(finding).await;
    }
}

/// Managers like mise/asdf keep one subdirectory per runtime under
/// `installs/`, each containing its own version directories.
async fn scan_multi_runtime_manager(
    ctx: &ScanCtx,
    manager: &str,
    installs_dir: &Path,
    runtime_managers: &mut HashMap<String, HashSet<String>>,
) {
    let Ok(entries) = std::fs::read_dir(installs_dir) else {
        return;
    };
    let mut runtime_dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    runtime_dirs.sort();
    for rd in runtime_dirs {
        if ctx.cancelled() {
            break;
        }
        let runtime = rd
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        scan_versions_dir(ctx, manager, &runtime, &rd, runtime_managers).await;
    }
}

/// rustup toolchains live under `~/.rustup/toolchains/<name>`. Cross-reference
/// `rustup toolchain list` (best-effort — tolerate failure) to know which one
/// is the active default; every other installed toolchain is flagged as
/// likely-unused cruft.
async fn scan_rustup(ctx: &ScanCtx, runtime_managers: &mut HashMap<String, HashSet<String>>) {
    let rustup_dir = ctx.paths.expand("~/.rustup");
    let toolchains_dir = rustup_dir.join("toolchains");
    let Ok(entries) = std::fs::read_dir(&toolchains_dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    paths.sort();
    if paths.is_empty() {
        return;
    }

    let mut default_map: HashMap<String, bool> = HashMap::new();
    if let Ok(out) = ctx
        .runner
        .run("rustup", &["toolchain", "list"], &ctx.token)
        .await
    {
        if out.success() {
            for line in out.stdout_str().lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let is_default = line.contains("(default)");
                let name = line.replace("(default)", "").trim().to_string();
                default_map.insert(name, is_default);
            }
        }
    }

    runtime_managers
        .entry("rust".to_string())
        .or_default()
        .insert("rustup".to_string());

    let multiple = paths.len() > 1;

    for path in paths {
        if ctx.cancelled() {
            break;
        }
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let size = du_blocks(&path, &|| ctx.token.is_cancelled());
        let is_default = default_map.get(&name).copied();
        // Flag as stale only when we positively know it's not the default and
        // there's more than one toolchain installed (a lone toolchain is fine
        // even if `rustup toolchain list` output couldn't be parsed).
        let stale = multiple && is_default == Some(false);
        let severity = if stale {
            Severity::Attention
        } else {
            Severity::Info
        };

        let key = path.to_string_lossy().to_string();
        let detail = if stale {
            format!("{name} — not the active default toolchain; consider `rustup toolchain uninstall {name}` if unused")
        } else {
            format!("{name} — {size} bytes on disk")
        };

        let finding = Finding::new(
            FindingKind::RuntimeVersion,
            &key,
            format!("rustup rust {name}"),
        )
        .detail(detail)
        .path(path.clone())
        .size(size)
        .severity(severity)
        .meta(json!({
            "manager": "rustup",
            "runtime": "rust",
            "version": name,
            "size_bytes": size,
            "is_default": is_default,
        }));
        ctx.emit(finding).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanEvent;

    fn ctx_with(
        tmp: &tempfile::TempDir,
        mock: crate::runner::MockCommandRunner,
    ) -> (ScanCtx, tokio::sync::mpsc::Receiver<ScanEvent>) {
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let ctx = ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: std::sync::Arc::new(crate::config::Config::default()),
            paths: std::sync::Arc::new(crate::config::Paths::from_home(tmp.path())),
            runner: std::sync::Arc::new(mock),
            current: ScannerId::Runtimes,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        (ctx, rx)
    }

    async fn drain(rx: &mut tokio::sync::mpsc::Receiver<ScanEvent>) -> Vec<crate::model::Finding> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                out.push(*finding);
            }
        }
        out
    }

    fn mk_version_dir(base: &Path, rel: &str) {
        let dir = base.join(rel);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("marker"), b"x").unwrap();
    }

    #[tokio::test]
    async fn detects_nvm_versions_and_conflict_with_fnm() {
        let tmp = tempfile::tempdir().unwrap();
        mk_version_dir(tmp.path(), ".nvm/versions/node/v18.16.0");
        mk_version_dir(tmp.path(), ".nvm/versions/node/v20.5.0");
        mk_version_dir(tmp.path(), ".fnm/node-versions/v20.5.0/installation");

        let mock = crate::runner::MockCommandRunner::new();
        let (ctx, mut rx) = ctx_with(&tmp, mock);

        RuntimesScanner.scan(ctx).await.unwrap();
        let findings = drain(&mut rx).await;

        let nvm_versions: Vec<_> = findings
            .iter()
            .filter(|f| f.meta.get("manager").and_then(|v| v.as_str()) == Some("nvm"))
            .collect();
        assert_eq!(nvm_versions.len(), 2);
        for f in &nvm_versions {
            assert_eq!(f.severity, Severity::Info);
            assert!(f.size_bytes.unwrap() > 0);
        }

        let conflict = findings
            .iter()
            .find(|f| f.title.contains("Multiple version managers"))
            .expect("expected a node conflict finding");
        assert_eq!(conflict.severity, Severity::Attention);
        assert_eq!(conflict.meta["runtime"], "node");
    }

    #[tokio::test]
    async fn detects_mise_multi_runtime_layout() {
        let tmp = tempfile::tempdir().unwrap();
        mk_version_dir(tmp.path(), ".local/share/mise/installs/node/20.5.0");
        mk_version_dir(tmp.path(), ".local/share/mise/installs/python/3.11.4");

        let mock = crate::runner::MockCommandRunner::new();
        let (ctx, mut rx) = ctx_with(&tmp, mock);

        RuntimesScanner.scan(ctx).await.unwrap();
        let findings = drain(&mut rx).await;

        assert!(findings
            .iter()
            .any(|f| f.meta["manager"] == "mise" && f.meta["runtime"] == "node"));
        assert!(findings
            .iter()
            .any(|f| f.meta["manager"] == "mise" && f.meta["runtime"] == "python"));
        // No conflicts expected — each runtime has exactly one manager.
        assert!(!findings
            .iter()
            .any(|f| f.title.contains("Multiple version managers")));
    }

    #[tokio::test]
    async fn flags_non_default_rustup_toolchain() {
        let tmp = tempfile::tempdir().unwrap();
        mk_version_dir(tmp.path(), ".rustup/toolchains/stable-aarch64-apple-darwin");
        mk_version_dir(tmp.path(), ".rustup/toolchains/1.70.0-aarch64-apple-darwin");

        let mock = crate::runner::MockCommandRunner::new().on(
            "rustup",
            &["toolchain", "list"],
            "stable-aarch64-apple-darwin (default)\n1.70.0-aarch64-apple-darwin\n",
        );
        let (ctx, mut rx) = ctx_with(&tmp, mock);

        RuntimesScanner.scan(ctx).await.unwrap();
        let findings = drain(&mut rx).await;

        let default_tc = findings
            .iter()
            .find(|f| f.meta["version"] == "stable-aarch64-apple-darwin")
            .unwrap();
        assert_eq!(default_tc.severity, Severity::Info);

        let stale_tc = findings
            .iter()
            .find(|f| f.meta["version"] == "1.70.0-aarch64-apple-darwin")
            .unwrap();
        assert_eq!(stale_tc.severity, Severity::Attention);
        assert_eq!(stale_tc.meta["is_default"], false);
    }

    #[tokio::test]
    async fn no_managers_present_emits_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = crate::runner::MockCommandRunner::new();
        let (ctx, mut rx) = ctx_with(&tmp, mock);

        RuntimesScanner.scan(ctx).await.unwrap();
        assert!(rx.try_recv().is_err());
    }
}
