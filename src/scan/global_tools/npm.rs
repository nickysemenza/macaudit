//! npm globals. Prefixes are discovered from the filesystem first (Homebrew,
//! `/usr/local`, `~/.npm-global`, every version-manager node, configured
//! extras) and `npm prefix -g` is only one more candidate: on the audited Mac
//! it pointed at pnpm's managed node, not at Homebrew's packages.
//!
//! Per prefix: `lib/node_modules/{*,@scope/*}/package.json` gives name,
//! version and declared `bin`s; `bin/*` symlinks whose target is under
//! `lib/node_modules/<pkg>/` are that package's launchers — dangling ones are
//! reported as Broken and get a launcher-only removal (the package is gone).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::launchers::{self, normalize};
use super::types::*;
use super::util::{bounded_size, file_name, list_dir, package_bins, read_json};
use super::ProbeCtx;

/// Well-known global prefixes (each must contain `lib/node_modules`).
pub fn candidate_prefixes(cx: &ProbeCtx) -> Vec<PathBuf> {
    let home = &cx.paths.home;
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    if let Some(b) = &cx.brew_prefix {
        push(b.clone());
    }
    push(PathBuf::from("/usr/local"));
    push(home.join(".npm-global"));
    push(home.join(".npm-packages"));
    for node_dir in [
        home.join("Library/pnpm/nodejs"),
        home.join(".nvm/versions/node"),
        home.join(".volta/tools/image/node"),
        home.join(".local/share/mise/installs/node"),
        home.join(".asdf/installs/nodejs"),
    ] {
        for v in list_dir(&node_dir) {
            if v.is_dir() && !v.is_symlink() {
                push(v);
            }
        }
    }
    for fnm in [
        home.join(".fnm/node-versions"),
        home.join("Library/Application Support/fnm/node-versions"),
    ] {
        for v in list_dir(&fnm) {
            push(v.join("installation"));
        }
    }
    for extra in &cx.config.extra_npm_prefixes {
        push(cx.paths.expand(extra));
    }
    for extra in &cx.extra_npm_prefixes {
        push(extra.clone());
    }
    out.into_iter()
        .filter(|p| p.join("lib/node_modules").is_dir())
        .collect()
}

/// Package directories under `lib/node_modules`, scoped packages included.
fn package_dirs(node_modules: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for entry in list_dir(node_modules) {
        let name = file_name(&entry);
        if name.starts_with('.') || !entry.is_dir() {
            continue;
        }
        if name.starts_with('@') {
            for sub in list_dir(&entry) {
                if sub.is_dir() {
                    out.push((format!("{name}/{}", file_name(&sub)), sub));
                }
            }
        } else {
            out.push((name, entry));
        }
    }
    out
}

/// `bin/<cmd> -> ../lib/node_modules/<pkg>/…` → (cmd, pkg, launcher).
fn bin_links(prefix: &Path, node_modules: &Path) -> Vec<(String, Launcher)> {
    let bin = prefix.join("bin");
    let mut out = Vec::new();
    for entry in list_dir(&bin) {
        let Ok(meta) = std::fs::symlink_metadata(&entry) else {
            continue;
        };
        if !meta.file_type().is_symlink() {
            continue;
        }
        let Some(target) = launchers::read_link_abs(&entry) else {
            continue;
        };
        if !launchers::under(&target, node_modules) {
            continue;
        }
        let rel = normalize(&target);
        let rel = rel.strip_prefix(normalize(node_modules)).unwrap_or(&rel);
        let mut comps = rel.components().filter_map(|c| c.as_os_str().to_str());
        let Some(first) = comps.next() else { continue };
        let pkg = if first.starts_with('@') {
            match comps.next() {
                Some(second) => format!("{first}/{second}"),
                None => continue,
            }
        } else {
            first.to_string()
        };
        if let Some(l) = launchers::inspect(&entry) {
            out.push((pkg, l));
        }
    }
    out
}

pub fn probe(cx: &ProbeCtx) -> ProbeResult {
    let prefixes = candidate_prefixes(cx);
    if prefixes.is_empty() {
        return ProbeResult::absent();
    }
    let mut installs = Vec::new();
    let mut scanned: Vec<String> = Vec::new();
    for prefix in &prefixes {
        let node_modules = prefix.join("lib/node_modules");
        scanned.push(prefix.display().to_string());
        let root = node_modules.clone();
        let mut links_by_pkg: BTreeMap<String, Vec<Launcher>> = BTreeMap::new();
        for (pkg, l) in bin_links(prefix, &node_modules) {
            links_by_pkg.entry(pkg).or_default().push(l);
        }
        let node = prefix.join("bin/node");
        let npm_program = prefix.join("bin/npm");
        for (name, dir) in package_dirs(&node_modules) {
            let mut t = ToolInstall::new(Manager::Npm, root.clone(), name.clone());
            t.install_dir = Some(dir.clone());
            t.runtime = Some(RuntimeRef {
                kind: "node",
                path: Some(node.clone()),
                version: None,
                exists: Some(node.exists()),
                source: "<prefix>/bin/node".into(),
            });
            match read_json(&dir.join("package.json")) {
                Some(pkg) => {
                    t.version = pkg
                        .get("version")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    for (cmd, target) in package_bins(&pkg, &name) {
                        t.commands.push(DeclaredCommand {
                            name: cmd,
                            declared_target: Some(target),
                        });
                    }
                    t.evidence(
                        "manager_metadata",
                        dir.join("package.json").display().to_string(),
                        format!(
                            "npm package {name} {}",
                            t.version.as_deref().unwrap_or("(no version)")
                        ),
                        Confidence::High,
                    );
                }
                None => t.completeness.add("package.json missing or unreadable"),
            }
            let mut ls = links_by_pkg.remove(&name).unwrap_or_default();
            for l in &mut ls {
                l.owner = Ownership::ThisInstall;
            }
            t.launchers = ls;
            if matches!(name.as_str(), "npm" | "corepack") {
                t.protected = Some("bundled with node; managed by the node installation".into());
            } else {
                t.removal.native = Some(NativeCommand {
                    program: if npm_program.exists() {
                        npm_program.display().to_string()
                    } else {
                        "npm".into()
                    },
                    args: if npm_program.exists() {
                        vec!["uninstall".into(), "-g".into(), name.clone()]
                    } else {
                        vec![
                            "uninstall".into(),
                            "-g".into(),
                            "--prefix".into(),
                            prefix.display().to_string(),
                            name.clone(),
                        ]
                    },
                    program_path: npm_program.exists().then(|| npm_program.clone()),
                });
                t.removal.launcher_only = t.launchers.iter().map(|l| l.path.clone()).collect();
                t.removal.follow_up.push(
                    "a later `npm install -g` of this package recreates its launchers".into(),
                );
            }
            t.size_bytes = bounded_size(&dir);
            t.manager_extra = json!({ "prefix": prefix, "npm": npm_program.exists().then(|| npm_program.clone()) });
            installs.push(t);
        }
        // Launchers whose package directory is gone: broken, launcher-only.
        for (pkg, ls) in links_by_pkg {
            let mut t = ToolInstall::new(Manager::Npm, root.clone(), pkg.clone());
            t.install_dir = Some(node_modules.join(&pkg));
            t.completeness.add(format!(
                "package directory {} is missing; only launchers remain",
                pkg
            ));
            t.evidence(
                "launcher",
                prefix.join("bin").display().to_string(),
                format!("{} launcher(s) point into a removed package", ls.len()),
                Confidence::High,
            );
            t.launchers = ls
                .into_iter()
                .map(|mut l| {
                    l.owner = Ownership::ThisInstall;
                    l
                })
                .collect();
            t.removal.launcher_only = t.launchers.iter().map(|l| l.path.clone()).collect();
            t.manager_extra = json!({ "prefix": prefix, "dangling_only": true });
            installs.push(t);
        }
    }
    ProbeResult {
        installs,
        status: Some(ManagerStatus::Ok {
            detail: Some(format!("prefixes: {}", scanned.join(", "))),
        }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{Paths, ToolsConfig};
    use crate::scan::global_tools::shellpath::ShellPath;
    use std::os::unix::fs::{symlink, PermissionsExt};

    /// A Homebrew-like prefix: `@openai/codex` and `wasm-pack` installed,
    /// `npm` bundled, and dangling `pn`/`pnpx` links from a removed pnpm.
    pub(crate) fn mk_prefix(prefix: &Path) {
        let nm = prefix.join("lib/node_modules");
        for (name, ver, bin) in [
            ("@openai/codex", "0.118.0", r#"{"codex": "bin/codex.js"}"#),
            ("wasm-pack", "0.13.1", r#""run.js""#),
            ("npm", "11.19.0", r#"{"npm": "bin/npm-cli.js"}"#),
        ] {
            let dir = nm.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("package.json"),
                format!(r#"{{"name": "{name}", "version": "{ver}", "bin": {bin}}}"#),
            )
            .unwrap();
        }
        std::fs::create_dir_all(nm.join("@openai/codex/bin")).unwrap();
        for target in [
            nm.join("@openai/codex/bin/codex.js"),
            nm.join("wasm-pack/run.js"),
        ] {
            std::fs::write(&target, "#!/usr/bin/env node\n").unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let bin = prefix.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        symlink(
            "../lib/node_modules/@openai/codex/bin/codex.js",
            bin.join("codex"),
        )
        .unwrap();
        symlink(
            "../lib/node_modules/wasm-pack/run.js",
            bin.join("wasm-pack"),
        )
        .unwrap();
        symlink("../lib/node_modules/pnpm/pn", bin.join("pn")).unwrap();
        symlink("../lib/node_modules/pnpm/pnpx", bin.join("pnpx")).unwrap();
        std::fs::write(bin.join("node"), "").unwrap();
        std::fs::write(bin.join("npm"), "").unwrap();
        // An unrelated Homebrew link in the same bin dir must be ignored.
        symlink("../Cellar/ripgrep/14.1.0/bin/rg", bin.join("rg")).unwrap();
    }

    pub(crate) fn cx<'a>(
        paths: &'a Paths,
        config: &'a ToolsConfig,
        shell: &'a ShellPath,
        brew: Option<PathBuf>,
    ) -> ProbeCtx<'a> {
        ProbeCtx {
            paths,
            config,
            shell,
            brew_prefix: brew,
            extra_npm_prefixes: Vec::new(),
        }
    }

    #[test]
    fn discovers_scoped_packages_bundled_npm_and_dangling_launchers() {
        let tmp = tempfile::tempdir().unwrap();
        let prefix = tmp.path().join("opt/homebrew");
        mk_prefix(&prefix);
        let paths = Paths::from_home(tmp.path().join("home"));
        let config = ToolsConfig::default();
        let shell = ShellPath::default();
        let r = probe(&cx(&paths, &config, &shell, Some(prefix.clone())));
        let names: Vec<&str> = r.installs.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["@openai/codex", "npm", "wasm-pack", "pnpm"]);

        let codex = &r.installs[0];
        assert_eq!(codex.version.as_deref(), Some("0.118.0"));
        assert_eq!(codex.commands[0].name, "codex");
        assert_eq!(codex.launchers.len(), 1);
        assert_eq!(codex.launchers[0].target_exists, Some(true));
        assert_eq!(codex.launchers[0].owner, Ownership::ThisInstall);
        let native = codex.removal.native.as_ref().unwrap();
        assert_eq!(native.program, prefix.join("bin/npm").display().to_string());
        assert_eq!(native.args, ["uninstall", "-g", "@openai/codex"]);
        assert_eq!(
            codex.identity_key(),
            format!(
                "npm:{}:@openai/codex",
                prefix.join("lib/node_modules").display()
            )
        );

        let npm = &r.installs[1];
        assert!(npm.protected.is_some());
        assert!(npm.removal.native.is_none());

        let pnpm = &r.installs[3];
        assert!(pnpm.version.is_none());
        assert_eq!(pnpm.completeness.level, "partial");
        assert_eq!(pnpm.launchers.len(), 2);
        assert!(pnpm
            .launchers
            .iter()
            .all(|l| l.target_exists == Some(false)));
        assert!(pnpm.removal.native.is_none());
        assert_eq!(pnpm.removal.launcher_only.len(), 2);
    }

    #[test]
    fn absent_without_any_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let config = ToolsConfig::default();
        let shell = ShellPath::default();
        let r = probe(&cx(&paths, &config, &shell, None));
        assert_eq!(r.status, Some(ManagerStatus::Absent));
    }
}
