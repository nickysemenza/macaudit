//! pnpm globals — every layout under `<pnpm_home>/global`, not just the one
//! the current `pnpm` reports:
//!
//! - `global/v<N>/<sha256>` (symlink → `<short>-<ts>-0` real dir), each a
//!   tiny project with `package.json` + `node_modules/`. The symlink path is
//!   the identity root (stable across reinstalls); the real dir is recorded.
//! - `global/<N>` legacy layouts (`package.json` + `node_modules/` directly,
//!   with `node_modules/.modules.yaml` naming the store, virtual store and
//!   the pnpm that wrote it). The current pnpm does not list these, and only
//!   a pnpm of the matching major can remove packages from them.
//!
//! Launchers are `cmd-shim` scripts in `<pnpm_home>/bin` (and, for older
//! installs, directly in `<pnpm_home>`); the file they exec names the
//! package and the layout they belong to. The pnpm package itself is
//! protected; pnpm homes and stores are never removal targets.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde_json::json;

use super::flatyaml;
use super::launchers::{self, normalize};
use super::types::*;
use super::util::{bounded_size, file_name, list_dir, package_bins, read_json};
use super::ProbeCtx;

/// Known pnpm-home shim names that are not tied to a global package.
const HOME_SHIMS: &[&str] = &[
    "pnpm", "pnpx", "pn", "pnx", "npm", "npx", "node", "corepack",
];

struct GlobalRoot {
    /// Identity root (symlink path when the layout uses hashed symlinks).
    root: PathBuf,
    realpath: Option<PathBuf>,
    layout: String,
    /// `.modules.yaml` scalars for legacy layouts.
    modules: BTreeMap<String, String>,
}

fn discover_roots(global: &Path) -> Vec<GlobalRoot> {
    let mut roots = Vec::new();
    for layout_dir in list_dir(global) {
        let layout = file_name(&layout_dir);
        if !layout_dir.is_dir() {
            continue;
        }
        if layout.chars().all(|c| c.is_ascii_digit()) {
            // Legacy: the layout dir *is* the project.
            let modules = std::fs::read_to_string(layout_dir.join("node_modules/.modules.yaml"))
                .map(|t| flatyaml::top_level_scalars(&t))
                .unwrap_or_default();
            if layout_dir.join("package.json").exists() || !modules.is_empty() {
                roots.push(GlobalRoot {
                    root: layout_dir.clone(),
                    realpath: None,
                    layout: format!("legacy-{layout}"),
                    modules,
                });
            }
            continue;
        }
        if !layout.starts_with('v') {
            continue;
        }
        let mut real_targets: Vec<PathBuf> = Vec::new();
        let entries = list_dir(&layout_dir);
        for e in &entries {
            if e.is_symlink() {
                if let Some(t) = launchers::read_link_abs(e) {
                    real_targets.push(t);
                }
            }
        }
        for e in entries {
            if !e.join("package.json").exists() {
                continue;
            }
            let is_link = e.is_symlink();
            let realpath = if is_link {
                launchers::read_link_abs(&e)
            } else {
                None
            };
            if !is_link && real_targets.iter().any(|t| *t == normalize(&e)) {
                continue; // the symlink entry already represents this dir
            }
            roots.push(GlobalRoot {
                root: e,
                realpath,
                layout: layout.clone(),
                modules: BTreeMap::new(),
            });
        }
    }
    roots
}

/// pnpm binaries cached by pnpm's own version manager, newest first:
/// `(version, path)`. Temporary download dirs (`*_tmp_*`) are skipped.
pub fn local_pnpm_binaries(home: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for family in list_dir(&home.join(".tools")) {
        for ver_dir in list_dir(&family) {
            let ver = file_name(&ver_dir);
            if ver.contains("_tmp_") {
                continue;
            }
            let bin = ver_dir.join("bin/pnpm");
            if bin.exists() {
                out.push((ver, bin));
            }
        }
    }
    out.sort_by_key(|a| std::cmp::Reverse(version_key(&a.0)));
    out
}

fn version_key(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit())
        .filter_map(|p| p.parse().ok())
        .collect()
}

fn major(v: &str) -> Option<u64> {
    version_key(v).first().copied()
}

/// The pnpm to use for a legacy layout: same major as `packageManager`
/// (exact version preferred).
fn matching_pnpm(
    local: &[(String, PathBuf)],
    package_manager: Option<&str>,
) -> Option<(String, PathBuf)> {
    let pm_version = package_manager?.strip_prefix("pnpm@")?;
    if let Some(exact) = local.iter().find(|(v, _)| v == pm_version) {
        return Some(exact.clone());
    }
    let want = major(pm_version)?;
    local.iter().find(|(v, _)| major(v) == Some(want)).cloned()
}

/// `(layout, root-or-hash, package)` parsed from a shim target path.
fn parse_shim_ref(target: &Path) -> Option<(String, String, String)> {
    let re = Regex::new(r"global/(v\d+|\d+)/(?:([^/]+)/)?node_modules/((?:@[^/]+/)?[^/]+)").ok()?;
    let s = target.to_string_lossy();
    let cap = re.captures(&s)?;
    let layout = cap[1].to_string();
    let hash = cap
        .get(2)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    // Legacy layouts have no hash segment: `global/5/node_modules/<pkg>`.
    if !layout.starts_with('v') && !hash.is_empty() && hash != "node_modules" {
        // `global/5/<something>/node_modules/...` — not a layout we know.
        return Some((layout, hash, cap[3].to_string()));
    }
    Some((layout, hash, cap[3].to_string()))
}

pub fn probe(cx: &ProbeCtx) -> ProbeResult {
    let home = cx.paths.expand(&cx.config.pnpm_home);
    if !home.is_dir() {
        return ProbeResult::absent();
    }
    let roots = discover_roots(&home.join("global"));
    let local = local_pnpm_binaries(&home);
    let node_current = home.join("nodejs_current/bin/node");
    let pnpm_shim = home.join("bin/pnpm");

    // Shims: <home>/bin/* plus top-level regular files.
    let mut shims: Vec<Launcher> = Vec::new();
    for dir in [home.join("bin"), home.clone()] {
        for entry in list_dir(&dir) {
            if !entry.is_file() && !entry.is_symlink() {
                continue;
            }
            if let Some(l) = launchers::inspect(&entry) {
                if l.kind == LauncherKind::ShShim
                    || (l.kind == LauncherKind::Symlink && dir == home)
                {
                    shims.push(l);
                }
            }
        }
    }

    let mut installs: Vec<ToolInstall> = Vec::new();
    let mut layouts: Vec<String> = Vec::new();
    for gr in &roots {
        if !layouts.contains(&gr.layout) {
            layouts.push(gr.layout.clone());
        }
        let pkg_json = read_json(&gr.root.join("package.json")).unwrap_or(json!({}));
        let deps: Vec<String> = pkg_json
            .get("dependencies")
            .and_then(|d| d.as_object())
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        let legacy = gr.layout.starts_with("legacy");
        let pm = gr.modules.get("packageManager").cloned();
        let store_dir = gr.modules.get("storeDir").cloned();
        let virtual_store = gr.modules.get("virtualStoreDir").map(|v| {
            let p = PathBuf::from(v);
            if p.is_absolute() {
                p
            } else {
                normalize(&gr.root.join("node_modules").join(p))
            }
        });
        let legacy_pnpm = if legacy {
            matching_pnpm(&local, pm.as_deref())
        } else {
            None
        };
        for name in deps {
            let mut t = ToolInstall::new(Manager::Pnpm, gr.root.clone(), name.clone());
            t.layout = Some(gr.layout.clone());
            t.root_realpath = gr.realpath.clone();
            let dir = gr.root.join("node_modules").join(&name);
            t.install_dir = Some(dir.clone());
            let node_path = pkg_json
                .get("dependenciesMeta")
                .and_then(|m| m.get(&name))
                .and_then(|m| m.get("node"))
                .and_then(|n| n.as_str())
                .map(PathBuf::from);
            let (rt_path, source) = match node_path {
                Some(p) => (p, "package.json dependenciesMeta.node"),
                None => (node_current.clone(), "<pnpm_home>/nodejs_current"),
            };
            t.runtime = Some(RuntimeRef {
                kind: "node",
                path: Some(rt_path.clone()),
                version: None,
                exists: Some(rt_path.exists()),
                source: source.into(),
            });
            match read_json(&dir.join("package.json")) {
                Some(p) => {
                    t.version = p
                        .get("version")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    for (cmd, target) in package_bins(&p, &name) {
                        t.commands.push(DeclaredCommand {
                            name: cmd,
                            declared_target: Some(target),
                        });
                    }
                    t.evidence(
                        "manager_metadata",
                        gr.root.join("package.json").display().to_string(),
                        format!("pnpm global ({}) lists {name}", gr.layout),
                        Confidence::High,
                    );
                }
                None => t
                    .completeness
                    .add(format!("node_modules/{name}/package.json unreadable")),
            }
            if name == "pnpm" {
                t.protected = Some("pnpm itself; managed by pnpm's own updater".into());
            } else if legacy {
                match &legacy_pnpm {
                    Some((ver, bin)) => {
                        let mut args = vec![
                            "remove".to_string(),
                            "-g".into(),
                            name.clone(),
                            "--global-dir".into(),
                            gr.root.display().to_string(),
                        ];
                        if let Some(s) = &store_dir {
                            args.push("--store-dir".into());
                            args.push(s.clone());
                        }
                        if let Some(v) = &virtual_store {
                            args.push("--virtual-store-dir".into());
                            args.push(v.display().to_string());
                        }
                        t.removal.native = Some(NativeCommand {
                            program: bin.display().to_string(),
                            args,
                            program_path: Some(bin.clone()),
                        });
                        t.evidence(
                            "manager_metadata",
                            gr.root
                                .join("node_modules/.modules.yaml")
                                .display()
                                .to_string(),
                            format!(
                                "legacy layout written by {} — local pnpm {ver} matches",
                                pm.as_deref().unwrap_or("unknown pnpm")
                            ),
                            Confidence::High,
                        );
                    }
                    None => {
                        t.removal.refusals.push(format!(
                            "no local pnpm matching {} found under {}; only launcher removal is offered",
                            pm.as_deref().unwrap_or("this layout's pnpm"),
                            home.join(".tools").display()
                        ));
                    }
                }
                t.removal.follow_up.push("package files stay under the legacy global dir; never remove global/, store/ or .pnpm wholesale".into());
            } else {
                t.removal.native = Some(NativeCommand {
                    program: if pnpm_shim.exists() {
                        pnpm_shim.display().to_string()
                    } else {
                        "pnpm".into()
                    },
                    args: vec!["remove".into(), "-g".into(), name.clone()],
                    program_path: pnpm_shim.exists().then(|| pnpm_shim.clone()),
                });
            }
            t.size_bytes = bounded_size(&dir);
            t.manager_extra = json!({
                "layout": gr.layout,
                "package_manager": pm,
                "store_dir": store_dir,
                "virtual_store_dir": virtual_store,
                "matching_local_pnpm": legacy_pnpm.as_ref().map(|(_, p)| p.clone()),
            });
            installs.push(t);
        }
    }

    // Attach shims to installs by the file they exec.
    let mut unmatched: Vec<Launcher> = Vec::new();
    for mut shim in shims {
        let name = file_name(&shim.path);
        let Some(target) = shim.target.clone() else {
            unmatched.push(shim);
            continue;
        };
        let Some((layout, hash, pkg)) = parse_shim_ref(&target) else {
            if HOME_SHIMS.contains(&name.as_str()) {
                continue; // node/npm/npx wrappers of the pnpm home
            }
            unmatched.push(shim);
            continue;
        };
        let owner = installs.iter_mut().find(|t| {
            t.name == pkg
                && t.layout
                    .as_deref()
                    .map(|l| l == layout || l == format!("legacy-{layout}"))
                    .unwrap_or(false)
                && (hash.is_empty()
                    || file_name(&t.root) == hash
                    || t.root_realpath
                        .as_ref()
                        .map(|r| file_name(r) == hash)
                        .unwrap_or(false))
        });
        match owner {
            Some(t) => {
                shim.owner = Ownership::ThisInstall;
                t.launchers.push(shim);
            }
            None if pkg == "pnpm" || HOME_SHIMS.contains(&name.as_str()) => {}
            None => {
                shim.owner = Ownership::Unknown;
                unmatched.push(shim);
            }
        }
    }
    // Shims whose package is gone: broken, launcher-only installs.
    let mut orphans: BTreeMap<(PathBuf, String, String), Vec<Launcher>> = BTreeMap::new();
    for shim in unmatched {
        let Some(target) = shim.target.clone() else {
            continue;
        };
        let Some((layout, hash, pkg)) = parse_shim_ref(&target) else {
            continue;
        };
        let root = if hash.is_empty() {
            home.join("global").join(&layout)
        } else {
            home.join("global").join(&layout).join(&hash)
        };
        let label = if layout.starts_with('v') {
            layout
        } else {
            format!("legacy-{layout}")
        };
        orphans.entry((root, label, pkg)).or_default().push(shim);
    }
    for ((root, layout, pkg), ls) in orphans {
        let mut t = ToolInstall::new(Manager::Pnpm, root.clone(), pkg.clone());
        t.layout = Some(layout);
        t.completeness.add(format!(
            "no global package.json lists {pkg}; only launchers remain"
        ));
        t.evidence(
            "launcher",
            home.join("bin").display().to_string(),
            format!("{} shim(s) exec a file under {}", ls.len(), root.display()),
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
        installs.push(t);
    }
    for t in &mut installs {
        if t.protected.is_none() && t.removal.launcher_only.is_empty() {
            t.removal.launcher_only = t.launchers.iter().map(|l| l.path.clone()).collect();
            if !t.launchers.is_empty() {
                t.removal
                    .follow_up
                    .push("a later `pnpm add -g` of this package recreates its shims".into());
            }
        }
    }

    ProbeResult {
        installs,
        status: Some(ManagerStatus::Ok {
            detail: Some(if layouts.is_empty() {
                "no global layouts".into()
            } else {
                format!("layouts: {}", layouts.join(", "))
            }),
        }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{Paths, ToolsConfig};
    use crate::scan::global_tools::launchers::tests::WRANGLER_SHIM;
    use crate::scan::global_tools::npm::tests::cx;
    use crate::scan::global_tools::shellpath::ShellPath;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn shim_for(home: &Path, exec_rel: &str) -> String {
        format!("#!/bin/sh\nbasedir=$(dirname \"$0\")\nexec node \"$basedir/{exec_rel}\" \"$@\"\n# cmd-shim-target={}\n", normalize(&home.join("bin").join(exec_rel)).display())
    }

    /// Mirrors the audited Mac: v11 with wrangler (hash symlink) and pnpm
    /// itself; legacy `global/5` with clawhub + pnpm 11.1.2 written by
    /// pnpm@10.30.0; a `.tools` pnpm 10.30.0; a dangling `clawdhub` shim
    /// for a package no longer listed anywhere.
    pub(crate) fn mk_pnpm_home(home: &Path) {
        let v11 = home.join("global/v11");
        let real = v11.join("11ced-18d4eb84254f02b8-0");
        std::fs::create_dir_all(real.join("node_modules/wrangler/bin")).unwrap();
        std::fs::write(
            real.join("package.json"),
            r#"{"dependencies": {"wrangler": "^4.131.1"}}"#,
        )
        .unwrap();
        std::fs::write(real.join("node_modules/wrangler/package.json"), r#"{"name":"wrangler","version":"4.131.1","bin":{"wrangler":"bin/wrangler.js","wrangler2":"bin/wrangler.js"}}"#).unwrap();
        std::fs::write(real.join("node_modules/wrangler/bin/wrangler.js"), "").unwrap();
        symlink(
            "11ced-18d4eb84254f02b8-0",
            v11.join("48a1e292ffa7f3001739e6a3b1a5fb0f33b31832c7624173b4da21822328e203"),
        )
        .unwrap();
        std::fs::write(v11.join("pnpm-lock.yaml"), "").unwrap();
        let real2 = v11.join("edfe-18d4c7081da95540-0");
        std::fs::create_dir_all(real2.join("node_modules/pnpm")).unwrap();
        std::fs::write(
            real2.join("package.json"),
            r#"{"dependencies": {"pnpm": "12.4.1"}}"#,
        )
        .unwrap();
        std::fs::write(
            real2.join("node_modules/pnpm/package.json"),
            r#"{"name":"pnpm","version":"12.4.1","bin":{"pnpm":"bin/pnpm.cjs"}}"#,
        )
        .unwrap();
        symlink(
            "edfe-18d4c7081da95540-0",
            v11.join("82859147b4fec5e788f016e5ca7f0a52c473a92cd2037e4c8bdc7029c86b60f3"),
        )
        .unwrap();

        let legacy = home.join("global/5");
        std::fs::create_dir_all(legacy.join("node_modules/clawhub/dist")).unwrap();
        std::fs::create_dir_all(legacy.join("node_modules/pnpm")).unwrap();
        std::fs::write(legacy.join("package.json"), r#"{"dependencies": {"clawhub": "0.7.0", "pnpm": "11.1.2"}, "dependenciesMeta": {"pnpm": {"node": "/nonexistent/node"}}}"#).unwrap();
        std::fs::write(legacy.join("node_modules/clawhub/package.json"), r#"{"name":"clawhub","version":"0.7.0","bin":{"clawhub":"dist/cli.js","clawdhub":"dist/cli.js"}}"#).unwrap();
        std::fs::write(legacy.join("node_modules/clawhub/dist/cli.js"), "").unwrap();
        std::fs::write(
            legacy.join("node_modules/pnpm/package.json"),
            r#"{"name":"pnpm","version":"11.1.2"}"#,
        )
        .unwrap();
        std::fs::write(
            legacy.join("node_modules/.modules.yaml"),
            format!("layoutVersion: 5\npackageManager: pnpm@10.30.0\nstoreDir: {}\nvirtualStoreDir: ../.pnpm\n", home.join("store/v10").display()),
        )
        .unwrap();

        let tools = home.join(".tools/@pnpm+macos-arm64/10.30.0/bin");
        std::fs::create_dir_all(&tools).unwrap();
        std::fs::write(tools.join("pnpm"), "").unwrap();
        std::fs::create_dir_all(home.join(".tools/@pnpm+macos-arm64/11.22.0_tmp_1/bin")).unwrap();
        std::fs::write(
            home.join(".tools/@pnpm+macos-arm64/11.22.0_tmp_1/bin/pnpm"),
            "",
        )
        .unwrap();

        let bin = home.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(
            bin.join("wrangler"),
            WRANGLER_SHIM.replace("/home/u", &home.display().to_string()),
        )
        .unwrap();
        std::fs::write(bin.join("wrangler2"), shim_for(home, "../global/v11/48a1e292ffa7f3001739e6a3b1a5fb0f33b31832c7624173b4da21822328e203/node_modules/wrangler/bin/wrangler.js")).unwrap();
        std::fs::write(
            bin.join("pnpm"),
            shim_for(
                home,
                "../global/v11/edfe-18d4c7081da95540-0/node_modules/pnpm/bin/pnpm.cjs",
            ),
        )
        .unwrap();
        std::fs::write(
            bin.join("clawhub"),
            shim_for(home, "../global/5/node_modules/clawhub/dist/cli.js"),
        )
        .unwrap();
        std::fs::write(
            bin.join("ghost"),
            shim_for(home, "../global/5/node_modules/ghost/bin/ghost.js"),
        )
        .unwrap();
        std::fs::create_dir_all(home.join("nodejs/24.15.0/bin")).unwrap();
        std::fs::write(home.join("nodejs/24.15.0/bin/node"), "").unwrap();
        symlink("nodejs/24.15.0", home.join("nodejs_current")).unwrap();
        // Real shims are executable; `which` skips anything that is not.
        for entry in std::fs::read_dir(&bin).unwrap().flatten() {
            std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn discovers_both_layouts_with_stable_identity_and_matching_legacy_pnpm() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let home = tmp.path().join("Library/pnpm");
        mk_pnpm_home(&home);
        let config = ToolsConfig::default();
        let shell = ShellPath::default();
        let r = probe(&cx(&paths, &config, &shell, None));
        let by = |n: &str, layout: &str| {
            r.installs
                .iter()
                .find(|t| t.name == n && t.layout.as_deref() == Some(layout))
                .unwrap_or_else(|| panic!("{n} {layout}"))
        };
        let wrangler = by("wrangler", "v11");
        assert_eq!(wrangler.version.as_deref(), Some("4.131.1"));
        assert!(wrangler
            .root
            .ends_with("48a1e292ffa7f3001739e6a3b1a5fb0f33b31832c7624173b4da21822328e203"));
        assert!(wrangler
            .root_realpath
            .as_ref()
            .unwrap()
            .ends_with("11ced-18d4eb84254f02b8-0"));
        let mut shim_names: Vec<String> = wrangler
            .launchers
            .iter()
            .map(|l| file_name(&l.path))
            .collect();
        shim_names.sort();
        assert_eq!(shim_names, ["wrangler", "wrangler2"]);
        assert_eq!(
            wrangler.removal.native.as_ref().unwrap().args,
            ["remove", "-g", "wrangler"]
        );
        assert_eq!(wrangler.runtime.as_ref().unwrap().exists, Some(true));

        // The real dir is not reported a second time.
        assert_eq!(
            r.installs.iter().filter(|t| t.name == "wrangler").count(),
            1
        );

        let pnpm_v11 = by("pnpm", "v11");
        assert!(pnpm_v11.protected.is_some());
        assert_eq!(pnpm_v11.launchers.len(), 1); // shim resolved via the real dir name

        let claw = by("clawhub", "legacy-5");
        assert_eq!(claw.version.as_deref(), Some("0.7.0"));
        let native = claw.removal.native.as_ref().unwrap();
        assert!(native
            .program
            .ends_with(".tools/@pnpm+macos-arm64/10.30.0/bin/pnpm"));
        assert_eq!(native.args[..3], ["remove", "-g", "clawhub"]);
        assert!(native.args.contains(&"--global-dir".to_string()));
        assert!(native.args.iter().any(|a| a.ends_with("store/v10")));
        assert!(native.args.iter().any(|a| a.ends_with("global/5/.pnpm")));
        assert_eq!(claw.launchers.len(), 1);
        assert_eq!(claw.manager_extra["package_manager"], "pnpm@10.30.0");
        let legacy_pnpm = by("pnpm", "legacy-5");
        assert!(legacy_pnpm.protected.is_some());
        assert_eq!(legacy_pnpm.runtime.as_ref().unwrap().exists, Some(false));

        // A shim for a package no longer listed anywhere: launcher-only.
        let ghost = by("ghost", "legacy-5");
        assert!(ghost.removal.native.is_none());
        assert_eq!(ghost.removal.launcher_only.len(), 1);
        assert_eq!(ghost.completeness.level, "partial");
    }

    #[test]
    fn legacy_without_matching_pnpm_offers_launcher_only() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let home = tmp.path().join("Library/pnpm");
        mk_pnpm_home(&home);
        std::fs::remove_dir_all(home.join(".tools/@pnpm+macos-arm64/10.30.0")).unwrap();
        let config = ToolsConfig::default();
        let shell = ShellPath::default();
        let r = probe(&cx(&paths, &config, &shell, None));
        let claw = r.installs.iter().find(|t| t.name == "clawhub").unwrap();
        assert!(claw.removal.native.is_none());
        assert_eq!(claw.removal.launcher_only.len(), 1);
        assert!(claw.removal.refusals[0].contains("no local pnpm matching pnpm@10.30.0"));
        // `_tmp_` download dirs never count.
        assert!(local_pnpm_binaries(&home).is_empty());
    }

    #[test]
    fn shim_ref_parsing() {
        assert_eq!(
            parse_shim_ref(Path::new(
                "/h/Library/pnpm/global/v11/abc/node_modules/@scope/x/bin/x.js"
            ))
            .unwrap(),
            ("v11".into(), "abc".into(), "@scope/x".into())
        );
        assert_eq!(
            parse_shim_ref(Path::new(
                "/h/Library/pnpm/global/5/node_modules/clawhub/dist/cli.js"
            ))
            .unwrap(),
            ("5".into(), "".into(), "clawhub".into())
        );
        assert!(parse_shim_ref(Path::new("/usr/bin/true")).is_none());
        assert_eq!(
            matching_pnpm(
                &[
                    ("11.2.0".into(), "/a".into()),
                    ("10.30.3".into(), "/b".into())
                ],
                Some("pnpm@10.30.0")
            )
            .unwrap()
            .0,
            "10.30.3"
        );
        assert!(matching_pnpm(&[("11.2.0".into(), "/a".into())], Some("pnpm@10.30.0")).is_none());
    }
}
