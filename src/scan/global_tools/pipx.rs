//! pipx environments: `<pipx_home>/venvs/<name>/pipx_metadata.json` names the
//! main package, its version, the apps it exports and the interpreter the
//! venv was created from. A venv whose interpreter is gone (a removed
//! Homebrew python@3.X) is Broken. Launchers are the `~/.local/bin/<app>`
//! symlinks that resolve *into this venv*; a launcher of the same name that
//! points elsewhere (uv's copy of the same tool) is foreign and never
//! touched.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::launchers;
use super::pymeta::pyvenv_cfg;
use super::shellpath;
use super::types::*;
use super::util::{bounded_size, file_name, list_dir, read_json};
use super::ProbeCtx;

fn venv_dirs(cx: &ProbeCtx) -> Vec<PathBuf> {
    let home = &cx.paths.home;
    let mut candidates = vec![cx.paths.expand(&cx.config.pipx_home).join("venvs")];
    candidates.push(home.join("Library/Application Support/pipx/venvs"));
    candidates.push(home.join(".local/share/pipx/venvs"));
    candidates.dedup();
    candidates.into_iter().filter(|p| p.is_dir()).collect()
}

fn path_value(v: &Value) -> Option<PathBuf> {
    v.get("__Path__")
        .and_then(|p| p.as_str())
        .or_else(|| v.as_str())
        .map(PathBuf::from)
}

/// Does `<venv>/bin/python` resolve to an existing interpreter, and does the
/// `pyvenv.cfg` home still exist?
pub fn interpreter_status(venv: &Path) -> (Option<PathBuf>, bool) {
    let python = venv.join("bin/python");
    let (_, last, exists) = launchers::follow_chain(&python);
    let cfg = pyvenv_cfg(venv);
    let home_ok = cfg
        .get("home")
        .map(|h| Path::new(h).is_dir())
        .unwrap_or(true);
    let target = if python.exists() || python.is_symlink() {
        Some(last)
    } else {
        None
    };
    (target, exists && home_ok)
}

pub fn probe(cx: &ProbeCtx) -> ProbeResult {
    let dirs = venv_dirs(cx);
    if dirs.is_empty() {
        return ProbeResult::absent();
    }
    let local_bin = cx.paths.home.join(".local/bin");
    let pipx_bin = cx
        .shell
        .shell_path
        .as_deref()
        .and_then(|p| shellpath::resolve_first("pipx", p))
        .or_else(|| shellpath::resolve_first("pipx", &cx.shell.process_path))
        .or_else(|| {
            cx.brew_prefix
                .as_ref()
                .map(|b| b.join("bin/pipx"))
                .filter(|p| p.exists())
        });
    let mut installs = Vec::new();
    for venvs in &dirs {
        for venv in list_dir(venvs) {
            if !venv.is_dir() {
                continue;
            }
            let name = file_name(&venv);
            let mut t = ToolInstall::new(Manager::Pipx, venvs.clone(), name.clone());
            t.install_dir = Some(venv.clone());
            let meta = read_json(&venv.join("pipx_metadata.json"));
            let main = meta.as_ref().and_then(|m| m.get("main_package"));
            let mut apps: Vec<String> = Vec::new();
            match main {
                Some(main) => {
                    t.version = main
                        .get("package_version")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    if let Some(pkg) = main.get("package").and_then(|v| v.as_str()) {
                        t.name = pkg.to_string();
                    }
                    apps = main
                        .get("apps")
                        .and_then(|a| a.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    let app_paths: Vec<PathBuf> = main
                        .get("app_paths")
                        .and_then(|a| a.as_array())
                        .map(|a| a.iter().filter_map(path_value).collect())
                        .unwrap_or_default();
                    for app in &apps {
                        let target = app_paths.iter().find(|p| file_name(p) == *app).cloned();
                        t.commands.push(DeclaredCommand {
                            name: app.clone(),
                            declared_target: target.map(|p| p.display().to_string()),
                        });
                    }
                    t.evidence(
                        "manager_metadata",
                        venv.join("pipx_metadata.json").display().to_string(),
                        format!(
                            "pipx venv {} ({})",
                            t.name,
                            t.version.as_deref().unwrap_or("no version")
                        ),
                        Confidence::High,
                    );
                }
                None => t
                    .completeness
                    .add("pipx_metadata.json missing or unreadable"),
            }
            let source_interp = meta
                .as_ref()
                .and_then(|m| m.get("source_interpreter"))
                .and_then(path_value);
            let python_version = meta
                .as_ref()
                .and_then(|m| m.get("python_version"))
                .and_then(|v| v.as_str())
                .map(|v| v.trim_start_matches("Python ").to_string());
            let (resolved, ok) = interpreter_status(&venv);
            t.runtime = Some(RuntimeRef {
                kind: "python",
                path: resolved.clone().or(source_interp.clone()),
                version: python_version,
                exists: Some(ok),
                source: "<venv>/bin/python symlink chain + pyvenv.cfg home".into(),
            });
            if !ok {
                t.evidence(
                    "interpreter",
                    venv.join("bin/python").display().to_string(),
                    format!(
                        "interpreter {} no longer exists",
                        resolved
                            .or(source_interp.clone())
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "(unknown)".into())
                    ),
                    Confidence::High,
                );
            }
            // Launchers in ~/.local/bin that resolve into this venv.
            for app in &apps {
                let link = local_bin.join(app);
                if let Some(mut l) = launchers::inspect(&link) {
                    let (_, last, _) = launchers::follow_chain(&link);
                    if launchers::under(&last, &venv)
                        || l.target
                            .as_deref()
                            .map(|t| launchers::under(t, &venv))
                            .unwrap_or(false)
                    {
                        l.owner = Ownership::ThisInstall;
                        t.launchers.push(l);
                    } else {
                        t.foreign_launchers.push(l);
                    }
                }
            }
            t.removal.native = Some(NativeCommand {
                program: pipx_bin
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "pipx".into()),
                args: vec!["uninstall".into(), t.name.clone()],
                program_path: pipx_bin.clone(),
            });
            if pipx_bin.is_none() {
                t.removal.refusals.push("pipx is not on the login-shell or process PATH; `pipx uninstall` cannot be verified to exist".into());
                t.removal.native = None;
                t.removal.follow_up.push(format!(
                    "the venv directory {} remains until pipx is available",
                    venv.display()
                ));
            }
            t.removal.launcher_only = t.launchers.iter().map(|l| l.path.clone()).collect();
            if !t.foreign_launchers.is_empty() {
                t.removal.follow_up.push(format!(
                    "{} launcher(s) of the same name belong to another installation and are preserved",
                    t.foreign_launchers.len()
                ));
            }
            t.size_bytes = bounded_size(&venv);
            t.manager_extra = json!({
                "source_interpreter": source_interp,
                "injected": meta.as_ref().and_then(|m| m.get("injected_packages")).and_then(|i| i.as_object()).map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
                "apps_of_dependencies": main.and_then(|m| m.get("apps_of_dependencies")).cloned().unwrap_or(json!([])),
                "pipx": pipx_bin,
            });
            installs.push(t);
        }
    }
    ProbeResult {
        installs,
        status: Some(ManagerStatus::Ok {
            detail: Some(format!("{} venv dir(s)", dirs.len())),
        }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{Paths, ToolsConfig};
    use crate::scan::global_tools::npm::tests::cx;
    use crate::scan::global_tools::shellpath::ShellPath;
    use std::os::unix::fs::{symlink, PermissionsExt};

    /// A pipx venv `name` created from `interp`; `valid` controls whether the
    /// interpreter exists. Mirrors the real `pipx_metadata.json` shape.
    pub(crate) fn mk_pipx_venv(
        home: &Path,
        name: &str,
        version: &str,
        apps: &[&str],
        interp: &Path,
        valid: bool,
    ) -> PathBuf {
        let venv = home.join(".local/pipx/venvs").join(name);
        std::fs::create_dir_all(venv.join("bin")).unwrap();
        if valid {
            std::fs::create_dir_all(interp.parent().unwrap()).unwrap();
            std::fs::write(interp, "").unwrap();
        }
        symlink(interp, venv.join("bin/python")).unwrap();
        std::fs::write(
            venv.join("pyvenv.cfg"),
            format!(
                "home = {}\nversion = 3.13.7\n",
                interp.parent().unwrap().display()
            ),
        )
        .unwrap();
        let app_paths: Vec<String> = apps
            .iter()
            .map(|a| {
                format!(
                    r#"{{"__Path__": "{}", "__type__": "Path"}}"#,
                    venv.join("bin").join(a).display()
                )
            })
            .collect();
        for a in apps {
            std::fs::write(venv.join("bin").join(a), "#!/x\n").unwrap();
            std::fs::set_permissions(
                venv.join("bin").join(a),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        std::fs::write(
            venv.join("pipx_metadata.json"),
            format!(
                r#"{{"main_package": {{"package": "{name}", "package_version": "{version}", "apps": [{apps}], "app_paths": [{paths}], "apps_of_dependencies": []}},
                    "injected_packages": {{}}, "python_version": "Python 3.13.7",
                    "source_interpreter": {{"__Path__": "{interp}", "__type__": "Path"}}, "pipx_metadata_version": "0.12"}}"#,
                apps = apps.iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(", "),
                paths = app_paths.join(", "),
                interp = interp.display(),
            ),
        )
        .unwrap();
        venv
    }

    #[test]
    fn metadata_paths_interpreter_validity_and_foreign_launcher_preserved() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let paths = Paths::from_home(home);
        let good_py = home.join("py/3.14/bin/python3.14");
        let gone_py = home.join("py/3.13/bin/python3.13");
        let lint = mk_pipx_venv(
            home,
            "ansible-lint",
            "26.6.0",
            &["ansible-lint"],
            &good_py,
            true,
        );
        let proxy = mk_pipx_venv(home, "mcp-proxy", "0.11.0", &["mcp-proxy"], &gone_py, false);
        let local_bin = home.join(".local/bin");
        std::fs::create_dir_all(&local_bin).unwrap();
        symlink(
            lint.join("bin/ansible-lint"),
            local_bin.join("ansible-lint"),
        )
        .unwrap();
        // mcp-proxy's launcher belongs to uv, not to the pipx venv.
        let uv_bin = home.join(".local/share/uv/tools/mcp-proxy/bin/mcp-proxy");
        std::fs::create_dir_all(uv_bin.parent().unwrap()).unwrap();
        std::fs::write(&uv_bin, "").unwrap();
        symlink(&uv_bin, local_bin.join("mcp-proxy")).unwrap();
        let _ = &proxy;

        let config = ToolsConfig::default();
        let shell = ShellPath {
            process_path: vec![home.join("bin")],
            ..Default::default()
        };
        std::fs::create_dir_all(home.join("bin")).unwrap();
        let pipx = home.join("bin/pipx");
        std::fs::write(&pipx, "").unwrap();
        std::fs::set_permissions(&pipx, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = probe(&cx(&paths, &config, &shell, None));
        let lint = r
            .installs
            .iter()
            .find(|t| t.name == "ansible-lint")
            .unwrap();
        assert_eq!(lint.version.as_deref(), Some("26.6.0"));
        assert_eq!(lint.runtime.as_ref().unwrap().exists, Some(true));
        assert_eq!(lint.launchers.len(), 1);
        assert_eq!(
            lint.removal.native.as_ref().unwrap().program,
            pipx.display().to_string()
        );
        assert_eq!(
            lint.removal.launcher_only,
            vec![local_bin.join("ansible-lint")]
        );

        let mp = r.installs.iter().find(|t| t.name == "mcp-proxy").unwrap();
        assert_eq!(mp.runtime.as_ref().unwrap().exists, Some(false));
        assert!(mp.evidence.iter().any(|e| e.kind == "interpreter"));
        assert!(mp.launchers.is_empty());
        assert_eq!(mp.foreign_launchers.len(), 1);
        assert!(mp.removal.launcher_only.is_empty());
        assert!(mp.removal.follow_up.iter().any(|f| f.contains("preserved")));
    }

    #[test]
    fn without_pipx_binary_no_native_remedy() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let paths = Paths::from_home(home);
        let py = home.join("py/bin/python3");
        mk_pipx_venv(home, "rendercv", "1.17.0", &["rendercv"], &py, true);
        let config = ToolsConfig::default();
        let shell = ShellPath::default();
        let r = probe(&cx(&paths, &config, &shell, None));
        let t = &r.installs[0];
        assert!(t.removal.native.is_none());
        assert!(!t.removal.refusals.is_empty());
    }
}
