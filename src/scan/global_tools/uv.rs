//! uv tools: `<uv_tool_dir>/<name>/uv-receipt.toml` lists the requirements
//! and the entrypoints uv installed (name + absolute `install-path`); the
//! venv's `pyvenv.cfg` names the interpreter. An entrypoint whose launcher
//! is gone is *not* broken — the package still works and
//! `uv tool upgrade` may recreate the launcher — so it is reported as a
//! missing entrypoint with that follow-up.

use std::path::PathBuf;

use serde_json::json;

use super::launchers;
use super::pipx::interpreter_status;
use super::pymeta::{pyvenv_cfg, venv_package_version};
use super::shellpath;
use super::types::*;
use super::util::{bounded_size, file_name, list_dir, read_toml};
use super::ProbeCtx;

pub fn probe(cx: &ProbeCtx) -> ProbeResult {
    let dir = cx.paths.expand(&cx.config.uv_tool_dir);
    if !dir.is_dir() {
        return ProbeResult::absent();
    }
    let uv_bin = cx
        .shell
        .shell_path
        .as_deref()
        .and_then(|p| shellpath::resolve_first("uv", p))
        .or_else(|| shellpath::resolve_first("uv", &cx.shell.process_path))
        .or_else(|| {
            let p = cx.paths.home.join(".local/bin/uv");
            p.exists().then_some(p)
        });
    let mut installs = Vec::new();
    for tool in list_dir(&dir) {
        if !tool.is_dir() || file_name(&tool).starts_with('.') {
            continue;
        }
        let name = file_name(&tool);
        let mut t = ToolInstall::new(Manager::Uv, dir.clone(), name.clone());
        t.install_dir = Some(tool.clone());
        let receipt = read_toml(&tool.join("uv-receipt.toml"));
        let mut missing: Vec<String> = Vec::new();
        let mut requirements: Vec<String> = Vec::new();
        match receipt.as_ref().and_then(|r| r.get("tool")) {
            Some(tool_tbl) => {
                if let Some(reqs) = tool_tbl.get("requirements").and_then(|r| r.as_array()) {
                    for r in reqs {
                        let n = r.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                        let src = r
                            .get("git")
                            .and_then(|g| g.as_str())
                            .map(|g| format!(" @ git+{g}"))
                            .or_else(|| {
                                r.get("specifier")
                                    .and_then(|s| s.as_str())
                                    .map(|s| s.to_string())
                            })
                            .unwrap_or_default();
                        requirements.push(format!("{n}{src}"));
                    }
                }
                if let Some(eps) = tool_tbl.get("entrypoints").and_then(|e| e.as_array()) {
                    for ep in eps {
                        let Some(cmd) = ep.get("name").and_then(|n| n.as_str()) else {
                            continue;
                        };
                        let install_path = ep
                            .get("install-path")
                            .and_then(|p| p.as_str())
                            .map(PathBuf::from);
                        t.commands.push(DeclaredCommand {
                            name: cmd.to_string(),
                            declared_target: install_path.as_ref().map(|p| p.display().to_string()),
                        });
                        match install_path {
                            Some(p) => match launchers::inspect(&p) {
                                Some(mut l) => {
                                    let (_, last, _) = launchers::follow_chain(&p);
                                    if launchers::under(&last, &tool)
                                        || l.target
                                            .as_deref()
                                            .map(|x| launchers::under(x, &tool))
                                            .unwrap_or(false)
                                    {
                                        l.owner = Ownership::ThisInstall;
                                        t.launchers.push(l);
                                    } else {
                                        t.foreign_launchers.push(l);
                                    }
                                }
                                None => missing.push(cmd.to_string()),
                            },
                            None => missing.push(cmd.to_string()),
                        }
                    }
                }
                t.evidence(
                    "manager_metadata",
                    tool.join("uv-receipt.toml").display().to_string(),
                    format!("uv tool receipt: {}", requirements.join(", ")),
                    Confidence::High,
                );
            }
            None => t.completeness.add("uv-receipt.toml missing or unreadable"),
        }
        t.version = venv_package_version(&tool, &name);
        let cfg = pyvenv_cfg(&tool);
        let (resolved, ok) = interpreter_status(&tool);
        t.runtime = Some(RuntimeRef {
            kind: "python",
            path: resolved.or_else(|| cfg.get("home").map(PathBuf::from)),
            version: cfg.get("version_info").cloned(),
            exists: Some(ok),
            source: "pyvenv.cfg home + <venv>/bin/python".into(),
        });
        if !ok {
            t.evidence(
                "interpreter",
                tool.join("pyvenv.cfg").display().to_string(),
                "interpreter home no longer exists",
                Confidence::High,
            );
        }
        if !missing.is_empty() {
            t.removal.follow_up.push(format!(
                "entrypoint launcher(s) missing: {} — `uv tool upgrade {name}` or a reinstall may recreate them",
                missing.join(", ")
            ));
        }
        t.removal.native = Some(NativeCommand {
            program: uv_bin
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "uv".into()),
            args: vec!["tool".into(), "uninstall".into(), name.clone()],
            program_path: uv_bin.clone(),
        });
        if uv_bin.is_none() {
            t.removal.native = None;
            t.removal
                .refusals
                .push("uv is not on the login-shell or process PATH".into());
        }
        t.removal.launcher_only = t.launchers.iter().map(|l| l.path.clone()).collect();
        t.size_bytes = bounded_size(&tool);
        t.manager_extra = json!({
            "requirements": requirements,
            "entrypoints_missing": missing,
            "uv": uv_bin,
        });
        installs.push(t);
    }
    ProbeResult {
        installs,
        status: Some(ManagerStatus::Ok { detail: None }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{Paths, ToolsConfig};
    use crate::scan::global_tools::npm::tests::cx;
    use crate::scan::global_tools::shellpath::ShellPath;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;

    /// Mirrors the audited Mac's `mcp-proxy` uv tool: two entrypoints, one
    /// launcher present in ~/.local/bin, one removed.
    pub(crate) fn mk_uv_tool(
        home: &Path,
        name: &str,
        version: &str,
        entrypoints: &[(&str, bool)],
        interp_home: &Path,
    ) -> PathBuf {
        let tool = home.join(".local/share/uv/tools").join(name);
        let site = tool.join("lib/python3.14/site-packages");
        std::fs::create_dir_all(tool.join("bin")).unwrap();
        std::fs::create_dir_all(&site).unwrap();
        std::fs::create_dir_all(interp_home).unwrap();
        std::fs::write(interp_home.join("python3.14"), "").unwrap();
        symlink(interp_home.join("python3.14"), tool.join("bin/python")).unwrap();
        std::fs::write(
            tool.join("pyvenv.cfg"),
            format!(
                "home = {}\nuv = 0.11.26\nversion_info = 3.14.6\n",
                interp_home.display()
            ),
        )
        .unwrap();
        std::fs::create_dir_all(site.join(format!("{name}-{version}.dist-info"))).unwrap();
        std::fs::write(
            site.join(format!("{name}-{version}.dist-info/METADATA")),
            format!("Name: {name}\nVersion: {version}\n\n"),
        )
        .unwrap();
        let local_bin = home.join(".local/bin");
        std::fs::create_dir_all(&local_bin).unwrap();
        let mut eps = String::new();
        for (ep, present) in entrypoints {
            std::fs::write(tool.join("bin").join(ep), "#!/x\n").unwrap();
            std::fs::set_permissions(
                tool.join("bin").join(ep),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            if *present {
                symlink(tool.join("bin").join(ep), local_bin.join(ep)).unwrap();
            }
            eps.push_str(&format!(
                "    {{ name = \"{ep}\", install-path = \"{}\", from = \"{name}\" }},\n",
                local_bin.join(ep).display()
            ));
        }
        std::fs::write(
            tool.join("uv-receipt.toml"),
            format!("[tool]\nrequirements = [{{ name = \"{name}\", git = \"https://github.com/x/{name}\" }}]\nentrypoints = [\n{eps}]\n"),
        )
        .unwrap();
        tool
    }

    #[test]
    fn receipt_entrypoints_missing_is_not_broken() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let paths = Paths::from_home(home);
        mk_uv_tool(
            home,
            "mcp-proxy",
            "0.12.0",
            &[("mcp-proxy", true), ("mcp-reverse-proxy", false)],
            &home.join("opt/python@3.14/bin"),
        );
        let config = ToolsConfig::default();
        let shell = ShellPath::default();
        let r = probe(&cx(&paths, &config, &shell, None));
        assert_eq!(r.installs.len(), 1);
        let t = &r.installs[0];
        assert_eq!(t.version.as_deref(), Some("0.12.0"));
        assert_eq!(t.runtime.as_ref().unwrap().exists, Some(true));
        assert_eq!(
            t.runtime.as_ref().unwrap().version.as_deref(),
            Some("3.14.6")
        );
        assert_eq!(t.commands.len(), 2);
        assert_eq!(t.launchers.len(), 1);
        assert_eq!(
            t.manager_extra["entrypoints_missing"],
            json!(["mcp-reverse-proxy"])
        );
        assert!(t
            .removal
            .follow_up
            .iter()
            .any(|f| f.contains("may recreate")));
        assert!(t.completeness.level == "full");
        // uv not resolvable in this sandbox ⇒ no native remedy, explicit refusal.
        assert!(t.removal.native.is_none());
        assert_eq!(t.removal.launcher_only.len(), 1);
    }
}
