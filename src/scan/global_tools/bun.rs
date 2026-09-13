//! bun globals: `<bun_home>/install/global/package.json` plus
//! `node_modules/<pkg>/package.json`; launchers in `<bun_home>/bin`
//! (`bun`/`bunx` themselves excluded).

use serde_json::json;

use super::launchers;
use super::types::*;
use super::util::{bounded_size, file_name, list_dir, package_bins, read_json};
use super::ProbeCtx;

pub fn probe(cx: &ProbeCtx) -> ProbeResult {
    let home = cx.paths.expand(&cx.config.bun_home);
    if !home.is_dir() {
        return ProbeResult::absent();
    }
    let global = home.join("install/global");
    let Some(pkg_json) = read_json(&global.join("package.json")) else {
        return ProbeResult {
            installs: Vec::new(),
            status: Some(ManagerStatus::Ok {
                detail: Some("no global packages".into()),
            }),
        };
    };
    let bin_dir = home.join("bin");
    let bun = bin_dir.join("bun");
    let mut launchers_by_cmd = std::collections::BTreeMap::new();
    for entry in list_dir(&bin_dir) {
        let name = file_name(&entry);
        if name == "bun" || name == "bunx" {
            continue;
        }
        if let Some(l) = launchers::inspect(&entry) {
            launchers_by_cmd.insert(name, l);
        }
    }
    let mut installs = Vec::new();
    let deps: Vec<String> = pkg_json
        .get("dependencies")
        .and_then(|d| d.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    for name in deps {
        let mut t = ToolInstall::new(Manager::Bun, global.clone(), name.clone());
        let dir = global.join("node_modules").join(&name);
        t.install_dir = Some(dir.clone());
        t.runtime = Some(RuntimeRef {
            kind: "bun",
            path: Some(bun.clone()),
            version: None,
            exists: Some(bun.exists()),
            source: "<bun_home>/bin/bun".into(),
        });
        match read_json(&dir.join("package.json")) {
            Some(p) => {
                t.version = p
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                for (cmd, target) in package_bins(&p, &name) {
                    if let Some(mut l) = launchers_by_cmd.remove(&cmd) {
                        l.owner = Ownership::ThisInstall;
                        t.launchers.push(l);
                    }
                    t.commands.push(DeclaredCommand {
                        name: cmd,
                        declared_target: Some(target),
                    });
                }
                t.evidence(
                    "manager_metadata",
                    global.join("package.json").display().to_string(),
                    format!("bun global lists {name}"),
                    Confidence::High,
                );
            }
            None => t
                .completeness
                .add(format!("node_modules/{name}/package.json unreadable")),
        }
        t.removal.native = Some(NativeCommand {
            program: if bun.exists() {
                bun.display().to_string()
            } else {
                "bun".into()
            },
            args: vec!["remove".into(), "-g".into(), name.clone()],
            program_path: bun.exists().then(|| bun.clone()),
        });
        t.removal.launcher_only = t.launchers.iter().map(|l| l.path.clone()).collect();
        t.size_bytes = bounded_size(&dir);
        t.manager_extra = json!({ "bun": bun.exists().then(|| bun.clone()) });
        installs.push(t);
    }
    ProbeResult {
        installs,
        status: Some(ManagerStatus::Ok { detail: None }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Paths, ToolsConfig};
    use crate::scan::global_tools::npm::tests::cx;
    use crate::scan::global_tools::shellpath::ShellPath;
    use std::os::unix::fs::symlink;

    #[test]
    fn bun_globals_and_launchers() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let home = tmp.path().join(".bun");
        let global = home.join("install/global");
        std::fs::create_dir_all(global.join("node_modules/prettier/bin")).unwrap();
        std::fs::write(
            global.join("package.json"),
            r#"{"dependencies": {"prettier": "^3"}}"#,
        )
        .unwrap();
        std::fs::write(
            global.join("node_modules/prettier/package.json"),
            r#"{"name":"prettier","version":"3.3.0","bin":{"prettier":"bin/prettier.cjs"}}"#,
        )
        .unwrap();
        std::fs::write(global.join("node_modules/prettier/bin/prettier.cjs"), "").unwrap();
        std::fs::create_dir_all(home.join("bin")).unwrap();
        std::fs::write(home.join("bin/bun"), "").unwrap();
        std::fs::write(home.join("bin/bunx"), "").unwrap();
        symlink(
            "../install/global/node_modules/prettier/bin/prettier.cjs",
            home.join("bin/prettier"),
        )
        .unwrap();
        let config = ToolsConfig::default();
        let shell = ShellPath::default();
        let r = probe(&cx(&paths, &config, &shell, None));
        assert_eq!(r.installs.len(), 1);
        let p = &r.installs[0];
        assert_eq!(p.version.as_deref(), Some("3.3.0"));
        assert_eq!(p.launchers.len(), 1);
        assert_eq!(p.launchers[0].target_exists, Some(true));
        assert_eq!(
            p.removal.native.as_ref().unwrap().args,
            ["remove", "-g", "prettier"]
        );
    }
}
