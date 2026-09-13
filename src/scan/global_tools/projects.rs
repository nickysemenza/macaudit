//! Project correlation: which repositories declare, pin or bundle a tool
//! that is also installed globally. Evidence only — a manifest line never
//! means the global copy is unused, and a project-local copy counts as an
//! *installed* alternative only when its binary actually exists.
//!
//! Walks the configured roots (`[tools] project_roots`, else `[scan] roots`,
//! else `$HOME`) to a bounded depth, never descending into `node_modules`,
//! `target`, vendored checkouts, caches, `~/Library`, or hidden directories,
//! with a wall-clock budget. Files read: `package.json`, lockfiles,
//! `Cargo.toml`/`rust-toolchain*`, `pyproject.toml`/`uv.lock`/
//! `requirements*.txt`, `.tool-versions`/`.mise.toml`/`.node-version`/
//! `.python-version`, `Brewfile`, bootstrap scripts pinning `X_VERSION=`,
//! and `.github/workflows/*.yml` (token match against command names).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use super::util::{file_name, list_dir, read_json, read_toml};
use super::ProbeCtx;

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "vendor",
    "Pods",
    "DerivedData",
    "Library",
    "Caches",
    "cache",
    "checkouts",
    "SourcePackages",
    "dist",
    "build",
    "__pycache__",
];
const MAX_PROJECTS: usize = 500;
const MAX_SCRIPT_BYTES: u64 = 256 * 1024;

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct LocalBinary {
    pub path: PathBuf,
    pub exists: bool,
    pub version: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ProjectRef {
    pub project: PathBuf,
    pub source: PathBuf,
    /// dev_dependency | dependency | script | package_manager | lockfile |
    /// tool_versions | version_file | brewfile | bootstrap_pin | ci_workflow
    pub kind: &'static str,
    pub tool: String,
    pub declared_version: Option<String>,
    pub local_binary: Option<LocalBinary>,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct ProjectCoverage {
    pub roots: Vec<PathBuf>,
    pub scanned: usize,
    pub truncated: bool,
    pub elapsed_ms: u64,
}

#[derive(Default, Debug)]
pub struct ProjectIndex {
    refs: BTreeMap<String, Vec<ProjectRef>>,
    /// Lowercased tokens seen in CI workflows, per project.
    ci_tokens: Vec<(PathBuf, PathBuf, BTreeSet<String>)>,
    pub coverage: ProjectCoverage,
}

impl ProjectIndex {
    /// References to any of `names` (case-insensitive), CI tokens included.
    pub fn refs_for(&self, names: &[String]) -> Vec<ProjectRef> {
        let mut out = Vec::new();
        for n in names {
            let key = n.to_ascii_lowercase();
            if let Some(v) = self.refs.get(&key) {
                out.extend(v.iter().cloned());
            }
            for (project, source, tokens) in &self.ci_tokens {
                if tokens.contains(&key) {
                    out.push(ProjectRef {
                        project: project.clone(),
                        source: source.clone(),
                        kind: "ci_workflow",
                        tool: n.clone(),
                        declared_version: None,
                        local_binary: None,
                    });
                }
            }
        }
        out.sort_by(|a, b| (&a.project, &a.source, &a.tool).cmp(&(&b.project, &b.source, &b.tool)));
        out.dedup();
        out
    }

    pub fn coverage_json(&self) -> Value {
        serde_json::to_value(&self.coverage).unwrap_or(Value::Null)
    }

    fn push(&mut self, r: ProjectRef) {
        self.refs
            .entry(r.tool.to_ascii_lowercase())
            .or_default()
            .push(r);
    }
}

fn is_project(dir: &Path) -> bool {
    [
        "package.json",
        "Cargo.toml",
        "pyproject.toml",
        "requirements.txt",
        ".tool-versions",
        ".mise.toml",
        "mise.toml",
        ".node-version",
        ".python-version",
        "Brewfile",
        "Package.swift",
        "go.mod",
    ]
    .iter()
    .any(|m| dir.join(m).exists())
}

fn node_local_binary(project: &Path, cmd: &str, pkg: Option<&str>) -> Option<LocalBinary> {
    let path = project.join("node_modules/.bin").join(cmd);
    let exists = path.exists();
    let version = pkg
        .and_then(|p| read_json(&project.join("node_modules").join(p).join("package.json")))
        .and_then(|j| {
            j.get("version")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });
    Some(LocalBinary {
        path,
        exists,
        version,
    })
}

fn index_package_json(idx: &mut ProjectIndex, project: &Path) {
    let file = project.join("package.json");
    let Some(j) = read_json(&file) else { return };
    for (section, kind) in [
        ("devDependencies", "dev_dependency"),
        ("dependencies", "dependency"),
    ] {
        if let Some(deps) = j.get(section).and_then(|d| d.as_object()) {
            for (name, range) in deps {
                // The command is usually the unscoped package name; a local
                // install's own `bin` map is the authority when present.
                let mut cmds: Vec<String> = Vec::new();
                if let Some(local) =
                    read_json(&project.join("node_modules").join(name).join("package.json"))
                {
                    for (c, _) in super::util::package_bins(&local, name) {
                        cmds.push(c);
                    }
                }
                if cmds.is_empty() {
                    cmds.push(name.rsplit('/').next().unwrap_or(name).to_string());
                }
                for cmd in cmds {
                    idx.push(ProjectRef {
                        project: project.to_path_buf(),
                        source: file.clone(),
                        kind,
                        tool: cmd.clone(),
                        declared_version: range.as_str().map(str::to_string),
                        local_binary: node_local_binary(project, &cmd, Some(name)),
                    });
                }
                if name.contains('/') {
                    // Also index the full package name for peers keyed by it.
                    idx.push(ProjectRef {
                        project: project.to_path_buf(),
                        source: file.clone(),
                        kind,
                        tool: name.clone(),
                        declared_version: range.as_str().map(str::to_string),
                        local_binary: None,
                    });
                }
            }
        }
    }
    if let Some(pm) = j.get("packageManager").and_then(|v| v.as_str()) {
        let (tool, ver) = pm
            .split_once('@')
            .map(|(t, v)| (t.to_string(), Some(v.to_string())))
            .unwrap_or((pm.to_string(), None));
        idx.push(ProjectRef {
            project: project.to_path_buf(),
            source: file.clone(),
            kind: "package_manager",
            tool,
            declared_version: ver,
            local_binary: None,
        });
    }
    if let Some(scripts) = j.get("scripts").and_then(|s| s.as_object()) {
        let mut seen = BTreeSet::new();
        for (_, v) in scripts {
            let Some(script) = v.as_str() else { continue };
            for segment in script.split(['&', '|', ';']) {
                let Some(tok) = segment.split_whitespace().find(|t| !t.contains('=')) else {
                    continue;
                };
                if matches!(
                    tok,
                    "cd" | "echo"
                        | "rm"
                        | "cp"
                        | "mkdir"
                        | "true"
                        | "false"
                        | "npm"
                        | "npx"
                        | "pnpm"
                        | "yarn"
                        | "bun"
                        | "node"
                ) {
                    continue;
                }
                if seen.insert(tok.to_string()) {
                    idx.push(ProjectRef {
                        project: project.to_path_buf(),
                        source: file.clone(),
                        kind: "script",
                        tool: tok.to_string(),
                        declared_version: None,
                        local_binary: node_local_binary(project, tok, None),
                    });
                }
            }
        }
    }
}

fn index_lockfiles(idx: &mut ProjectIndex, project: &Path) {
    for (file, tool) in [
        ("yarn.lock", "yarn"),
        ("pnpm-lock.yaml", "pnpm"),
        ("package-lock.json", "npm"),
        ("bun.lock", "bun"),
        ("bun.lockb", "bun"),
        ("uv.lock", "uv"),
        ("Podfile.lock", "pod"),
        ("Gemfile.lock", "bundle"),
        ("poetry.lock", "poetry"),
    ] {
        let p = project.join(file);
        if p.exists() {
            idx.push(ProjectRef {
                project: project.to_path_buf(),
                source: p,
                kind: "lockfile",
                tool: tool.to_string(),
                declared_version: None,
                local_binary: None,
            });
        }
    }
}

fn index_python(idx: &mut ProjectIndex, project: &Path) {
    let py = project.join("pyproject.toml");
    if let Some(t) = read_toml(&py) {
        let mut names: Vec<(String, Option<String>)> = Vec::new();
        let mut collect = |arr: Option<&toml::Value>| {
            if let Some(a) = arr.and_then(|a| a.as_array()) {
                for v in a {
                    if let Some(s) = v.as_str() {
                        let name: String = s
                            .chars()
                            .take_while(|c| {
                                c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.'
                            })
                            .collect();
                        let spec = s[name.len()..].trim().to_string();
                        if !name.is_empty() {
                            names.push((name, (!spec.is_empty()).then_some(spec)));
                        }
                    }
                }
            }
        };
        collect(t.get("project").and_then(|p| p.get("dependencies")));
        if let Some(opt) = t
            .get("project")
            .and_then(|p| p.get("optional-dependencies"))
            .and_then(|o| o.as_table())
        {
            for (_, v) in opt {
                collect(Some(v));
            }
        }
        if let Some(groups) = t.get("dependency-groups").and_then(|g| g.as_table()) {
            for (_, v) in groups {
                collect(Some(v));
            }
        }
        if let Some(tools) = t.get("tool").and_then(|x| x.as_table()) {
            for (name, _) in tools {
                names.push((name.clone(), None));
            }
        }
        for (name, ver) in names {
            let bin = project.join(".venv/bin").join(&name);
            idx.push(ProjectRef {
                project: project.to_path_buf(),
                source: py.clone(),
                kind: "dependency",
                tool: name,
                declared_version: ver,
                local_binary: Some(LocalBinary {
                    exists: bin.exists(),
                    path: bin,
                    version: None,
                }),
            });
        }
    }
    for entry in list_dir(project) {
        let name = file_name(&entry);
        if name.starts_with("requirements") && name.ends_with(".txt") {
            if let Ok(text) = std::fs::read_to_string(&entry) {
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                        continue;
                    }
                    let pkg: String = line
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
                        .collect();
                    if !pkg.is_empty() {
                        idx.push(ProjectRef {
                            project: project.to_path_buf(),
                            source: entry.clone(),
                            kind: "dependency",
                            tool: pkg,
                            declared_version: Some(line[..].to_string()),
                            local_binary: None,
                        });
                    }
                }
            }
        }
    }
}

fn index_version_files(idx: &mut ProjectIndex, project: &Path) {
    if let Ok(text) = std::fs::read_to_string(project.join(".tool-versions")) {
        for line in text.lines() {
            let mut it = line.split_whitespace();
            if let (Some(tool), Some(ver)) = (it.next(), it.next()) {
                idx.push(ProjectRef {
                    project: project.to_path_buf(),
                    source: project.join(".tool-versions"),
                    kind: "tool_versions",
                    tool: tool.to_string(),
                    declared_version: Some(ver.to_string()),
                    local_binary: None,
                });
            }
        }
    }
    for mise in [".mise.toml", "mise.toml"] {
        if let Some(t) = read_toml(&project.join(mise)) {
            if let Some(tools) = t.get("tools").and_then(|x| x.as_table()) {
                for (tool, ver) in tools {
                    idx.push(ProjectRef {
                        project: project.to_path_buf(),
                        source: project.join(mise),
                        kind: "tool_versions",
                        tool: tool.clone(),
                        declared_version: ver.as_str().map(str::to_string),
                        local_binary: None,
                    });
                }
            }
        }
    }
    for (file, tool) in [
        (".node-version", "node"),
        (".python-version", "python"),
        ("rust-toolchain", "rustc"),
    ] {
        if let Ok(text) = std::fs::read_to_string(project.join(file)) {
            let v = text.trim().to_string();
            if !v.is_empty() && !v.starts_with('[') {
                idx.push(ProjectRef {
                    project: project.to_path_buf(),
                    source: project.join(file),
                    kind: "version_file",
                    tool: tool.to_string(),
                    declared_version: Some(v),
                    local_binary: None,
                });
            }
        }
    }
    if let Some(t) = read_toml(&project.join("rust-toolchain.toml")) {
        if let Some(ch) = t
            .get("toolchain")
            .and_then(|x| x.get("channel"))
            .and_then(|c| c.as_str())
        {
            idx.push(ProjectRef {
                project: project.to_path_buf(),
                source: project.join("rust-toolchain.toml"),
                kind: "version_file",
                tool: "rustc".into(),
                declared_version: Some(ch.to_string()),
                local_binary: None,
            });
        }
    }
    if let Ok(text) = std::fs::read_to_string(project.join("Brewfile")) {
        let re = Regex::new(r#"^\s*(brew|cask)\s+["']([^"']+)["']"#).unwrap();
        for line in text.lines() {
            if let Some(c) = re.captures(line) {
                let name = c[2].rsplit('/').next().unwrap_or(&c[2]).to_string();
                idx.push(ProjectRef {
                    project: project.to_path_buf(),
                    source: project.join("Brewfile"),
                    kind: "brewfile",
                    tool: name,
                    declared_version: None,
                    local_binary: None,
                });
            }
        }
    }
}

fn index_bootstrap_scripts(idx: &mut ProjectIndex, project: &Path) {
    let re = Regex::new(r#"([A-Z][A-Z0-9_]*?)_VERSION\s*[:?]?=\s*["']?(\d[^"'\s]*)"#).unwrap();
    let mut files: Vec<PathBuf> = Vec::new();
    for dir in [
        project.join("scripts"),
        project.join("bin"),
        project.join("tools"),
        project.to_path_buf(),
    ] {
        for e in list_dir(&dir) {
            let n = file_name(&e);
            if e.is_file()
                && (n.ends_with(".sh")
                    || n == "Makefile"
                    || n == "Justfile"
                    || n == "justfile"
                    || (dir != *project && !n.contains('.')))
            {
                files.push(e);
            }
        }
    }
    for f in files {
        let Ok(meta) = std::fs::metadata(&f) else {
            continue;
        };
        if meta.len() > MAX_SCRIPT_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        for c in re.captures_iter(&text) {
            let tool = c[1].to_ascii_lowercase();
            let local = project.join(".tools").join(&tool);
            idx.push(ProjectRef {
                project: project.to_path_buf(),
                source: f.clone(),
                kind: "bootstrap_pin",
                tool,
                declared_version: Some(c[2].to_string()),
                local_binary: Some(LocalBinary {
                    exists: local.exists(),
                    path: local,
                    version: None,
                }),
            });
        }
    }
}

fn index_ci(idx: &mut ProjectIndex, project: &Path) {
    let re = Regex::new(r"[a-z][a-z0-9_-]{2,}").unwrap();
    for wf in list_dir(&project.join(".github/workflows")) {
        let n = file_name(&wf);
        if !(n.ends_with(".yml") || n.ends_with(".yaml")) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&wf) else {
            continue;
        };
        if meta.len() > MAX_SCRIPT_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&wf) else {
            continue;
        };
        let tokens: BTreeSet<String> = re
            .find_iter(&text.to_ascii_lowercase())
            .map(|m| m.as_str().to_string())
            .collect();
        idx.ci_tokens.push((project.to_path_buf(), wf, tokens));
    }
}

/// Build the index over the configured roots.
pub fn index(cx: &ProbeCtx) -> ProjectIndex {
    let roots: Vec<PathBuf> = if !cx.config.project_roots.is_empty() {
        cx.config
            .project_roots
            .iter()
            .map(|r| cx.paths.expand(r))
            .collect()
    } else {
        cx.paths.default_roots()
    };
    index_roots(
        &roots,
        cx.config.project_max_depth,
        Duration::from_secs(cx.config.project_time_budget_secs),
    )
}

pub fn index_roots(roots: &[PathBuf], max_depth: usize, budget: Duration) -> ProjectIndex {
    let start = Instant::now();
    let mut idx = ProjectIndex {
        coverage: ProjectCoverage {
            roots: roots.to_vec(),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut stack: Vec<(PathBuf, usize)> = roots
        .iter()
        .filter(|r| r.is_dir())
        .map(|r| (r.clone(), 0))
        .collect();
    while let Some((dir, depth)) = stack.pop() {
        if start.elapsed() > budget || idx.coverage.scanned >= MAX_PROJECTS {
            idx.coverage.truncated = true;
            break;
        }
        if is_project(&dir) {
            idx.coverage.scanned += 1;
            index_package_json(&mut idx, &dir);
            index_lockfiles(&mut idx, &dir);
            index_python(&mut idx, &dir);
            index_version_files(&mut idx, &dir);
            index_bootstrap_scripts(&mut idx, &dir);
            index_ci(&mut idx, &dir);
        }
        if depth >= max_depth {
            continue;
        }
        for e in list_dir(&dir) {
            let n = file_name(&e);
            if n.starts_with('.') || SKIP_DIRS.contains(&n.as_str()) {
                continue;
            }
            match std::fs::symlink_metadata(&e) {
                Ok(m) if m.is_dir() => stack.push((e, depth + 1)),
                _ => {}
            }
        }
    }
    idx.coverage.elapsed_ms = start.elapsed().as_millis() as u64;
    idx
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Overboard-like (pinned swiftlint/swiftformat in scripts/tools.sh, CI
    /// workflow), cubby-like (knip + playwright devDependencies with local
    /// binaries), ingrid-like (yarn.lock only), and a vendored copy that
    /// must be ignored.
    pub(crate) fn mk_projects(root: &Path) {
        let ob = root.join("overboard/scripts");
        std::fs::create_dir_all(&ob).unwrap();
        std::fs::write(root.join("overboard/Package.swift"), "").unwrap();
        std::fs::write(
            ob.join("tools.sh"),
            "#!/bin/sh\nSWIFTLINT_VERSION=0.65.0\nSWIFTFORMAT_VERSION=\"0.61.1\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("overboard/.github/workflows")).unwrap();
        std::fs::write(
            root.join("overboard/.github/workflows/ci.yml"),
            "jobs:\n  lint:\n    run: scripts/tools.sh lint\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("overboard/.tools")).unwrap();
        std::fs::write(root.join("overboard/.tools/swiftlint"), "").unwrap();

        let cubby = root.join("cubby");
        std::fs::create_dir_all(cubby.join("node_modules/.bin")).unwrap();
        std::fs::create_dir_all(cubby.join("node_modules/knip")).unwrap();
        std::fs::write(cubby.join("package.json"), r#"{"devDependencies": {"knip": "^6.32.0", "playwright": "^1.62.1", "@playwright/test": "^1.62.1"}, "scripts": {"lint": "knip && eslint .", "e2e": "playwright test"}, "packageManager": "pnpm@10.30.0"}"#).unwrap();
        std::fs::write(
            cubby.join("node_modules/knip/package.json"),
            r#"{"name":"knip","version":"6.32.0","bin":{"knip":"bin/knip.js"}}"#,
        )
        .unwrap();
        std::fs::write(cubby.join("node_modules/.bin/knip"), "").unwrap();
        std::fs::write(cubby.join("pnpm-lock.yaml"), "").unwrap();
        // A vendored copy inside node_modules must never count as a project.
        std::fs::create_dir_all(cubby.join("node_modules/vendored")).unwrap();
        std::fs::write(
            cubby.join("node_modules/vendored/package.json"),
            r#"{"devDependencies": {"eas-cli": "1"}}"#,
        )
        .unwrap();

        let ingrid = root.join("ingrid");
        std::fs::create_dir_all(&ingrid).unwrap();
        std::fs::write(ingrid.join("package.json"), "{}").unwrap();
        std::fs::write(ingrid.join("yarn.lock"), "").unwrap();
        std::fs::write(ingrid.join(".tool-versions"), "nodejs 20.11.0\n").unwrap();
        std::fs::write(
            ingrid.join("Brewfile"),
            "brew \"swiftlint\"\ncask \"docker\"\n",
        )
        .unwrap();

        let py = root.join("pyproj");
        std::fs::create_dir_all(py.join(".venv/bin")).unwrap();
        std::fs::write(py.join("pyproject.toml"), "[project]\nname = \"x\"\ndependencies = [\"requests>=2\"]\n[tool.ruff]\nline-length = 100\n").unwrap();
        std::fs::write(py.join(".venv/bin/ruff"), "").unwrap();
    }

    #[test]
    fn indexes_manifests_pins_lockfiles_and_local_binaries() {
        let tmp = tempfile::tempdir().unwrap();
        mk_projects(tmp.path());
        let idx = index_roots(&[tmp.path().to_path_buf()], 4, Duration::from_secs(5));
        assert_eq!(idx.coverage.scanned, 4);
        assert!(!idx.coverage.truncated);

        let knip = idx.refs_for(&["knip".into()]);
        let dev = knip.iter().find(|r| r.kind == "dev_dependency").unwrap();
        assert_eq!(dev.declared_version.as_deref(), Some("^6.32.0"));
        let lb = dev.local_binary.as_ref().unwrap();
        assert!(lb.exists);
        assert_eq!(lb.version.as_deref(), Some("6.32.0"));
        assert!(knip.iter().any(|r| r.kind == "script"));

        // Declared but no local binary: evidence, not an installed alternative.
        let pw = idx.refs_for(&["playwright".into()]);
        assert!(pw
            .iter()
            .all(|r| r.local_binary.as_ref().map(|b| !b.exists).unwrap_or(true)));

        let swiftlint = idx.refs_for(&["swiftlint".into()]);
        let pin = swiftlint
            .iter()
            .find(|r| r.kind == "bootstrap_pin")
            .unwrap();
        assert_eq!(pin.declared_version.as_deref(), Some("0.65.0"));
        assert!(pin.local_binary.as_ref().unwrap().exists);
        assert!(swiftlint.iter().any(|r| r.kind == "brewfile"));
        let fmt = idx.refs_for(&["swiftformat".into()]);
        assert_eq!(fmt[0].declared_version.as_deref(), Some("0.61.1"));
        assert!(!fmt[0].local_binary.as_ref().unwrap().exists);

        assert!(idx
            .refs_for(&["yarn".into()])
            .iter()
            .any(|r| r.kind == "lockfile"));
        assert!(idx.refs_for(&["pnpm".into()]).iter().any(
            |r| r.kind == "package_manager" && r.declared_version.as_deref() == Some("10.30.0")
        ));
        assert!(idx
            .refs_for(&["nodejs".into()])
            .iter()
            .any(|r| r.kind == "tool_versions"));
        let ruff = idx.refs_for(&["ruff".into()]);
        assert!(ruff
            .iter()
            .any(|r| r.local_binary.as_ref().map(|b| b.exists).unwrap_or(false)));
        // CI token match, and vendored trees excluded.
        assert!(idx
            .refs_for(&["lint".into()])
            .iter()
            .any(|r| r.kind == "ci_workflow"));
        assert!(idx.refs_for(&["eas-cli".into()]).is_empty());
    }

    #[test]
    fn depth_and_budget_truncate_honestly() {
        let tmp = tempfile::tempdir().unwrap();
        mk_projects(tmp.path());
        let idx = index_roots(&[tmp.path().to_path_buf()], 0, Duration::from_secs(5));
        assert_eq!(idx.coverage.scanned, 0);
        let idx = index_roots(&[tmp.path().to_path_buf()], 4, Duration::from_secs(0));
        assert!(idx.coverage.truncated);
    }
}
