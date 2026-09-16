//! End-to-end test: run the real `macaudit` binary with `scan --json` against a
//! fixture HOME and assert on the emitted `Vec<Finding>` (spec §10).
//!
//! This drives the whole pipeline — CLI parse → `Paths`/`Config` resolution via
//! `$MACAUDIT_HOME` → the engine → the filesystem-based scanners (FsScanner's
//! real `ignore` walk + GitScanner shelling real `git`) → JSON serialization —
//! without mocking anything. It also asserts `FindingId` stability across two
//! runs of an identical scan.
//!
//! We scan only `disk` (which pulls in git discovery) so the test needs no stub
//! CLIs for brew/system_profiler/etc.; those scanners have their own unit tests
//! with fixture output.

use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// Build a fixture HOME tree: a JS project with a node_modules artifact, and a
/// real git repo. Returns the tempdir (kept alive by the caller).
fn build_fixture_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("tempdir");
    let root = home.path();

    // A JS project: node_modules next to package.json → a BuildArtifact finding.
    let proj = root.join("code/webapp");
    std::fs::create_dir_all(proj.join("node_modules/leftpad")).unwrap();
    std::fs::write(proj.join("package.json"), r#"{"name":"webapp"}"#).unwrap();
    std::fs::write(
        proj.join("node_modules/leftpad/index.js"),
        "module.exports=1;\n",
    )
    .unwrap();
    std::fs::write(proj.join("src.js"), "console.log(1)\n").unwrap();

    // A real git repo → a GitRepo finding (best-effort; skipped if git absent).
    let repo = root.join("code/repo");
    std::fs::create_dir_all(&repo).unwrap();
    let _ = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status();
    std::fs::write(repo.join("README.md"), "# repo\n").unwrap();

    // A project under ~/dev — this is what makes the "Development" disk
    // category (~/dev) exist for this fixture, so `disk_category` findings
    // are actually emitted. No `node_modules` here (that would add a second
    // build-artifact hit and break `scan_json_finds_node_modules_artifact`'s
    // "exactly one" assertion) — just a couple of plain source files.
    let dev_proj = root.join("dev/proj");
    std::fs::create_dir_all(&dev_proj).unwrap();
    std::fs::write(dev_proj.join("package.json"), r#"{"name":"proj"}"#).unwrap();
    std::fs::write(dev_proj.join("main.js"), "console.log(2)\n").unwrap();

    home
}

/// Run `macaudit scan --section disk --json` against the fixture HOME and return
/// the parsed findings array.
fn run_scan_json(home: &Path) -> Vec<Value> {
    let out = Command::new(env!("CARGO_BIN_EXE_macaudit"))
        .args(["scan", "--section", "disk", "--json"])
        .env("MACAUDIT_HOME", home)
        .output()
        .expect("run macaudit");
    assert!(
        out.status.success(),
        "macaudit exited {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let json: Value = serde_json::from_slice(&out.stdout).expect("valid JSON array");
    json.as_array().expect("top-level array").clone()
}

#[test]
fn scan_json_finds_node_modules_artifact() {
    let home = build_fixture_home();
    let findings = run_scan_json(home.path());

    let node_modules: Vec<&Value> = findings
        .iter()
        .filter(|f| f["kind"] == "build_artifact")
        .filter(|f| {
            f["path"]
                .as_str()
                .map(|p| p.ends_with("node_modules"))
                .unwrap_or(false)
        })
        .collect();

    assert_eq!(
        node_modules.len(),
        1,
        "expected exactly one node_modules artifact, got findings: {findings:#?}"
    );
    let nm = node_modules[0];
    // Discovery does not descend: no nested node_modules finding.
    assert!(
        nm["path"]
            .as_str()
            .unwrap()
            .contains("code/webapp/node_modules"),
        "unexpected artifact path: {}",
        nm["path"]
    );
    // A reclaimable severity + a Trash remedy should be attached.
    assert_eq!(nm["severity"], "reclaimable");
    let has_trash = nm["remedies"]
        .as_array()
        .map(|rs| rs.iter().any(|r| r["command"]["type"] == "trash"))
        .unwrap_or(false);
    assert!(has_trash, "node_modules finding should have a Trash remedy");
}

#[test]
fn scan_json_disk_categories_are_complete() {
    let home = build_fixture_home();
    let findings = run_scan_json(home.path());

    let categories: Vec<&Value> = findings
        .iter()
        .filter(|f| f["kind"] == "disk_category")
        .collect();

    assert!(
        !categories.is_empty(),
        "expected at least one disk_category finding, got findings: {findings:#?}"
    );
    for c in &categories {
        assert_eq!(
            c["meta"]["complete"], true,
            "disk_category finding should be complete in this fixture: {c:#?}"
        );
    }
}

#[test]
fn finding_ids_are_stable_across_runs() {
    let home = build_fixture_home();

    let ids_of = |findings: &[Value]| -> Vec<String> {
        let mut ids: Vec<String> = findings.iter().map(|f| f["id"].to_string()).collect();
        ids.sort();
        ids
    };

    let run1 = run_scan_json(home.path());
    let run2 = run_scan_json(home.path());

    // Same fixture, same ids — findings must be identifiable across scans.
    assert_eq!(
        ids_of(&run1),
        ids_of(&run2),
        "FindingIds must be stable across identical scans"
    );
    assert!(
        !run1.is_empty(),
        "expected at least the node_modules finding"
    );
}
