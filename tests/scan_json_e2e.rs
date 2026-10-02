use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

fn run(home: &Path, cwd: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_macaudit"))
        .args(["--fake", "--offline"])
        .args(arguments)
        .env("MACAUDIT_HOME", home)
        .env("HOME", home)
        .env_remove("RUST_LOG")
        .current_dir(cwd)
        .output()
        .expect("run macaudit")
}

fn scan(home: &Path, cwd: &Path, arguments: &[&str]) -> Value {
    let output = run(home, cwd, arguments);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("valid run JSON")
}

fn findings(json: &Value) -> Vec<&Value> {
    json["disk"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .chain(json["audit_host"]["findings"].as_array().unwrap())
        .collect()
}

#[test]
fn scan_json_separates_selected_root_and_global_audits() {
    let home = tempfile::tempdir().unwrap();
    let json = scan(home.path(), home.path(), &["scan", "--json"]);
    let expected_root = home.path().canonicalize().unwrap();
    assert_eq!(
        json["request"]["selected_root"],
        expected_root.to_str().unwrap()
    );
    assert!(json["run_id"].as_u64().unwrap() > 0);
    assert_eq!(json["active_scanners"], 0);
    assert!(!json["disk"]["findings"].as_array().unwrap().is_empty());
    assert!(!json["audit_host"]["findings"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(json["disk"]["metadata"].get("coverage").is_some());
    assert!(json["audit_host"]["metadata"].get("coverage").is_some());
    assert_eq!(json["disk"]["metadata"]["context"]["type"], "disk");
    assert_eq!(
        json["audit_host"]["metadata"]["context"]["type"],
        "audit_host"
    );
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn section_filter_does_not_change_the_single_run_contract() {
    let home = tempfile::tempdir().unwrap();
    let json = scan(
        home.path(),
        home.path(),
        &["scan", "--section", "projects", "--json"],
    );
    assert!(json["disk"]["findings"].as_array().unwrap().is_empty());
    let rows = findings(&json);
    assert!(!rows.is_empty());
    assert!(rows
        .iter()
        .all(|finding| matches!(finding["kind"].as_str(), Some("project" | "project_bucket"))));
    assert_eq!(json["active_scanners"], 0);
    assert!(!json["audit_host"]["footprints"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn relative_and_tilde_roots_resolve_without_changing_host_context() {
    let home = tempfile::tempdir().unwrap();
    let subset = home.path().join("cf-repos");
    std::fs::create_dir(&subset).unwrap();
    let expected = subset.canonicalize().unwrap();
    for input in ["cf-repos", "~/cf-repos"] {
        let json = scan(
            home.path(),
            home.path(),
            &["--root", input, "scan", "--json"],
        );
        assert_eq!(json["request"]["selected_root"], expected.to_str().unwrap());
        assert!(!json["audit_host"]["findings"]
            .as_array()
            .unwrap()
            .is_empty());
    }
    assert_eq!(std::fs::read_dir(&subset).unwrap().count(), 0);
}

#[test]
fn invalid_and_multiple_roots_are_rejected_without_fallback() {
    let home = tempfile::tempdir().unwrap();
    for arguments in [
        vec!["--root", "missing", "scan", "--json"],
        vec!["--root", "~", "--root", "/", "scan", "--json"],
        vec!["--root", "", "scan", "--json"],
    ] {
        let output = run(home.path(), home.path(), &arguments);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn launches_ignore_and_preserve_legacy_runtime_artifacts() {
    let home = tempfile::tempdir().unwrap();
    let artifacts = [
        (".config/macaudit/config.toml", "invalid legacy config"),
        (
            "Library/Caches/macaudit/sizes.sqlite",
            "historical size database",
        ),
        ("Library/Caches/macaudit/catalog.json", "historical catalog"),
        (
            ".local/state/macaudit/reports/old.json",
            "historical report",
        ),
    ];
    for (relative, contents) in artifacts {
        let path = home.path().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    for _ in 0..2 {
        let json = scan(home.path(), home.path(), &["scan", "--json"]);
        assert!(!findings(&json).is_empty());
    }
    for (relative, contents) in artifacts {
        assert_eq!(
            std::fs::read_to_string(home.path().join(relative)).unwrap(),
            contents
        );
    }
    assert_eq!(
        std::fs::read_dir(home.path().join(".config/macaudit"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_dir(home.path().join("Library/Caches/macaudit"))
            .unwrap()
            .count(),
        2
    );
    assert_eq!(
        std::fs::read_dir(home.path().join(".local/state/macaudit/reports"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn explicit_configuration_is_a_read_only_input() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join("input.toml");
    let contents = "[network]\noffline = true\n[scan]\nroots = [\"/must-not-be-used\"]\n";
    std::fs::write(&config, contents).unwrap();
    let json = scan(
        home.path(),
        home.path(),
        &["--config", "input.toml", "scan", "--json"],
    );
    assert_eq!(
        json["request"]["selected_root"],
        home.path().canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(std::fs::read_to_string(config).unwrap(), contents);
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 1);
}

#[test]
fn finding_identity_does_not_require_saved_state_between_launches() {
    let home = tempfile::tempdir().unwrap();
    let first = scan(home.path(), home.path(), &["scan", "--json"]);
    let second = scan(home.path(), home.path(), &["scan", "--json"]);
    let identities = |json: &Value| {
        let mut ids: Vec<_> = findings(json)
            .into_iter()
            .map(|finding| finding["id"].to_string())
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(identities(&first), identities(&second));
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}
