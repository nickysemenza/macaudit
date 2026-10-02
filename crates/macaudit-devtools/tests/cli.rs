#![cfg(unix)]

use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};
use tempfile::TempDir;

struct Fixture {
    directory: TempDir,
}

impl Fixture {
    fn new(metadata: serde_json::Value, failure: Option<&str>) -> Self {
        let directory = TempDir::new().unwrap();
        fs::write(
            directory.path().join("metadata.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        let script = if let Some(failure) = failure {
            format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FIXTURE/arguments\"\nprintf '%s\\n' '{failure}' >&2\nexit 7\n")
        } else {
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FIXTURE/arguments\"\n/bin/cat \"$FIXTURE/metadata.json\"\n".to_owned()
        };
        let cargo = directory.path().join("cargo");
        fs::write(&cargo, script).unwrap();
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
        Self { directory }
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_macaudit-devtools"))
            .args(arguments)
            .env("FIXTURE", self.directory.path())
            .env("PATH", self.directory.path())
            .current_dir(self.directory.path())
            .output()
            .unwrap()
    }

    fn arguments(&self) -> String {
        fs::read_to_string(self.directory.path().join("arguments")).unwrap()
    }
}

#[test]
fn target_directory_prints_only_metadata_target_and_uses_locked_no_deps() {
    let fixture = Fixture::new(json!({"target_directory": "/custom target/debug"}), None);
    let result = fixture.run(&["target-directory"]);
    assert!(result.status.success());
    assert_eq!(result.stdout, b"/custom target/debug\n");
    assert!(result.stderr.is_empty());
    assert_eq!(
        fixture.arguments(),
        "metadata\n--locked\n--no-deps\n--format-version\n1\n"
    );
}

#[test]
fn dependency_check_reports_sorted_inventory_and_exits_nonzero_on_failures() {
    let fixture = Fixture::new(
        json!({"packages": [
            {"name": "zeta", "version": "1.0.0", "source": "registry+example", "rust_version": "1.94", "manifest_path": "Cargo.toml"},
            {"name": "alpha", "version": "1.0.0", "source": null, "license": "MIT", "manifest_path": "Cargo.toml"}
        ]}),
        None,
    );
    let result = fixture.run(&["check-dependencies", "--licenses"]);
    assert!(!result.status.success());
    assert_eq!(result.stdout, b"alpha 1.0.0\tMIT\nzeta 1.0.0\tworkspace\n");
    assert_eq!(
        result.stderr,
        b"zeta 1.0.0 requires Rust 1.94\nzeta 1.0.0 has no declared license\n"
    );
    assert_eq!(
        fixture.arguments(),
        "metadata\n--locked\n--format-version\n1\n"
    );
    let result = fixture.run(&["check-dependencies"]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
}

#[test]
fn dependency_check_success_preserves_summary() {
    let fixture = Fixture::new(json!({"packages": []}), None);
    let result = fixture.run(&["check-dependencies"]);
    assert!(result.status.success());
    assert_eq!(
        result.stdout,
        b"Verified 0 resolved packages against Rust 1.93 and declared licenses\n"
    );
    assert!(result.stderr.is_empty());
}

#[test]
fn command_failures_are_clean_stderr_and_do_not_create_notices() {
    let fixture = Fixture::new(json!({}), Some("locked graph unavailable"));
    let output = fixture.directory.path().join("new-directory/notices.txt");
    let result = fixture.run(&["third-party-notices", output.to_str().unwrap()]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.starts_with("cargo metadata failed ("));
    assert!(stderr.ends_with(": locked graph unavailable\n"));
    assert!(!stderr.contains("panicked"));
    assert!(!output.exists());
    assert!(!output.parent().unwrap().exists());
}

#[test]
fn malformed_metadata_is_a_clean_nonzero_error() {
    let fixture = Fixture::new(json!({}), None);
    let result = fixture.run(&["target-directory"]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8(result.stderr)
        .unwrap()
        .starts_with("Invalid cargo metadata: "));
}

#[test]
fn unknown_arguments_fail_before_invoking_cargo() {
    let fixture = Fixture::new(json!({}), None);
    let result = fixture.run(&["third-party-notices", "--unknown"]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8(result.stderr)
        .unwrap()
        .starts_with("Unknown argument: --unknown\n"));
    assert!(!fixture.directory.path().join("arguments").exists());
}
