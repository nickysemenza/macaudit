use super::*;
use serde_json::{json, Value};
use tempfile::TempDir;

const SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const CHECKSUM: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

struct Fixture {
    directory: TempDir,
    packages: Vec<Value>,
    pins: Vec<Value>,
    sidecar: Value,
    lockfile: String,
}

impl Fixture {
    fn new() -> Self {
        Self {
            directory: TempDir::new().unwrap(),
            packages: Vec::new(),
            pins: Vec::new(),
            sidecar: json!({"packages": {}, "files": {}}),
            lockfile: String::from(
                "version = 4\n\n[[package]]\nname = \"workspace\"\nversion = \"0.1.0\"\n",
            ),
        }
    }

    fn root(&self) -> &Path {
        self.directory.path()
    }

    fn file(&self, relative: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.root().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }

    fn package(&mut self, name: &str, version: &str) -> PathBuf {
        let manifest = self.file(format!("crates/{name}-{version}/Cargo.toml"), "");
        self.packages.push(json!({
            "name": name,
            "version": version,
            "source": SOURCE,
            "license": "MIT",
            "manifest_path": manifest
        }));
        self.lockfile.push_str(&format!(
            "\n[[package]]\nname = {name:?}\nversion = {version:?}\nsource = {SOURCE:?}\nchecksum = {CHECKSUM:?}\n"
        ));
        manifest.parent().unwrap().to_owned()
    }

    fn preserved(&mut self, name: &str, version: &str, status: &str) {
        self.package(name, version);
        let relative = format!("docs/licenses/{name}/LICENSE.txt");
        let bytes = b"Preserved terms\r\nCopyright owner\n";
        self.file(&relative, bytes);
        self.sidecar["packages"][format!("{name}@{version}")] = json!({
            "name": name,
            "version": version,
            "source": SOURCE,
            "crate_sha256": CHECKSUM,
            "license_files": [relative],
            "repository": "https://example.com/upstream",
            "revision": REVISION,
            "license_text_status": status
        });
        self.sidecar["files"][relative] = json!({"sha256": format!("{:x}", Sha256::digest(bytes))});
    }

    fn pin(&mut self, identity: &str, version: Option<&str>) {
        self.pins.push(json!({
            "identity": identity,
            "location": format!("https://example.com/{identity}"),
            "state": {"revision": REVISION, "version": version}
        }));
    }

    fn checkout(
        &self,
        parent: &Path,
        identity: &str,
        revision: &str,
        text: Option<&[u8]>,
    ) -> PathBuf {
        let directory = parent.join(identity);
        fs::create_dir_all(directory.join(".git/objects")).unwrap();
        fs::create_dir_all(directory.join(".git/refs")).unwrap();
        fs::write(directory.join(".git/HEAD"), format!("{revision}\n")).unwrap();
        if let Some(text) = text {
            fs::write(directory.join("LICENSE"), text).unwrap();
        }
        directory
    }

    fn write(&self, output: &Path, checkouts: &[PathBuf]) -> Result<()> {
        self.file(
            "docs/licenses/manifest.json",
            serde_json::to_vec(&self.sidecar).unwrap(),
        );
        self.file("Cargo.lock", &self.lockfile);
        self.file(
            "swift/MacAuditKit/Package.resolved",
            serde_json::to_vec(&json!({"pins": self.pins})).unwrap(),
        );
        let metadata = serde_json::from_value(json!({"packages": self.packages})).unwrap();
        super::write(self.root(), &metadata, output, checkouts)
    }

    fn assert_failure(&self, expected: &str, checkouts: &[PathBuf]) {
        let output = self.root().join("new-directory/notices.txt");
        assert_eq!(
            self.write(&output, checkouts).unwrap_err().to_string(),
            expected
        );
        assert!(!output.exists());
        assert!(!output.parent().unwrap().exists());
        let existing = self.file("existing.txt", "previous notices");
        assert_eq!(
            self.write(&existing, checkouts).unwrap_err().to_string(),
            expected
        );
        assert_eq!(fs::read_to_string(existing).unwrap(), "previous notices");
    }
}

#[test]
fn writes_exact_sorted_notices_with_declared_files_and_lossy_text() {
    let mut fixture = Fixture::new();
    let zeta = fixture.package("zeta", "1.0.0");
    fs::write(zeta.join("notice"), b"notice\r\n").unwrap();
    fs::write(zeta.join("LICENSE"), b"terms\xff\rline").unwrap();
    fs::create_dir(zeta.join("LICENSE-directory")).unwrap();
    fs::write(zeta.join("README"), "not terms").unwrap();
    let alpha = fixture.package("alpha", "1.0.0");
    fs::create_dir(alpha.join("legal")).unwrap();
    fs::write(alpha.join("legal/terms.txt"), "declared text").unwrap();
    fixture.packages[1]["license_file"] = json!("legal/terms.txt");
    fixture.packages.push(json!({
        "name": "workspace", "version": "0.1.0", "source": null, "manifest_path": "nonexistent/Cargo.toml"
    }));
    let output = fixture.root().join("new-directory/notices.txt");
    fixture.write(&output, &[]).unwrap();
    let separator = "=".repeat(72);
    assert_eq!(fs::read_to_string(output).unwrap(), format!(
        "MacAudit third-party notices\n\n{separator}\nalpha 1.0.0\nLicense: MIT\n\n--- terms.txt ---\ndeclared text\n\n{separator}\nzeta 1.0.0\nLicense: MIT\n\n--- LICENSE ---\nterms\u{fffd}\nline\n\n--- notice ---\nnotice\n\n"
    ));
}

#[test]
fn does_not_duplicate_a_declared_license_already_discovered() {
    let mut fixture = Fixture::new();
    let directory = fixture.package("alpha", "1.0.0");
    fs::write(directory.join("LICENSE"), "terms").unwrap();
    fixture.packages[0]["license_file"] = json!("LICENSE");
    let output = fixture.root().join("notices.txt");
    fixture.write(&output, &[]).unwrap();
    assert_eq!(
        fs::read_to_string(output)
            .unwrap()
            .matches("--- LICENSE ---")
            .count(),
        1
    );
}

#[test]
fn verifies_fallback_hashes_and_emits_incomplete_terms_limitations() {
    for status in ["complete", "notice-only"] {
        let mut fixture = Fixture::new();
        fixture.preserved("alpha", "1.0.0", status);
        let output = fixture.root().join("notices.txt");
        fixture.write(&output, &[]).unwrap();
        let text = fs::read_to_string(output).unwrap();
        assert!(text.contains(&format!(
            "Upstream: https://example.com/upstream\nRevision: {REVISION}\n"
        )));
        assert!(text.contains("--- LICENSE.txt ---\nPreserved terms\nCopyright owner\n\n"));
        assert_eq!(text.contains("NOTICE LIMITATION:"), status != "complete");
        if status != "complete" {
            assert!(text.contains("alpha 1.0.0: upstream notice preserved; complete license terms/attribution require upstream clarification"));
        }
    }
}

#[test]
fn rejects_every_sidecar_package_provenance_mismatch_without_output() {
    for field in ["name", "version", "source", "crate_sha256"] {
        let mut fixture = Fixture::new();
        fixture.preserved("alpha", "1.0.0", "complete");
        fixture.sidecar["packages"]["alpha@1.0.0"][field] = json!("mismatch");
        fixture.assert_failure("License provenance mismatch: alpha 1.0.0", &[]);
    }
}

#[test]
fn rejects_every_lockfile_package_provenance_mismatch_without_output() {
    for (original, replacement) in [
        ("name = \"alpha\"", "name = \"beta\""),
        ("version = \"1.0.0\"", "version = \"2.0.0\""),
        (SOURCE, "registry+https://example.com/other"),
        (CHECKSUM, "mismatch"),
    ] {
        let mut fixture = Fixture::new();
        fixture.preserved("alpha", "1.0.0", "complete");
        fixture.lockfile = fixture.lockfile.replace(original, replacement);
        fixture.assert_failure("License provenance mismatch: alpha 1.0.0", &[]);
    }
}

#[test]
fn matches_lockfile_packages_by_source_as_well_as_name_and_version() {
    let mut fixture = Fixture::new();
    fixture.preserved("alpha", "1.0.0", "complete");
    fixture.lockfile.push_str("\n[[package]]\nname = \"alpha\"\nversion = \"1.0.0\"\nsource = \"registry+https://example.com/other\"\nchecksum = \"other\"\n");
    fixture
        .write(&fixture.root().join("notices.txt"), &[])
        .unwrap();
}

#[test]
fn rejects_changed_preserved_text_without_output() {
    let mut fixture = Fixture::new();
    fixture.preserved("alpha", "1.0.0", "complete");
    fixture.file("docs/licenses/alpha/LICENSE.txt", "changed terms");
    fixture.assert_failure(
        "Preserved license hash mismatch: docs/licenses/alpha/LICENSE.txt",
        &[],
    );
}

#[test]
fn does_not_use_fallback_provenance_when_upstream_text_exists() {
    let mut fixture = Fixture::new();
    fixture.preserved("alpha", "1.0.0", "notice-only");
    fixture.sidecar["packages"]["alpha@1.0.0"]["crate_sha256"] = json!("mismatch");
    fixture.file("crates/alpha-1.0.0/LICENSE", "upstream terms");
    let output = fixture.root().join("notices.txt");
    fixture.write(&output, &[]).unwrap();
    let text = fs::read_to_string(output).unwrap();
    assert!(text.contains("upstream terms"));
    assert!(!text.contains("Upstream:"));
    assert!(!text.contains("NOTICE LIMITATION:"));
}

#[test]
fn aggregates_missing_cargo_and_swift_texts_without_creating_output() {
    let mut fixture = Fixture::new();
    fixture.package("zeta", "1.0.0");
    fixture.package("alpha", "1.0.0");
    fixture.pin("swift-zeta", Some("1.0.0"));
    fixture.pin("swift-alpha", Some("1.0.0"));
    fixture.assert_failure(
        "Missing license texts: alpha 1.0.0, zeta 1.0.0, swift-alpha, swift-zeta",
        &[],
    );
}

#[test]
fn rejects_an_empty_fallback_file_list_as_missing_text() {
    let mut fixture = Fixture::new();
    fixture.preserved("alpha", "1.0.0", "complete");
    fixture.sidecar["packages"]["alpha@1.0.0"]["license_files"] = json!([]);
    fixture.assert_failure("Missing license texts: alpha 1.0.0", &[]);
}

#[test]
fn uses_repeated_swift_checkout_paths_before_defaults_and_sorts_pins() {
    let mut fixture = Fixture::new();
    fixture.pin("swift-zeta", Some("1.0.0"));
    fixture.pin("swift-alpha", None);
    let first = fixture.root().join("first checkout");
    let second = fixture.root().join("second checkout");
    fixture.checkout(&first, "swift-zeta", REVISION, Some(b"first terms"));
    fixture.checkout(&second, "swift-alpha", REVISION, Some(b"second terms"));
    fixture.checkout(
        &second,
        "swift-zeta",
        "ffffffffffffffffffffffffffffffffffffffff",
        Some(b"wrong checkout"),
    );
    fixture.checkout(
        &fixture.root().join("swift/MacAuditKit/.build/checkouts"),
        "swift-zeta",
        "ffffffffffffffffffffffffffffffffffffffff",
        Some(b"wrong default"),
    );
    let output = fixture.root().join("notices.txt");
    fixture.write(&output, &[first, second]).unwrap();
    let text = fs::read_to_string(output).unwrap();
    assert!(text.find("swift-alpha None").unwrap() < text.find("swift-zeta 1.0.0").unwrap());
    assert!(text.contains("second terms"));
    assert!(text.contains("first terms"));
    assert!(!text.contains("wrong checkout"));
    assert!(!text.contains("wrong default"));
}

#[test]
fn finds_both_default_swift_checkout_locations() {
    for parent in [
        "swift/MacAuditKit/.build/checkouts",
        "build/DerivedData/SourcePackages/checkouts",
    ] {
        let mut fixture = Fixture::new();
        fixture.pin("swift-alpha", Some("1.0.0"));
        fixture.checkout(
            &fixture.root().join(parent),
            "swift-alpha",
            REVISION,
            Some(b"default terms"),
        );
        let output = fixture.root().join("notices.txt");
        fixture.write(&output, &[]).unwrap();
        assert!(fs::read_to_string(output)
            .unwrap()
            .contains("default terms"));
    }
}

#[test]
fn rejects_mismatched_swift_revision_even_when_license_text_is_missing() {
    for text in [Some(b"terms".as_slice()), None] {
        let mut fixture = Fixture::new();
        fixture.pin("swift-alpha", Some("1.0.0"));
        let parent = fixture.root().join("checkouts");
        fixture.checkout(
            &parent,
            "swift-alpha",
            "ffffffffffffffffffffffffffffffffffffffff",
            text,
        );
        fixture.assert_failure(
            "Swift license checkout revision mismatch: swift-alpha",
            &[parent],
        );
    }
}

#[test]
fn rejects_pinned_swift_checkout_without_license_text() {
    let mut fixture = Fixture::new();
    fixture.pin("swift-alpha", Some("1.0.0"));
    let parent = fixture.root().join("checkouts");
    fixture.checkout(&parent, "swift-alpha", REVISION, None);
    fixture.assert_failure("Missing license texts: swift-alpha", &[parent]);
}
