use crate::metadata::Metadata;
use crate::Result;

#[derive(Debug)]
pub(crate) struct Report {
    pub output: String,
    pub failures: Vec<String>,
}

fn supported_version(minimum: &str) -> Result<bool> {
    let mut version = [0_u64; 3];
    for (index, part) in minimum.split('.').enumerate() {
        if index >= version.len()
            || part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(format!("expected a stable numeric Rust version, got {minimum:?}").into());
        }
        version[index] = part.parse()?;
    }
    Ok(version <= [1, 93, 0])
}

pub(crate) fn check(metadata: &Metadata, licenses: bool) -> Result<Report> {
    let mut failures = Vec::new();
    let mut output = String::new();
    for package in metadata.sorted_packages() {
        if let Some(minimum) = package.rust_version.as_deref() {
            if !supported_version(minimum).map_err(|error| {
                format!(
                    "Invalid Rust version for {} {}: {minimum}: {error}",
                    package.name, package.version
                )
            })? {
                failures.push(format!(
                    "{} {} requires Rust {minimum}",
                    package.name, package.version
                ));
            }
        }
        if package.source.is_some() && package.declared_license().is_none() {
            failures.push(format!(
                "{} {} has no declared license",
                package.name, package.version
            ));
        }
        if licenses {
            output.push_str(&format!(
                "{} {}\t{}\n",
                package.name,
                package.version,
                package.declared_license().unwrap_or("workspace")
            ));
        }
    }
    if metadata
        .packages
        .iter()
        .any(|package| package.name == "rusqlite")
    {
        failures.push("persistent rusqlite dependency remains in the resolved graph".to_owned());
    }
    if !licenses && failures.is_empty() {
        output.push_str(&format!(
            "Verified {} resolved packages against Rust 1.93 and declared licenses\n",
            metadata.packages.len()
        ));
    }
    Ok(Report { output, failures })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compares_all_version_components_at_the_msrv_boundary() {
        for minimum in ["0.99", "1", "1.9", "1.92.999", "1.93", "1.93.0"] {
            assert!(supported_version(minimum).unwrap(), "{minimum}");
        }
        for minimum in ["1.93.1", "1.93.999", "1.94", "1.100.0", "2.0", "93.1"] {
            assert!(!supported_version(minimum).unwrap(), "{minimum}");
        }
        for minimum in [
            "",
            "invalid",
            "1.invalid",
            "1.93-beta",
            "1.93.0-beta.1",
            "1.92.invalid",
            "1.92.0.extra",
            "1.93.0+metadata",
            "1..0",
            "1.93.",
            "+1.93.0",
        ] {
            assert!(supported_version(minimum).is_err(), "{minimum}");
        }
    }

    #[test]
    fn sorts_inventory_and_aggregates_graph_failures() {
        let metadata: Metadata = serde_json::from_value(json!({"packages": [
            {"name": "zeta", "version": "2.0", "source": "registry+example", "rust_version": "1.94", "license": null, "manifest_path": "zeta/Cargo.toml"},
            {"name": "alpha", "version": "1.9", "source": "registry+example", "license_file": "COPYING", "manifest_path": "alpha/Cargo.toml"},
            {"name": "rusqlite", "version": "0.1", "source": null, "manifest_path": "rusqlite/Cargo.toml"},
            {"name": "alpha", "version": "1.10", "source": null, "license": "MIT", "manifest_path": "alpha/Cargo.toml"}
        ]})).unwrap();
        let report = check(&metadata, true).unwrap();
        assert_eq!(
            report.output,
            "alpha 1.10\tMIT\nalpha 1.9\tCOPYING\nrusqlite 0.1\tworkspace\nzeta 2.0\tworkspace\n"
        );
        assert_eq!(
            report.failures,
            [
                "zeta 2.0 requires Rust 1.94",
                "zeta 2.0 has no declared license",
                "persistent rusqlite dependency remains in the resolved graph"
            ]
        );
        assert!(check(&metadata, false).unwrap().output.is_empty());
    }

    #[test]
    fn accepts_workspace_packages_and_declared_external_license_files() {
        let metadata: Metadata = serde_json::from_value(json!({"packages": [
            {"name": "workspace", "version": "0.1", "source": null, "manifest_path": "Cargo.toml"},
            {"name": "external", "version": "0.1", "source": "git+example", "rust_version": "1.93", "license": "", "license_file": "LICENSE.txt", "manifest_path": "external/Cargo.toml"}
        ]})).unwrap();
        let report = check(&metadata, false).unwrap();
        assert!(report.failures.is_empty());
        assert_eq!(
            report.output,
            "Verified 2 resolved packages against Rust 1.93 and declared licenses\n"
        );
    }

    #[test]
    fn rejects_patch_versions_above_the_floor_and_malformed_patch_suffixes() {
        let mut metadata: Metadata = serde_json::from_value(json!({"packages": [
            {"name": "external", "version": "0.1", "source": "registry+example", "rust_version": "1.93.1", "license": "MIT", "manifest_path": "Cargo.toml"}
        ]})).unwrap();
        assert_eq!(
            check(&metadata, false).unwrap().failures,
            ["external 0.1 requires Rust 1.93.1"]
        );
        metadata.packages[0].rust_version = Some("1.92.invalid".to_owned());
        assert!(check(&metadata, false)
            .unwrap_err()
            .to_string()
            .starts_with("Invalid Rust version for external 0.1: 1.92.invalid:"));
    }
}
