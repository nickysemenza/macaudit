use crate::Result;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Debug, Deserialize)]
pub(crate) struct Metadata {
    pub packages: Vec<Package>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Package {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub rust_version: Option<String>,
    pub license: Option<String>,
    pub license_file: Option<String>,
    pub manifest_path: PathBuf,
}

impl Package {
    pub fn declared_license(&self) -> Option<&str> {
        self.license
            .as_deref()
            .filter(|value| !value.is_empty())
            .or(self
                .license_file
                .as_deref()
                .filter(|value| !value.is_empty()))
    }
}

impl Metadata {
    pub fn sorted_packages(&self) -> Vec<&Package> {
        let mut packages: Vec<_> = self.packages.iter().collect();
        packages
            .sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
        packages
    }
}

pub(crate) fn command_output(command: &mut Command, description: &str) -> Result<Output> {
    let output = command
        .output()
        .map_err(|error| format!("Failed to run {description}: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{description} failed ({}): {}",
            output.status,
            stderr.trim()
        )
        .into());
    }
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(output)
}

fn cargo_metadata(root: &Path, no_dependencies: bool) -> Result<Vec<u8>> {
    let mut command = Command::new("cargo");
    command.current_dir(root).args(["metadata", "--locked"]);
    if no_dependencies {
        command.arg("--no-deps");
    }
    command.args(["--format-version", "1"]);
    Ok(command_output(&mut command, "cargo metadata")?.stdout)
}

pub(crate) fn load(root: &Path) -> Result<Metadata> {
    serde_json::from_slice(&cargo_metadata(root, false)?)
        .map_err(|error| format!("Invalid cargo metadata: {error}").into())
}

pub(crate) fn target_directory(root: &Path) -> Result<PathBuf> {
    #[derive(Deserialize)]
    struct TargetMetadata {
        target_directory: PathBuf,
    }

    let metadata: TargetMetadata = serde_json::from_slice(&cargo_metadata(root, true)?)
        .map_err(|error| format!("Invalid cargo metadata: {error}"))?;
    Ok(metadata.target_directory)
}
