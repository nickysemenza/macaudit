use crate::metadata::{command_output, Metadata, Package};
use crate::Result;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(test)]
mod tests;

#[derive(Deserialize)]
struct Sidecar {
    packages: BTreeMap<String, PreservedPackage>,
    files: BTreeMap<String, PreservedFile>,
}

#[derive(Deserialize)]
struct PreservedPackage {
    name: String,
    version: String,
    source: String,
    crate_sha256: String,
    license_files: Vec<String>,
    repository: String,
    revision: String,
    license_text_status: String,
}

#[derive(Deserialize)]
struct PreservedFile {
    sha256: String,
}

#[derive(Deserialize)]
struct Lockfile {
    package: Vec<LockedPackage>,
}

#[derive(Deserialize)]
struct LockedPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

#[derive(Deserialize)]
struct SwiftResolved {
    pins: Vec<SwiftPin>,
}

#[derive(Deserialize)]
struct SwiftPin {
    identity: String,
    location: String,
    state: SwiftState,
}

#[derive(Deserialize)]
struct SwiftState {
    revision: String,
    version: Option<String>,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?)
        .map_err(|error| format!("{}: {error}", path.display()).into())
}

fn license_files(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in
        fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let path = entry?.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_uppercase();
        if path.is_file()
            && ["LICENSE", "LICENCE", "COPYING", "NOTICE"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn append_files(notices: &mut String, files: &[PathBuf]) -> Result<()> {
    for file in files {
        let bytes = fs::read(file).map_err(|error| format!("{}: {error}", file.display()))?;
        let text = String::from_utf8_lossy(&bytes)
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        notices.push_str(&format!(
            "\n--- {} ---\n{text}\n",
            file.file_name().unwrap_or_default().to_string_lossy()
        ));
    }
    Ok(())
}

fn preserved_files(
    root: &Path,
    package: &Package,
    fallback: &PreservedPackage,
    sidecar: &Sidecar,
    locked: &Lockfile,
) -> Result<Vec<PathBuf>> {
    let archives: Vec<_> = locked
        .package
        .iter()
        .filter(|archive| {
            archive.name == package.name
                && archive.version == package.version
                && archive.source == package.source
        })
        .collect();
    if fallback.name != package.name
        || fallback.version != package.version
        || Some(fallback.source.as_str()) != package.source.as_deref()
        || archives.len() != 1
        || archives[0].checksum.as_deref() != Some(fallback.crate_sha256.as_str())
    {
        return Err(format!(
            "License provenance mismatch: {} {}",
            package.name, package.version
        )
        .into());
    }
    let mut files = Vec::new();
    for relative in &fallback.license_files {
        let file = root.join(relative);
        let expected = sidecar
            .files
            .get(relative)
            .ok_or_else(|| format!("Missing preserved license hash: {relative}"))?;
        let bytes = fs::read(&file).map_err(|error| format!("{}: {error}", file.display()))?;
        if format!("{:x}", Sha256::digest(&bytes)) != expected.sha256 {
            return Err(format!("Preserved license hash mismatch: {relative}").into());
        }
        files.push(file);
    }
    Ok(files)
}

pub(crate) fn write(
    root: &Path,
    metadata: &Metadata,
    output: &Path,
    swift_checkouts: &[PathBuf],
) -> Result<()> {
    let sidecar: Sidecar = read_json(&root.join("docs/licenses/manifest.json"))?;
    let lock_path = root.join("Cargo.lock");
    let locked: Lockfile = toml::from_str(
        &fs::read_to_string(&lock_path)
            .map_err(|error| format!("{}: {error}", lock_path.display()))?,
    )
    .map_err(|error| format!("{}: {error}", lock_path.display()))?;
    let mut notices = String::from("MacAudit third-party notices\n");
    let mut missing = Vec::new();
    for package in metadata.sorted_packages() {
        if package.source.is_none() {
            continue;
        }
        let directory = package
            .manifest_path
            .parent()
            .ok_or_else(|| format!("Invalid manifest path: {}", package.manifest_path.display()))?;
        let mut files = license_files(directory)?;
        if let Some(declared) = &package.license_file {
            let declared = directory.join(declared);
            if declared.is_file() && !files.contains(&declared) {
                files.push(declared);
            }
        }
        let fallback = if files.is_empty() {
            sidecar
                .packages
                .get(&format!("{}@{}", package.name, package.version))
        } else {
            None
        };
        if let Some(fallback) = fallback {
            files = preserved_files(root, package, fallback, &sidecar, &locked)?;
        }
        if files.is_empty() {
            missing.push(format!("{} {}", package.name, package.version));
        }
        notices.push_str(&format!(
            "\n{}\n{} {}\nLicense: {}\n",
            "=".repeat(72),
            package.name,
            package.version,
            package.declared_license().unwrap_or("None")
        ));
        if let Some(fallback) = fallback {
            notices.push_str(&format!(
                "Upstream: {}\nRevision: {}\n",
                fallback.repository, fallback.revision
            ));
            if fallback.license_text_status != "complete" {
                let warning = format!(
                    "{} {}: upstream notice preserved; complete license terms/attribution require upstream clarification",
                    package.name, package.version
                );
                notices.push_str(&format!("NOTICE LIMITATION: {warning}\n"));
                eprintln!("{warning}");
            }
        }
        append_files(&mut notices, &files)?;
    }
    let mut resolved: SwiftResolved = read_json(&root.join("swift/MacAuditKit/Package.resolved"))?;
    let checkouts: Vec<_> = swift_checkouts
        .iter()
        .cloned()
        .chain([
            root.join("swift/MacAuditKit/.build/checkouts"),
            root.join("build/DerivedData/SourcePackages/checkouts"),
        ])
        .collect();
    resolved
        .pins
        .sort_by(|left, right| left.identity.cmp(&right.identity));
    for pin in resolved.pins {
        let directory = checkouts
            .iter()
            .map(|checkout| checkout.join(&pin.identity))
            .find(|directory| directory.is_dir());
        let files = if let Some(directory) = directory {
            let files = license_files(&directory)?;
            let revision = command_output(
                Command::new("git")
                    .arg("-C")
                    .arg(&directory)
                    .args(["rev-parse", "HEAD"]),
                "git rev-parse HEAD",
            )?;
            if String::from_utf8(revision.stdout)?.trim() != pin.state.revision {
                return Err(
                    format!("Swift license checkout revision mismatch: {}", pin.identity).into(),
                );
            }
            files
        } else {
            Vec::new()
        };
        if files.is_empty() {
            missing.push(pin.identity.clone());
        }
        notices.push_str(&format!(
            "\n{}\n{} {}\n{}\nRevision: {}\n",
            "=".repeat(72),
            pin.identity,
            pin.state.version.as_deref().unwrap_or("None"),
            pin.location,
            pin.state.revision
        ));
        append_files(&mut notices, &files)?;
    }
    if !missing.is_empty() {
        return Err(format!("Missing license texts: {}", missing.join(", ")).into());
    }
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    fs::write(output, notices).map_err(|error| format!("{}: {error}", output.display()).into())
}
