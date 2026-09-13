//! The single source of truth mapping `ScannerId` → section metadata and its
//! constructor. Sidebar rendering, `--section` filtering, and the engine's
//! spawn list all iterate `REGISTRY`, so adding/removing a scanner is a one-line
//! change here rather than an edit in three files (avoids fan-out merge wars).

use crate::model::ScannerId;
use crate::scan::apps::AppsScanner;
use crate::scan::brew::BrewScanner;
use crate::scan::docker::DockerScanner;
use crate::scan::fs::FsScanner;
use crate::scan::git::GitScanner;
use crate::scan::launchd::LaunchdScanner;
use crate::scan::ports::PortsScanner;
use crate::scan::runtimes::RuntimesScanner;
use crate::scan::shell_env::ShellEnvScanner;
use crate::scan::simulator::SimulatorScanner;
use crate::scan::ssh_keys::SshKeysScanner;
use crate::scan::system::SystemScanner;
use crate::scan::tm_snapshots::TmSnapshotsScanner;
use crate::scan::Scanner;

/// How a section's findings are primarily presented.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ViewKind {
    /// Purpose-built summary screen for point-in-time resource health.
    Overview,
    /// Collapsible tree (Apps, Brew dependency trees).
    Tree,
    /// Sortable flat table (Disk, Ports, everything else).
    Table,
}

/// Static metadata + constructor for one scanner section.
pub struct SectionMeta {
    pub id: ScannerId,
    pub title: &'static str,
    /// ≤10-column label for the nav rail.
    pub short_title: &'static str,
    pub view: ViewKind,
    /// Build a fresh scanner instance. Boxed trait object so the engine can hold
    /// a heterogeneous list.
    pub build: fn() -> Box<dyn Scanner>,
}

/// The canonical section list, in sidebar order.
pub const REGISTRY: &[SectionMeta] = &[
    SectionMeta {
        id: ScannerId::System,
        title: "Resource Health",
        short_title: "Health",
        view: ViewKind::Overview,
        build: || Box::new(SystemScanner),
    },
    SectionMeta {
        id: ScannerId::Apps,
        title: "Apps",
        short_title: "Apps",
        view: ViewKind::Tree,
        build: || Box::new(AppsScanner),
    },
    SectionMeta {
        id: ScannerId::Brew,
        title: "Brew",
        short_title: "Brew",
        view: ViewKind::Tree,
        build: || Box::new(BrewScanner),
    },
    SectionMeta {
        id: ScannerId::Fs,
        title: "Disk",
        short_title: "Disk",
        // Grouped by artifact category (node_modules / target / Caches /
        // Large files / iOS Backups …) — thousands of flat rows are unreadable.
        view: ViewKind::Tree,
        build: || Box::new(FsScanner),
    },
    SectionMeta {
        id: ScannerId::Launchd,
        title: "Daemons",
        short_title: "Daemons",
        view: ViewKind::Table,
        build: || Box::new(LaunchdScanner),
    },
    SectionMeta {
        id: ScannerId::ShellEnv,
        title: "Shell",
        short_title: "Shell",
        view: ViewKind::Table,
        build: || Box::new(ShellEnvScanner),
    },
    SectionMeta {
        id: ScannerId::Runtimes,
        title: "Runtimes",
        short_title: "Runtimes",
        view: ViewKind::Table,
        build: || Box::new(RuntimesScanner),
    },
    SectionMeta {
        id: ScannerId::Docker,
        title: "Docker",
        short_title: "Docker",
        view: ViewKind::Table,
        build: || Box::new(DockerScanner),
    },
    SectionMeta {
        id: ScannerId::Ports,
        title: "Ports",
        short_title: "Ports",
        view: ViewKind::Table,
        build: || Box::new(PortsScanner),
    },
    SectionMeta {
        id: ScannerId::Git,
        title: "Git",
        short_title: "Git",
        view: ViewKind::Table,
        build: || Box::new(GitScanner),
    },
    SectionMeta {
        id: ScannerId::Simulator,
        title: "Simulators",
        short_title: "Simulators",
        view: ViewKind::Table,
        build: || Box::new(SimulatorScanner),
    },
    SectionMeta {
        id: ScannerId::SshKeys,
        title: "Keys",
        short_title: "Keys",
        view: ViewKind::Table,
        build: || Box::new(SshKeysScanner),
    },
    SectionMeta {
        id: ScannerId::TmSnapshots,
        title: "Snapshots",
        short_title: "Snapshots",
        view: ViewKind::Table,
        build: || Box::new(TmSnapshotsScanner),
    },
];

/// Look up a section's metadata by id.
pub fn section(id: ScannerId) -> &'static SectionMeta {
    REGISTRY
        .iter()
        .find(|s| s.id == id)
        .expect("REGISTRY missing a ScannerId — keep it in sync with ScannerId::ALL")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn registry_covers_every_scanner_id_exactly_once() {
        assert_eq!(REGISTRY.len(), ScannerId::ALL.len());
        let ids: HashSet<_> = REGISTRY.iter().map(|s| s.id).collect();
        assert_eq!(ids.len(), REGISTRY.len(), "duplicate id in REGISTRY");
        for id in ScannerId::ALL {
            assert!(ids.contains(id), "REGISTRY missing {:?}", id);
        }
    }

    #[test]
    fn every_scanner_reports_its_registered_id() {
        for meta in REGISTRY {
            let scanner = (meta.build)();
            assert_eq!(scanner.id(), meta.id, "{} builds wrong id", meta.title);
        }
    }
}
