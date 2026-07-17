//! A synthetic scanner used by the `--fake` flag and the M1 skeleton. It proves
//! the architecture end-to-end (streaming findings, deferred sizing, remedies,
//! cancellation) without touching the real machine.

use std::time::Duration;

use async_trait::async_trait;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::{ScanCtx, Scanner};

/// Emits a handful of believable findings for one section, including a finding
/// whose size arrives in a later event (exercises upsert-by-id).
pub struct FakeScanner {
    id: ScannerId,
}

impl FakeScanner {
    pub fn for_section(id: ScannerId) -> Self {
        FakeScanner { id }
    }

    fn kind_for(id: ScannerId) -> FindingKind {
        match id {
            ScannerId::Apps => FindingKind::App,
            ScannerId::Brew => FindingKind::BrewFormula,
            ScannerId::Fs => FindingKind::BuildArtifact,
            ScannerId::Launchd => FindingKind::LaunchdItem,
            ScannerId::ShellEnv => FindingKind::PathEntry,
            ScannerId::Runtimes => FindingKind::RuntimeVersion,
            ScannerId::Docker => FindingKind::DockerObject,
            ScannerId::Ports => FindingKind::PortListener,
            ScannerId::Git => FindingKind::GitRepo,
            ScannerId::Simulator => FindingKind::Simulator,
            ScannerId::SshKeys => FindingKind::SshKey,
            ScannerId::TmSnapshots => FindingKind::LocalSnapshot,
        }
    }
}

#[async_trait]
impl Scanner for FakeScanner {
    fn id(&self) -> ScannerId {
        self.id
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        let kind = Self::kind_for(self.id);
        ctx.progress("scanning…", 0, Some(3)).await;

        for i in 0..3u64 {
            if ctx.cancelled() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(120)).await;
            let key = format!("{}/{}", self.id.slug(), i);
            let title = format!("{} item {}", self.id.slug(), i);
            let mut f = Finding::new(kind, &key, title)
                .detail(format!("synthetic finding #{i} for {}", self.id.slug()))
                .path(format!("/fake/{}/{}", self.id.slug(), i))
                .severity(match i % 3 {
                    0 => Severity::Reclaimable,
                    1 => Severity::Attention,
                    _ => Severity::Info,
                });
            // First finding gets its size immediately; second gets it in a
            // follow-up event (deferred sizing); third stays unsized.
            if i == 0 {
                f = f.size(512 * 1024 * 1024 + i * 1000);
                f = f.remedy(Remedy {
                    label: "Delete (move to Trash)".into(),
                    command: RemedyCommand::Trash {
                        path: format!("/fake/{}/{}", self.id.slug(), i).into(),
                    },
                    reclaims_bytes: Some(512 * 1024 * 1024),
                    destructive: true,
                });
            }
            ctx.emit(f).await;
            ctx.progress("scanning…", i + 1, Some(3)).await;
        }

        // Deferred size update for item 1: re-emit the same id with a size.
        if !ctx.cancelled() {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let key = format!("{}/{}", self.id.slug(), 1);
            let f = Finding::new(kind, &key, format!("{} item 1", self.id.slug()))
                .detail("synthetic finding #1 (sized)")
                .path(format!("/fake/{}/1", self.id.slug()))
                .severity(Severity::Attention)
                .size(128 * 1024 * 1024);
            ctx.emit(f).await;
        }

        Ok(())
    }
}
