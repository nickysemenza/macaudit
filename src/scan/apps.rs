//! AppsScanner — STUB until lane S1 lands. Emits no findings.
//!
//! Implementation contract: depend only on the frozen types (Finding,
//! FindingKind, Remedy, RemedyCommand, Severity, ScanEvent, ScannerId, Scanner,
//! ScanCtx, CommandRunner, Config, Paths). Send Progress/Finding only. Touch
//! only this file and tests/fixtures/apps/.

use async_trait::async_trait;

use crate::model::ScannerId;
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct AppsScanner;

#[async_trait]
impl Scanner for AppsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Apps
    }

    async fn scan(&self, _ctx: ScanCtx) -> anyhow::Result<()> {
        // STUB: real implementation arrives in lane S1.
        Ok(())
    }
}
