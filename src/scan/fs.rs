//! FsScanner — STUB until lane S2 lands. Emits no findings.
//!
//! Implementation contract: depend only on the frozen types (Finding,
//! FindingKind, Remedy, RemedyCommand, Severity, ScanEvent, ScannerId, Scanner,
//! ScanCtx, CommandRunner, Config, Paths). Send Progress/Finding only. Touch
//! only this file and tests/fixtures/fs/.

use async_trait::async_trait;

use crate::model::ScannerId;
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct FsScanner;

#[async_trait]
impl Scanner for FsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Fs
    }

    async fn scan(&self, _ctx: ScanCtx) -> anyhow::Result<()> {
        // STUB: real implementation arrives in lane S2.
        Ok(())
    }
}
