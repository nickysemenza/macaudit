//! RuntimesScanner — STUB until lane S3 lands. Emits no findings.
//!
//! Implementation contract: depend only on the frozen types (Finding,
//! FindingKind, Remedy, RemedyCommand, Severity, ScanEvent, ScannerId, Scanner,
//! ScanCtx, CommandRunner, Config, Paths). Send Progress/Finding only. Touch
//! only this file and tests/fixtures/runtimes/.

use async_trait::async_trait;

use crate::model::ScannerId;
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct RuntimesScanner;

#[async_trait]
impl Scanner for RuntimesScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Runtimes
    }

    async fn scan(&self, _ctx: ScanCtx) -> anyhow::Result<()> {
        // STUB: real implementation arrives in lane S3.
        Ok(())
    }
}
