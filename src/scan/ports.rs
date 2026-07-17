//! PortsScanner — STUB until lane S4 lands. Emits no findings.
//!
//! Implementation contract: depend only on the frozen types (Finding,
//! FindingKind, Remedy, RemedyCommand, Severity, ScanEvent, ScannerId, Scanner,
//! ScanCtx, CommandRunner, Config, Paths). Send Progress/Finding only. Touch
//! only this file and tests/fixtures/ports/.

use async_trait::async_trait;

use crate::model::ScannerId;
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct PortsScanner;

#[async_trait]
impl Scanner for PortsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Ports
    }

    async fn scan(&self, _ctx: ScanCtx) -> anyhow::Result<()> {
        // STUB: real implementation arrives in lane S4.
        Ok(())
    }
}
