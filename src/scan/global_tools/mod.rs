//! Global developer-tool audit: what is installed by npm, pnpm, cargo, pipx,
//! uv, pip and bun; which manager owns each copy; which executable the user's
//! login shell actually runs; and what evidence supports keeping or removing
//! each installation.
//!
//! Scans are filesystem-metadata-first: the only subprocesses are one login
//! shell probe for `$PATH` and an optional `npm prefix -g`. Discovered
//! binaries are never executed and Python modules are never imported.

use async_trait::async_trait;

use crate::model::{Finding, FindingKind, ScannerId};
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct ToolsScanner;

#[async_trait]
impl Scanner for ToolsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Tools
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        ctx.emit(
            Finding::new(
                FindingKind::ToolCoverage,
                "__coverage__",
                "Global tools coverage",
            )
            .detail("no managers scanned yet")
            .meta(serde_json::json!({ "managers": {} })),
        )
        .await;
        Ok(())
    }
}
