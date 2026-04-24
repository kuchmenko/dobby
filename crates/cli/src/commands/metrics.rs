//! `dobby metrics` — resource utilisation dump. Phase 5+.

use clap::Args;

use super::not_yet;

#[derive(Debug, Args)]
pub struct MetricsArgs {
    /// Limit to a specific app.
    pub name: Option<String>,
}

pub async fn run(_args: MetricsArgs) -> anyhow::Result<()> {
    Err(not_yet("Phase 5", "dobby metrics"))
}
