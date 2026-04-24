//! `dobby status` — fleet overview with MANAGED / SHARED / UNMANAGED
//! classification and per-app health. See issue #1 § Container
//! classification and Fault tolerance (Elf unreachable).

use clap::Args;

use super::not_yet;

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Limit to a specific app.
    pub name: Option<String>,
}

pub async fn run(_args: StatusArgs) -> anyhow::Result<()> {
    Err(not_yet("Phase 1", "dobby status"))
}
