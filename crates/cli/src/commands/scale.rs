//! `dobby scale` — adjust cores / memory / disk of a managed LXC.

use clap::Args;

use super::not_yet;

#[derive(Debug, Args)]
pub struct ScaleArgs {
    /// App name.
    pub name: String,

    /// New memory limit in MiB.
    #[arg(long)]
    pub memory: Option<u32>,

    /// New CPU core count.
    #[arg(long)]
    pub cores: Option<u32>,

    /// New root disk size in GiB.
    #[arg(long)]
    pub disk: Option<u32>,
}

pub async fn run(_args: ScaleArgs) -> anyhow::Result<()> {
    Err(not_yet("Phase 3c", "dobby scale"))
}
