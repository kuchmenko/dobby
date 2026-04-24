//! `dobby init` — create a managed LXC and deploy the app defined by
//! `dobby.toml`. See issue #1 § Core workflow and Bootstrap details.

use clap::Args;

use super::not_yet;

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Override path to the manifest (default: `./dobby.toml`).
    #[arg(long, value_name = "PATH", default_value = "dobby.toml")]
    pub file: std::path::PathBuf,

    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,

    /// Force a specific Proxmox VMID (default: first free from 200+).
    #[arg(long)]
    pub vmid: Option<u32>,
}

pub async fn run(_args: InitArgs) -> anyhow::Result<()> {
    Err(not_yet("Phase 2", "dobby init"))
}
