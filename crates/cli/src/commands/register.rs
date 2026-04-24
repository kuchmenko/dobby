//! `dobby register` — register an existing (SHARED) LXC as a dependency
//! endpoint discoverable via `.dobby` DNS. See issue #1 § Container
//! classification → SHARED.

use clap::Args;

use super::not_yet;

#[derive(Debug, Args)]
pub struct RegisterArgs {
    /// Short name used for DNS (`<name>.dobby`).
    pub name: String,

    /// Proxmox VMID of the existing LXC.
    #[arg(long)]
    pub vmid: u32,

    /// Service port (informational — DNS still only holds an A record).
    #[arg(long)]
    pub port: Option<u16>,
}

pub async fn run(_args: RegisterArgs) -> anyhow::Result<()> {
    Err(not_yet("Phase 1", "dobby register"))
}
