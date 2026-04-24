//! `dobby destroy` — tear down a managed LXC and remove registry /
//! DNS / watcher state. See issue #1 § Safety & resource management.

use clap::Args;

use super::not_yet;

#[derive(Debug, Args)]
pub struct DestroyArgs {
    /// App name.
    pub name: String,

    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

pub async fn run(_args: DestroyArgs) -> anyhow::Result<()> {
    Err(not_yet("Phase 2", "dobby destroy"))
}
