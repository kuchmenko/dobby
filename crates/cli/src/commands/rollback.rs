//! `dobby rollback` — swap symlinks back to the previous version.

use clap::Args;

use super::not_yet;

#[derive(Debug, Args)]
pub struct RollbackArgs {
    /// App name.
    pub name: String,

    /// Restrict rollback to a single service; otherwise all services.
    #[arg(long, value_name = "SVC")]
    pub service: Option<String>,
}

pub async fn run(_args: RollbackArgs) -> anyhow::Result<()> {
    Err(not_yet("Phase 2", "dobby rollback"))
}
