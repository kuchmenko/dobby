//! `dobby update` — self-update of the dobby binary. See issue #1 §
//! Distribution & updates.

use clap::Args;

use super::not_yet;

#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Resume auto-updates after a critical-state freeze.
    #[arg(long, group = "mode")]
    pub resume: bool,

    /// Trigger interactive migration path for flagged releases (Phase 7 stub).
    #[arg(long, group = "mode")]
    pub interactive: bool,

    /// Roll back this binary to the previous version. Called by
    /// `dobby-rollback.service` on systemd `OnFailure=`.
    #[arg(long, group = "mode", hide = true)]
    pub rollback_self: bool,
}

pub async fn run(_args: UpdateArgs) -> anyhow::Result<()> {
    Err(not_yet("Phase 7", "dobby update"))
}
