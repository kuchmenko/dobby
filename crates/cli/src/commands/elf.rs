//! `dobby elf ...` — Elf daemon inside a managed LXC.
//!
//! Phase 1 exposes only `dobby elf start`. Deploy / RequestSecrets /
//! StreamLogs / Exec are Keeper-initiated gRPCs, not CLI subcommands.

use clap::{Args, Subcommand};

use super::not_yet;

#[derive(Debug, Subcommand)]
pub enum ElfCommand {
    /// Start the Elf daemon (mTLS gRPC server + systemd-notify lifecycle).
    Start(StartArgs),
}

#[derive(Debug, Args)]
pub struct StartArgs {}

pub async fn run(cmd: ElfCommand) -> anyhow::Result<()> {
    match cmd {
        ElfCommand::Start(_) => Err(not_yet("Phase 1", "dobby elf start")),
    }
}
