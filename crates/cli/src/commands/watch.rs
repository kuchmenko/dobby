//! `dobby watch` — operational control over the release watcher for an app.

use clap::{Args, Subcommand};

use super::not_yet;

#[derive(Debug, Subcommand)]
pub enum WatchCommand {
    /// Start the watcher for `<name>` (auto on `dobby init` if a trigger is set).
    Start(AppArgs),
    /// Stop the watcher.
    Stop(AppArgs),
    /// Print the watcher state.
    Status(AppArgs),
}

#[derive(Debug, Args)]
pub struct AppArgs {
    /// App name.
    pub name: String,
}

pub async fn run(cmd: WatchCommand) -> anyhow::Result<()> {
    let phase = "Phase 4";
    match cmd {
        WatchCommand::Start(_) => Err(not_yet(phase, "dobby watch start")),
        WatchCommand::Stop(_) => Err(not_yet(phase, "dobby watch stop")),
        WatchCommand::Status(_) => Err(not_yet(phase, "dobby watch status")),
    }
}
