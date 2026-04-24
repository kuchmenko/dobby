//! Dobby CLI — clap command tree.
//!
//! The top-level `dobby` binary (at workspace root) calls into this
//! crate via [`dispatch`] after initialising tracing. Each subcommand
//! lives in its own module under [`commands`] and returns an
//! `anyhow::Result<()>`.
//!
//! Phase 1 scope: the full UX surface is wired (every command from
//! issue #1 is visible in `dobby --help`), but nearly every handler
//! returns [`anyhow::Error`] with a `unimplemented: phase N` message
//! until its phase lands.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

pub mod commands;

/// Top-level CLI parser.
#[derive(Debug, Parser)]
#[command(
    name = "dobby",
    version,
    about = "Proxmox LXC deployment automation",
    long_about = "dobby — a single binary in three personas (CLI / Keeper / Elf). \
                  CLI runs on the workstation, Keeper runs on the Proxmox node's \
                  dedicated LXC, Elf runs inside each managed LXC. See \
                  https://github.com/kuchmenko/dobby/issues/1 for the full design."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands. Keep in sync with issue #1 § CLI commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Keeper daemon lifecycle, bootstrap, backup/restore, key rotation.
    #[command(subcommand)]
    Keeper(commands::keeper::KeeperCommand),

    /// Elf daemon lifecycle (runs inside managed LXCs).
    #[command(subcommand)]
    Elf(commands::elf::ElfCommand),

    /// Pair this workstation with a Keeper (mDNS auto or explicit address).
    Pair(commands::pair::PairArgs),

    /// Register a shared (non-dobby-managed) LXC as a dependency endpoint.
    Register(commands::register::RegisterArgs),

    /// Validate `dobby.toml` — dependency cycles, cross-refs, ports, env.
    Check(commands::check::CheckArgs),

    /// Create a managed LXC and deploy the app defined by `dobby.toml`.
    Init(commands::init::InitArgs),

    /// Destroy a managed LXC and remove its registry entries.
    Destroy(commands::destroy::DestroyArgs),

    /// Adjust a managed LXC's cores / memory / disk.
    Scale(commands::scale::ScaleArgs),

    /// Deploy a new artefact (GitHub Release tag or local file).
    Push(commands::push::PushArgs),

    /// Roll back one or all services to the previous version.
    Rollback(commands::rollback::RollbackArgs),

    /// Release watcher — start / stop / status.
    #[command(subcommand)]
    Watch(commands::watch::WatchCommand),

    /// Per-app secrets management (set, list, history, rollback, gc).
    #[command(subcommand)]
    Secrets(commands::secrets::SecretsCommand),

    /// Fleet overview — MANAGED / SHARED / UNMANAGED with health.
    Status(commands::status::StatusArgs),

    /// Exec a command inside an LXC, a service user, or an OCI container.
    Exec(commands::exec::ExecArgs),

    /// Stream logs — app, Keeper-host, audit, DNS.
    Logs(commands::logs::LogsArgs),

    /// Scoped API tokens for CI (Phase 4+).
    #[command(subcommand)]
    Token(commands::token::TokenCommand),

    /// Self-update of the dobby binary.
    Update(commands::update::UpdateArgs),

    /// Resource metrics (Phase 5+).
    Metrics(commands::metrics::MetricsArgs),
}

/// Dispatch a parsed [`Cli`] to the appropriate handler.
pub async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    use Command as C;
    match cli.command {
        C::Keeper(cmd) => commands::keeper::run(cmd).await,
        C::Elf(cmd) => commands::elf::run(cmd).await,
        C::Pair(args) => commands::pair::run(args).await,
        C::Register(args) => commands::register::run(args).await,
        C::Check(args) => commands::check::run(args).await,
        C::Init(args) => commands::init::run(args).await,
        C::Destroy(args) => commands::destroy::run(args).await,
        C::Scale(args) => commands::scale::run(args).await,
        C::Push(args) => commands::push::run(args).await,
        C::Rollback(args) => commands::rollback::run(args).await,
        C::Watch(cmd) => commands::watch::run(cmd).await,
        C::Secrets(cmd) => commands::secrets::run(cmd).await,
        C::Status(args) => commands::status::run(args).await,
        C::Exec(args) => commands::exec::run(args).await,
        C::Logs(args) => commands::logs::run(args).await,
        C::Token(cmd) => commands::token::run(cmd).await,
        C::Update(args) => commands::update::run(args).await,
        C::Metrics(args) => commands::metrics::run(args).await,
    }
}
