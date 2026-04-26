//! Dobby Keeper — daemon running inside its own unprivileged LXC on
//! the Proxmox host. See issue #1 § High-level architecture.
//!
//! Phase 1 surface (this slice):
//!   - tonic gRPC server bound on `keeper_ip:8443` with the host TLS identity from
//!     `<dir>/tls/host.{crt,key}`
//!   - `KeeperService::HealthCheck` returns version + ok status
//!   - `KeeperService::Pair` is a stub returning `Unimplemented`
//!   - graceful shutdown on `SIGINT` / `SIGTERM`
//!
//! Out of scope here (each lands in its own PR):
//!   - mDNS advertisement
//!   - embedded `.dobby` DNS server + source-IP allowlist
//!   - reverse proxy
//!   - sd_notify(READY=1) + WATCHDOG=1 event loop
//!   - ed25519 signature verification on incoming CLI requests
//!   - real Pair logic (bootstrap-token verification + workstation pubkey registry)

#![allow(dead_code)] // skeleton stubs filled per phase

use std::path::Path;

mod config;
mod server;
mod services;
mod tls;

pub use server::ServerError;

/// Re-exports of internal helpers for end-to-end integration tests
/// in this crate. Not a stable surface — `cfg(any(test, feature =
/// "test-support"))` would be cleaner, but `tonic`'s gen code makes
/// feature gymnastics painful. Keeping this `pub` is intentional and
/// scoped to in-tree tests; downstream code depends on `run` only.
pub mod test_support {
    pub use crate::{server::serve, tls::load_server_tls};
}

/// Run the Keeper daemon until `SIGINT` / `SIGTERM`.
///
/// `dir` is the Keeper state directory produced by `dobby keeper init`,
/// conventionally `/etc/dobby`. We read `keeper.toml` from there for
/// the bind address and load the host TLS material from `tls/`.
pub async fn run(dir: &Path) -> Result<(), ServerError> {
    server::run(dir).await
}
