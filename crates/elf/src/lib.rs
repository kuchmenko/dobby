//! Dobby Elf — daemon running inside each managed LXC.
//! Responsibilities:
//!
//!   - tonic mTLS gRPC server (`Keeper ↔ Elf`)
//!   - artefact deployment (download, unpack, symlink swap, restart)
//!   - native OCI container runtime (via `dobby-runtime`, Phase 3)
//!   - per-service systemd unit generation + orchestration
//!   - per-service UID allocation (60000-60999, persisted in `elf.toml`)
//!   - health checks (http, exec, process-alive via cgroup)
//!   - secret retrieval from Keeper at boot (`RequestSecrets`) →
//!     per-service tmpfs env files
//!
//! See issue #1 § High-level architecture. Phase 1 delivers: `run()`
//! stub, mTLS gRPC server binding, handshake RPC.

#![allow(dead_code)] // skeleton stubs — filled per-phase

/// Run the Elf daemon.
///
/// Binds the mTLS gRPC server on the LXC's `eth0` interface, reads
/// `/etc/dobby/elf.toml`, requests secrets from Keeper, and waits for
/// deploy commands.
pub async fn run() -> anyhow::Result<()> {
    anyhow::bail!("unimplemented: dobby-elf::run lands in Phase 1");
}
