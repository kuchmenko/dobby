//! Dobby Keeper — daemon running inside its own unprivileged LXC on
//! the Proxmox host. Responsibilities:
//!
//!   - tonic gRPC server (`CLI ↔ Keeper`) over TLS on Tailscale
//!   - tonic gRPC client (`Keeper ↔ Elf`) over mTLS on the LXC bridge
//!   - Proxmox HTTP API wrapper (pool-scoped token, no `pct`)
//!   - mDNS advertisement (`_dobby._tcp.local`)
//!   - embedded DNS for `.dobby` zone (hickory-server)
//!   - reverse proxy (`:80`) driven by the `dobby-proxy` crate
//!   - release watcher polling GitHub
//!   - metrics collector
//!   - age-encrypted secret store + TLS CA for minting Elf certs
//!
//! See issue #1 § High-level architecture. Phase 1 delivers: `run()`
//! stub, tonic server boilerplate, mDNS+DNS binding on the configured
//! `keeper_ip`, auth scaffolding.

#![allow(dead_code)] // skeleton stubs — filled per-phase

/// Run the Keeper daemon.
///
/// Binds the gRPC server on `keeper_ip:8443`, starts mDNS advertisement,
/// starts the embedded DNS server on `keeper_ip:53`, and waits for
/// SIGTERM.
pub async fn run() -> anyhow::Result<()> {
    anyhow::bail!("unimplemented: dobby-keeper::run lands in Phase 1");
}
