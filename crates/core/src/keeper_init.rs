//! `dobby keeper init` — orchestrator.
//!
//! Composes [`tls`](crate::tls), [`bootstrap_token`](crate::bootstrap_token),
//! and [`keeper_config`](crate::keeper_config) into the on-disk layout
//! the Keeper daemon expects:
//!
//! ```text
//! <dir>/
//! ├── keeper.toml                       (0644)
//! ├── tls/
//! │   ├── ca.crt                        (0644)
//! │   ├── ca.key                        (0600)
//! │   ├── host.crt                      (0644)
//! │   └── host.key                      (0600)
//! └── secrets/
//!     └── bootstrap_token               (0600)
//! ```
//!
//! The caller passes a fully-specified [`Request`] — there is no
//! auto-detection of the eth0 IP or LAN topology. Explicit-config
//! discipline: the operator states the intent, the code records it.
//!
//! Interactive prompts (Proxmox API token, GitHub Device Flow, backup
//! passphrase) live in the CLI layer and their persistence lands in
//! separate PRs once the age-encrypted secret pipeline is in place.

use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::keeper_config::{KeeperConfig, Network};
use crate::state::{self, AtomicWriteError};
use crate::{bootstrap_token, tls};

/// Input to [`init`].
#[derive(Debug, Clone)]
pub struct Request {
    /// Target directory for Keeper state (conventionally `/etc/dobby`).
    pub dir: PathBuf,
    /// Keeper LXC's own IP on `bridge`. Used both as cert SAN and as
    /// `[network].keeper_ip` in `keeper.toml`.
    pub keeper_ip: IpAddr,
    /// LAN gateway on `bridge`.
    pub gateway: IpAddr,
    /// Upstream DNS for non-`.dobby` forwarding.
    pub dns_upstream: IpAddr,
    /// LAN subnet in CIDR form (`10.0.0.0/24`).
    pub subnet: String,
    /// Allocation range for managed LXCs (`10.0.0.200-10.0.0.250`).
    pub static_range: String,
    /// Proxmox bridge name (`vmbr0`).
    pub bridge: String,
    /// Overwrite an existing non-empty target directory.
    pub force: bool,
}

/// Result of a successful [`init`] — what the CLI prints to the operator.
#[derive(Debug)]
pub struct InitOutcome {
    /// One-time token the operator passes to `dobby pair --token`.
    /// Zeroised on drop so the CLI must not clone it loosely.
    pub bootstrap_token: Zeroizing<String>,
    /// SHA-256 fingerprint (lowercase hex) of the Keeper TLS host cert
    /// in DER form. Used by `dobby pair --fingerprint` for out-of-band
    /// verification on hostile LAN segments.
    pub tls_fingerprint_sha256: String,
}

/// Errors from [`init`].
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// The target directory already contains dobby state and `force`
    /// was not set. `init` refuses to clobber existing keys silently.
    #[error("target directory {0} already contains dobby state; pass --force to overwrite")]
    NotEmpty(PathBuf),

    /// TLS material generation failed.
    #[error("TLS material generation: {0}")]
    Tls(#[from] tls::TlsError),

    /// Bootstrap token generation failed.
    #[error("bootstrap token generation: {0}")]
    Token(#[from] bootstrap_token::TokenError),

    /// `keeper.toml` serialisation failed (should be impossible given
    /// the schema — included for totality).
    #[error("serialising keeper.toml: {0}")]
    Serialise(#[from] toml::ser::Error),

    /// Filesystem / atomic-write error.
    #[error(transparent)]
    Write(#[from] AtomicWriteError),

    /// Ambient filesystem error (mkdir, readdir).
    #[error("{op} on {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Entry point. Idempotent only with `force = true`; otherwise refuses
/// to run on a non-empty `dir`.
pub fn init(req: &Request) -> Result<InitOutcome, InitError> {
    ensure_target_dir(&req.dir, req.force)?;

    let tls_dir = req.dir.join("tls");
    let secrets_dir = req.dir.join("secrets");
    for sub in [&tls_dir, &secrets_dir] {
        fs::create_dir_all(sub).map_err(|source| InitError::Io {
            op: "mkdir -p",
            path: sub.clone(),
            source,
        })?;
    }
    // Lock down the secrets dir (tls/ already contains world-readable
    // certs so 0755 is fine there).
    fs::set_permissions(&secrets_dir, fs::Permissions::from_mode(0o700)).map_err(|source| {
        InitError::Io {
            op: "chmod 0700",
            path: secrets_dir.clone(),
            source,
        }
    })?;

    let tls_material = tls::generate(req.keeper_ip)?;
    let token = bootstrap_token::generate()?;
    let config = build_config(req);
    let config_toml = config.to_toml()?;

    // Non-secret artefacts.
    state::atomic_write(&req.dir.join("keeper.toml"), config_toml.as_bytes(), 0o644)?;
    state::atomic_write(
        &tls_dir.join("ca.crt"),
        tls_material.ca_cert_pem.as_bytes(),
        0o644,
    )?;
    state::atomic_write(
        &tls_dir.join("host.crt"),
        tls_material.host_cert_pem.as_bytes(),
        0o644,
    )?;

    // Secret artefacts — 0600, owner read only.
    state::atomic_write(
        &tls_dir.join("ca.key"),
        tls_material.ca_key_pem.as_bytes(),
        0o600,
    )?;
    state::atomic_write(
        &tls_dir.join("host.key"),
        tls_material.host_key_pem.as_bytes(),
        0o600,
    )?;
    state::atomic_write(
        &secrets_dir.join("bootstrap_token"),
        token.as_bytes(),
        0o600,
    )?;

    Ok(InitOutcome {
        bootstrap_token: token,
        tls_fingerprint_sha256: tls_material.host_fingerprint_sha256,
    })
}

fn build_config(req: &Request) -> KeeperConfig {
    KeeperConfig {
        network: Network {
            bridge: req.bridge.clone(),
            subnet: req.subnet.clone(),
            static_range: req.static_range.clone(),
            keeper_ip: req.keeper_ip,
            gateway: req.gateway,
            dns_upstream: req.dns_upstream,
        },
    }
}

/// Create `dir` if missing; if it exists with contents, require
/// `force`. Never touches user files until `force` is confirmed.
fn ensure_target_dir(dir: &Path, force: bool) -> Result<(), InitError> {
    match fs::read_dir(dir) {
        Ok(mut iter) => {
            let has_entry = iter.next().is_some();
            if has_entry && !force {
                return Err(InitError::NotEmpty(dir.to_path_buf()));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(dir).map_err(|source| InitError::Io {
                op: "mkdir -p",
                path: dir.to_path_buf(),
                source,
            })
        }
        Err(e) => Err(InitError::Io {
            op: "read_dir",
            path: dir.to_path_buf(),
            source: e,
        }),
    }
}

#[cfg(test)]
mod tests;
