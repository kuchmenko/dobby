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

use std::fs::{self, File};
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

    /// `keeper_ip` is one address family and the network-scope fields
    /// (`subnet` / `static_range`) are another. The resulting
    /// `keeper.toml` would be non-functional — refuse to write it.
    #[error(
        "network config family mismatch: keeper_ip is {keeper_ip_family}, but {field} = {field_value:?} is {field_family}"
    )]
    FamilyMismatch {
        field: &'static str,
        field_value: String,
        keeper_ip_family: &'static str,
        field_family: &'static str,
    },

    /// Malformed `subnet` or `static_range` string.
    #[error("{field} = {value:?} is not a valid {expected}")]
    MalformedNetworkField {
        field: &'static str,
        value: String,
        expected: &'static str,
    },

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
    // Validate before we touch disk — family mismatches would produce
    // a non-functional keeper.toml and there's no reason to write it.
    validate_network_families(req)?;

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

    // Fsync the directory inodes themselves so the newly-renamed
    // entries survive a power loss between return-from-rename and
    // the kernel flushing the metadata journal. POSIX rename(2) is
    // atomic on the inode-in-dir mapping but makes no durability
    // guarantee unless we fsync the containing directory.
    //
    // `atomic_write` deliberately doesn't do this per-call (one-off
    // writes to already-fsynced dirs wouldn't benefit) — we do it
    // here, once, for the batch.
    for d in [&req.dir, &tls_dir, &secrets_dir] {
        fsync_dir(d)?;
    }

    Ok(InitOutcome {
        bootstrap_token: token,
        tls_fingerprint_sha256: tls_material.host_fingerprint_sha256,
    })
}

/// Open `dir` read-only and `fsync` it. Linux allows fsync on a
/// directory fd to persist directory-entry changes (rename results,
/// mkdir results); macOS / BSD differ but still accept the call.
fn fsync_dir(dir: &Path) -> Result<(), InitError> {
    let handle = File::open(dir).map_err(|source| InitError::Io {
        op: "open dir for fsync",
        path: dir.to_path_buf(),
        source,
    })?;
    handle.sync_all().map_err(|source| InitError::Io {
        op: "fsync dir",
        path: dir.to_path_buf(),
        source,
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

/// Reject configs whose CIDR / range fields belong to a different
/// address family than `keeper_ip`. Everyone else in `Request` is
/// already typed `IpAddr` and checked here too for symmetry.
fn validate_network_families(req: &Request) -> Result<(), InitError> {
    let kip = req.keeper_ip;

    // gateway + dns_upstream are IpAddr already — cheap to compare.
    check_family("gateway", req.gateway, kip)?;
    check_family("dns_upstream", req.dns_upstream, kip)?;

    // subnet is "<ip>/<prefix>"; we only need the LHS for family.
    let (subnet_ip_str, _) =
        req.subnet
            .split_once('/')
            .ok_or_else(|| InitError::MalformedNetworkField {
                field: "subnet",
                value: req.subnet.clone(),
                expected: "CIDR (\"<ip>/<prefix>\")",
            })?;
    let subnet_ip: IpAddr =
        subnet_ip_str
            .parse()
            .map_err(|_| InitError::MalformedNetworkField {
                field: "subnet",
                value: req.subnet.clone(),
                expected: "CIDR with parseable IP",
            })?;
    check_family("subnet", subnet_ip, kip)?;

    // static_range is "<first>-<last>". Family must match on both.
    let (first_str, last_str) =
        req.static_range
            .split_once('-')
            .ok_or_else(|| InitError::MalformedNetworkField {
                field: "static_range",
                value: req.static_range.clone(),
                expected: "range (\"<first-ip>-<last-ip>\")",
            })?;
    let first: IpAddr = first_str
        .trim()
        .parse()
        .map_err(|_| InitError::MalformedNetworkField {
            field: "static_range",
            value: req.static_range.clone(),
            expected: "range with parseable IPs",
        })?;
    let last: IpAddr = last_str
        .trim()
        .parse()
        .map_err(|_| InitError::MalformedNetworkField {
            field: "static_range",
            value: req.static_range.clone(),
            expected: "range with parseable IPs",
        })?;
    check_family("static_range", first, kip)?;
    check_family("static_range", last, kip)?;

    Ok(())
}

fn check_family(field: &'static str, value: IpAddr, keeper_ip: IpAddr) -> Result<(), InitError> {
    if value.is_ipv4() != keeper_ip.is_ipv4() {
        return Err(InitError::FamilyMismatch {
            field,
            field_value: value.to_string(),
            keeper_ip_family: if keeper_ip.is_ipv4() { "IPv4" } else { "IPv6" },
            field_family: if value.is_ipv4() { "IPv4" } else { "IPv6" },
        });
    }
    Ok(())
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
