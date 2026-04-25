//! Loading the host TLS identity (`<dir>/tls/host.crt` + `host.key`)
//! and turning it into a `tonic::transport::ServerTlsConfig` ready
//! for `Server::builder().tls_config(...)`.
//!
//! The corresponding CA stays on the Keeper LXC — this module isn't
//! responsible for it, only for the leaf cert that tonic presents on
//! the wire.

use std::path::{Path, PathBuf};

use tonic::transport::{Identity, ServerTlsConfig};

/// Errors loading the host TLS identity from disk.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Cert PEM file unreadable.
    #[error("reading TLS cert {path}: {source}")]
    ReadCert {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Key PEM file unreadable.
    #[error("reading TLS key {path}: {source}")]
    ReadKey {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Layout: `<dir>/tls/host.crt` + `<dir>/tls/host.key`. Returns a
/// `ServerTlsConfig` carrying the parsed `Identity`. Tonic does the
/// actual PEM parsing inside `Identity::from_pem` — invalid material
/// surfaces later at server-bind time as a tonic error, which is the
/// right layer to attribute it.
pub fn load_server_tls(dir: &Path) -> Result<ServerTlsConfig, TlsError> {
    let cert_path = dir.join("tls").join("host.crt");
    let key_path = dir.join("tls").join("host.key");

    let cert = std::fs::read(&cert_path).map_err(|source| TlsError::ReadCert {
        path: cert_path.clone(),
        source,
    })?;
    let key = std::fs::read(&key_path).map_err(|source| TlsError::ReadKey {
        path: key_path.clone(),
        source,
    })?;

    let identity = Identity::from_pem(cert, key);
    Ok(ServerTlsConfig::new().identity(identity))
}

#[cfg(test)]
mod tests;
