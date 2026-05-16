//! `KeeperService` — the CLI ↔ Keeper gRPC surface.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use dobby_core::{auth, bootstrap_token, tls};
use dobby_proto::v1::{
    KeeperServiceHealthCheckRequest, KeeperServiceHealthCheckResponse, PairRequest, PairResponse,
    Status as PbStatus, Version, keeper_service_server::KeeperService, status::Code as StatusCode,
};
use tonic::{Request, Response, Status};
use tracing::warn;

/// Paths and identity material required by the Pair RPC.
#[derive(Debug, Clone)]
struct PairState {
    tls_fingerprint_sha256: [u8; 32],
    bootstrap_token_path: PathBuf,
    registry_path: PathBuf,
}

/// Concrete `KeeperService`.
#[derive(Debug, Clone)]
pub struct KeeperServiceImpl {
    pair_state: Arc<PairState>,
}

/// Errors constructing [`KeeperServiceImpl`] from a Keeper state dir.
#[derive(Debug, thiserror::Error)]
pub enum ServiceInitError {
    /// Could not read the persisted host certificate.
    #[error("reading Keeper host cert {path}: {source}")]
    ReadHostCert {
        /// Certificate path.
        path: PathBuf,
        /// Filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// Could not compute the host certificate fingerprint.
    #[error("computing Keeper TLS fingerprint: {0}")]
    TlsFingerprint(#[from] tls::TlsError),
}

impl KeeperServiceImpl {
    /// Build a service from the state dir produced by `dobby keeper init`.
    pub fn from_dir(dir: &Path) -> Result<Self, ServiceInitError> {
        let host_cert_path = dir.join("tls/host.crt");
        let host_cert =
            std::fs::read(&host_cert_path).map_err(|source| ServiceInitError::ReadHostCert {
                path: host_cert_path.clone(),
                source,
            })?;
        let tls_fingerprint_sha256 = tls::fingerprint_sha256_bytes_from_pem(&host_cert)?;
        Ok(Self::from_pair_state(PairState {
            tls_fingerprint_sha256,
            bootstrap_token_path: dir.join("secrets/bootstrap_token"),
            registry_path: dir.join("auth/workstations.toml"),
        }))
    }

    fn from_pair_state(pair_state: PairState) -> Self {
        Self {
            pair_state: Arc::new(pair_state),
        }
    }

    /// Build the `Version` payload reported on every response.
    fn version_payload() -> Version {
        Version {
            semver: env!("CARGO_PKG_VERSION").to_string(),
            // Populated at build time when CI / release tooling sets
            // `DOBBY_GIT_SHA`. Empty in `cargo build` from a working
            // tree — matches the proto contract ("when available").
            git_sha: option_env!("DOBBY_GIT_SHA").unwrap_or("").to_string(),
        }
    }

    fn pair_response(&self) -> PairResponse {
        PairResponse {
            keeper_version: Some(Self::version_payload()),
            tls_fingerprint_sha256: self.pair_state.tls_fingerprint_sha256.to_vec(),
        }
    }
}

#[tonic::async_trait]
impl KeeperService for KeeperServiceImpl {
    async fn health_check(
        &self,
        _request: Request<KeeperServiceHealthCheckRequest>,
    ) -> Result<Response<KeeperServiceHealthCheckResponse>, Status> {
        Ok(Response::new(KeeperServiceHealthCheckResponse {
            keeper_version: Some(Self::version_payload()),
            status: Some(PbStatus {
                code: StatusCode::Ok as i32,
                message: "keeper running".into(),
            }),
        }))
    }

    async fn pair(&self, request: Request<PairRequest>) -> Result<Response<PairResponse>, Status> {
        let request = request.into_inner();
        let public_key = auth::parse_public_key_bytes(&request.workstation_pubkey)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let request_fingerprint: [u8; 32] = request
            .tls_fingerprint_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("TLS fingerprint must be 32 bytes"))?;
        if request_fingerprint != self.pair_state.tls_fingerprint_sha256 {
            return Err(Status::unauthenticated("TLS fingerprint mismatch"));
        }

        let signature = auth::parse_signature_bytes(&request.workstation_signature)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let challenge = auth::pair_challenge(&request_fingerprint, &public_key);
        auth::verify_signature(&public_key, &challenge, &signature)
            .map_err(|_| Status::unauthenticated("workstation signature verification failed"))?;

        let mut registry = auth::load_keeper_registry(&self.pair_state.registry_path)
            .map_err(|err| auth_status(&err))?;
        if registry.contains_public_key(&public_key) {
            return Ok(Response::new(self.pair_response()));
        }
        if registry.bootstrap_token_consumed {
            return Err(Status::unauthenticated("bootstrap token already consumed"));
        }

        let stored_hash =
            std::fs::read_to_string(&self.pair_state.bootstrap_token_path).map_err(|source| {
                if source.kind() == std::io::ErrorKind::NotFound {
                    Status::unauthenticated("bootstrap token is not available")
                } else {
                    Status::internal(format!("reading bootstrap token hash: {source}"))
                }
            })?;
        let token_ok = bootstrap_token::verify_against_hash(&request.bootstrap_token, &stored_hash)
            .map_err(|_| Status::unauthenticated("invalid bootstrap token"))?;
        if !token_ok {
            return Err(Status::unauthenticated("invalid bootstrap token"));
        }

        registry.add_public_key(&public_key);
        registry.bootstrap_token_consumed = true;
        auth::save_keeper_registry(&self.pair_state.registry_path, &registry)
            .map_err(|err| auth_status(&err))?;

        if let Err(source) = std::fs::remove_file(&self.pair_state.bootstrap_token_path)
            && source.kind() != std::io::ErrorKind::NotFound
        {
            warn!(
                target = "dobby_keeper::pair",
                path = %self.pair_state.bootstrap_token_path.display(),
                error = %source,
                "failed to remove consumed bootstrap token hash"
            );
        }

        Ok(Response::new(self.pair_response()))
    }
}

fn auth_status(err: &auth::AuthError) -> Status {
    let message = err.to_string();
    match err {
        auth::AuthError::Parse { .. }
        | auth::AuthError::DecodeHex(_)
        | auth::AuthError::InvalidPublicKey => Status::failed_precondition(message),
        auth::AuthError::Io { .. } | auth::AuthError::Write(_) | auth::AuthError::Serialise(_) => {
            Status::internal(message)
        }
        auth::AuthError::Rng(_)
        | auth::AuthError::InvalidPublicKeyLength { .. }
        | auth::AuthError::InvalidSignatureLength { .. }
        | auth::AuthError::Signature
        | auth::AuthError::InvalidPrivateKeyFile => Status::invalid_argument(message),
    }
}

#[cfg(test)]
mod tests;
