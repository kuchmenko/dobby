//! `KeeperService` — the CLI ↔ Keeper gRPC surface.

use dobby_proto::v1::{
    KeeperServiceHealthCheckRequest, KeeperServiceHealthCheckResponse, PairRequest, PairResponse,
    Status as PbStatus, Version, keeper_service_server::KeeperService, status::Code as StatusCode,
};
use tonic::{Request, Response, Status};

/// Concrete `KeeperService`. Phase-1 surface holds no state; later
/// phases will pass in the bootstrap-token registry, the workstation
/// pubkey store, and an audit-event sink here.
#[derive(Debug, Default)]
pub struct KeeperServiceImpl;

impl KeeperServiceImpl {
    pub fn new() -> Self {
        Self
    }

    /// Build the `Version` payload reported on every health-check.
    fn version_payload() -> Version {
        Version {
            semver: env!("CARGO_PKG_VERSION").to_string(),
            // Populated at build time when CI / release tooling sets
            // `DOBBY_GIT_SHA`. Empty in `cargo build` from a working
            // tree — matches the proto contract ("when available").
            git_sha: option_env!("DOBBY_GIT_SHA").unwrap_or("").to_string(),
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

    async fn pair(&self, _request: Request<PairRequest>) -> Result<Response<PairResponse>, Status> {
        // Real Pair logic — bootstrap-token verification, ed25519
        // public-key registration, TLS-fingerprint hand-off — lands
        // in the next PR. Returning Unimplemented here rather than a
        // half-baked accept is deliberate: a Pair stub that "succeeds"
        // would invite the CLI to record a workstation key against
        // a fingerprint the Keeper hasn't actually committed to.
        Err(Status::unimplemented(
            "dobby pair lands in the next Phase-1 PR",
        ))
    }
}

#[cfg(test)]
mod tests;
