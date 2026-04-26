//! Tonic server bring-up: read config + TLS, bind, register services,
//! drive the `tokio::select!` between "client traffic" and "shutdown
//! signal". When SIGINT or SIGTERM arrives, we ask tonic to drain
//! in-flight requests and stop accepting new ones.
//!
//! Phase 1 wires only the `KeeperService`. Subsequent phases will
//! attach the Elf gRPC client (for outbound Keeper→Elf calls), the
//! mDNS advertiser, and the embedded DNS server alongside this
//! single tonic listener.

use std::{net::SocketAddr, path::Path};

use dobby_proto::v1::keeper_service_server::KeeperServiceServer;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info};

use crate::{
    config::{self, ConfigError},
    services::KeeperServiceImpl,
    tls::{self, TlsError},
};

/// Port the Keeper gRPC server binds to. Must match the CLI's
/// `KEEPER_GRPC_PORT` constant — both refer to the same protocol
/// surface defined in issue #1 § Communication protocol.
pub const KEEPER_GRPC_PORT: u16 = 8443;

/// Failure modes for `run`.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Couldn't load `keeper.toml` — typically missing or malformed
    /// state directory (run `dobby keeper init` first).
    #[error("loading keeper config: {0}")]
    Config(#[from] ConfigError),

    /// Couldn't load the host TLS material from `<dir>/tls/`.
    #[error("loading TLS identity: {0}")]
    Tls(#[from] TlsError),

    /// Tonic transport-level failure (bind error, TLS setup, …).
    #[error("tonic transport: {0}")]
    Transport(#[from] tonic::transport::Error),

    /// Couldn't install a UNIX signal handler (extremely rare —
    /// kernel out of resources).
    #[error("installing {signal} handler: {source}")]
    Signal {
        signal: &'static str,
        #[source]
        source: std::io::Error,
    },
}

/// Start the Keeper gRPC server. Returns once a shutdown signal is
/// received and tonic has drained in-flight requests.
pub async fn run(dir: &Path) -> Result<(), ServerError> {
    let cfg = config::load(dir)?;
    let tls_config = tls::load_server_tls(dir)?;

    let bind_addr = SocketAddr::new(cfg.network.keeper_ip, KEEPER_GRPC_PORT);
    info!(target = "dobby_keeper::server", %bind_addr, "starting tonic server");

    serve(bind_addr, tls_config, shutdown_signal()).await
}

/// Inner driver — unit-testable surface that takes its own bind
/// address, TLS config, and shutdown future. The user-facing `run`
/// supplies real defaults.
pub async fn serve(
    bind_addr: SocketAddr,
    tls_config: tonic::transport::ServerTlsConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), ServerError> {
    let svc = KeeperServiceServer::new(KeeperServiceImpl::new());

    // tonic 0.14: `Server::add_service(&mut self) -> Router` — needs
    // a binding so we can take `&mut`. Subsequent services chain on
    // `Router::add_service` (which takes `self`).
    let mut server = tonic::transport::Server::builder().tls_config(tls_config)?;
    let router = server.add_service(svc);
    router.serve_with_shutdown(bind_addr, shutdown).await?;

    info!(target = "dobby_keeper::server", "server stopped cleanly");
    Ok(())
}

/// Resolve when either SIGINT or SIGTERM is received. Used by `run`
/// to drive `tonic::Server::serve_with_shutdown`.
async fn shutdown_signal() -> () {
    // Both signals close the listener; `tokio::signal::unix` is the
    // only way to handle SIGTERM (ctrl_c() only listens for SIGINT).
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to install SIGTERM handler; continuing without");
            // Pending forever — falls through to SIGINT branch.
            return wait_for_sigint().await;
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to install SIGINT handler; continuing without");
            sigterm.recv().await;
            return;
        }
    };

    tokio::select! {
        _ = sigterm.recv() => info!("received SIGTERM, shutting down"),
        _ = sigint.recv() => info!("received SIGINT, shutting down"),
    }
}

async fn wait_for_sigint() {
    if let Ok(mut s) = signal(SignalKind::interrupt()) {
        s.recv().await;
        info!("received SIGINT, shutting down");
    }
}
