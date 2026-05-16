//! End-to-end exercise of the Phase-1 Keeper daemon: bring up the
//! tonic server bound on an ephemeral port (so concurrent test runs
//! don't clash on `:8443`), connect a client that trusts the
//! Keeper-issued CA, and assert `HealthCheck` returns the expected
//! version + ok status. `Pair` registers the first workstation key.

// `allow-unwrap-in-tests` / `allow-expect-in-tests` only catch `#[test]`
// bodies and `#[cfg(test)]` modules — integration-test helper functions
// in `tests/*.rs` need an explicit per-file allow.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::Path,
    time::Duration,
};

use dobby_core::{auth, keeper_init};
use dobby_proto::v1::{
    KeeperServiceHealthCheckRequest, PairRequest, keeper_service_client::KeeperServiceClient,
    status::Code as StatusCode,
};
use tokio::sync::oneshot;
use tonic::transport::{Certificate, ClientTlsConfig};

/// Spawn the Keeper server on `127.0.0.1:<ephemeral>`, return its
/// bind address + a shutdown oneshot. The port is picked by binding
/// a kernel-allocated socket and immediately dropping it — there's a
/// theoretical race window, but on a single-process test runner with
/// no ambient port pressure it's effectively never observable.
fn pick_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    addr
}

fn keeper_init_request(dir: &Path, keeper_ip: IpAddr) -> keeper_init::Request {
    keeper_init::Request {
        dir: dir.to_path_buf(),
        keeper_ip,
        gateway: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dns_upstream: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        subnet: "10.0.0.0/24".into(),
        static_range: "10.0.0.200-10.0.0.250".into(),
        bridge: "vmbr0".into(),
        force: false,
    }
}

async fn build_client_for_dir(
    dir: &Path,
    bind_addr: SocketAddr,
) -> KeeperServiceClient<tonic::transport::Channel> {
    let ca_pem = std::fs::read(dir.join("tls/ca.crt")).expect("read CA");
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_pem))
        // The server cert was issued for `keeper_ip` (127.0.0.1 in
        // these tests). rustls uses SNI's "domain_name" to match SAN
        // entries, so we explicitly pin the IP-form SAN here.
        .domain_name(bind_addr.ip().to_string());

    let endpoint = format!("https://{bind_addr}");
    let channel = tonic::transport::Channel::from_shared(endpoint)
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .expect("connect to keeper");
    KeeperServiceClient::new(channel)
}

#[tokio::test]
async fn health_and_pair_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let bind_addr = pick_port();
    let keeper_ip = bind_addr.ip();

    let init = keeper_init::init(&keeper_init_request(tmp.path(), keeper_ip)).expect("init");

    let tls_config = dobby_keeper::test_support::load_server_tls(tmp.path()).expect("tls");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let server_handle = tokio::spawn({
        let tls = tls_config.clone();
        let tmp_path = tmp.path().to_path_buf();
        async move {
            dobby_keeper::test_support::serve(bind_addr, tls, tmp_path, async {
                let _ = shutdown_rx.await;
            })
            .await
        }
    });

    // Tiny grace period so the listener is actually accept()ing
    // before the client tries connect(). 200ms is plenty on
    // localhost; in CI the cargo-test runtime is hot too.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut client = build_client_for_dir(tmp.path(), bind_addr).await;
    let resp = client
        .health_check(KeeperServiceHealthCheckRequest {})
        .await
        .expect("health check call")
        .into_inner();

    let v = resp.keeper_version.expect("version");
    assert!(!v.semver.is_empty());

    let s = resp.status.expect("status");
    assert_eq!(s.code, StatusCode::Ok as i32);

    let keypair = auth::WorkstationKeypair::generate().unwrap();
    let pubkey = keypair.public_key_bytes();
    let fingerprint = dobby_core::tls::parse_fingerprint_hex(&init.tls_fingerprint_sha256).unwrap();
    let challenge = auth::pair_challenge(&fingerprint, &pubkey);
    let signature = keypair.sign(&challenge);

    let pair = client
        .pair(PairRequest {
            workstation_pubkey: pubkey.to_vec(),
            bootstrap_token: init.bootstrap_token.to_string(),
            tls_fingerprint_sha256: fingerprint.to_vec(),
            workstation_signature: signature.to_vec(),
        })
        .await
        .expect("pair call")
        .into_inner();
    assert_eq!(pair.tls_fingerprint_sha256, fingerprint);

    let registry = auth::load_keeper_registry(&tmp.path().join("auth/workstations.toml")).unwrap();
    assert!(registry.contains_public_key(&pubkey));
    assert!(registry.bootstrap_token_consumed);

    let _ = shutdown_tx.send(());
    server_handle.await.expect("join").expect("serve");
}
