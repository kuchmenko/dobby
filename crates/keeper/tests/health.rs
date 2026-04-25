//! End-to-end exercise of the Phase-1 Keeper daemon: bring up the
//! tonic server bound on an ephemeral port (so concurrent test runs
//! don't clash on `:8443`), connect a client that trusts the
//! Keeper-issued CA, and assert `HealthCheck` returns the expected
//! version + ok status. `Pair` returns `Unimplemented`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::Path;
use std::time::Duration;

use dobby_core::keeper_init;
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
async fn health_check_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let bind_addr = pick_port();
    let keeper_ip = bind_addr.ip();

    keeper_init::init(&keeper_init_request(tmp.path(), keeper_ip)).expect("init");

    let tls_config = dobby_keeper::test_support::load_server_tls(tmp.path()).expect("tls");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let server_handle = tokio::spawn({
        let tls = tls_config.clone();
        async move {
            dobby_keeper::test_support::serve(bind_addr, tls, async {
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

    // Pair stub.
    let err = client
        .pair(PairRequest {
            workstation_pubkey: vec![0u8; 32],
            bootstrap_token: "dby_boot_xxx".into(),
        })
        .await
        .expect_err("pair should be unimplemented");
    assert_eq!(err.code(), tonic::Code::Unimplemented);

    let _ = shutdown_tx.send(());
    server_handle.await.expect("join").expect("serve");
}
