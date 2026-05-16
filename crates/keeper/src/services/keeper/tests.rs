use std::{
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use dobby_core::{auth, bootstrap_token, keeper_init};

use super::*;

fn test_service() -> KeeperServiceImpl {
    KeeperServiceImpl::from_pair_state(PairState {
        tls_fingerprint_sha256: [7u8; 32],
        bootstrap_token_path: PathBuf::from("/tmp/dobby-test-bootstrap-token"),
        registry_path: PathBuf::from("/tmp/dobby-test-workstations.toml"),
        pair_lock: tokio::sync::Mutex::new(()),
    })
}

fn init_req(dir: &Path) -> keeper_init::Request {
    keeper_init::Request {
        dir: dir.to_path_buf(),
        keeper_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        gateway: IpAddr::V4(Ipv4Addr::LOCALHOST),
        dns_upstream: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        subnet: "127.0.0.0/24".into(),
        static_range: "127.0.0.200-127.0.0.250".into(),
        bridge: "lo".into(),
        force: false,
    }
}

fn pair_request(
    keypair: &auth::WorkstationKeypair,
    fingerprint: &[u8; 32],
    token: &str,
) -> PairRequest {
    let pubkey = keypair.public_key_bytes();
    let challenge = auth::pair_challenge(fingerprint, &pubkey);
    let signature = keypair.sign(&challenge);
    PairRequest {
        workstation_pubkey: pubkey.to_vec(),
        bootstrap_token: token.into(),
        tls_fingerprint_sha256: fingerprint.to_vec(),
        workstation_signature: signature.to_vec(),
    }
}

#[tokio::test]
async fn health_check_returns_ok_status() {
    let svc = test_service();
    let resp = svc
        .health_check(Request::new(KeeperServiceHealthCheckRequest {}))
        .await
        .expect("health_check should not error");
    let inner = resp.into_inner();

    let v = inner.keeper_version.expect("version present");
    assert!(!v.semver.is_empty());

    let s = inner.status.expect("status present");
    assert_eq!(s.code, StatusCode::Ok as i32);
    assert_eq!(s.message, "keeper running");
}

#[tokio::test]
async fn pair_registers_public_key_and_consumes_token() {
    let tmp = tempfile::tempdir().unwrap();
    let outcome = keeper_init::init(&init_req(tmp.path())).unwrap();
    let svc = KeeperServiceImpl::from_dir(tmp.path()).unwrap();
    let fingerprint =
        dobby_core::tls::parse_fingerprint_hex(&outcome.tls_fingerprint_sha256).unwrap();
    let keypair = auth::WorkstationKeypair::generate().unwrap();

    let resp = svc
        .pair(Request::new(pair_request(
            &keypair,
            &fingerprint,
            &outcome.bootstrap_token,
        )))
        .await
        .expect("pair succeeds")
        .into_inner();

    assert_eq!(resp.tls_fingerprint_sha256, fingerprint);
    let registry = auth::load_keeper_registry(&tmp.path().join("auth/workstations.toml")).unwrap();
    assert!(registry.bootstrap_token_consumed);
    assert!(registry.contains_public_key(&keypair.public_key_bytes()));
    assert!(!tmp.path().join("secrets/bootstrap_token").exists());
}

#[tokio::test]
async fn pair_rejects_wrong_token() {
    let tmp = tempfile::tempdir().unwrap();
    let outcome = keeper_init::init(&init_req(tmp.path())).unwrap();
    let svc = KeeperServiceImpl::from_dir(tmp.path()).unwrap();
    let fingerprint =
        dobby_core::tls::parse_fingerprint_hex(&outcome.tls_fingerprint_sha256).unwrap();
    let keypair = auth::WorkstationKeypair::generate().unwrap();
    let wrong = bootstrap_token::generate().unwrap();

    let err = svc
        .pair(Request::new(pair_request(&keypair, &fingerprint, &wrong)))
        .await
        .expect_err("bad token rejected");

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn pair_rejects_wrong_fingerprint() {
    let tmp = tempfile::tempdir().unwrap();
    let outcome = keeper_init::init(&init_req(tmp.path())).unwrap();
    let svc = KeeperServiceImpl::from_dir(tmp.path()).unwrap();
    let mut fingerprint =
        dobby_core::tls::parse_fingerprint_hex(&outcome.tls_fingerprint_sha256).unwrap();
    fingerprint[0] ^= 0xff;
    let keypair = auth::WorkstationKeypair::generate().unwrap();

    let err = svc
        .pair(Request::new(pair_request(
            &keypair,
            &fingerprint,
            &outcome.bootstrap_token,
        )))
        .await
        .expect_err("bad fingerprint rejected");

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn pair_is_idempotent_for_same_key_after_token_consumption() {
    let tmp = tempfile::tempdir().unwrap();
    let outcome = keeper_init::init(&init_req(tmp.path())).unwrap();
    let svc = KeeperServiceImpl::from_dir(tmp.path()).unwrap();
    let fingerprint =
        dobby_core::tls::parse_fingerprint_hex(&outcome.tls_fingerprint_sha256).unwrap();
    let keypair = auth::WorkstationKeypair::generate().unwrap();

    svc.pair(Request::new(pair_request(
        &keypair,
        &fingerprint,
        &outcome.bootstrap_token,
    )))
    .await
    .expect("first pair succeeds");

    let resp = svc
        .pair(Request::new(pair_request(
            &keypair,
            &fingerprint,
            "dby_boot_000000000000000000000000000000000000000000000000",
        )))
        .await
        .expect("same key retry succeeds without token")
        .into_inner();

    assert_eq!(resp.tls_fingerprint_sha256, fingerprint);
}

#[tokio::test]
async fn consumed_token_cannot_pair_different_key() {
    let tmp = tempfile::tempdir().unwrap();
    let outcome = keeper_init::init(&init_req(tmp.path())).unwrap();
    let svc = KeeperServiceImpl::from_dir(tmp.path()).unwrap();
    let fingerprint =
        dobby_core::tls::parse_fingerprint_hex(&outcome.tls_fingerprint_sha256).unwrap();
    let first = auth::WorkstationKeypair::generate().unwrap();
    let second = auth::WorkstationKeypair::generate().unwrap();

    svc.pair(Request::new(pair_request(
        &first,
        &fingerprint,
        &outcome.bootstrap_token,
    )))
    .await
    .expect("first pair succeeds");

    let err = svc
        .pair(Request::new(pair_request(
            &second,
            &fingerprint,
            &outcome.bootstrap_token,
        )))
        .await
        .expect_err("different key rejected after consumption");

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn concurrent_pair_requests_consume_token_once() {
    let tmp = tempfile::tempdir().unwrap();
    let outcome = keeper_init::init(&init_req(tmp.path())).unwrap();
    let svc = KeeperServiceImpl::from_dir(tmp.path()).unwrap();
    let fingerprint =
        dobby_core::tls::parse_fingerprint_hex(&outcome.tls_fingerprint_sha256).unwrap();
    let first = auth::WorkstationKeypair::generate().unwrap();
    let second = auth::WorkstationKeypair::generate().unwrap();

    let first_request = Request::new(pair_request(&first, &fingerprint, &outcome.bootstrap_token));
    let second_request = Request::new(pair_request(
        &second,
        &fingerprint,
        &outcome.bootstrap_token,
    ));
    let (first_result, second_result) =
        tokio::join!(svc.pair(first_request), svc.pair(second_request));

    let successes = usize::from(first_result.is_ok()) + usize::from(second_result.is_ok());
    assert_eq!(successes, 1);

    let registry = auth::load_keeper_registry(&tmp.path().join("auth/workstations.toml")).unwrap();
    assert!(registry.bootstrap_token_consumed);
    assert_eq!(registry.workstations.len(), 1);
}
