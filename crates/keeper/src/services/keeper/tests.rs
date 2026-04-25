use super::*;

#[tokio::test]
async fn health_check_returns_ok_status() {
    let svc = KeeperServiceImpl::new();
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
async fn pair_returns_unimplemented() {
    let svc = KeeperServiceImpl::new();
    let err = svc
        .pair(Request::new(PairRequest {
            workstation_pubkey: vec![],
            bootstrap_token: String::new(),
        }))
        .await
        .expect_err("pair should not succeed yet");
    assert_eq!(err.code(), tonic::Code::Unimplemented);
}
