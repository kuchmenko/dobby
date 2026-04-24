//! Focused unit tests. The full-manifest fixture tests live under
//! `tests/manifest_fixtures.rs` so they exercise the crate from the
//! outside (same path callers take).

use super::*;

fn p() -> &'static Path {
    Path::new("<inline>")
}

#[test]
fn rejects_unknown_top_level_field() {
    let src = r#"
        [app]
        name = "x"
        repo = "a/b"

        [bogus]
        foo = 1
    "#;
    let err = parse_str(src, p()).unwrap_err();
    assert!(matches!(err, ManifestError::Toml { .. }));
}

#[test]
fn defaults_service_kind_to_binary() {
    let src = r#"
        [app]
        name = "x"
        repo = "a/b"

        [services.api]
        ports = [8080]
    "#;
    let m = parse_str(src, p()).unwrap();
    assert_eq!(m.services["api"].kind, ServiceKind::Binary);
}

#[test]
fn applies_binary_service_defaults() {
    let src = r#"
        [app]
        name = "myapp"
        repo = "me/myapp"

        [services.api]
        ports = [8080]
    "#;
    let mut m = parse_str(src, p()).unwrap();
    m.apply_defaults();
    let api = &m.services["api"];
    assert_eq!(api.artifact.as_deref(), Some("api"));
    assert_eq!(
        api.exec_start.as_deref(),
        Some("/opt/myapp/api/current/api"),
    );
    assert_eq!(api.restart, Some(RestartPolicy::Always));
}

#[test]
fn apply_defaults_preserves_explicit_overrides() {
    let src = r#"
        [app]
        name = "myapp"
        repo = "me/myapp"

        [services.api]
        ports = [8080]
        artifact = "api-bin"
        exec_start = "/custom/path"
        restart = "on-failure"
    "#;
    let mut m = parse_str(src, p()).unwrap();
    m.apply_defaults();
    let api = &m.services["api"];
    assert_eq!(api.artifact.as_deref(), Some("api-bin"));
    assert_eq!(api.exec_start.as_deref(), Some("/custom/path"));
    assert_eq!(api.restart, Some(RestartPolicy::OnFailure));
}

#[test]
fn port_spec_accepts_integer_and_string() {
    let src = r#"
        [app]
        name = "x"
        repo = "a/b"

        [services.web]
        ports = [8080]

        [services.prom]
        type = "container"
        image = "prom/prometheus:latest"
        ports = ["9090:9090"]
    "#;
    let m = parse_str(src, p()).unwrap();
    assert_eq!(m.services["web"].ports, vec![PortSpec::Single(8080)]);
    assert_eq!(
        m.services["prom"].ports,
        vec![PortSpec::Mapping("9090:9090".into())],
    );
}

#[test]
fn port_spec_container_port_helper() {
    assert_eq!(PortSpec::Single(8080).container_port(), Some(8080));
    assert_eq!(
        PortSpec::Mapping("3001:3000".into()).container_port(),
        Some(3000),
    );
    assert_eq!(PortSpec::Mapping("bogus".into()).container_port(), None,);
}

#[test]
fn external_service_parses_host_port() {
    let src = r#"
        [app]
        name = "x"
        repo = "a/b"

        [services.db]
        type = "external"
        host = "postgres.dobby"
        port = 5432
    "#;
    let m = parse_str(src, p()).unwrap();
    let db = &m.services["db"];
    assert_eq!(db.kind, ServiceKind::External);
    assert_eq!(db.host.as_deref(), Some("postgres.dobby"));
    assert_eq!(db.port, Some(5432));
}

#[test]
fn apply_defaults_skips_restart_for_external() {
    let src = r#"
        [app]
        name = "x"
        repo = "a/b"

        [services.db]
        type = "external"
        host = "postgres.dobby"
        port = 5432
    "#;
    let mut m = parse_str(src, p()).unwrap();
    m.apply_defaults();
    assert!(m.services["db"].restart.is_none());
}

#[test]
fn proxy_entry_requires_domain_and_port() {
    let src = r#"
        [app]
        name = "x"
        repo = "a/b"

        [proxy.api]
        domain = "api"
    "#;
    // missing `port` → parse error
    assert!(parse_str(src, p()).is_err());
}

#[test]
fn io_error_reports_path_in_message() {
    let err = parse_file(Path::new("/does/not/exist/dobby.toml")).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("/does/not/exist/dobby.toml"), "msg = {msg}");
}

#[test]
fn app_defaults_fill_trigger_and_interval_when_absent() {
    let src = r#"
        [app]
        name = "x"
        repo = "a/b"
    "#;
    let mut m = parse_str(src, p()).unwrap();
    // Raw parse preserves absence.
    assert!(m.app.trigger.is_none());
    assert!(m.app.interval.is_none());
    // Defaults materialise on apply_defaults.
    m.apply_defaults();
    assert_eq!(m.app.trigger.as_deref(), Some(DEFAULT_TRIGGER));
    assert_eq!(m.app.interval.as_deref(), Some(DEFAULT_INTERVAL));
    // And the constants match the documented values.
    assert_eq!(DEFAULT_TRIGGER, "release");
    assert_eq!(DEFAULT_INTERVAL, "5m");
}

#[test]
fn app_defaults_preserve_explicit_values() {
    let src = r#"
        [app]
        name = "x"
        repo = "a/b"
        trigger = "branch:main"
        interval = "30s"
    "#;
    let mut m = parse_str(src, p()).unwrap();
    m.apply_defaults();
    assert_eq!(m.app.trigger.as_deref(), Some("branch:main"));
    assert_eq!(m.app.interval.as_deref(), Some("30s"));
}

#[test]
fn app_defaults_materialise_only_missing_field() {
    // trigger present, interval absent — interval gets default,
    // trigger stays exactly as written.
    let src = r#"
        [app]
        name = "x"
        repo = "a/b"
        trigger = "branch:dev"
    "#;
    let mut m = parse_str(src, p()).unwrap();
    m.apply_defaults();
    assert_eq!(m.app.trigger.as_deref(), Some("branch:dev"));
    assert_eq!(m.app.interval.as_deref(), Some(DEFAULT_INTERVAL));
}
