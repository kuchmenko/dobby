//! Integration tests: parse the exact manifest snippets from issue #1
//! (koban single-service + mm-eh multi-service) and assert the shape
//! of the resulting [`Manifest`].

use std::path::{Path, PathBuf};

use dobby_core::manifest::{self, PortSpec, RestartPolicy, ServiceKind};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

// ── koban ───────────────────────────────────────────────────────────────

#[test]
fn koban_round_trip() {
    let m = manifest::parse_file(&fixture_path("koban.toml")).expect("parse");

    // [app]
    assert_eq!(m.app.name, "koban");
    assert_eq!(m.app.repo, "kuchmenko/koban");
    assert_eq!(m.app.trigger.as_deref(), Some("release"));

    // [container]
    let c = m.container.as_ref().expect("container section");
    assert_eq!(c.template, "debian-12");
    assert_eq!(c.cores, 2);
    assert_eq!(c.memory, 512);
    assert_eq!(c.disk, 10);

    // [environment]
    assert_eq!(
        m.environment.get("RUST_LOG").map(String::as_str),
        Some("info")
    );
    assert!(m.environment.contains_key("DATABASE_URL"));

    // [services.db] — external
    let db = &m.services["db"];
    assert_eq!(db.kind, ServiceKind::External);
    assert_eq!(db.host.as_deref(), Some("postgres.dobby"));
    assert_eq!(db.port, Some(5432));

    // [services.koban] — binary (default)
    let svc = &m.services["koban"];
    assert_eq!(svc.kind, ServiceKind::Binary);
    assert_eq!(svc.ports, vec![PortSpec::Single(8080)]);
    assert_eq!(svc.depends, vec!["db"]);
    assert_eq!(
        svc.env_from,
        vec!["DATABASE_URL".to_string(), "RUST_LOG".into()]
    );

    // [proxy.koban]
    let px = &m.proxy["koban"];
    assert_eq!(px.domain, "koban");
    assert_eq!(px.port, 8080);

    // No [health] section
    assert!(m.health.is_empty());
}

#[test]
fn koban_defaults_applied() {
    let mut m = manifest::parse_file(&fixture_path("koban.toml")).unwrap();
    m.apply_defaults();

    let svc = &m.services["koban"];
    assert_eq!(svc.artifact.as_deref(), Some("koban"));
    assert_eq!(
        svc.exec_start.as_deref(),
        Some("/opt/koban/koban/current/koban")
    );
    assert_eq!(svc.restart, Some(RestartPolicy::Always));
}

// ── mm-eh ───────────────────────────────────────────────────────────────

#[test]
fn mm_eh_round_trip() {
    let m = manifest::parse_file(&fixture_path("mm-eh.toml")).expect("parse");

    // [app]
    assert_eq!(m.app.name, "mm-eh");
    assert_eq!(m.app.trigger.as_deref(), Some("branch:main"));
    assert_eq!(m.app.interval.as_deref(), Some("5m"));

    // [container]
    let c = m.container.as_ref().unwrap();
    assert_eq!(c.cores, 4);
    assert_eq!(c.memory, 2048);

    // Seven services: db (external), prometheus + grafana (container),
    // indexer + paper + explorer + data-api (binary).
    assert_eq!(m.services.len(), 7);

    let prom = &m.services["prometheus"];
    assert_eq!(prom.kind, ServiceKind::Container);
    assert_eq!(prom.image.as_deref(), Some("prom/prometheus:latest"));
    assert_eq!(prom.ports, vec![PortSpec::Mapping("9090:9090".into())]);
    assert_eq!(prom.memory, Some(256));

    let grafana = &m.services["grafana"];
    assert_eq!(grafana.kind, ServiceKind::Container);
    assert_eq!(grafana.ports, vec![PortSpec::Mapping("3001:3000".into())]);
    assert_eq!(grafana.depends, vec!["prometheus"]);

    let indexer = &m.services["indexer"];
    assert_eq!(indexer.kind, ServiceKind::Binary);
    assert_eq!(indexer.ports, vec![PortSpec::Single(9100)]);
    assert_eq!(indexer.depends, vec!["db"]);
    assert_eq!(
        indexer.env_from,
        vec![
            "DATABASE_URL".to_string(),
            "API_KEY".into(),
            "RUST_LOG".into()
        ]
    );

    // paper deliberately omits API_KEY — verifies env_from is opt-in
    let paper = &m.services["paper"];
    assert_eq!(
        paper.env_from,
        vec!["DATABASE_URL".to_string(), "RUST_LOG".into()]
    );
    assert_eq!(paper.memory, Some(1024));

    let explorer = &m.services["explorer"];
    assert_eq!(
        explorer.ports,
        vec![PortSpec::Single(3000), PortSpec::Single(9102)]
    );

    let data_api = &m.services["data-api"];
    assert_eq!(
        data_api.ports,
        vec![PortSpec::Single(9103), PortSpec::Single(8080)]
    );
    // service-specific literal env (mixed with env_from on the same service)
    assert_eq!(
        data_api.env.get("JWT_SECRET").map(String::as_str),
        Some("${JWT_SECRET}")
    );

    // [proxy.*] — two explicit routes, everything else NXDOMAIN at runtime
    assert_eq!(m.proxy.len(), 2);
    assert_eq!(m.proxy["explorer"].port, 3000);
    assert_eq!(m.proxy["data-api"].domain, "api");

    // [health.*] — overrides only for explorer + data-api
    assert_eq!(m.health.len(), 2);
    assert_eq!(m.health["explorer"].http.as_deref(), Some("/health"));
    assert_eq!(m.health["explorer"].port, Some(9102));
    assert_eq!(m.health["explorer"].interval.as_deref(), Some("15s"));
    assert_eq!(m.health["data-api"].port, Some(9103));
    assert!(m.health["data-api"].interval.is_none()); // uses default 30s
}

#[test]
fn mm_eh_defaults_applied() {
    let mut m = manifest::parse_file(&fixture_path("mm-eh.toml")).unwrap();
    m.apply_defaults();

    // Binary services got their artifact/exec_start filled in.
    assert_eq!(
        m.services["indexer"].exec_start.as_deref(),
        Some("/opt/mm-eh/indexer/current/indexer")
    );
    assert_eq!(
        m.services["paper"].exec_start.as_deref(),
        Some("/opt/mm-eh/paper/current/paper")
    );

    // External still has no restart — defaulting is type-aware.
    assert!(m.services["db"].restart.is_none());
}
