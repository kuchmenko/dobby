//! Reverse proxy bound on `keeper_ip:80` inside the Keeper LXC.
//! See issue #1 § Reverse proxy (`proxy`).
//!
//! HTTP/1.1 + WebSocket upgrade + keep-alive pool + graceful shutdown,
//! built on `hyper` directly. Route table driven by `[proxy.*]` entries
//! in per-app `dobby.toml` manifests. Source-IP allowlist rebuilt from
//! the MANAGED registry on every change.
//!
//! **Phase 3c** scope. Currently a compile-time placeholder — no
//! symbols exported.

#![allow(dead_code)]
