//! Generated gRPC types for dobby.
//!
//! All protobuf messages and tonic service traits are defined by
//! `proto/*.proto` files at the workspace root and generated at build
//! time (see `build.rs`). This crate re-exports them under the
//! `dobby.v1` package module.

#![allow(clippy::all, missing_debug_implementations)]

pub mod v1 {
    tonic::include_proto!("dobby.v1");
}
