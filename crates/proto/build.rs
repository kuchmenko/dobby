//! Build-time codegen from `proto/*.proto` → Rust types + tonic service traits.
// SAFETY: `std::env::set_var` is `unsafe` in edition 2024 because it's not
// thread-safe. In a build.rs at startup, nothing else is touching env vars;
// the call is safe in this context.
#![allow(unsafe_code)]

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Vendored protoc — avoids requiring `protobuf-compiler` from the
    // distro. Works on linux/macos/windows, aarch64 + x86_64.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: `set_var` is safe here because build.rs is single-threaded
    // at this point (before any codegen kicks off).
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    // Workspace root is two levels up from this crate (crates/proto → ../..).
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/proto must live inside a workspace root")
        .to_path_buf();
    let proto_dir = workspace_root.join("proto");

    let files = [
        proto_dir.join("common.proto"),
        proto_dir.join("keeper.proto"),
        proto_dir.join("elf.proto"),
    ];

    // Rebuild whenever any .proto file (or the directory listing) changes.
    println!("cargo:rerun-if-changed={}", proto_dir.display());
    for f in &files {
        println!("cargo:rerun-if-changed={}", f.display());
    }

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&files, &[proto_dir])?;

    Ok(())
}
