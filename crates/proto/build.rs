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

    // `proto_root` is the include-path buf uses; `proto_pkg_dir` is where
    // the actual files live. Having separate layers lets `import` paths
    // inside the .proto files read as `dobby/v1/common.proto`, matching
    // the package — required by buf STANDARD's DIRECTORY_SAME_PACKAGE.
    let proto_root = workspace_root.join("proto");
    let proto_pkg_dir = proto_root.join("dobby").join("v1");

    let files = [
        proto_pkg_dir.join("common.proto"),
        proto_pkg_dir.join("keeper.proto"),
        proto_pkg_dir.join("elf.proto"),
    ];

    // Rebuild whenever any .proto file (or the directory listing) changes.
    println!("cargo:rerun-if-changed={}", proto_pkg_dir.display());
    for f in &files {
        println!("cargo:rerun-if-changed={}", f.display());
    }

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&files, &[proto_root])?;

    Ok(())
}
