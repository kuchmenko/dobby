//! Native OCI container runtime. See issue #1 § Native OCI container runtime.
//!
//! Replaces runc for `type = "container"` services — direct Linux
//! syscalls via the `nix` crate for `clone()`, `mount()`, `pivot_root()`,
//! cgroup v2 writes, veth pair creation, capability drop, seccomp BPF.
//!
//! Also orchestrates image pull (via `oci-distribution`), overlayfs layer
//! assembly, and IPAM on the `dobby0` bridge.
//!
//! **Phase 3** scope (broken into 3a / 3b / 3c in issue #1). Currently
//! a compile-time placeholder — no symbols exported.

#![allow(dead_code)]
