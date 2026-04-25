//! Tonic gRPC service implementations.
//!
//! Phase 1 surface: `KeeperService`, with `HealthCheck` returning
//! version info and `Pair` returning `Unimplemented`. Subsequent
//! phases extend this module (additional RPCs, the Elf service, …).

pub mod keeper;

pub use keeper::KeeperServiceImpl;
