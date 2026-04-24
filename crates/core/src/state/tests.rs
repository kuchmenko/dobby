use std::os::unix::fs::PermissionsExt;

use super::*;

#[test]
fn writes_file_with_exact_contents() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("keeper.toml");
    atomic_write(&target, b"hello world", 0o644).unwrap();

    let read = std::fs::read(&target).unwrap();
    assert_eq!(read, b"hello world");
}

#[test]
fn applies_requested_mode() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("secret");
    atomic_write(&target, b"shh", 0o600).unwrap();

    let meta = std::fs::metadata(&target).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "mode = {mode:#o}");
}

// Direct FFI to umask(2) to avoid a libc dep for a single test.
// `umask` signature is stable across glibc/musl: mode_t is u32 on
// Linux. `unsafe extern "C"` is the canonical pattern.
#[allow(unsafe_code)]
unsafe extern "C" {
    fn umask(mask: u32) -> u32;
}

#[test]
fn applies_public_mode_under_restrictive_umask() {
    // Regression: `OpenOptions::mode` is masked by the process's
    // `umask(2)`. Under `umask 077` a requested 0o644 would land as
    // 0o600 silently. The explicit `chmod` after open restores the
    // caller's exact mode.
    //
    // `umask(2)` is process-global. Cargo's default multi-threaded
    // test runner may interleave this with other tests, but no other
    // test in this crate depends on a specific umask value, so the
    // race is theoretical. We restore the old umask even on a write
    // failure so the process stays clean.
    #[allow(unsafe_code)]
    let prev = unsafe { umask(0o077) };

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("public");
    let write_result = atomic_write(&target, b"hi", 0o644);

    #[allow(unsafe_code)]
    unsafe {
        umask(prev);
    }

    write_result.unwrap();
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644, "mode = {mode:#o}");
}

#[test]
fn overwrites_existing_target_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("keeper.toml");
    std::fs::write(&target, b"old").unwrap();

    atomic_write(&target, b"new", 0o644).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
}

#[test]
fn leaves_no_tempfile_on_success() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("keeper.toml");
    atomic_write(&target, b"x", 0o644).unwrap();

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    // exactly one file — no stray tempfiles.
    assert_eq!(entries.len(), 1, "entries = {entries:?}");
}

#[test]
fn rejects_target_without_parent() {
    // A bare relative filename like "foo" has `Some("")` as parent
    // in std — which we treat as no useful parent. Guard rejects it.
    let err = atomic_write(Path::new("foo"), b"x", 0o644).unwrap_err();
    assert!(matches!(err, AtomicWriteError::NoParent(_)), "{err}");
}

#[test]
fn reports_path_in_error() {
    let err = atomic_write(Path::new("/proc/definitely-not-writable"), b"x", 0o644).unwrap_err();
    // Some form of Io error with the tempfile path noted.
    let msg = err.to_string();
    assert!(msg.contains("/proc/"), "msg = {msg}");
}

#[test]
fn leaves_no_tempfile_on_failure() {
    // Force rename to fail by making the target a directory — you
    // can't `rename(2)` a regular file over a non-empty directory.
    // Before the refactor, tmp would orphan here; after, cleanup runs.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("pin"), b"makes the dir non-empty").unwrap();

    let err = atomic_write(&target, b"data", 0o644).unwrap_err();
    assert!(matches!(err, AtomicWriteError::Io { .. }), "{err}");

    // Walk the parent dir: no `.target.tmp-*` survived.
    let strays: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .filter(|n| n.to_string_lossy().starts_with(".target.tmp-"))
        .collect();
    assert!(strays.is_empty(), "tempfile leaked: {strays:?}");
}
