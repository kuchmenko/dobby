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
