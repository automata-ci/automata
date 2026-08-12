//! Private-directory fixtures for native custody tests.
//!
//! Ambient temporary directories can carry inherited access entries broader
//! than the owner-private secure-file policy accepts, so custody tests build
//! their file fixtures beneath a directory restricted to the exact test
//! identity on every platform.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

/// Creates a unique fixture directory only the test identity can use.
///
/// On Unix the directory is owner-only. On Windows inheritance is removed and
/// the DACL grants only the current user, `SYSTEM`, and `Administrators`, so
/// files created inside satisfy the owner-private secure-file policy.
pub(crate) fn private_fixture_directory(label: &str) -> PathBuf {
    let root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map_or_else(std::env::temp_dir, PathBuf::from)
        .join(format!(
            "automata-fixture-{label}-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
    fs::create_dir_all(&root).expect("fixture directory");
    restrict_to_test_identity(&root);
    root
}

/// Writes one private fixture file beneath a restricted fixture directory.
pub(crate) fn write_private_file(directory: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, bytes).expect("fixture file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("owner-only fixture");
    }
    path
}

#[cfg(unix)]
fn restrict_to_test_identity(root: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("owner-only fixture root");
}

#[cfg(windows)]
fn restrict_to_test_identity(root: &Path) {
    let user = automata_ci_secure_file_windows::current_user_sid_text().expect("test user SID");
    let output = std::process::Command::new("icacls")
        .arg(root)
        .args([
            "/inheritance:r",
            "/grant",
            &format!("*{user}:(OI)(CI)F"),
            "/grant",
            "*S-1-5-18:(OI)(CI)F",
            "/grant",
            "*S-1-5-32-544:(OI)(CI)F",
        ])
        .output()
        .expect("icacls must run");
    assert!(output.status.success(), "icacls must restrict the fixture");
}

#[cfg(not(any(unix, windows)))]
fn restrict_to_test_identity(_root: &Path) {}
