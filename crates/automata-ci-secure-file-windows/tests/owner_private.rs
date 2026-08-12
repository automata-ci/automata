#![cfg(windows)]

use std::{
    fs,
    fs::OpenOptions,
    os::windows::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use automata_ci_secure_file_windows::{SecureFileError, read_owner_private};
use windows_permissions::{Sid, utilities::current_process_sid, wrappers::ConvertSidToStringSid};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

/// Creates a directory with inheritance disabled and the accepted DACL shape.
fn restricted_directory(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "automata-secure-file-{label}-{}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("fixture directory");
    let user = ConvertSidToStringSid(&current_process_sid().expect("process SID"))
        .expect("SID text")
        .into_string()
        .expect("Unicode SID text");
    let status = Command::new("icacls")
        .arg(&root)
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
    assert!(status.status.success(), "icacls must restrict the fixture");
    root
}

fn write_secret(directory: &Path, name: &str, content: &[u8]) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, content).expect("fixture file");
    path
}

#[test]
fn well_known_sid_constants_match_the_documented_authorities() {
    let system = Sid::well_known_sid(22).expect("SYSTEM SID");
    let administrators = Sid::well_known_sid(26).expect("Administrators SID");
    assert_eq!(
        ConvertSidToStringSid(&system).expect("SYSTEM text"),
        "S-1-5-18"
    );
    assert_eq!(
        ConvertSidToStringSid(&administrators).expect("Administrators text"),
        "S-1-5-32-544"
    );
}

#[test]
fn restricted_files_round_trip_bounded_and_byte_exact() {
    let root = restricted_directory("round-trip");
    let secret = b"exact-secret-content\n";
    let path = write_secret(&root, "secret.pem", secret);
    let loaded = read_owner_private(&path, secret.len()).expect("exact bound must load");
    assert_eq!(&*loaded, secret);
    let relaxed = read_owner_private(&path, 4_096).expect("larger bound must load");
    assert_eq!(&*relaxed, secret);
    fs::remove_dir_all(&root).expect("fixture cleanup");
}

#[test]
fn oversized_files_and_zero_bounds_are_rejected() {
    let root = restricted_directory("bounds");
    let path = write_secret(&root, "secret.pem", &[0_u8; 64]);
    assert!(matches!(
        read_owner_private(&path, 63),
        Err(SecureFileError::TooLarge { maximum: 63 })
    ));
    assert!(matches!(
        read_owner_private(&path, 0),
        Err(SecureFileError::Insecure)
    ));
    fs::remove_dir_all(&root).expect("fixture cleanup");
}

#[test]
fn broad_access_control_entries_are_rejected() {
    let root = restricted_directory("broad-ace");
    let path = write_secret(&root, "secret.pem", b"broad");
    let status = Command::new("icacls")
        .arg(&path)
        .args(["/grant", "*S-1-1-0:R"])
        .output()
        .expect("icacls must run");
    assert!(status.status.success(), "icacls must widen the fixture");
    assert!(matches!(
        read_owner_private(&path, 4_096),
        Err(SecureFileError::Insecure)
    ));
    fs::remove_dir_all(&root).expect("fixture cleanup");
}

#[test]
fn junction_ancestors_are_rejected() {
    let root = restricted_directory("junction");
    let real = root.join("real");
    fs::create_dir(&real).expect("real directory");
    write_secret(&real, "secret.pem", b"behind-junction");
    let junction = root.join("junction");
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&real)
        .output()
        .expect("mklink must run");
    assert!(status.status.success(), "junction fixture must exist");
    assert!(matches!(
        read_owner_private(&junction.join("secret.pem"), 4_096),
        Err(SecureFileError::Insecure)
    ));
    assert!(read_owner_private(&real.join("secret.pem"), 4_096).is_ok());
    fs::remove_dir_all(&root).expect("fixture cleanup");
}

#[test]
fn ambiguous_namespace_forms_are_rejected_without_filesystem_access() {
    let missing_root = "Z:\\automata-missing-fixture";
    for path in [
        "relative\\secret.pem",
        "C:secret.pem",
        "\\\\server\\share\\secret.pem",
        "\\\\?\\C:\\automata\\secret.pem",
        "\\\\.\\C:\\automata\\secret.pem",
        &format!("{missing_root}\\.\\secret.pem"),
        &format!("{missing_root}\\..\\secret.pem"),
        &format!("{missing_root}\\secret.pem."),
        &format!("{missing_root}\\secret.pem "),
        &format!("{missing_root}\\secret.pem:stream"),
        &format!("{missing_root}\\NUL"),
        &format!("{missing_root}\\nul.txt"),
        &format!("{missing_root}\\COM1"),
        "C:\\",
    ] {
        assert!(
            matches!(
                read_owner_private(Path::new(path), 4_096),
                Err(SecureFileError::Insecure)
            ),
            "must reject: {path}"
        );
    }
}

#[test]
fn directories_and_exclusively_locked_files_are_rejected() {
    let root = restricted_directory("open-denials");
    assert!(matches!(
        read_owner_private(&root, 4_096),
        Err(SecureFileError::Insecure)
    ));
    let path = write_secret(&root, "secret.pem", b"locked");
    let exclusive = OpenOptions::new()
        .write(true)
        .share_mode(0)
        .open(&path)
        .expect("exclusive handle");
    assert!(matches!(
        read_owner_private(&path, 4_096),
        Err(SecureFileError::Insecure)
    ));
    drop(exclusive);
    assert!(read_owner_private(&path, 4_096).is_ok());
    fs::remove_dir_all(&root).expect("fixture cleanup");
}
