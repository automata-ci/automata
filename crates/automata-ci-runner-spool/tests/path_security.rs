mod support;

use std::{fs, path::Path, sync::Arc};

use automata_ci_core::Sha256Digest;
use automata_ci_runner_spool::{
    ContentKind, DurableContentRef, DurableContentStore, FileSpool, ProtectionId, SpoolError,
    SpoolRoot, SpoolRootError,
};
use sha2::{Digest as _, Sha256};
use support::{Scratch, TestProtector, adopt, content_path};

fn protector() -> Arc<TestProtector> {
    Arc::new(TestProtector::new("security-test-aead-v1", 0x92))
}

#[test]
fn spool_root_rejects_relative_root_traversal_and_temporary_hierarchy() {
    let scratch = Scratch::new("root-policy");
    assert!(matches!(
        SpoolRoot::explicit("relative/content"),
        Err(SpoolRootError::Relative)
    ));
    assert!(matches!(
        SpoolRoot::explicit(Path::new("/")),
        Err(SpoolRootError::FilesystemRoot)
    ));
    assert!(matches!(
        SpoolRoot::explicit(scratch.path().join("child").join("..").join("content")),
        Err(SpoolRootError::Traversal)
    ));
    assert!(matches!(
        SpoolRoot::explicit(scratch.path().join("tmp").join("content")),
        Err(SpoolRootError::TemporaryHierarchy)
    ));
    assert!(matches!(
        SpoolRoot::from_xdg_state_home(""),
        Err(SpoolRootError::MissingXdgStateHome)
    ));
}

#[cfg(unix)]
#[test]
fn roots_and_content_are_owner_only_and_symlinks_are_never_followed() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let scratch = Scratch::new("permissions-and-links");
    let real = scratch.child("real-parent");
    fs::create_dir(&real).expect("create real parent");
    let link = scratch.child("linked-parent");
    symlink(&real, &link).expect("create parent symlink");
    let linked_root = SpoolRoot::explicit(link.join("content")).expect("syntactically valid root");
    assert!(matches!(
        FileSpool::open(linked_root, protector()),
        Err(SpoolError::PathSecurity)
    ));

    let root = scratch.spool_root();
    let spool = FileSpool::open(root.clone(), protector()).expect("open spool");
    let reference = adopt(
        spool
            .persist(ContentKind::LogSpool, b"durable log frame")
            .expect("persist log"),
    );
    let root_mode = fs::metadata(root.as_path())
        .expect("root metadata")
        .permissions()
        .mode()
        & 0o777;
    let content_mode = fs::metadata(content_path(&root, &reference))
        .expect("content metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(root_mode, 0o700);
    assert_eq!(content_mode, 0o600);
    drop(spool);

    let digest = Sha256Digest::from_bytes(Sha256::digest(b"other content").into());
    let malicious_ref = DurableContentRef::after_commit(
        ContentKind::JobIr,
        13,
        digest,
        ProtectionId::new("security-test-aead-v1").expect("protection id"),
    )
    .expect("content reference");
    symlink(&real, content_path(&root, &malicious_ref)).expect("content symlink");
    assert!(matches!(
        FileSpool::open(root, protector()),
        Err(SpoolError::PathSecurity)
    ));
}

#[test]
fn altered_and_oversized_protected_files_are_rejected() {
    let scratch = Scratch::new("corrupt-content");
    let root = scratch.spool_root();
    let spool = FileSpool::open(root.clone(), protector()).expect("open spool");
    let reference = adopt(
        spool
            .persist(ContentKind::TerminalResult, b"result body")
            .expect("persist result"),
    );
    drop(spool);

    let path = content_path(&root, &reference);
    let mut protected = fs::read(&path).expect("read protected bytes");
    protected.truncate(protected.len() - 1);
    fs::write(&path, protected).expect("truncate protected content");
    let spool = FileSpool::open(root.clone(), protector()).expect("reopen truncated spool");
    assert!(matches!(
        spool.load(&reference),
        Err(SpoolError::Protection(_))
    ));
    drop(spool);

    fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .expect("open protected content")
        .set_len(258 * 1024 * 1024)
        .expect("oversize protected content");
    assert!(matches!(
        FileSpool::open(root, protector()),
        Err(SpoolError::CapacityExhausted)
    ));
}
