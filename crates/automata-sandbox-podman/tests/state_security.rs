#![cfg(target_os = "linux")]

mod support;

use std::{path::PathBuf, sync::Arc};

use automata_sandbox_podman::{
    PodmanCommandExecutor, PodmanOpenError, PodmanStateRoot, PodmanStateRootError,
    RootlessPodmanProvider,
};

use support::{FakePodman, ScratchRoot, options};

#[test]
fn state_root_rejects_relative_root_traversal_and_temporary_components() {
    assert_eq!(
        PodmanStateRoot::existing("target/agent-scratch/relative").expect_err("relative"),
        PodmanStateRootError::Relative
    );
    assert_eq!(
        PodmanStateRoot::existing(PathBuf::from("/")).expect_err("filesystem root"),
        PodmanStateRootError::FilesystemRoot
    );
    let traversal =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/agent-scratch/../escape");
    assert_eq!(
        PodmanStateRoot::existing(traversal).expect_err("traversal"),
        PodmanStateRootError::Traversal
    );

    let scratch = ScratchRoot::new("temporary-component");
    let temporary = scratch.path().join("tmp").join("adapter");
    std::fs::create_dir_all(&temporary).expect("create nested scratch");
    set_mode(&temporary, 0o700);
    assert_eq!(
        PodmanStateRoot::existing(temporary).expect_err("temporary hierarchy"),
        PodmanStateRootError::TemporaryHierarchy
    );
}

#[cfg(unix)]
#[test]
fn symlink_and_broad_permissions_are_rejected() {
    use std::os::unix::fs::symlink;

    let scratch = ScratchRoot::new("path-attacks");
    let real = scratch.path().join("real");
    std::fs::create_dir(&real).expect("real directory");
    set_mode(&real, 0o700);
    let alias = scratch.path().join("alias");
    symlink(&real, &alias).expect("create symlink in scratch");
    assert_eq!(
        PodmanStateRoot::existing(alias).expect_err("symlink"),
        PodmanStateRootError::NotCanonical
    );

    let broad = scratch.path().join("broad");
    std::fs::create_dir(&broad).expect("broad directory");
    set_mode(&broad, 0o750);
    assert_eq!(
        PodmanStateRoot::existing(broad).expect_err("broad permissions"),
        PodmanStateRootError::NotOwnerOnly
    );
}

#[test]
fn one_adapter_exclusively_owns_a_state_root() {
    let scratch = ScratchRoot::new("lock");
    let first_fake = Arc::new(FakePodman::default());
    let first = RootlessPodmanProvider::open_with_executor(
        options(scratch.path()),
        Arc::clone(&first_fake) as Arc<dyn PodmanCommandExecutor>,
    )
    .expect("first provider");
    let second_fake = Arc::new(FakePodman::default());
    let error = RootlessPodmanProvider::open_with_executor(
        options(scratch.path()),
        second_fake as Arc<dyn PodmanCommandExecutor>,
    )
    .expect_err("second provider must not share state root");
    assert_eq!(
        error,
        PodmanOpenError::StateRoot(PodmanStateRootError::AlreadyLocked)
    );
    drop(first);
}

#[cfg(unix)]
#[test]
fn reopen_removes_only_valid_abandoned_transfer_objects_without_following_links() {
    use std::os::unix::fs::symlink;

    let scratch = ScratchRoot::new("transfer-recovery");
    let fake = Arc::new(FakePodman::default());
    let provider = RootlessPodmanProvider::open_with_executor(
        options(scratch.path()),
        Arc::clone(&fake) as Arc<dyn PodmanCommandExecutor>,
    )
    .expect("initial provider");
    drop(provider);

    let transfers = scratch.path().join("transfers");
    let abandoned_file = transfers.join(format!("copy-in-{}", "a".repeat(32)));
    std::fs::write(&abandoned_file, b"abandoned-sensitive-bytes").expect("abandoned input");
    set_mode(&abandoned_file, 0o600);
    let abandoned_directory = transfers.join(format!("copy-out-{}", "b".repeat(32)));
    std::fs::create_dir(&abandoned_directory).expect("abandoned output directory");
    set_mode(&abandoned_directory, 0o700);
    let outside = scratch.path().join("outside");
    std::fs::write(&outside, b"outside-survives").expect("outside fixture");
    symlink(&outside, abandoned_directory.join("payload")).expect("stale payload symlink");

    let reopened = RootlessPodmanProvider::open_with_executor(
        options(scratch.path()),
        fake as Arc<dyn PodmanCommandExecutor>,
    )
    .expect("reopen cleans valid abandoned transfers");
    assert!(
        std::fs::read_dir(&transfers)
            .expect("transfers")
            .next()
            .is_none()
    );
    assert_eq!(
        std::fs::read(&outside).expect("outside survives"),
        b"outside-survives"
    );
    drop(reopened);
}

#[cfg(unix)]
#[test]
fn reopen_rejects_a_top_level_transfer_symlink_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let scratch = ScratchRoot::new("transfer-link-attack");
    let fake = Arc::new(FakePodman::default());
    let provider = RootlessPodmanProvider::open_with_executor(
        options(scratch.path()),
        Arc::clone(&fake) as Arc<dyn PodmanCommandExecutor>,
    )
    .expect("initial provider");
    drop(provider);
    let outside = scratch.path().join("outside");
    std::fs::write(&outside, b"outside-survives").expect("outside fixture");
    let attack = scratch
        .path()
        .join("transfers")
        .join(format!("exec-env-{}", "c".repeat(32)));
    symlink(&outside, &attack).expect("top-level transfer symlink");

    let error = RootlessPodmanProvider::open_with_executor(
        options(scratch.path()),
        fake as Arc<dyn PodmanCommandExecutor>,
    )
    .expect_err("top-level symlink must fail closed");
    assert_eq!(
        error,
        PodmanOpenError::StateRoot(PodmanStateRootError::PathSecurity)
    );
    assert_eq!(
        std::fs::read(&outside).expect("outside survives"),
        b"outside-survives"
    );
}

fn set_mode(path: &std::path::Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("permissions");
    }
    #[cfg(not(unix))]
    let _ignored = (path, mode);
}
