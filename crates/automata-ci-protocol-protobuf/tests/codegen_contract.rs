use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn checked_in_dto_matches_fresh_pinned_codegen() {
    let root = crate_root();
    let output = Command::new(root.join("tools/protobuf-codegen.sh"))
        .arg("verify")
        .output()
        .expect("codegen verifier must start");

    assert!(
        output.status.success(),
        "codegen verification failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
struct ContainmentFixture {
    root: PathBuf,
    existing_target: PathBuf,
    links: [PathBuf; 2],
    fake_repository: PathBuf,
    redirected_target: PathBuf,
    fake_target_link: PathBuf,
}

#[cfg(unix)]
impl Drop for ContainmentFixture {
    fn drop(&mut self) {
        for link in &self.links {
            let _ = fs::remove_file(link);
        }
        let _ = fs::remove_file(&self.fake_target_link);
        let _ = fs::remove_dir_all(&self.existing_target);
        let _ = fs::remove_dir_all(&self.fake_repository);
        let _ = fs::remove_dir_all(&self.redirected_target);
        let _ = fs::remove_dir(&self.root);
    }
}

#[cfg(unix)]
fn assert_real_directory(path: &Path) {
    let metadata = fs::symlink_metadata(path).expect("contained directory metadata");
    assert!(metadata.is_dir(), "{} must be a directory", path.display());
    assert!(
        !metadata.file_type().is_symlink(),
        "{} must not be a symlink",
        path.display()
    );
    assert_eq!(
        fs::canonicalize(path).expect("canonical contained directory"),
        path,
        "{} must be canonical",
        path.display()
    );
}

#[cfg(unix)]
fn containment_fixture() -> ContainmentFixture {
    use std::io::ErrorKind;
    use std::os::unix::fs::symlink;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    let crate_root = crate_root();
    let repository_root = crate_root
        .parent()
        .and_then(Path::parent)
        .expect("crate is under the repository crates directory");
    let target = repository_root.join("target");
    assert_real_directory(&target);

    let agent_scratch = target.join("agent-scratch");
    match fs::create_dir(&agent_scratch) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => panic!("could not create agent scratch directory: {error}"),
    }
    assert_real_directory(&agent_scratch);

    let root = loop {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let candidate = agent_scratch.join(format!(
            "protobuf-codegen-containment-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => panic!("could not create containment fixture: {error}"),
        }
    };
    assert_real_directory(&root);

    let existing_target = root.join("existing-target");
    fs::create_dir(&existing_target).expect("existing symlink target");
    let existing_link = root.join("linked-parent");
    let broken_link = root.join("broken-parent");
    symlink(&existing_target, &existing_link).expect("existing parent symlink");
    symlink(root.join("missing-target"), &broken_link).expect("broken parent symlink");

    let fake_repository = root.join("fake-repository");
    let fake_tool_directory = fake_repository.join("crates/automata-ci-protocol-protobuf/tools");
    let fake_helper_directory = fake_repository.join("scripts/ci/lib");
    fs::create_dir_all(&fake_tool_directory).expect("fake tool directory");
    fs::create_dir_all(&fake_helper_directory).expect("fake helper directory");
    fs::copy(
        crate_root.join("tools/protobuf-codegen.sh"),
        fake_tool_directory.join("protobuf-codegen.sh"),
    )
    .expect("copy verifier");
    fs::copy(
        repository_root.join("scripts/ci/lib/target-paths.sh"),
        fake_helper_directory.join("target-paths.sh"),
    )
    .expect("copy containment helper");
    let redirected_target = root.join("redirected-target");
    fs::create_dir(&redirected_target).expect("redirected target");
    let fake_target_link = fake_repository.join("target");
    symlink(&redirected_target, &fake_target_link).expect("fake target symlink");

    ContainmentFixture {
        root,
        existing_target,
        links: [existing_link, broken_link],
        fake_repository,
        redirected_target,
        fake_target_link,
    }
}

#[cfg(unix)]
#[test]
fn verifier_rejects_existing_and_broken_scratch_parent_symlinks() {
    let fixture = containment_fixture();
    let verifier = crate_root().join("tools/protobuf-codegen.sh");

    for link in &fixture.links {
        let output = Command::new(&verifier)
            .arg("verify")
            .env("AUTOMATA_PROTOBUF_CODEGEN_SCRATCH_DIR", link)
            .output()
            .expect("codegen verifier must start");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "symlinked scratch parent was accepted: {}",
            link.display()
        );
        assert!(
            stderr.contains("must not contain symbolic links"),
            "unexpected containment diagnostic: {stderr}"
        );
    }

    assert!(
        fs::read_dir(&fixture.existing_target)
            .expect("existing target")
            .next()
            .is_none(),
        "verifier wrote through a scratch-parent symlink"
    );
    assert!(
        !fixture.root.join("missing-target").exists(),
        "verifier materialized a broken symlink target"
    );
}

#[cfg(unix)]
#[test]
fn verifier_rejects_a_symlinked_repository_target() {
    let fixture = containment_fixture();
    let verifier = fixture
        .fake_repository
        .join("crates/automata-ci-protocol-protobuf/tools/protobuf-codegen.sh");
    let output = Command::new(verifier)
        .arg("verify")
        .output()
        .expect("copied codegen verifier must start");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "symlinked target was accepted");
    assert!(
        stderr.contains("repository target directory must not be a symbolic link"),
        "unexpected target containment diagnostic: {stderr}"
    );
    assert!(
        fs::read_dir(&fixture.redirected_target)
            .expect("redirected target")
            .next()
            .is_none(),
        "verifier wrote through the repository target symlink"
    );
}
