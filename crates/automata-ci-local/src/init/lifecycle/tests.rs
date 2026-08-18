use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::atomic::{AtomicU64, Ordering},
};

use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::*;
use crate::InstallationId;
use crate::init::{certificates::CertificateMaterial, epoch::authority_test_epoch};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate is inside the workspace");
        let scratch = workspace.join("target/task-tmp/automata-ci-local");
        fs::create_dir_all(&scratch).unwrap();
        let path = scratch.join(format!(
            "automata-ci-local-lifecycle-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn state_path(&self) -> PathBuf {
        self.0.join("state")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fixture() -> (TestDirectory, EstablishedLifecycle) {
    let directory = TestDirectory::new();
    let state = StateRoot::acquire(&directory.state_path()).unwrap();
    let installation = Installation::verified(
        InstallationName::new("lifecycle-test").unwrap(),
        InstallationId::from_str("11111111-2222-4333-8444-555555555555").unwrap(),
    );
    let material_root = [0x51; 32];
    let epoch = authority_test_epoch(&installation, &material_root, state.authority_sha256());
    let certificates = CertificateMaterial {
        ca_pem: "ca\n".to_owned(),
        ca_key_pem: Zeroizing::new("ca-key\n".to_owned()),
        postgres_chain_pem: "postgres\n".to_owned(),
        postgres_key_pem: Zeroizing::new("postgres-key\n".to_owned()),
        object_chain_pem: "object\n".to_owned(),
        object_key_pem: Zeroizing::new("object-key\n".to_owned()),
        runner_chain_pem: "runner\n".to_owned(),
        runner_key_pem: Zeroizing::new("runner-key\n".to_owned()),
    };
    (
        directory,
        EstablishedLifecycle {
            installation,
            epoch,
            material_root: Zeroizing::new(material_root),
            certificates,
        },
    )
}

#[test]
fn bootstrap_identity_uses_the_installation_uuid_and_material_root_identifier() {
    let (_directory, established) = fixture();
    let artifacts = derive_bootstrap_artifacts(&established).unwrap();
    let request: serde_json::Value = serde_json::from_slice(&artifacts.request).unwrap();

    assert_eq!(
        request["tenant"]["tenant_id"],
        format!("local-{}", established.installation.id().as_uuid().simple())
    );
    assert_eq!(
        request["installation_authority_source_sha256"],
        established.epoch.material_root_sha256().to_string()
    );
    assert_eq!(request["runner_id"], artifacts.runner_id.to_string());
}

#[test]
fn bootstrap_artifacts_are_stable_for_one_sealed_epoch() {
    let (_directory, established) = fixture();
    let first = derive_bootstrap_artifacts(&established).unwrap();
    let second = derive_bootstrap_artifacts(&established).unwrap();

    assert_eq!(first.request, second.request);
    assert_eq!(first.token.as_str(), second.token.as_str());
    assert_eq!(first.runner_id, second.runner_id);
    assert_eq!(first.spool_key.as_str(), second.spool_key.as_str());
    assert_eq!(first.s3_access_key, second.s3_access_key);
    assert_eq!(first.s3_secret_key.as_str(), second.s3_secret_key.as_str());
}

#[test]
fn lifecycle_has_no_host_operation_journal() {
    let source = include_str!("../lifecycle.rs");
    for rejected in [
        "LifecycleIntent",
        "LifecyclePhase",
        "lifecycle-operation.json",
        "store_lifecycle_operation",
        "observe_lifecycle_operation",
    ] {
        assert!(
            !source.contains(rejected),
            "found rejected host journal token {rejected}"
        );
    }
}

#[test]
fn cancellation_checkpoint_is_fail_closed() {
    let cancellation = CancellationToken::new();
    assert!(cancellation_checkpoint(&cancellation).is_ok());
    cancellation.cancel();
    assert_eq!(
        cancellation_checkpoint(&cancellation).unwrap_err().code(),
        LocalInitErrorCode::Cancelled
    );
}

#[tokio::test]
async fn lifecycle_boundary_preserves_holder_loss_over_caller_cancellation() {
    for (cancel_caller, lose_holder, expected) in [
        (true, false, LocalInitErrorCode::Cancelled),
        (false, true, LocalInitErrorCode::ResetRequired),
        (true, true, LocalInitErrorCode::ResetRequired),
    ] {
        let holder_lost = CancellationToken::new();
        let transaction_cancellation = CancellationToken::new();
        if cancel_caller {
            transaction_cancellation.cancel();
        }
        if lose_holder {
            holder_lost.cancel();
        }

        let result = holder_bounded(
            &holder_lost,
            cancellation_bounded(&transaction_cancellation, async { Ok(()) }),
        )
        .await;

        assert_eq!(result.unwrap_err().code(), expected);
    }
}

#[test]
fn public_up_and_down_use_the_holder_dominant_boundary() {
    let source = include_str!("../lifecycle.rs");
    let (_, up_and_later) = source
        .split_once("pub async fn up_local(")
        .expect("public up entry point exists");
    let (up, down_and_later) = up_and_later
        .split_once("pub async fn down_local(")
        .expect("public down entry point exists");
    let (down, _) = down_and_later
        .split_once("async fn recover_stopped_lock_if_authorized(")
        .expect("down entry point has a trailing helper boundary");

    for operation in [up, down] {
        assert_eq!(
            operation
                .matches("let holder_lost = holder.holder_lost();")
                .count(),
            1
        );
        assert_eq!(operation.matches("holder_bounded(").count(), 1);
    }
}

#[test]
fn running_replay_attests_exact_cas_material_once() {
    let source = include_str!("../lifecycle.rs");
    let (_, running_and_later) = source
        .split_once("if let LifecycleTopology::Running { transit_id } = &initial {")
        .expect("up has a Running replay branch");
    let (running, _) = running_and_later
        .split_once("if initial == LifecycleTopology::Partial {")
        .expect("Running replay precedes Partial convergence");

    assert_eq!(running.matches("attest_exact_cas_material(").count(), 1);
}

#[test]
fn lower_hex_is_exact_and_lowercase() {
    assert_eq!(lower_hex(&[0x00, 0x0f, 0x10, 0xab, 0xff]), "000f10abff");
}
