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

#[derive(Default)]
struct RecordingExactCasMaterialAttester {
    targets: std::sync::Mutex<Vec<CasTarget>>,
}

#[async_trait::async_trait]
impl ExactCasMaterialAttester for RecordingExactCasMaterialAttester {
    async fn attest(
        &self,
        target: CasTarget,
        _expected: Sha256Digest,
        _expected_attachments: BTreeSet<String>,
    ) -> Result<(), LocalInitError> {
        self.targets.lock().unwrap().push(target);
        Ok(())
    }
}

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
async fn acquired_up_and_down_operations_preserve_holder_loss() {
    async fn assert_result<Output>(
        cancel_caller: bool,
        lose_holder: bool,
        expected: LocalInitErrorCode,
    ) {
        let holder_lost = CancellationToken::new();
        let transaction_cancellation = CancellationToken::new();
        let holder_signal = holder_lost.clone();
        let cancel_transaction = transaction_cancellation.clone();
        let operation = async move {
            if cancel_caller {
                cancel_transaction.cancel();
            }
            if lose_holder {
                holder_signal.cancel();
            }
            std::future::pending::<Result<Output, LocalInitError>>().await
        };

        let Err(error) =
            run_acquired_lifecycle_operation(&holder_lost, &transaction_cancellation, operation)
                .await
        else {
            panic!("a cancelled lifecycle operation cannot complete");
        };
        assert_eq!(error.code(), expected);
    }

    for (cancel_caller, lose_holder, expected) in [
        (true, false, LocalInitErrorCode::Cancelled),
        (false, true, LocalInitErrorCode::ResetRequired),
        (true, true, LocalInitErrorCode::ResetRequired),
    ] {
        assert_result::<UpLifecycleOperationResult>(cancel_caller, lose_holder, expected).await;
        assert_result::<DownLifecycleOperationResult>(cancel_caller, lose_holder, expected).await;
    }
}

#[test]
fn public_up_and_down_use_the_acquired_holder_boundary() {
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

    for (operation, result_type) in [
        (up, "UpLifecycleOperationResult"),
        (down, "DownLifecycleOperationResult"),
    ] {
        assert_eq!(
            operation
                .matches("let holder_lost = holder.holder_lost();")
                .count(),
            1
        );
        assert_eq!(
            operation
                .matches(
                    "run_acquired_lifecycle_operation(&holder_lost, &transaction_cancellation, operation)",
                )
                .count(),
            1
        );
        assert!(operation.contains(&format!(
            "let {result_type} {{ desired, resumed }} = match operation"
        )));

        let (_, completion) = operation
            .split_once("watcher.abort();")
            .expect("the acquired operation is joined before lock release");
        let (completion, _) = completion
            .split_once(".release_lifecycle_lock(")
            .expect("the operation result precedes graceful lock release");
        assert_eq!(completion.matches("return Err(error);").count(), 1);
    }
}

#[tokio::test]
async fn running_replay_attests_each_exact_cas_target_once() {
    let (_directory, established) = fixture();
    let artifacts = derive_bootstrap_artifacts(&established).unwrap();
    let attester = RecordingExactCasMaterialAttester::default();
    let initial = LifecycleTopology::Running {
        transit_id: "transit-id".to_owned(),
    };

    complete_running_replay(
        &initial,
        &CancellationToken::new(),
        || {
            attest_exact_cas_material_with(
                &attester,
                &established,
                &artifacts,
                b"relay binding\n",
                b"runner config\n",
                "relay-id",
                "runner-id",
            )
        },
        || async { Ok(initial.clone()) },
    )
    .await
    .unwrap();

    assert_eq!(
        *attester.targets.lock().unwrap(),
        vec![
            CasTarget::BootstrapRequest,
            CasTarget::BootstrapToken,
            CasTarget::RelayBinding,
            CasTarget::RunnerConfig,
            CasTarget::RunnerS3AccessKey,
            CasTarget::RunnerS3Ca,
            CasTarget::RunnerS3SecretKey,
            CasTarget::RunnerSpoolKey,
        ]
    );
}

#[test]
fn running_branch_calls_exact_cas_attestation_once() {
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
