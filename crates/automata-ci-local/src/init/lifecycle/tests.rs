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
async fn acquired_lifecycle_signals_preserve_holder_loss_for_both_outcomes() {
    async fn assert_result<Output>(
        cancel_caller: bool,
        lose_holder: bool,
        expected: LocalInitErrorCode,
    ) {
        let holder_lost = CancellationToken::new();
        let caller = CancellationToken::new();
        let signals = AcquiredLifecycleSignals::from_signals(&caller, holder_lost.clone());
        let holder_signal = holder_lost.clone();
        let cancel_caller_signal = caller.clone();
        let operation = async move {
            if cancel_caller {
                cancel_caller_signal.cancel();
            }
            if lose_holder {
                holder_signal.cancel();
            }
            std::future::pending::<Result<Output, LocalInitError>>().await
        };

        let Err(error) = signals.run(operation).await else {
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

#[tokio::test]
async fn running_replay_attests_each_exact_cas_target_once() {
    let (_directory, established) = fixture();
    let artifacts = derive_bootstrap_artifacts(&established).unwrap();
    let attester = RecordingExactCasMaterialAttester::default();
    let initial = LifecycleTopology::Running {
        transit_id: "transit-id".to_owned(),
    };

    complete_running_replay(
        &attester,
        &established,
        &artifacts,
        b"relay binding\n",
        b"runner config\n",
        "relay-id",
        "runner-id",
        &initial,
        &CancellationToken::new(),
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
fn lower_hex_is_exact_and_lowercase() {
    assert_eq!(lower_hex(&[0x00, 0x0f, 0x10, 0xab, 0xff]), "000f10abff");
}
