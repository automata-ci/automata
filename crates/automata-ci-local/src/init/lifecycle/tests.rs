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

struct RecordingRunningReplayDriver {
    services: std::sync::Mutex<Vec<&'static str>>,
    cas: std::sync::Mutex<Vec<(CasTarget, Sha256Digest, BTreeSet<String>)>>,
    inspections: AtomicU64,
    topology: LifecycleTopology,
}

struct TestLifecycleHolder {
    holder_lost: CancellationToken,
    drops: std::sync::Arc<AtomicU64>,
}

impl LifecycleHolderAuthority for TestLifecycleHolder {
    fn holder_lost(&self) -> CancellationToken {
        self.holder_lost.clone()
    }
}

impl Drop for TestLifecycleHolder {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

#[async_trait::async_trait]
impl RunningReplayDriver for RecordingRunningReplayDriver {
    async fn attest_service(&self, service: &'static str) -> Result<String, LocalInitError> {
        self.services.lock().unwrap().push(service);
        Ok(match service {
            "automata" => "c".repeat(64),
            "engine-relay" => "d".repeat(64),
            "runner" => "e".repeat(64),
            _ => panic!("unexpected running service {service}"),
        })
    }

    async fn attest_cas(
        &self,
        target: CasTarget,
        expected: Sha256Digest,
        expected_attachments: BTreeSet<String>,
    ) -> Result<(), LocalInitError> {
        self.cas
            .lock()
            .unwrap()
            .push((target, expected, expected_attachments));
        Ok(())
    }

    async fn inspect_topology(&self) -> Result<LifecycleTopology, LocalInitError> {
        self.inspections.fetch_add(1, Ordering::Relaxed);
        Ok(self.topology.clone())
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
async fn acquired_up_and_down_guards_preserve_holder_loss() {
    fn signals(
        cancel_caller: bool,
        lose_holder: bool,
    ) -> (
        AcquiredLifecycleGuard<TestLifecycleHolder>,
        impl Future<Output = ()>,
        std::sync::Arc<AtomicU64>,
    ) {
        let holder_lost = CancellationToken::new();
        let caller = CancellationToken::new();
        let drops = std::sync::Arc::new(AtomicU64::new(0));
        let acquired = AcquiredLifecycleGuard::new(
            &caller,
            TestLifecycleHolder {
                holder_lost: holder_lost.clone(),
                drops: std::sync::Arc::clone(&drops),
            },
        );
        let holder_signal = holder_lost.clone();
        let cancel_caller_signal = caller.clone();
        let operation = async move {
            if cancel_caller {
                cancel_caller_signal.cancel();
            }
            if lose_holder {
                holder_signal.cancel();
            }
            std::future::pending::<()>().await;
        };
        (acquired, operation, drops)
    }

    async fn assert_up(cancel_caller: bool, lose_holder: bool, expected: LocalInitErrorCode) {
        let (acquired, operation, drops) = signals(cancel_caller, lose_holder);
        let guarded = acquired
            .run_up(async move {
                operation.await;
                unreachable!("a cancelled lifecycle operation cannot complete")
            })
            .await;
        let Err(error) = acquired.finish(guarded) else {
            panic!("a cancelled lifecycle operation cannot complete");
        };
        assert_eq!(error.code(), expected);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    async fn assert_down(cancel_caller: bool, lose_holder: bool, expected: LocalInitErrorCode) {
        let (acquired, operation, drops) = signals(cancel_caller, lose_holder);
        let guarded = acquired
            .run_down(async move {
                operation.await;
                unreachable!("a cancelled lifecycle operation cannot complete")
            })
            .await;
        let Err(error) = acquired.finish(guarded) else {
            panic!("a cancelled lifecycle operation cannot complete");
        };
        assert_eq!(error.code(), expected);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    for (cancel_caller, lose_holder, expected) in [
        (true, false, LocalInitErrorCode::Cancelled),
        (false, true, LocalInitErrorCode::ResetRequired),
        (true, true, LocalInitErrorCode::ResetRequired),
    ] {
        assert_up(cancel_caller, lose_holder, expected).await;
        assert_down(cancel_caller, lose_holder, expected).await;
    }
}

#[tokio::test]
async fn running_topology_branch_attests_each_exact_cas_target_once() {
    let (_directory, established) = fixture();
    let initial = LifecycleTopology::Running {
        transit_id: "f".repeat(64),
    };
    let driver = RecordingRunningReplayDriver {
        services: std::sync::Mutex::new(Vec::new()),
        cas: std::sync::Mutex::new(Vec::new()),
        inspections: AtomicU64::new(0),
        topology: initial.clone(),
    };
    let desired = crate::init::desired_from_catalog(
        &crate::init::catalog::desired_test_catalog(),
        &established.installation,
        std::num::NonZeroU16::new(1).unwrap(),
    )
    .unwrap();
    let relay_engine = RelayEngineFacts {
        id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        api_version: "1.48",
        server_version: "28.3.3",
        architecture: crate::EngineArchitecture::Amd64,
    };

    let result = replay_running_topology_if_present(
        &driver,
        &established,
        &desired,
        &relay_engine,
        &initial,
        true,
        &CancellationToken::new(),
    )
    .await
    .unwrap()
    .expect("running topology replays");

    assert_eq!(result.desired, desired);
    assert!(result.resumed);
    assert_eq!(
        *driver.services.lock().unwrap(),
        ["automata", "engine-relay", "runner"]
    );
    assert_eq!(driver.inspections.load(Ordering::Relaxed), 1);
    {
        let cas = driver.cas.lock().unwrap();
        assert!(
            cas.iter()
                .all(|(_, digest, _)| *digest != Sha256Digest::from_bytes([0; 32]))
        );
        assert_eq!(
            cas.iter().map(|(target, _, _)| *target).collect::<Vec<_>>(),
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
        assert_eq!(cas[0].2, BTreeSet::new());
        assert_eq!(cas[1].2, BTreeSet::new());
        assert_eq!(cas[2].2, BTreeSet::from(["d".repeat(64)]));
        for (_, _, attachments) in &cas[3..] {
            assert_eq!(*attachments, BTreeSet::from(["e".repeat(64)]));
        }
    }

    let idle = RecordingRunningReplayDriver {
        services: std::sync::Mutex::new(Vec::new()),
        cas: std::sync::Mutex::new(Vec::new()),
        inspections: AtomicU64::new(0),
        topology: LifecycleTopology::Empty,
    };
    assert!(
        replay_running_topology_if_present(
            &idle,
            &established,
            &desired,
            &relay_engine,
            &LifecycleTopology::Empty,
            false,
            &CancellationToken::new(),
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(idle.services.lock().unwrap().is_empty());
    assert!(idle.cas.lock().unwrap().is_empty());
    assert_eq!(idle.inspections.load(Ordering::Relaxed), 0);
}

#[test]
fn lower_hex_is_exact_and_lowercase() {
    assert_eq!(lower_hex(&[0x00, 0x0f, 0x10, 0xab, 0xff]), "000f10abff");
}
