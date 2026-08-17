use super::*;
use crate::admission::repository::{
    FileWindowsBrokerAdmissionRepository, WindowsBrokerAdmissionRepository,
};
use crate::custody::file::FileWindowsBrokerCustody;
use automata_ci_core::{
    Architecture, ContainerCapabilities, EnvironmentProfile, EnvironmentProfileId, IsolationLevel,
    JobResourceAllocation, OperatingSystem, OperationId, ResourceCapacity, RunnerCapabilities,
    RunnerFeature, RunnerId, RunnerPlatform, SandboxCapabilities, SandboxFeature,
};
use automata_ci_protocol::{
    WindowsAdmissionImage, WindowsEnrollmentTransactionBinding, WindowsImagePromotionBinding,
};
use automata_ci_windows_broker_core::{
    admission::{
        VerifiedWindowsBrokerAdmissionEvaluator, WindowsBrokerAdmissionInputSet,
        WindowsBrokerAdmissionInputSource, WindowsBrokerPromotionTrustBundle,
        WindowsBrokerPromotionTrustKey, WindowsBrokerPromotionTrustRegistry,
        WindowsBrokerSyntheticProbe, WindowsBrokerSyntheticProbeEvidence,
    },
    host_input::{
        WindowsBrokerHostInputAttestation, WindowsBrokerHostInputDescriptor,
        WindowsBrokerHostInputKind, WindowsBrokerHostInputObservation,
        WindowsBrokerHostInputRequest,
    },
    request::{
        WindowsAdmissionArgv, WindowsAdmissionBackendContract, WindowsAdmissionLaunchContract,
        WindowsAdmissionProbeContract, WindowsAdmissionPromotionRequest,
        WindowsAdmissionResourceLimits,
    },
};
use automata_ci_windows_broker_protocol::WINDOWS_HYPERV_PROVIDER_ID;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair as _},
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Barrier,
};

const TEST_NOW_MILLIS: i64 = 1_000_000;
const TEST_PROMOTION_PAYLOAD_SCHEMA_VERSION: u16 = 2;
const TEST_EVIDENCE_REFERENCE_MEDIA_TYPE: &str =
    "application/vnd.automata.windows-image-evidence-reference+json";

#[derive(Serialize)]
struct TestPromotionPayload {
    schema_version: u16,
    decision: String,
    promotion_serial: u64,
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
    profile_id: String,
    base_image: String,
    image: String,
    manifest_sha256: String,
    lock_sha256: String,
    provenance_sha256: String,
    sbom_sha256: String,
    patch_report_sha256: String,
    revocations_sha256: String,
    revocation_generation: u64,
    provenance_accepted: TestAccepted,
    sbom_accepted: TestAccepted,
    patch_accepted: TestAccepted,
    revocations_accepted: TestAccepted,
}

#[derive(Serialize)]
#[serde(transparent)]
struct TestAccepted(bool);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PromotionFault {
    None,
    WrongSignature,
    UnknownKey,
    NonCanonicalPayload,
    Stale,
    CandidateEvidence,
}

#[derive(Debug)]
struct FixtureInputSource {
    host_id: Sha256Digest,
    documents: BTreeMap<WindowsBrokerHostInputKind, Vec<u8>>,
}

impl WindowsBrokerAdmissionInputSource for FixtureInputSource {
    fn load(
        &self,
        request: &WindowsBrokerHostInputRequest,
        issued_at: UnixMillis,
        valid_until: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionInputSet, WindowsBrokerAdmissionError> {
        let observations = request
            .inputs()
            .iter()
            .enumerate()
            .map(|(index, descriptor)| {
                let byte_len = self.documents.get(&descriptor.kind()).map_or(64, Vec::len);
                WindowsBrokerHostInputObservation::new(
                    descriptor,
                    u64::try_from(byte_len)
                        .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?,
                    41,
                    [u8::try_from(index + 1)
                        .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
                        16],
                    "S-1-5-80-1-2-3-4-5".to_owned(),
                    Sha256Digest::from_bytes([91; 32]),
                )
                .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let attestation = WindowsBrokerHostInputAttestation::issue(
            self.host_id,
            request,
            observations,
            issued_at,
            valid_until,
        )
        .map_err(|_| WindowsBrokerAdmissionError::EvidenceRejected)?;
        let documents = self
            .documents
            .iter()
            .map(|(kind, bytes)| (*kind, Zeroizing::new(bytes.clone())))
            .collect();
        WindowsBrokerAdmissionInputSet::new(request, attestation, documents)
    }
}

#[derive(Clone, Copy, Debug)]
struct FixtureProbe;

impl WindowsBrokerSyntheticProbe for FixtureProbe {
    fn execute(
        &self,
        _request: &WindowsBrokerAdmissionRequest,
        _host_inputs: &WindowsBrokerHostInputAttestation,
        _now: UnixMillis,
        _valid_until: UnixMillis,
    ) -> Result<WindowsBrokerSyntheticProbeEvidence, WindowsBrokerAdmissionError> {
        WindowsBrokerSyntheticProbeEvidence::new(
            Sha256Digest::from_bytes([92; 32]),
            Sha256Digest::from_bytes([93; 32]),
            Sha256Digest::from_bytes([94; 32]),
        )
    }
}

#[derive(Debug)]
struct BarrierAdmissionEvaluator {
    inner: Arc<dyn WindowsBrokerAdmissionEvaluator>,
    rendezvous: Arc<Barrier>,
}

impl WindowsBrokerAdmissionEvaluator for BarrierAdmissionEvaluator {
    fn evaluate(
        &self,
        request: &WindowsBrokerAdmissionRequest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionEvaluation, WindowsBrokerAdmissionError> {
        self.rendezvous.wait();
        self.inner.evaluate(request, now)
    }
}

#[derive(Debug)]
struct FixtureProtector;

impl crate::custody::WindowsBrokerCustodyProtector for FixtureProtector {
    fn seal(&self, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError> {
        let mut sealed = b"admission-test-v1:".to_vec();
        sealed.extend(plaintext.iter().map(|byte| byte ^ 0xa5));
        Ok(Zeroizing::new(sealed))
    }

    fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError> {
        let ciphertext = sealed
            .strip_prefix(b"admission-test-v1:")
            .ok_or(WindowsBrokerCustodyError::Protector)?;
        Ok(Zeroizing::new(
            ciphertext.iter().map(|byte| byte ^ 0xa5).collect(),
        ))
    }
}

struct PromotionFixture {
    host_id: Sha256Digest,
    request: WindowsBrokerAdmissionRequest,
    documents: BTreeMap<WindowsBrokerHostInputKind, Vec<u8>>,
    trust: WindowsBrokerPromotionTrustRegistry,
}

impl PromotionFixture {
    fn evaluator(&self) -> VerifiedWindowsBrokerAdmissionEvaluator {
        VerifiedWindowsBrokerAdmissionEvaluator::new(
            self.host_id,
            Arc::new(FixtureInputSource {
                host_id: self.host_id,
                documents: self.documents.clone(),
            }),
            self.trust.clone(),
            Arc::new(FixtureProbe),
        )
        .expect("fixture evaluator")
    }
}

fn evidence_document(
    kind: &str,
    subject_media_type: &str,
    image: &str,
    candidate_fixture: bool,
    revocation_expiry: Option<u64>,
) -> Vec<u8> {
    let mut document = serde_json::json!({
        "schema_version": 1,
        "kind": kind,
        "candidate_fixture": candidate_fixture,
        "profile_id": "example.com/windows-server-2025",
        "image": image,
        "subject": {
            "sha256": Sha256Digest::from_bytes([52; 32]).to_string(),
            "media_type": subject_media_type,
        },
        "statement": "production evidence accepted",
    });
    if kind == "revocations" {
        let object = document.as_object_mut().expect("evidence object");
        object.insert("generation".to_owned(), serde_json::json!(7));
        object.insert(
            "issued_at_unix_millis".to_owned(),
            serde_json::json!(800_000_u64),
        );
        object.insert(
            "expires_at_unix_millis".to_owned(),
            serde_json::json!(revocation_expiry.expect("revocation expiry")),
        );
        object.insert("revoked_images".to_owned(), serde_json::json!([]));
    }
    serde_json::to_vec(&document).expect("evidence document")
}

#[allow(clippy::too_many_lines)]
fn promotion_fixture(fault: PromotionFault, sealed_action_trees: bool) -> PromotionFixture {
    let host_id = Sha256Digest::from_bytes([11; 32]);
    let image_digest = Sha256Digest::from_bytes([12; 32]);
    let image = format!("registry.example/windows/runner@sha256:{image_digest}");
    let base_digest = Sha256Digest::from_bytes([13; 32]);
    let base_image = format!("registry.example/windows/base@sha256:{base_digest}");
    let promotion_expiry = if fault == PromotionFault::Stale {
        u64::try_from(TEST_NOW_MILLIS).expect("positive test clock")
    } else {
        2_000_000
    };

    let provenance = evidence_document(
        "provenance",
        "application/vnd.in-toto+json",
        &image,
        false,
        None,
    );
    let sbom = evidence_document(
        "sbom",
        "application/spdx+json",
        &image,
        fault == PromotionFault::CandidateEvidence,
        None,
    );
    let patch_report = evidence_document(
        "patch_report",
        "application/vnd.automata.windows-patch-report+json",
        &image,
        false,
        None,
    );
    let revocations = evidence_document(
        "revocations",
        "application/vnd.automata.image-revocations+json",
        &image,
        false,
        Some(promotion_expiry),
    );
    let provenance_sha256 = sha256(&provenance);
    let sbom_sha256 = sha256(&sbom);
    let patch_report_sha256 = sha256(&patch_report);
    let revocations_sha256 = sha256(&revocations);
    let tool_sha256 = Sha256Digest::from_bytes([14; 32]).to_string();
    let manifest = serde_json::to_vec(&serde_json::json!({
         "schema_version": 1,
         "status": "candidate",
         "profile_id": "example.com/windows-server-2025",
         "operating_system": "windows-server-2025",
         "variant": "server-core",
         "architecture": "x86_64",
         "isolation": "hyperv-container",
         "base_image": base_image,
         "image": image,
         "workspace": r"C:\Automata\workspace",
         "guest_agent": r"C:\Automata\guest.exe",
         "network_disabled": true,
         "unprivileged": true,
         "clean_workspace": true,
         "tools": [
             {"kind": "pwsh", "path": r"C:\Program Files\PowerShell\7\pwsh.exe", "version": "7.4", "sha256": tool_sha256},
             {"kind": "powershell", "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "version": "5.1", "sha256": tool_sha256},
             {"kind": "cmd", "path": r"C:\Windows\System32\cmd.exe", "version": "10.0", "sha256": tool_sha256},
             {"kind": "sha256", "path": r"C:\Automata\tools\automata-sha256.exe", "version": "1.0", "sha256": tool_sha256},
         ],
         "evidence": {
             "provenance": {"sha256": provenance_sha256.to_string(), "media_type": TEST_EVIDENCE_REFERENCE_MEDIA_TYPE},
             "sbom": {"sha256": sbom_sha256.to_string(), "media_type": TEST_EVIDENCE_REFERENCE_MEDIA_TYPE},
             "patch_report": {"sha256": patch_report_sha256.to_string(), "media_type": TEST_EVIDENCE_REFERENCE_MEDIA_TYPE},
             "revocations": {"sha256": revocations_sha256.to_string(), "media_type": TEST_EVIDENCE_REFERENCE_MEDIA_TYPE},
         },
     }))
     .expect("manifest");
    let manifest_sha256 = sha256(&manifest);
    let lock = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "profile_id": "example.com/windows-server-2025",
        "manifest_sha256": manifest_sha256.to_string(),
        "base_image": base_image,
        "image": image,
    }))
    .expect("lock");
    let lock_sha256 = sha256(&lock);
    let payload = TestPromotionPayload {
        schema_version: TEST_PROMOTION_PAYLOAD_SCHEMA_VERSION,
        decision: "promote".to_owned(),
        promotion_serial: 17,
        issued_at_unix_millis: 900_000,
        expires_at_unix_millis: promotion_expiry,
        profile_id: "example.com/windows-server-2025".to_owned(),
        base_image: base_image.clone(),
        image: image.clone(),
        manifest_sha256: manifest_sha256.to_string(),
        lock_sha256: lock_sha256.to_string(),
        provenance_sha256: provenance_sha256.to_string(),
        sbom_sha256: sbom_sha256.to_string(),
        patch_report_sha256: patch_report_sha256.to_string(),
        revocations_sha256: revocations_sha256.to_string(),
        revocation_generation: 7,
        provenance_accepted: TestAccepted(true),
        sbom_accepted: TestAccepted(true),
        patch_accepted: TestAccepted(true),
        revocations_accepted: TestAccepted(true),
    };
    let mut payload_bytes = serde_json::to_vec(&payload).expect("payload");
    if fault == PromotionFault::NonCanonicalPayload {
        payload_bytes.push(b' ');
    }
    let trusted_key_pair =
        Ed25519KeyPair::from_seed_unchecked(&[61; 32]).expect("trusted promotion key");
    let signing_key_pair = if fault == PromotionFault::WrongSignature {
        Ed25519KeyPair::from_seed_unchecked(&[62; 32]).expect("untrusted promotion key")
    } else {
        Ed25519KeyPair::from_seed_unchecked(&[61; 32]).expect("promotion key")
    };
    let requested_key_id = if fault == PromotionFault::UnknownKey {
        "missing-promotion-key"
    } else {
        "windows-promotion-key"
    };
    let signature = signing_key_pair.sign(&payload_bytes);
    let promotion_envelope = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "key_id": requested_key_id,
        "payload_base64": BASE64.encode(&payload_bytes),
        "signature_base64": BASE64.encode(signature.as_ref()),
    }))
    .expect("promotion envelope");

    let backend_path = r"C:\Program Files\Automata\automata-windows-hyperv-broker-client.exe";
    let envelope_path = r"C:\Automata\promotion-envelope.json";
    let input_values = [
        (
            WindowsBrokerHostInputKind::Configuration,
            r"C:\Automata\runner.json",
            Sha256Digest::from_bytes([31; 32]),
        ),
        (
            WindowsBrokerHostInputKind::BackendExecutable,
            backend_path,
            Sha256Digest::from_bytes([32; 32]),
        ),
        (
            WindowsBrokerHostInputKind::ImageManifest,
            r"C:\Automata\image-manifest.json",
            manifest_sha256,
        ),
        (
            WindowsBrokerHostInputKind::ImageLock,
            r"C:\Automata\image-lock.json",
            lock_sha256,
        ),
        (
            WindowsBrokerHostInputKind::Provenance,
            r"C:\Automata\provenance.json",
            provenance_sha256,
        ),
        (
            WindowsBrokerHostInputKind::Sbom,
            r"C:\Automata\sbom.json",
            sbom_sha256,
        ),
        (
            WindowsBrokerHostInputKind::PatchReport,
            r"C:\Automata\patch-report.json",
            patch_report_sha256,
        ),
        (
            WindowsBrokerHostInputKind::Revocations,
            r"C:\Automata\revocations.json",
            revocations_sha256,
        ),
        (
            WindowsBrokerHostInputKind::PromotionEnvelope,
            envelope_path,
            sha256(&promotion_envelope),
        ),
    ];
    let host_inputs = WindowsBrokerHostInputRequest::new(
        host_id.to_string(),
        WINDOWS_HYPERV_PROVIDER_ID,
        input_values
            .into_iter()
            .map(|(kind, path, digest)| {
                WindowsBrokerHostInputDescriptor::new(kind, path, digest).expect("host input")
            })
            .collect(),
    )
    .expect("host inputs");
    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("example.com/windows-server-2025").expect("profile id"),
        Sha256Digest::from_bytes([15; 32]),
    );
    let capacity = ResourceCapacity::new(2_000, 2 * 1024 * 1024 * 1024, 0, 0);
    let allocation = JobResourceAllocation::new(capacity, capacity).expect("allocation");
    let resources = WindowsAdmissionResourceLimits::new(2 * 1024 * 1024 * 1024, 2_000, 128)
        .expect("resource limits");
    let launch = WindowsAdmissionLaunchContract::new(
        profile.clone(),
        WindowsAdmissionImage::new(image, image_digest).expect("image"),
        WindowsAdmissionArgv::new(r"C:\Automata\guest.exe", vec!["keepalive".to_owned()])
            .expect("keepalive"),
        r"C:\Automata\workspace",
        Vec::new(),
        resources,
        allocation,
        true,
        true,
        true,
        true,
        sealed_action_trees,
    )
    .expect("launch");
    let probe = WindowsAdmissionProbeContract::new(
        1,
        Sha256Digest::from_bytes([16; 32]),
        resources,
        allocation,
        true,
        true,
        true,
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\System32\cmd.exe",
        None,
        r"C:\Automata\tools\automata-sha256.exe",
        None,
        None,
        None,
        None,
    )
    .expect("probe");
    let runner_id = RunnerId::new();
    let runner_name = "windows-runner";
    let transaction = WindowsEnrollmentTransactionBinding::new(
        runner_id,
        OperationId::new(),
        "https://control.example/",
        "https://enrollment.example/",
        sha256(runner_name.as_bytes()),
        Sha256Digest::from_bytes([17; 32]),
        Sha256Digest::from_bytes([18; 32]),
    )
    .expect("transaction");
    let mut features = vec![
        RunnerFeature::SHELL_STEPS,
        RunnerFeature::DEFAULT_WINDOWS_SHELL,
        RunnerFeature::PWSH_SHELL,
        RunnerFeature::WINDOWS_POWERSHELL_SHELL,
        RunnerFeature::CMD_SHELL,
    ];
    if sealed_action_trees {
        features.extend([
            RunnerFeature::REPOSITORY_ACTIONS,
            RunnerFeature::COMPOSITE_ACTIONS,
        ]);
    }
    let capabilities = RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Windows, Architecture::X86_64),
    )
    .with_max_parallel_jobs(1)
    .expect("parallel jobs")
    .with_resources_per_job(capacity)
    .with_sandbox(SandboxCapabilities::new(
        IsolationLevel::VirtualMachine,
        [
            SandboxFeature::CLEAN_WORKSPACE,
            SandboxFeature::NETWORK_ISOLATION,
            SandboxFeature::WINDOWS_HYPERV_CONTAINER,
        ],
    ))
    .with_containers(ContainerCapabilities::default())
    .with_features(features)
    .with_environment_profiles([profile]);
    let promotion = WindowsAdmissionPromotionRequest::new(
        envelope_path,
        "windows-production-v1",
        requested_key_id,
        manifest_sha256,
        lock_sha256,
    )
    .expect("promotion request");
    let request = WindowsBrokerAdmissionRequest::new(
        transaction,
        runner_name,
        host_id.to_string(),
        WINDOWS_HYPERV_PROVIDER_ID,
        WindowsAdmissionBackendContract::new(
            backend_path,
            Sha256Digest::from_bytes([32; 32]),
            120_000,
        )
        .expect("backend"),
        host_inputs,
        launch,
        probe,
        promotion,
        capabilities,
    )
    .expect("issue request");
    let documents = BTreeMap::from([
        (WindowsBrokerHostInputKind::ImageManifest, manifest),
        (WindowsBrokerHostInputKind::ImageLock, lock),
        (WindowsBrokerHostInputKind::Provenance, provenance),
        (WindowsBrokerHostInputKind::Sbom, sbom),
        (WindowsBrokerHostInputKind::PatchReport, patch_report),
        (WindowsBrokerHostInputKind::Revocations, revocations),
        (
            WindowsBrokerHostInputKind::PromotionEnvelope,
            promotion_envelope,
        ),
    ]);
    let trusted_public_key: [u8; 32] = trusted_key_pair
        .public_key()
        .as_ref()
        .try_into()
        .expect("public key length");
    let trust_key =
        WindowsBrokerPromotionTrustKey::new("windows-promotion-key", trusted_public_key)
            .expect("trust key");
    let trust_sha256 = WindowsBrokerPromotionTrustBundle::canonical_sha256(
        "windows-production-v1",
        std::slice::from_ref(&trust_key),
    );
    let trust = WindowsBrokerPromotionTrustRegistry::new(vec![
        WindowsBrokerPromotionTrustBundle::new(
            "windows-production-v1",
            trust_sha256,
            vec![trust_key],
        )
        .expect("trust bundle"),
    ])
    .expect("trust registry");
    PromotionFixture {
        host_id,
        request,
        documents,
        trust,
    }
}

fn temp_root() -> PathBuf {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).expect("random temp root");
    std::env::temp_dir().join(format!("automata-admission-{}", sha256(&nonce)))
}

fn signing_key(pkcs8: &[u8]) -> Arc<WindowsBrokerAdmissionSigningKey> {
    Arc::new(
        WindowsBrokerAdmissionSigningKey::from_pkcs8("windows-admission-key", pkcs8)
            .expect("admission signing key"),
    )
}

fn file_admission_service<C>(
    state_path: &Path,
    custody: Arc<C>,
    evaluator: Arc<dyn WindowsBrokerAdmissionEvaluator>,
    signing_key: Arc<WindowsBrokerAdmissionSigningKey>,
) -> Result<WindowsBrokerAdmissionService, WindowsBrokerAdmissionError>
where
    C: WindowsBrokerAdmissionCustody + 'static,
{
    let repository = Arc::new(FileWindowsBrokerAdmissionRepository::open(state_path)?);
    let custody: Arc<dyn WindowsBrokerAdmissionCustody> = custody;
    WindowsBrokerAdmissionService::new(repository, custody, evaluator, signing_key)
}

fn binding_with_promotion(
    binding: &WindowsRunnerAdmissionBinding,
    serial: u64,
    revocation_generation: u64,
    digest_marker: u8,
) -> WindowsRunnerAdmissionBinding {
    let promotion = WindowsImagePromotionBinding::new(
        binding.promotion().trust_bundle_id(),
        binding.promotion().key_id(),
        Sha256Digest::from_bytes([digest_marker; 32]),
        Sha256Digest::from_bytes([digest_marker.saturating_add(1); 32]),
        serial,
        revocation_generation,
        binding.promotion().validity(),
    )
    .expect("promotion binding");
    WindowsRunnerAdmissionBinding::new(
        binding.transaction().clone(),
        binding.broker_profile().clone(),
        promotion,
        binding.capabilities().clone(),
    )
    .expect("admission binding")
}

#[test]
fn issue_timestamp_is_floored_without_moving_expiry() {
    let observed = UnixMillis::new(12_345);
    let expiry = UnixMillis::new(912_345);
    assert_eq!(
        floor_windows_admission_issued_at(observed).expect("floor"),
        UnixMillis::new(12_000)
    );
    assert_eq!(expiry, UnixMillis::new(912_345));
    assert_eq!(
        floor_windows_admission_issued_at(UnixMillis::new(-1)),
        Err(WindowsBrokerAdmissionError::InvalidRequest)
    );
}

#[test]
fn promotion_trust_bundle_commitment_is_ordered_and_exact() {
    let first = WindowsBrokerPromotionTrustKey::new("key-a", [1_u8; 32]).expect("key");
    let second = WindowsBrokerPromotionTrustKey::new("key-b", [2_u8; 32]).expect("key");
    let forward = WindowsBrokerPromotionTrustBundle::canonical_sha256(
        "windows-production-v1",
        &[first.clone(), second.clone()],
    );
    let reverse = WindowsBrokerPromotionTrustBundle::canonical_sha256(
        "windows-production-v1",
        &[second.clone(), first.clone()],
    );
    assert_eq!(forward, reverse);
    let forward_bundle = WindowsBrokerPromotionTrustBundle::new(
        "windows-production-v1",
        forward,
        vec![first.clone(), second.clone()],
    )
    .expect("forward bundle");
    let reverse_bundle = WindowsBrokerPromotionTrustBundle::new(
        "windows-production-v1",
        reverse,
        vec![second, first.clone()],
    )
    .expect("reverse bundle");
    assert_eq!(forward_bundle, reverse_bundle);
    assert_eq!(
        WindowsBrokerPromotionTrustBundle::new(
            "windows-production-v1",
            Sha256Digest::from_bytes([9_u8; 32]),
            vec![first],
        ),
        Err(WindowsBrokerAdmissionError::InvalidRequest)
    );
}

#[test]
fn any_candidate_fixture_rejects_the_entire_promotion() {
    let fixture = promotion_fixture(PromotionFault::CandidateEvidence, false);
    assert!(matches!(
        fixture
            .evaluator()
            .evaluate(&fixture.request, UnixMillis::new(TEST_NOW_MILLIS)),
        Err(WindowsBrokerAdmissionError::EvidenceRejected)
    ));
}

#[test]
fn verified_promotion_rejects_signature_key_canonical_stale_and_candidate_failures() {
    let valid = promotion_fixture(PromotionFault::None, false);
    let evaluation = valid
        .evaluator()
        .evaluate(&valid.request, UnixMillis::new(TEST_NOW_MILLIS))
        .expect("valid promotion");
    assert_eq!(evaluation.launch(), valid.request.launch());

    for fault in [
        PromotionFault::WrongSignature,
        PromotionFault::UnknownKey,
        PromotionFault::NonCanonicalPayload,
        PromotionFault::Stale,
        PromotionFault::CandidateEvidence,
    ] {
        let fixture = promotion_fixture(fault, false);
        assert!(matches!(
            fixture
                .evaluator()
                .evaluate(&fixture.request, UnixMillis::new(TEST_NOW_MILLIS)),
            Err(WindowsBrokerAdmissionError::EvidenceRejected)
        ));
    }
}

#[test]
fn evaluator_rejects_action_capabilities_until_sealed_trees_are_supported() {
    let fixture = promotion_fixture(PromotionFault::None, true);
    assert!(matches!(
        fixture
            .evaluator()
            .evaluate(&fixture.request, UnixMillis::new(TEST_NOW_MILLIS)),
        Err(WindowsBrokerAdmissionError::EvidenceRejected)
    ));
}

#[test]
fn promotion_high_water_rejects_rollback_and_same_serial_substitution() {
    let fixture = promotion_fixture(PromotionFault::None, false);
    let evaluation = fixture
        .evaluator()
        .evaluate(&fixture.request, UnixMillis::new(TEST_NOW_MILLIS))
        .expect("verified evaluation");
    let binding = evaluation.binding();
    let mut state = WindowsBrokerAdmissionSnapshot::default();
    WindowsBrokerAdmissionService::enforce_and_advance_high_water(&mut state, binding)
        .expect("initial head");
    WindowsBrokerAdmissionService::enforce_and_advance_high_water(&mut state, binding)
        .expect("exact replay");

    let lower_serial = binding_with_promotion(binding, 16, 7, 81);
    assert_eq!(
        WindowsBrokerAdmissionService::enforce_and_advance_high_water(&mut state, &lower_serial,),
        Err(WindowsBrokerAdmissionError::EvidenceRejected)
    );
    let lower_revocation = binding_with_promotion(binding, 18, 6, 82);
    assert_eq!(
        WindowsBrokerAdmissionService::enforce_and_advance_high_water(
            &mut state,
            &lower_revocation,
        ),
        Err(WindowsBrokerAdmissionError::EvidenceRejected)
    );
    let substituted = binding_with_promotion(binding, 17, 7, 83);
    assert_eq!(
        WindowsBrokerAdmissionService::enforce_and_advance_high_water(&mut state, &substituted,),
        Err(WindowsBrokerAdmissionError::EvidenceRejected)
    );
    let advanced = binding_with_promotion(binding, 18, 8, 84);
    WindowsBrokerAdmissionService::enforce_and_advance_high_water(&mut state, &advanced)
        .expect("monotonic advance");
}

#[test]
fn concurrent_renewals_replay_the_exact_retained_envelope_until_ack() {
    let fixture = promotion_fixture(PromotionFault::None, false);
    let root = temp_root();
    let state_path = root.join("admission-state.json");
    let custody = Arc::new(
        FileWindowsBrokerCustody::open(root.join("custody"), Arc::new(FixtureProtector))
            .expect("custody"),
    );
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .expect("generate admission key")
        .as_ref()
        .to_vec();
    let authority = file_admission_service(
        &state_path,
        Arc::clone(&custody),
        Arc::new(fixture.evaluator()),
        signing_key(&pkcs8),
    )
    .expect("authority");
    let receipt = authority
        .issue(&fixture.request, UnixMillis::new(TEST_NOW_MILLIS))
        .expect("issue");
    authority
        .complete(receipt.handle(), receipt.envelope_sha256())
        .expect("complete");
    drop(authority);

    let evaluator: Arc<dyn WindowsBrokerAdmissionEvaluator> = Arc::new(BarrierAdmissionEvaluator {
        inner: Arc::new(fixture.evaluator()),
        rendezvous: Arc::new(Barrier::new(2)),
    });
    let authority = file_admission_service(&state_path, custody, evaluator, signing_key(&pkcs8))
        .expect("restart authority");
    let now = UnixMillis::new(1_100_000);
    let (first, second) = std::thread::scope(|scope| {
        let first =
            scope.spawn(|| authority.renew(receipt.handle(), receipt.envelope_sha256(), now));
        let second =
            scope.spawn(|| authority.renew(receipt.handle(), receipt.envelope_sha256(), now));
        (
            first.join().expect("first renewal thread"),
            second.join().expect("second renewal thread"),
        )
    });
    let first = first.expect("first renewal");
    let second = second.expect("second renewal");
    assert_eq!(first, second);
    assert_eq!(
        first
            .envelope()
            .claims()
            .expect("renewal claims")
            .renewal_serial(),
        1
    );
    authority
        .acknowledge_renewal(receipt.handle(), first.envelope_sha256())
        .expect("ack retained renewal");
    authority
        .acknowledge_renewal(receipt.handle(), first.envelope_sha256())
        .expect("idempotent ACK");

    fs::remove_dir_all(root).expect("remove temp root");
}

#[test]
#[allow(clippy::too_many_lines)]
fn authority_recovers_issue_and_replays_renewal_until_exact_ack() {
    let fixture = promotion_fixture(PromotionFault::None, false);
    let root = temp_root();
    let state_path = root.join("admission-state.json");
    let custody_root = root.join("custody");
    let protector: Arc<dyn crate::custody::WindowsBrokerCustodyProtector> =
        Arc::new(FixtureProtector);
    let custody = Arc::new(
        FileWindowsBrokerCustody::open(&custody_root, Arc::clone(&protector)).expect("custody"),
    );
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .expect("generate admission key")
        .as_ref()
        .to_vec();
    let evaluator: Arc<dyn WindowsBrokerAdmissionEvaluator> = Arc::new(fixture.evaluator());
    let authority = file_admission_service(
        &state_path,
        Arc::clone(&custody),
        Arc::clone(&evaluator),
        signing_key(&pkcs8),
    )
    .expect("authority");

    let now = UnixMillis::new(TEST_NOW_MILLIS);
    let receipt = authority.issue(&fixture.request, now).expect("issue");
    let replay = authority
        .issue(&fixture.request, UnixMillis::new(TEST_NOW_MILLIS + 1))
        .expect("issue replay");
    assert_eq!(receipt, replay);
    let request_sha256 = fixture.request.request_sha256().expect("request digest");
    assert_eq!(
        authority
            .resume(
                receipt.handle(),
                request_sha256,
                UnixMillis::new(TEST_NOW_MILLIS + 2),
            )
            .expect("resume"),
        receipt
    );
    drop(authority);

    let repository =
        FileWindowsBrokerAdmissionRepository::open(&state_path).expect("open repository");
    let mut interrupted = repository.load().expect("read state");
    interrupted
        .records
        .get_mut(&request_sha256.to_string())
        .expect("issued record")
        .phase = AdmissionRecordPhase::Issuing;
    repository
        .store(&interrupted)
        .expect("persist interrupted issue");
    let authority = file_admission_service(
        &state_path,
        Arc::clone(&custody),
        Arc::clone(&evaluator),
        signing_key(&pkcs8),
    )
    .expect("recover issuing authority");
    assert_eq!(
        authority
            .resume(
                receipt.handle(),
                request_sha256,
                UnixMillis::new(TEST_NOW_MILLIS + 3),
            )
            .expect("resume recovered issue"),
        receipt
    );
    assert_eq!(
        authority.complete(receipt.handle(), Sha256Digest::from_bytes([99; 32])),
        Err(WindowsBrokerAdmissionError::InvalidReceipt)
    );
    authority
        .complete(receipt.handle(), receipt.envelope_sha256())
        .expect("complete");
    authority
        .complete(receipt.handle(), receipt.envelope_sha256())
        .expect("idempotent completion");
    drop(authority);
    drop(custody);

    let restarted_custody = Arc::new(
        FileWindowsBrokerCustody::open(&custody_root, protector).expect("restart custody"),
    );
    let restarted = file_admission_service(
        &state_path,
        restarted_custody,
        evaluator,
        signing_key(&pkcs8),
    )
    .expect("restart authority");
    assert_eq!(
        restarted.issue(&fixture.request, UnixMillis::new(TEST_NOW_MILLIS + 4)),
        Err(WindowsBrokerAdmissionError::InvalidState)
    );

    let first_renewal = restarted
        .renew(
            receipt.handle(),
            receipt.envelope_sha256(),
            UnixMillis::new(1_100_000),
        )
        .expect("first renewal");
    let replayed_renewal = restarted
        .renew(
            receipt.handle(),
            receipt.envelope_sha256(),
            UnixMillis::new(1_100_001),
        )
        .expect("replayed renewal");
    assert_eq!(first_renewal, replayed_renewal);
    assert_eq!(
        first_renewal
            .envelope()
            .claims()
            .expect("renewal claims")
            .renewal_serial(),
        1
    );
    assert_eq!(
        restarted.acknowledge_renewal(receipt.handle(), Sha256Digest::from_bytes([98; 32]),),
        Err(WindowsBrokerAdmissionError::InvalidReceipt)
    );
    restarted
        .acknowledge_renewal(receipt.handle(), first_renewal.envelope_sha256())
        .expect("ack renewal");
    restarted
        .acknowledge_renewal(receipt.handle(), first_renewal.envelope_sha256())
        .expect("idempotent renewal ack");
    let second_renewal = restarted
        .renew(
            receipt.handle(),
            receipt.envelope_sha256(),
            UnixMillis::new(1_200_000),
        )
        .expect("second renewal");
    assert_eq!(
        second_renewal
            .envelope()
            .claims()
            .expect("renewal claims")
            .renewal_serial(),
        2
    );
    drop(restarted);
    fs::remove_dir_all(root).expect("remove temp root");
}
