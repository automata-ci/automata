#![cfg(windows)]

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use automata_ci_core::{
    Architecture, IsolationLevel, OperatingSystem, RunnerFeature, SandboxFeature,
};
use automata_ci_execution::{
    NetworkPolicy, RootFilesystemPolicy, SandboxLaunch, SandboxPrivilegePolicy,
};
use automata_ci_protocol::WindowsRunnerAdmissionIssueRequest;
use automata_ci_runner::product::{
    RunnerProductConfig, RunnerProductConfigError, WindowsEnrollmentAdmissionRequest,
    WindowsEnrollmentIntent, WindowsHostInputKind, WindowsImageAdmission,
    windows_enrollment_admission_request,
};
use base64::Engine as _;
use ring::{rand::SystemRandom, signature::Ed25519KeyPair};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

static NEXT_EVIDENCE_ROOT: AtomicUsize = AtomicUsize::new(0);
const BROKER_HOST_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn write_secure_fixture(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write Windows evidence fixture");
    automata_ci_windows_file_security::restrict_file_to_current_user_for_test(path)
        .expect("restrict Windows evidence fixture DACL");
}

fn assert_admitted_action_features(request: &WindowsEnrollmentAdmissionRequest) {
    for feature in [
        RunnerFeature::JAVASCRIPT_ACTIONS,
        RunnerFeature::COMPOSITE_ACTIONS,
        RunnerFeature::REPOSITORY_ACTIONS,
        RunnerFeature::NODE24_ACTIONS,
    ] {
        assert!(
            request
                .binding()
                .capabilities()
                .features()
                .contains(&feature),
            "active admission must prove exact registration feature {feature}"
        );
    }
    assert!(
        !request
            .binding()
            .capabilities()
            .features()
            .contains(&RunnerFeature::LOCAL_ACTIONS),
        "workspace-local actions must remain ineligible on Windows"
    );
}

fn assert_host_input_contract(request: &WindowsEnrollmentAdmissionRequest, config_path: &Path) {
    let inputs = request.binding().host_inputs();
    assert_eq!(
        inputs
            .iter()
            .map(automata_ci_runner::product::WindowsHostInputDescriptor::kind)
            .collect::<Vec<_>>(),
        vec![
            WindowsHostInputKind::Configuration,
            WindowsHostInputKind::BackendExecutable,
            WindowsHostInputKind::ImageManifest,
            WindowsHostInputKind::ImageLock,
            WindowsHostInputKind::Provenance,
            WindowsHostInputKind::Sbom,
            WindowsHostInputKind::PatchReport,
            WindowsHostInputKind::Revocations,
            WindowsHostInputKind::PromotionEnvelope,
        ]
    );
    assert_eq!(inputs[0].absolute_path(), config_path);
    assert!(inputs.iter().all(|input| {
        input.absolute_path().is_absolute()
            && input
                .expected_sha256()
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
    }));
    assert_eq!(
        inputs
            .iter()
            .map(automata_ci_runner::product::WindowsHostInputDescriptor::absolute_path)
            .collect::<BTreeSet<_>>()
            .len(),
        inputs.len()
    );
}

struct EvidenceFixture {
    root: PathBuf,
    config: serde_json::Value,
}

impl EvidenceFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "automata-windows-image-evidence-{}-{}",
            std::process::id(),
            NEXT_EVIDENCE_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create evidence root");
        for (name, bytes) in [
            (
                "manifest.json",
                &include_bytes!(
                    "../../../images/windows-server-2025-hyperv-candidate/manifest.candidate.json"
                )[..],
            ),
            (
                "image.lock.json",
                &include_bytes!(
                    "../../../images/windows-server-2025-hyperv-candidate/image.lock.candidate.json"
                )[..],
            ),
            (
                "provenance.json",
                &include_bytes!(
                    "../../../images/windows-server-2025-hyperv-candidate/provenance.candidate.json"
                )[..],
            ),
            (
                "sbom.spdx.json",
                &include_bytes!(
                    "../../../images/windows-server-2025-hyperv-candidate/sbom.candidate.json"
                )[..],
            ),
            (
                "patch-report.json",
                &include_bytes!(
                    "../../../images/windows-server-2025-hyperv-candidate/patch-report.candidate.json"
                )[..],
            ),
            (
                "revocations.json",
                &include_bytes!(
                    "../../../images/windows-server-2025-hyperv-candidate/revocations.candidate.json"
                )[..],
            ),
        ] {
            write_secure_fixture(&root.join(name), bytes);
        }
        let mut config = baseline();
        for (field, name) in [
            ("manifest_path", "manifest.json"),
            ("lock_path", "image.lock.json"),
            ("provenance_path", "provenance.json"),
            ("sbom_path", "sbom.spdx.json"),
            ("patch_report_path", "patch-report.json"),
            ("revocations_path", "revocations.json"),
        ] {
            config["windows_hyperv"]["image_contract"][field] =
                serde_json::json!(root.join(name).to_string_lossy());
        }
        let mut fixture = Self { root, config };
        fixture.refresh_contract_digests();
        fixture
    }

    fn write_config(&self, name: &str) -> PathBuf {
        let path = self.root.join(name);
        let bytes = serde_json::to_vec(&self.config).expect("serialize evidence configuration");
        write_secure_fixture(&path, &bytes);
        path
    }

    fn make_production_eligible(&mut self, now_millis: u64) {
        for (field, name) in [
            ("provenance", "provenance.json"),
            ("sbom", "sbom.spdx.json"),
            ("patch_report", "patch-report.json"),
            ("revocations", "revocations.json"),
        ] {
            let path = self.root.join(name);
            let mut document: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).expect("read evidence"))
                    .expect("parse evidence");
            document
                .as_object_mut()
                .expect("evidence object")
                .remove("candidate_fixture");
            if field == "revocations" {
                document["issued_at_unix_millis"] = serde_json::json!(now_millis - 60_000);
                document["expires_at_unix_millis"] = serde_json::json!(now_millis + 600_000);
            }
            let bytes = serde_json::to_vec(&document).expect("serialize production evidence");
            write_secure_fixture(&path, &bytes);
        }

        self.refresh_contract_digests();
    }

    fn refresh_contract_digests(&mut self) {
        let manifest_path = self.root.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("parse manifest");
        for (field, name) in [
            ("provenance", "provenance.json"),
            ("sbom", "sbom.spdx.json"),
            ("patch_report", "patch-report.json"),
            ("revocations", "revocations.json"),
        ] {
            manifest["evidence"][field]["sha256"] = serde_json::json!(sha256_hex(
                &fs::read(self.root.join(name)).expect("read evidence fixture")
            ));
        }
        let manifest_bytes = serde_json::to_vec(&manifest).expect("serialize manifest");
        write_secure_fixture(&manifest_path, &manifest_bytes);
        let manifest_sha256 = sha256_hex(&manifest_bytes);

        let lock_path = self.root.join("image.lock.json");
        let mut lock: serde_json::Value =
            serde_json::from_slice(&fs::read(&lock_path).expect("read lock")).expect("parse lock");
        lock["manifest_sha256"] = serde_json::json!(manifest_sha256.clone());
        let lock_bytes = serde_json::to_vec(&lock).expect("serialize lock");
        write_secure_fixture(&lock_path, &lock_bytes);

        self.config["windows_hyperv"]["image_contract"]["manifest_sha256"] =
            serde_json::json!(manifest_sha256.clone());
        self.config["windows_hyperv"]["image_contract"]["lock_sha256"] =
            serde_json::json!(sha256_hex(&lock_bytes));
        self.config["inventory"]["environment_profiles"][0]["manifest_sha256"] =
            serde_json::json!(manifest_sha256);
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

impl Drop for EvidenceFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct TestPromotionPayload {
    schema_version: u16,
    decision: &'static str,
    promotion_serial: u64,
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
    profile_id: &'static str,
    base_image: String,
    image: String,
    manifest_sha256: String,
    lock_sha256: String,
    provenance_sha256: String,
    sbom_sha256: String,
    patch_report_sha256: String,
    revocations_sha256: String,
    revocation_generation: u64,
    provenance_accepted: bool,
    sbom_accepted: bool,
    patch_accepted: bool,
    revocations_accepted: bool,
}

fn add_promotion(fixture: &mut EvidenceFixture, now_millis: u64) {
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.root.join("manifest.json")).expect("read current manifest"),
    )
    .expect("parse current manifest");
    let payload = TestPromotionPayload {
        schema_version: 2,
        decision: "promote",
        promotion_serial: 7,
        issued_at_unix_millis: now_millis - 1_000,
        expires_at_unix_millis: now_millis + 300_000,
        profile_id: "automata.dev/windows-2025-x64-hyperv-v1",
        base_image: format!(
            "mcr.microsoft.com/windows/servercore@sha256:{}",
            "0".repeat(64)
        ),
        image: format!(
            "registry.example/automata/windows-runner@sha256:{}",
            "1".repeat(64)
        ),
        manifest_sha256: fixture.config["windows_hyperv"]["image_contract"]["manifest_sha256"]
            .as_str()
            .expect("manifest digest")
            .to_owned(),
        lock_sha256: fixture.config["windows_hyperv"]["image_contract"]["lock_sha256"]
            .as_str()
            .expect("lock digest")
            .to_owned(),
        provenance_sha256: manifest["evidence"]["provenance"]["sha256"]
            .as_str()
            .expect("provenance digest")
            .to_owned(),
        sbom_sha256: manifest["evidence"]["sbom"]["sha256"]
            .as_str()
            .expect("SBOM digest")
            .to_owned(),
        patch_report_sha256: manifest["evidence"]["patch_report"]["sha256"]
            .as_str()
            .expect("patch digest")
            .to_owned(),
        revocations_sha256: manifest["evidence"]["revocations"]["sha256"]
            .as_str()
            .expect("revocation digest")
            .to_owned(),
        revocation_generation: 1,
        provenance_accepted: true,
        sbom_accepted: true,
        patch_accepted: true,
        revocations_accepted: true,
    };
    let payload = serde_json::to_vec(&payload).expect("serialize canonical promotion payload");
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate signing key");
    let key = Ed25519KeyPair::from_pkcs8(key.as_ref()).expect("decode signing key");
    let encoder = base64::engine::general_purpose::STANDARD;
    let envelope = serde_json::json!({
        "schema_version": 1,
        "key_id": "test.windows-image-promotion.v1",
        "payload_base64": encoder.encode(&payload),
        "signature_base64": encoder.encode(key.sign(&payload).as_ref())
    });
    let envelope_path = fixture.root.join("promotion.json");
    let envelope_bytes = serde_json::to_vec(&envelope).expect("serialize promotion envelope");
    write_secure_fixture(&envelope_path, &envelope_bytes);
    fixture.config["windows_hyperv"]["image_contract"]["promotion"] = serde_json::json!({
        "envelope_path": envelope_path.to_string_lossy(),
        "trust_bundle_id": "windows-promotion.test.v1",
        "key_id": "test.windows-image-promotion.v1"
    });
}

fn baseline() -> serde_json::Value {
    serde_json::from_slice(include_bytes!("fixtures/runner.windows.product.json"))
        .expect("internal Windows product fixture JSON")
}

fn parse(value: &serde_json::Value) -> Result<RunnerProductConfig, RunnerProductConfigError> {
    RunnerProductConfig::from_json(
        &serde_json::to_vec(value).expect("serialize mutated Windows configuration"),
    )
}

fn enrollment_intent() -> WindowsEnrollmentIntent {
    WindowsEnrollmentIntent::new(
        uuid::Uuid::from_u128(1),
        &reqwest::Url::parse("https://enroll.example.test/").expect("enrollment origin"),
        "windows-runner",
        automata_ci_core::Sha256Digest::from_bytes([41; 32]),
        automata_ci_core::Sha256Digest::from_bytes([42; 32]),
    )
    .expect("enrollment intent")
}

#[test]
#[allow(clippy::too_many_lines)]
fn internal_windows_fixture_selects_only_hyperv_containers() {
    let config = parse(&baseline()).expect("internal Windows product fixture");
    let windows = config.windows_hyperv().expect("Windows Hyper-V provider");

    assert!(config.podman().is_none());
    assert!(config.kubernetes().is_none());
    assert!(config.macos_virtualization().is_none());
    assert_eq!(
        windows.runtime_executable(),
        std::path::Path::new(r"C:\Program Files\Docker\docker.exe")
    );
    assert_eq!(
        windows.guest_agent_path().as_str(),
        r"C:\automata\guest\automata-ci-sandbox-guest.exe"
    );
    assert_eq!(
        windows.operation_timeout(),
        std::time::Duration::from_mins(2)
    );
    assert_eq!(config.executor().network(), NetworkPolicy::Disabled);
    assert_eq!(
        config.executor().root_filesystem(),
        RootFilesystemPolicy::Writable
    );
    assert_eq!(
        config.executor().privilege(),
        SandboxPrivilegePolicy::Unprivileged
    );
    assert_eq!(
        config.inventory().platform().operating_system(),
        &OperatingSystem::Windows
    );
    assert_eq!(
        config.inventory().platform().architecture(),
        &Architecture::X86_64
    );
    assert_eq!(
        config.inventory().sandbox().maximum_isolation(),
        IsolationLevel::VirtualMachine
    );
    assert_eq!(
        config.inventory().sandbox().features(),
        &BTreeSet::from([
            SandboxFeature::CLEAN_WORKSPACE,
            SandboxFeature::NETWORK_ISOLATION,
            SandboxFeature::WINDOWS_HYPERV_CONTAINER,
        ])
    );
    assert!(config.executor().toolchain().pwsh().is_some());
    assert!(config.executor().toolchain().powershell().is_some());
    assert!(config.executor().toolchain().cmd().is_some());
    assert!(config.executor().toolchain().tar().is_some());
    assert!(config.executor().toolchain().sha256sum().is_some());
    assert!(config.executor().toolchain().node24().is_some());
    assert_eq!(windows.image_admission(), WindowsImageAdmission::Unverified);
    for feature in [
        RunnerFeature::SHELL_STEPS,
        RunnerFeature::DEFAULT_WINDOWS_SHELL,
        RunnerFeature::PWSH_SHELL,
        RunnerFeature::WINDOWS_POWERSHELL_SHELL,
        RunnerFeature::CMD_SHELL,
        RunnerFeature::COMMAND_FILES,
        RunnerFeature::JOB_SUMMARIES,
    ] {
        assert!(
            config.inventory().features().contains(&feature),
            "missing expected Windows runner feature {feature}; actual: {:?}",
            config.inventory().features()
        );
    }
    for feature in [
        RunnerFeature::DEFAULT_POSIX_SHELL,
        RunnerFeature::BASH_SHELL,
        RunnerFeature::SH_SHELL,
        RunnerFeature::PYTHON_SHELL,
        RunnerFeature::JAVASCRIPT_ACTIONS,
        RunnerFeature::COMPOSITE_ACTIONS,
        RunnerFeature::REPOSITORY_ACTIONS,
        RunnerFeature::LOCAL_ACTIONS,
        RunnerFeature::NODE12_ACTIONS,
        RunnerFeature::NODE16_ACTIONS,
        RunnerFeature::NODE20_ACTIONS,
        RunnerFeature::NODE24_ACTIONS,
    ] {
        assert!(!config.inventory().features().contains(&feature));
    }

    let environment = config
        .environments()
        .first_key_value()
        .expect("Hyper-V container environment")
        .1;
    let SandboxLaunch::WindowsHyperVContainer { image, keepalive } = environment.launch() else {
        panic!("Windows must not expose another launch mode")
    };
    assert!(image.reference().contains("@sha256:"));
    assert_eq!(
        keepalive.program().as_str(),
        r"C:\automata\guest\automata-ci-sandbox-guest.exe"
    );
    assert_eq!(keepalive.arguments(), &["keepalive".to_owned()]);
    assert_eq!(environment.workspace().as_str(), r"C:\__w");
    assert_eq!(
        config
            .executor()
            .toolchain()
            .node24()
            .map(automata_ci_execution::TargetPath::as_str),
        Some(r"C:\automata\externals\node24\node.exe")
    );
}

#[test]
fn candidate_evidence_is_verified_but_does_not_publish_action_capabilities() {
    let fixture = EvidenceFixture::new();
    let config = RunnerProductConfig::load(&fixture.write_config("candidate-runner.json"))
        .expect("candidate evidence is internally consistent");

    assert_eq!(
        config
            .windows_hyperv()
            .expect("Windows provider")
            .image_admission(),
        WindowsImageAdmission::Candidate
    );
    for feature in [
        RunnerFeature::JAVASCRIPT_ACTIONS,
        RunnerFeature::COMPOSITE_ACTIONS,
        RunnerFeature::REPOSITORY_ACTIONS,
        RunnerFeature::LOCAL_ACTIONS,
        RunnerFeature::NODE24_ACTIONS,
    ] {
        assert!(!config.inventory().features().contains(&feature));
    }
    assert!(
        windows_enrollment_admission_request(&config, BROKER_HOST_ID, enrollment_intent(),)
            .expect("candidate admission request")
            .is_none(),
        "unsigned candidate evidence must not create active enrollment authority"
    );
}

#[test]
fn a_signed_candidate_fixture_is_permanently_ineligible_for_broker_submission() {
    let mut fixture = EvidenceFixture::new();
    let now_millis = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("current time")
            .as_millis(),
    )
    .expect("time fits u64");
    add_promotion(&mut fixture, now_millis);

    assert_eq!(
        RunnerProductConfig::load(&fixture.write_config("signed-candidate-runner.json"))
            .expect_err("candidate fixture marker must win before signature handling"),
        RunnerProductConfigError::InvalidWindowsImage
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn exact_external_promotion_keeps_actions_pending_for_active_enrollment_admission() {
    let mut fixture = EvidenceFixture::new();
    let now_millis = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("current time")
            .as_millis(),
    )
    .expect("time fits u64");
    fixture.make_production_eligible(now_millis);
    add_promotion(&mut fixture, now_millis);
    let config_path = fixture.write_config("promoted-runner.json");
    let config = RunnerProductConfig::load(&config_path)
        .expect("production evidence envelope is ready for broker verification");

    assert_eq!(
        config
            .windows_hyperv()
            .expect("Windows provider")
            .image_admission(),
        WindowsImageAdmission::PromotionPending
    );
    for feature in [
        RunnerFeature::JAVASCRIPT_ACTIONS,
        RunnerFeature::COMPOSITE_ACTIONS,
        RunnerFeature::REPOSITORY_ACTIONS,
        RunnerFeature::LOCAL_ACTIONS,
        RunnerFeature::NODE24_ACTIONS,
    ] {
        assert!(
            !config.inventory().features().contains(&feature),
            "pre-admission inventory unexpectedly advertised {feature}"
        );
    }
    for feature in [
        RunnerFeature::NODE12_ACTIONS,
        RunnerFeature::NODE16_ACTIONS,
        RunnerFeature::NODE20_ACTIONS,
    ] {
        assert!(!config.inventory().features().contains(&feature));
    }

    let request =
        windows_enrollment_admission_request(&config, BROKER_HOST_ID, enrollment_intent())
            .expect("build promoted active-admission request")
            .expect("a promoted Windows image requires active admission");
    assert_eq!(request.binding().runner_id(), config.runner_id());
    assert_eq!(request.binding().backend_id(), BROKER_HOST_ID);
    assert_eq!(request.binding().sandbox_provider_id(), "windows-hyperv");
    let windows = config.windows_hyperv().expect("Windows provider");
    assert_eq!(
        request.binding().backend_executable(),
        windows.runtime_executable()
    );
    assert_eq!(
        request.binding().backend_executable_sha256(),
        windows.runtime_sha256()
    );
    assert_eq!(
        request.binding().promotion_trust_bundle_id(),
        "windows-promotion.test.v1"
    );
    assert_eq!(
        request.binding().promotion_envelope_sha256(),
        windows
            .promotion_envelope_sha256()
            .expect("verified promotion envelope")
    );
    assert_eq!(
        request.binding().intent().operation_id(),
        uuid::Uuid::from_u128(1)
    );
    assert_eq!(
        request.binding().profile(),
        request.environment().attestation()
    );
    assert_eq!(request.probe_policy().contract_schema_version(), 1);
    assert!(
        request
            .probe_policy()
            .contract_sha256()
            .as_bytes()
            .iter()
            .any(|byte| *byte != 0),
        "the shared exact probe contract must be digest-bound"
    );
    assert_eq!(
        request.binding().image(),
        request
            .environment()
            .image()
            .expect("Hyper-V container image")
            .reference()
    );
    assert_admitted_action_features(&request);
    assert_host_input_contract(&request, &config_path);

    let issue = request
        .to_protocol_issue_request()
        .expect("build canonical broker issue request");
    let canonical = issue.canonical_bytes().expect("canonical issue bytes");
    assert_eq!(
        WindowsRunnerAdmissionIssueRequest::from_canonical_bytes(&canonical)
            .expect("broker parses exact canonical bytes"),
        issue
    );
    let binding = request
        .to_protocol_binding()
        .expect("build signed-envelope binding");
    assert_eq!(
        binding.broker_profile().request_binding_sha256(),
        issue.request_sha256().expect("issue request digest")
    );
    let mut forged: serde_json::Value =
        serde_json::from_slice(&canonical).expect("issue request JSON");
    forged["forged_evidence_sha256"] = serde_json::json!("f".repeat(64));
    assert!(
        WindowsRunnerAdmissionIssueRequest::from_canonical_bytes(
            &serde_json::to_vec(&forged).expect("forged issue JSON"),
        )
        .is_err(),
        "runner-supplied evidence and unknown fields must not enter issuance"
    );
}

#[test]
fn evidence_verification_rejects_a_same_basename_tool_substitution() {
    let mut fixture = EvidenceFixture::new();
    fixture.config["executor"]["toolchain"]["node24"] =
        serde_json::json!(r"C:\automata\externals\substituted\node.exe");

    assert_eq!(
        RunnerProductConfig::load(&fixture.write_config("substituted-tool-runner.json"))
            .expect_err("manifest and configured Node path must agree"),
        RunnerProductConfigError::InvalidWindowsImage
    );
}

#[test]
fn evidence_verification_fails_closed_on_missing_evidence_and_malformed_authenticator() {
    let fixture = EvidenceFixture::new();
    fs::remove_file(fixture.root.join("sbom.spdx.json")).expect("remove SBOM fixture");
    assert_eq!(
        RunnerProductConfig::load(&fixture.write_config("missing-sbom-runner.json"))
            .expect_err("a missing SBOM must fail closed"),
        RunnerProductConfigError::InvalidWindowsImage
    );

    let mut fixture = EvidenceFixture::new();
    let now_millis = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("current time")
            .as_millis(),
    )
    .expect("time fits u64");
    fixture.make_production_eligible(now_millis);
    add_promotion(&mut fixture, now_millis);
    let envelope_path = fixture.root.join("promotion.json");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&envelope_path).expect("read promotion envelope"))
            .expect("parse promotion envelope");
    envelope["signature_base64"] =
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode([0_u8; 63]));
    let envelope_bytes =
        serde_json::to_vec(&envelope).expect("serialize corrupt promotion envelope");
    write_secure_fixture(&envelope_path, &envelope_bytes);
    assert_eq!(
        RunnerProductConfig::load(&fixture.write_config("malformed-authenticator-runner.json"))
            .expect_err("a malformed promotion authenticator must fail fast"),
        RunnerProductConfigError::InvalidWindowsImage
    );
}

#[test]
fn legacy_and_alternate_windows_providers_are_rejected() {
    let mut no_provider = baseline();
    no_provider
        .as_object_mut()
        .expect("configuration object")
        .remove("windows_hyperv");
    assert_eq!(
        parse(&no_provider).expect_err("a provider is required"),
        RunnerProductConfigError::InvalidProvider
    );

    let mut legacy = baseline();
    legacy
        .as_object_mut()
        .expect("configuration object")
        .remove("windows_hyperv");
    legacy["windows_native"] = serde_json::json!({});
    assert_eq!(
        parse(&legacy).expect_err("the native provider key must be unknown"),
        RunnerProductConfigError::InvalidDocument
    );

    let mut schema_two = baseline();
    schema_two["schema_version"] = serde_json::json!(2);
    assert_eq!(
        parse(&schema_two).expect_err("schema v2 must not be migrated implicitly"),
        RunnerProductConfigError::UnsupportedSchema
    );

    let linux = serde_json::from_slice::<serde_json::Value>(include_bytes!(
        "../config/runner.local-1.example.json"
    ))
    .expect("checked-in Linux configuration JSON");
    let mut two_providers = baseline();
    two_providers["podman"] = linux["podman"].clone();
    assert_eq!(
        parse(&two_providers).expect_err("multiple providers must fail closed"),
        RunnerProductConfigError::InvalidProvider
    );
}

#[test]
fn windows_configuration_rejects_every_weaker_boundary() {
    for (field, invalid_value) in [
        ("network", serde_json::json!("private_egress")),
        ("network", serde_json::json!("host")),
        ("root_filesystem", serde_json::json!("read_only")),
        ("root_filesystem", serde_json::json!("host")),
        ("privilege", serde_json::json!("administrator")),
        ("privilege", serde_json::json!("host")),
    ] {
        let mut value = baseline();
        value["executor"][field] = invalid_value;
        assert_eq!(
            parse(&value).expect_err("Hyper-V isolation policy is mandatory"),
            RunnerProductConfigError::InvalidExecutor
        );
    }

    let mut parallel = baseline();
    parallel["inventory"]["max_parallel_jobs"] = serde_json::json!(2);
    parse(&parallel).expect("independent Hyper-V containers may run concurrently");

    for field in ["ephemeral_disk_bytes", "gpu_count"] {
        let mut value = baseline();
        value["executor"]["resources"][field] = serde_json::json!(1);
        value["inventory"]["resources_per_job"][field] = serde_json::json!(1);
        assert!(parse(&value).is_err(), "nonzero {field} must fail closed");
    }
}

#[test]
fn windows_container_image_runtime_and_guest_agent_are_pinned() {
    let mut mutable_image = baseline();
    mutable_image["inventory"]["environment_profiles"][0]["image"] =
        serde_json::json!("mcr.microsoft.com/windows/servercore:ltsc2025");
    assert_eq!(
        parse(&mutable_image).expect_err("mutable images must be rejected"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut missing_keepalive = baseline();
    missing_keepalive["inventory"]["environment_profiles"][0]
        .as_object_mut()
        .expect("profile object")
        .remove("keepalive_program");
    assert_eq!(
        parse(&missing_keepalive).expect_err("an in-image keepalive is required"),
        RunnerProductConfigError::InvalidInventory
    );

    for (field, invalid) in [
        ("runtime_executable", serde_json::json!(r"docker.exe")),
        (
            "runtime_executable",
            serde_json::json!(r"C:\Program Files\Docker\container.exe"),
        ),
        ("runtime_sha256", serde_json::json!("not-a-digest")),
        ("guest_agent_path", serde_json::json!(r"C:\guest\agent.cmd")),
        (
            "guest_agent_path",
            serde_json::json!(r"C:\guest\%AUTOMATA_AGENT%.exe"),
        ),
        ("operation_timeout_seconds", serde_json::json!(0)),
        ("operation_timeout_seconds", serde_json::json!(601)),
    ] {
        let mut value = baseline();
        value["windows_hyperv"][field] = invalid;
        assert_eq!(
            parse(&value).expect_err("runtime and guest configuration must be exact"),
            RunnerProductConfigError::InvalidProvider,
            "invalid {field}"
        );
    }

    let mut mismatched_guest = baseline();
    mismatched_guest["windows_hyperv"]["guest_agent_path"] =
        serde_json::json!(r"C:\automata\guest\different-agent.exe");
    assert_eq!(
        parse(&mismatched_guest).expect_err("provider and launch guest paths must agree"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut alternate_keepalive = baseline();
    alternate_keepalive["inventory"]["environment_profiles"][0]["keepalive_arguments"] =
        serde_json::json!(["stdio-once"]);
    assert_eq!(
        parse(&alternate_keepalive).expect_err("the exact keepalive mode is mandatory"),
        RunnerProductConfigError::InvalidInventory
    );
}

#[test]
fn windows_container_toolchain_and_paths_are_in_image_and_literal() {
    let mut configured_node = baseline();
    configured_node["executor"]["toolchain"]["node24"] =
        serde_json::json!(r"C:\Program Files\nodejs\node.exe");
    let configured_node = parse(&configured_node).expect("literal node.exe is syntactically valid");
    assert!(
        !configured_node
            .inventory()
            .features()
            .contains(&RunnerFeature::NODE24_ACTIONS),
        "configuration parsing alone must not advertise the runtime"
    );

    let mut invalid_node = baseline();
    invalid_node["executor"]["toolchain"]["node20"] =
        serde_json::json!(r"C:\automata\externals\node20\node.cmd");
    assert_eq!(
        parse(&invalid_node).expect_err("every Node generation requires node.exe"),
        RunnerProductConfigError::InvalidExecutor
    );

    for (field, invalid) in [
        ("pwsh", r"C:\automata\tools\noop.exe"),
        ("powershell", r"C:\automata\tools\pwsh.exe"),
        ("cmd", r"C:\automata\tools\command.exe"),
        ("python", r"C:\automata\tools\noop.exe"),
    ] {
        let mut wrong_interpreter = baseline();
        wrong_interpreter["executor"]["toolchain"][field] = serde_json::json!(invalid);
        assert_eq!(
            parse(&wrong_interpreter)
                .expect_err("configured shell paths require the exact executable basename"),
            RunnerProductConfigError::InvalidExecutor,
            "invalid {field} executable"
        );
    }

    let mut packaged_shell = baseline();
    packaged_shell["executor"]["toolchain"]["pwsh"] =
        serde_json::json!(r"C:\Users\ContainerUser\AppData\Local\Microsoft\WindowsApps\pwsh.exe");
    assert_eq!(
        parse(&packaged_shell).expect_err("WindowsApps tools are not admitted"),
        RunnerProductConfigError::InvalidExecutor
    );

    let mut expanded_runner_root = baseline();
    expanded_runner_root["executor"]["runner_root"] =
        serde_json::json!(r"C:\automata\%RUNNER_ROOT%");
    assert_eq!(
        parse(&expanded_runner_root).expect_err("expanded paths must fail closed"),
        RunnerProductConfigError::InvalidExecutor
    );

    let mut expanded_workspace = baseline();
    expanded_workspace["inventory"]["environment_profiles"][0]["workspace"] =
        serde_json::json!(r"C:\%WORKSPACE%");
    assert_eq!(
        parse(&expanded_workspace).expect_err("expanded workspace must fail closed"),
        RunnerProductConfigError::InvalidInventory
    );

    for invalid in [r"C:\PROGRA~1\PowerShell", r"C:\Program Filés\PowerShell"] {
        let mut aliased_workspace = baseline();
        aliased_workspace["inventory"]["environment_profiles"][0]["workspace"] =
            serde_json::json!(invalid);
        assert_eq!(
            parse(&aliased_workspace)
                .expect_err("ambiguous Windows namespace aliases must fail closed"),
            RunnerProductConfigError::InvalidInventory,
            "invalid workspace {invalid}"
        );
    }

    let mut short_runner_root = baseline();
    short_runner_root["executor"]["runner_root"] = serde_json::json!(r"C:\AUTOMA~1\runner");
    assert_eq!(
        parse(&short_runner_root).expect_err("8.3 executor paths must fail closed"),
        RunnerProductConfigError::InvalidExecutor
    );
}

#[test]
fn windows_state_and_container_roots_are_disjoint_and_unambiguous() {
    let mut aliased = baseline();
    aliased["state"]["journal"] = serde_json::json!(r"c:\AUTOMATA\STATE\SPOOL\journal-alias");
    assert_eq!(
        parse(&aliased).expect_err("case-insensitive state roots overlap"),
        RunnerProductConfigError::InvalidStateRoots
    );

    for invalid in [
        r"\\server\share\automata\journal",
        r"\\?\C:\automata\state\journal",
        r"\\.\C:\automata\state\journal",
        r"C:\automata\state\CON",
        r"C:\AUTOMA~1\state\journal",
        r"C:\automáta\state\journal",
    ] {
        let mut value = baseline();
        value["state"]["journal"] = serde_json::json!(invalid);
        assert_eq!(
            parse(&value).expect_err("ambiguous Windows state path must fail closed"),
            RunnerProductConfigError::InvalidStateRoots,
            "invalid root {invalid}"
        );
    }

    let mut guest_overlap = baseline();
    guest_overlap["executor"]["runner_root"] = serde_json::json!(r"C:\__w\runner");
    assert_eq!(
        parse(&guest_overlap).expect_err("container roots must be disjoint"),
        RunnerProductConfigError::InvalidInventory
    );

    let mut tool_overlap = baseline();
    tool_overlap["inventory"]["environment_profiles"][0]["workspace"] =
        serde_json::json!(r"C:\Program Files\PowerShell");
    assert_eq!(
        parse(&tool_overlap).expect_err("the workspace must not contain an admitted tool"),
        RunnerProductConfigError::InvalidInventory
    );
}
