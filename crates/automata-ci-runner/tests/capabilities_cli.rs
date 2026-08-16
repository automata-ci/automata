use std::process::Command;

use automata_ci_core::{RunnerCapabilities, RunnerFeature};
use automata_ci_runner::product::RunnerProductConfig;

#[cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

#[cfg(windows)]
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

#[cfg(unix)]
use automata_ci_core::OperationId;

#[cfg(target_os = "macos")]
const HOST_CONFIG: &str = "config/runner.macos.example.json";
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const HOST_CONFIG: &str = "config/runner.local-1.example.json";

#[cfg(windows)]
static NEXT_EVIDENCE_ROOT: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
fn write_secure_windows_fixture(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write Windows evidence fixture");
    automata_ci_windows_file_security::restrict_file_to_current_user_for_test(path)
        .expect("restrict Windows evidence fixture DACL");
}

#[cfg(windows)]
struct WindowsEvidenceFixture {
    root: PathBuf,
    config_path: PathBuf,
}

#[cfg(windows)]
impl WindowsEvidenceFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "automata-capabilities-windows-evidence-{}-{}",
            std::process::id(),
            NEXT_EVIDENCE_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create Windows evidence fixture root");
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
            write_secure_windows_fixture(&root.join(name), bytes);
        }
        let mut config: serde_json::Value =
            serde_json::from_slice(include_bytes!("fixtures/runner.windows.product.json"))
                .expect("parse internal Windows product fixture");
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
        let config_path = root.join("runner.json");
        let config_bytes =
            serde_json::to_vec(&config).expect("serialize Windows evidence configuration");
        write_secure_windows_fixture(&config_path, &config_bytes);
        Self { root, config_path }
    }
}

#[cfg(windows)]
impl Drop for WindowsEvidenceFixture {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn capabilities_command_emits_only_the_canonical_validated_inventory() {
    #[cfg(windows)]
    let fixture = WindowsEvidenceFixture::new();
    #[cfg(windows)]
    let config_path = fixture.config_path.to_string_lossy().into_owned();
    #[cfg(not(windows))]
    let config_path = format!("{}/{HOST_CONFIG}", env!("CARGO_MANIFEST_DIR"));
    let secret_sentinel = "capabilities-must-not-read-this-secret";
    let output = Command::new(env!("CARGO_BIN_EXE_automata-runner"))
        .args(["capabilities", "--config", &config_path])
        .env("AUTOMATA_S3_ACCESS_KEY_ID", secret_sentinel)
        .env("AUTOMATA_S3_SECRET_ACCESS_KEY", secret_sentinel)
        .output()
        .expect("runner capabilities command must start");

    assert!(
        output.status.success(),
        "capabilities command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("capabilities output must be JSON");
    let observed: RunnerCapabilities = serde_json::from_value(actual.clone())
        .expect("capabilities output must remain a canonical runner inventory");
    assert!(
        !observed.features().contains(&RunnerFeature::OIDC_TOKENS),
        "the official observed runner inventory must keep OIDC dark"
    );
    let config_bytes = std::fs::read(&config_path).expect("read checked-in product configuration");
    let config = RunnerProductConfig::from_json(&config_bytes)
        .expect("checked-in product configuration must validate");
    let expected = serde_json::to_value(config.inventory()).expect("inventory must serialize");
    assert_eq!(actual, expected);

    let stdout = String::from_utf8(output.stdout).expect("capabilities output must be UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostics must be UTF-8");
    for forbidden in [
        secret_sentinel,
        "AUTOMATA_S3_ACCESS_KEY_ID",
        "AUTOMATA_S3_SECRET_ACCESS_KEY",
        "certificate_chain",
        "private_key",
        "spool",
    ] {
        assert!(!stdout.contains(forbidden));
        assert!(!stderr.contains(forbidden));
    }
}

#[cfg(unix)]
#[test]
fn invalid_configuration_does_not_echo_input_bytes() {
    struct Fixture(PathBuf);

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.0);
        }
    }

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let fixture = Fixture(
        workspace
            .join("target")
            .join("runner-capabilities-cli-tests")
            .join(OperationId::new().to_string()),
    );
    fs::create_dir_all(&fixture.0).expect("create configuration fixture directory");
    let config_path = fixture.0.join("runner.json");
    let secret_sentinel = "malformed-config-secret-must-not-escape";
    fs::write(
        &config_path,
        format!(r#"{{"unreviewed_secret":"{secret_sentinel}"}}"#),
    )
    .expect("write malformed configuration fixture");
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
        .expect("restrict malformed configuration fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_automata-runner"))
        .args(["capabilities", "--config"])
        .arg(&config_path)
        .output()
        .expect("runner capabilities command must start");

    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret_sentinel));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret_sentinel));
}
