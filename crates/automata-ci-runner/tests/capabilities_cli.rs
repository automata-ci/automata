use std::process::Command;

use automata_ci_core::{RunnerCapabilities, RunnerFeature};
use automata_ci_runner::product::RunnerProductConfig;

#[cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

#[cfg(unix)]
use automata_ci_core::OperationId;

#[test]
fn capabilities_command_emits_only_the_canonical_validated_inventory() {
    let config_path = format!(
        "{}/config/runner.local.example.json",
        env!("CARGO_MANIFEST_DIR")
    );
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
    let config =
        RunnerProductConfig::from_json(include_bytes!("../config/runner.local.example.json"))
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
