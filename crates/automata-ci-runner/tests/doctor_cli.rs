use std::process::Command;

use automata_ci_runner::capability_probe::{PODMAN_NETWORK_ISOLATION, PROCESS_EXECUTION};

#[test]
fn doctor_json_command_emits_a_machine_readable_report() {
    let output = Command::new(env!("CARGO_BIN_EXE_automata-runner"))
        .args(["doctor", "--json"])
        .output()
        .expect("runner doctor must start");

    assert!(
        output.status.success(),
        "doctor failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor output must be JSON");
    assert!(
        report["capabilities"]
            .as_array()
            .expect("capabilities must be an array")
            .iter()
            .any(|capability| capability == PROCESS_EXECUTION)
    );
    assert!(
        !report["capabilities"]
            .as_array()
            .expect("capabilities must be an array")
            .iter()
            .any(|capability| capability == PODMAN_NETWORK_ISOLATION)
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn active_doctor_json_reports_unsupported_platform_and_exits_unsuccessfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_automata-runner"))
        .args(["doctor", "--active", "--json"])
        .env_remove("RUST_LOG")
        .output()
        .expect("active runner doctor must start");

    assert!(!output.status.success());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor output must be JSON");
    assert_eq!(report["active"], true);
    assert!(
        !report["capabilities"]
            .as_array()
            .expect("capabilities must be an array")
            .iter()
            .any(|capability| capability == PODMAN_NETWORK_ISOLATION)
    );
    assert!(
        report["capability_probes"]
            .as_array()
            .expect("capability probes must be an array")
            .iter()
            .any(|probe| {
                probe["capability"] == PODMAN_NETWORK_ISOLATION
                    && probe["status"] == "unavailable"
                    && probe["reason"]["code"] == "active_probe_unsupported_platform"
            })
    );
    assert_eq!(
        String::from_utf8(output.stderr)
            .expect("stderr must be UTF-8")
            .trim(),
        "Error: active Podman network isolation probe failed"
    );
}
