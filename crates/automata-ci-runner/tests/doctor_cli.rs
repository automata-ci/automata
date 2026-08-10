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
