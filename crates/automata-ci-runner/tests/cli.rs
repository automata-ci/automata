use std::process::Command;

#[test]
fn top_level_help_describes_the_supported_linux_host() {
    let output = Command::new(env!("CARGO_BIN_EXE_automata-runner"))
        .arg("--help")
        .output()
        .expect("runner help must execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("runner help must be UTF-8");
    assert!(stdout.contains("Automata runner for rootless Linux execution hosts"));
    assert!(stdout.contains("capabilities"));
    assert!(stdout.contains("without loading credentials"));
    assert!(!stdout.contains("cross-platform"));
}
