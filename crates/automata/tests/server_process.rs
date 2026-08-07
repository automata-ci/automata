use std::process::Command;

#[test]
fn startup_errors_do_not_disclose_secret_source_references() {
    let marker = "AUTOMATA_PRIVATE_CA_LOCATION_MARKER";
    let accidental_inline_secret = format!("inline-private-value-{marker}");
    let output = Command::new(env!("CARGO_BIN_EXE_automata"))
        .args([
            "server",
            "--listen",
            "127.0.0.1:0",
            "--runner-listen",
            "127.0.0.1:0",
            "--runner-client-ca-source",
            &accidental_inline_secret,
        ])
        .output()
        .expect("control-plane process must start");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("secret configuration must use env:NAME or file:PATH references"));
    assert!(!stderr.contains(marker));
    assert!(!stderr.contains(&accidental_inline_secret));
}
