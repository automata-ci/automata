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

#[test]
fn malformed_arguments_never_echo_secret_material() {
    for arguments in [
        vec![
            "secret",
            "set",
            "TOKEN",
            "--scope",
            "repo:automata/automata",
            "managed-secret-sentinel",
        ],
        vec![
            "server",
            "--auth-decryption-key",
            "auth-decryption-key-sentinel",
        ],
        vec![
            "server",
            "--secret-decryption-key",
            "secret-decryption-key-sentinel",
        ],
        vec![
            "server",
            "--control-plane-decryption-key",
            "control-plane-decryption-key-sentinel",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_automata"))
            .args(&arguments)
            .output()
            .expect("control-plane process must start");

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr,
            "Error: invalid command-line arguments; run `automata --help`\n"
        );
        for argument in arguments {
            assert!(!stderr.contains(argument));
        }
    }
}
