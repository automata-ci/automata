#![cfg(not(unix))]

use std::{io::ErrorKind, net::TcpListener, process::Command};

const SERVER_SENTINEL: &str = "http://127.0.0.1:9";
const SECRET_SENTINEL: &str = "WINDOWS_SECRET_SENTINEL";
const PATH_SENTINEL: &str = "WINDOWS_PATH_SENTINEL.txt";

#[test]
fn authentication_commands_fail_before_using_operator_input() {
    for operation in ["login", "status", "logout"] {
        assert_unsupported(
            &["auth", "--server-url", SERVER_SENTINEL, operation],
            "CLI authentication is not supported on this platform",
        );
    }
}

#[test]
fn secret_commands_fail_before_using_operator_input() {
    for arguments in [
        vec![
            "secret",
            "--server-url",
            SERVER_SENTINEL,
            "list",
            "--scope",
            "repo:owner/repository",
        ],
        vec![
            "secret",
            "--server-url",
            SERVER_SENTINEL,
            "create",
            SECRET_SENTINEL,
            "--scope",
            "repo:owner/repository",
            "--from-file",
            PATH_SENTINEL,
        ],
        vec![
            "secret",
            "--server-url",
            SERVER_SENTINEL,
            "delete",
            SECRET_SENTINEL,
            "--scope",
            "repo:owner/repository",
            "--yes",
        ],
        vec![
            "secret",
            "--server-url",
            SERVER_SENTINEL,
            "provider",
            "status",
        ],
        vec![
            "secret",
            "--server-url",
            SERVER_SENTINEL,
            "provider",
            "activate",
        ],
    ] {
        assert_unsupported(
            &arguments,
            "CLI secret management is not supported on this platform",
        );
    }
}

#[test]
fn server_startup_fails_closed_and_enumerates_missing_adapters() {
    let output = Command::new(env!("CARGO_BIN_EXE_automata"))
        .args([
            "server",
            "--results-public-url",
            "https://results.example.test/",
        ])
        .env_remove("RUST_LOG")
        .output()
        .expect("server command must start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr must be UTF-8");
    assert_eq!(
        stderr.trim(),
        "Error: the automata server is unavailable on this platform pending reviewed adapters: \
         service secret custody, secure bounded-file input, static runner registration, \
         service lifecycle shutdown"
    );
}

fn assert_unsupported(arguments: &[&str], expected: &str) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("sentinel server must bind");
    listener
        .set_nonblocking(true)
        .expect("sentinel server must become nonblocking");
    let server = format!(
        "http://{}",
        listener
            .local_addr()
            .expect("sentinel server address must be available")
    );
    let arguments = arguments
        .iter()
        .map(|argument| {
            if *argument == SERVER_SENTINEL {
                server.clone()
            } else {
                (*argument).to_owned()
            }
        })
        .collect::<Vec<_>>();
    let output = Command::new(env!("CARGO_BIN_EXE_automata"))
        .args(&arguments)
        .env_remove("RUST_LOG")
        .output()
        .expect("operator command must start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let stderr = String::from_utf8(output.stderr).expect("stderr must be UTF-8");
    assert_eq!(stderr.trim(), format!("Error: {expected}"));
    assert!(!stderr.contains(&server));
    assert!(!stderr.contains(SECRET_SENTINEL));
    assert!(!stderr.contains(PATH_SENTINEL));
    assert_eq!(
        listener
            .accept()
            .expect_err("unsupported commands must not contact the server")
            .kind(),
        ErrorKind::WouldBlock
    );
}
