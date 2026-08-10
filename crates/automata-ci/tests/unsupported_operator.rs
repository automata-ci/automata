#![cfg(not(unix))]

use std::{io::ErrorKind, net::TcpListener, process::Command};

const SERVER_SENTINEL: &str = "http://127.0.0.1:9";
const SECRET_SENTINEL: &str = "WINDOWS_SECRET_SENTINEL";
const PATH_SENTINEL: &str = "WINDOWS_PATH_SENTINEL.txt";

#[test]
fn authentication_commands_fail_before_using_operator_input() {
    for operation in ["login", "status", "logout"] {
        assert_unsupported(
            &["--server-url", SERVER_SENTINEL, "auth", operation],
            "CLI authentication is not supported on this platform",
        );
    }
}

#[test]
fn secret_commands_fail_before_using_operator_input() {
    for arguments in [
        vec![
            "--server-url",
            SERVER_SENTINEL,
            "secret",
            "list",
            "--scope",
            "repo:owner/repository",
        ],
        vec![
            "--server-url",
            SERVER_SENTINEL,
            "secret",
            "create",
            SECRET_SENTINEL,
            "--scope",
            "repo:owner/repository",
            "--from-file",
            PATH_SENTINEL,
        ],
        vec![
            "--server-url",
            SERVER_SENTINEL,
            "secret",
            "delete",
            SECRET_SENTINEL,
            "--scope",
            "repo:owner/repository",
            "--yes",
        ],
        vec![
            "--server-url",
            SERVER_SENTINEL,
            "secret",
            "provider",
            "status",
        ],
        vec![
            "--server-url",
            SERVER_SENTINEL,
            "secret",
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
