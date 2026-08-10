use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("child must be present")
    }

    fn finish(mut self) -> Child {
        self.0.take().expect("child must be present")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ignored = child.kill();
            let _ignored = child.wait();
        }
    }
}

#[test]
fn internal_probe_command_is_hidden_from_normal_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_automata-runner"))
        .arg("--help")
        .output()
        .expect("runner help must start");

    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("__probe-http-ready"));
}

#[test]
fn internal_probe_serves_one_readiness_response_then_exits() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral port must bind");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);

    let child = Command::new(env!("CARGO_BIN_EXE_automata-runner"))
        .args([
            "__probe-http-ready",
            "--port",
            &port.to_string(),
            "--token",
            TOKEN,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("internal readiness server must start");
    let mut guard = ChildGuard(Some(child));

    let response = request_when_ready(port, guard.child_mut());
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("automata-podman-network-ready\n"));

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = guard
            .child_mut()
            .try_wait()
            .expect("child status must be readable")
        {
            assert!(status.success(), "internal server failed: {status}");
            break;
        }
        assert!(Instant::now() < deadline, "internal server did not exit");
        thread::sleep(Duration::from_millis(20));
    }
    let mut child = guard.finish();
    child.wait().expect("internal server must be reaped");
}

fn request_when_ready(port: u16, child: &mut Child) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            let request = format!(
                "GET /ready/{TOKEN} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(request.as_bytes())
                .expect("request must be writable");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .expect("response must be readable");
            return response;
        }
        if let Some(status) = child.try_wait().expect("child status must be readable") {
            panic!("internal server exited before readiness: {status}");
        }
        assert!(Instant::now() < deadline, "internal server did not listen");
        thread::sleep(Duration::from_millis(20));
    }
}
