#![cfg(unix)]

use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("child must still be running")
    }

    fn finish(mut self) -> Child {
        self.0.take().expect("child must still be present")
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
fn sigterm_triggers_a_clean_shutdown() {
    let address = unused_loopback_address();
    let child = Command::new(env!("CARGO_BIN_EXE_automata"))
        .args(["server", "--listen", &address.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("server must start");
    let mut guard = ChildGuard(Some(child));

    wait_until_listening(address, guard.child_mut());
    let signal_status = Command::new("kill")
        .args(["-TERM", &guard.child_mut().id().to_string()])
        .status()
        .expect("kill command must run");
    assert!(signal_status.success(), "SIGTERM must be delivered");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = guard
            .child_mut()
            .try_wait()
            .expect("server status must be readable")
        {
            assert!(status.success(), "server exited unsuccessfully: {status}");
            break;
        }
        assert!(Instant::now() < deadline, "server ignored SIGTERM");
        thread::sleep(Duration::from_millis(20));
    }

    let mut child = guard.finish();
    child.wait().expect("server must be reaped");
}

fn unused_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral port must bind");
    listener.local_addr().expect("bound address must exist")
}

fn wait_until_listening(address: SocketAddr, child: &mut Child) {
    // A cold debug build compiles the embedded WebAssembly component before
    // binding the listener, which can take several seconds on small runners.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if TcpStream::connect(address).is_ok() {
            return;
        }
        if let Some(status) = child.try_wait().expect("server status must be readable") {
            panic!("server exited before listening: {status}");
        }
        assert!(Instant::now() < deadline, "server did not start listening");
        thread::sleep(Duration::from_millis(20));
    }
}
