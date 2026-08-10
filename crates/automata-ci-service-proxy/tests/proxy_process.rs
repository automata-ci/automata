#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_automata-ci-service-proxy"))
}

fn non_loopback_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket
        .connect(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 9))
        .ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(address)
            if !address.ip().is_unspecified()
                && !address.ip().is_loopback()
                && !address.ip().is_multicast() =>
        {
            Some(*address.ip())
        }
        SocketAddr::V4(_) | SocketAddr::V6(_) => None,
    }
}

fn read_status(child: &mut Child) -> (BufReader<std::process::ChildStdout>, Vec<u16>) {
    let stdout = child.stdout.take().expect("piped stdout");
    let mut stdout = BufReader::new(stdout);
    let mut line = String::new();
    stdout.read_line(&mut line).expect("startup status");
    assert!(line.ends_with('\n'));
    let prefix = "{\"version\":1,\"ports\":[";
    let body = line
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix("]}\n"))
        .expect("strict status envelope");
    let ports = body
        .split(',')
        .map(|value| value.parse::<u16>().expect("status port"))
        .collect::<Vec<_>>();
    assert!(ports.iter().all(|port| *port != 0));
    (stdout, ports)
}

fn stop_and_assert_stdout_silent(
    child: &mut Child,
    mut stdout: BufReader<std::process::ChildStdout>,
) {
    child.kill().expect("kill proxy");
    let status = child.wait().expect("wait proxy");
    assert!(!status.success());
    let mut remainder = String::new();
    stdout
        .read_to_string(&mut remainder)
        .expect("remaining stdout");
    assert_eq!(remainder, "");
}

#[test]
fn mixed_tcp_udp_proxy_preserves_order_half_close_and_stdout_silence() {
    let Some(service_ip) = non_loopback_ipv4() else {
        return;
    };
    let tcp_backend = TcpListener::bind((service_ip, 0)).expect("TCP backend");
    let tcp_port = tcp_backend.local_addr().expect("TCP address").port();
    let tcp_server = thread::spawn(move || {
        let (mut stream, _) = tcp_backend.accept().expect("TCP accept");
        let mut request = Vec::new();
        stream.read_to_end(&mut request).expect("request EOF");
        assert_eq!(request, b"tcp-request");
        stream.write_all(b"tcp-response").expect("TCP response");
        stream.shutdown(Shutdown::Write).expect("response EOF");
    });

    let udp_backend = UdpSocket::bind((service_ip, 0)).expect("UDP backend");
    let udp_port = udp_backend.local_addr().expect("UDP address").port();
    let udp_server = thread::spawn(move || {
        let mut datagram = [0_u8; 64];
        let (length, source) = udp_backend.recv_from(&mut datagram).expect("UDP receive");
        assert_eq!(&datagram[..length], b"udp-request");
        udp_backend
            .send_to(b"udp-response", source)
            .expect("UDP response");
    });

    let mut child = binary()
        .arg("serve-v1")
        .arg(format!("udp|{service_ip}|{udp_port}|0"))
        .arg(format!("tcp|{service_ip}|{tcp_port}|0"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxy");
    let (stdout, ports) = read_status(&mut child);
    assert_eq!(ports.len(), 2);

    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP client");
    udp_client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("UDP timeout");
    udp_client
        .send_to(
            b"udp-request",
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, ports[0]),
        )
        .expect("send UDP through proxy");
    let mut datagram = [0_u8; 64];
    let (length, _) = udp_client
        .recv_from(&mut datagram)
        .expect("UDP proxy response");
    assert_eq!(&datagram[..length], b"udp-response");

    let mut tcp_client =
        TcpStream::connect((Ipv4Addr::LOCALHOST, ports[1])).expect("connect TCP through proxy");
    tcp_client
        .write_all(b"tcp-request")
        .expect("send TCP request");
    tcp_client.shutdown(Shutdown::Write).expect("request EOF");
    let mut response = Vec::new();
    tcp_client
        .read_to_end(&mut response)
        .expect("TCP response EOF");
    assert_eq!(response, b"tcp-response");

    udp_server.join().expect("UDP server");
    tcp_server.join().expect("TCP server");
    stop_and_assert_stdout_silent(&mut child, stdout);
}

#[test]
fn exact_front_port_is_honored_and_reported() {
    let Some(service_ip) = non_loopback_ipv4() else {
        return;
    };
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
    let front_port = reservation
        .local_addr()
        .expect("reservation address")
        .port();
    drop(reservation);
    let backend = TcpListener::bind((service_ip, 0)).expect("backend");
    let backend_port = backend.local_addr().expect("backend address").port();

    let mut child = binary()
        .arg("serve-v1")
        .arg(format!("tcp|{service_ip}|{backend_port}|{front_port}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxy");
    let (stdout, ports) = read_status(&mut child);
    assert_eq!(ports, vec![front_port]);
    TcpStream::connect((Ipv4Addr::LOCALHOST, front_port)).expect("exact port listens");
    assert!(
        TcpStream::connect_timeout(
            &SocketAddr::V4(SocketAddrV4::new(service_ip, front_port)),
            Duration::from_millis(250),
        )
        .is_err(),
        "front listener must not bind the non-loopback interface"
    );
    stop_and_assert_stdout_silent(&mut child, stdout);
}

#[test]
fn bind_failure_emits_no_status_and_releases_prior_bindings() {
    let Some(service_ip) = non_loopback_ipv4() else {
        return;
    };
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
    let port = reservation
        .local_addr()
        .expect("reservation address")
        .port();
    drop(reservation);
    let mapping = format!("tcp|{service_ip}|80|{port}");
    let output = binary()
        .arg("serve-v1")
        .arg(&mapping)
        .arg(&mapping)
        .stdin(Stdio::null())
        .output()
        .expect("run proxy");

    assert!(!output.status.success());
    assert_eq!(output.stdout, b"");
    assert_eq!(output.stderr, b"automata-ci-service-proxy: bind-failed\n");
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect("prior binding released");
}

#[test]
fn malformed_input_is_never_reflected_to_diagnostics() {
    let marker = "sensitive-marker-that-must-not-be-logged";
    let output = binary()
        .arg("serve-v1")
        .arg(format!("tcp|{marker}|80|0"))
        .stdin(Stdio::null())
        .output()
        .expect("run proxy");

    assert!(!output.status.success());
    assert_eq!(output.stdout, b"");
    assert_eq!(
        output.stderr,
        b"automata-ci-service-proxy: configuration-invalid\n"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
}
