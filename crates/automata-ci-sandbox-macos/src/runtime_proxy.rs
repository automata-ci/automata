use std::{
    collections::HashMap,
    fs,
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs as _},
    num::NonZeroU16,
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use automata_ci_execution::{RuntimeServiceProtocol, RuntimeServiceRoute, RuntimeServiceRoutes};
use url::Url;

const SOCKET_NAME: &str = "runtime-proxy.sock";
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_SESSIONS: usize = 16;
const ACCEPT_POLL: Duration = Duration::from_millis(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_mins(5);

#[derive(Debug)]
pub(crate) struct RuntimeProxy {
    socket_path: PathBuf,
    shutdown: Arc<AtomicBool>,
    listener: Option<JoinHandle<()>>,
    sessions: Arc<Mutex<HashMap<usize, SessionSockets>>>,
}

#[derive(Debug)]
struct SessionSockets {
    downstream: UnixStream,
    upstream: Option<TcpStream>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestError {
    BadRequest,
    Forbidden,
    MethodNotAllowed,
}

struct ForwardRequest {
    route: RuntimeServiceRoute,
    bytes: Vec<u8>,
    established_response: bool,
}

impl RuntimeProxy {
    pub(crate) fn start(
        attempt_directory: &Path,
        routes: RuntimeServiceRoutes,
    ) -> io::Result<Self> {
        if routes.is_empty() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let socket_path = attempt_directory.join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        validate_socket(&socket_path)?;
        listener.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let next_id = Arc::new(AtomicUsize::new(1));
        let routes = Arc::new(routes);
        let listener_shutdown = Arc::clone(&shutdown);
        let listener_sessions = Arc::clone(&sessions);
        let listener_active = Arc::clone(&active);
        let listener_next_id = Arc::clone(&next_id);
        let listener_thread = thread::Builder::new()
            .name("automata-macos-runtime-proxy".to_owned())
            .spawn(move || {
                accept_loop(
                    &listener,
                    &routes,
                    &listener_shutdown,
                    &listener_sessions,
                    &listener_active,
                    &listener_next_id,
                );
            })?;

        Ok(Self {
            socket_path,
            shutdown,
            listener: Some(listener_thread),
            sessions,
        })
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub(crate) fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Ok(sessions) = self.sessions.lock() {
            for sockets in sessions.values() {
                let _ = sockets.downstream.shutdown(Shutdown::Both);
                if let Some(upstream) = sockets.upstream.as_ref() {
                    let _ = upstream.shutdown(Shutdown::Both);
                }
            }
        }
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
        let _ = fs::remove_file(&self.socket_path);
    }
}

impl Drop for RuntimeProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(
    listener: &UnixListener,
    routes: &Arc<RuntimeServiceRoutes>,
    shutdown: &Arc<AtomicBool>,
    sessions: &Arc<Mutex<HashMap<usize, SessionSockets>>>,
    active: &Arc<AtomicUsize>,
    next_id: &Arc<AtomicUsize>,
) {
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if active.fetch_add(1, Ordering::AcqRel) >= MAX_SESSIONS {
                    active.fetch_sub(1, Ordering::AcqRel);
                    let _ = write_response(&mut stream, 503, "Service Unavailable");
                    continue;
                }
                let id = next_id.fetch_add(1, Ordering::Relaxed);
                let Ok(registry_stream) = stream.try_clone() else {
                    active.fetch_sub(1, Ordering::AcqRel);
                    continue;
                };
                let Ok(mut registry) = sessions.lock() else {
                    active.fetch_sub(1, Ordering::AcqRel);
                    continue;
                };
                registry.insert(
                    id,
                    SessionSockets {
                        downstream: registry_stream,
                        upstream: None,
                    },
                );
                drop(registry);
                let routes = Arc::clone(routes);
                let shutdown = Arc::clone(shutdown);
                let sessions = Arc::clone(sessions);
                let active = Arc::clone(active);
                let _ = thread::Builder::new()
                    .name("automata-macos-runtime-proxy-session".to_owned())
                    .spawn(move || {
                        let _guard = SessionGuard {
                            id,
                            sessions: Arc::clone(&sessions),
                            active,
                        };
                        serve_session(id, &mut stream, &routes, &shutdown, &sessions);
                    });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(_) => break,
        }
    }
}

struct SessionGuard {
    id: usize,
    sessions: Arc<Mutex<HashMap<usize, SessionSockets>>>,
    active: Arc<AtomicUsize>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(&self.id);
        }
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve_session(
    id: usize,
    downstream: &mut UnixStream,
    routes: &RuntimeServiceRoutes,
    shutdown: &AtomicBool,
    sessions: &Mutex<HashMap<usize, SessionSockets>>,
) {
    if downstream.set_read_timeout(Some(HEADER_TIMEOUT)).is_err()
        || downstream.set_write_timeout(Some(HEADER_TIMEOUT)).is_err()
    {
        return;
    }
    let request = match read_request(downstream, routes) {
        Ok(request) => request,
        Err(error) => {
            let (status, reason) = match error {
                RequestError::BadRequest => (400, "Bad Request"),
                RequestError::Forbidden => (403, "Forbidden"),
                RequestError::MethodNotAllowed => (405, "Method Not Allowed"),
            };
            let _ = write_response(downstream, status, reason);
            return;
        }
    };
    if shutdown.load(Ordering::Acquire) {
        return;
    }
    let Ok(mut upstream) = connect_route(&request.route) else {
        let _ = write_response(downstream, 502, "Bad Gateway");
        return;
    };
    let Ok(registry_upstream) = upstream.try_clone() else {
        return;
    };
    let Ok(mut registry) = sessions.lock() else {
        return;
    };
    let Some(session) = registry.get_mut(&id) else {
        return;
    };
    session.upstream = Some(registry_upstream);
    drop(registry);
    if shutdown.load(Ordering::Acquire) {
        return;
    }
    if request.established_response
        && downstream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
    {
        return;
    }
    if !request.bytes.is_empty() && upstream.write_all(&request.bytes).is_err() {
        return;
    }
    let _ = downstream.set_read_timeout(Some(RELAY_IDLE_TIMEOUT));
    let _ = downstream.set_write_timeout(Some(RELAY_IDLE_TIMEOUT));
    let _ = upstream.set_read_timeout(Some(RELAY_IDLE_TIMEOUT));
    let _ = upstream.set_write_timeout(Some(RELAY_IDLE_TIMEOUT));
    relay(downstream, &mut upstream);
}

fn read_request(
    stream: &mut UnixStream,
    routes: &RuntimeServiceRoutes,
) -> Result<ForwardRequest, RequestError> {
    let mut bytes = Vec::with_capacity(1024);
    let header_end = loop {
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err(RequestError::BadRequest);
        }
        let remaining = MAX_HEADER_BYTES - bytes.len();
        let mut chunk = [0_u8; 4096];
        let length = remaining.min(chunk.len());
        let count = stream
            .read(&mut chunk[..length])
            .map_err(|_| RequestError::BadRequest)?;
        if count == 0 {
            return Err(RequestError::BadRequest);
        }
        bytes.extend_from_slice(&chunk[..count]);
    };

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers);
    match parsed
        .parse(&bytes[..header_end])
        .map_err(|_| RequestError::BadRequest)?
    {
        httparse::Status::Complete(consumed) if consumed == header_end => {}
        _ => return Err(RequestError::BadRequest),
    }
    if parsed.version != Some(1) {
        return Err(RequestError::BadRequest);
    }
    let method = parsed.method.ok_or(RequestError::BadRequest)?;
    let target = parsed.path.ok_or(RequestError::BadRequest)?;
    if method == "CONNECT" {
        return connect_request(target, &bytes[header_end..], routes);
    }
    http_request(method, target, parsed.headers, &bytes[header_end..], routes)
}

fn connect_request(
    target: &str,
    trailing: &[u8],
    routes: &RuntimeServiceRoutes,
) -> Result<ForwardRequest, RequestError> {
    let (host, port) = explicit_authority(target).ok_or(RequestError::BadRequest)?;
    let route = route_from_parts(RuntimeServiceProtocol::Https, &host, port)
        .ok_or(RequestError::BadRequest)?;
    require_route(routes, &route)?;
    Ok(ForwardRequest {
        route,
        bytes: trailing.to_vec(),
        established_response: true,
    })
}

fn http_request(
    method: &str,
    target: &str,
    headers: &[httparse::Header<'_>],
    trailing: &[u8],
    routes: &RuntimeServiceRoutes,
) -> Result<ForwardRequest, RequestError> {
    let url = Url::parse(target).map_err(|_| RequestError::BadRequest)?;
    if url.fragment().is_some() {
        return Err(RequestError::BadRequest);
    }
    let route = RuntimeServiceRoute::from_url(&url).map_err(|_| RequestError::BadRequest)?;
    if route.protocol() != RuntimeServiceProtocol::Http {
        return Err(RequestError::MethodNotAllowed);
    }
    require_route(routes, &route)?;
    let host = single_host_header(headers).ok_or(RequestError::BadRequest)?;
    let header_route = route_from_authority(RuntimeServiceProtocol::Http, host, 80)
        .ok_or(RequestError::BadRequest)?;
    if header_route != route {
        return Err(RequestError::Forbidden);
    }

    let mut origin = if url.path().is_empty() {
        "/".to_owned()
    } else {
        url.path().to_owned()
    };
    if let Some(query) = url.query() {
        origin.push('?');
        origin.push_str(query);
    }
    let mut rewritten = Vec::with_capacity(MAX_HEADER_BYTES + trailing.len());
    write!(&mut rewritten, "{method} {origin} HTTP/1.1\r\n")
        .map_err(|_| RequestError::BadRequest)?;
    for header in headers {
        if header.name.eq_ignore_ascii_case("proxy-connection")
            || header.name.eq_ignore_ascii_case("proxy-authorization")
        {
            continue;
        }
        rewritten.extend_from_slice(header.name.as_bytes());
        rewritten.extend_from_slice(b": ");
        rewritten.extend_from_slice(header.value);
        rewritten.extend_from_slice(b"\r\n");
    }
    rewritten.extend_from_slice(b"\r\n");
    rewritten.extend_from_slice(trailing);
    Ok(ForwardRequest {
        route,
        bytes: rewritten,
        established_response: false,
    })
}

fn single_host_header<'a>(headers: &'a [httparse::Header<'a>]) -> Option<&'a str> {
    let mut values = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"));
    let first = std::str::from_utf8(values.next()?.value).ok()?.trim();
    if first.is_empty() || values.next().is_some() {
        None
    } else {
        Some(first)
    }
}

fn require_route(
    routes: &RuntimeServiceRoutes,
    route: &RuntimeServiceRoute,
) -> Result<(), RequestError> {
    routes
        .as_slice()
        .contains(route)
        .then_some(())
        .ok_or(RequestError::Forbidden)
}

fn explicit_authority(authority: &str) -> Option<(String, NonZeroU16)> {
    if authority.contains(['@', '/', '?', '#']) {
        return None;
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let port = rest[close + 1..].strip_prefix(':')?;
        (host, port)
    } else {
        authority.rsplit_once(':')?
    };
    let port = port.parse::<u16>().ok().and_then(NonZeroU16::new)?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_owned(), port))
}

fn route_from_authority(
    protocol: RuntimeServiceProtocol,
    authority: &str,
    default_port: u16,
) -> Option<RuntimeServiceRoute> {
    let scheme = scheme(protocol);
    let url = Url::parse(&format!("{scheme}://{authority}/")).ok()?;
    let route = RuntimeServiceRoute::from_url(&url).ok()?;
    if url.port().is_none() && route.port().get() != default_port {
        return None;
    }
    Some(route)
}

fn route_from_parts(
    protocol: RuntimeServiceProtocol,
    host: &str,
    port: NonZeroU16,
) -> Option<RuntimeServiceRoute> {
    let authority = match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    };
    route_from_authority(protocol, &authority, port.get())
}

const fn scheme(protocol: RuntimeServiceProtocol) -> &'static str {
    match protocol {
        RuntimeServiceProtocol::Http => "http",
        RuntimeServiceProtocol::Https => "https",
    }
}

fn connect_route(route: &RuntimeServiceRoute) -> io::Result<TcpStream> {
    let addresses: Vec<SocketAddr> = (route.host(), route.port().get())
        .to_socket_addrs()?
        .collect();
    if addresses.is_empty() {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::from(io::ErrorKind::ConnectionRefused)))
}

fn relay(downstream: &mut UnixStream, upstream: &mut TcpStream) {
    let Ok(mut downstream_reader) = downstream.try_clone() else {
        return;
    };
    let Ok(mut upstream_writer) = upstream.try_clone() else {
        return;
    };
    thread::scope(|scope| {
        let upload = scope.spawn(move || {
            let _ = io::copy(&mut downstream_reader, &mut upstream_writer);
            let _ = upstream_writer.shutdown(Shutdown::Write);
        });
        let _ = io::copy(upstream, downstream);
        let _ = downstream.shutdown(Shutdown::Write);
        let _ = downstream.shutdown(Shutdown::Read);
        let _ = upload.join();
    });
}

fn write_response(stream: &mut UnixStream, status: u16, reason: &str) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    )
}

fn validate_socket(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        io::{Read, Write},
        net::{Shutdown, TcpListener},
        os::unix::{fs::PermissionsExt as _, net::UnixStream},
        path::{Path, PathBuf},
        process::{Child, Command, ExitStatus, Stdio},
        thread,
    };

    use automata_ci_execution::{OperationId, RuntimeServiceRoute, RuntimeServiceRoutes};
    use automata_ci_sandbox_guest::{
        GUEST_PROTOCOL_VERSION, GuestRequest, GuestResponse, GuestTermination, decode_frame,
        encode_frame,
    };
    use serde_json::{Value, json};
    use url::Url;

    use super::RuntimeProxy;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = Path::new("/tmp").join(format!("automata-proxy-{}", OperationId::new()));
            fs::create_dir(&path).expect("create test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn connect_relays_only_an_exact_allowed_tls_origin() {
        let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let port = upstream.local_addr().expect("upstream address").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().expect("accept upstream");
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).expect("read relayed bytes");
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").expect("write relayed bytes");
        });
        let directory = TestDirectory::new();
        let mut proxy = RuntimeProxy::start(
            directory.path(),
            routes(&format!("https://127.0.0.1:{port}/")),
        )
        .expect("start proxy");
        let metadata = fs::symlink_metadata(proxy.socket_path()).expect("socket metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        let mut client = UnixStream::connect(proxy.socket_path()).expect("connect proxy");
        write!(
            client,
            "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\nping"
        )
        .expect("send CONNECT");
        assert_eq!(
            read_header(&mut client),
            "HTTP/1.1 200 Connection Established\r\n\r\n"
        );
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).expect("read tunnel bytes");
        assert_eq!(&response, b"pong");
        let _ = client.shutdown(Shutdown::Both);
        server.join().expect("join upstream");
        proxy.stop();
        assert!(!proxy.socket_path().exists());
    }

    #[test]
    fn connect_rejects_an_origin_outside_the_route_set() {
        let directory = TestDirectory::new();
        let proxy = RuntimeProxy::start(directory.path(), routes("https://127.0.0.1:443/"))
            .expect("start proxy");
        let mut client = UnixStream::connect(proxy.socket_path()).expect("connect proxy");
        client
            .write_all(b"CONNECT 127.0.0.1:444 HTTP/1.1\r\nHost: 127.0.0.1:444\r\n\r\n")
            .expect("send CONNECT");
        assert!(read_header(&mut client).starts_with("HTTP/1.1 403 Forbidden\r\n"));
    }

    #[test]
    fn plain_http_is_rewritten_to_origin_form_and_proxy_headers_are_removed() {
        let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let port = upstream.local_addr().expect("upstream address").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().expect("accept upstream");
            let request = read_header(&mut stream);
            assert!(request.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
            assert!(request.contains(&format!("Host: 127.0.0.1:{port}\r\n")));
            assert!(!request.to_ascii_lowercase().contains("proxy-connection"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write response");
        });
        let directory = TestDirectory::new();
        let proxy = RuntimeProxy::start(
            directory.path(),
            routes(&format!("http://127.0.0.1:{port}/")),
        )
        .expect("start proxy");
        let mut client = UnixStream::connect(proxy.socket_path()).expect("connect proxy");
        write!(
            client,
            "GET http://127.0.0.1:{port}/path?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nProxy-Connection: keep-alive\r\n\r\n"
        )
        .expect("send request");
        client
            .shutdown(Shutdown::Write)
            .expect("finish proxy request");
        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .expect("read proxy response");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("\r\n\r\nok"));
        server.join().expect("join upstream");
    }

    #[test]
    fn plain_http_rejects_a_mismatched_host_header() {
        let directory = TestDirectory::new();
        let proxy = RuntimeProxy::start(directory.path(), routes("http://127.0.0.1:8080/"))
            .expect("start proxy");
        let mut client = UnixStream::connect(proxy.socket_path()).expect("connect proxy");
        client
            .write_all(b"GET http://127.0.0.1:8080/ HTTP/1.1\r\nHost: 127.0.0.1:8081\r\n\r\n")
            .expect("send request");
        assert!(read_header(&mut client).starts_with("HTTP/1.1 403 Forbidden\r\n"));
    }

    #[test]
    #[ignore = "requires the dedicated physical macOS VM test host"]
    fn physical_guest_reaches_an_allowlisted_origin_through_the_vsock_proxy() {
        let helper = required_path("AUTOMATA_MACOS_PHYSICAL_HELPER");
        let manifest_path = required_path("AUTOMATA_MACOS_PHYSICAL_MANIFEST");
        let attempt_root = required_path("AUTOMATA_MACOS_PHYSICAL_ATTEMPT_ROOT");
        let manifest: Value = serde_json::from_slice(
            &fs::read(&manifest_path).expect("read physical template manifest"),
        )
        .expect("decode physical template manifest");
        let attempt = attempt_root.join(format!("p-{}", OperationId::new()));
        fs::create_dir(&attempt).expect("create physical attempt directory");
        fs::set_permissions(&attempt, fs::Permissions::from_mode(0o700))
            .expect("secure physical attempt directory");
        let _attempt_cleanup = AttemptCleanup(attempt.clone());

        let (port, server) = physical_upstream();
        let mut proxy = RuntimeProxy::start(&attempt, routes(&format!("http://127.0.0.1:{port}/")))
            .expect("start physical runtime proxy");

        let launch = physical_launch_request(&manifest, &attempt, &proxy);
        let child = Command::new(helper)
            .args(["run", "--lock"])
            .arg(attempt.join(".vm.lock"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("launch physical helper");
        let mut child = PhysicalHelper(Some(child));
        let mut input = child.child().stdin.take().expect("physical helper input");
        let mut output = child.child().stdout.take().expect("physical helper output");
        write_json_frame(&mut input, &launch);
        let response = match read_json_frame(&mut output) {
            Ok(response) => response,
            Err(error) => {
                drop(input);
                let status = child.wait().expect("wait for failed physical helper");
                panic!("physical helper closed before launch response ({status}): {error}");
            }
        };
        assert_eq!(response, json!({"protocol": 2, "status": "ready"}));

        let environment = BTreeMap::from([
            ("http_proxy".to_owned(), "http://127.0.0.1:18081".to_owned()),
            ("no_proxy".to_owned(), String::new()),
        ]);
        let request = GuestRequest::Exec {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OperationId::new().to_string(),
            program: "/usr/bin/curl".to_owned(),
            arguments: vec![
                "--fail".to_owned(),
                "--silent".to_owned(),
                "--show-error".to_owned(),
                "--max-time".to_owned(),
                "20".to_owned(),
                format!("http://127.0.0.1:{port}/probe"),
            ],
            environment,
            working_directory: "/".to_owned(),
            timeout_millis: 30_000,
            output_limit: 16 * 1024,
            process_limit: None,
        };
        input
            .write_all(&encode_frame(&request).expect("encode physical guest request"))
            .expect("send physical guest request");
        input.flush().expect("flush physical guest request");
        let response: GuestResponse =
            decode_frame(&read_binary_frame(&mut output)).expect("decode physical guest response");
        let GuestResponse::Exec {
            termination,
            records,
            truncated,
            ..
        } = response
        else {
            panic!("physical guest rejected proxy request")
        };
        let output = records
            .iter()
            .filter_map(|record| record.data().ok())
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(
            termination,
            GuestTermination::Exited(0),
            "physical guest curl output: {}",
            String::from_utf8_lossy(&output)
        );
        assert!(!truncated);
        assert_eq!(output, b"macos-runtime-proxy-ok");
        server.join().expect("join physical upstream");
        drop(input);
        assert!(child.wait().expect("stop physical helper").success());
        proxy.stop();
    }

    fn routes(url: &str) -> RuntimeServiceRoutes {
        RuntimeServiceRoutes::new([RuntimeServiceRoute::from_url(
            &Url::parse(url).expect("route URL"),
        )
        .expect("runtime route")])
        .expect("runtime routes")
    }

    fn read_header(reader: &mut impl Read) -> String {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            reader.read_exact(&mut byte).expect("read header byte");
            bytes.push(byte[0]);
            assert!(bytes.len() < 16 * 1024);
        }
        String::from_utf8(bytes).expect("ASCII HTTP header")
    }

    struct AttemptCleanup(PathBuf);

    impl Drop for AttemptCleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct PhysicalHelper(Option<Child>);

    impl PhysicalHelper {
        fn child(&mut self) -> &mut Child {
            self.0.as_mut().expect("physical helper process")
        }

        fn wait(&mut self) -> std::io::Result<ExitStatus> {
            let mut child = self.0.take().expect("physical helper process");
            child.wait()
        }
    }

    impl Drop for PhysicalHelper {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn required_path(name: &str) -> PathBuf {
        std::env::var_os(name).map_or_else(
            || panic!("{name} must name a physical-host path"),
            PathBuf::from,
        )
    }

    fn physical_launch_request(manifest: &Value, attempt: &Path, proxy: &RuntimeProxy) -> Value {
        let attempt_id = attempt
            .file_name()
            .and_then(|name| name.to_str())
            .expect("physical attempt name");
        json!({
            "protocol": 2,
            "attempt_id": attempt_id,
            "source_disk_image": manifest_string(manifest, "disk_image", Some("path")),
            "source_auxiliary_storage": manifest_string(manifest, "auxiliary_storage", Some("path")),
            "attempt_directory": attempt,
            "hardware_model_base64": manifest_string(manifest, "hardware_model_base64", None),
            "cpu_count": 4,
            "memory_bytes": 8_u64 * 1024 * 1024 * 1024,
            "process_limit": manifest_u64(manifest, "process_limit"),
            "guest_port": manifest_u64(manifest, "guest_port"),
            "guest_protocol": manifest_u64(manifest, "guest_protocol"),
            "expected_profile_id": manifest_string(manifest, "profile_id", None),
            "guest_agent_sha256": manifest_string(manifest, "guest_agent_sha256", None),
            "expected_macos_version": manifest_string(manifest, "macos_version", None),
            "expected_macos_build": manifest_string(manifest, "macos_build", None),
            "expected_architecture": manifest_string(manifest, "architecture", None),
            "expected_job_uid": manifest_u64(manifest, "job_uid"),
            "expected_job_gid": manifest_u64(manifest, "job_gid"),
            "expected_process_limit": manifest_u64(manifest, "process_limit"),
            "minimum_cpu_count": manifest_u64(manifest, "minimum_cpu_count"),
            "minimum_memory_bytes": manifest_u64(manifest, "minimum_memory_bytes"),
            "handshake_nonce": OperationId::new().to_string(),
            "boot_timeout_millis": 300_000,
            "stop_timeout_millis": 10_000,
            "runtime_proxy_socket": proxy.socket_path(),
        })
    }

    fn physical_upstream() -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind physical upstream");
        let port = listener
            .local_addr()
            .expect("physical upstream address")
            .port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept physical upstream");
            let request = read_header(&mut stream);
            assert!(request.starts_with("GET /probe HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 22\r\nConnection: close\r\n\r\nmacos-runtime-proxy-ok",
                )
                .expect("write physical upstream response");
        });
        (port, server)
    }

    fn manifest_string<'a>(manifest: &'a Value, field: &str, nested: Option<&str>) -> &'a str {
        let value = nested.map_or(&manifest[field], |nested| &manifest[field][nested]);
        value
            .as_str()
            .unwrap_or_else(|| panic!("manifest field {field} must be a string"))
    }

    fn manifest_u64(manifest: &Value, field: &str) -> u64 {
        manifest[field]
            .as_u64()
            .unwrap_or_else(|| panic!("manifest field {field} must be an unsigned integer"))
    }

    fn write_json_frame(writer: &mut impl Write, value: &Value) {
        let bytes = serde_json::to_vec(value).expect("encode physical helper request");
        let length = u32::try_from(bytes.len()).expect("physical helper request length");
        writer
            .write_all(&length.to_be_bytes())
            .and_then(|()| writer.write_all(&bytes))
            .and_then(|()| writer.flush())
            .expect("send physical helper request");
    }

    fn read_json_frame(reader: &mut impl Read) -> std::io::Result<Value> {
        serde_json::from_slice(&read_binary_payload_result(reader)?).map_err(std::io::Error::other)
    }

    fn read_binary_frame(reader: &mut impl Read) -> Vec<u8> {
        let payload = read_binary_payload(reader);
        let length = u32::try_from(payload.len()).expect("physical response length");
        let mut frame = length.to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame
    }

    fn read_binary_payload(reader: &mut impl Read) -> Vec<u8> {
        read_binary_payload_result(reader).expect("read frame")
    }

    fn read_binary_payload_result(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
        let mut header = [0_u8; 4];
        reader.read_exact(&mut header)?;
        let length = usize::try_from(u32::from_be_bytes(header)).expect("frame length");
        let mut payload = vec![0_u8; length];
        reader.read_exact(&mut payload)?;
        Ok(payload)
    }
}
