use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::{self, Read as _, Write as _},
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use automata_execution::{ResourceLimits, SandboxHandle};
use serde_json::{Map, Value, json};

use crate::{
    PodmanConfigurationError, PodmanOptions, command::PersistentPodmanProcess,
    state::JobEnginePaths,
};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_CONTROL_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_BUILD_CONTEXT_BYTES: u64 = 512 * 1024 * 1024;
const BACKEND_START_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const BACKEND_IDLE_SECONDS: &str = "0";
const PUBLIC_SOCKET_MODE: u32 = 0o600;
const MAX_CONNECTION_WORKERS: usize = 64;

pub(crate) const DOCKER_SOCKET_DIRECTORY_TARGET: &str = "/run/automata-engine";

#[derive(Debug)]
pub(crate) struct JobDockerListener(UnixListener);

#[derive(Debug)]
pub(crate) struct JobDockerService {
    stop: Arc<AtomicBool>,
    accept_worker: Option<thread::JoinHandle<()>>,
    connections: Arc<Mutex<Vec<ConnectionWorker>>>,
    backend: PersistentPodmanProcess,
}

#[derive(Debug)]
struct ConnectionWorker {
    control: UnixStream,
    worker: thread::JoinHandle<()>,
}

impl JobDockerService {
    pub(crate) fn start(
        options: &PodmanOptions,
        paths: &JobEnginePaths,
        listener: JobDockerListener,
        sandbox: &SandboxHandle,
        outer_process_id: u32,
        outer_cgroup: String,
        resources: ResourceLimits,
    ) -> Result<Self, PodmanConfigurationError> {
        prepare_socket_path(paths.backend_socket())?;
        let backend_uri = format!("unix://{}", paths.backend_socket().display());
        let arguments = vec![
            OsString::from("--remote=false"),
            format!(
                "--hooks-dir={}",
                options.state_root().as_path().join("empty-hooks").display()
            )
            .into(),
            format!("--root={}", paths.graph_root().display()).into(),
            format!("--runroot={}", paths.run_root().display()).into(),
            OsString::from("--storage-driver=vfs"),
            OsString::from("--cgroup-manager=cgroupfs"),
            OsString::from("system"),
            OsString::from("service"),
            OsString::from("--time"),
            OsString::from(BACKEND_IDLE_SECONDS),
            OsString::from(backend_uri),
        ];
        let mut backend = PersistentPodmanProcess::spawn(
            options.binary().as_path(),
            &arguments,
            options.process_environment(),
        )
        .map_err(|()| PodmanConfigurationError::JobEngineUnavailable)?;
        wait_for_backend(paths.backend_socket(), &mut backend)?;

        let policy = Arc::new(ProxyPolicy::new(
            sandbox,
            outer_process_id,
            outer_cgroup,
            resources,
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let connections = Arc::new(Mutex::new(Vec::new()));
        let worker_connections = Arc::clone(&connections);
        let backend_socket = paths.backend_socket().to_path_buf();
        let accept_worker = thread::Builder::new()
            .name("automata-job-docker-api".to_owned())
            .spawn(move || {
                serve(
                    &listener.0,
                    &backend_socket,
                    &policy,
                    &worker_stop,
                    &worker_connections,
                );
            })
            .map_err(|_| PodmanConfigurationError::JobEngineUnavailable)?;
        Ok(Self {
            stop,
            accept_worker: Some(accept_worker),
            connections,
            backend,
        })
    }

    pub(crate) fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.backend.stop();
        if let Some(worker) = self.accept_worker.take() {
            let _ignored = worker.join();
        }
        let workers = self
            .connections
            .lock()
            .map(|mut workers| workers.drain(..).collect::<Vec<_>>())
            .unwrap_or_default();
        for worker in &workers {
            let _ignored = worker.control.shutdown(std::net::Shutdown::Both);
        }
        for worker in workers {
            let _ignored = worker.worker.join();
        }
    }
}

pub(crate) fn bind_public_socket(
    path: &Path,
) -> Result<JobDockerListener, PodmanConfigurationError> {
    prepare_socket_path(path)?;
    let listener =
        UnixListener::bind(path).map_err(|_| PodmanConfigurationError::JobEngineUnavailable)?;
    fs::set_permissions(path, fs::Permissions::from_mode(PUBLIC_SOCKET_MODE))
        .map_err(|_| PodmanConfigurationError::JobEngineUnavailable)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| PodmanConfigurationError::JobEngineUnavailable)?;
    Ok(JobDockerListener(listener))
}

impl Drop for JobDockerService {
    fn drop(&mut self) {
        self.stop();
    }
}

fn wait_for_backend(
    socket: &Path,
    backend: &mut PersistentPodmanProcess,
) -> Result<(), PodmanConfigurationError> {
    let deadline = Instant::now() + BACKEND_START_TIMEOUT;
    loop {
        if UnixStream::connect(socket).is_ok() {
            return Ok(());
        }
        if backend.has_exited().unwrap_or(true) || Instant::now() >= deadline {
            return Err(PodmanConfigurationError::JobEngineUnavailable);
        }
        thread::sleep(ACCEPT_POLL_INTERVAL);
    }
}

fn prepare_socket_path(path: &Path) -> Result<(), PodmanConfigurationError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(PodmanConfigurationError::JobEngineUnavailable),
    };
    if !metadata.file_type().is_socket() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(PodmanConfigurationError::JobEngineUnavailable);
    }
    fs::remove_file(path).map_err(|_| PodmanConfigurationError::JobEngineUnavailable)
}

fn serve(
    listener: &UnixListener,
    backend_socket: &Path,
    policy: &Arc<ProxyPolicy>,
    stop: &AtomicBool,
    connections: &Mutex<Vec<ConnectionWorker>>,
) {
    while !stop.load(Ordering::Acquire) {
        if reap_finished_connections(connections).is_err() {
            break;
        }
        match listener.accept() {
            Ok((mut client, _address)) => {
                let at_capacity = connections
                    .lock()
                    .map_or(true, |workers| workers.len() >= MAX_CONNECTION_WORKERS);
                if at_capacity {
                    let _ignored =
                        send_rejection(&mut client, 503, "Docker API connection limit reached");
                    continue;
                }
                let Ok(control) = client.try_clone() else {
                    continue;
                };
                let backend_socket = backend_socket.to_path_buf();
                let policy = Arc::clone(policy);
                let Ok(worker) = thread::Builder::new()
                    .name("automata-job-docker-request".to_owned())
                    .spawn(move || {
                        let _ignored = handle_connection(client, &backend_socket, &policy);
                    })
                else {
                    continue;
                };
                let connection = ConnectionWorker { control, worker };
                if let Ok(mut workers) = connections.lock() {
                    workers.push(connection);
                } else {
                    let _ignored = connection.control.shutdown(std::net::Shutdown::Both);
                    let _ignored = connection.worker.join();
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

fn reap_finished_connections(connections: &Mutex<Vec<ConnectionWorker>>) -> Result<(), ()> {
    let finished = {
        let mut workers = connections.lock().map_err(|_| ())?;
        let mut finished = Vec::new();
        let mut index = 0;
        while index < workers.len() {
            if workers[index].worker.is_finished() {
                finished.push(workers.swap_remove(index));
            } else {
                index += 1;
            }
        }
        finished
    };
    for worker in finished {
        let _ignored = worker.worker.join();
    }
    Ok(())
}

#[derive(Debug)]
struct ProxyPolicy {
    owner_labels: Map<String, Value>,
    network_namespace: String,
    cgroup_parent: String,
    resources: ResourceLimits,
    ports: Mutex<BTreeMap<String, BTreeMap<String, PublishedPort>>>,
}

impl ProxyPolicy {
    fn new(
        sandbox: &SandboxHandle,
        outer_process_id: u32,
        cgroup_parent: String,
        resources: ResourceLimits,
    ) -> Self {
        let mut owner_labels = Map::new();
        owner_labels.insert(
            "io.automata.owner".to_owned(),
            Value::String("automata-runner".to_owned()),
        );
        owner_labels.insert(
            "io.automata.job-engine".to_owned(),
            Value::String(sandbox.opaque().to_owned()),
        );
        Self {
            owner_labels,
            network_namespace: format!("ns:/proc/{outer_process_id}/ns/net"),
            cgroup_parent,
            resources,
            ports: Mutex::new(BTreeMap::new()),
        }
    }

    fn authorize(&self, method: &str, target: &str, body: &[u8]) -> Result<AuthorizedRequest, ()> {
        let route = DockerRoute::parse(method, target)?;
        match route {
            DockerRoute::Build => {
                let target = self.rewrite_build_target(target)?;
                Ok(AuthorizedRequest::passthrough(target, body.to_vec()))
            }
            DockerRoute::ContainerCreate { name } => {
                let (body, ports) = self.rewrite_container_create(body)?;
                Ok(AuthorizedRequest {
                    target: target.to_owned(),
                    body,
                    response: ResponseTransform::RecordContainer { name, ports },
                })
            }
            DockerRoute::ContainerInspect { identifier } => Ok(AuthorizedRequest {
                target: target.to_owned(),
                body: body.to_vec(),
                response: ResponseTransform::RewriteInspect { identifier },
            }),
            DockerRoute::Ping
            | DockerRoute::Version
            | DockerRoute::ImageInspect
            | DockerRoute::ImageDelete
            | DockerRoute::ContainerOperation => Ok(AuthorizedRequest::passthrough(
                target.to_owned(),
                body.to_vec(),
            )),
        }
    }

    fn rewrite_build_target(&self, target: &str) -> Result<String, ()> {
        let separator = if target.contains('?') { '&' } else { '?' };
        let query = target.split_once('?').map_or("", |(_, query)| query);
        if query_parameters(query).any(|(name, _)| {
            matches!(
                name,
                "labels"
                    | "remote"
                    | "networkmode"
                    | "cgroupparent"
                    | "memory"
                    | "cpuperiod"
                    | "cpuquota"
            )
        }) {
            return Err(());
        }
        let labels = serde_json::to_string(&self.owner_labels).map_err(|_| ())?;
        let cpu_period = 100_000_u64;
        let cpu_quota = u64::from(self.resources.cpu_millis())
            .checked_mul(cpu_period)
            .ok_or(())?
            / 1_000;
        Ok(format!(
            "{target}{separator}labels={}&memory={}&cpuperiod={cpu_period}&cpuquota={cpu_quota}&cgroupparent={}",
            percent_encode(&labels),
            self.resources.memory_bytes(),
            percent_encode(&self.cgroup_parent),
        ))
    }

    fn rewrite_container_create(
        &self,
        body: &[u8],
    ) -> Result<(Vec<u8>, BTreeMap<String, PublishedPort>), ()> {
        let mut document: Value = serde_json::from_slice(body).map_err(|_| ())?;
        let object = document.as_object_mut().ok_or(())?;
        reject_nonempty(object, "Volumes")?;
        let labels = object
            .entry("Labels")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or(())?;
        for (name, value) in &self.owner_labels {
            if labels.contains_key(name) {
                return Err(());
            }
            labels.insert(name.clone(), value.clone());
        }

        let host = object
            .entry("HostConfig")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or(())?;
        for field in [
            "Binds",
            "Mounts",
            "Devices",
            "DeviceRequests",
            "CapAdd",
            "VolumesFrom",
            "Links",
            "GroupAdd",
            "Sysctls",
            "Tmpfs",
            "SecurityOpt",
            "MaskedPaths",
            "ReadonlyPaths",
        ] {
            reject_nonempty(host, field)?;
        }
        reject_true(host, "Privileged")?;
        for field in [
            "PidMode",
            "IpcMode",
            "UTSMode",
            "UsernsMode",
            "CgroupnsMode",
            "CgroupParent",
            "Runtime",
            "Isolation",
        ] {
            reject_nonempty(host, field)?;
        }
        if let Some(network) = host.get("NetworkMode").and_then(Value::as_str)
            && !matches!(network, "" | "default" | "bridge")
        {
            return Err(());
        }

        let ports = parse_port_bindings(host.remove("PortBindings"))?;
        host.insert(
            "NetworkMode".to_owned(),
            Value::String(self.network_namespace.clone()),
        );
        host.insert(
            "CgroupParent".to_owned(),
            Value::String(self.cgroup_parent.clone()),
        );
        host.insert("ReadonlyRootfs".to_owned(), Value::Bool(true));
        host.insert("CapDrop".to_owned(), json!(["ALL"]));
        host.insert("SecurityOpt".to_owned(), json!(["no-new-privileges"]));
        host.insert("PublishAllPorts".to_owned(), Value::Bool(false));
        serde_json::to_vec(&document)
            .map(|body| (body, ports))
            .map_err(|_| ())
    }

    fn record_container(
        &self,
        name: Option<String>,
        identifier: &str,
        ports: BTreeMap<String, PublishedPort>,
    ) -> Result<(), ()> {
        let mut mappings = self.ports.lock().map_err(|_| ())?;
        mappings.insert(identifier.to_owned(), ports.clone());
        if identifier.len() >= 12 {
            mappings.insert(identifier[..12].to_owned(), ports.clone());
        }
        if let Some(name) = name {
            mappings.insert(name, ports);
        }
        Ok(())
    }

    fn rewrite_inspect(&self, identifier: &str, body: &[u8]) -> Result<Vec<u8>, ()> {
        let ports = self.ports.lock().map_err(|_| ())?.get(identifier).cloned();
        let Some(ports) = ports else {
            return Ok(body.to_vec());
        };
        let mut document: Value = serde_json::from_slice(body).map_err(|_| ())?;
        let object = document.as_object_mut().ok_or(())?;
        let network = object
            .entry("NetworkSettings")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or(())?;
        let exposed = ports
            .into_iter()
            .map(|(container, published)| {
                (
                    container,
                    json!([{
                        "HostIp": "127.0.0.1",
                        "HostPort": published.host_port.to_string(),
                    }]),
                )
            })
            .collect();
        network.insert("Ports".to_owned(), Value::Object(exposed));
        serde_json::to_vec(&document).map_err(|_| ())
    }
}

#[derive(Debug)]
struct AuthorizedRequest {
    target: String,
    body: Vec<u8>,
    response: ResponseTransform,
}

impl AuthorizedRequest {
    fn passthrough(target: String, body: Vec<u8>) -> Self {
        Self {
            target,
            body,
            response: ResponseTransform::Passthrough,
        }
    }
}

#[derive(Debug)]
enum ResponseTransform {
    Passthrough,
    RecordContainer {
        name: Option<String>,
        ports: BTreeMap<String, PublishedPort>,
    },
    RewriteInspect {
        identifier: String,
    },
}

#[derive(Clone, Copy, Debug)]
struct PublishedPort {
    host_port: u16,
}

#[derive(Debug)]
enum DockerRoute {
    Ping,
    Version,
    Build,
    ImageInspect,
    ImageDelete,
    ContainerCreate { name: Option<String> },
    ContainerInspect { identifier: String },
    ContainerOperation,
}

impl DockerRoute {
    fn parse(method: &str, target: &str) -> Result<Self, ()> {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let path = strip_api_version(path)?;
        match (method, path) {
            ("HEAD" | "GET", "/_ping") => Ok(Self::Ping),
            ("GET", "/version") => Ok(Self::Version),
            ("POST", "/build") => Ok(Self::Build),
            ("POST", "/containers/create") => Ok(Self::ContainerCreate {
                name: query_parameters(query)
                    .find(|(name, _)| *name == "name")
                    .map(|(_, value)| percent_decode(value))
                    .transpose()?,
            }),
            _ => parse_object_route(method, path),
        }
    }
}

fn parse_object_route(method: &str, path: &str) -> Result<DockerRoute, ()> {
    let components = path.split('/').collect::<Vec<_>>();
    match components.as_slice() {
        ["", "images", identifier, "json"] if method == "GET" && valid_object(identifier) => {
            Ok(DockerRoute::ImageInspect)
        }
        ["", "images", identifier] if method == "DELETE" && valid_object(identifier) => {
            Ok(DockerRoute::ImageDelete)
        }
        ["", "containers", identifier, "json"] if method == "GET" && valid_object(identifier) => {
            Ok(DockerRoute::ContainerInspect {
                identifier: percent_decode(identifier)?,
            })
        }
        ["", "containers", identifier, operation]
            if valid_object(identifier)
                && matches!(
                    (method, *operation),
                    ("POST", "start" | "wait" | "attach") | ("GET", "logs")
                ) =>
        {
            Ok(DockerRoute::ContainerOperation)
        }
        ["", "containers", identifier] if method == "DELETE" && valid_object(identifier) => {
            Ok(DockerRoute::ContainerOperation)
        }
        _ => Err(()),
    }
}

fn strip_api_version(path: &str) -> Result<&str, ()> {
    let Some(rest) = path.strip_prefix("/v") else {
        return Ok(path);
    };
    let Some(separator) = rest.find('/') else {
        return Err(());
    };
    let version = &rest[..separator];
    if version.is_empty()
        || version.len() > 16
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || !version.contains('.')
    {
        return Err(());
    }
    Ok(&rest[separator..])
}

fn valid_object(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~:%@+-".contains(&byte))
}

fn parse_port_bindings(value: Option<Value>) -> Result<BTreeMap<String, PublishedPort>, ()> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    if value.is_null() {
        return Ok(BTreeMap::new());
    }
    let object = value.as_object().ok_or(())?;
    let mut result = BTreeMap::new();
    for (container, bindings) in object {
        let (number, protocol) = container.split_once('/').ok_or(())?;
        let container_port = number.parse::<u16>().map_err(|_| ())?;
        if container_port == 0 || protocol != "tcp" {
            return Err(());
        }
        let bindings = bindings.as_array().ok_or(())?;
        if bindings.len() != 1 {
            return Err(());
        }
        let binding = bindings[0].as_object().ok_or(())?;
        let host_ip = binding.get("HostIp").and_then(Value::as_str).unwrap_or("");
        if !matches!(host_ip, "" | "127.0.0.1") {
            return Err(());
        }
        let requested = binding
            .get("HostPort")
            .and_then(Value::as_str)
            .unwrap_or("");
        let host_port = if requested.is_empty() {
            container_port
        } else {
            requested.parse::<u16>().map_err(|_| ())?
        };
        if host_port == 0 || host_port != container_port {
            return Err(());
        }
        result.insert(container.clone(), PublishedPort { host_port });
    }
    Ok(result)
}

fn reject_nonempty(object: &Map<String, Value>, field: &str) -> Result<(), ()> {
    if object.get(field).is_some_and(|value| !empty_json(value)) {
        Err(())
    } else {
        Ok(())
    }
}

fn reject_true(object: &Map<String, Value>, field: &str) -> Result<(), ()> {
    if object.get(field).and_then(Value::as_bool).unwrap_or(false) {
        Err(())
    } else {
        Ok(())
    }
}

fn empty_json(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(value) => !value,
        Value::String(value) => value.is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
        Value::Number(value) => value.as_i64() == Some(0),
    }
}

fn handle_connection(
    mut client: UnixStream,
    backend_socket: &Path,
    policy: &ProxyPolicy,
) -> io::Result<()> {
    let header = read_header(&mut client)?;
    let Ok(parsed) = ParsedHeader::parse(&header) else {
        return send_rejection(&mut client, 400, "malformed Docker API request");
    };
    let is_build = DockerRoute::parse(&parsed.method, &parsed.target)
        .is_ok_and(|route| matches!(route, DockerRoute::Build));
    if parsed.chunked && !is_build {
        return send_rejection(
            &mut client,
            400,
            "chunked bodies are only accepted for Docker builds",
        );
    }
    if is_build && !parsed.chunked && parsed.content_length as u64 > MAX_BUILD_CONTEXT_BYTES {
        return send_rejection(&mut client, 413, "Docker build context is too large");
    }
    let body = if is_build {
        Vec::new()
    } else {
        match read_fixed_body(&mut client, parsed.content_length, MAX_CONTROL_BODY_BYTES) {
            Ok(body) => body,
            Err(_) => return send_rejection(&mut client, 413, "Docker API request is too large"),
        }
    };
    let Ok(authorized) = policy.authorize(&parsed.method, &parsed.target, &body) else {
        return send_rejection(&mut client, 403, "Docker API operation is not allowed");
    };

    let mut backend = UnixStream::connect(backend_socket)?;
    let upgrade = parsed.upgrade;
    let forwarded = rewrite_header(
        &parsed,
        &authorized.target,
        if is_build && parsed.chunked {
            None
        } else if is_build {
            Some(parsed.content_length)
        } else {
            Some(authorized.body.len())
        },
        upgrade,
    );
    backend.write_all(&forwarded)?;
    if is_build && parsed.chunked {
        copy_chunked(&mut client, &mut backend, MAX_BUILD_CONTEXT_BYTES)?;
    } else if is_build {
        copy_fixed(
            &mut client,
            &mut backend,
            parsed.content_length as u64,
            MAX_BUILD_CONTEXT_BYTES,
        )?;
    } else {
        backend.write_all(&authorized.body)?;
    }
    backend.flush()?;

    if upgrade {
        return relay_upgraded(client, backend);
    }
    match authorized.response {
        ResponseTransform::Passthrough => {
            io::copy(&mut backend, &mut client)?;
            Ok(())
        }
        ResponseTransform::RecordContainer { name, ports } => {
            let response = read_response(&mut backend, MAX_CONTROL_BODY_BYTES)?;
            if response.success()
                && let Some(identifier) = response
                    .json_body()
                    .and_then(|value| value.get("Id").and_then(Value::as_str).map(str::to_owned))
            {
                policy
                    .record_container(name, &identifier, ports)
                    .map_err(|()| io::Error::other("Docker API policy state is unavailable"))?;
            }
            response.write_to(&mut client)
        }
        ResponseTransform::RewriteInspect { identifier } => {
            let mut response = read_response(&mut backend, MAX_CONTROL_BODY_BYTES)?;
            if response.success() {
                response.body = policy
                    .rewrite_inspect(&identifier, &response.body)
                    .map_err(|()| io::Error::other("invalid Docker inspect response"))?;
            }
            response.write_to(&mut client)
        }
    }
}

fn relay_upgraded(mut client: UnixStream, mut backend: UnixStream) -> io::Result<()> {
    let mut client_reader = client.try_clone()?;
    let mut backend_writer = backend.try_clone()?;
    let upload = thread::spawn(move || {
        let result = io::copy(&mut client_reader, &mut backend_writer);
        let _ignored = backend_writer.shutdown(std::net::Shutdown::Write);
        result
    });
    let download = io::copy(&mut backend, &mut client);
    let _ignored = client.shutdown(std::net::Shutdown::Write);
    let upload = upload
        .join()
        .map_err(|_| io::Error::other("Docker API relay worker failed"))?;
    upload?;
    download.map(|_| ())
}

#[derive(Debug)]
struct ParsedHeader {
    method: String,
    target: String,
    version: String,
    fields: Vec<(String, String)>,
    content_length: usize,
    chunked: bool,
    upgrade: bool,
}

impl ParsedHeader {
    fn parse(header: &[u8]) -> Result<Self, ()> {
        let text = std::str::from_utf8(header).map_err(|_| ())?;
        let mut lines = text.strip_suffix("\r\n\r\n").ok_or(())?.split("\r\n");
        let mut request = lines.next().ok_or(())?.split(' ');
        let method = request.next().ok_or(())?;
        let target = request.next().ok_or(())?;
        let version = request.next().ok_or(())?;
        if request.next().is_some()
            || !matches!(method, "GET" | "HEAD" | "POST" | "DELETE")
            || !target.starts_with('/')
            || target.len() > 8 * 1024
            || version != "HTTP/1.1"
        {
            return Err(());
        }
        let mut fields = Vec::new();
        let mut content_length = None;
        let mut chunked = false;
        let mut upgrade = false;
        for line in lines {
            let (name, value) = line.split_once(':').ok_or(())?;
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() && byte != b'\t')
            {
                return Err(());
            }
            let value = value.trim().to_owned();
            match name.to_ascii_lowercase().as_str() {
                "content-length" => {
                    if content_length.is_some() {
                        return Err(());
                    }
                    content_length = Some(value.parse::<usize>().map_err(|_| ())?);
                }
                "transfer-encoding" => {
                    if !value.eq_ignore_ascii_case("chunked") {
                        return Err(());
                    }
                    chunked = true;
                }
                "connection" if value.eq_ignore_ascii_case("upgrade") => upgrade = true,
                _ => {}
            }
            fields.push((name.to_owned(), value));
        }
        if chunked && content_length.is_some() {
            return Err(());
        }
        Ok(Self {
            method: method.to_owned(),
            target: target.to_owned(),
            version: version.to_owned(),
            fields,
            content_length: content_length.unwrap_or(0),
            chunked,
            upgrade,
        })
    }
}

fn rewrite_header(
    request: &ParsedHeader,
    target: &str,
    content_length: Option<usize>,
    upgrade: bool,
) -> Vec<u8> {
    let mut output = format!("{} {target} {}\r\n", request.method, request.version).into_bytes();
    for (name, value) in &request.fields {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || (content_length.is_some() && name.eq_ignore_ascii_case("transfer-encoding"))
        {
            continue;
        }
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    if let Some(length) = content_length {
        output.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
    }
    if upgrade {
        output.extend_from_slice(b"Connection: Upgrade\r\n");
    } else {
        output.extend_from_slice(b"Connection: close\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output
}

fn read_header(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut byte = [0_u8; 1];
    while result.len() < MAX_HEADER_BYTES {
        stream.read_exact(&mut byte)?;
        result.push(byte[0]);
        if result.ends_with(b"\r\n\r\n") {
            return Ok(result);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Docker API header exceeded its limit",
    ))
}

fn read_fixed_body(stream: &mut UnixStream, length: usize, maximum: usize) -> io::Result<Vec<u8>> {
    if length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Docker API body exceeded its limit",
        ));
    }
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn copy_chunked(
    source: &mut UnixStream,
    destination: &mut UnixStream,
    maximum: u64,
) -> io::Result<()> {
    let mut total = 0_u64;
    loop {
        let line = read_crlf_line(source, 128)?;
        destination.write_all(&line)?;
        let size_text = std::str::from_utf8(&line[..line.len() - 2])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        let size_text = size_text.split(';').next().unwrap_or("");
        let size = u64::from_str_radix(size_text, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        if size == 0 {
            loop {
                let trailer = read_crlf_line(source, MAX_HEADER_BYTES)?;
                destination.write_all(&trailer)?;
                if trailer == b"\r\n" {
                    return Ok(());
                }
            }
        }
        total = total
            .checked_add(size)
            .filter(|total| *total <= maximum)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "build context exceeded its limit",
                )
            })?;
        let mut limited = source.take(size + 2);
        let copied = io::copy(&mut limited, destination)?;
        if copied != size + 2 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete Docker API chunk",
            ));
        }
    }
}

fn copy_fixed(
    source: &mut UnixStream,
    destination: &mut UnixStream,
    length: u64,
    maximum: u64,
) -> io::Result<()> {
    if length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "build context exceeded its limit",
        ));
    }
    let copied = io::copy(&mut source.take(length), destination)?;
    if copied != length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "incomplete Docker build context",
        ));
    }
    Ok(())
}

fn read_crlf_line<R: io::Read>(reader: &mut R, maximum: usize) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut byte = [0_u8; 1];
    while result.len() < maximum {
        reader.read_exact(&mut byte)?;
        result.push(byte[0]);
        if result.ends_with(b"\r\n") {
            return Ok(result);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "line exceeded its limit",
    ))
}

#[derive(Debug)]
struct BufferedResponse {
    status_line: String,
    fields: Vec<(String, String)>,
    body: Vec<u8>,
}

impl BufferedResponse {
    fn success(&self) -> bool {
        self.status_line
            .split_whitespace()
            .nth(1)
            .is_some_and(|status| status.starts_with('2'))
    }

    fn json_body(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    fn write_to(&self, destination: &mut UnixStream) -> io::Result<()> {
        destination.write_all(self.status_line.as_bytes())?;
        destination.write_all(b"\r\n")?;
        for (name, value) in &self.fields {
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
                || name.eq_ignore_ascii_case("connection")
            {
                continue;
            }
            destination.write_all(name.as_bytes())?;
            destination.write_all(b": ")?;
            destination.write_all(value.as_bytes())?;
            destination.write_all(b"\r\n")?;
        }
        destination.write_all(format!("Content-Length: {}\r\n", self.body.len()).as_bytes())?;
        destination.write_all(b"Connection: close\r\n\r\n")?;
        destination.write_all(&self.body)
    }
}

fn read_response(stream: &mut UnixStream, maximum: usize) -> io::Result<BufferedResponse> {
    let header = read_header(stream)?;
    let text = std::str::from_utf8(&header)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid backend response"))?;
    let mut lines = text
        .strip_suffix("\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid backend response"))?
        .split("\r\n");
    let status_line = lines
        .next()
        .filter(|line| line.starts_with("HTTP/1.1 "))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid backend status"))?
        .to_owned();
    let mut fields = Vec::new();
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid backend header"))?;
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(value.parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid backend length")
            })?);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.eq_ignore_ascii_case("chunked");
        }
        fields.push((name.to_owned(), value));
    }
    let body = if chunked {
        read_chunked_body(stream, maximum)?
    } else {
        read_fixed_body(stream, length.unwrap_or(0), maximum)?
    };
    Ok(BufferedResponse {
        status_line,
        fields,
        body,
    })
}

fn read_chunked_body(stream: &mut UnixStream, maximum: usize) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = read_crlf_line(stream, 128)?;
        let size_text = std::str::from_utf8(&line[..line.len() - 2])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or(""), 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        if size == 0 {
            loop {
                if read_crlf_line(stream, MAX_HEADER_BYTES)? == b"\r\n" {
                    return Ok(body);
                }
            }
        }
        if body
            .len()
            .checked_add(size)
            .is_none_or(|size| size > maximum)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "backend response exceeded its limit",
            ));
        }
        let start = body.len();
        body.resize(start + size, 0);
        stream.read_exact(&mut body[start..])?;
        let mut terminator = [0_u8; 2];
        stream.read_exact(&mut terminator)?;
        if terminator != *b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunk terminator",
            ));
        }
    }
}

fn send_rejection(stream: &mut UnixStream, status: u16, message: &str) -> io::Result<()> {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        413 => "Content Too Large",
        _ => "Error",
    };
    let body = serde_json::to_vec(&json!({ "message": message }))?;
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)
}

fn query_parameters(query: &str) -> impl Iterator<Item = (&str, &str)> {
    query
        .split('&')
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .split_once('=')
                .map_or((value, ""), |(name, value)| (name, value))
        })
}

fn percent_encode(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            result.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ignored = write!(result, "%{byte:02X}");
        }
    }
    result
}

fn percent_decode(value: &str) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let high = decode_hex(bytes[index + 1]).ok_or(())?;
                let low = decode_hex(bytes[index + 2]).ok_or(())?;
                result.push((high << 4) | low);
                index += 3;
            }
            b'+' => {
                result.push(b' ');
                index += 1;
            }
            byte if byte.is_ascii() && !byte.is_ascii_control() => {
                result.push(byte);
                index += 1;
            }
            _ => return Err(()),
        }
    }
    String::from_utf8(result).map_err(|_| ())
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
