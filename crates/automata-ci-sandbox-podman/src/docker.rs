use std::{
    collections::{BTreeMap, BTreeSet},
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
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use automata_ci_execution::{ResourceLimits, SandboxHandle};
use rustix::event::{PollFd, PollFlags, poll};
use serde_json::{Map, Value, json};

use crate::{
    DockerProxyOutcome, DockerProxyRejection, DockerProxyRoute, PodmanConfigurationError,
    PodmanEvent, PodmanObserver, PodmanOptions, PodmanProcessEnvironment,
    command::PersistentPodmanProcess, state::JobEnginePaths,
};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_CONTROL_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_BUILD_CONTEXT_BYTES: u64 = 512 * 1024 * 1024;
const BACKEND_START_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const BACKEND_IDLE_SECONDS: &str = "0";
const PUBLIC_SOCKET_MODE: u32 = 0o600;
const MAX_CONNECTION_WORKERS: usize = 64;
// A backend response EOF is terminal, so the client upload gets only a bounded
// grace. Client-write EOF is deliberately different: Docker attach may keep
// streaming backend output until the container exits.
const UPGRADED_BACKEND_EOF_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
// A rejected upgrade can already have one pipelined request queued locally.
// Drain at most one bounded head for a bounded interval after half-closing the
// response direction, so dropping the Unix socket does not reset a response
// that the client has not consumed yet.
const REJECTED_UPGRADE_DRAIN_TIMEOUT: Duration = Duration::from_millis(50);
const MAX_REJECTED_UPGRADE_DRAIN_BYTES: u64 = 64 * 1024;
const UPGRADED_RELAY_THREAD_STACK_BYTES: usize = 128 * 1024;
// Podman maps Docker's file driver to storage below the attempt-scoped graph
// root, so engine teardown removes it while attached output and `docker logs`
// remain compatible. Never inherit the host default: it is commonly journald.
const JOB_LOCAL_LOG_DRIVER: &str = "json-file";
const BUILDX_DEFAULT_IMAGE: &str = "moby/buildkit:buildx-stable-1";
const BUILDX_DEFAULT_NORMALIZED_REPOSITORY: &str = "docker.io/moby/buildkit";
const BUILDX_DEFAULT_TAG: &str = "buildx-stable-1";
const BUILDX_CONTAINER_PREFIX: &str = "buildx_buildkit_";
const BUILDKIT_STATE_DIRECTORY: &str = "/var/lib/buildkit";
const BUILDKIT_CONFIG_ARCHIVE_DESTINATION: &str = "/etc";
const BUILDKIT_GHA_PROVENANCE_FILE: &str = "buildkit/provenance.d/github_actions_context.json";
const MAX_BUILDKIT_EXECS: usize = 256;

// The distribution image uses Docker's legacy builder with `--file`, `--quiet`,
// and one `--tag`. Docker 29 emits these four query fields for that command.
// Keep this list closed; additional build features require an explicit policy
// review and coverage in the opt-in distribution command-surface test.
const DISTRIBUTION_BUILD_QUERY_PARAMETERS: [&str; 4] = ["dockerfile", "q", "t", "version"];

pub(crate) use crate::docker_contract::DOCKER_SOCKET_DIRECTORY_TARGET;

#[derive(Debug)]
pub(crate) struct JobDockerListener(UnixListener);

pub(crate) use crate::docker_contract::JobDockerLaunch;

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
        launch: JobDockerLaunch<'_>,
        observer: Arc<dyn PodmanObserver>,
    ) -> Result<Self, PodmanConfigurationError> {
        options.process_environment().validate_launch()?;
        prepare_socket_path(paths.backend_socket())?;
        let backend_uri = format!("unix://{}", paths.backend_socket().display());
        let mut arguments =
            options.global_arguments(paths.graph_root(), paths.run_root(), paths.tmp_dir());
        arguments.extend([
            OsString::from("system"),
            OsString::from("service"),
            OsString::from("--time"),
            OsString::from(BACKEND_IDLE_SECONDS),
            OsString::from(backend_uri),
        ]);
        let mut backend = PersistentPodmanProcess::spawn(
            options.binary().as_path(),
            &arguments,
            options.process_environment(),
        )
        .map_err(|()| PodmanConfigurationError::JobEngineUnavailable)?;
        wait_for_backend(paths.backend_socket(), &mut backend)?;

        let policy = Arc::new(ProxyPolicy::new(
            launch.sandbox,
            launch.outer_process_id,
            launch.outer_cgroup,
            launch.resources,
            options.process_environment().clone(),
            options
                .buildkit_runtime()
                .map(|runtime| runtime.image().reference().to_owned()),
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
                    &observer,
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
    observer: &Arc<dyn PodmanObserver>,
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
                    observer.observe(PodmanEvent::DockerRejected {
                        reason: DockerProxyRejection::ConnectionLimit,
                    });
                    let _ignored =
                        send_rejection(&mut client, 503, "Docker API connection limit reached");
                    continue;
                }
                let Ok(control) = client.try_clone() else {
                    observer.observe(PodmanEvent::DockerRejected {
                        reason: DockerProxyRejection::WorkerUnavailable,
                    });
                    continue;
                };
                let backend_socket = backend_socket.to_path_buf();
                let policy = Arc::clone(policy);
                let worker_observer = Arc::clone(observer);
                let Ok(worker) = thread::Builder::new()
                    .name("automata-job-docker-request".to_owned())
                    .spawn(move || {
                        let _ignored = handle_connection(
                            client,
                            &backend_socket,
                            &policy,
                            worker_observer.as_ref(),
                        );
                    })
                else {
                    observer.observe(PodmanEvent::DockerRejected {
                        reason: DockerProxyRejection::WorkerUnavailable,
                    });
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
    launch_validator: Arc<dyn DockerLaunchValidator>,
    buildkit: Option<BuildKitPolicy>,
}

#[derive(Debug)]
struct BuildKitPolicy {
    image: String,
    state: Mutex<BuildKitState>,
}

#[derive(Debug, Default)]
struct BuildKitState {
    container: Option<OwnedBuildKitContainer>,
    execs: BTreeSet<String>,
}

#[derive(Debug)]
struct OwnedBuildKitContainer {
    name: String,
    identifier: Option<String>,
    volume: String,
}

trait DockerLaunchValidator: std::fmt::Debug + Send + Sync {
    fn validate(&self) -> bool;
}

impl DockerLaunchValidator for PodmanProcessEnvironment {
    fn validate(&self) -> bool {
        self.validate_launch().is_ok()
    }
}

impl ProxyPolicy {
    fn new(
        sandbox: &SandboxHandle,
        outer_process_id: u32,
        cgroup_parent: String,
        resources: ResourceLimits,
        process_environment: PodmanProcessEnvironment,
        buildkit_image: Option<String>,
    ) -> Self {
        Self::new_with_validator(
            sandbox,
            outer_process_id,
            cgroup_parent,
            resources,
            Arc::new(process_environment),
            buildkit_image,
        )
    }

    fn new_with_validator(
        sandbox: &SandboxHandle,
        outer_process_id: u32,
        cgroup_parent: String,
        resources: ResourceLimits,
        launch_validator: Arc<dyn DockerLaunchValidator>,
        buildkit_image: Option<String>,
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
            launch_validator,
            buildkit: buildkit_image.map(|image| BuildKitPolicy {
                image,
                state: Mutex::new(BuildKitState::default()),
            }),
        }
    }

    fn authorize(&self, method: &str, target: &str, body: &[u8]) -> Result<AuthorizedRequest, ()> {
        if !self.launch_validator.validate() {
            return Err(());
        }
        let route = DockerRoute::parse(method, target)?;
        match route {
            DockerRoute::Build => {
                let target = self.rewrite_build_target(target)?;
                Ok(AuthorizedRequest::passthrough(target, body.to_vec()))
            }
            DockerRoute::Info => self.authorize_info(target, body),
            DockerRoute::ImagePull => self.authorize_buildkit_image_pull(target, body),
            DockerRoute::ImageInspect { identifier } => {
                if is_buildx_default_image(&identifier) {
                    require_empty_body(body)?;
                    let target = self.rewrite_buildkit_image_inspect_target(target)?;
                    Ok(AuthorizedRequest {
                        target,
                        body: body.to_vec(),
                        response: ResponseTransform::RewriteBuildKitImageInspect,
                        buildkit_container_reservation: None,
                    })
                } else if self.is_configured_buildkit_image(&identifier) {
                    Err(())
                } else {
                    Ok(AuthorizedRequest::passthrough(
                        target.to_owned(),
                        body.to_vec(),
                    ))
                }
            }
            DockerRoute::ImageDelete { identifier } => {
                if is_buildx_default_image(&identifier)
                    || self.is_configured_buildkit_image(&identifier)
                {
                    Err(())
                } else {
                    Ok(AuthorizedRequest::passthrough(
                        target.to_owned(),
                        body.to_vec(),
                    ))
                }
            }
            DockerRoute::ContainerCreate { name } => {
                self.authorize_container_create(target, name, body)
            }
            DockerRoute::ContainerInspect { identifier } => {
                self.authorize_container_inspect(target, body, identifier)
            }
            DockerRoute::ContainerOperation {
                identifier,
                operation,
            } => {
                if self.is_owned_buildkit_container(&identifier)? {
                    Self::authorize_buildkit_container_operation(
                        target,
                        body,
                        &identifier,
                        operation,
                    )
                } else if is_buildx_container_name(&identifier) {
                    Err(())
                } else {
                    Ok(AuthorizedRequest::passthrough(
                        target.to_owned(),
                        body.to_vec(),
                    ))
                }
            }
            DockerRoute::ExecOperation {
                identifier,
                operation,
            } => self.authorize_buildkit_exec_operation(target, body, &identifier, operation),
            DockerRoute::VolumeDelete { identifier } => {
                self.authorize_buildkit_volume_delete(target, body, &identifier)
            }
            DockerRoute::Ping | DockerRoute::Version => Ok(AuthorizedRequest::passthrough(
                target.to_owned(),
                body.to_vec(),
            )),
        }
    }

    fn authorize_container_create(
        &self,
        target: &str,
        name: Option<String>,
        body: &[u8],
    ) -> Result<AuthorizedRequest, ()> {
        let image = request_image(body)?;
        let special_name = name.as_deref().is_some_and(is_buildx_container_name);
        let special_image = image.as_deref().is_some_and(|image| {
            is_buildx_default_image(image) || self.is_configured_buildkit_image(image)
        });
        if special_name || special_image {
            let name = name.ok_or(())?;
            let body = self.rewrite_buildkit_container_create(target, &name, body)?;
            Ok(AuthorizedRequest {
                target: target.to_owned(),
                body,
                response: ResponseTransform::RecordBuildKitContainer { name: name.clone() },
                buildkit_container_reservation: Some(name),
            })
        } else {
            let (body, ports) = self.rewrite_container_create(body)?;
            Ok(AuthorizedRequest {
                target: target.to_owned(),
                body,
                response: ResponseTransform::RecordContainer { name, ports },
                buildkit_container_reservation: None,
            })
        }
    }

    fn authorize_info(&self, target: &str, body: &[u8]) -> Result<AuthorizedRequest, ()> {
        self.buildkit()?;
        validate_empty_query(target)?;
        require_empty_body(body)?;
        Ok(AuthorizedRequest {
            target: target.to_owned(),
            body: Vec::new(),
            response: ResponseTransform::RewriteInfo,
            buildkit_container_reservation: None,
        })
    }

    fn authorize_container_inspect(
        &self,
        target: &str,
        body: &[u8],
        identifier: String,
    ) -> Result<AuthorizedRequest, ()> {
        if self.is_owned_buildkit_container(&identifier)? {
            validate_empty_query(target)?;
            require_empty_body(body)?;
            Ok(AuthorizedRequest::passthrough(
                target.to_owned(),
                Vec::new(),
            ))
        } else if is_buildx_container_name(&identifier) {
            self.buildkit()?;
            validate_empty_query(target)?;
            require_empty_body(body)?;
            Ok(AuthorizedRequest {
                target: target.to_owned(),
                body: Vec::new(),
                response: ResponseTransform::InspectBuildKitCandidate { name: identifier },
                buildkit_container_reservation: None,
            })
        } else {
            Ok(AuthorizedRequest {
                target: target.to_owned(),
                body: body.to_vec(),
                response: ResponseTransform::RewriteInspect { identifier },
                buildkit_container_reservation: None,
            })
        }
    }

    fn buildkit(&self) -> Result<&BuildKitPolicy, ()> {
        self.buildkit.as_ref().ok_or(())
    }

    fn is_configured_buildkit_image(&self, image: &str) -> bool {
        self.buildkit
            .as_ref()
            .is_some_and(|buildkit| buildkit.image == image)
    }

    fn authorize_buildkit_image_pull(
        &self,
        target: &str,
        body: &[u8],
    ) -> Result<AuthorizedRequest, ()> {
        self.buildkit()?;
        validate_buildkit_image_pull_query(target)?;
        require_empty_body(body)?;
        Ok(AuthorizedRequest {
            target: target.to_owned(),
            body: Vec::new(),
            response: ResponseTransform::SyntheticImagePull,
            buildkit_container_reservation: None,
        })
    }

    fn rewrite_buildkit_image_inspect_target(&self, target: &str) -> Result<String, ()> {
        let buildkit = self.buildkit()?;
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        if !query.is_empty() {
            return Err(());
        }
        let stripped = strip_api_version(path)?;
        let prefix = &path[..path.len().checked_sub(stripped.len()).ok_or(())?];
        Ok(format!(
            "{prefix}/images/{}/json",
            percent_encode(&buildkit.image)
        ))
    }

    fn rewrite_buildkit_container_create(
        &self,
        target: &str,
        name: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, ()> {
        let buildkit = self.buildkit()?;
        validate_buildkit_create_query(target, name)?;
        if !is_buildx_container_name(name) {
            return Err(());
        }
        let volume = format!("{name}_state");
        let mut document: Value = serde_json::from_slice(body).map_err(|_| ())?;
        let object = document.as_object_mut().ok_or(())?;
        if object
            .keys()
            .any(|field| !allowed_buildkit_create_field(field))
        {
            return Err(());
        }
        let image = object.get("Image").and_then(Value::as_str).ok_or(())?;
        if image != BUILDX_DEFAULT_IMAGE {
            return Err(());
        }
        validate_buildkit_command(object.get("Cmd"))?;
        for field in ["Entrypoint", "Env", "User", "WorkingDir", "Volumes"] {
            reject_nonempty(object, field)?;
        }
        for field in [
            "Hostname",
            "Domainname",
            "ExposedPorts",
            "Healthcheck",
            "OnBuild",
            "StopSignal",
            "StopTimeout",
            "Shell",
            "NetworkingConfig",
        ] {
            reject_nonempty(object, field)?;
        }
        reject_true(object, "ArgsEscaped")?;
        for field in [
            "AttachStdin",
            "AttachStdout",
            "AttachStderr",
            "Tty",
            "OpenStdin",
            "StdinOnce",
            "NetworkDisabled",
        ] {
            reject_true(object, field)?;
        }
        let labels = object_field_or_empty(object, "Labels")?;
        if !labels.is_empty() {
            return Err(());
        }
        for (label, value) in &self.owner_labels {
            if labels.contains_key(label) {
                return Err(());
            }
            labels.insert(label.clone(), value.clone());
        }
        object.insert("Image".to_owned(), Value::String(buildkit.image.clone()));

        let host = object
            .entry("HostConfig")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or(())?;
        self.rewrite_buildkit_host_config(host, &volume)?;

        let encoded = serde_json::to_vec(&document).map_err(|_| ())?;
        let mut state = buildkit.state.lock().map_err(|_| ())?;
        if state.container.is_some() {
            return Err(());
        }
        state.container = Some(OwnedBuildKitContainer {
            name: name.to_owned(),
            identifier: None,
            volume: format!("{name}_state"),
        });
        Ok(encoded)
    }

    fn rewrite_buildkit_host_config(
        &self,
        host: &mut Map<String, Value>,
        volume: &str,
    ) -> Result<(), ()> {
        validate_buildkit_host_config(host, volume)?;
        force_job_local_log_config(host)?;
        host.insert(
            "NetworkMode".to_owned(),
            Value::String(self.network_namespace.clone()),
        );
        host.insert(
            "CgroupParent".to_owned(),
            Value::String(self.cgroup_parent.clone()),
        );
        host.insert(
            "RestartPolicy".to_owned(),
            json!({"Name": "no", "MaximumRetryCount": 0}),
        );
        host.insert("Privileged".to_owned(), Value::Bool(true));
        host.insert("Init".to_owned(), Value::Bool(true));
        host.insert("ReadonlyRootfs".to_owned(), Value::Bool(false));
        host.insert("PublishAllPorts".to_owned(), Value::Bool(false));
        host.insert("PortBindings".to_owned(), Value::Object(Map::new()));
        host.insert(
            "Mounts".to_owned(),
            json!([{
                "Type": "volume",
                "Source": volume,
                "Target": BUILDKIT_STATE_DIRECTORY,
                "ReadOnly": false,
            }]),
        );
        let cpu_period = 100_000_u64;
        let cpu_quota = u64::from(self.resources.cpu_millis())
            .checked_mul(cpu_period)
            .ok_or(())?
            / 1_000;
        host.insert("Memory".to_owned(), json!(self.resources.memory_bytes()));
        host.insert("CpuPeriod".to_owned(), json!(cpu_period));
        host.insert("CpuQuota".to_owned(), json!(cpu_quota));
        Ok(())
    }

    fn is_owned_buildkit_container(&self, identifier: &str) -> Result<bool, ()> {
        let Some(buildkit) = self.buildkit.as_ref() else {
            return Ok(false);
        };
        let state = buildkit.state.lock().map_err(|_| ())?;
        Ok(state.container.as_ref().is_some_and(|container| {
            container.name == identifier
                || container.identifier.as_deref() == Some(identifier)
                || container
                    .identifier
                    .as_ref()
                    .is_some_and(|owned| identifier.len() >= 12 && owned.starts_with(identifier))
        }))
    }

    fn authorize_buildkit_container_operation(
        target: &str,
        body: &[u8],
        _identifier: &str,
        operation: ContainerOperation,
    ) -> Result<AuthorizedRequest, ()> {
        let response = match operation {
            ContainerOperation::Start | ContainerOperation::Stop => {
                validate_empty_query(target)?;
                require_empty_body(body)?;
                ResponseTransform::Passthrough
            }
            ContainerOperation::Logs => {
                validate_buildkit_logs_query(target)?;
                require_empty_body(body)?;
                ResponseTransform::Passthrough
            }
            ContainerOperation::Remove => {
                validate_buildkit_remove_query(target)?;
                require_empty_body(body)?;
                ResponseTransform::Passthrough
            }
            ContainerOperation::Archive => {
                validate_buildkit_archive_query(target)?;
                validate_buildkit_config_archive(body)?;
                ResponseTransform::Passthrough
            }
            ContainerOperation::ExecCreate => {
                validate_buildkit_exec_create(body)?;
                validate_empty_query(target)?;
                ResponseTransform::RecordBuildKitExec
            }
            ContainerOperation::Wait | ContainerOperation::Attach => return Err(()),
        };
        Ok(AuthorizedRequest {
            target: target.to_owned(),
            body: body.to_vec(),
            response,
            buildkit_container_reservation: None,
        })
    }

    fn authorize_buildkit_exec_operation(
        &self,
        target: &str,
        body: &[u8],
        identifier: &str,
        operation: ExecOperation,
    ) -> Result<AuthorizedRequest, ()> {
        let buildkit = self.buildkit()?;
        if !buildkit
            .state
            .lock()
            .map_err(|_| ())?
            .execs
            .contains(identifier)
        {
            return Err(());
        }
        validate_empty_query(target)?;
        match operation {
            ExecOperation::Start => validate_buildkit_exec_start(body)?,
            ExecOperation::Inspect => require_empty_body(body)?,
        }
        Ok(AuthorizedRequest::passthrough(
            target.to_owned(),
            body.to_vec(),
        ))
    }

    fn authorize_buildkit_volume_delete(
        &self,
        target: &str,
        body: &[u8],
        identifier: &str,
    ) -> Result<AuthorizedRequest, ()> {
        let buildkit = self.buildkit()?;
        let owned = buildkit
            .state
            .lock()
            .map_err(|_| ())?
            .container
            .as_ref()
            .is_some_and(|container| container.volume == identifier);
        if !owned {
            return Err(());
        }
        validate_empty_query(target)?;
        require_empty_body(body)?;
        Ok(AuthorizedRequest::passthrough(
            target.to_owned(),
            body.to_vec(),
        ))
    }

    fn cancel_buildkit_container_reservation(&self, name: &str) {
        let Some(buildkit) = self.buildkit.as_ref() else {
            return;
        };
        let Ok(mut state) = buildkit.state.lock() else {
            return;
        };
        if state
            .container
            .as_ref()
            .is_some_and(|container| container.name == name && container.identifier.is_none())
        {
            state.container = None;
        }
    }

    fn finish_buildkit_container_create(
        &self,
        name: &str,
        identifier: Option<String>,
    ) -> Result<(), ()> {
        let buildkit = self.buildkit()?;
        let mut state = buildkit.state.lock().map_err(|_| ())?;
        let container = state.container.as_mut().ok_or(())?;
        if container.name != name || container.identifier.is_some() {
            return Err(());
        }
        match identifier {
            Some(identifier) if valid_backend_identifier(&identifier) => {
                container.identifier = Some(identifier);
                Ok(())
            }
            _ => {
                state.container = None;
                Ok(())
            }
        }
    }

    fn record_buildkit_exec(&self, identifier: &str) -> Result<(), ()> {
        if !valid_backend_identifier(identifier) {
            return Err(());
        }
        let buildkit = self.buildkit()?;
        let mut state = buildkit.state.lock().map_err(|_| ())?;
        if state.execs.len() >= MAX_BUILDKIT_EXECS || !state.execs.insert(identifier.to_owned()) {
            return Err(());
        }
        Ok(())
    }

    fn adopt_buildkit_container(&self, name: &str, body: &[u8]) -> Result<(), ()> {
        let buildkit = self.buildkit()?;
        let document: Value = serde_json::from_slice(body).map_err(|_| ())?;
        let object = document.as_object().ok_or(())?;
        let identifier = object.get("Id").and_then(Value::as_str).ok_or(())?;
        if !valid_backend_identifier(identifier)
            || object
                .get("Name")
                .and_then(Value::as_str)
                .map(|actual| actual.trim_start_matches('/'))
                != Some(name)
            || document.pointer("/Config/Image").and_then(Value::as_str)
                != Some(buildkit.image.as_str())
            || document
                .pointer("/Config/Labels/io.automata.owner")
                .and_then(Value::as_str)
                != Some("automata-runner")
            || document
                .pointer("/Config/Labels/io.automata.job-engine")
                .and_then(Value::as_str)
                != self
                    .owner_labels
                    .get("io.automata.job-engine")
                    .and_then(Value::as_str)
            || document
                .pointer("/HostConfig/Privileged")
                .and_then(Value::as_bool)
                != Some(true)
            || document
                .pointer("/HostConfig/NetworkMode")
                .and_then(Value::as_str)
                != Some(self.network_namespace.as_str())
            || document
                .pointer("/HostConfig/CgroupParent")
                .and_then(Value::as_str)
                != Some(self.cgroup_parent.as_str())
        {
            return Err(());
        }
        let expected_volume = format!("{name}_state");
        let mounts = object.get("Mounts").and_then(Value::as_array).ok_or(())?;
        if mounts.len() != 1
            || mounts[0].get("Name").and_then(Value::as_str) != Some(expected_volume.as_str())
            || mounts[0].get("Destination").and_then(Value::as_str)
                != Some(BUILDKIT_STATE_DIRECTORY)
            || mounts[0].get("RW").and_then(Value::as_bool) != Some(true)
        {
            return Err(());
        }
        let mut state = buildkit.state.lock().map_err(|_| ())?;
        match state.container.as_ref() {
            Some(container)
                if container.name == name
                    && container.identifier.as_deref() == Some(identifier) =>
            {
                Ok(())
            }
            None => {
                state.container = Some(OwnedBuildKitContainer {
                    name: name.to_owned(),
                    identifier: Some(identifier.to_owned()),
                    volume: expected_volume,
                });
                Ok(())
            }
            Some(_) => Err(()),
        }
    }

    fn rewrite_build_target(&self, target: &str) -> Result<String, ()> {
        let separator = if target.contains('?') { '&' } else { '?' };
        let query = target.split_once('?').map_or("", |(_, query)| query);
        validate_build_query(query)?;
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
        let labels = object_field_or_empty(object, "Labels")?;
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

        force_job_local_log_config(host)?;
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

    fn rewrite_info(body: &[u8]) -> Result<Vec<u8>, ()> {
        let mut document: Value = serde_json::from_slice(body).map_err(|_| ())?;
        let object = document.as_object_mut().ok_or(())?;
        object.insert(
            "CgroupDriver".to_owned(),
            Value::String("cgroupfs".to_owned()),
        );
        if let Some(options) = object.get_mut("SecurityOptions") {
            let options = options.as_array_mut().ok_or(())?;
            options.retain(|option| {
                option.as_str().is_none_or(|value| {
                    !value.contains("name=userns") && !value.contains("name=rootless")
                })
            });
        }
        serde_json::to_vec(&document).map_err(|_| ())
    }

    fn rewrite_buildkit_image_inspect(&self, body: &[u8]) -> Result<Vec<u8>, ()> {
        let buildkit = self.buildkit()?;
        let document: Value = serde_json::from_slice(body).map_err(|_| ())?;
        let object = document.as_object().ok_or(())?;
        let expected_id = buildkit
            .image
            .rsplit_once('@')
            .map(|(_, digest)| digest)
            .ok_or(())?;
        let id = object.get("Id").and_then(Value::as_str).ok_or(())?;
        if id != expected_id {
            return Err(());
        }
        serde_json::to_vec(&json!({
            "Id": id,
            "RepoTags": [BUILDX_DEFAULT_IMAGE],
            "RepoDigests": [],
        }))
        .map_err(|_| ())
    }

    fn rewrite_buildkit_image_inspect_response(
        &self,
        response: &mut BufferedResponse,
    ) -> Result<(), ()> {
        let status = parse_backend_status(&response.status_line).map_err(|_| ())?;
        let body = match status {
            200 => self.rewrite_buildkit_image_inspect(&response.body)?,
            300..=599 => br#"{"message":"BuildKit image is unavailable"}"#.to_vec(),
            _ => return Err(()),
        };
        response.status_line = format!("HTTP/1.1 {status} BuildKit image response");
        response.fields = vec![("Content-Type".to_owned(), "application/json".to_owned())];
        response.body = body;
        Ok(())
    }
}

struct BuildKitContainerReservation<'a> {
    policy: &'a ProxyPolicy,
    name: String,
    active: bool,
}

impl BuildKitContainerReservation<'_> {
    fn commit(&mut self) {
        self.active = false;
    }
}

impl Drop for BuildKitContainerReservation<'_> {
    fn drop(&mut self) {
        if self.active {
            self.policy
                .cancel_buildkit_container_reservation(&self.name);
        }
    }
}

#[derive(Debug)]
struct AuthorizedRequest {
    target: String,
    body: Vec<u8>,
    response: ResponseTransform,
    buildkit_container_reservation: Option<String>,
}

impl AuthorizedRequest {
    fn passthrough(target: String, body: Vec<u8>) -> Self {
        Self {
            target,
            body,
            response: ResponseTransform::Passthrough,
            buildkit_container_reservation: None,
        }
    }
}

#[derive(Debug)]
enum ResponseTransform {
    Passthrough,
    SyntheticImagePull,
    RewriteInfo,
    RewriteBuildKitImageInspect,
    InspectBuildKitCandidate {
        name: String,
    },
    RecordContainer {
        name: Option<String>,
        ports: BTreeMap<String, PublishedPort>,
    },
    RewriteInspect {
        identifier: String,
    },
    RecordBuildKitContainer {
        name: String,
    },
    RecordBuildKitExec,
}

#[derive(Clone, Copy, Debug)]
struct PublishedPort {
    host_port: u16,
}

#[derive(Debug)]
enum DockerRoute {
    Ping,
    Version,
    Info,
    Build,
    ImagePull,
    ImageInspect {
        identifier: String,
    },
    ImageDelete {
        identifier: String,
    },
    ContainerCreate {
        name: Option<String>,
    },
    ContainerInspect {
        identifier: String,
    },
    ContainerOperation {
        identifier: String,
        operation: ContainerOperation,
    },
    ExecOperation {
        identifier: String,
        operation: ExecOperation,
    },
    VolumeDelete {
        identifier: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContainerOperation {
    Start,
    Wait,
    Attach,
    Logs,
    Stop,
    Remove,
    Archive,
    ExecCreate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecOperation {
    Start,
    Inspect,
}

impl DockerRoute {
    const fn metric_route(&self) -> DockerProxyRoute {
        match self {
            Self::Ping => DockerProxyRoute::Ping,
            Self::Version | Self::Info => DockerProxyRoute::Version,
            Self::Build => DockerProxyRoute::Build,
            Self::ImagePull | Self::ImageInspect { .. } => DockerProxyRoute::ImageInspect,
            Self::ImageDelete { .. } => DockerProxyRoute::ImageDelete,
            Self::ContainerCreate { .. } => DockerProxyRoute::ContainerCreate,
            Self::ContainerInspect { .. } => DockerProxyRoute::ContainerInspect,
            Self::ContainerOperation { .. }
            | Self::ExecOperation { .. }
            | Self::VolumeDelete { .. } => DockerProxyRoute::ContainerOperation,
        }
    }

    fn parse(method: &str, target: &str) -> Result<Self, ()> {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let path = strip_api_version(path)?;
        match (method, path) {
            ("HEAD" | "GET", "/_ping") => Ok(Self::Ping),
            ("GET", "/version") => Ok(Self::Version),
            ("GET", "/info") => Ok(Self::Info),
            ("POST", "/build") => Ok(Self::Build),
            ("POST", "/images/create") => Ok(Self::ImagePull),
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
            Ok(DockerRoute::ImageInspect {
                identifier: percent_decode(identifier)?,
            })
        }
        ["", "images", identifier] if method == "DELETE" && valid_object(identifier) => {
            Ok(DockerRoute::ImageDelete {
                identifier: percent_decode(identifier)?,
            })
        }
        ["", "containers", identifier, "json"] if method == "GET" && valid_object(identifier) => {
            Ok(DockerRoute::ContainerInspect {
                identifier: percent_decode(identifier)?,
            })
        }
        ["", "containers", identifier, "start"] if method == "POST" && valid_object(identifier) => {
            Ok(container_operation(identifier, ContainerOperation::Start)?)
        }
        ["", "containers", identifier, "wait"] if method == "POST" && valid_object(identifier) => {
            Ok(container_operation(identifier, ContainerOperation::Wait)?)
        }
        ["", "containers", identifier, "attach"]
            if method == "POST" && valid_object(identifier) =>
        {
            Ok(container_operation(identifier, ContainerOperation::Attach)?)
        }
        ["", "containers", identifier, "logs"] if method == "GET" && valid_object(identifier) => {
            Ok(container_operation(identifier, ContainerOperation::Logs)?)
        }
        ["", "containers", identifier, "stop"] if method == "POST" && valid_object(identifier) => {
            Ok(container_operation(identifier, ContainerOperation::Stop)?)
        }
        ["", "containers", identifier, "archive"]
            if method == "PUT" && valid_object(identifier) =>
        {
            Ok(container_operation(
                identifier,
                ContainerOperation::Archive,
            )?)
        }
        ["", "containers", identifier, "exec"] if method == "POST" && valid_object(identifier) => {
            Ok(container_operation(
                identifier,
                ContainerOperation::ExecCreate,
            )?)
        }
        ["", "containers", identifier] if method == "DELETE" && valid_object(identifier) => {
            Ok(container_operation(identifier, ContainerOperation::Remove)?)
        }
        ["", "exec", identifier, "start"] if method == "POST" && valid_object(identifier) => {
            Ok(DockerRoute::ExecOperation {
                identifier: percent_decode(identifier)?,
                operation: ExecOperation::Start,
            })
        }
        ["", "exec", identifier, "json"] if method == "GET" && valid_object(identifier) => {
            Ok(DockerRoute::ExecOperation {
                identifier: percent_decode(identifier)?,
                operation: ExecOperation::Inspect,
            })
        }
        ["", "volumes", identifier] if method == "DELETE" && valid_object(identifier) => {
            Ok(DockerRoute::VolumeDelete {
                identifier: percent_decode(identifier)?,
            })
        }
        _ => Err(()),
    }
}

fn container_operation(identifier: &str, operation: ContainerOperation) -> Result<DockerRoute, ()> {
    Ok(DockerRoute::ContainerOperation {
        identifier: percent_decode(identifier)?,
        operation,
    })
}

fn strip_api_version(path: &str) -> Result<&str, ()> {
    let Some(rest) = path.strip_prefix("/v") else {
        return Ok(path);
    };
    if !rest.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        return Ok(path);
    }
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

fn is_buildx_default_image(value: &str) -> bool {
    matches!(
        value,
        BUILDX_DEFAULT_IMAGE | "docker.io/moby/buildkit:buildx-stable-1"
    )
}

fn is_buildx_container_name(value: &str) -> bool {
    value
        .strip_prefix(BUILDX_CONTAINER_PREFIX)
        .is_some_and(|suffix| {
            !suffix.is_empty()
                && value.len() <= 128
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        })
}

fn valid_backend_identifier(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn request_image(body: &[u8]) -> Result<Option<String>, ()> {
    let value: Value = serde_json::from_slice(body).map_err(|_| ())?;
    Ok(value
        .get("Image")
        .and_then(Value::as_str)
        .map(str::to_owned))
}

fn decoded_query(target: &str) -> Result<BTreeMap<String, String>, ()> {
    let query = target.split_once('?').map_or("", |(_, query)| query);
    let mut result = BTreeMap::new();
    if query.is_empty() {
        return Ok(result);
    }
    for parameter in query.split('&') {
        let (name, value) = parameter.split_once('=').ok_or(())?;
        let name = percent_decode(name)?;
        let value = percent_decode(value)?;
        if name.is_empty() || result.insert(name, value).is_some() {
            return Err(());
        }
    }
    Ok(result)
}

fn validate_empty_query(target: &str) -> Result<(), ()> {
    decoded_query(target)?.is_empty().then_some(()).ok_or(())
}

fn validate_buildkit_image_pull_query(target: &str) -> Result<(), ()> {
    let query = decoded_query(target)?;
    (query.len() == 2
        && query.get("fromImage").map(String::as_str) == Some(BUILDX_DEFAULT_NORMALIZED_REPOSITORY)
        && query.get("tag").map(String::as_str) == Some(BUILDX_DEFAULT_TAG))
    .then_some(())
    .ok_or(())
}

fn validate_buildkit_create_query(target: &str, name: &str) -> Result<(), ()> {
    let query = decoded_query(target)?;
    (query.len() == 1 && query.get("name").map(String::as_str) == Some(name))
        .then_some(())
        .ok_or(())
}

fn validate_buildkit_logs_query(target: &str) -> Result<(), ()> {
    let query = decoded_query(target)?;
    (query.len() == 2
        && query.get("stdout").map(String::as_str) == Some("1")
        && query.get("stderr").map(String::as_str) == Some("1"))
    .then_some(())
    .ok_or(())
}

fn validate_buildkit_remove_query(target: &str) -> Result<(), ()> {
    let query = decoded_query(target)?;
    let allowed = query.len() <= 2
        && query.get("v").map(String::as_str) == Some("1")
        && query.get("force").is_none_or(|value| value.as_str() == "1")
        && query
            .keys()
            .all(|key| matches!(key.as_str(), "v" | "force"));
    allowed.then_some(()).ok_or(())
}

fn validate_buildkit_archive_query(target: &str) -> Result<(), ()> {
    let query = decoded_query(target)?;
    (query.len() == 2
        && query.get("path").map(String::as_str) == Some(BUILDKIT_CONFIG_ARCHIVE_DESTINATION)
        && query.get("noOverwriteDirNonDir").map(String::as_str) == Some("true"))
    .then_some(())
    .ok_or(())
}

fn require_empty_body(body: &[u8]) -> Result<(), ()> {
    body.is_empty().then_some(()).ok_or(())
}

fn validate_buildkit_command(value: Option<&Value>) -> Result<(), ()> {
    if value.is_none_or(empty_json) {
        return Ok(());
    }
    let command = value.and_then(Value::as_array).ok_or(())?;
    let command = command
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .ok_or(())?;
    (command
        == [
            "--allow-insecure-entitlement",
            "security.insecure",
            "--allow-insecure-entitlement",
            "network.host",
        ])
    .then_some(())
    .ok_or(())
}

fn allowed_buildkit_create_field(field: &str) -> bool {
    matches!(
        field,
        "Hostname"
            | "Domainname"
            | "User"
            | "AttachStdin"
            | "AttachStdout"
            | "AttachStderr"
            | "ExposedPorts"
            | "Tty"
            | "OpenStdin"
            | "StdinOnce"
            | "Env"
            | "Cmd"
            | "Healthcheck"
            | "ArgsEscaped"
            | "Image"
            | "Volumes"
            | "WorkingDir"
            | "Entrypoint"
            | "NetworkDisabled"
            | "OnBuild"
            | "Labels"
            | "StopSignal"
            | "StopTimeout"
            | "Shell"
            | "HostConfig"
            | "NetworkingConfig"
    )
}

fn validate_buildkit_host_config(
    host: &Map<String, Value>,
    expected_volume: &str,
) -> Result<(), ()> {
    if host
        .keys()
        .any(|field| !allowed_buildkit_host_config_field(field))
    {
        return Err(());
    }
    if host.get("Privileged").and_then(Value::as_bool) != Some(true)
        || host.get("Init").and_then(Value::as_bool) != Some(true)
    {
        return Err(());
    }
    for field in [
        "Binds",
        "Devices",
        "DeviceRequests",
        "CapAdd",
        "CapDrop",
        "VolumesFrom",
        "Links",
        "GroupAdd",
        "Sysctls",
        "Tmpfs",
        "SecurityOpt",
        "MaskedPaths",
        "ReadonlyPaths",
        "ExtraHosts",
        "Dns",
        "DnsOptions",
        "DnsSearch",
        "Ulimits",
        "StorageOpt",
        "PortBindings",
        "ContainerIDFile",
        "VolumeDriver",
        "Annotations",
        "Cgroup",
    ] {
        reject_nonempty(host, field)?;
    }
    for field in [
        "AutoRemove",
        "ReadonlyRootfs",
        "PublishAllPorts",
        "OomKillDisable",
    ] {
        reject_true(host, field)?;
    }
    for field in [
        "PidMode",
        "IpcMode",
        "UTSMode",
        "UsernsMode",
        "CgroupnsMode",
        "Runtime",
        "Isolation",
    ] {
        reject_nonempty(host, field)?;
    }
    reject_buildkit_resource_overrides(host)?;
    if let Some(network) = host.get("NetworkMode").and_then(Value::as_str)
        && !network.is_empty()
    {
        return Err(());
    }
    if let Some(cgroup) = host.get("CgroupParent").and_then(Value::as_str)
        && !matches!(cgroup, "" | "/docker/buildx")
    {
        return Err(());
    }
    if let Some(policy) = host.get("RestartPolicy")
        && !policy.is_null()
    {
        let policy = policy.as_object().ok_or(())?;
        if policy
            .keys()
            .any(|key| !matches!(key.as_str(), "Name" | "MaximumRetryCount"))
            || !policy.get("MaximumRetryCount").is_none_or(empty_json)
            || policy.get("Name").and_then(Value::as_str) != Some("unless-stopped")
        {
            return Err(());
        }
    }
    validate_zero_console_size(host.get("ConsoleSize"))?;
    validate_buildkit_mounts(host.get("Mounts"), expected_volume)
}

fn allowed_buildkit_host_config_field(field: &str) -> bool {
    matches!(
        field,
        "Binds"
            | "ContainerIDFile"
            | "LogConfig"
            | "NetworkMode"
            | "PortBindings"
            | "RestartPolicy"
            | "AutoRemove"
            | "VolumeDriver"
            | "VolumesFrom"
            | "ConsoleSize"
            | "Annotations"
            | "CapAdd"
            | "CapDrop"
            | "CgroupnsMode"
            | "Dns"
            | "DnsOptions"
            | "DnsSearch"
            | "ExtraHosts"
            | "GroupAdd"
            | "IpcMode"
            | "Cgroup"
            | "Links"
            | "OomScoreAdj"
            | "PidMode"
            | "Privileged"
            | "PublishAllPorts"
            | "ReadonlyRootfs"
            | "SecurityOpt"
            | "StorageOpt"
            | "Tmpfs"
            | "UTSMode"
            | "UsernsMode"
            | "ShmSize"
            | "Sysctls"
            | "Runtime"
            | "Isolation"
            | "CpuShares"
            | "Memory"
            | "NanoCpus"
            | "CgroupParent"
            | "BlkioWeight"
            | "BlkioWeightDevice"
            | "BlkioDeviceReadBps"
            | "BlkioDeviceWriteBps"
            | "BlkioDeviceReadIOps"
            | "BlkioDeviceWriteIOps"
            | "CpuPeriod"
            | "CpuQuota"
            | "CpuRealtimePeriod"
            | "CpuRealtimeRuntime"
            | "CpusetCpus"
            | "CpusetMems"
            | "Devices"
            | "DeviceCgroupRules"
            | "DeviceRequests"
            | "MemoryReservation"
            | "MemorySwap"
            | "MemorySwappiness"
            | "OomKillDisable"
            | "PidsLimit"
            | "Ulimits"
            | "CpuCount"
            | "CpuPercent"
            | "IOMaximumIOps"
            | "IOMaximumBandwidth"
            | "Mounts"
            | "MaskedPaths"
            | "ReadonlyPaths"
            | "Init"
    )
}

fn validate_zero_console_size(value: Option<&Value>) -> Result<(), ()> {
    match value {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Array(size)) if size.len() == 2 && size.iter().all(empty_json) => Ok(()),
        Some(_) => Err(()),
    }
}

fn reject_buildkit_resource_overrides(host: &Map<String, Value>) -> Result<(), ()> {
    for field in [
        "Memory",
        "MemorySwap",
        "MemoryReservation",
        "KernelMemory",
        "CpuPeriod",
        "CpuQuota",
        "CpuShares",
        "NanoCpus",
        "CpuRealtimePeriod",
        "CpuRealtimeRuntime",
        "CpusetCpus",
        "CpusetMems",
        "PidsLimit",
        "ShmSize",
        "OomScoreAdj",
        "IOMaximumIOps",
        "IOMaximumBandwidth",
        "BlkioWeight",
        "BlkioWeightDevice",
        "BlkioDeviceReadBps",
        "BlkioDeviceWriteBps",
        "BlkioDeviceReadIOps",
        "BlkioDeviceWriteIOps",
        "DeviceCgroupRules",
        "MemorySwappiness",
        "CpuCount",
        "CpuPercent",
        // Reject alternate JSON casing too, so a duplicate key cannot win in
        // a backend with case-insensitive Go decoding.
        "CPUPeriod",
        "CPUQuota",
        "CPUShares",
    ] {
        reject_nonempty(host, field)?;
    }
    Ok(())
}

fn validate_buildkit_mounts(value: Option<&Value>, expected_volume: &str) -> Result<(), ()> {
    let mounts = value.and_then(Value::as_array).ok_or(())?;
    if mounts.len() != 1 {
        return Err(());
    }
    let mount = mounts[0].as_object().ok_or(())?;
    if mount.keys().any(|field| {
        !matches!(
            field.as_str(),
            "Type"
                | "Source"
                | "Target"
                | "ReadOnly"
                | "Consistency"
                | "BindOptions"
                | "VolumeOptions"
                | "TmpfsOptions"
                | "ImageOptions"
                | "ClusterOptions"
        )
    }) || mount.get("Type").and_then(Value::as_str) != Some("volume")
        || mount.get("Source").and_then(Value::as_str) != Some(expected_volume)
        || mount.get("Target").and_then(Value::as_str) != Some(BUILDKIT_STATE_DIRECTORY)
        || mount
            .get("ReadOnly")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || mount
            .get("Consistency")
            .is_some_and(|value| !empty_json(value))
        || [
            "BindOptions",
            "VolumeOptions",
            "TmpfsOptions",
            "ImageOptions",
            "ClusterOptions",
        ]
        .into_iter()
        .any(|field| mount.get(field).is_some_and(|value| !empty_json(value)))
    {
        return Err(());
    }
    Ok(())
}

fn validate_buildkit_exec_create(body: &[u8]) -> Result<(), ()> {
    let value: Value = serde_json::from_slice(body).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    if object.keys().any(|field| {
        !matches!(
            field.as_str(),
            "User"
                | "Privileged"
                | "Tty"
                | "ConsoleSize"
                | "AttachStdin"
                | "AttachStderr"
                | "AttachStdout"
                | "DetachKeys"
                | "Env"
                | "WorkingDir"
                | "Cmd"
        )
    }) || object.get("AttachStdin").and_then(Value::as_bool) != Some(true)
        || object.get("AttachStdout").and_then(Value::as_bool) != Some(true)
        || object.get("AttachStderr").and_then(Value::as_bool) != Some(true)
    {
        return Err(());
    }
    for field in [
        "User",
        "Privileged",
        "Tty",
        "ConsoleSize",
        "DetachKeys",
        "Env",
        "WorkingDir",
    ] {
        if object.get(field).is_some_and(|value| !empty_json(value)) {
            return Err(());
        }
    }
    let command = object
        .get("Cmd")
        .and_then(Value::as_array)
        .ok_or(())?
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .ok_or(())?;
    matches!(
        command.as_slice(),
        ["buildctl", "debug", "workers"] | ["buildkitd", "--version"] | ["buildctl", "dial-stdio"]
    )
    .then_some(())
    .ok_or(())
}

fn validate_buildkit_exec_start(body: &[u8]) -> Result<(), ()> {
    let value: Value = serde_json::from_slice(body).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    if object
        .keys()
        .any(|field| !matches!(field.as_str(), "Detach" | "Tty" | "ConsoleSize"))
    {
        return Err(());
    }
    for field in ["Detach", "Tty", "ConsoleSize"] {
        if object.get(field).is_some_and(|value| !empty_json(value)) {
            return Err(());
        }
    }
    Ok(())
}

fn validate_buildkit_config_archive(body: &[u8]) -> Result<(), ()> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(body));
    let mut provenance_seen = false;
    for entry in archive.entries().map_err(|_| ())? {
        let mut entry = entry.map_err(|_| ())?;
        let header = entry.header();
        let path = entry.path().map_err(|_| ())?;
        let path = path.to_str().ok_or(())?.trim_end_matches('/');
        let mode = header.mode().map_err(|_| ())?;
        if header.uid().map_err(|_| ())? != 0
            || header.gid().map_err(|_| ())? != 0
            || mode & !0o755 != 0
        {
            return Err(());
        }
        if header.entry_type().is_dir() {
            if !matches!(path, "buildkit" | "buildkit/provenance.d") || mode != 0o755 {
                return Err(());
            }
            continue;
        }
        if !header.entry_type().is_file()
            || path != BUILDKIT_GHA_PROVENANCE_FILE
            || provenance_seen
            || mode != 0o644
        {
            return Err(());
        }
        let mut payload = Vec::new();
        entry.read_to_end(&mut payload).map_err(|_| ())?;
        let context: Value = serde_json::from_slice(&payload).map_err(|_| ())?;
        if !context.is_object() {
            return Err(());
        }
        provenance_seen = true;
    }
    Ok(())
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

fn object_field_or_empty<'a>(
    object: &'a mut Map<String, Value>,
    field: &str,
) -> Result<&'a mut Map<String, Value>, ()> {
    let value = object
        .entry(field.to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if value.is_null() {
        *value = Value::Object(Map::new());
    }
    value.as_object_mut().ok_or(())
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

fn force_job_local_log_config(host: &mut Map<String, Value>) -> Result<(), ()> {
    if let Some(value) = host.remove("LogConfig")
        && !value.is_null()
    {
        let supplied = value.as_object().ok_or(())?;
        if supplied
            .keys()
            .any(|field| !matches!(field.as_str(), "Type" | "Config"))
        {
            return Err(());
        }
        match supplied.get("Type") {
            None => {}
            Some(Value::String(driver)) if driver.is_empty() || driver == JOB_LOCAL_LOG_DRIVER => {}
            Some(_) => return Err(()),
        }
        match supplied.get("Config") {
            None | Some(Value::Null) => {}
            Some(Value::Object(options)) if options.is_empty() => {}
            Some(_) => return Err(()),
        }
    }
    host.insert(
        "LogConfig".to_owned(),
        json!({"Type": JOB_LOCAL_LOG_DRIVER, "Config": {}}),
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn handle_connection(
    mut client: UnixStream,
    backend_socket: &Path,
    policy: &ProxyPolicy,
    observer: &dyn PodmanObserver,
) -> io::Result<()> {
    let header = match read_header(&mut client) {
        Ok(header) => header,
        Err(error) => {
            observer.observe(PodmanEvent::DockerRejected {
                reason: DockerProxyRejection::MalformedHead,
            });
            return Err(error);
        }
    };
    let Ok(parsed) = ParsedHeader::parse(&header) else {
        observer.observe(PodmanEvent::DockerRejected {
            reason: DockerProxyRejection::MalformedHead,
        });
        return send_rejection(&mut client, 400, "malformed Docker API request");
    };
    let route = DockerRoute::parse(&parsed.method, &parsed.target);
    let is_build = route
        .as_ref()
        .is_ok_and(|route| matches!(route, DockerRoute::Build));
    let is_archive = route.as_ref().is_ok_and(|route| {
        matches!(
            route,
            DockerRoute::ContainerOperation {
                operation: ContainerOperation::Archive,
                ..
            }
        )
    });
    let Ok(route) = route else {
        observer.observe(PodmanEvent::DockerRejected {
            reason: DockerProxyRejection::Policy,
        });
        return send_rejection(&mut client, 403, "Docker API operation is not allowed");
    };
    let mut observation = DockerRequestObservation::new(observer, route.metric_route());
    if parsed.chunked && !is_build && !is_archive {
        observer.observe(PodmanEvent::DockerRejected {
            reason: DockerProxyRejection::UnsupportedTransfer,
        });
        observation.complete(DockerProxyOutcome::Rejected, 0);
        return send_rejection(
            &mut client,
            400,
            "chunked body is not accepted for this Docker API operation",
        );
    }
    if is_build && !parsed.chunked && parsed.content_length as u64 > MAX_BUILD_CONTEXT_BYTES {
        observer.observe(PodmanEvent::DockerRejected {
            reason: DockerProxyRejection::RequestTooLarge,
        });
        observation.complete(DockerProxyOutcome::Rejected, 0);
        return send_rejection(&mut client, 413, "Docker build context is too large");
    }
    let body = if is_build {
        Vec::new()
    } else if is_archive && parsed.chunked {
        let Ok(body) = read_chunked_body(&mut client, MAX_CONTROL_BODY_BYTES) else {
            observer.observe(PodmanEvent::DockerRejected {
                reason: DockerProxyRejection::RequestTooLarge,
            });
            observation.complete(DockerProxyOutcome::Rejected, 0);
            return send_rejection(&mut client, 413, "Docker API request is too large");
        };
        body
    } else {
        let Ok(body) = read_fixed_body(&mut client, parsed.content_length, MAX_CONTROL_BODY_BYTES)
        else {
            observer.observe(PodmanEvent::DockerRejected {
                reason: DockerProxyRejection::RequestTooLarge,
            });
            observation.complete(DockerProxyOutcome::Rejected, 0);
            return send_rejection(&mut client, 413, "Docker API request is too large");
        };
        body
    };
    observation.add_request_bytes(u64::try_from(body.len()).unwrap_or(u64::MAX));
    let Ok(authorized) = policy.authorize(&parsed.method, &parsed.target, &body) else {
        observer.observe(PodmanEvent::DockerRejected {
            reason: DockerProxyRejection::Policy,
        });
        observation.complete(DockerProxyOutcome::Rejected, 0);
        return send_rejection(&mut client, 403, "Docker API operation is not allowed");
    };
    let mut reservation = authorized
        .buildkit_container_reservation
        .as_ref()
        .map(|name| BuildKitContainerReservation {
            policy,
            name: name.clone(),
            active: true,
        });

    if matches!(&authorized.response, ResponseTransform::SyntheticImagePull) {
        let response_bytes = send_synthetic_buildkit_pull(&mut client)?;
        observation.complete(DockerProxyOutcome::Forwarded, response_bytes);
        return Ok(());
    }

    let mut backend = UnixStream::connect(backend_socket)?;
    let upgrade = parsed.upgrade;
    let upgrade_protocol = parsed.upgrade_protocol().map(str::to_owned);
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
        let bytes = copy_chunked(&mut client, &mut backend, MAX_BUILD_CONTEXT_BYTES)?;
        observation.add_request_bytes(bytes);
    } else if is_build {
        let bytes = copy_fixed(
            &mut client,
            &mut backend,
            parsed.content_length as u64,
            MAX_BUILD_CONTEXT_BYTES,
        )?;
        observation.add_request_bytes(bytes);
    } else {
        backend.write_all(&authorized.body)?;
    }
    backend.flush()?;

    if upgrade {
        let (request_bytes, response_bytes) = forward_upgrade_response(
            client,
            backend,
            upgrade_protocol.as_deref(),
            parsed.method == "HEAD",
        )?;
        observation.add_request_bytes(request_bytes);
        observation.complete(DockerProxyOutcome::Forwarded, response_bytes);
        return Ok(());
    }
    match authorized.response {
        ResponseTransform::Passthrough => {
            let response_bytes = io::copy(&mut backend, &mut client)?;
            observation.complete(DockerProxyOutcome::Forwarded, response_bytes);
            Ok(())
        }
        ResponseTransform::SyntheticImagePull => unreachable!("handled before backend connect"),
        ResponseTransform::RewriteInfo => {
            let mut response = read_response(&mut backend, MAX_CONTROL_BODY_BYTES)?;
            if response.success() {
                response.body = ProxyPolicy::rewrite_info(&response.body)
                    .map_err(|()| io::Error::other("invalid Docker info response"))?;
            }
            let response_bytes = u64::try_from(response.body.len()).unwrap_or(u64::MAX);
            response.write_to(&mut client)?;
            observation.complete(DockerProxyOutcome::Forwarded, response_bytes);
            Ok(())
        }
        ResponseTransform::RewriteBuildKitImageInspect => {
            let mut response = read_response(&mut backend, MAX_CONTROL_BODY_BYTES)?;
            policy
                .rewrite_buildkit_image_inspect_response(&mut response)
                .map_err(|()| io::Error::other("invalid BuildKit image inspect response"))?;
            let response_bytes = u64::try_from(response.body.len()).unwrap_or(u64::MAX);
            response.write_to(&mut client)?;
            observation.complete(DockerProxyOutcome::Forwarded, response_bytes);
            Ok(())
        }
        ResponseTransform::InspectBuildKitCandidate { name } => {
            let response = read_response(&mut backend, MAX_CONTROL_BODY_BYTES)?;
            if response.success() {
                policy
                    .adopt_buildkit_container(&name, &response.body)
                    .map_err(|()| io::Error::other("unowned BuildKit container response"))?;
            }
            let response_bytes = u64::try_from(response.body.len()).unwrap_or(u64::MAX);
            response.write_to(&mut client)?;
            observation.complete(DockerProxyOutcome::Forwarded, response_bytes);
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
            let response_bytes = u64::try_from(response.body.len()).unwrap_or(u64::MAX);
            response.write_to(&mut client)?;
            observation.complete(DockerProxyOutcome::Forwarded, response_bytes);
            Ok(())
        }
        ResponseTransform::RewriteInspect { identifier } => {
            let mut response = read_response(&mut backend, MAX_CONTROL_BODY_BYTES)?;
            if response.success() {
                response.body = policy
                    .rewrite_inspect(&identifier, &response.body)
                    .map_err(|()| io::Error::other("invalid Docker inspect response"))?;
            }
            let response_bytes = u64::try_from(response.body.len()).unwrap_or(u64::MAX);
            response.write_to(&mut client)?;
            observation.complete(DockerProxyOutcome::Forwarded, response_bytes);
            Ok(())
        }
        ResponseTransform::RecordBuildKitContainer { name } => {
            let response = read_response(&mut backend, MAX_CONTROL_BODY_BYTES)?;
            let identifier = response
                .success()
                .then(|| {
                    response.json_body().and_then(|value| {
                        value.get("Id").and_then(Value::as_str).map(str::to_owned)
                    })
                })
                .flatten();
            policy
                .finish_buildkit_container_create(&name, identifier)
                .map_err(|()| io::Error::other("BuildKit container policy state is unavailable"))?;
            if let Some(reservation) = reservation.as_mut() {
                reservation.commit();
            }
            let response_bytes = u64::try_from(response.body.len()).unwrap_or(u64::MAX);
            response.write_to(&mut client)?;
            observation.complete(DockerProxyOutcome::Forwarded, response_bytes);
            Ok(())
        }
        ResponseTransform::RecordBuildKitExec => {
            let response = read_response(&mut backend, MAX_CONTROL_BODY_BYTES)?;
            if response.success() {
                let identifier = response
                    .json_body()
                    .and_then(|value| value.get("Id").and_then(Value::as_str).map(str::to_owned))
                    .ok_or_else(|| io::Error::other("invalid BuildKit exec response"))?;
                policy
                    .record_buildkit_exec(&identifier)
                    .map_err(|()| io::Error::other("BuildKit exec policy state is unavailable"))?;
            }
            let response_bytes = u64::try_from(response.body.len()).unwrap_or(u64::MAX);
            response.write_to(&mut client)?;
            observation.complete(DockerProxyOutcome::Forwarded, response_bytes);
            Ok(())
        }
    }
}

struct DockerRequestObservation<'a> {
    observer: &'a dyn PodmanObserver,
    route: DockerProxyRoute,
    started: Instant,
    request_bytes: u64,
    completed: bool,
}

impl<'a> DockerRequestObservation<'a> {
    fn new(observer: &'a dyn PodmanObserver, route: DockerProxyRoute) -> Self {
        observer.observe(PodmanEvent::DockerRequestStarted { route });
        Self {
            observer,
            route,
            started: Instant::now(),
            request_bytes: 0,
            completed: false,
        }
    }

    fn add_request_bytes(&mut self, bytes: u64) {
        self.request_bytes = self.request_bytes.saturating_add(bytes);
    }

    fn complete(&mut self, outcome: DockerProxyOutcome, response_bytes: u64) {
        if self.completed {
            return;
        }
        self.observer.observe(PodmanEvent::DockerRequestCompleted {
            route: self.route,
            outcome,
            duration: self.started.elapsed(),
            request_bytes: self.request_bytes,
            response_bytes,
        });
        self.completed = true;
    }
}

impl Drop for DockerRequestObservation<'_> {
    fn drop(&mut self) {
        self.complete(DockerProxyOutcome::IoError, 0);
    }
}

fn relay_upgraded(client: UnixStream, backend: UnixStream) -> io::Result<(u64, u64)> {
    relay_upgraded_with_drain_timeout(client, backend, UPGRADED_BACKEND_EOF_DRAIN_TIMEOUT)
}

fn relay_upgraded_with_drain_timeout(
    mut client: UnixStream,
    mut backend: UnixStream,
    drain_timeout: Duration,
) -> io::Result<(u64, u64)> {
    let mut client_reader = client.try_clone()?;
    let mut backend_writer = backend.try_clone()?;
    let hangup_client = client.try_clone()?;
    let hangup_backend = backend.try_clone()?;
    let (mut cancel_hangup, hangup_cancelled) = UnixStream::pair()?;
    let hangup = thread::Builder::new()
        .name("automata-docker-hangup".to_owned())
        .stack_size(UPGRADED_RELAY_THREAD_STACK_BYTES)
        .spawn(move || {
            supervise_client_hangup(&hangup_client, &hangup_backend, &hangup_cancelled)
        })?;
    let (upload_finished, wait_for_upload) = mpsc::channel();
    let upload = match thread::Builder::new()
        .name("automata-docker-upload".to_owned())
        .stack_size(UPGRADED_RELAY_THREAD_STACK_BYTES)
        .spawn(move || {
            let result = io::copy(&mut client_reader, &mut backend_writer);
            let _ignored = backend_writer.shutdown(std::net::Shutdown::Write);
            let _ignored = upload_finished.send(());
            result
        }) {
        Ok(upload) => upload,
        Err(error) => {
            let _ignored = client.shutdown(std::net::Shutdown::Both);
            let _ignored = backend.shutdown(std::net::Shutdown::Both);
            let _ignored = cancel_hangup.write_all(&[0]);
            let _ignored = hangup.join();
            return Err(error);
        }
    };
    let download = io::copy(&mut backend, &mut client);
    let _ignored = client.shutdown(std::net::Shutdown::Write);
    let _ignored = cancel_hangup.write_all(&[0]);
    let hangup = hangup
        .join()
        .map_err(|_| io::Error::other("Docker API hangup supervisor failed"));
    if wait_for_upload.recv_timeout(drain_timeout).is_err() {
        let _ignored = client.shutdown(std::net::Shutdown::Read);
        let _ignored = backend.shutdown(std::net::Shutdown::Write);
    }
    let upload = upload
        .join()
        .map_err(|_| io::Error::other("Docker API relay worker failed"))?;
    let upload = upload?;
    let hangup = hangup?;
    hangup?;
    download.map(|download| (upload, download))
}

fn supervise_client_hangup(
    client: &UnixStream,
    backend: &UnixStream,
    cancelled: &UnixStream,
) -> io::Result<()> {
    loop {
        let mut descriptors = [
            // HUP and ERR are reported even when they are not requested.
            // Deliberately request no client readiness bit: Linux RDHUP is
            // attach stdin EOF and must not terminate backend output.
            PollFd::new(&client, PollFlags::empty()),
            PollFd::new(&cancelled, PollFlags::IN),
        ];
        if let Err(error) = poll(&mut descriptors, None) {
            if error == rustix::io::Errno::INTR {
                continue;
            }
            let _ignored = backend.shutdown(std::net::Shutdown::Both);
            return Err(io::Error::from(error));
        }
        let cancellation = descriptors[1].revents();
        if cancellation.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) {
            return Ok(());
        }
        let client_ready = descriptors[0].revents();
        if client_ready.intersects(PollFlags::HUP | PollFlags::ERR) {
            let _ignored = backend.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }
    }
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
            || !matches!(method, "GET" | "HEAD" | "POST" | "PUT" | "DELETE")
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

    fn upgrade_protocol(&self) -> Option<&str> {
        let mut protocols = self
            .fields
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("upgrade"))
            .map(|(_, value)| value.as_str());
        let protocol = protocols.next()?;
        if protocols.next().is_some() || !valid_http_token(protocol) {
            return None;
        }
        Some(protocol)
    }
}

fn valid_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
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
) -> io::Result<u64> {
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
                    return Ok(total);
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
) -> io::Result<u64> {
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
    Ok(copied)
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
enum BackendUpgradeResponse {
    SwitchingProtocols(Vec<u8>),
    Ordinary {
        response: BufferedResponse,
        content_length: usize,
    },
}

fn forward_upgrade_response(
    mut client: UnixStream,
    mut backend: UnixStream,
    expected_protocol: Option<&str>,
    request_is_head: bool,
) -> io::Result<(u64, u64)> {
    match read_backend_upgrade_response_supervised(
        &client,
        &mut backend,
        expected_protocol,
        request_is_head,
    )? {
        BackendUpgradeResponse::SwitchingProtocols(header) => {
            client.write_all(&header)?;
            client.flush()?;
            let response_header_bytes = u64::try_from(header.len()).unwrap_or(u64::MAX);
            relay_upgraded(client, backend).map(|(request_bytes, response_bytes)| {
                (
                    request_bytes,
                    response_header_bytes.saturating_add(response_bytes),
                )
            })
        }
        BackendUpgradeResponse::Ordinary {
            response,
            content_length,
        } => {
            let _ignored = backend.shutdown(std::net::Shutdown::Both);
            let response_bytes = u64::try_from(response.body.len()).unwrap_or(u64::MAX);
            response.write_to_with_content_length(&mut client, content_length)?;
            client.flush()?;
            let _ignored = client.shutdown(std::net::Shutdown::Write);
            drain_rejected_upgrade_request(&mut client);
            Ok((0, response_bytes))
        }
    }
}

fn drain_rejected_upgrade_request(client: &mut UnixStream) {
    if client
        .set_read_timeout(Some(REJECTED_UPGRADE_DRAIN_TIMEOUT))
        .is_err()
    {
        return;
    }
    let _ignored = io::copy(
        &mut client.take(MAX_REJECTED_UPGRADE_DRAIN_BYTES),
        &mut io::sink(),
    );
}

fn read_backend_upgrade_response_supervised(
    client: &UnixStream,
    backend: &mut UnixStream,
    expected_protocol: Option<&str>,
    request_is_head: bool,
) -> io::Result<BackendUpgradeResponse> {
    let hangup_client = client.try_clone()?;
    let hangup_backend = backend.try_clone()?;
    let (mut cancel_hangup, hangup_cancelled) = UnixStream::pair()?;
    let hangup = thread::Builder::new()
        .name("automata-docker-handshake-hangup".to_owned())
        .stack_size(UPGRADED_RELAY_THREAD_STACK_BYTES)
        .spawn(move || {
            supervise_client_hangup(&hangup_client, &hangup_backend, &hangup_cancelled)
        })?;
    let response = read_backend_upgrade_response(backend, expected_protocol, request_is_head);
    let _ignored = cancel_hangup.write_all(&[0]);
    let hangup = hangup
        .join()
        .map_err(|_| io::Error::other("Docker API handshake supervisor failed"))?;
    hangup?;
    response
}

fn read_backend_upgrade_response(
    backend: &mut UnixStream,
    expected_protocol: Option<&str>,
    request_is_head: bool,
) -> io::Result<BackendUpgradeResponse> {
    let header = read_header(backend)?;
    let response = parse_backend_response_head(&header)?;
    if response.status == 101 {
        let protocol_matches = expected_protocol
            .zip(response.upgrade_protocol.as_deref())
            .is_some_and(|(expected, actual)| expected.eq_ignore_ascii_case(actual));
        if !response.connection_upgrade
            || !protocol_matches
            || response.content_length.is_some()
            || response.chunked
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid backend upgrade response",
            ));
        }
        return Ok(BackendUpgradeResponse::SwitchingProtocols(header));
    }
    let body_allowed = !request_is_head
        && !(100..=199).contains(&response.status)
        && !matches!(response.status, 204 | 304);
    let body = if !body_allowed {
        Vec::new()
    } else if response.chunked {
        read_chunked_body(backend, MAX_CONTROL_BODY_BYTES)?
    } else {
        read_fixed_body(
            backend,
            response.content_length.unwrap_or(0),
            MAX_CONTROL_BODY_BYTES,
        )?
    };
    let content_length = if request_is_head || response.status == 304 {
        response.content_length.unwrap_or(0)
    } else {
        body.len()
    };
    Ok(BackendUpgradeResponse::Ordinary {
        response: BufferedResponse {
            status_line: response.status_line,
            fields: response.fields,
            body,
        },
        content_length,
    })
}

struct BackendResponseHead {
    status_line: String,
    status: u16,
    fields: Vec<(String, String)>,
    content_length: Option<usize>,
    chunked: bool,
    connection_upgrade: bool,
    upgrade_protocol: Option<String>,
}

fn parse_backend_response_head(header: &[u8]) -> io::Result<BackendResponseHead> {
    let text = std::str::from_utf8(header)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid backend response"))?;
    let mut lines = text
        .strip_suffix("\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid backend response"))?
        .split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid backend status"))?;
    let status = parse_backend_status(status_line)?;
    let mut response = BackendResponseHead {
        status_line: status_line.to_owned(),
        status,
        fields: Vec::new(),
        content_length: None,
        chunked: false,
        connection_upgrade: false,
        upgrade_protocol: None,
    };
    for line in lines {
        parse_backend_response_field(&mut response, line)?;
    }
    if response.chunked && response.content_length.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ambiguous backend response framing",
        ));
    }
    Ok(response)
}

fn parse_backend_status(status_line: &str) -> io::Result<u16> {
    if !status_line
        .bytes()
        .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid backend status",
        ));
    }
    status_line
        .strip_prefix("HTTP/1.1 ")
        .and_then(|status| status.split_once(' ').map(|(code, _)| code))
        .filter(|status| status.len() == 3 && status.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|status| status.parse::<u16>().ok())
        .filter(|status| (100..=599).contains(status))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid backend status"))
}

fn parse_backend_response_field(response: &mut BackendResponseHead, line: &str) -> io::Result<()> {
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid backend header"))?;
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid backend header",
        ));
    }
    let value = value.trim().to_owned();
    if name.eq_ignore_ascii_case("content-length") {
        if response.content_length.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid backend length",
            ));
        }
        response.content_length =
            Some(value.parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid backend length")
            })?);
    } else if name.eq_ignore_ascii_case("transfer-encoding") {
        if response.chunked || !value.eq_ignore_ascii_case("chunked") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid backend transfer encoding",
            ));
        }
        response.chunked = true;
    } else if name.eq_ignore_ascii_case("connection") {
        for token in value.split(',').map(str::trim) {
            if !valid_http_token(token) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid backend connection header",
                ));
            }
            response.connection_upgrade |= token.eq_ignore_ascii_case("upgrade");
        }
    } else if name.eq_ignore_ascii_case("upgrade") {
        if response.upgrade_protocol.is_some() || !valid_http_token(&value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid backend upgrade header",
            ));
        }
        response.upgrade_protocol = Some(value.clone());
    }
    response.fields.push((name.to_owned(), value));
    Ok(())
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
        self.write_to_with_content_length(destination, self.body.len())
    }

    fn write_to_with_content_length(
        &self,
        destination: &mut UnixStream,
        content_length: usize,
    ) -> io::Result<()> {
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
        destination.write_all(format!("Content-Length: {content_length}\r\n").as_bytes())?;
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

fn read_chunked_body<R: io::Read>(stream: &mut R, maximum: usize) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = read_crlf_line(stream, 128)?;
        let size_text = std::str::from_utf8(&line[..line.len() - 2])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or(""), 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        if size == 0 {
            let mut trailer_bytes = 0_usize;
            loop {
                let remaining = MAX_HEADER_BYTES.checked_sub(trailer_bytes).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "backend response trailers exceeded their limit",
                    )
                })?;
                if remaining == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "backend response trailers exceeded their limit",
                    ));
                }
                let trailer = read_crlf_line(stream, remaining)?;
                trailer_bytes += trailer.len();
                if trailer == b"\r\n" {
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

fn send_synthetic_buildkit_pull(stream: &mut UnixStream) -> io::Result<u64> {
    let body = b"{\"status\":\"Image is available from the verified local store\"}\r\n";
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    Ok(u64::try_from(body.len()).unwrap_or(u64::MAX))
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

fn validate_build_query(query: &str) -> Result<(), ()> {
    if query.is_empty() {
        return Ok(());
    }

    let mut seen = BTreeSet::new();
    for parameter in query.split('&') {
        let (encoded_name, encoded_value) = parameter.split_once('=').ok_or(())?;
        let name = percent_decode(encoded_name)?;
        let value = percent_decode(encoded_value)?;
        if !DISTRIBUTION_BUILD_QUERY_PARAMETERS.contains(&name.as_str())
            || !seen.insert(name.clone())
        {
            return Err(());
        }
        match name.as_str() {
            "dockerfile" if is_safe_build_context_path(&value) => {}
            "q" | "version" if value == "1" => {}
            "t" if is_safe_local_image_tag(&value) => {}
            _ => return Err(()),
        }
    }
    Ok(())
}

fn is_safe_build_context_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn is_safe_local_image_tag(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
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
                let decoded = (high << 4) | low;
                if decoded.is_ascii_control() {
                    return Err(());
                }
                result.push(decoded);
                index += 3;
            }
            b'%' => return Err(()),
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

#[cfg(test)]
#[path = "../tests/support/docker_policy.rs"]
mod tests;

#[cfg(test)]
mod observer_tests {
    use std::{
        fs,
        io::{Read as _, Write as _},
        path::PathBuf,
        sync::{
            Mutex, PoisonError,
            atomic::{AtomicU64, Ordering as AtomicOrdering},
        },
    };

    use automata_ci_execution::ProviderId;

    use super::*;

    static NEXT_BACKEND_SOCKET: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug, Default)]
    struct CapturingObserver(Mutex<Vec<PodmanEvent>>);

    impl CapturingObserver {
        fn events(&self) -> Vec<PodmanEvent> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl PodmanObserver for CapturingObserver {
        fn observe(&self, event: PodmanEvent) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(event);
        }
    }

    #[derive(Debug)]
    struct StaticLaunchValidator(bool);

    impl DockerLaunchValidator for StaticLaunchValidator {
        fn validate(&self) -> bool {
            self.0
        }
    }

    fn policy() -> ProxyPolicy {
        policy_with_launch_validation(true)
    }

    fn policy_with_launch_validation(valid: bool) -> ProxyPolicy {
        let provider = ProviderId::new("observer-test").expect("provider");
        let sandbox = SandboxHandle::new(provider, "private-sandbox-sentinel").expect("sandbox");
        ProxyPolicy::new_with_validator(
            &sandbox,
            42,
            "/observer.slice".to_owned(),
            ResourceLimits::new(16 * 1024 * 1024, 1_000, 32).expect("resources"),
            Arc::new(StaticLaunchValidator(valid)),
            None,
        )
    }

    fn buildkit_policy() -> ProxyPolicy {
        let provider = ProviderId::new("observer-test").expect("provider");
        let sandbox = SandboxHandle::new(provider, "private-sandbox-sentinel").expect("sandbox");
        ProxyPolicy::new_with_validator(
            &sandbox,
            42,
            "/observer.slice".to_owned(),
            ResourceLimits::new(16 * 1024 * 1024, 1_000, 32).expect("resources"),
            Arc::new(StaticLaunchValidator(true)),
            Some(format!(
                "registry.example.invalid/buildkit/runtime@sha256:{}",
                "66".repeat(32)
            )),
        )
    }

    fn send_request(mut stream: UnixStream, request: &'static [u8]) -> Vec<u8> {
        stream.write_all(request).expect("write request");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("finish request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response");
        response
    }

    fn send_owned_request(mut stream: UnixStream, request: &[u8]) -> Vec<u8> {
        stream.write_all(request).expect("write request");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("finish request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response");
        response
    }

    fn request(method: &str, target: &str, body: &[u8]) -> Vec<u8> {
        let mut request = format!(
            "{method} {target} HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        request
    }

    fn buildkit_create_request_body(name: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "Image": BUILDX_DEFAULT_IMAGE,
            "Cmd": [
                "--allow-insecure-entitlement",
                "security.insecure",
                "--allow-insecure-entitlement",
                "network.host"
            ],
            "Labels": null,
            "HostConfig": {
                "Privileged": true,
                "Init": true,
                "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
                "Mounts": [{
                    "Type": "volume",
                    "Source": format!("{name}_state"),
                    "Target": BUILDKIT_STATE_DIRECTORY,
                    "ReadOnly": false
                }]
            }
        }))
        .expect("create body")
    }

    fn buildkit_exec_request_body() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "AttachStdin": true,
            "AttachStdout": true,
            "AttachStderr": true,
            "Cmd": ["buildctl", "dial-stdio"]
        }))
        .expect("exec body")
    }

    fn serve_buildkit_lifecycle(
        listener: UnixListener,
        container_id: String,
        exec_id: String,
    ) -> thread::JoinHandle<Vec<(String, Vec<u8>)>> {
        thread::spawn(move || {
            let mut captured = Vec::new();
            for index in 0..7 {
                let (mut connection, _) = listener.accept().expect("backend connection");
                let header = read_header(&mut connection).expect("backend request header");
                let parsed = ParsedHeader::parse(&header).expect("backend parsed header");
                let body = read_fixed_body(
                    &mut connection,
                    parsed.content_length,
                    MAX_CONTROL_BODY_BYTES,
                )
                .expect("backend request body");
                captured.push((parsed.target, body));
                let response_body = match index {
                    0 => serde_json::to_vec(&json!({"Id": container_id}))
                        .expect("container response"),
                    2 => serde_json::to_vec(&json!({"Id": exec_id})).expect("exec response"),
                    3 => b"{\"Running\":true}".to_vec(),
                    _ => Vec::new(),
                };
                write!(
                    connection,
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    if index == 0 { "201 Created" } else { "200 OK" },
                    response_body.len()
                )
                .expect("backend response header");
                connection
                    .write_all(&response_body)
                    .expect("backend response body");
            }
            captured
        })
    }

    fn temporary_backend_socket() -> PathBuf {
        std::env::temp_dir().join(format!(
            "automata-podman-backend-{}-{}.sock",
            std::process::id(),
            NEXT_BACKEND_SOCKET.fetch_add(1, AtomicOrdering::Relaxed),
        ))
    }

    #[test]
    fn route_in_flight_is_paired_on_backend_io_error_with_complete_request_bytes() {
        let observer = CapturingObserver::default();
        let policy = policy();
        let (client, server) = UnixStream::pair().expect("socket pair");
        let worker = thread::spawn(move || {
            send_request(
                client,
                b"POST /v1.44/containers/create HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
            )
        });
        let missing = PathBuf::from("/definitely-missing-automata-docker-observer.sock");
        assert!(handle_connection(server, &missing, &policy, &observer).is_err());
        assert!(worker.join().expect("client worker").is_empty());

        let events = observer.events();
        assert!(events.iter().any(|event| matches!(
            event,
            PodmanEvent::DockerRequestStarted {
                route: DockerProxyRoute::ContainerCreate
            }
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            PodmanEvent::DockerRequestCompleted {
                route: DockerProxyRoute::ContainerCreate,
                outcome: DockerProxyOutcome::IoError,
                request_bytes: 2,
                response_bytes: 0,
                ..
            }
        )));
        let debug = format!("{events:?}");
        assert!(!debug.contains("private-sandbox-sentinel"));
        assert!(!debug.contains("definitely-missing"));
    }

    #[test]
    fn malformed_head_emits_only_the_closed_rejection_reason() {
        let observer = CapturingObserver::default();
        let policy = policy();
        let (client, server) = UnixStream::pair().expect("socket pair");
        let worker = thread::spawn(move || send_request(client, b"private-value\r\n\r\n"));
        handle_connection(
            server,
            Path::new("/unused-for-malformed-request"),
            &policy,
            &observer,
        )
        .expect("malformed request receives a rejection");
        let response = worker.join().expect("client worker");
        assert!(response.starts_with(b"HTTP/1.1 400"));
        let events = observer.events();
        assert_eq!(
            events,
            vec![PodmanEvent::DockerRejected {
                reason: DockerProxyRejection::MalformedHead,
            }]
        );
        assert!(!format!("{events:?}").contains("private-value"));
    }

    #[test]
    fn launch_trust_drift_rejects_before_connecting_to_the_backend() {
        let observer = CapturingObserver::default();
        let policy = policy_with_launch_validation(false);
        let (client, server) = UnixStream::pair().expect("socket pair");
        let worker = thread::spawn(move || {
            send_request(client, b"GET /_ping HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
        });
        handle_connection(
            server,
            Path::new("/definitely-missing-launch-trust-backend.sock"),
            &policy,
            &observer,
        )
        .expect("failed launch trust must reject without a backend connection");
        let response = worker.join().expect("client worker");
        assert!(response.starts_with(b"HTTP/1.1 403"));
    }

    #[test]
    fn buildkit_pull_is_disabled_by_default_and_verified_alias_never_contacts_backend() {
        const PULL: &[u8] = b"POST /v1.44/images/create?fromImage=docker.io%2Fmoby%2Fbuildkit&tag=buildx-stable-1 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let missing = Path::new("/definitely-missing-buildkit-backend.sock");

        let observer = CapturingObserver::default();
        let policy = policy();
        let (client, server) = UnixStream::pair().expect("socket pair");
        let worker = thread::spawn(move || send_request(client, PULL));
        handle_connection(server, missing, &policy, &observer)
            .expect("disabled BuildKit route is rejected locally");
        assert!(
            worker
                .join()
                .expect("disabled client worker")
                .starts_with(b"HTTP/1.1 403")
        );

        let observer = CapturingObserver::default();
        let policy = buildkit_policy();
        let (client, server) = UnixStream::pair().expect("socket pair");
        let worker = thread::spawn(move || send_request(client, PULL));
        handle_connection(server, missing, &policy, &observer)
            .expect("verified local alias response does not need a backend");
        let response = worker.join().expect("enabled client worker");
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(
            response
                .windows(b"verified local store".len())
                .any(|window| window == b"verified local store")
        );
    }

    #[test]
    fn buildkit_exec_and_archive_requests_are_bounded_before_backend_access() {
        let policy = buildkit_policy();
        let observer = CapturingObserver::default();
        let oversized = MAX_CONTROL_BODY_BYTES + 1;
        let missing = Path::new("/definitely-missing-buildkit-bounds-backend.sock");
        for (method, target) in [
            ("POST", "/v1.44/containers/buildx_buildkit_neutral0/exec"),
            (
                "PUT",
                "/v1.44/containers/buildx_buildkit_neutral0/archive?path=%2Fetc&noOverwriteDirNonDir=true",
            ),
        ] {
            let header =
                format!("{method} {target} HTTP/1.1\r\nContent-Length: {oversized}\r\n\r\n")
                    .into_bytes();
            let (client, server) = UnixStream::pair().expect("socket pair");
            let worker = thread::spawn(move || send_owned_request(client, &header));
            handle_connection(server, missing, &policy, &observer)
                .expect("oversized request is rejected before backend access");
            assert!(
                worker
                    .join()
                    .expect("bounded client worker")
                    .starts_with(b"HTTP/1.1 413"),
                "{method} {target}"
            );
        }
        let events = observer.events();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event,
                    PodmanEvent::DockerRejected {
                        reason: DockerProxyRejection::RequestTooLarge
                    }
                ))
                .count(),
            2
        );
    }

    #[test]
    fn buildkit_proxy_lifecycle_rewrites_records_and_cleans_up_exact_objects() {
        let name = "buildx_buildkit_neutral-0123456789abcdef0";
        let volume = format!("{name}_state");
        let container_id = "aa".repeat(32);
        let exec_id = "bb".repeat(32);
        let create_body = buildkit_create_request_body(name);
        let exec_body = buildkit_exec_request_body();
        let requests = vec![
            request(
                "POST",
                &format!("/v1.44/containers/create?name={name}"),
                &create_body,
            ),
            request(
                "POST",
                &format!("/v1.44/containers/{container_id}/start"),
                &[],
            ),
            request(
                "POST",
                &format!("/v1.44/containers/{container_id}/exec"),
                &exec_body,
            ),
            request("GET", &format!("/v1.44/exec/{exec_id}/json"), &[]),
            request(
                "POST",
                &format!("/v1.44/containers/{container_id}/stop"),
                &[],
            ),
            request(
                "DELETE",
                &format!("/v1.44/containers/{container_id}?v=1"),
                &[],
            ),
            request("DELETE", &format!("/v1.44/volumes/{volume}"), &[]),
        ];

        let socket = temporary_backend_socket();
        let listener = UnixListener::bind(&socket).expect("fake backend listener");
        let backend = serve_buildkit_lifecycle(listener, container_id.clone(), exec_id);
        let policy = buildkit_policy();
        let observer = CapturingObserver::default();
        for request in requests {
            let (client, server) = UnixStream::pair().expect("socket pair");
            let worker = thread::spawn(move || send_owned_request(client, &request));
            handle_connection(server, &socket, &policy, &observer)
                .expect("BuildKit lifecycle request");
            assert!(
                worker
                    .join()
                    .expect("BuildKit lifecycle client")
                    .starts_with(b"HTTP/1.1 2")
            );
        }
        let captured = backend.join().expect("backend worker");
        let rewritten: Value =
            serde_json::from_slice(&captured[0].1).expect("rewritten create body");
        assert_eq!(
            rewritten["Image"],
            json!(format!(
                "registry.example.invalid/buildkit/runtime@sha256:{}",
                "66".repeat(32)
            ))
        );
        assert_eq!(rewritten["Labels"]["io.automata.owner"], "automata-runner");
        assert_eq!(
            rewritten["Labels"]["io.automata.job-engine"],
            "private-sandbox-sentinel"
        );
        assert_eq!(rewritten["HostConfig"]["NetworkMode"], "ns:/proc/42/ns/net");
        assert_eq!(captured[2].1, exec_body);
        assert_eq!(
            captured[5].0,
            format!("/v1.44/containers/{container_id}?v=1")
        );
        assert_eq!(captured[6].0, format!("/v1.44/volumes/{volume}"));
        fs::remove_file(socket).expect("remove fake backend socket");
    }

    #[test]
    fn upgraded_relay_waits_for_an_exact_backend_switching_response() {
        const SWITCHING: &[u8] =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n";

        let (mut client, proxy_client) = UnixStream::pair().expect("client socket pair");
        let (proxy_backend, mut backend) = UnixStream::pair().expect("backend socket pair");
        let relay = thread::spawn(move || {
            forward_upgrade_response(proxy_client, proxy_backend, Some("tcp"), false)
        });

        client
            .write_all(b"request")
            .expect("early upgraded request");
        backend
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("backend read timeout");
        let error = backend
            .read(&mut [0_u8; 1])
            .expect_err("raw bytes must wait for a validated 101 response");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        backend
            .set_read_timeout(None)
            .expect("clear backend read timeout");

        backend.write_all(SWITCHING).expect("switching response");
        let mut switching = vec![0_u8; SWITCHING.len()];
        client
            .read_exact(&mut switching)
            .expect("forwarded switching response");
        assert_eq!(switching, SWITCHING);
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("client request EOF");

        let mut request = Vec::new();
        backend
            .read_to_end(&mut request)
            .expect("upgraded backend request");
        assert_eq!(request, b"request");
        backend.write_all(b"response").expect("backend response");
        backend
            .shutdown(std::net::Shutdown::Write)
            .expect("backend response EOF");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("upgraded client response");
        assert_eq!(response, b"response");
        assert_eq!(
            relay.join().expect("relay worker").expect("relay outcome"),
            (
                7,
                u64::try_from(SWITCHING.len()).expect("header length") + 8,
            )
        );
    }

    #[test]
    fn non_switching_backend_response_closes_without_forwarding_raw_client_bytes() {
        const ORDINARY: &[u8] = b"HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\nnope";

        let (mut client, proxy_client) = UnixStream::pair().expect("client socket pair");
        let (proxy_backend, mut backend) = UnixStream::pair().expect("backend socket pair");
        let relay = thread::spawn(move || {
            forward_upgrade_response(proxy_client, proxy_backend, Some("tcp"), false)
        });
        client
            .write_all(b"GET /second HTTP/1.1\r\n\r\n")
            .expect("queued second request");
        backend.write_all(ORDINARY).expect("ordinary response");

        let mut forwarded = Vec::new();
        backend
            .read_to_end(&mut forwarded)
            .expect("closed backend request direction");
        assert!(forwarded.is_empty(), "a second request reached the backend");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("bounded ordinary response");
        assert_eq!(
            response,
            b"HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope"
        );
        assert_eq!(
            relay.join().expect("relay worker").expect("relay outcome"),
            (0, 4)
        );
    }

    #[test]
    fn upgraded_head_response_does_not_wait_for_the_declared_get_body() {
        let (mut client, proxy_client) = UnixStream::pair().expect("client socket pair");
        let (proxy_backend, mut backend) = UnixStream::pair().expect("backend socket pair");
        let (relay_finished, wait_for_relay) = mpsc::channel();
        let relay = thread::spawn(move || {
            let outcome = forward_upgrade_response(proxy_client, proxy_backend, Some("tcp"), true);
            relay_finished.send(outcome).expect("report relay outcome");
        });
        backend
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n")
            .expect("HEAD response");

        let outcome = match wait_for_relay.recv_timeout(Duration::from_secs(1)) {
            Ok(outcome) => outcome,
            Err(error) => {
                let _ignored = backend.shutdown(std::net::Shutdown::Both);
                let _ignored = client.shutdown(std::net::Shutdown::Both);
                let _ignored = relay.join();
                panic!("HEAD response waited for a nonexistent body: {error}");
            }
        };
        relay.join().expect("relay worker");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("bounded HEAD response");
        assert_eq!(
            response,
            b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(outcome.expect("relay outcome"), (0, 0));
        drop(backend);
    }

    #[test]
    fn upgrade_request_with_non_101_backend_response_cannot_send_a_second_request() {
        const ORDINARY: &[u8] = b"HTTP/1.1 409 Conflict\r\nContent-Length: 4\r\n\r\nnope";

        let socket = temporary_backend_socket();
        let listener = UnixListener::bind(&socket).expect("fake backend listener");
        let backend = thread::spawn(move || {
            let (mut connection, _) = listener.accept().expect("fake backend connection");
            let request = read_header(&mut connection).expect("forwarded request header");
            connection.write_all(ORDINARY).expect("ordinary response");
            connection
                .shutdown(std::net::Shutdown::Write)
                .expect("ordinary response EOF");
            let mut unexpected = Vec::new();
            connection
                .read_to_end(&mut unexpected)
                .expect("closed backend request direction");
            (request, unexpected)
        });
        let observer = CapturingObserver::default();
        let policy = policy();
        let (mut client, proxy_client) = UnixStream::pair().expect("client socket pair");
        let proxy_socket = socket.clone();
        let proxy = thread::spawn(move || {
            let result = handle_connection(proxy_client, &proxy_socket, &policy, &observer);
            (result, observer)
        });

        client
            .write_all(
                b"POST /v1.44/containers/example/attach HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\nGET /_ping HTTP/1.1\r\n\r\n",
            )
            .expect("upgrade plus queued second request");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("client request EOF");
        let mut response = Vec::new();
        if let Err(error) = client.read_to_end(&mut response) {
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        }
        assert_eq!(
            response,
            b"HTTP/1.1 409 Conflict\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope"
        );

        let (result, observer) = proxy.join().expect("proxy worker");
        result.expect("ordinary response is forwarded and closed");
        let (request, unexpected) = backend.join().expect("backend worker");
        assert!(
            std::str::from_utf8(&request)
                .expect("forwarded request text")
                .starts_with("POST /v1.44/containers/example/attach HTTP/1.1\r\n")
        );
        assert!(
            unexpected.is_empty(),
            "a second request reached the backend"
        );
        assert!(observer.events().iter().any(|event| matches!(
            event,
            PodmanEvent::DockerRequestCompleted {
                route: DockerProxyRoute::ContainerOperation,
                outcome: DockerProxyOutcome::Forwarded,
                request_bytes: 0,
                response_bytes: 4,
                ..
            }
        )));
        fs::remove_file(socket).expect("remove fake backend socket");
    }

    #[test]
    fn full_client_hangup_before_backend_response_reaps_the_connection_worker() {
        let socket = temporary_backend_socket();
        let listener = UnixListener::bind(&socket).expect("fake backend listener");
        let (request_seen, wait_for_request) = mpsc::channel();
        let (release_backend, wait_for_release) = mpsc::channel();
        let backend = thread::spawn(move || {
            let (mut connection, _) = listener.accept().expect("fake backend connection");
            let request = read_header(&mut connection).expect("forwarded request header");
            request_seen.send(request).expect("report backend request");
            let _ignored = wait_for_release.recv();
        });
        let observer = CapturingObserver::default();
        let policy = policy();
        let (mut client, proxy_client) = UnixStream::pair().expect("client socket pair");
        let proxy_socket = socket.clone();
        let (proxy_finished, wait_for_proxy) = mpsc::channel();
        let proxy = thread::spawn(move || {
            let result = handle_connection(proxy_client, &proxy_socket, &policy, &observer);
            proxy_finished.send(result).expect("report proxy outcome");
            observer
        });

        client
            .write_all(
                b"POST /v1.44/containers/example/attach HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n",
            )
            .expect("upgrade request");
        let request = wait_for_request
            .recv_timeout(Duration::from_secs(1))
            .expect("backend request");
        assert!(request.starts_with(b"POST /v1.44/containers/example/attach HTTP/1.1\r\n"));
        drop(client);

        let result = wait_for_proxy.recv_timeout(Duration::from_secs(1));
        let _ignored = release_backend.send(());
        backend.join().expect("backend worker");
        let observer = proxy.join().expect("proxy worker");
        assert!(
            result
                .expect("full client HUP must reap a pre-101 connection")
                .is_err(),
            "a missing backend response must not be accepted",
        );
        assert!(observer.events().iter().any(|event| matches!(
            event,
            PodmanEvent::DockerRequestCompleted {
                route: DockerProxyRoute::ContainerOperation,
                outcome: DockerProxyOutcome::IoError,
                ..
            }
        )));
        fs::remove_file(socket).expect("remove fake backend socket");
    }

    #[test]
    fn client_rdhup_before_backend_101_preserves_delayed_attach_output() {
        const SWITCHING: &[u8] =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n";

        let socket = temporary_backend_socket();
        let listener = UnixListener::bind(&socket).expect("fake backend listener");
        let (request_seen, wait_for_request) = mpsc::channel();
        let (release_response, wait_for_release) = mpsc::channel();
        let backend = thread::spawn(move || {
            let (mut connection, _) = listener.accept().expect("fake backend connection");
            let request = read_header(&mut connection).expect("forwarded request header");
            request_seen.send(request).expect("report backend request");
            wait_for_release.recv().expect("release delayed response");
            connection.write_all(SWITCHING).expect("switching response");
            let mut request_body = Vec::new();
            connection
                .read_to_end(&mut request_body)
                .expect("attach stdin EOF");
            assert!(request_body.is_empty());
            connection.write_all(b"response").expect("attach output");
            connection
                .shutdown(std::net::Shutdown::Write)
                .expect("attach output EOF");
        });
        let observer = CapturingObserver::default();
        let policy = policy();
        let (mut client, proxy_client) = UnixStream::pair().expect("client socket pair");
        let proxy_socket = socket.clone();
        let (proxy_finished, wait_for_proxy) = mpsc::channel();
        let proxy = thread::spawn(move || {
            let result = handle_connection(proxy_client, &proxy_socket, &policy, &observer);
            proxy_finished.send(result).expect("report proxy outcome");
            observer
        });

        client
            .write_all(
                b"POST /v1.44/containers/example/attach HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n",
            )
            .expect("upgrade request");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("attach stdin EOF");
        wait_for_request
            .recv_timeout(Duration::from_secs(1))
            .expect("backend request");
        assert!(
            matches!(
                wait_for_proxy.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "RDHUP terminated the pre-101 connection",
        );
        release_response.send(()).expect("release backend response");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("delayed attach response");
        assert_eq!([SWITCHING, b"response"].concat(), response);
        wait_for_proxy
            .recv_timeout(Duration::from_secs(1))
            .expect("proxy completion")
            .expect("successful upgraded relay");
        let observer = proxy.join().expect("proxy worker");
        backend.join().expect("backend worker");
        assert!(observer.events().iter().any(|event| matches!(
            event,
            PodmanEvent::DockerRequestCompleted {
                route: DockerProxyRoute::ContainerOperation,
                outcome: DockerProxyOutcome::Forwarded,
                ..
            }
        )));
        fs::remove_file(socket).expect("remove fake backend socket");
    }

    #[test]
    fn malformed_switching_response_never_admits_raw_relay() {
        let (mut client, proxy_client) = UnixStream::pair().expect("client socket pair");
        let (proxy_backend, mut backend) = UnixStream::pair().expect("backend socket pair");
        let relay = thread::spawn(move || {
            forward_upgrade_response(proxy_client, proxy_backend, Some("tcp"), false)
        });
        client
            .write_all(b"private-request")
            .expect("queued raw request");
        backend
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .expect("mismatched switching response");

        let mut forwarded = Vec::new();
        backend
            .read_to_end(&mut forwarded)
            .expect("closed backend request direction");
        assert!(forwarded.is_empty(), "an invalid 101 admitted raw relay");
        let error = relay
            .join()
            .expect("relay worker")
            .expect_err("mismatched protocol must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let mut response = [0_u8; 1];
        match client.read(&mut response) {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Ok(_) => panic!("an invalid 101 reached the client"),
            Err(error) => panic!("unexpected client close error: {error}"),
        }
    }

    #[test]
    fn backend_101_requires_the_exact_upgrade_protocol_shape() {
        const INVALID_RESPONSES: [&[u8]; 7] = [
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: tcp\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nUpgrade: tcp\r\n\r\n",
            b"HTTP/1.1 101 Switching\0Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n",
        ];

        for response in INVALID_RESPONSES {
            let (mut proxy_backend, mut backend) = UnixStream::pair().expect("backend socket pair");
            backend.write_all(response).expect("invalid response");
            backend
                .shutdown(std::net::Shutdown::Write)
                .expect("invalid response EOF");
            let error = read_backend_upgrade_response(&mut proxy_backend, Some("tcp"), false)
                .expect_err("invalid 101 must fail closed");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }

        let (mut proxy_backend, mut backend) = UnixStream::pair().expect("backend socket pair");
        backend
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n",
            )
            .expect("valid response without a client protocol");
        let error = read_backend_upgrade_response(&mut proxy_backend, None, false)
            .expect_err("an absent client protocol must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn chunked_backend_response_trailer_aggregate_is_bounded() {
        fn encoded_trailers(value_bytes: usize) -> Vec<u8> {
            let mut encoded = b"0\r\nX: ".to_vec();
            encoded.resize(encoded.len() + value_bytes, b'a');
            encoded.extend_from_slice(b"\r\n\r\n");
            encoded
        }

        let exact_value_bytes = MAX_HEADER_BYTES.checked_sub(7).expect("trailer framing");
        let mut exact = io::Cursor::new(encoded_trailers(exact_value_bytes));
        assert_eq!(
            read_chunked_body(&mut exact, MAX_CONTROL_BODY_BYTES).expect("exact trailer bound"),
            Vec::<u8>::new(),
        );

        let mut oversized = io::Cursor::new(encoded_trailers(exact_value_bytes + 1));
        let error = read_chunked_body(&mut oversized, MAX_CONTROL_BODY_BYTES)
            .expect_err("one-over trailer aggregate must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn upgraded_full_client_hangup_reaps_a_silent_backend() {
        let (client, proxy_client) = UnixStream::pair().expect("client socket pair");
        let (proxy_backend, backend) = UnixStream::pair().expect("backend socket pair");
        let (relay_finished, wait_for_relay) = mpsc::channel();
        let relay = thread::spawn(move || {
            let outcome = relay_upgraded_with_drain_timeout(
                proxy_client,
                proxy_backend,
                Duration::from_millis(50),
            );
            relay_finished.send(outcome).expect("report relay outcome");
        });

        drop(client);
        assert_eq!(
            wait_for_relay
                .recv_timeout(Duration::from_secs(1))
                .expect("full client HUP must reap a silent backend")
                .expect("bounded relay outcome"),
            (0, 0),
        );
        relay.join().expect("relay worker");
        drop(backend);
    }

    #[test]
    fn upgraded_backend_eof_reaps_an_open_client_upload_after_the_drain_bound() {
        let (mut client, proxy_client) = UnixStream::pair().expect("client socket pair");
        let (proxy_backend, backend) = UnixStream::pair().expect("backend socket pair");
        let (relay_finished, wait_for_relay) = mpsc::channel();
        let relay = thread::spawn(move || {
            let outcome = relay_upgraded_with_drain_timeout(
                proxy_client,
                proxy_backend,
                Duration::from_millis(50),
            );
            relay_finished.send(outcome).expect("report relay outcome");
        });

        backend
            .shutdown(std::net::Shutdown::Write)
            .expect("backend response EOF");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("client response EOF");
        assert!(response.is_empty());
        assert_eq!(
            wait_for_relay
                .recv_timeout(Duration::from_secs(1))
                .expect("backend EOF must bound the open upload")
                .expect("bounded relay outcome"),
            (0, 0),
        );

        relay.join().expect("relay worker");
        drop((client, backend));
    }

    #[test]
    fn upgraded_backend_eof_reclaims_every_connection_worker_slot() {
        let connections = Mutex::new(Vec::with_capacity(MAX_CONNECTION_WORKERS));
        let (outcome_sender, wait_for_outcomes) = mpsc::channel();
        let mut clients = Vec::with_capacity(MAX_CONNECTION_WORKERS);
        let mut backends = Vec::with_capacity(MAX_CONNECTION_WORKERS);

        for _ in 0..MAX_CONNECTION_WORKERS {
            let (client, proxy_client) = UnixStream::pair().expect("client socket pair");
            let control = proxy_client.try_clone().expect("connection control");
            let (proxy_backend, backend) = UnixStream::pair().expect("backend socket pair");
            let outcome_sender = outcome_sender.clone();
            let worker = thread::spawn(move || {
                let outcome =
                    relay_upgraded_with_drain_timeout(proxy_client, proxy_backend, Duration::ZERO);
                outcome_sender.send(outcome).expect("report relay outcome");
            });
            connections
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(ConnectionWorker { control, worker });
            clients.push(client);
            backends.push(backend);
        }
        drop(outcome_sender);

        assert_eq!(
            connections
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len(),
            MAX_CONNECTION_WORKERS,
        );
        for backend in &backends {
            backend
                .shutdown(std::net::Shutdown::Write)
                .expect("backend response EOF");
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        let reaped = loop {
            reap_finished_connections(&connections).expect("reap connection workers");
            if connections
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
            {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            thread::sleep(Duration::from_millis(5));
        };

        if !reaped {
            let survivors = connections
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .drain(..)
                .collect::<Vec<_>>();
            for survivor in &survivors {
                let _ignored = survivor.control.shutdown(std::net::Shutdown::Both);
            }
            for survivor in survivors {
                let _ignored = survivor.worker.join();
            }
        }
        assert!(reaped, "backend EOF did not reclaim every worker slot");

        let mut completed = 0_usize;
        for outcome in wait_for_outcomes {
            assert_eq!(outcome.expect("bounded relay outcome"), (0, 0));
            completed += 1;
        }
        assert_eq!(completed, MAX_CONNECTION_WORKERS);
        assert_eq!(clients.len(), MAX_CONNECTION_WORKERS);
        assert_eq!(backends.len(), MAX_CONNECTION_WORKERS);
    }

    #[test]
    fn upgraded_client_eof_preserves_a_delayed_backend_response() {
        let (mut client, proxy_client) = UnixStream::pair().expect("client socket pair");
        let (proxy_backend, mut backend) = UnixStream::pair().expect("backend socket pair");
        let backend_worker = thread::spawn(move || {
            let mut request = Vec::new();
            backend
                .read_to_end(&mut request)
                .expect("backend request EOF");
            assert_eq!(request, b"request");
            thread::sleep(Duration::from_millis(75));
            backend.write_all(b"response").expect("backend response");
            backend
                .shutdown(std::net::Shutdown::Write)
                .expect("backend response EOF");
        });
        let relay = thread::spawn(move || {
            relay_upgraded_with_drain_timeout(
                proxy_client,
                proxy_backend,
                Duration::from_millis(20),
            )
        });

        client.write_all(b"request").expect("client request");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("client request EOF");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("client response EOF");
        assert_eq!(response, b"response");
        assert_eq!(
            relay.join().expect("relay worker").expect("relay outcome"),
            (7, 8)
        );
        backend_worker.join().expect("backend worker");
    }
}
