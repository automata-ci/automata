use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fmt,
    ops::Deref,
    path::Path,
    sync::{Arc, Mutex, Weak},
    thread,
    time::{Duration, Instant},
};

use automata_ci_execution::{
    Cancellation, ContainerHandle, DestroyDisposition, DestroySandbox, EnvironmentProfile,
    ExecutionEnvironment, NetworkPolicy, NeverCancelled, OperationOutcome, ProviderCapabilities,
    ProviderError, ProviderErrorKind, ProviderId, ProviderStage, RootFilesystemPolicy,
    SandboxCapability, SandboxHandle, SandboxInspection, SandboxPrivilegePolicy, SandboxProvider,
    SandboxRecord, SandboxSpec, SandboxState, ServiceContainerBinding, ServiceContainerBindings,
    ServiceContainerSpec, ServiceHealthPolicy, ServiceNetwork, ServicePortBinding,
    ServiceTransportProtocol,
};
use sha2::{Digest as _, Sha256};

use crate::{
    CommandOutput, CommandRequest, CommandTermination, JobContainerEngine, NoopPodmanObserver,
    PODMAN_PROVIDER_ID, PodmanCommandExecutor, PodmanCommandOutcome, PodmanCommandStage,
    PodmanEvent, PodmanHostGatewayAlias, PodmanObserver, PodmanOpenError, PodmanOptions,
    SystemCommandExecutor,
    command::process_cgroup,
    docker::{
        DOCKER_SOCKET_DIRECTORY_TARGET, JobDockerLaunch, JobDockerListener, JobDockerService,
        bind_public_socket,
    },
    endpoint::{EnvironmentDocument, PodmanExecutionEndpoint, environment_document},
    naming::{InspectedLabels, ResourceNames, label_format},
    provider_error,
    service::{ServiceHealthExpectation, ServiceManifest, ServiceManifestEntry},
    service_proxy::{
        ENTRYPOINT as SERVICE_PROXY_ENTRYPOINT, SERVE_COMMAND as SERVICE_PROXY_SERVE_COMMAND,
        mapping_argument as service_proxy_mapping_argument,
        parse_service_address as parse_proxy_service_address,
        parse_status as parse_service_proxy_status,
    },
    state::{JobEnginePaths, LocalState},
};

const SERVICE_HEALTH_FORMAT: &str = "{{.State.Status}}\n{{if .Config.Healthcheck}}configured{{else}}none{{end}}\n{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}";
const SERVICE_HEALTH_CONFIGURATION_FORMAT: &str = "{{json .Config.Healthcheck}}";
const SERVICE_HEALTH_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_SERVICE_PROCESS_ENVIRONMENT_BYTES: usize = 48 * 1024;
const MAX_SERVICE_PROXY_PORTS: usize = 128;
const SERVICE_PROXY_IMAGE_FORMAT: &str =
    "{{.Digest}}\n{{ index .Labels \"io.automata.service-proxy.protocol-version\" }}";
const SERVICE_PROXY_IMAGE_VERSION: &str = "1";
const SERVICE_PROXY_CONFIG_FORMAT: &str =
    "{{.ImageName}}\n{{.Pod}}\n{{json .Config.Entrypoint}}\n{{json .Config.Cmd}}";
const CONTAINER_POD_FORMAT: &str = "{{.Pod}}";
const POD_INFRA_CONTAINER_FORMAT: &str = "{{.InfraContainerID}}";
const JOB_NETWORK_SYSCTL: &str = "net.ipv4.ip_unprivileged_port_start=0";
const JOB_NETWORK_SYSCTL_FORMAT: &str =
    "{{ index .HostConfig.Sysctls \"net.ipv4.ip_unprivileged_port_start\" }}";
const ENDPOINT_CAPABILITIES: [SandboxCapability; 6] = [
    SandboxCapability::Exec,
    SandboxCapability::Signal,
    SandboxCapability::Wait,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::EnvironmentInjection,
];

/// Local rootless Podman provider for one whole-job container per sandbox.
///
/// Construction exclusively locks and prepares the explicit private state
/// root; cloning shares that lock and the injected command adapter. Sandbox
/// operations serialize by opaque handle, attach revalidates live cgroup
/// containment and zero-swap resource enforcement, and cleanup reinspects
/// attempt ownership before removing exact resources rather than using a
/// global prune. Service-container capability is exposed only when the
/// configured immutable namespace-local proxy image passes local inspection.
#[derive(Clone)]
pub struct RootlessPodmanProvider {
    pub(crate) inner: Arc<PodmanInner>,
}

impl RootlessPodmanProvider {
    /// Opens the provider with the safe local process adapter.
    ///
    /// # Errors
    ///
    /// Returns a typed state-root, platform, or configured-helper verification
    /// failure. A configured service proxy image is inspected locally before
    /// the service-container capability is advertised.
    pub fn open(options: PodmanOptions) -> Result<Self, PodmanOpenError> {
        Self::open_with_executor_and_observer(
            options,
            Arc::new(SystemCommandExecutor),
            Arc::new(NoopPodmanObserver),
        )
    }

    /// Opens the provider with an injectable argv command boundary.
    ///
    /// # Errors
    ///
    /// Returns a typed state-root or platform failure before invoking Podman.
    pub fn open_with_executor(
        options: PodmanOptions,
        executor: Arc<dyn PodmanCommandExecutor>,
    ) -> Result<Self, PodmanOpenError> {
        Self::open_with_executor_and_observer(options, executor, Arc::new(NoopPodmanObserver))
    }

    /// Opens the safe local adapter with an identifier-free observer.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::open`].
    pub fn open_with_observer(
        options: PodmanOptions,
        observer: Arc<dyn PodmanObserver>,
    ) -> Result<Self, PodmanOpenError> {
        Self::open_with_executor_and_observer(options, Arc::new(SystemCommandExecutor), observer)
    }

    /// Opens with injectable process and observation boundaries.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::open_with_executor`].
    pub fn open_with_executor_and_observer(
        options: PodmanOptions,
        executor: Arc<dyn PodmanCommandExecutor>,
        observer: Arc<dyn PodmanObserver>,
    ) -> Result<Self, PodmanOpenError> {
        #[cfg(not(target_os = "linux"))]
        return Err(crate::PodmanConfigurationError::UnsupportedPlatform.into());
        options.process_environment().validate_provider_use()?;
        let state = LocalState::open(&options)?;
        options.process_environment().validate_provider_use()?;
        let provider_id = ProviderId::new(PODMAN_PROVIDER_ID)
            .map_err(|_| crate::PodmanConfigurationError::InvalidBinary)?;
        let mut declared_capabilities = vec![
            SandboxCapability::WholeJob,
            SandboxCapability::Attach,
            SandboxCapability::Inspect,
            SandboxCapability::Exec,
            SandboxCapability::Signal,
            SandboxCapability::Wait,
            SandboxCapability::CopyTo,
            SandboxCapability::CopyFrom,
            SandboxCapability::EnvironmentInjection,
            SandboxCapability::NetworkDisabled,
            SandboxCapability::PrivateEgress,
            SandboxCapability::ReadOnlyRootFilesystem,
            SandboxCapability::WritableRootFilesystem,
            SandboxCapability::Administrator,
            SandboxCapability::UserNamespace,
            SandboxCapability::ResourceLimits,
        ];
        if options.service_proxy_image().is_some() {
            declared_capabilities.push(SandboxCapability::ServiceContainers);
        }
        if options.job_container_engine() == JobContainerEngine::AttemptScopedDockerApi {
            declared_capabilities.push(SandboxCapability::DockerCompatibleApi);
        }
        let capabilities = ProviderCapabilities::new(declared_capabilities)
            .map_err(|_| crate::PodmanConfigurationError::InvalidLimits)?;
        let inner = Arc::new(PodmanInner {
            options,
            state,
            executor,
            observer,
            provider_id,
            capabilities,
            handle_locks: Mutex::new(BTreeMap::new()),
            docker_services: Mutex::new(BTreeMap::new()),
        });
        if inner.options.service_proxy_image().is_some() {
            inner
                .verify_service_proxy_image(inner.operation_deadline(), &NeverCancelled)
                .map_err(|_| crate::PodmanConfigurationError::ServiceProxyUnavailable)?;
        }
        Ok(Self { inner })
    }
}

impl fmt::Debug for RootlessPodmanProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootlessPodmanProvider")
            .field("provider_id", &self.inner.provider_id)
            .field("state_root", &self.inner.options.state_root())
            .field("capabilities", &self.inner.capabilities)
            .finish_non_exhaustive()
    }
}

impl SandboxProvider for RootlessPodmanProvider {
    fn provider_id(&self) -> &ProviderId {
        &self.inner.provider_id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.inner.capabilities
    }

    fn create(
        &self,
        spec: &SandboxSpec,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError> {
        self.inner
            .require_provider_trust(ProviderStage::CreateSandbox)?;
        let handle = ResourceNames::for_create(spec.operation_id(), spec.generation()).handle();
        let operation_lock = self.inner.handle_lock(&handle)?;
        let _operation = operation_lock
            .lock()
            .map_err(|_| provider_error::local_storage(ProviderStage::CreateSandbox))?;
        self.inner.create(spec, cancellation)
    }

    fn attach(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn automata_ci_execution::ExecutionEndpoint>, ProviderError> {
        self.inner.require_provider_trust(ProviderStage::Attach)?;
        let operation_lock = self.inner.handle_lock(handle)?;
        let operation = operation_lock
            .lock()
            .map_err(|_| provider_error::local_storage(ProviderStage::Attach))?;
        let inspection = self.inner.inspect(handle, cancellation)?;
        if inspection.state() != SandboxState::Running {
            return Err(provider_error::invalid_state(ProviderStage::Attach));
        }
        let names = ResourceNames::from_handle(handle, &self.inner.provider_id)?;
        self.inner.ensure_no_swap_cgroup(
            &names,
            self.inner.operation_deadline(),
            cancellation,
            ProviderStage::Attach,
        )?;
        drop(operation);
        Ok(Box::new(PodmanExecutionEndpoint::new(
            Arc::clone(&self.inner),
            handle.clone(),
            names,
            operation_lock,
        )))
    }

    fn inspect(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        self.inner.require_provider_trust(ProviderStage::Inspect)?;
        let operation_lock = self.inner.handle_lock(handle)?;
        let _operation = operation_lock
            .lock()
            .map_err(|_| provider_error::local_storage(ProviderStage::Inspect))?;
        self.inner.inspect(handle, cancellation)
    }

    fn service_bindings(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<ServiceContainerBindings, ProviderError> {
        self.inner.require_provider_trust(ProviderStage::Inspect)?;
        let operation_lock = self.inner.handle_lock(handle)?;
        let _operation = operation_lock
            .lock()
            .map_err(|_| provider_error::local_storage(ProviderStage::Inspect))?;
        self.inner.service_bindings(handle, cancellation)
    }

    fn destroy(
        &self,
        request: &DestroySandbox,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        self.inner
            .require_provider_trust(ProviderStage::DestroySandbox)?;
        let operation_lock = self.inner.handle_lock(request.handle())?;
        let _operation = operation_lock
            .lock()
            .map_err(|_| provider_error::local_storage(ProviderStage::DestroySandbox))?;
        self.inner.destroy(request, cancellation)
    }
}

pub(crate) struct PodmanInner {
    options: PodmanOptions,
    state: LocalState,
    executor: Arc<dyn PodmanCommandExecutor>,
    observer: Arc<dyn PodmanObserver>,
    provider_id: ProviderId,
    capabilities: ProviderCapabilities,
    handle_locks: Mutex<BTreeMap<String, Weak<Mutex<()>>>>,
    docker_services: Mutex<BTreeMap<String, JobDockerService>>,
}

impl fmt::Debug for PodmanInner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PodmanInner")
            .field("provider_id", &self.provider_id)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl PodmanInner {
    fn require_provider_trust(&self, stage: ProviderStage) -> Result<(), ProviderError> {
        self.options
            .process_environment()
            .validate_provider_use()
            .map_err(|_| provider_error::known(ProviderErrorKind::InvalidState, stage))
    }

    fn handle_lock(&self, handle: &SandboxHandle) -> Result<Arc<Mutex<()>>, ProviderError> {
        let lock_key = ResourceNames::from_handle(handle, &self.provider_id)?.workspace();
        let mut locks = self
            .handle_locks
            .lock()
            .map_err(|_| provider_error::local_storage(ProviderStage::Validate))?;
        locks.retain(|_, value| value.strong_count() > 0);
        if let Some(lock) = locks.get(&lock_key).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(lock_key, Arc::downgrade(&lock));
        Ok(lock)
    }

    #[allow(clippy::too_many_lines)]
    fn create(
        self: &Arc<Self>,
        spec: &SandboxSpec,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError> {
        validate_spec(spec)?;
        if !spec.services().is_empty()
            && !self
                .capabilities
                .supports(SandboxCapability::ServiceContainers)
        {
            return Err(provider_error::known(
                ProviderErrorKind::UnsupportedCapability,
                ProviderStage::Validate,
            ));
        }
        let deadline = self.operation_deadline();
        if spec
            .services()
            .iter()
            .any(|(_, service)| !service.ports().is_empty())
        {
            self.verify_service_proxy_image(deadline, cancellation)?;
        }
        let cgroup_parent = self.executor.delegated_no_swap_cgroup().ok_or_else(|| {
            provider_error::known(
                ProviderErrorKind::InvalidState,
                ProviderStage::CreateSandbox,
            )
        })?;
        let names = ResourceNames::for_create(spec.operation_id(), spec.generation());
        let handle = names.handle();
        let fingerprint = spec_fingerprint(
            spec,
            self.options.job_container_engine(),
            self.options.host_gateway_alias(),
            self.options.service_proxy_image(),
        );
        let labels = names.labels(spec.profile().attestation(), &fingerprint);
        let labels = ProvisionLabels {
            arguments: &labels,
            fingerprint: &fingerprint,
        };
        self.reject_conflicting_replay(&names, &fingerprint, deadline, cancellation)?;
        let mut service_manifest = self.prepare_service_manifest(spec, &names, &fingerprint)?;

        let workspace = self
            .state
            .ensure_workspace(&names.workspace())
            .map_err(|_| {
                provider_error::uncertain(
                    ProviderErrorKind::LocalStorage,
                    ProviderStage::CreateWorkspace,
                    handle.clone(),
                )
            })?;
        let engine =
            if self.options.job_container_engine() == JobContainerEngine::AttemptScopedDockerApi {
                Some(
                    self.state
                        .ensure_job_engine(&names.workspace())
                        .map_err(|_| {
                            provider_error::uncertain(
                                ProviderErrorKind::LocalStorage,
                                ProviderStage::CreateWorkspace,
                                handle.clone(),
                            )
                        })?,
                )
            } else {
                None
            };
        let mut docker_listener = match engine.as_ref() {
            Some(paths) if !self.has_job_docker_service(&names)? => {
                Some(bind_public_socket(paths.public_socket()).map_err(|_| {
                    provider_error::uncertain(
                        ProviderErrorKind::AdapterUnavailable,
                        ProviderStage::CreateContainer,
                        handle.clone(),
                    )
                })?)
            }
            _ => None,
        };
        self.ensure_network(spec, &names, &labels, deadline, cancellation)?;
        self.ensure_pod(
            spec,
            &names,
            &labels,
            &cgroup_parent,
            deadline,
            cancellation,
        )?;
        self.ensure_container(
            spec,
            &names,
            &labels,
            ProvisionStorage {
                workspace: &workspace,
                engine: engine.as_ref(),
            },
            deadline,
            cancellation,
        )?;
        self.ensure_started(&names, deadline, cancellation)?;
        self.ensure_no_swap_cgroup(&names, deadline, cancellation, ProviderStage::Start)?;
        if let Some(engine) = engine.as_ref() {
            self.ensure_job_docker_service(
                spec,
                &names,
                engine,
                docker_listener.take(),
                deadline,
                cancellation,
            )?;
        }
        self.ensure_services(
            spec,
            &names,
            &labels,
            &mut service_manifest,
            deadline,
            cancellation,
        )?;
        let inspection = self.inspect_with_deadline(&handle, deadline, cancellation)?;
        finish_create(&inspection, handle)
    }

    fn ensure_service_manifest(
        &self,
        names: &ResourceNames,
        manifest: &ServiceManifest,
    ) -> Result<ServiceManifest, ProviderError> {
        let bytes = manifest.encode(names).ok_or_else(|| {
            provider_error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let current = self
            .state
            .read_service_manifest(&names.workspace())
            .map_err(|_| provider_error::local_storage(ProviderStage::Validate))?;
        if let Some(current) = current {
            let current = ServiceManifest::decode(&current, names).ok_or_else(|| {
                provider_error::known(ProviderErrorKind::Conflict, ProviderStage::Validate)
            })?;
            if !current.same_request(manifest) {
                return Err(provider_error::known(
                    ProviderErrorKind::Conflict,
                    ProviderStage::Validate,
                ));
            }
            return Ok(current);
        }
        self.state
            .write_service_manifest(&names.workspace(), &bytes)
            .map_err(|_| {
                provider_error::uncertain(
                    ProviderErrorKind::LocalStorage,
                    ProviderStage::CreateContainer,
                    names.handle(),
                )
            })?;
        let published = self
            .state
            .read_service_manifest(&names.workspace())
            .map_err(|_| {
                provider_error::uncertain(
                    ProviderErrorKind::LocalStorage,
                    ProviderStage::CreateContainer,
                    names.handle(),
                )
            })?;
        if published.as_deref() != Some(bytes.as_slice()) {
            return Err(provider_error::uncertain(
                ProviderErrorKind::LocalStorage,
                ProviderStage::CreateContainer,
                names.handle(),
            ));
        }
        Ok(manifest.clone())
    }

    fn prepare_service_manifest(
        &self,
        spec: &SandboxSpec,
        names: &ResourceNames,
        fingerprint: &str,
    ) -> Result<ServiceManifest, ProviderError> {
        let manifest = ServiceManifest::from_specs(
            names,
            fingerprint,
            spec.resources().pids(),
            spec.services(),
            self.options.service_proxy_image(),
        )
        .ok_or_else(|| {
            provider_error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        self.ensure_service_manifest(names, &manifest)
    }

    fn load_service_manifest(
        &self,
        names: &ResourceNames,
        stage: ProviderStage,
    ) -> Result<Option<ServiceManifest>, ProviderError> {
        self.state
            .read_service_manifest(&names.workspace())
            .map_err(|_| provider_error::local_storage(stage))?
            .map(|bytes| {
                ServiceManifest::decode(&bytes, names)
                    .ok_or_else(|| provider_error::invalid_state(stage))
            })
            .transpose()
    }

    fn publish_service_manifest(
        &self,
        names: &ResourceNames,
        manifest: &ServiceManifest,
        stage: ProviderStage,
    ) -> Result<(), ProviderError> {
        let bytes = manifest
            .encode(names)
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        self.state
            .write_service_manifest(&names.workspace(), &bytes)
            .map_err(|_| {
                provider_error::uncertain(ProviderErrorKind::LocalStorage, stage, names.handle())
            })?;
        let current = self
            .state
            .read_service_manifest(&names.workspace())
            .map_err(|_| {
                provider_error::uncertain(ProviderErrorKind::LocalStorage, stage, names.handle())
            })?;
        if current.as_deref() != Some(bytes.as_slice()) {
            return Err(provider_error::uncertain(
                ProviderErrorKind::LocalStorage,
                stage,
                names.handle(),
            ));
        }
        Ok(())
    }

    fn ensure_services(
        &self,
        spec: &SandboxSpec,
        names: &ResourceNames,
        labels: &ProvisionLabels<'_>,
        manifest: &mut ServiceManifest,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let result = (|| {
            let service_cgroup = if manifest.entries().is_empty() {
                None
            } else {
                Some(self.pod_cgroup_path(
                    names,
                    deadline,
                    cancellation,
                    ProviderStage::CreateContainer,
                )?)
            };
            for entry in manifest.entries().to_vec() {
                let service = spec.services().get(entry.alias()).ok_or_else(|| {
                    provider_error::known(
                        ProviderErrorKind::InvalidConfiguration,
                        ProviderStage::Validate,
                    )
                })?;
                let identifier = self.ensure_service_container(
                    spec,
                    service,
                    &entry,
                    manifest,
                    names,
                    labels,
                    service_cgroup.as_deref().ok_or_else(|| {
                        provider_error::invalid_state(ProviderStage::CreateContainer)
                    })?,
                    deadline,
                    cancellation,
                )?;
                let Some(changed) = manifest.finish_service_create(entry.alias(), &identifier)
                else {
                    return Err(provider_error::ownership_mismatch(
                        ProviderStage::VerifyOwnership,
                    ));
                };
                if changed {
                    self.publish_service_manifest(names, manifest, ProviderStage::CreateContainer)?;
                }
            }
            for entry in manifest.entries() {
                self.ensure_service_started(
                    entry,
                    names,
                    labels.fingerprint,
                    deadline,
                    cancellation,
                )?;
            }
            for entry in manifest.entries() {
                self.ensure_service_no_swap_cgroup(
                    entry,
                    names,
                    labels.fingerprint,
                    service_cgroup
                        .as_deref()
                        .ok_or_else(|| provider_error::invalid_state(ProviderStage::Start))?,
                    manifest.aggregate_pids(),
                    deadline,
                    cancellation,
                )?;
            }
            for entry in manifest.entries() {
                self.wait_for_service(entry, names, labels.fingerprint, deadline, cancellation)?;
            }
            if manifest.port_count() != 0 {
                self.ensure_service_proxy(
                    names,
                    labels,
                    manifest,
                    service_cgroup
                        .as_deref()
                        .ok_or_else(|| provider_error::invalid_state(ProviderStage::Start))?,
                    deadline,
                    cancellation,
                )?;
            }
            self.collect_service_bindings(manifest, names, deadline, cancellation)?;
            Ok(())
        })();
        result.map_err(|error| create_service_error(&error, names.handle()))
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn ensure_service_container(
        &self,
        sandbox: &SandboxSpec,
        service: &ServiceContainerSpec,
        entry: &ServiceManifestEntry,
        manifest: &mut ServiceManifest,
        names: &ResourceNames,
        labels: &ProvisionLabels<'_>,
        cgroup_parent: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<String, ProviderError> {
        if entry.identifier().is_some() && !entry.transition() {
            return self
                .verify_service_for_spec(
                    entry,
                    names,
                    labels.fingerprint,
                    deadline,
                    cancellation,
                    ProviderStage::VerifyOwnership,
                )
                .map(|inspection| inspection.identifier);
        }
        if !entry.transition() {
            if !manifest.begin_service_create(entry.alias()) {
                return Err(provider_error::invalid_state(
                    ProviderStage::CreateContainer,
                ));
            }
            self.publish_service_manifest(names, manifest, ProviderStage::CreateContainer)?;
        }
        if self.named_container_exists(
            entry.container(),
            deadline,
            cancellation,
            ProviderStage::CreateContainer,
        )? {
            return self
                .inspect_service_container(
                    entry.container(),
                    entry,
                    names,
                    labels.fingerprint,
                    deadline,
                    cancellation,
                    ProviderStage::VerifyOwnership,
                )
                .map(|inspection| inspection.identifier);
        }
        let resources = sandbox.resources();
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["create"]));
        push_option(&mut arguments, "--name", entry.container());
        push_labels(&mut arguments, labels.arguments);
        arguments.push("--pull=never".into());
        arguments.push("--cap-drop=all".into());
        push_administrator_capabilities(&mut arguments, sandbox.privilege());
        arguments.extend(os_args([
            "--security-opt=no-new-privileges",
            "--restart=no",
            "--init",
            "--image-volume=tmpfs",
        ]));
        let user_namespace = match sandbox.privilege() {
            SandboxPrivilegePolicy::Unprivileged => "keep-id",
            SandboxPrivilegePolicy::Administrator => "keep-id:uid=0,gid=0",
            SandboxPrivilegePolicy::Host => {
                return Err(provider_error::known(
                    ProviderErrorKind::UnsupportedCapability,
                    ProviderStage::Validate,
                ));
            }
        };
        push_option(&mut arguments, "--userns", user_namespace);
        push_option(&mut arguments, "--cgroup-parent", cgroup_parent);
        push_option(&mut arguments, "--cpus", cpu_value(resources.cpu_millis()));
        push_option(
            &mut arguments,
            "--memory",
            format!("{}b", resources.memory_bytes()),
        );
        push_option(
            &mut arguments,
            "--memory-swap",
            format!("{}b", resources.memory_bytes()),
        );
        push_option(&mut arguments, "--pids-limit", resources.pids().to_string());
        push_option(&mut arguments, "--network", names.network());
        push_option(&mut arguments, "--network-alias", entry.alias());
        push_option(&mut arguments, "--sysctl", JOB_NETWORK_SYSCTL);
        let environment_document = environment_document(service.environment()).map_err(|()| {
            provider_error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::CreateContainer,
            )
        })?;
        if !environment_document.is_empty() {
            arguments.extend(os_args(["--env-file", "/dev/stdin"]));
        }
        push_service_health_options(&mut arguments, service.health());
        arguments.push(service.image().reference().into());
        let output = self.run_mutation_with_environment(
            arguments,
            (!environment_document.is_empty()).then_some(environment_document),
            deadline,
            cancellation,
            ProviderStage::CreateContainer,
            names.handle(),
        )?;
        let identifier = parse_container_identifier(output.stdout()).ok_or_else(|| {
            provider_error::uncertain(
                ProviderErrorKind::InvalidState,
                ProviderStage::CreateContainer,
                names.handle(),
            )
        })?;
        if manifest
            .record_pending_identifier(entry.alias(), identifier)
            .is_none()
        {
            return Err(provider_error::uncertain(
                ProviderErrorKind::InvalidState,
                ProviderStage::CreateContainer,
                names.handle(),
            ));
        }
        self.publish_service_manifest(names, manifest, ProviderStage::CreateContainer)?;
        let inspection = self.inspect_service_container(
            identifier,
            entry,
            names,
            labels.fingerprint,
            deadline,
            cancellation,
            ProviderStage::VerifyOwnership,
        )?;
        Ok(inspection.identifier)
    }

    fn pod_cgroup_path(
        &self,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<String, ProviderError> {
        let delegated = self
            .executor
            .delegated_no_swap_cgroup()
            .ok_or_else(|| provider_error::known(ProviderErrorKind::InvalidState, stage))?;
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["pod", "inspect", "--format", "{{.CgroupPath}}"]));
        arguments.push(names.pod().into());
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation, stage),
            stage,
            None,
        )?;
        parse_owned_cgroup_path(output.stdout(), &delegated)
            .ok_or_else(|| provider_error::known(ProviderErrorKind::InvalidState, stage))
    }

    fn ensure_service_started(
        &self,
        entry: &ServiceManifestEntry,
        names: &ResourceNames,
        fingerprint: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let inspection = self.verify_service_for_spec(
            entry,
            names,
            fingerprint,
            deadline,
            cancellation,
            ProviderStage::Start,
        )?;
        if inspection.state() == Some("running") {
            return Ok(());
        }
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["start"]));
        arguments.push(inspection.identifier().into());
        self.run_mutation(
            arguments,
            deadline,
            cancellation,
            ProviderStage::Start,
            names.handle(),
        )
        .map(|_| ())
    }

    fn wait_for_service(
        &self,
        entry: &ServiceManifestEntry,
        names: &ResourceNames,
        fingerprint: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        loop {
            if cancellation.is_cancelled() {
                return Err(provider_error::known(
                    ProviderErrorKind::Cancelled,
                    ProviderStage::Start,
                ));
            }
            if Instant::now() >= deadline {
                return Err(provider_error::known(
                    ProviderErrorKind::TimedOut,
                    ProviderStage::Start,
                ));
            }
            match self.service_readiness(
                entry,
                names,
                fingerprint,
                deadline,
                cancellation,
                ProviderStage::Start,
            )? {
                ServiceReadiness::Ready => return Ok(()),
                ServiceReadiness::Failed => {
                    return Err(provider_error::known(
                        ProviderErrorKind::InvalidState,
                        ProviderStage::Start,
                    ));
                }
                ServiceReadiness::Waiting => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    thread::sleep(SERVICE_HEALTH_POLL_INTERVAL.min(remaining));
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn ensure_service_no_swap_cgroup(
        &self,
        entry: &ServiceManifestEntry,
        names: &ResourceNames,
        fingerprint: &str,
        pod_cgroup: &str,
        aggregate_pids: u32,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let inspection = self.verify_service_for_spec(
            entry,
            names,
            fingerprint,
            deadline,
            cancellation,
            ProviderStage::Start,
        )?;
        let process_id = self.named_container_process_id(
            inspection.identifier(),
            deadline,
            cancellation,
            ProviderStage::Start,
        )?;
        if !self
            .executor
            .enforces_job_cgroup(process_id, pod_cgroup, aggregate_pids)
            || self.named_container_process_id(
                inspection.identifier(),
                deadline,
                cancellation,
                ProviderStage::Start,
            )? != process_id
        {
            return Err(provider_error::uncertain(
                ProviderErrorKind::InvalidState,
                ProviderStage::Start,
                names.handle(),
            ));
        }
        Ok(())
    }

    fn named_container_process_id(
        &self,
        container: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<u32, ProviderError> {
        let mut arguments = self.base_arguments();
        arguments.extend(os_args([
            "container",
            "inspect",
            "--format",
            "{{.State.Pid}}",
        ]));
        arguments.push(container.into());
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation, stage),
            stage,
            None,
        )?;
        parse_process_id(output.stdout()).ok_or_else(|| provider_error::invalid_state(stage))
    }

    fn service_readiness(
        &self,
        entry: &ServiceManifestEntry,
        names: &ResourceNames,
        fingerprint: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<ServiceReadiness, ProviderError> {
        let identifier = entry
            .identifier()
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        let Some(inspection) =
            self.inspect_named_container(identifier, deadline, cancellation, stage)?
        else {
            return Ok(ServiceReadiness::Failed);
        };
        if !names.expected_ownership().matches(&inspection)
            || inspection.spec_fingerprint() != fingerprint
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        let Some(named_container) =
            self.inspect_named_container(entry.container(), deadline, cancellation, stage)?
        else {
            return Ok(ServiceReadiness::Failed);
        };
        if named_container.identifier() != inspection.identifier()
            || !names.expected_ownership().matches(&named_container)
            || named_container.spec_fingerprint() != fingerprint
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        if inspection.state() != Some("running") {
            return Ok(ServiceReadiness::Failed);
        }
        let mut arguments = self.base_arguments();
        arguments.extend(os_args([
            "container",
            "inspect",
            "--format",
            SERVICE_HEALTH_FORMAT,
        ]));
        arguments.push(inspection.identifier().into());
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation, stage),
            stage,
            None,
        )?;
        parse_service_readiness(output.stdout(), entry.health())
            .ok_or_else(|| provider_error::invalid_state(stage))
    }

    fn verify_service_for_spec(
        &self,
        entry: &ServiceManifestEntry,
        names: &ResourceNames,
        fingerprint: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<InspectedServiceContainer, ProviderError> {
        let token = entry.identifier().unwrap_or_else(|| entry.container());
        self.inspect_service_container(
            token,
            entry,
            names,
            fingerprint,
            deadline,
            cancellation,
            stage,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_service_container(
        &self,
        token: &str,
        entry: &ServiceManifestEntry,
        names: &ResourceNames,
        fingerprint: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<InspectedServiceContainer, ProviderError> {
        let inspection = self.inspect_service_container_base(
            token,
            entry,
            names,
            fingerprint,
            deadline,
            cancellation,
            stage,
        )?;
        if let Some(expected) = entry.health_configuration() {
            let mut arguments = self.base_arguments();
            arguments.extend(os_args(["container", "inspect", "--format"]));
            arguments.push(SERVICE_HEALTH_CONFIGURATION_FORMAT.into());
            arguments.push(inspection.identifier().into());
            let output = Self::require_success(
                self.run(arguments, deadline, cancellation, stage),
                stage,
                None,
            )?;
            if !expected.matches_inspection(output.stdout()) {
                return Err(provider_error::ownership_mismatch(
                    ProviderStage::VerifyOwnership,
                ));
            }
        }
        Ok(inspection)
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_service_container_base(
        &self,
        token: &str,
        entry: &ServiceManifestEntry,
        names: &ResourceNames,
        fingerprint: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<InspectedServiceContainer, ProviderError> {
        let inspection = self
            .inspect_named_container(token, deadline, cancellation, stage)?
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        if !names.expected_ownership().matches(&inspection)
            || inspection.spec_fingerprint() != fingerprint
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        let named_container = self
            .inspect_named_container(entry.container(), deadline, cancellation, stage)?
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        if named_container.identifier() != inspection.identifier()
            || !names.expected_ownership().matches(&named_container)
            || named_container.spec_fingerprint() != fingerprint
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["container", "inspect", "--format"]));
        arguments.push(service_configuration_format(&names.network(), entry.alias()).into());
        arguments.push(inspection.identifier().into());
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation, stage),
            stage,
            None,
        )?;
        let expected = format!("{}\nunpublished\nalias\n0", entry.image());
        let actual = std::str::from_utf8(output.stdout())
            .ok()
            .map(str::trim_end)
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        if actual != expected {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        Ok(inspection)
    }

    fn named_container_exists(
        &self,
        name: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<bool, ProviderError> {
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["container", "exists"]));
        arguments.push(name.into());
        let output = self.run(arguments, deadline, cancellation, stage);
        match output.termination() {
            CommandTermination::Exited(Some(0)) if !output.was_truncated() => Ok(true),
            CommandTermination::Exited(Some(1)) if !output.was_truncated() => Ok(false),
            _ => Self::require_success(output, stage, None).map(|_| true),
        }
    }

    fn inspect_named_container(
        &self,
        name: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<Option<InspectedServiceContainer>, ProviderError> {
        if !self.named_container_exists(name, deadline, cancellation, stage)? {
            return Ok(None);
        }
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["container", "inspect", "--format"]));
        arguments.push(service_inspection_format().into());
        arguments.push(name.into());
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation, stage),
            stage,
            None,
        )?;
        parse_service_inspection(output.stdout())
            .map(Some)
            .ok_or_else(|| provider_error::invalid_state(stage))
    }

    #[allow(
        clippy::single_match_else,
        clippy::too_many_arguments,
        clippy::too_many_lines
    )]
    fn ensure_service_proxy(
        &self,
        names: &ResourceNames,
        labels: &ProvisionLabels<'_>,
        manifest: &mut ServiceManifest,
        pod_cgroup: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let primary = self
            .inspect_named_container(
                &names.container(),
                deadline,
                cancellation,
                ProviderStage::CreateContainer,
            )?
            .ok_or_else(|| provider_error::invalid_state(ProviderStage::CreateContainer))?;
        if !names.expected_ownership().matches(&primary)
            || primary.spec_fingerprint() != manifest.fingerprint()
            || primary.state() != Some("running")
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        let pod = self
            .inspect_resource(
                ResourceKind::Pod,
                names,
                deadline,
                cancellation,
                ProviderStage::CreateContainer,
            )?
            .ok_or_else(|| provider_error::invalid_state(ProviderStage::CreateContainer))?;
        if !names.expected_ownership().matches(&pod)
            || pod.spec_fingerprint() != manifest.fingerprint()
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        self.verify_container_pod(
            &primary,
            &names.container(),
            pod.identifier(),
            names,
            manifest.fingerprint(),
            deadline,
            cancellation,
            ProviderStage::VerifyOwnership,
        )?;

        let mut addresses_changed = false;
        for entry in manifest.entries().to_vec() {
            let service = self.verify_service_for_spec(
                &entry,
                names,
                manifest.fingerprint(),
                deadline,
                cancellation,
                ProviderStage::CreateContainer,
            )?;
            let address = self.service_network_address(
                service.identifier(),
                manifest.network(),
                deadline,
                cancellation,
            )?;
            let address = address.to_string();
            let changed = entry.address() != Some(address.as_str());
            if manifest.record_address(entry.alias(), &address) != Some(true) {
                return Err(provider_error::ownership_mismatch(
                    ProviderStage::VerifyOwnership,
                ));
            }
            addresses_changed |= changed;
        }
        if addresses_changed {
            self.publish_service_manifest(names, manifest, ProviderStage::CreateContainer)?;
        }

        let mut mappings = Vec::with_capacity(manifest.port_count());
        for entry in manifest.entries() {
            let address = entry
                .address()
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| provider_error::invalid_state(ProviderStage::CreateContainer))?;
            for (port, host) in entry.ports().iter().zip(entry.host_ports()) {
                let listen = port.requested_host_port().or(*host);
                mappings.push(service_proxy_mapping_argument(address, *port, listen));
            }
        }

        let existing = if manifest.proxy_transition() {
            match self.inspect_named_container(
                manifest.proxy_container(),
                deadline,
                cancellation,
                ProviderStage::CreateContainer,
            )? {
                Some(inspection) => Some(self.verify_service_proxy_container(
                    inspection,
                    manifest,
                    names,
                    Some(pod.identifier()),
                    deadline,
                    cancellation,
                    ProviderStage::CreateContainer,
                )?),
                None => None,
            }
        } else {
            match manifest.proxy_identifier() {
                Some(identifier) => match self.inspect_named_container(
                    identifier,
                    deadline,
                    cancellation,
                    ProviderStage::CreateContainer,
                )? {
                    Some(inspection) => Some(self.verify_service_proxy_container(
                        inspection,
                        manifest,
                        names,
                        Some(pod.identifier()),
                        deadline,
                        cancellation,
                        ProviderStage::CreateContainer,
                    )?),
                    None => {
                        if self.named_container_exists(
                            manifest.proxy_container(),
                            deadline,
                            cancellation,
                            ProviderStage::CreateContainer,
                        )? {
                            return Err(provider_error::ownership_mismatch(
                                ProviderStage::VerifyOwnership,
                            ));
                        }
                        if !manifest.begin_proxy_replacement() {
                            return Err(provider_error::invalid_state(
                                ProviderStage::CreateContainer,
                            ));
                        }
                        self.publish_service_manifest(
                            names,
                            manifest,
                            ProviderStage::CreateContainer,
                        )?;
                        None
                    }
                },
                None => match self.inspect_named_container(
                    manifest.proxy_container(),
                    deadline,
                    cancellation,
                    ProviderStage::CreateContainer,
                )? {
                    Some(_) => {
                        return Err(provider_error::ownership_mismatch(
                            ProviderStage::VerifyOwnership,
                        ));
                    }
                    None => None,
                },
            }
        };

        let proxy = match existing {
            Some(proxy) if proxy.state() == Some("running") => proxy,
            Some(proxy) => {
                self.remove_verified_proxy_container(
                    &proxy,
                    manifest,
                    names,
                    deadline,
                    cancellation,
                )?;
                if !manifest.begin_proxy_replacement() {
                    return Err(provider_error::uncertain(
                        ProviderErrorKind::InvalidState,
                        ProviderStage::CreateContainer,
                        names.handle(),
                    ));
                }
                self.publish_service_manifest(names, manifest, ProviderStage::CreateContainer)?;
                self.create_service_proxy_container(
                    names,
                    labels,
                    manifest,
                    pod.identifier(),
                    &mappings,
                    deadline,
                    cancellation,
                )?
            }
            None => {
                if !manifest.proxy_transition() {
                    if !manifest.begin_proxy_replacement() {
                        return Err(provider_error::invalid_state(
                            ProviderStage::CreateContainer,
                        ));
                    }
                    self.publish_service_manifest(names, manifest, ProviderStage::CreateContainer)?;
                }
                self.create_service_proxy_container(
                    names,
                    labels,
                    manifest,
                    pod.identifier(),
                    &mappings,
                    deadline,
                    cancellation,
                )?
            }
        };
        let Some(proxy_changed) = manifest.finish_proxy_replacement(proxy.identifier()) else {
            return Err(provider_error::invalid_state(
                ProviderStage::CreateContainer,
            ));
        };
        if proxy_changed {
            self.publish_service_manifest(names, manifest, ProviderStage::CreateContainer)?;
        }

        if proxy.state() != Some("running") {
            let mut arguments = self.base_arguments();
            arguments.extend(os_args(["start"]));
            arguments.push(proxy.identifier().into());
            self.run_mutation(
                arguments,
                deadline,
                cancellation,
                ProviderStage::Start,
                names.handle(),
            )?;
        }
        let process_id = self.named_container_process_id(
            proxy.identifier(),
            deadline,
            cancellation,
            ProviderStage::Start,
        )?;
        if !self
            .executor
            .enforces_job_cgroup(process_id, pod_cgroup, manifest.aggregate_pids())
            || self.named_container_process_id(
                proxy.identifier(),
                deadline,
                cancellation,
                ProviderStage::Start,
            )? != process_id
        {
            return Err(provider_error::uncertain(
                ProviderErrorKind::InvalidState,
                ProviderStage::Start,
                names.handle(),
            ));
        }
        let ports = self.wait_for_service_proxy_status(
            proxy.identifier(),
            manifest.port_count(),
            deadline,
            cancellation,
            ProviderStage::Start,
        )?;
        match manifest.record_host_ports(&ports) {
            Some(true) => self.publish_service_manifest(names, manifest, ProviderStage::Start),
            Some(false) => Ok(()),
            None => Err(provider_error::invalid_state(ProviderStage::Start)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn create_service_proxy_container(
        &self,
        names: &ResourceNames,
        labels: &ProvisionLabels<'_>,
        manifest: &mut ServiceManifest,
        pod_identifier: &str,
        mappings: &[String],
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<InspectedServiceContainer, ProviderError> {
        let image = manifest
            .proxy_image()
            .ok_or_else(|| provider_error::invalid_state(ProviderStage::Validate))?;
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["create"]));
        push_option(&mut arguments, "--name", manifest.proxy_container());
        push_labels(&mut arguments, labels.arguments);
        arguments.extend(os_args([
            "--pull=never",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--restart=no",
            "--read-only",
            "--read-only-tmpfs=false",
            "--image-volume=tmpfs",
            "--unsetenv-all",
            "--no-healthcheck",
        ]));
        push_option(
            &mut arguments,
            "--pids-limit",
            manifest.aggregate_pids().to_string(),
        );
        push_option(&mut arguments, "--pod", pod_identifier);
        push_option(&mut arguments, "--entrypoint", SERVICE_PROXY_ENTRYPOINT);
        arguments.push(image.into());
        arguments.push(SERVICE_PROXY_SERVE_COMMAND.into());
        arguments.extend(mappings.iter().map(OsString::from));
        let output = self.run_mutation(
            arguments,
            deadline,
            cancellation,
            ProviderStage::CreateContainer,
            names.handle(),
        )?;
        let identifier = parse_container_identifier(output.stdout()).ok_or_else(|| {
            provider_error::uncertain(
                ProviderErrorKind::InvalidState,
                ProviderStage::CreateContainer,
                names.handle(),
            )
        })?;
        if manifest
            .record_pending_proxy_identifier(identifier)
            .is_none()
        {
            return Err(provider_error::uncertain(
                ProviderErrorKind::InvalidState,
                ProviderStage::CreateContainer,
                names.handle(),
            ));
        }
        self.publish_service_manifest(names, manifest, ProviderStage::CreateContainer)?;
        let inspection = self
            .inspect_named_container(
                identifier,
                deadline,
                cancellation,
                ProviderStage::VerifyOwnership,
            )?
            .ok_or_else(|| provider_error::invalid_state(ProviderStage::VerifyOwnership))?;
        self.verify_service_proxy_container(
            inspection,
            manifest,
            names,
            Some(pod_identifier),
            deadline,
            cancellation,
            ProviderStage::VerifyOwnership,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_service_proxy_container(
        &self,
        inspection: InspectedServiceContainer,
        manifest: &ServiceManifest,
        names: &ResourceNames,
        pod_identifier: Option<&str>,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<InspectedServiceContainer, ProviderError> {
        if !names.expected_ownership().matches(&inspection)
            || inspection.spec_fingerprint() != manifest.fingerprint()
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        let named_container = self
            .inspect_named_container(manifest.proxy_container(), deadline, cancellation, stage)?
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        if named_container.identifier() != inspection.identifier() {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        let image = manifest
            .proxy_image()
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        let mut arguments = self.base_arguments();
        arguments.extend(os_args([
            "container",
            "inspect",
            "--format",
            SERVICE_PROXY_CONFIG_FORMAT,
        ]));
        arguments.push(inspection.identifier().into());
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation, stage),
            stage,
            None,
        )?;
        let actual = std::str::from_utf8(output.stdout())
            .ok()
            .map(str::trim_end)
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        let mut lines = actual.split('\n');
        let actual_image = lines.next();
        let actual_pod = lines.next();
        let actual_entrypoint = lines.next();
        let actual_command = lines.next();
        let valid_pod = actual_pod
            .is_some_and(|value| parse_container_identifier(value.as_bytes()) == Some(value));
        let valid_entrypoint = actual_entrypoint
            .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
            .is_some_and(|value| value.as_slice() == [SERVICE_PROXY_ENTRYPOINT]);
        if lines.next().is_some()
            || actual_image != Some(image)
            || !valid_pod
            || pod_identifier.is_some_and(|expected| actual_pod != Some(expected))
            || !valid_entrypoint
            || actual_command.is_none_or(|value| !service_proxy_command_matches(manifest, value))
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        let stable = self
            .inspect_named_container(manifest.proxy_container(), deadline, cancellation, stage)?
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        if stable.identifier() != inspection.identifier()
            || !names.expected_ownership().matches(&stable)
            || stable.spec_fingerprint() != manifest.fingerprint()
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        Ok(inspection)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_container_pod(
        &self,
        inspection: &InspectedServiceContainer,
        expected_name: &str,
        expected_pod: &str,
        names: &ResourceNames,
        fingerprint: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<(), ProviderError> {
        let mut arguments = self.base_arguments();
        arguments.extend(os_args([
            "container",
            "inspect",
            "--format",
            CONTAINER_POD_FORMAT,
        ]));
        arguments.push(inspection.identifier().into());
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation, stage),
            stage,
            None,
        )?;
        let actual_pod = std::str::from_utf8(output.stdout()).ok().and_then(|value| {
            let value = value.strip_suffix('\n').unwrap_or(value);
            (!value.contains(['\n', '\r'])).then_some(value)
        });
        let stable = self
            .inspect_named_container(expected_name, deadline, cancellation, stage)?
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        if actual_pod != Some(expected_pod)
            || stable.identifier() != inspection.identifier()
            || !names.expected_ownership().matches(&stable)
            || stable.spec_fingerprint() != fingerprint
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        Ok(())
    }

    fn service_network_address(
        &self,
        identifier: &str,
        network: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<std::net::Ipv4Addr, ProviderError> {
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["container", "inspect", "--format"]));
        arguments.push(service_network_address_format(network).into());
        arguments.push(identifier.into());
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation, ProviderStage::Inspect),
            ProviderStage::Inspect,
            None,
        )?;
        parse_proxy_service_address(output.stdout())
            .ok_or_else(|| provider_error::invalid_state(ProviderStage::Inspect))
    }

    fn wait_for_service_proxy_status(
        &self,
        identifier: &str,
        expected_ports: usize,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<Vec<u16>, ProviderError> {
        loop {
            if cancellation.is_cancelled() {
                return Err(provider_error::known(ProviderErrorKind::Cancelled, stage));
            }
            if Instant::now() >= deadline {
                return Err(provider_error::known(ProviderErrorKind::TimedOut, stage));
            }
            let mut arguments = self.base_arguments();
            arguments.extend(os_args(["logs"]));
            arguments.push(identifier.into());
            let output = Self::require_success(
                self.run(arguments, deadline, cancellation, stage),
                stage,
                None,
            )?;
            if output.stdout().is_empty() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                thread::sleep(SERVICE_HEALTH_POLL_INTERVAL.min(remaining));
                continue;
            }
            return parse_service_proxy_status(output.stdout(), expected_ports)
                .ok_or_else(|| provider_error::invalid_state(stage));
        }
    }

    fn verify_service_proxy_for_lookup(
        &self,
        manifest: &ServiceManifest,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<(), ProviderError> {
        if manifest.port_count() == 0 {
            return Ok(());
        }
        let primary = self
            .inspect_named_container(&names.container(), deadline, cancellation, stage)?
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        if !names.expected_ownership().matches(&primary)
            || primary.spec_fingerprint() != manifest.fingerprint()
            || primary.state() != Some("running")
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        let pod = self
            .inspect_resource(ResourceKind::Pod, names, deadline, cancellation, stage)?
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        if !names.expected_ownership().matches(&pod)
            || pod.spec_fingerprint() != manifest.fingerprint()
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        self.verify_container_pod(
            &primary,
            &names.container(),
            pod.identifier(),
            names,
            manifest.fingerprint(),
            deadline,
            cancellation,
            ProviderStage::VerifyOwnership,
        )?;
        let identifier = manifest
            .proxy_identifier()
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        let proxy = self
            .inspect_named_container(identifier, deadline, cancellation, stage)?
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        let proxy = self.verify_service_proxy_container(
            proxy,
            manifest,
            names,
            Some(pod.identifier()),
            deadline,
            cancellation,
            stage,
        )?;
        if proxy.state() != Some("running") {
            return Err(provider_error::invalid_state(stage));
        }
        let ports = self.wait_for_service_proxy_status(
            proxy.identifier(),
            manifest.port_count(),
            deadline,
            cancellation,
            stage,
        )?;
        let expected = manifest
            .entries()
            .iter()
            .flat_map(ServiceManifestEntry::host_ports)
            .copied()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| provider_error::invalid_state(stage))?;
        if ports != expected {
            return Err(provider_error::invalid_state(stage));
        }
        for entry in manifest.entries() {
            if entry.ports().is_empty() {
                continue;
            }
            let identifier = entry
                .identifier()
                .ok_or_else(|| provider_error::invalid_state(stage))?;
            let address = self.service_network_address(
                identifier,
                manifest.network(),
                deadline,
                cancellation,
            )?;
            if entry.address() != Some(address.to_string().as_str()) {
                return Err(provider_error::invalid_state(stage));
            }
        }
        Ok(())
    }

    fn service_bindings(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<ServiceContainerBindings, ProviderError> {
        let deadline = self.operation_deadline();
        let inspection = self.inspect_with_deadline(handle, deadline, cancellation)?;
        if inspection.state() != SandboxState::Running {
            return Err(provider_error::invalid_state(ProviderStage::Inspect));
        }
        let names = ResourceNames::from_handle(handle, &self.provider_id)?;
        let manifest = self
            .load_service_manifest(&names, ProviderStage::Inspect)?
            .ok_or_else(|| provider_error::invalid_state(ProviderStage::Inspect))?;
        self.collect_service_bindings(&manifest, &names, deadline, cancellation)
    }

    fn collect_service_bindings(
        &self,
        manifest: &ServiceManifest,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<ServiceContainerBindings, ProviderError> {
        let network = ServiceNetwork::new(manifest.network())
            .map_err(|_| provider_error::invalid_state(ProviderStage::Inspect))?;
        self.verify_service_proxy_for_lookup(
            manifest,
            names,
            deadline,
            cancellation,
            ProviderStage::Inspect,
        )?;
        let mut values = BTreeMap::new();
        for entry in manifest.entries() {
            if self.service_readiness(
                entry,
                names,
                manifest.fingerprint(),
                deadline,
                cancellation,
                ProviderStage::Inspect,
            )? != ServiceReadiness::Ready
            {
                return Err(provider_error::invalid_state(ProviderStage::Inspect));
            }
            let inspection = self.verify_service_for_spec(
                entry,
                names,
                manifest.fingerprint(),
                deadline,
                cancellation,
                ProviderStage::Inspect,
            )?;
            let ports = entry
                .ports()
                .iter()
                .zip(entry.host_ports())
                .map(|(port, host)| {
                    let host =
                        host.ok_or_else(|| provider_error::invalid_state(ProviderStage::Inspect))?;
                    ServicePortBinding::new(*port, host)
                        .map_err(|_| provider_error::invalid_state(ProviderStage::Inspect))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let container = ContainerHandle::new(inspection.identifier())
                .map_err(|_| provider_error::invalid_state(ProviderStage::Inspect))?;
            let binding = ServiceContainerBinding::new(container, network.clone(), ports)
                .map_err(|_| provider_error::invalid_state(ProviderStage::Inspect))?;
            values.insert(entry.alias().to_owned(), binding);
        }
        ServiceContainerBindings::new(values)
            .map_err(|_| provider_error::invalid_state(ProviderStage::Inspect))
    }

    pub(crate) fn inspect(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        self.inspect_with_deadline(handle, self.operation_deadline(), cancellation)
    }

    fn inspect_with_deadline(
        &self,
        handle: &SandboxHandle,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        let names = ResourceNames::from_handle(handle, &self.provider_id)?;
        let network = self.inspect_resource(
            ResourceKind::Network,
            &names,
            deadline,
            cancellation,
            ProviderStage::Inspect,
        )?;
        let pod = self.inspect_resource(
            ResourceKind::Pod,
            &names,
            deadline,
            cancellation,
            ProviderStage::Inspect,
        )?;
        let container = self.inspect_resource(
            ResourceKind::Container,
            &names,
            deadline,
            cancellation,
            ProviderStage::Inspect,
        )?;
        let present = [network.as_ref(), pod.as_ref(), container.as_ref()];
        if present.iter().all(Option::is_none) {
            return Err(provider_error::known(
                ProviderErrorKind::NotFound,
                ProviderStage::Inspect,
            ));
        }
        let expected = names.expected_ownership();
        if present
            .iter()
            .flatten()
            .any(|labels| !expected.matches(labels))
        {
            return Err(provider_error::ownership_mismatch(ProviderStage::Inspect));
        }
        let labels = [network.as_deref(), pod.as_deref(), container.as_deref()];
        let profile = consistent_profile(labels)?;
        let core_fingerprint = ensure_consistent_fingerprint(labels)?;
        let workspace = self
            .state
            .workspace_exists(&names.workspace())
            .map_err(|_| provider_error::local_storage(ProviderStage::Inspect))?;
        let mut state = aggregate_state(
            network.is_some(),
            pod.is_some(),
            container.as_deref().and_then(InspectedLabels::state),
            workspace,
        );
        let manifest = self
            .load_service_manifest(&names, ProviderStage::Inspect)?
            .ok_or_else(|| provider_error::invalid_state(ProviderStage::Inspect))?;
        if manifest.fingerprint() != core_fingerprint {
            return Err(provider_error::invalid_state(ProviderStage::Inspect));
        }
        if state == SandboxState::Running {
            for entry in manifest.entries() {
                if self.service_readiness(
                    entry,
                    &names,
                    manifest.fingerprint(),
                    deadline,
                    cancellation,
                    ProviderStage::Inspect,
                )? != ServiceReadiness::Ready
                {
                    state = SandboxState::Degraded;
                    break;
                }
            }
            if state == SandboxState::Running
                && let Err(error) = self.verify_service_proxy_for_lookup(
                    &manifest,
                    &names,
                    deadline,
                    cancellation,
                    ProviderStage::Inspect,
                )
            {
                if error.kind() == ProviderErrorKind::InvalidState {
                    state = SandboxState::Degraded;
                } else {
                    return Err(error);
                }
            }
        }
        Ok(SandboxInspection::new(
            handle.clone(),
            names.generation(),
            profile,
            state,
        ))
    }

    fn destroy(
        &self,
        request: &DestroySandbox,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        let names = ResourceNames::from_handle(request.handle(), &self.provider_id)?;
        if names.generation() != request.generation() {
            return Err(provider_error::known(
                ProviderErrorKind::Conflict,
                ProviderStage::Validate,
            ));
        }
        let deadline = self.operation_deadline();
        let (manifest, mut removed) =
            self.remove_services_for_destroy(request, &names, deadline, cancellation)?;
        fence_destroy_result(
            self.stop_job_docker_service(&names),
            removed,
            request.handle(),
        )?;
        if self.options.job_container_engine() == JobContainerEngine::AttemptScopedDockerApi {
            fence_destroy_result(
                self.cleanup_job_engine(&names, deadline, cancellation),
                removed,
                request.handle(),
            )?;
        }
        let primary = fence_destroy_result(
            self.remove_exact(ResourceKind::Container, &names, deadline, cancellation),
            removed,
            request.handle(),
        )?;
        removed |= primary;
        let pod = fence_destroy_result(
            self.remove_exact(ResourceKind::Pod, &names, deadline, cancellation),
            removed,
            request.handle(),
        )?;
        removed |= pod;
        let network = fence_destroy_result(
            self.remove_exact(ResourceKind::Network, &names, deadline, cancellation),
            removed,
            request.handle(),
        )?;
        removed |= network;
        let workspace = fence_destroy_result(
            self.remove_exact_workspace(&names, deadline, cancellation),
            removed,
            request.handle(),
        )?;
        removed |= workspace;
        if self.options.job_container_engine() == JobContainerEngine::AttemptScopedDockerApi {
            removed |= self
                .state
                .remove_job_engine(&names.workspace())
                .map_err(|_| {
                    provider_error::uncertain(
                        ProviderErrorKind::LocalStorage,
                        ProviderStage::DestroyWorkspace,
                        request.handle().clone(),
                    )
                })?;
        }
        if manifest.is_some() {
            removed |= self
                .state
                .remove_service_manifest(&names.workspace())
                .map_err(|_| {
                    provider_error::uncertain(
                        ProviderErrorKind::LocalStorage,
                        ProviderStage::DestroyContainer,
                        request.handle().clone(),
                    )
                })?;
        }
        Ok(if removed {
            DestroyDisposition::Destroyed
        } else {
            DestroyDisposition::AlreadyAbsent
        })
    }

    fn remove_services_for_destroy(
        &self,
        request: &DestroySandbox,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(Option<ServiceManifest>, bool), ProviderError> {
        let manifest = self.load_service_manifest(names, ProviderStage::DestroyContainer)?;
        let Some(current) = manifest.as_ref() else {
            for kind in [
                ResourceKind::Network,
                ResourceKind::Pod,
                ResourceKind::Container,
            ] {
                if self.resource_exists(
                    kind,
                    names,
                    deadline,
                    cancellation,
                    ProviderStage::DestroySandbox,
                )? {
                    return Err(provider_error::invalid_state(ProviderStage::DestroySandbox));
                }
            }
            return Ok((None, false));
        };
        self.verify_manifest_core_fingerprint(
            names,
            current.fingerprint(),
            deadline,
            cancellation,
            ProviderStage::DestroyContainer,
        )?;
        let mut removed =
            self.remove_service_proxy_container(current, names, deadline, cancellation)?;
        for entry in current.entries().iter().rev() {
            match self.remove_service_container(
                entry,
                names,
                current.fingerprint(),
                deadline,
                cancellation,
            ) {
                Ok(service_removed) => removed |= service_removed,
                Err(error) if removed => {
                    return Err(destroy_service_error(&error, request.handle().clone()));
                }
                Err(error) => return Err(error),
            }
        }
        Ok((manifest, removed))
    }

    #[allow(clippy::single_match_else)]
    fn remove_service_proxy_container(
        &self,
        manifest: &ServiceManifest,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<bool, ProviderError> {
        if manifest.port_count() == 0 {
            return Ok(false);
        }
        let inspection = if manifest.proxy_transition() {
            match self.inspect_named_container(
                manifest.proxy_container(),
                deadline,
                cancellation,
                ProviderStage::DestroyContainer,
            )? {
                Some(inspection) => inspection,
                None => return Ok(false),
            }
        } else {
            match manifest.proxy_identifier() {
                Some(identifier) => match self.inspect_named_container(
                    identifier,
                    deadline,
                    cancellation,
                    ProviderStage::DestroyContainer,
                )? {
                    Some(inspection) => inspection,
                    None => {
                        if self.named_container_exists(
                            manifest.proxy_container(),
                            deadline,
                            cancellation,
                            ProviderStage::DestroyContainer,
                        )? {
                            return Err(provider_error::ownership_mismatch(
                                ProviderStage::VerifyOwnership,
                            ));
                        }
                        return Ok(false);
                    }
                },
                None => match self.inspect_named_container(
                    manifest.proxy_container(),
                    deadline,
                    cancellation,
                    ProviderStage::DestroyContainer,
                )? {
                    Some(_) => {
                        return Err(provider_error::ownership_mismatch(
                            ProviderStage::VerifyOwnership,
                        ));
                    }
                    None => return Ok(false),
                },
            }
        };
        let inspection = self.verify_service_proxy_container(
            inspection,
            manifest,
            names,
            None,
            deadline,
            cancellation,
            ProviderStage::DestroyContainer,
        )?;
        self.remove_verified_proxy_container(&inspection, manifest, names, deadline, cancellation)
    }

    fn remove_verified_proxy_container(
        &self,
        inspection: &InspectedServiceContainer,
        manifest: &ServiceManifest,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<bool, ProviderError> {
        let mut arguments = self.base_arguments();
        arguments.extend(os_args([
            "rm",
            "--force",
            "--ignore",
            "--time",
            "0",
            "--volumes",
        ]));
        arguments.push(inspection.identifier().into());
        self.run_mutation(
            arguments,
            deadline,
            cancellation,
            ProviderStage::DestroyContainer,
            names.handle(),
        )?;
        if self.named_container_exists(
            inspection.identifier(),
            deadline,
            cancellation,
            ProviderStage::DestroyContainer,
        )? {
            return Err(provider_error::uncertain(
                ProviderErrorKind::BackendRejected,
                ProviderStage::DestroyContainer,
                names.handle(),
            ));
        }
        if self.named_container_exists(
            manifest.proxy_container(),
            deadline,
            cancellation,
            ProviderStage::DestroyContainer,
        )? {
            return Err(provider_error::uncertain(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
                names.handle(),
            ));
        }
        Ok(true)
    }

    fn remove_exact_workspace(
        &self,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<bool, ProviderError> {
        let Some(path) = self
            .state
            .workspace_cleanup_target(&names.workspace())
            .map_err(|_| {
                provider_error::uncertain(
                    ProviderErrorKind::LocalStorage,
                    ProviderStage::DestroyWorkspace,
                    names.handle(),
                )
            })?
        else {
            return Ok(false);
        };
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["unshare"]));
        arguments.push(
            self.options
                .user_namespace_remove_program()
                .as_os_str()
                .to_owned(),
        );
        arguments.extend(os_args([
            "--recursive",
            "--force",
            "--one-file-system",
            "--",
        ]));
        arguments.push(path.into_os_string());
        Self::require_success(
            self.run(
                arguments,
                deadline,
                cancellation,
                ProviderStage::DestroyWorkspace,
            ),
            ProviderStage::DestroyWorkspace,
            Some(names.handle()),
        )?;
        self.state
            .confirm_workspace_removed(&names.workspace())
            .map_err(|_| {
                provider_error::uncertain(
                    ProviderErrorKind::LocalStorage,
                    ProviderStage::DestroyWorkspace,
                    names.handle(),
                )
            })?;
        Ok(true)
    }

    fn reject_conflicting_replay(
        &self,
        names: &ResourceNames,
        fingerprint: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        for kind in [
            ResourceKind::Network,
            ResourceKind::Pod,
            ResourceKind::Container,
        ] {
            if let Some(labels) =
                self.inspect_resource(kind, names, deadline, cancellation, ProviderStage::Inspect)?
            {
                if !names.expected_ownership().matches(&labels) {
                    return Err(provider_error::ownership_mismatch(
                        ProviderStage::VerifyOwnership,
                    ));
                }
                if labels.spec_fingerprint() != fingerprint {
                    return Err(provider_error::known(
                        ProviderErrorKind::Conflict,
                        ProviderStage::Validate,
                    ));
                }
            }
        }
        Ok(())
    }

    fn verify_manifest_core_fingerprint(
        &self,
        names: &ResourceNames,
        fingerprint: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<(), ProviderError> {
        for kind in [
            ResourceKind::Network,
            ResourceKind::Pod,
            ResourceKind::Container,
        ] {
            let Some(labels) = self.inspect_resource(kind, names, deadline, cancellation, stage)?
            else {
                continue;
            };
            if !names.expected_ownership().matches(&labels) {
                return Err(provider_error::ownership_mismatch(
                    ProviderStage::VerifyOwnership,
                ));
            }
            if labels.spec_fingerprint() != fingerprint {
                return Err(provider_error::invalid_state(stage));
            }
        }
        Ok(())
    }

    fn ensure_network(
        &self,
        spec: &SandboxSpec,
        names: &ResourceNames,
        labels: &ProvisionLabels<'_>,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        if self.resource_exists(
            ResourceKind::Network,
            names,
            deadline,
            cancellation,
            ProviderStage::CreateNetwork,
        )? {
            return self.verify_owned_for_spec(
                ResourceKind::Network,
                names,
                spec.profile().attestation(),
                labels.fingerprint,
                deadline,
                cancellation,
            );
        }
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["network", "create"]));
        push_labels(&mut arguments, labels.arguments);
        if spec.network() == NetworkPolicy::Disabled {
            arguments.push("--internal".into());
        }
        arguments.push(names.network().into());
        self.run_mutation(
            arguments,
            deadline,
            cancellation,
            ProviderStage::CreateNetwork,
            names.handle(),
        )?;
        self.verify_owned_for_spec(
            ResourceKind::Network,
            names,
            spec.profile().attestation(),
            labels.fingerprint,
            deadline,
            cancellation,
        )
    }

    fn ensure_pod(
        &self,
        spec: &SandboxSpec,
        names: &ResourceNames,
        labels: &ProvisionLabels<'_>,
        cgroup_parent: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        if self.resource_exists(
            ResourceKind::Pod,
            names,
            deadline,
            cancellation,
            ProviderStage::CreateSandbox,
        )? {
            self.verify_owned_for_spec(
                ResourceKind::Pod,
                names,
                spec.profile().attestation(),
                labels.fingerprint,
                deadline,
                cancellation,
            )?;
            return self.verify_pod_network_sysctl(names, deadline, cancellation);
        }
        let resources = spec.resources();
        let mut arguments = self.base_arguments();
        arguments.extend(os_args([
            "pod",
            "create",
            "--infra=true",
            "--exit-policy=continue",
        ]));
        push_option(&mut arguments, "--name", names.pod());
        push_labels(&mut arguments, labels.arguments);
        push_option(&mut arguments, "--network", names.network());
        push_option(&mut arguments, "--sysctl", JOB_NETWORK_SYSCTL);
        push_option(&mut arguments, "--cgroup-parent", cgroup_parent);
        if let Some(alias) = self.options.host_gateway_alias() {
            arguments.push(format!("--add-host={}:host-gateway", alias.as_str()).into());
        }
        let user_namespace = match spec.privilege() {
            SandboxPrivilegePolicy::Unprivileged => "keep-id",
            SandboxPrivilegePolicy::Administrator => "keep-id:uid=0,gid=0",
            SandboxPrivilegePolicy::Host => {
                return Err(provider_error::known(
                    ProviderErrorKind::UnsupportedCapability,
                    ProviderStage::Validate,
                ));
            }
        };
        push_option(&mut arguments, "--userns", user_namespace);
        push_option(&mut arguments, "--cpus", cpu_value(resources.cpu_millis()));
        push_option(
            &mut arguments,
            "--memory",
            format!("{}b", resources.memory_bytes()),
        );
        push_option(
            &mut arguments,
            "--memory-swap",
            format!("{}b", resources.memory_bytes()),
        );
        self.run_mutation(
            arguments,
            deadline,
            cancellation,
            ProviderStage::CreateSandbox,
            names.handle(),
        )?;
        self.verify_owned_for_spec(
            ResourceKind::Pod,
            names,
            spec.profile().attestation(),
            labels.fingerprint,
            deadline,
            cancellation,
        )?;
        self.verify_pod_network_sysctl(names, deadline, cancellation)
    }

    fn verify_pod_network_sysctl(
        &self,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let infra_identifier = self.pod_infra_identifier(names, deadline, cancellation)?;
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["container", "inspect", "--format"]));
        arguments.push(JOB_NETWORK_SYSCTL_FORMAT.into());
        arguments.push(infra_identifier.clone().into());
        let output = Self::require_success(
            self.run(
                arguments,
                deadline,
                cancellation,
                ProviderStage::VerifyOwnership,
            ),
            ProviderStage::VerifyOwnership,
            None,
        )?;
        if output.stdout() != b"0\n" && output.stdout() != b"0" {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        if self.pod_infra_identifier(names, deadline, cancellation)? != infra_identifier {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        Ok(())
    }

    fn pod_infra_identifier(
        &self,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<String, ProviderError> {
        let mut arguments = self.base_arguments();
        arguments.extend(os_args([
            "pod",
            "inspect",
            "--format",
            POD_INFRA_CONTAINER_FORMAT,
        ]));
        arguments.push(names.pod().into());
        let output = Self::require_success(
            self.run(
                arguments,
                deadline,
                cancellation,
                ProviderStage::VerifyOwnership,
            ),
            ProviderStage::VerifyOwnership,
            None,
        )?;
        parse_container_identifier(output.stdout())
            .map(str::to_owned)
            .ok_or_else(|| provider_error::invalid_state(ProviderStage::VerifyOwnership))
    }

    fn ensure_container(
        &self,
        spec: &SandboxSpec,
        names: &ResourceNames,
        labels: &ProvisionLabels<'_>,
        storage: ProvisionStorage<'_>,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        if self.resource_exists(
            ResourceKind::Container,
            names,
            deadline,
            cancellation,
            ProviderStage::CreateContainer,
        )? {
            return self.verify_owned_for_spec(
                ResourceKind::Container,
                names,
                spec.profile().attestation(),
                labels.fingerprint,
                deadline,
                cancellation,
            );
        }
        let mount = workspace_mount(storage.workspace, spec.workspace().as_str())?;
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["create"]));
        push_option(&mut arguments, "--name", names.container());
        push_option(&mut arguments, "--pod", names.pod());
        push_labels(&mut arguments, labels.arguments);
        arguments.push("--pull=never".into());
        if spec.root_filesystem() == RootFilesystemPolicy::ReadOnly {
            arguments.extend(os_args(["--read-only", "--read-only-tmpfs=false"]));
        }
        arguments.push("--cap-drop=all".into());
        push_administrator_capabilities(&mut arguments, spec.privilege());
        arguments.extend(os_args([
            "--security-opt=no-new-privileges",
            "--restart=no",
            "--unsetenv-all",
            "--init",
        ]));
        push_job_engine_create_options(&mut arguments, storage.engine)?;
        push_option(
            &mut arguments,
            "--pids-limit",
            spec.resources().pids().to_string(),
        );
        push_option(&mut arguments, "--volume", mount);
        push_option(&mut arguments, "--workdir", spec.workspace().as_str());
        push_option(
            &mut arguments,
            "--entrypoint",
            spec.profile()
                .keepalive()
                .expect("validated container profile")
                .program()
                .as_str(),
        );
        arguments.push(
            spec.profile()
                .image()
                .expect("validated container profile")
                .reference()
                .into(),
        );
        arguments.extend(
            spec.profile()
                .keepalive()
                .expect("validated container profile")
                .arguments()
                .iter()
                .map(OsString::from),
        );
        self.run_mutation(
            arguments,
            deadline,
            cancellation,
            ProviderStage::CreateContainer,
            names.handle(),
        )?;
        self.verify_owned_for_spec(
            ResourceKind::Container,
            names,
            spec.profile().attestation(),
            labels.fingerprint,
            deadline,
            cancellation,
        )
    }

    fn ensure_started(
        &self,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let inspection = self
            .inspect_resource(
                ResourceKind::Container,
                names,
                deadline,
                cancellation,
                ProviderStage::Start,
            )?
            .ok_or_else(|| provider_error::invalid_state(ProviderStage::Start))?;
        if inspection.state() == Some("running") {
            return Ok(());
        }
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["start"]));
        arguments.push(names.container().into());
        self.run_mutation(
            arguments,
            deadline,
            cancellation,
            ProviderStage::Start,
            names.handle(),
        )
        .map(|_| ())
    }

    fn ensure_no_swap_cgroup(
        &self,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<(), ProviderError> {
        let result = (|| {
            let process_id = self.container_process_id(names, deadline, cancellation, stage)?;
            let manifest = self
                .load_service_manifest(names, stage)?
                .ok_or_else(|| provider_error::invalid_state(stage))?;
            let pod_cgroup = self.pod_cgroup_path(names, deadline, cancellation, stage)?;
            if !self.executor.enforces_job_cgroup(
                process_id,
                &pod_cgroup,
                manifest.aggregate_pids(),
            ) || self.container_process_id(names, deadline, cancellation, stage)? != process_id
            {
                return Err(provider_error::uncertain(
                    ProviderErrorKind::InvalidState,
                    stage,
                    names.handle(),
                ));
            }
            Ok(())
        })();
        if result.is_err() {
            self.quarantine_no_swap_failure(names);
        }
        result
    }

    fn quarantine_no_swap_failure(&self, names: &ResourceNames) {
        let cancellation = NeverCancelled;
        let deadline = self.operation_deadline();
        let _ignored = self.stop_job_docker_service(names);
        if self.options.job_container_engine() == JobContainerEngine::AttemptScopedDockerApi {
            let _ignored = self.cleanup_job_engine(names, deadline, &cancellation);
        }
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["pod", "stop", "--time", "0"]));
        arguments.push(names.pod().into());
        let _ignored = self.run(
            arguments,
            deadline,
            &cancellation,
            ProviderStage::DestroySandbox,
        );
    }

    fn container_process_id(
        &self,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<u32, ProviderError> {
        let mut arguments = self.base_arguments();
        arguments.extend(os_args([
            "container",
            "inspect",
            "--format",
            "{{.State.Pid}}",
        ]));
        arguments.push(names.container().into());
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation, stage),
            stage,
            Some(names.handle()),
        )?;
        parse_process_id(output.stdout()).ok_or_else(|| {
            provider_error::uncertain(ProviderErrorKind::InvalidState, stage, names.handle())
        })
    }

    fn ensure_job_docker_service(
        &self,
        spec: &SandboxSpec,
        names: &ResourceNames,
        paths: &JobEnginePaths,
        listener: Option<JobDockerListener>,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        {
            let services = self
                .docker_services
                .lock()
                .map_err(|_| provider_error::local_storage(ProviderStage::CreateContainer))?;
            if services.contains_key(names.handle().opaque()) {
                return Ok(());
            }
        }
        let listener = listener.ok_or_else(|| {
            provider_error::uncertain(
                ProviderErrorKind::AdapterUnavailable,
                ProviderStage::CreateContainer,
                names.handle(),
            )
        })?;
        let process_id = self.container_process_id(
            names,
            deadline,
            cancellation,
            ProviderStage::CreateContainer,
        )?;
        let cgroup = process_cgroup(process_id).map_err(|()| {
            provider_error::uncertain(
                ProviderErrorKind::InvalidState,
                ProviderStage::CreateContainer,
                names.handle(),
            )
        })?;
        let mut service = JobDockerService::start(
            &self.options,
            paths,
            listener,
            JobDockerLaunch::new(&names.handle(), process_id, cgroup, spec.resources()),
            Arc::clone(&self.observer),
        )
        .map_err(|_| {
            provider_error::uncertain(
                ProviderErrorKind::AdapterUnavailable,
                ProviderStage::CreateContainer,
                names.handle(),
            )
        })?;
        let mut services = self
            .docker_services
            .lock()
            .map_err(|_| provider_error::local_storage(ProviderStage::CreateContainer))?;
        if services.contains_key(names.handle().opaque()) {
            service.stop();
        } else {
            services.insert(names.handle().opaque().to_owned(), service);
        }
        Ok(())
    }

    fn has_job_docker_service(&self, names: &ResourceNames) -> Result<bool, ProviderError> {
        let services = self
            .docker_services
            .lock()
            .map_err(|_| provider_error::local_storage(ProviderStage::CreateContainer))?;
        Ok(services.contains_key(names.handle().opaque()))
    }

    fn stop_job_docker_service(&self, names: &ResourceNames) -> Result<(), ProviderError> {
        let service = self
            .docker_services
            .lock()
            .map_err(|_| provider_error::local_storage(ProviderStage::DestroyContainer))?
            .remove(names.handle().opaque());
        if let Some(mut service) = service {
            service.stop();
        }
        Ok(())
    }

    fn cleanup_job_engine(
        &self,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let paths = self
            .state
            .ensure_job_engine(&names.workspace())
            .map_err(|_| provider_error::local_storage(ProviderStage::DestroyContainer))?;
        let ownership = format!("label=io.automata.job-engine={}", names.handle().opaque());
        let container_ids = self.list_job_engine_objects(
            &paths,
            ["ps", "--all", "--quiet", "--filter", ownership.as_str()],
            deadline,
            cancellation,
        )?;
        for identifier in container_ids {
            self.verify_job_engine_object(
                &paths,
                JobEngineObjectKind::Container,
                &identifier,
                names,
                deadline,
                cancellation,
            )?;
            let mut arguments = self.options.global_arguments(
                paths.graph_root(),
                paths.run_root(),
                paths.tmp_dir(),
            );
            arguments.extend(os_args(["rm", "--force", "--ignore"]));
            arguments.push(identifier.into());
            Self::require_success(
                self.run(
                    arguments,
                    deadline,
                    cancellation,
                    ProviderStage::DestroyContainer,
                ),
                ProviderStage::DestroyContainer,
                Some(names.handle()),
            )?;
        }

        let image_ids = self.list_job_engine_objects(
            &paths,
            ["images", "--quiet", "--filter", ownership.as_str()],
            deadline,
            cancellation,
        )?;
        for identifier in image_ids {
            self.verify_job_engine_object(
                &paths,
                JobEngineObjectKind::Image,
                &identifier,
                names,
                deadline,
                cancellation,
            )?;
            let mut arguments = self.options.global_arguments(
                paths.graph_root(),
                paths.run_root(),
                paths.tmp_dir(),
            );
            arguments.extend(os_args(["image", "rm", "--force"]));
            arguments.push(identifier.into());
            Self::require_success(
                self.run(
                    arguments,
                    deadline,
                    cancellation,
                    ProviderStage::DestroyContainer,
                ),
                ProviderStage::DestroyContainer,
                Some(names.handle()),
            )?;
        }
        Ok(())
    }

    fn list_job_engine_objects<const N: usize>(
        &self,
        paths: &JobEnginePaths,
        command: [&str; N],
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<String>, ProviderError> {
        let mut arguments =
            self.options
                .global_arguments(paths.graph_root(), paths.run_root(), paths.tmp_dir());
        arguments.extend(command.into_iter().map(OsString::from));
        let output = Self::require_success(
            self.run(
                arguments,
                deadline,
                cancellation,
                ProviderStage::DestroyContainer,
            ),
            ProviderStage::DestroyContainer,
            None,
        )?;
        parse_engine_identifiers(output.stdout()).ok_or_else(|| {
            provider_error::known(
                ProviderErrorKind::InvalidState,
                ProviderStage::DestroyContainer,
            )
        })
    }

    fn verify_job_engine_object(
        &self,
        paths: &JobEnginePaths,
        kind: JobEngineObjectKind,
        identifier: &str,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let mut arguments =
            self.options
                .global_arguments(paths.graph_root(), paths.run_root(), paths.tmp_dir());
        arguments.extend(kind.inspect_command().iter().map(OsString::from));
        arguments.push("--format".into());
        arguments.push(job_engine_ownership_format(kind == JobEngineObjectKind::Container).into());
        arguments.push(identifier.into());
        let output = Self::require_success(
            self.run(
                arguments,
                deadline,
                cancellation,
                ProviderStage::VerifyOwnership,
            ),
            ProviderStage::VerifyOwnership,
            None,
        )?;
        let expected = format!("automata-runner\n{}\n", names.handle().opaque());
        if output.stdout() != expected.as_bytes()
            && output.stdout() != expected.trim_end().as_bytes()
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        Ok(())
    }

    fn verify_service_proxy_image(
        &self,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let image = self.options.service_proxy_image().ok_or_else(|| {
            provider_error::known(
                ProviderErrorKind::UnsupportedCapability,
                ProviderStage::Validate,
            )
        })?;
        let reference = image.reference();
        let expected_digest = reference
            .rsplit_once('@')
            .map(|(_, digest)| digest)
            .ok_or_else(|| {
                provider_error::known(
                    ProviderErrorKind::InvalidConfiguration,
                    ProviderStage::Validate,
                )
            })?;
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["image", "exists"]));
        arguments.push(reference.into());
        let exists = self.run(arguments, deadline, cancellation, ProviderStage::Validate);
        match exists.termination() {
            CommandTermination::Exited(Some(0)) if !exists.was_truncated() => {}
            CommandTermination::Exited(Some(1)) if !exists.was_truncated() => {
                return Err(provider_error::known(
                    ProviderErrorKind::InvalidConfiguration,
                    ProviderStage::Validate,
                ));
            }
            _ => {
                Self::require_success(exists, ProviderStage::Validate, None)?;
            }
        }
        let mut arguments = self.base_arguments();
        arguments.extend(os_args([
            "image",
            "inspect",
            "--format",
            SERVICE_PROXY_IMAGE_FORMAT,
        ]));
        arguments.push(reference.into());
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation, ProviderStage::Validate),
            ProviderStage::Validate,
            None,
        )?;
        let expected = format!("{expected_digest}\n{SERVICE_PROXY_IMAGE_VERSION}");
        let actual = std::str::from_utf8(output.stdout())
            .ok()
            .map(str::trim_end)
            .ok_or_else(|| provider_error::invalid_state(ProviderStage::Validate))?;
        if actual != expected {
            return Err(provider_error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            ));
        }
        Ok(())
    }

    fn verify_owned_for_spec(
        &self,
        kind: ResourceKind,
        names: &ResourceNames,
        profile: &EnvironmentProfile,
        fingerprint: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let labels = self
            .inspect_resource(
                kind,
                names,
                deadline,
                cancellation,
                ProviderStage::VerifyOwnership,
            )?
            .ok_or_else(|| provider_error::invalid_state(ProviderStage::VerifyOwnership))?;
        if !names.expected_ownership().matches(&labels)
            || labels.profile().as_ref() != Some(profile)
            || labels.spec_fingerprint() != fingerprint
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        Ok(())
    }

    fn inspect_resource(
        &self,
        kind: ResourceKind,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<Option<InspectedResource>, ProviderError> {
        if !self.resource_exists(kind, names, deadline, cancellation, stage)? {
            return Ok(None);
        }
        let mut arguments = self.base_arguments();
        arguments.extend(kind.inspect_command().iter().map(OsString::from));
        arguments.extend(os_args(["--format"]));
        let expected_name = kind.name(names);
        arguments.push(resource_inspection_format(kind).into());
        arguments.push(expected_name.clone().into());
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation, stage),
            stage,
            None,
        )?;
        parse_inspected_resource(
            output.stdout(),
            kind == ResourceKind::Container,
            &expected_name,
        )
        .map(Some)
        .ok_or_else(|| provider_error::invalid_state(stage))
    }

    fn resource_exists(
        &self,
        kind: ResourceKind,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<bool, ProviderError> {
        self.resource_token_exists(kind, &kind.name(names), deadline, cancellation, stage)
    }

    fn resource_token_exists(
        &self,
        kind: ResourceKind,
        token: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<bool, ProviderError> {
        let mut arguments = self.base_arguments();
        arguments.extend(kind.exists_command().iter().map(OsString::from));
        arguments.push(token.into());
        let output = self.run(arguments, deadline, cancellation, stage);
        match output.termination() {
            CommandTermination::Exited(Some(0)) if !output.was_truncated() => Ok(true),
            CommandTermination::Exited(Some(1)) if !output.was_truncated() => Ok(false),
            _ => Self::require_success(output, stage, None).map(|_| true),
        }
    }

    fn remove_exact(
        &self,
        kind: ResourceKind,
        names: &ResourceNames,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<bool, ProviderError> {
        let stage = kind.destroy_stage();
        let Some(labels) = self.inspect_resource(kind, names, deadline, cancellation, stage)?
        else {
            return Ok(false);
        };
        if !names.expected_ownership().matches(&labels) {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        let mut arguments = self.base_arguments();
        arguments.extend(kind.remove_command().iter().map(OsString::from));
        arguments.push(labels.identifier().into());
        self.run_mutation(arguments, deadline, cancellation, stage, names.handle())?;
        let still_exists = self
            .resource_token_exists(kind, labels.identifier(), deadline, cancellation, stage)
            .map_err(|error| destroy_service_error(&error, names.handle()))?;
        if still_exists {
            return Err(provider_error::uncertain(
                ProviderErrorKind::BackendRejected,
                stage,
                names.handle(),
            ));
        }
        if self
            .resource_exists(kind, names, deadline, cancellation, stage)
            .map_err(|error| destroy_service_error(&error, names.handle()))?
        {
            return Err(provider_error::uncertain(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
                names.handle(),
            ));
        }
        Ok(true)
    }

    #[allow(clippy::single_match_else, clippy::too_many_lines)]
    fn remove_service_container(
        &self,
        entry: &ServiceManifestEntry,
        names: &ResourceNames,
        fingerprint: &str,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<bool, ProviderError> {
        let inspection = if entry.transition() {
            let Some(named_container) = self.inspect_named_container(
                entry.container(),
                deadline,
                cancellation,
                ProviderStage::DestroyContainer,
            )?
            else {
                return Ok(false);
            };
            let pending_matches_name = if let Some(identifier) = entry.identifier() {
                self.inspect_named_container(
                    identifier,
                    deadline,
                    cancellation,
                    ProviderStage::DestroyContainer,
                )?
                .is_some_and(|pending| pending.identifier() == named_container.identifier())
            } else {
                false
            };
            if pending_matches_name {
                self.inspect_service_container_base(
                    entry.identifier().ok_or_else(|| {
                        provider_error::invalid_state(ProviderStage::DestroyContainer)
                    })?,
                    entry,
                    names,
                    fingerprint,
                    deadline,
                    cancellation,
                    ProviderStage::DestroyContainer,
                )?
            } else {
                self.inspect_service_container(
                    entry.container(),
                    entry,
                    names,
                    fingerprint,
                    deadline,
                    cancellation,
                    ProviderStage::DestroyContainer,
                )?
            }
        } else {
            match entry.identifier() {
                Some(identifier) => match self.inspect_named_container(
                    identifier,
                    deadline,
                    cancellation,
                    ProviderStage::DestroyContainer,
                )? {
                    Some(inspection) => inspection,
                    None => {
                        if self.named_container_exists(
                            entry.container(),
                            deadline,
                            cancellation,
                            ProviderStage::DestroyContainer,
                        )? {
                            return Err(provider_error::ownership_mismatch(
                                ProviderStage::VerifyOwnership,
                            ));
                        }
                        return Ok(false);
                    }
                },
                None => match self.inspect_named_container(
                    entry.container(),
                    deadline,
                    cancellation,
                    ProviderStage::DestroyContainer,
                )? {
                    Some(_) => {
                        return Err(provider_error::ownership_mismatch(
                            ProviderStage::VerifyOwnership,
                        ));
                    }
                    None => return Ok(false),
                },
            }
        };
        if !names.expected_ownership().matches(&inspection)
            || inspection.spec_fingerprint() != fingerprint
        {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        let named_container = self
            .inspect_named_container(
                entry.container(),
                deadline,
                cancellation,
                ProviderStage::DestroyContainer,
            )?
            .ok_or_else(|| provider_error::invalid_state(ProviderStage::DestroyContainer))?;
        if named_container.identifier() != inspection.identifier() {
            return Err(provider_error::ownership_mismatch(
                ProviderStage::VerifyOwnership,
            ));
        }
        let mut arguments = self.base_arguments();
        arguments.extend(os_args([
            "rm",
            "--force",
            "--ignore",
            "--time",
            "0",
            "--volumes",
        ]));
        arguments.push(inspection.identifier().into());
        self.run_mutation(
            arguments,
            deadline,
            cancellation,
            ProviderStage::DestroyContainer,
            names.handle(),
        )?;
        let still_exists = self
            .named_container_exists(
                inspection.identifier(),
                deadline,
                cancellation,
                ProviderStage::DestroyContainer,
            )
            .map_err(|error| destroy_service_error(&error, names.handle()))?;
        if still_exists {
            return Err(provider_error::uncertain(
                ProviderErrorKind::BackendRejected,
                ProviderStage::DestroyContainer,
                names.handle(),
            ));
        }
        if self
            .named_container_exists(
                entry.container(),
                deadline,
                cancellation,
                ProviderStage::DestroyContainer,
            )
            .map_err(|error| destroy_service_error(&error, names.handle()))?
        {
            return Err(provider_error::uncertain(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
                names.handle(),
            ));
        }
        Ok(true)
    }

    pub(crate) fn run_endpoint(
        &self,
        arguments: Vec<OsString>,
        timeout: Duration,
        output_limit: usize,
        cancellation: &dyn Cancellation,
        stage: automata_ci_execution::ExecutionStage,
    ) -> CommandOutput {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let request = CommandRequest::new(
            self.options.binary().as_path().to_path_buf(),
            arguments,
            timeout.min(self.options.limits().operation_timeout()),
            deadline,
            output_limit.min(self.options.limits().output_limit()),
        );
        self.execute_observed(&request, cancellation, PodmanCommandStage::Endpoint(stage))
    }

    pub(crate) fn run_endpoint_with_environment(
        &self,
        arguments: Vec<OsString>,
        environment_document: EnvironmentDocument,
        timeout: Duration,
        output_limit: usize,
        cancellation: &dyn Cancellation,
        stage: automata_ci_execution::ExecutionStage,
    ) -> CommandOutput {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let mut request = CommandRequest::new(
            self.options.binary().as_path().to_path_buf(),
            arguments,
            timeout,
            deadline,
            output_limit,
        );
        if !environment_document.is_empty() {
            request = request.with_environment_stdin(environment_document);
        }
        self.execute_observed(&request, cancellation, PodmanCommandStage::Endpoint(stage))
    }

    pub(crate) fn run_endpoint_transport(
        &self,
        arguments: Vec<OsString>,
        stdin: Option<Vec<u8>>,
        timeout: Duration,
        output_limit: usize,
        cancellation: &dyn Cancellation,
        stage: automata_ci_execution::ExecutionStage,
    ) -> CommandOutput {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let mut request = CommandRequest::new(
            self.options.binary().as_path().to_path_buf(),
            arguments,
            timeout.min(self.options.limits().operation_timeout()),
            deadline,
            output_limit,
        );
        if let Some(stdin) = stdin {
            request = request.with_stdin(stdin);
        }
        self.execute_observed(&request, cancellation, PodmanCommandStage::Endpoint(stage))
    }

    pub(crate) fn endpoint_operation_timeout(&self) -> Duration {
        self.options.limits().operation_timeout()
    }

    pub(crate) fn base_arguments(&self) -> Vec<OsString> {
        self.options.shared_global_arguments()
    }

    pub(crate) fn operation_deadline(&self) -> Instant {
        Instant::now()
            .checked_add(self.options.limits().operation_timeout())
            .unwrap_or_else(Instant::now)
    }

    fn run(
        &self,
        arguments: Vec<OsString>,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> CommandOutput {
        let request = CommandRequest::new(
            self.options.binary().as_path().to_path_buf(),
            arguments,
            self.options.limits().command_timeout(),
            deadline,
            self.options.limits().output_limit(),
        );
        self.execute_observed(&request, cancellation, PodmanCommandStage::Provider(stage))
    }

    fn run_with_environment(
        &self,
        arguments: Vec<OsString>,
        environment: Option<EnvironmentDocument>,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> CommandOutput {
        let mut request = CommandRequest::new(
            self.options.binary().as_path().to_path_buf(),
            arguments,
            self.options.limits().command_timeout(),
            deadline,
            self.options.limits().output_limit(),
        );
        if let Some(environment) = environment {
            request = request.with_environment_stdin(environment);
        }
        self.execute_observed(&request, cancellation, PodmanCommandStage::Provider(stage))
    }

    fn execute_observed(
        &self,
        request: &CommandRequest,
        cancellation: &dyn Cancellation,
        stage: PodmanCommandStage,
    ) -> CommandOutput {
        self.observer.observe(PodmanEvent::CommandStarted { stage });
        let started = Instant::now();
        let output = if self
            .options
            .process_environment()
            .validate_provider_use()
            .is_err()
        {
            rejected_before_executor(request)
        } else {
            self.executor
                .execute(request, self.options.process_environment(), cancellation)
        };
        self.observer.observe(PodmanEvent::CommandCompleted {
            stage,
            outcome: command_outcome(&output),
            duration: started.elapsed(),
            stdout_bytes: u64::try_from(output.stdout().len()).unwrap_or(u64::MAX),
            stderr_bytes: u64::try_from(output.stderr().len()).unwrap_or(u64::MAX),
        });
        output
    }

    fn run_mutation(
        &self,
        arguments: Vec<OsString>,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
        handle: SandboxHandle,
    ) -> Result<CommandOutput, ProviderError> {
        let output = self.run(arguments, deadline, cancellation, stage);
        Self::require_success(output, stage, Some(handle))
    }

    fn run_mutation_with_environment(
        &self,
        arguments: Vec<OsString>,
        environment: Option<EnvironmentDocument>,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
        handle: SandboxHandle,
    ) -> Result<CommandOutput, ProviderError> {
        let output =
            self.run_with_environment(arguments, environment, deadline, cancellation, stage);
        Self::require_success(output, stage, Some(handle))
    }

    fn require_success(
        output: CommandOutput,
        stage: ProviderStage,
        mutation: Option<SandboxHandle>,
    ) -> Result<CommandOutput, ProviderError> {
        if output.succeeded() && !output.was_truncated() && output.stdin_was_fully_written() {
            return Ok(output);
        }
        let kind = match output.termination() {
            CommandTermination::Cancelled => ProviderErrorKind::Cancelled,
            CommandTermination::TimedOut => ProviderErrorKind::TimedOut,
            CommandTermination::FailedToStart => ProviderErrorKind::AdapterUnavailable,
            CommandTermination::Exited(_) if output.was_truncated() => {
                ProviderErrorKind::OutputLimitExceeded
            }
            CommandTermination::Exited(_) => ProviderErrorKind::BackendRejected,
        };
        Err(mutation.map_or_else(
            || provider_error::known(kind, stage),
            |handle| provider_error::uncertain(kind, stage, handle),
        ))
    }
}

fn rejected_before_executor(request: &CommandRequest<'_>) -> CommandOutput {
    CommandOutput::terminated_before_input(request, CommandTermination::FailedToStart)
}

const fn command_outcome(output: &CommandOutput) -> PodmanCommandOutcome {
    if !output.stdin_was_fully_written() {
        return PodmanCommandOutcome::InputIncomplete;
    }
    if output.was_truncated() {
        return PodmanCommandOutcome::OutputTruncated;
    }
    match output.termination() {
        CommandTermination::Exited(Some(0)) => PodmanCommandOutcome::Success,
        CommandTermination::Exited(Some(_)) => PodmanCommandOutcome::NonzeroExit,
        CommandTermination::Exited(None) => PodmanCommandOutcome::Signalled,
        CommandTermination::TimedOut => PodmanCommandOutcome::TimedOut,
        CommandTermination::Cancelled => PodmanCommandOutcome::Cancelled,
        CommandTermination::FailedToStart => PodmanCommandOutcome::FailedToStart,
    }
}

#[cfg(test)]
mod command_completion_tests {
    use std::{ffi::OsString, path::PathBuf, time::Duration};

    use super::*;

    fn request() -> CommandRequest<'static> {
        CommandRequest::new(
            PathBuf::from("/usr/bin/podman"),
            Vec::<OsString>::new(),
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            1,
        )
    }

    #[test]
    fn provider_rejection_before_executor_reports_input_truthfully() {
        let without_input = rejected_before_executor(&request());
        assert_eq!(
            without_input.termination(),
            CommandTermination::FailedToStart
        );
        assert!(without_input.stdin_was_fully_written());

        let with_input = rejected_before_executor(&request().with_stdin(vec![0x53]));
        assert_eq!(with_input.termination(), CommandTermination::FailedToStart);
        assert!(!with_input.stdin_was_fully_written());
        assert_eq!(
            command_outcome(&with_input),
            PodmanCommandOutcome::InputIncomplete
        );
    }
}

fn finish_create(
    inspection: &SandboxInspection,
    handle: SandboxHandle,
) -> Result<SandboxRecord, ProviderError> {
    if inspection.state() != SandboxState::Running {
        return Err(provider_error::uncertain(
            ProviderErrorKind::InvalidState,
            ProviderStage::Start,
            handle,
        ));
    }
    Ok(SandboxRecord::new(
        inspection.handle().clone(),
        inspection.generation(),
        inspection.profile().clone(),
        inspection.state(),
    ))
}

#[derive(Clone, Copy, Debug)]
struct ProvisionLabels<'a> {
    arguments: &'a [String],
    fingerprint: &'a str,
}

#[derive(Clone, Copy, Debug)]
struct ProvisionStorage<'a> {
    workspace: &'a Path,
    engine: Option<&'a JobEnginePaths>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceReadiness {
    Ready,
    Waiting,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InspectedServiceContainer {
    labels: InspectedLabels,
    identifier: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InspectedResource {
    labels: InspectedLabels,
    identifier: String,
}

impl InspectedResource {
    fn identifier(&self) -> &str {
        &self.identifier
    }
}

impl Deref for InspectedResource {
    type Target = InspectedLabels;

    fn deref(&self) -> &Self::Target {
        &self.labels
    }
}

impl InspectedServiceContainer {
    fn identifier(&self) -> &str {
        &self.identifier
    }
}

impl Deref for InspectedServiceContainer {
    type Target = InspectedLabels;

    fn deref(&self) -> &Self::Target {
        &self.labels
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResourceKind {
    Network,
    Pod,
    Container,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobEngineObjectKind {
    Container,
    Image,
}

impl JobEngineObjectKind {
    const fn inspect_command(self) -> &'static [&'static str] {
        match self {
            Self::Container => &["container", "inspect"],
            Self::Image => &["image", "inspect"],
        }
    }
}

impl ResourceKind {
    fn name(self, names: &ResourceNames) -> String {
        match self {
            Self::Network => names.network(),
            Self::Pod => names.pod(),
            Self::Container => names.container(),
        }
    }

    const fn exists_command(self) -> &'static [&'static str] {
        match self {
            Self::Network => &["network", "exists"],
            Self::Pod => &["pod", "exists"],
            Self::Container => &["container", "exists"],
        }
    }

    const fn inspect_command(self) -> &'static [&'static str] {
        match self {
            Self::Network => &["network", "inspect"],
            Self::Pod => &["pod", "inspect"],
            Self::Container => &["container", "inspect"],
        }
    }

    const fn identifier_format(self) -> &'static str {
        match self {
            Self::Network | Self::Container => "{{.ID}}",
            Self::Pod => "{{.Id}}",
        }
    }

    const fn remove_command(self) -> &'static [&'static str] {
        match self {
            Self::Network => &["network", "rm"],
            Self::Pod => &["pod", "rm", "--force", "--ignore"],
            Self::Container => &["rm", "--force", "--ignore"],
        }
    }

    const fn destroy_stage(self) -> ProviderStage {
        match self {
            Self::Network => ProviderStage::DestroyNetwork,
            Self::Pod => ProviderStage::DestroySandbox,
            Self::Container => ProviderStage::DestroyContainer,
        }
    }
}

fn validate_spec(spec: &SandboxSpec) -> Result<(), ProviderError> {
    let workspace = spec.workspace().as_str();
    let Some(keepalive) = spec.profile().keepalive() else {
        return Err(provider_error::known(
            ProviderErrorKind::UnsupportedCapability,
            ProviderStage::Validate,
        ));
    };
    if spec.profile().image().is_none()
        || spec.scratch().is_some()
        || spec.network() == NetworkPolicy::Host
        || spec.root_filesystem() == RootFilesystemPolicy::Host
        || spec.privilege() == SandboxPrivilegePolicy::Host
    {
        return Err(provider_error::known(
            ProviderErrorKind::UnsupportedCapability,
            ProviderStage::Validate,
        ));
    }
    let keepalive_program = keepalive.program().as_str();
    let service_port_count = spec
        .services()
        .iter()
        .try_fold(0_usize, |total, (_, service)| {
            total.checked_add(service.ports().len())
        });
    let mut explicit_listeners = BTreeSet::new();
    let duplicate_listener = spec.services().iter().any(|(_, service)| {
        service.ports().iter().any(|port| {
            port.requested_host_port()
                .is_some_and(|host| !explicit_listeners.insert((port.protocol(), host)))
        })
    });
    if service_port_count.is_none_or(|count| count > MAX_SERVICE_PROXY_PORTS)
        || duplicate_listener
        || spec
            .services()
            .iter()
            .any(|(_, service)| !supported_service_environment(service.environment()))
        || workspace.contains([':', ','])
        || keepalive_program.contains('\0')
        || keepalive
            .arguments()
            .iter()
            .any(|argument| argument.contains('\0'))
    {
        return Err(provider_error::known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
        ));
    }
    Ok(())
}

fn supported_service_environment(environment: &ExecutionEnvironment) -> bool {
    !environment
        .values()
        .iter()
        .any(automata_ci_execution::EnvironmentVariable::is_secret)
        && environment_document(environment)
            .is_ok_and(|document| document.byte_len() <= MAX_SERVICE_PROCESS_ENVIRONMENT_BYTES)
}

fn workspace_mount(host: &std::path::Path, target: &str) -> Result<String, ProviderError> {
    let host = host.to_str().ok_or_else(|| {
        provider_error::known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::CreateContainer,
        )
    })?;
    if host.contains([':', ',']) || target.contains([':', ',']) {
        return Err(provider_error::known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::CreateContainer,
        ));
    }
    Ok(format!("{host}:{target}:rw,Z,nodev,nosuid"))
}

fn consistent_profile(
    present: [Option<&InspectedLabels>; 3],
) -> Result<EnvironmentProfile, ProviderError> {
    let mut profiles = present
        .iter()
        .flatten()
        .filter_map(|labels| labels.profile());
    let profile = profiles
        .next()
        .ok_or_else(|| provider_error::invalid_state(ProviderStage::Inspect))?;
    if profiles.any(|other| other != profile) {
        return Err(provider_error::invalid_state(ProviderStage::Inspect));
    }
    Ok(profile)
}

fn ensure_consistent_fingerprint(
    present: [Option<&InspectedLabels>; 3],
) -> Result<String, ProviderError> {
    let mut fingerprints = present
        .iter()
        .flatten()
        .map(|labels| labels.spec_fingerprint());
    let fingerprint = fingerprints
        .next()
        .ok_or_else(|| provider_error::invalid_state(ProviderStage::Inspect))?;
    if fingerprints.any(|other| other != fingerprint) {
        return Err(provider_error::invalid_state(ProviderStage::Inspect));
    }
    Ok(fingerprint.to_owned())
}

fn aggregate_state(
    network: bool,
    pod: bool,
    container_state: Option<&str>,
    workspace: bool,
) -> SandboxState {
    if !network || !pod || !workspace || container_state.is_none() {
        return SandboxState::Degraded;
    }
    match container_state {
        Some("running") => SandboxState::Running,
        Some("created" | "configured") => SandboxState::Created,
        Some("exited" | "stopped") => SandboxState::Stopped,
        _ => SandboxState::Degraded,
    }
}

fn job_engine_ownership_format(container: bool) -> String {
    let labels = if container {
        ".Config.Labels"
    } else {
        ".Labels"
    };
    format!(
        "{{{{ index {labels} \"io.automata.owner\" }}}}\n{{{{ index {labels} \"io.automata.job-engine\" }}}}"
    )
}

fn spec_fingerprint(
    spec: &SandboxSpec,
    job_engine: JobContainerEngine,
    host_gateway_alias: Option<&PodmanHostGatewayAlias>,
    service_proxy_image: Option<&automata_ci_execution::ImmutableImage>,
) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, spec.profile().id().as_str().as_bytes());
    hash_field(&mut hasher, spec.profile().digest().as_bytes());
    hash_field(
        &mut hasher,
        spec.profile()
            .image()
            .expect("validated container profile")
            .reference()
            .as_bytes(),
    );
    hash_field(
        &mut hasher,
        spec.profile()
            .keepalive()
            .expect("validated container profile")
            .program()
            .as_str()
            .as_bytes(),
    );
    for argument in spec
        .profile()
        .keepalive()
        .expect("validated container profile")
        .arguments()
    {
        hash_field(&mut hasher, argument.as_bytes());
    }
    hash_field(&mut hasher, spec.workspace().as_str().as_bytes());
    hash_field(&mut hasher, &[spec.network() as u8]);
    hash_field(&mut hasher, &[spec.root_filesystem() as u8]);
    hash_field(&mut hasher, &[spec.privilege() as u8]);
    hash_field(&mut hasher, &spec.resources().memory_bytes().to_be_bytes());
    hash_field(&mut hasher, &spec.resources().cpu_millis().to_be_bytes());
    hash_field(&mut hasher, &spec.resources().pids().to_be_bytes());
    hash_field(&mut hasher, &[job_engine as u8]);
    match host_gateway_alias {
        Some(alias) => {
            hash_field(&mut hasher, &[1]);
            hash_field(&mut hasher, alias.as_str().as_bytes());
        }
        None => hash_field(&mut hasher, &[0]),
    }
    let needs_service_proxy = spec
        .services()
        .iter()
        .any(|(_, service)| !service.ports().is_empty());
    match (needs_service_proxy, service_proxy_image) {
        (true, Some(image)) => {
            hash_field(&mut hasher, &[1]);
            hash_field(&mut hasher, image.reference().as_bytes());
        }
        _ => hash_field(&mut hasher, &[0]),
    }
    hash_field(
        &mut hasher,
        &u64::try_from(spec.services().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for (alias, service) in spec.services().iter() {
        hash_field(&mut hasher, alias.as_bytes());
        hash_field(&mut hasher, service.image().reference().as_bytes());
        hash_field(
            &mut hasher,
            &u64::try_from(service.environment().values().len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for variable in service.environment().values() {
            hash_field(&mut hasher, variable.name().as_str().as_bytes());
            hash_field(&mut hasher, variable.value().expose().as_bytes());
            hash_field(&mut hasher, &[u8::from(variable.is_secret())]);
        }
        hash_field(
            &mut hasher,
            &u64::try_from(service.ports().len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for port in service.ports() {
            hash_field(&mut hasher, &port.container_port().to_be_bytes());
            match port.requested_host_port() {
                Some(host) => {
                    hash_field(&mut hasher, &[1]);
                    hash_field(&mut hasher, &host.to_be_bytes());
                }
                None => hash_field(&mut hasher, &[0]),
            }
            hash_field(&mut hasher, service_protocol(port.protocol()).as_bytes());
        }
        hash_service_health(&mut hasher, service.health());
    }
    format!("{:x}", hasher.finalize())
}

fn hash_service_health(hasher: &mut Sha256, health: &ServiceHealthPolicy) {
    match health {
        ServiceHealthPolicy::Image => hash_field(hasher, b"image"),
        ServiceHealthPolicy::Disabled => hash_field(hasher, b"disabled"),
        ServiceHealthPolicy::Override(overrides) => {
            hash_field(hasher, b"override");
            hash_optional_field(hasher, overrides.command().map(str::as_bytes));
            hash_optional_duration(hasher, overrides.interval());
            hash_optional_duration(hasher, overrides.timeout());
            hash_optional_duration(hasher, overrides.start_period());
            match overrides.retries() {
                Some(retries) => {
                    hash_field(hasher, &[1]);
                    hash_field(hasher, &retries.to_be_bytes());
                }
                None => hash_field(hasher, &[0]),
            }
        }
    }
}

fn hash_optional_duration(hasher: &mut Sha256, value: Option<Duration>) {
    match value {
        Some(value) => {
            hash_field(hasher, &[1]);
            hash_field(hasher, &value.as_nanos().to_be_bytes());
        }
        None => hash_field(hasher, &[0]),
    }
}

fn hash_optional_field(hasher: &mut Sha256, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            hash_field(hasher, &[1]);
            hash_field(hasher, value);
        }
        None => hash_field(hasher, &[0]),
    }
}

fn engine_socket_mount(host: &Path) -> Result<String, ProviderError> {
    let host = host.to_str().ok_or_else(|| {
        provider_error::known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::CreateContainer,
        )
    })?;
    if host.contains([':', ',']) {
        return Err(provider_error::known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::CreateContainer,
        ));
    }
    Ok(format!(
        "{host}:{DOCKER_SOCKET_DIRECTORY_TARGET}:rw,Z,nodev,nosuid,noexec"
    ))
}

fn push_job_engine_create_options(
    arguments: &mut Vec<OsString>,
    engine: Option<&JobEnginePaths>,
) -> Result<(), ProviderError> {
    let Some(engine) = engine else {
        return Ok(());
    };
    push_option(
        arguments,
        "--env",
        format!("DOCKER_HOST=unix://{DOCKER_SOCKET_DIRECTORY_TARGET}/docker.sock"),
    );
    push_option(arguments, "--env", "DOCKER_BUILDKIT=0");
    push_option(
        arguments,
        "--volume",
        engine_socket_mount(engine.public_directory())?,
    );
    Ok(())
}

fn push_service_health_options(arguments: &mut Vec<OsString>, health: &ServiceHealthPolicy) {
    match health {
        ServiceHealthPolicy::Image => {}
        ServiceHealthPolicy::Disabled => arguments.push("--no-healthcheck".into()),
        ServiceHealthPolicy::Override(overrides) => {
            if let Some(command) = overrides.command() {
                push_option(arguments, "--health-cmd", command);
            }
            if let Some(interval) = overrides.interval() {
                push_option(arguments, "--health-interval", podman_duration(interval));
            }
            if let Some(timeout) = overrides.timeout() {
                push_option(arguments, "--health-timeout", podman_duration(timeout));
            }
            if let Some(start_period) = overrides.start_period() {
                push_option(
                    arguments,
                    "--health-start-period",
                    podman_duration(start_period),
                );
            }
            if let Some(retries) = overrides.retries() {
                push_option(arguments, "--health-retries", retries.to_string());
            }
        }
    }
}

fn push_administrator_capabilities(
    arguments: &mut Vec<OsString>,
    privilege: SandboxPrivilegePolicy,
) {
    if privilege != SandboxPrivilegePolicy::Administrator {
        return;
    }
    for capability in [
        "chown",
        "dac_override",
        "fowner",
        "fsetid",
        "kill",
        "net_bind_service",
        "setfcap",
        "setgid",
        "setpcap",
        "setuid",
        "sys_chroot",
    ] {
        push_option(arguments, "--cap-add", capability);
    }
}

fn podman_duration(value: Duration) -> String {
    format!("{}ns", value.as_nanos())
}

const fn service_protocol(protocol: ServiceTransportProtocol) -> &'static str {
    match protocol {
        ServiceTransportProtocol::Tcp => "tcp",
        ServiceTransportProtocol::Udp => "udp",
    }
}

fn parse_service_readiness(
    bytes: &[u8],
    expectation: ServiceHealthExpectation,
) -> Option<ServiceReadiness> {
    let value = std::str::from_utf8(bytes)
        .ok()?
        .strip_suffix('\n')
        .unwrap_or_else(|| std::str::from_utf8(bytes).expect("already validated UTF-8"));
    let mut lines = value.lines();
    let state = lines.next()?;
    let configuration = lines.next()?;
    let health = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    if state != "running" {
        return Some(ServiceReadiness::Failed);
    }
    match (expectation, configuration, health) {
        (ServiceHealthExpectation::Disabled | ServiceHealthExpectation::Image, "none", "none")
        | (
            ServiceHealthExpectation::Image | ServiceHealthExpectation::Override,
            "configured",
            "healthy",
        ) => Some(ServiceReadiness::Ready),
        (
            ServiceHealthExpectation::Image | ServiceHealthExpectation::Override,
            "configured",
            "starting",
        ) => Some(ServiceReadiness::Waiting),
        (
            ServiceHealthExpectation::Image | ServiceHealthExpectation::Override,
            "configured",
            "unhealthy",
        ) => Some(ServiceReadiness::Failed),
        _ => None,
    }
}

fn service_inspection_format() -> String {
    format!("{}\n{{{{.Id}}}}", label_format(true, true))
}

fn service_network_address_format(network: &str) -> String {
    format!(
        "{{{{with index .NetworkSettings.Networks \"{network}\"}}}}{{{{.IPAddress}}}}{{{{end}}}}"
    )
}

fn service_proxy_command_matches(manifest: &ServiceManifest, value: &str) -> bool {
    let Ok(command) = serde_json::from_str::<Vec<String>>(value) else {
        return false;
    };
    if command.first().map(String::as_str) != Some(SERVICE_PROXY_SERVE_COMMAND)
        || command.len() != manifest.port_count().saturating_add(1)
    {
        return false;
    }
    let mut arguments = command.iter().skip(1);
    for entry in manifest.entries() {
        let Some(address) = entry.address().and_then(|value| value.parse().ok()) else {
            return false;
        };
        for (port, host) in entry.ports().iter().zip(entry.host_ports()) {
            let Some(actual) = arguments.next() else {
                return false;
            };
            let initial =
                service_proxy_mapping_argument(address, *port, port.requested_host_port());
            let durable = service_proxy_mapping_argument(
                address,
                *port,
                port.requested_host_port().or(*host),
            );
            if actual != &initial && actual != &durable {
                return false;
            }
        }
    }
    arguments.next().is_none()
}

fn service_configuration_format(network: &str, alias: &str) -> String {
    format!(
        "{{{{.ImageName}}}}\n\
         {{{{if .HostConfig.PortBindings}}}}published{{{{else}}}}unpublished{{{{end}}}}\n\
         {{{{with index .NetworkSettings.Networks \"{network}\"}}}}\
         {{{{range .Aliases}}}}{{{{if eq . \"{alias}\"}}}}alias{{{{end}}}}{{{{end}}}}\
         {{{{else}}}}missing{{{{end}}}}\n\
         {JOB_NETWORK_SYSCTL_FORMAT}"
    )
}

fn parse_service_inspection(bytes: &[u8]) -> Option<InspectedServiceContainer> {
    let value = std::str::from_utf8(bytes).ok()?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    let (labels, identifier) = value.rsplit_once('\n')?;
    if identifier.len() != 64
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    let mut label_bytes = labels.as_bytes().to_vec();
    label_bytes.push(b'\n');
    Some(InspectedServiceContainer {
        labels: InspectedLabels::parse(&label_bytes, true)?,
        identifier: identifier.to_owned(),
    })
}

fn parse_owned_cgroup_path(bytes: &[u8], delegated: &str) -> Option<String> {
    let value = std::str::from_utf8(bytes).ok()?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.is_empty()
        || value.len() > 4_096
        || value.contains(['\n', '\r'])
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'@')
        })
    {
        return None;
    }
    let normalized = value.trim_start_matches('/');
    if normalized
        .split('/')
        .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return None;
    }
    let delegated = delegated.trim_start_matches('/').trim_end_matches('/');
    if delegated.is_empty()
        || !normalized
            .strip_prefix(delegated)
            .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1)
    {
        return None;
    }
    Some(value.to_owned())
}

fn create_service_error(error: &ProviderError, handle: SandboxHandle) -> ProviderError {
    ProviderError::new(
        error.kind(),
        error.stage(),
        OperationOutcome::Uncertain,
        Some(handle),
    )
}

fn destroy_service_error(error: &ProviderError, handle: SandboxHandle) -> ProviderError {
    ProviderError::new(
        error.kind(),
        error.stage(),
        OperationOutcome::Uncertain,
        Some(handle),
    )
}

fn fence_destroy_result<T>(
    result: Result<T, ProviderError>,
    mutated: bool,
    handle: &SandboxHandle,
) -> Result<T, ProviderError> {
    result.map_err(|error| {
        if mutated {
            destroy_service_error(&error, handle.clone())
        } else {
            error
        }
    })
}

fn parse_process_id(bytes: &[u8]) -> Option<u32> {
    let value = std::str::from_utf8(bytes).ok()?.trim();
    let process_id = value.parse::<u32>().ok()?;
    (process_id > 1).then_some(process_id)
}

fn parse_container_identifier(bytes: &[u8]) -> Option<&str> {
    let value = std::str::from_utf8(bytes).ok()?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Some(value)
    } else {
        None
    }
}

fn resource_inspection_format(kind: ResourceKind) -> String {
    format!(
        "{}\n{{{{.Name}}}}\n{}",
        kind.identifier_format(),
        label_format(
            kind == ResourceKind::Container,
            kind == ResourceKind::Container,
        )
    )
}

fn parse_inspected_resource(
    bytes: &[u8],
    includes_state: bool,
    expected_name: &str,
) -> Option<InspectedResource> {
    let value = std::str::from_utf8(bytes).ok()?;
    let (identifier, remaining) = value.split_once('\n')?;
    let (name, labels) = remaining.split_once('\n')?;
    if name != expected_name
        || parse_container_identifier(identifier.as_bytes()) != Some(identifier)
    {
        return None;
    }
    Some(InspectedResource {
        labels: InspectedLabels::parse(labels.as_bytes(), includes_state)?,
        identifier: identifier.to_owned(),
    })
}

fn parse_engine_identifiers(bytes: &[u8]) -> Option<Vec<String>> {
    let document = std::str::from_utf8(bytes).ok()?;
    let mut identifiers = Vec::new();
    for identifier in document.lines().filter(|line| !line.is_empty()) {
        if identifier.len() < 12
            || identifier.len() > 64
            || !identifier.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        identifiers.push(identifier.to_owned());
    }
    Some(identifiers)
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn push_labels(arguments: &mut Vec<OsString>, labels: &[String]) {
    for label in labels {
        push_option(arguments, "--label", label);
    }
}

fn push_option(arguments: &mut Vec<OsString>, name: &str, value: impl Into<OsString>) {
    arguments.push(name.into());
    arguments.push(value.into());
}

fn os_args<const N: usize>(values: [&str; N]) -> impl Iterator<Item = OsString> {
    values.into_iter().map(OsString::from)
}

fn cpu_value(millis: u32) -> String {
    format!("{}.{:03}", millis / 1_000, millis % 1_000)
}

pub(crate) fn endpoint_capabilities() -> &'static [SandboxCapability] {
    &ENDPOINT_CAPABILITIES
}

pub(crate) fn endpoint_error_from_provider(
    error: &ProviderError,
    stage: automata_ci_execution::ExecutionStage,
) -> automata_ci_execution::ExecutionError {
    use automata_ci_execution::{ExecutionError, ExecutionErrorKind};
    let kind = match error.kind() {
        ProviderErrorKind::UnsupportedCapability | ProviderErrorKind::UnsupportedPlatform => {
            ExecutionErrorKind::UnsupportedCapability
        }
        ProviderErrorKind::Cancelled => ExecutionErrorKind::Cancelled,
        ProviderErrorKind::TimedOut => ExecutionErrorKind::TimedOut,
        ProviderErrorKind::NotFound => ExecutionErrorKind::NotFound,
        ProviderErrorKind::OwnershipMismatch => ExecutionErrorKind::OwnershipMismatch,
        ProviderErrorKind::OutputLimitExceeded => ExecutionErrorKind::OutputLimitExceeded,
        ProviderErrorKind::LocalStorage => ExecutionErrorKind::LocalStorage,
        ProviderErrorKind::AdapterUnavailable
        | ProviderErrorKind::BackendRejected
        | ProviderErrorKind::Conflict
        | ProviderErrorKind::InvalidConfiguration
        | ProviderErrorKind::InvalidState => ExecutionErrorKind::BackendRejected,
    };
    ExecutionError::new(kind, stage)
}
