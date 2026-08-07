use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt, fs,
    path::Path,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use automata_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, EnvironmentProfile, ExecutionEnvironment,
    NetworkPolicy, ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderId,
    ProviderStage, RootFilesystemPolicy, SandboxCapability, SandboxHandle, SandboxInspection,
    SandboxPrivilegePolicy, SandboxProvider, SandboxRecord, SandboxSpec, SandboxState,
};
use sha2::{Digest as _, Sha256};

use crate::{
    CommandOutput, CommandRequest, CommandTermination, JobContainerEngine, PODMAN_PROVIDER_ID,
    PodmanCommandExecutor, PodmanHostGatewayAlias, PodmanOpenError, PodmanOptions,
    SystemCommandExecutor,
    docker::{
        DOCKER_SOCKET_DIRECTORY_TARGET, JobDockerListener, JobDockerService, bind_public_socket,
    },
    endpoint::PodmanExecutionEndpoint,
    naming::{InspectedLabels, ResourceNames, label_format},
    provider_error,
    state::{JobEnginePaths, LocalState},
};

const INFO_FORMAT: &str = "{{.Host.Security.Rootless}}\n{{.Host.CgroupsVersion}}";
const USER_NAMESPACE_REMOVE_PROGRAM: &str = "/usr/bin/rm";
const ENDPOINT_CAPABILITIES: [SandboxCapability; 6] = [
    SandboxCapability::Exec,
    SandboxCapability::Signal,
    SandboxCapability::Wait,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::EnvironmentInjection,
];

/// Local rootless Podman provider. Construction exclusively locks the explicit
/// state root; cloning shares that lock and the injected command adapter.
#[derive(Clone)]
pub struct RootlessPodmanProvider {
    pub(crate) inner: Arc<PodmanInner>,
}

impl RootlessPodmanProvider {
    /// Opens the provider with the safe local process adapter.
    ///
    /// # Errors
    ///
    /// Returns a typed state-root or platform failure before invoking Podman.
    pub fn open(options: PodmanOptions) -> Result<Self, PodmanOpenError> {
        Self::open_with_executor(options, Arc::new(SystemCommandExecutor))
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
        #[cfg(not(target_os = "linux"))]
        return Err(crate::PodmanConfigurationError::UnsupportedPlatform.into());
        let state = LocalState::open(options.state_root())?;
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
        if options.job_container_engine() == JobContainerEngine::AttemptScopedDockerApi {
            declared_capabilities.push(SandboxCapability::DockerCompatibleApi);
        }
        let capabilities = ProviderCapabilities::new(declared_capabilities)
            .map_err(|_| crate::PodmanConfigurationError::InvalidLimits)?;
        Ok(Self {
            inner: Arc::new(PodmanInner {
                options,
                state,
                executor,
                provider_id,
                capabilities,
                handle_locks: Mutex::new(BTreeMap::new()),
                docker_services: Mutex::new(BTreeMap::new()),
            }),
        })
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
    ) -> Result<Box<dyn automata_execution::ExecutionEndpoint>, ProviderError> {
        let operation_lock = self.inner.handle_lock(handle)?;
        let operation = operation_lock
            .lock()
            .map_err(|_| provider_error::local_storage(ProviderStage::Attach))?;
        let inspection = self.inner.inspect(handle, cancellation)?;
        if inspection.state() != SandboxState::Running {
            return Err(provider_error::invalid_state(ProviderStage::Attach));
        }
        let names = ResourceNames::from_handle(handle, &self.inner.provider_id)?;
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
        let operation_lock = self.inner.handle_lock(handle)?;
        let _operation = operation_lock
            .lock()
            .map_err(|_| provider_error::local_storage(ProviderStage::Inspect))?;
        self.inner.inspect(handle, cancellation)
    }

    fn destroy(
        &self,
        request: &DestroySandbox,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
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
    fn handle_lock(&self, handle: &SandboxHandle) -> Result<Arc<Mutex<()>>, ProviderError> {
        let mut locks = self
            .handle_locks
            .lock()
            .map_err(|_| provider_error::local_storage(ProviderStage::Validate))?;
        locks.retain(|_, value| value.strong_count() > 0);
        if let Some(lock) = locks.get(handle.opaque()).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(handle.opaque().to_owned(), Arc::downgrade(&lock));
        Ok(lock)
    }

    fn create(
        self: &Arc<Self>,
        spec: &SandboxSpec,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError> {
        validate_spec(spec)?;
        let deadline = self.operation_deadline();
        self.verify_host(deadline, cancellation)?;
        let names = ResourceNames::for_create(spec.operation_id(), spec.generation());
        let handle = names.handle();
        let fingerprint = spec_fingerprint(
            spec,
            self.options.job_container_engine(),
            self.options.host_gateway_alias(),
        );
        let labels = names.labels(spec.profile().attestation(), &fingerprint);
        let labels = ProvisionLabels {
            arguments: &labels,
            fingerprint: &fingerprint,
        };
        self.reject_conflicting_replay(&names, &fingerprint, deadline, cancellation)?;

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
        self.ensure_pod(spec, &names, &labels, deadline, cancellation)?;
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
        let inspection = self.inspect_with_deadline(&handle, deadline, cancellation)?;
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
        let profile = consistent_profile(present)?;
        ensure_consistent_fingerprint(present)?;
        let workspace = self
            .state
            .workspace_exists(&names.workspace())
            .map_err(|_| provider_error::local_storage(ProviderStage::Inspect))?;
        let state = aggregate_state(
            network.is_some(),
            pod.is_some(),
            container.as_ref().and_then(InspectedLabels::state),
            workspace,
        );
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
        let mut removed = false;
        self.stop_job_docker_service(&names)?;
        if self.options.job_container_engine() == JobContainerEngine::AttemptScopedDockerApi {
            self.cleanup_job_engine(&names, deadline, cancellation)?;
        }
        removed |= self.remove_exact(ResourceKind::Container, &names, deadline, cancellation)?;
        removed |= self.remove_exact(ResourceKind::Pod, &names, deadline, cancellation)?;
        removed |= self.remove_exact(ResourceKind::Network, &names, deadline, cancellation)?;
        removed |= self.remove_exact_workspace(&names, deadline, cancellation)?;
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
        Ok(if removed {
            DestroyDisposition::Destroyed
        } else {
            DestroyDisposition::AlreadyAbsent
        })
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
        arguments.extend(os_args([
            "unshare",
            USER_NAMESPACE_REMOVE_PROGRAM,
            "--recursive",
            "--force",
            "--one-file-system",
            "--",
        ]));
        arguments.push(path.into_os_string());
        Self::require_success(
            self.run(arguments, deadline, cancellation),
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
            return self.verify_owned_for_spec(
                ResourceKind::Pod,
                names,
                spec.profile().attestation(),
                labels.fingerprint,
                deadline,
                cancellation,
            );
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
        if let Some(alias) = self.options.host_gateway_alias() {
            arguments.push(format!("--add-host={}:host-gateway", alias.as_str()).into());
        }
        let user_namespace = match spec.privilege() {
            SandboxPrivilegePolicy::Unprivileged => "keep-id",
            SandboxPrivilegePolicy::Administrator => "keep-id:uid=0,gid=0",
        };
        push_option(&mut arguments, "--userns", user_namespace);
        push_option(&mut arguments, "--cpus", cpu_value(resources.cpu_millis()));
        push_option(
            &mut arguments,
            "--memory",
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
        )
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
        if spec.privilege() == SandboxPrivilegePolicy::Administrator {
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
                push_option(&mut arguments, "--cap-add", capability);
            }
        }
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
            spec.profile().keepalive().program().as_str(),
        );
        arguments.push(spec.profile().image().reference().into());
        arguments.extend(
            spec.profile()
                .keepalive()
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
        let mut arguments = self.base_arguments();
        arguments.extend(os_args([
            "container",
            "inspect",
            "--format",
            "{{.State.Pid}}",
        ]));
        arguments.push(names.container().into());
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation),
            ProviderStage::CreateContainer,
            Some(names.handle()),
        )?;
        let process_id = parse_process_id(output.stdout()).ok_or_else(|| {
            provider_error::uncertain(
                ProviderErrorKind::InvalidState,
                ProviderStage::CreateContainer,
                names.handle(),
            )
        })?;
        let cgroup = read_cgroup(process_id).map_err(|()| {
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
            &names.handle(),
            process_id,
            cgroup,
            spec.resources(),
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
            let mut arguments = job_engine_base_arguments(&self.state, &paths);
            arguments.extend(os_args(["rm", "--force", "--ignore"]));
            arguments.push(identifier.into());
            Self::require_success(
                self.run(arguments, deadline, cancellation),
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
            let mut arguments = job_engine_base_arguments(&self.state, &paths);
            arguments.extend(os_args(["image", "rm", "--force"]));
            arguments.push(identifier.into());
            Self::require_success(
                self.run(arguments, deadline, cancellation),
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
        let mut arguments = job_engine_base_arguments(&self.state, paths);
        arguments.extend(command.into_iter().map(OsString::from));
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation),
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
        let mut arguments = job_engine_base_arguments(&self.state, paths);
        arguments.extend(kind.inspect_command().iter().map(OsString::from));
        arguments.push("--format".into());
        arguments.push(job_engine_ownership_format(kind == JobEngineObjectKind::Container).into());
        arguments.push(identifier.into());
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation),
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

    fn verify_host(
        &self,
        deadline: Instant,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let mut arguments = self.base_arguments();
        arguments.extend(os_args(["info", "--format", INFO_FORMAT]));
        let output = Self::require_success(
            self.run(arguments, deadline, cancellation),
            ProviderStage::Validate,
            None,
        )?;
        if output.stdout() != b"true\nv2\n" && output.stdout() != b"true\nv2" {
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
    ) -> Result<Option<InspectedLabels>, ProviderError> {
        if !self.resource_exists(kind, names, deadline, cancellation, stage)? {
            return Ok(None);
        }
        let mut arguments = self.base_arguments();
        arguments.extend(kind.inspect_command().iter().map(OsString::from));
        arguments.extend(os_args(["--format"]));
        arguments.push(
            label_format(
                kind == ResourceKind::Container,
                kind == ResourceKind::Container,
            )
            .into(),
        );
        arguments.push(kind.name(names).into());
        let output =
            Self::require_success(self.run(arguments, deadline, cancellation), stage, None)?;
        InspectedLabels::parse(output.stdout(), kind == ResourceKind::Container)
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
        let mut arguments = self.base_arguments();
        arguments.extend(kind.exists_command().iter().map(OsString::from));
        arguments.push(kind.name(names).into());
        let output = self.run(arguments, deadline, cancellation);
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
        arguments.push(kind.name(names).into());
        self.run_mutation(arguments, deadline, cancellation, stage, names.handle())?;
        if self.resource_exists(kind, names, deadline, cancellation, stage)? {
            return Err(provider_error::uncertain(
                ProviderErrorKind::BackendRejected,
                stage,
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
        self.executor
            .execute(&request, self.options.process_environment(), cancellation)
    }

    pub(crate) fn run_endpoint_with_environment(
        &self,
        arguments: Vec<OsString>,
        environment: ExecutionEnvironment,
        timeout: Duration,
        output_limit: usize,
        cancellation: &dyn Cancellation,
    ) -> CommandOutput {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let request = CommandRequest::new(
            self.options.binary().as_path().to_path_buf(),
            arguments,
            timeout,
            deadline,
            output_limit,
        )
        .with_child_environment(environment);
        self.executor
            .execute(&request, self.options.process_environment(), cancellation)
    }

    pub(crate) fn endpoint_operation_timeout(&self) -> Duration {
        self.options.limits().operation_timeout()
    }

    pub(crate) const fn local_state(&self) -> &LocalState {
        &self.state
    }

    pub(crate) fn base_arguments(&self) -> Vec<OsString> {
        vec![
            "--remote=false".into(),
            format!("--hooks-dir={}", self.state.hooks_path().display()).into(),
        ]
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
    ) -> CommandOutput {
        let request = CommandRequest::new(
            self.options.binary().as_path().to_path_buf(),
            arguments,
            self.options.limits().command_timeout(),
            deadline,
            self.options.limits().output_limit(),
        );
        self.executor
            .execute(&request, self.options.process_environment(), cancellation)
    }

    fn run_mutation(
        &self,
        arguments: Vec<OsString>,
        deadline: Instant,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
        handle: SandboxHandle,
    ) -> Result<CommandOutput, ProviderError> {
        let output = self.run(arguments, deadline, cancellation);
        Self::require_success(output, stage, Some(handle))
    }

    fn require_success(
        output: CommandOutput,
        stage: ProviderStage,
        mutation: Option<SandboxHandle>,
    ) -> Result<CommandOutput, ProviderError> {
        if output.succeeded() && !output.was_truncated() {
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
    let keepalive = spec.profile().keepalive().program().as_str();
    if workspace.contains([':', ','])
        || keepalive.contains('\0')
        || spec
            .profile()
            .keepalive()
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
) -> Result<(), ProviderError> {
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
    Ok(())
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
) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, spec.profile().id().as_str().as_bytes());
    hash_field(&mut hasher, spec.profile().digest().as_bytes());
    hash_field(&mut hasher, spec.profile().image().reference().as_bytes());
    hash_field(
        &mut hasher,
        spec.profile().keepalive().program().as_str().as_bytes(),
    );
    for argument in spec.profile().keepalive().arguments() {
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
    format!("{:x}", hasher.finalize())
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

fn parse_process_id(bytes: &[u8]) -> Option<u32> {
    let value = std::str::from_utf8(bytes).ok()?.trim();
    let process_id = value.parse::<u32>().ok()?;
    (process_id > 1).then_some(process_id)
}

fn read_cgroup(process_id: u32) -> Result<String, ()> {
    let path = Path::new("/proc")
        .join(process_id.to_string())
        .join("cgroup");
    let document = fs::read_to_string(path).map_err(|_| ())?;
    let mut values = document.lines().filter_map(|line| line.strip_prefix("0::"));
    let value = values.next().ok_or(())?;
    if values.next().is_some()
        || !value.starts_with('/')
        || value.len() > 4_096
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.split('/').any(|component| component == "..")
    {
        return Err(());
    }
    Ok(value.to_owned())
}

fn job_engine_base_arguments(state: &LocalState, paths: &JobEnginePaths) -> Vec<OsString> {
    vec![
        "--remote=false".into(),
        format!("--hooks-dir={}", state.hooks_path().display()).into(),
        format!("--root={}", paths.graph_root().display()).into(),
        format!("--runroot={}", paths.run_root().display()).into(),
        "--storage-driver=vfs".into(),
        "--cgroup-manager=cgroupfs".into(),
    ]
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
    stage: automata_execution::ExecutionStage,
) -> automata_execution::ExecutionError {
    use automata_execution::{ExecutionError, ExecutionErrorKind};
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
