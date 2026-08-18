use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt,
    fs::{self, File, OpenOptions},
    io::Read as _,
    num::NonZeroU16,
    os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Component, Path, PathBuf},
    str::FromStr as _,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use automata_ci_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, EnvironmentProfile, EnvironmentProfileId,
    NeverCancelled, OperationId, OperationOutcome, ProviderCapabilities, ProviderError,
    ProviderErrorKind, ProviderId, ProviderStage, RootFilesystemPolicy, RunnerId,
    SandboxAuthorization, SandboxCapability, SandboxCustody, SandboxHandle, SandboxInspection,
    SandboxLaunch, SandboxPrivilegePolicy, SandboxProvider, SandboxRecord, SandboxSpec,
    SandboxState, Sha256Digest, TargetPath, TargetPlatform,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::{
    RuntimeCommandExecutor, RuntimeCommandOutput, RuntimeCommandRequest, RuntimeCommandTermination,
    SystemRuntimeCommandExecutor, WINDOWS_HYPERV_PROVIDER_ID,
    WindowsHyperVSandboxAuthorizationConsumer, WindowsHyperVSandboxAuthorizationRequest,
    endpoint::{EndpointReplayCache, WindowsHyperVExecutionEndpoint},
    error,
    naming::ResourceName,
    persistence::{
        DurableCreate, DurableDestroyDisposition, DurableDestroyRequest, DurableEntry,
        DurableEntryPhase, DurableEvent, DurableSnapshot, LifecycleJournal,
    },
};

const DOCKER_HOST: &str = "npipe:////./pipe/docker_engine";
const DOCKER_CONFIG_DIRECTORY: &str = "docker-cli-empty";
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const MAX_RUNTIME_BINARY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HOST_PATH_UTF16: usize = 1024;
const MAX_PROCESS_LIMIT: u32 = 1_000_000;
const CONTROL_OUTPUT_BYTES: usize = 1024 * 1024;
const OWNER_LABEL: &str = "io.automata.owner";
const OWNER_VALUE: &str = "automata-runner";
const RESOURCE_SCHEMA_LABEL: &str = "io.automata.sandbox-schema";
const RESOURCE_SCHEMA: &str = "2";
const CUSTODY_KIND_LABEL: &str = "io.automata.custody-kind";
const CUSTODY_RUNNER_LABEL: &str = "io.automata.custody-runner";
const CUSTODY_SLOT_LABEL: &str = "io.automata.custody-slot";
const SANDBOX_LABEL: &str = "io.automata.sandbox";
const GENERATION_LABEL: &str = "io.automata.generation";
const PROFILE_LABEL: &str = "io.automata.profile";
const PROFILE_DIGEST_LABEL: &str = "io.automata.profile-sha256";
const SPEC_DIGEST_LABEL: &str = "io.automata.spec-sha256";
const IMAGE_LABEL: &str = "io.automata.image";
const WORKSPACE_LABEL: &str = "io.automata.workspace";
const HYPERV_LABEL: &str = "io.automata.windows.hyperv-required";
const MEMORY_LIMIT_LABEL: &str = "io.automata.windows.memory-bytes";
const CPU_LIMIT_LABEL: &str = "io.automata.windows.cpu-millis";
const PROCESS_LIMIT_LABEL: &str = "io.automata.windows.process-limit";

/// Closed host configuration for the Hyper-V Windows container provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsHyperVContainerProviderOptions {
    state_root: PathBuf,
    runtime_executable: PathBuf,
    runtime_sha256: Sha256Digest,
    guest_agent_path: TargetPath,
    operation_timeout: Duration,
}

impl WindowsHyperVContainerProviderOptions {
    /// Creates an exact provider configuration.
    ///
    /// The runtime must be an absolute `.exe` path pinned by SHA-256. The
    /// guest agent path is inside the immutable Windows container image.
    ///
    /// # Errors
    ///
    /// Rejects ambiguous host paths, a non-Windows guest path, or an invalid
    /// executable filename.
    pub fn new(
        state_root: impl Into<PathBuf>,
        runtime_executable: impl Into<PathBuf>,
        runtime_sha256: Sha256Digest,
        guest_agent_path: TargetPath,
    ) -> Result<Self, ProviderError> {
        let state_root = state_root.into();
        let runtime_executable = runtime_executable.into();
        if !safe_host_path(&state_root, false)
            || !safe_host_path(&runtime_executable, true)
            || guest_agent_path.platform() != TargetPlatform::Windows
            || !guest_agent_path
                .as_str()
                .to_ascii_lowercase()
                .ends_with(".exe")
        {
            return Err(error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            ));
        }
        Ok(Self {
            state_root,
            runtime_executable,
            runtime_sha256,
            guest_agent_path,
            operation_timeout: Duration::from_mins(2),
        })
    }

    /// Replaces the default two-minute container-control timeout.
    ///
    /// # Errors
    ///
    /// Rejects zero or more than ten minutes.
    pub fn with_operation_timeout(mut self, timeout: Duration) -> Result<Self, ProviderError> {
        if timeout.is_zero() || timeout > Duration::from_mins(10) {
            return Err(error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            ));
        }
        self.operation_timeout = timeout;
        Ok(self)
    }

    /// Returns the provider's dedicated host-state root.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Returns the exact pinned container CLI executable.
    #[must_use]
    pub fn runtime_executable(&self) -> &Path {
        &self.runtime_executable
    }

    /// Returns the expected runtime executable digest.
    #[must_use]
    pub const fn runtime_sha256(&self) -> Sha256Digest {
        self.runtime_sha256
    }

    /// Returns the in-image guest-agent executable path.
    #[must_use]
    pub const fn guest_agent_path(&self) -> &TargetPath {
        &self.guest_agent_path
    }

    /// Returns the lifecycle operation timeout.
    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }
}

/// Whole-job provider backed exclusively by Hyper-V-isolated Windows containers.
#[derive(Clone)]
pub struct WindowsHyperVContainerProvider {
    pub(crate) inner: Arc<ProviderInner>,
}

impl WindowsHyperVContainerProvider {
    /// Opens the provider using the real local container CLI.
    ///
    /// # Errors
    ///
    /// Fails when the pinned runtime binary or dedicated state root cannot be
    /// verified. No container is created during open.
    pub fn open(options: WindowsHyperVContainerProviderOptions) -> Result<Self, ProviderError> {
        Self::open_with_boundaries(options, Arc::new(SystemRuntimeCommandExecutor), None)
    }

    /// Opens the provider with a restricted authorization-consumer boundary.
    ///
    /// Job-custody creates require this boundary. Profile-admission creates may
    /// use [`Self::open`] because they carry no workload placement authority.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration or local-storage failure.
    pub fn open_with_authorization_consumer(
        options: WindowsHyperVContainerProviderOptions,
        authorization_consumer: Arc<dyn WindowsHyperVSandboxAuthorizationConsumer>,
    ) -> Result<Self, ProviderError> {
        Self::open_with_boundaries(
            options,
            Arc::new(SystemRuntimeCommandExecutor),
            Some(authorization_consumer),
        )
    }

    /// Opens the provider with an injected runtime boundary.
    ///
    /// This is intended for shipped conformance tests; the same binary digest
    /// and host-state validation are still applied.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration or local-storage failure.
    pub fn open_with_executor(
        options: WindowsHyperVContainerProviderOptions,
        executor: Arc<dyn RuntimeCommandExecutor>,
    ) -> Result<Self, ProviderError> {
        Self::open_with_boundaries(options, executor, None)
    }

    /// Opens the provider with injected runtime and authorization boundaries.
    ///
    /// This is intended for shipped conformance tests. Future broker composition
    /// may use [`Self::open_with_authorization_consumer`]; current product wiring
    /// leaves job custody fail closed.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration or local-storage failure.
    pub fn open_with_executor_and_authorization_consumer(
        options: WindowsHyperVContainerProviderOptions,
        executor: Arc<dyn RuntimeCommandExecutor>,
        authorization_consumer: Arc<dyn WindowsHyperVSandboxAuthorizationConsumer>,
    ) -> Result<Self, ProviderError> {
        Self::open_with_boundaries(options, executor, Some(authorization_consumer))
    }

    fn open_with_boundaries(
        options: WindowsHyperVContainerProviderOptions,
        executor: Arc<dyn RuntimeCommandExecutor>,
        authorization_consumer: Option<Arc<dyn WindowsHyperVSandboxAuthorizationConsumer>>,
    ) -> Result<Self, ProviderError> {
        prepare_state_root(options.state_root())?;
        prepare_empty_runtime_config(options.state_root())?;
        let runtime_guard = verify_runtime_binary(&options)?;
        let (journal, snapshot) =
            LifecycleJournal::open(options.state_root()).map_err(|failure| {
                let kind = match failure.kind() {
                    std::io::ErrorKind::WouldBlock => ProviderErrorKind::Conflict,
                    std::io::ErrorKind::InvalidData | std::io::ErrorKind::FileTooLarge => {
                        ProviderErrorKind::InvalidConfiguration
                    }
                    _ => ProviderErrorKind::LocalStorage,
                };
                error::known(kind, ProviderStage::Validate)
            })?;
        let provider_id = ProviderId::new(WINDOWS_HYPERV_PROVIDER_ID).map_err(|_| {
            error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let capabilities = ProviderCapabilities::new([
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
            SandboxCapability::WritableRootFilesystem,
            SandboxCapability::ResourceLimits,
            SandboxCapability::ProcessLimits,
        ])
        .map_err(|_| {
            error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let inner = Arc::new(ProviderInner {
            options,
            executor,
            authorization_consumer,
            provider_id,
            capabilities,
            _runtime_guard: runtime_guard,
            lifecycle: Mutex::new(LifecycleState { journal, snapshot }),
            handle_locks: Mutex::new(BTreeMap::new()),
            endpoint_replay: Mutex::new(EndpointReplayCache::default()),
        });
        inner.reconcile_startup()?;
        Ok(Self { inner })
    }
}

impl fmt::Debug for WindowsHyperVContainerProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsHyperVContainerProvider")
            .field("provider_id", &self.inner.provider_id)
            .field("state_root", &self.inner.options.state_root())
            .field("capabilities", &self.inner.capabilities)
            .finish_non_exhaustive()
    }
}

impl SandboxProvider for WindowsHyperVContainerProvider {
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
        validate_spec(spec, self.inner.authorization_consumer.is_some())?;
        let names = ResourceName::for_create(spec.operation_id(), spec.generation());
        let fingerprint = spec_fingerprint(spec);
        self.inner.runtime_request(
            create_arguments(spec, &names, &fingerprint),
            None,
            self.inner.options.operation_timeout(),
            CONTROL_OUTPUT_BYTES,
        )?;
        let operation_lock = self.inner.handle_lock(&names)?;
        let _operation = operation_lock.lock().map_err(|_| {
            error::known(
                ProviderErrorKind::LocalStorage,
                ProviderStage::CreateSandbox,
            )
        })?;
        self.inner.create(spec, &names, &fingerprint, cancellation)
    }

    fn attach(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn automata_ci_execution::ExecutionEndpoint>, ProviderError> {
        let names = ResourceName::from_handle(handle, &self.inner.provider_id)?;
        let operation_lock = self.inner.handle_lock(&names)?;
        let process_limit = {
            let _operation = operation_lock.lock().map_err(|_| {
                error::known(ProviderErrorKind::LocalStorage, ProviderStage::Attach)
            })?;
            let inspection = self.inner.inspect_owned(&names, cancellation)?;
            if inspection.state() != SandboxState::Running {
                return Err(error::known(
                    ProviderErrorKind::InvalidState,
                    ProviderStage::Attach,
                ));
            }
            self.inner.process_limit(&names, cancellation)?
        };
        Ok(Box::new(WindowsHyperVExecutionEndpoint::new(
            Arc::clone(&self.inner),
            names,
            operation_lock,
            process_limit,
        )))
    }

    fn inspect(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        let names = ResourceName::from_handle(handle, &self.inner.provider_id)?;
        let operation_lock = self.inner.handle_lock(&names)?;
        let _operation = operation_lock
            .lock()
            .map_err(|_| error::known(ProviderErrorKind::LocalStorage, ProviderStage::Inspect))?;
        self.inner.inspect_owned(&names, cancellation)
    }

    fn destroy(
        &self,
        request: &DestroySandbox,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        let names = ResourceName::from_handle(request.handle(), &self.inner.provider_id)?;
        if names.generation() != request.generation() {
            return Err(error::known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
            ));
        }
        let operation_lock = self.inner.handle_lock(&names)?;
        let _operation = operation_lock.lock().map_err(|_| {
            error::known(
                ProviderErrorKind::LocalStorage,
                ProviderStage::DestroySandbox,
            )
        })?;
        self.inner.destroy(request, &names, cancellation)
    }
}

pub(crate) struct ProviderInner {
    pub(crate) options: WindowsHyperVContainerProviderOptions,
    executor: Arc<dyn RuntimeCommandExecutor>,
    authorization_consumer: Option<Arc<dyn WindowsHyperVSandboxAuthorizationConsumer>>,
    provider_id: ProviderId,
    capabilities: ProviderCapabilities,
    _runtime_guard: File,
    lifecycle: Mutex<LifecycleState>,
    handle_locks: Mutex<BTreeMap<String, Weak<Mutex<()>>>>,
    pub(crate) endpoint_replay: Mutex<EndpointReplayCache>,
}

struct LifecycleState {
    journal: LifecycleJournal,
    snapshot: DurableSnapshot,
}

impl LifecycleState {
    fn append(&mut self, event: &DurableEvent) -> std::io::Result<u64> {
        self.journal.append_to_snapshot(&mut self.snapshot, event)
    }
}

impl fmt::Debug for ProviderInner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderInner")
            .field("provider_id", &self.provider_id)
            .field("state_root", &self.options.state_root())
            .finish_non_exhaustive()
    }
}

impl ProviderInner {
    fn reconcile_startup(&self) -> Result<(), ProviderError> {
        let mut lifecycle = self.lifecycle.lock().map_err(|_| invalid_lifecycle())?;
        validate_durable_snapshot(&self.provider_id, &lifecycle.snapshot)?;
        let entries: Vec<_> = lifecycle.snapshot.entries.values().cloned().collect();
        for entry in entries {
            let names = resource_from_durable(&self.provider_id, &entry)?;
            let request = if let Some(request) = lifecycle
                .snapshot
                .pending_destroys
                .values()
                .find(|request| request.handle == entry.handle)
                .cloned()
            {
                request
            } else {
                let request = DurableDestroyRequest {
                    operation_id: OperationId::new(),
                    handle: entry.handle.clone(),
                    generation: entry.generation,
                    profile: entry.profile.clone(),
                    custody: entry.custody,
                };
                lifecycle
                    .append(&DurableEvent::DestroyIntent {
                        request: request.clone(),
                    })
                    .map_err(|_| invalid_lifecycle())?;
                request
            };
            if let Some(inspection) = self.inspect_optional(&names, &NeverCancelled)? {
                validate_durable_inspection(&inspection, &names, &entry)?;
                self.remove_container(&names, &NeverCancelled)?;
            }
            if self.inspect_optional(&names, &NeverCancelled)?.is_some() {
                return Err(error::uncertain(
                    ProviderErrorKind::InvalidState,
                    ProviderStage::DestroyContainer,
                    names.handle(),
                ));
            }
            lifecycle
                .append(&DurableEvent::DestroyComplete {
                    operation_id: request.operation_id,
                })
                .map_err(|_| invalid_lifecycle())?;
        }
        drop(lifecycle);

        if !self.list_owned_container_names()?.is_empty() {
            return Err(error::known(
                ProviderErrorKind::Conflict,
                ProviderStage::VerifyOwnership,
            ));
        }
        Ok(())
    }

    fn list_owned_container_names(&self) -> Result<Vec<String>, ProviderError> {
        let filter = format!("label={OWNER_LABEL}={OWNER_VALUE}");
        let output = self.runtime(
            strings([
                "container",
                "ls",
                "--all",
                "--filter",
                filter.as_str(),
                "--format",
                "{{.Names}}",
            ]),
            None,
            self.options.operation_timeout(),
            CONTROL_OUTPUT_BYTES,
            &NeverCancelled,
        )?;
        if !output.succeeded() {
            return Err(command_error(
                &output,
                ProviderStage::Validate,
                OperationOutcome::KnownNoEffect,
                None,
            ));
        }
        let text = std::str::from_utf8(output.stdout()).map_err(|_| {
            error::known(ProviderErrorKind::BackendRejected, ProviderStage::Validate)
        })?;
        let mut names = Vec::new();
        for value in text
            .lines()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if value.len() > 255
                || !value.is_ascii()
                || !value.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
                })
            {
                return Err(error::known(
                    ProviderErrorKind::BackendRejected,
                    ProviderStage::Validate,
                ));
            }
            names.push(value.to_owned());
        }
        Ok(names)
    }

    fn handle_lock(&self, names: &ResourceName) -> Result<Arc<Mutex<()>>, ProviderError> {
        let mut locks = self
            .handle_locks
            .lock()
            .map_err(|_| error::known(ProviderErrorKind::LocalStorage, ProviderStage::Validate))?;
        locks.retain(|_, value| value.strong_count() > 0);
        if let Some(lock) = locks.get(names.identifier()).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(names.identifier().to_owned(), Arc::downgrade(&lock));
        Ok(lock)
    }

    fn consume_sandbox_authorization(&self, spec: &SandboxSpec) -> Result<(), ProviderError> {
        let Some(authorization) =
            sandbox_authorization(spec, self.authorization_consumer.is_some())?
        else {
            return Ok(());
        };
        let consumer = self.authorization_consumer.as_ref().ok_or_else(|| {
            error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let allocation = spec.resource_allocation().ok_or_else(|| {
            error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let execution_binding = spec.execution_binding().ok_or_else(|| {
            error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        consumer.consume(
            authorization,
            WindowsHyperVSandboxAuthorizationRequest::new(
                spec.operation_id(),
                spec.custody(),
                execution_binding,
                spec.profile().attestation(),
                spec.generation(),
                allocation,
                spec.resources().pids(),
            ),
        )
    }

    #[allow(clippy::too_many_lines)] // One locked durable transition is easier to audit intact.
    fn create(
        &self,
        spec: &SandboxSpec,
        names: &ResourceName,
        fingerprint: &str,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError> {
        if cancellation.disposition().requires_termination() {
            return Err(error::known(
                ProviderErrorKind::Cancelled,
                ProviderStage::CreateSandbox,
            ));
        }
        let handle = names.handle();
        let mut lifecycle = self.lifecycle.lock().map_err(|_| {
            error::known(
                ProviderErrorKind::LocalStorage,
                ProviderStage::CreateSandbox,
            )
        })?;
        let new_create = if let Some(replay) = lifecycle.snapshot.creates.get(&spec.operation_id())
        {
            if replay.handle != handle.opaque()
                || replay.fingerprint != fingerprint
                || replay.custody != spec.custody()
            {
                return Err(error::known(
                    ProviderErrorKind::Conflict,
                    ProviderStage::CreateSandbox,
                ));
            }
            if let Some(tombstone) = lifecycle.snapshot.tombstones.get(handle.opaque()) {
                if tombstone.generation != names.generation().get()
                    || tombstone.profile != *spec.profile().attestation()
                    || tombstone.custody != spec.custody()
                {
                    return Err(invalid_lifecycle());
                }
                return Ok(record(
                    names,
                    tombstone.profile.clone(),
                    SandboxState::Absent,
                ));
            }
            let entry = lifecycle
                .snapshot
                .entries
                .get(handle.opaque())
                .ok_or_else(invalid_lifecycle)?;
            validate_durable_entry(
                entry,
                names,
                fingerprint,
                spec.profile().attestation(),
                spec.custody(),
            )?;
            if entry.phase == DurableEntryPhase::Destroying {
                return Err(error::known(
                    ProviderErrorKind::Conflict,
                    ProviderStage::CreateSandbox,
                ));
            }
            false
        } else {
            self.consume_sandbox_authorization(spec)?;
            if self.inspect_optional(names, cancellation)?.is_some() {
                return Err(error::known(
                    ProviderErrorKind::Conflict,
                    ProviderStage::CreateSandbox,
                ));
            }
            self.verify_image(spec, cancellation)?;
            let event = DurableEvent::CreateIntent {
                create: DurableCreate {
                    operation_id: spec.operation_id(),
                    fingerprint: fingerprint.to_owned(),
                    handle: handle.opaque().to_owned(),
                    custody: spec.custody(),
                },
                entry: DurableEntry {
                    handle: handle.opaque().to_owned(),
                    generation: names.generation().get(),
                    profile: spec.profile().attestation().clone(),
                    custody: spec.custody(),
                    container: names.container(),
                    fingerprint: fingerprint.to_owned(),
                    phase: DurableEntryPhase::Intent,
                },
            };
            lifecycle.append(&event).map_err(|_| {
                error::uncertain(
                    ProviderErrorKind::LocalStorage,
                    ProviderStage::CreateSandbox,
                    handle.clone(),
                )
            })?;
            true
        };

        let existing = if new_create {
            None
        } else {
            self.inspect_optional(names, cancellation)
                .map_err(|failure| {
                    error::uncertain(failure.kind(), ProviderStage::CreateSandbox, handle.clone())
                })?
        };
        if let Some(existing) = existing {
            validate_inspection(
                &existing,
                names,
                spec.profile().attestation(),
                fingerprint,
                spec,
            )
            .map_err(|failure| {
                error::uncertain(
                    failure.kind(),
                    ProviderStage::VerifyOwnership,
                    handle.clone(),
                )
            })?;
            if existing.state.running {
                if let Err(failure) = self.probe_guest(names, cancellation) {
                    let _ = self.terminate_container(names, &NeverCancelled);
                    return Err(failure);
                }
                if lifecycle
                    .snapshot
                    .entries
                    .get(handle.opaque())
                    .is_some_and(|entry| entry.phase == DurableEntryPhase::Intent)
                {
                    lifecycle
                        .append(&DurableEvent::CreateRunning {
                            handle: handle.opaque().to_owned(),
                        })
                        .map_err(|_| {
                            error::uncertain(
                                ProviderErrorKind::LocalStorage,
                                ProviderStage::CreateSandbox,
                                handle.clone(),
                            )
                        })?;
                }
                return Ok(record(names, existing.profile()?, SandboxState::Running));
            }
            if existing.state.status != "created" {
                return Err(error::uncertain(
                    ProviderErrorKind::Conflict,
                    ProviderStage::CreateSandbox,
                    handle.clone(),
                ));
            }
        } else {
            if !new_create {
                self.verify_image(spec, cancellation).map_err(|failure| {
                    error::uncertain(failure.kind(), ProviderStage::CreateSandbox, handle.clone())
                })?;
            }
            let output = self
                .runtime(
                    create_arguments(spec, names, fingerprint),
                    None,
                    self.options.operation_timeout(),
                    CONTROL_OUTPUT_BYTES,
                    cancellation,
                )
                .map_err(|failure| {
                    error::uncertain(
                        failure.kind(),
                        ProviderStage::CreateContainer,
                        handle.clone(),
                    )
                })?;
            if !output.succeeded() {
                return Err(command_error(
                    &output,
                    ProviderStage::CreateContainer,
                    OperationOutcome::Uncertain,
                    Some(names.handle()),
                ));
            }
            let created = self
                .inspect_optional(names, cancellation)
                .map_err(|failure| {
                    error::uncertain(
                        failure.kind(),
                        ProviderStage::VerifyOwnership,
                        names.handle(),
                    )
                })?
                .ok_or_else(|| {
                    error::uncertain(
                        ProviderErrorKind::NotFound,
                        ProviderStage::VerifyOwnership,
                        names.handle(),
                    )
                })?;
            validate_inspection(
                &created,
                names,
                spec.profile().attestation(),
                fingerprint,
                spec,
            )
            .map_err(|failure| {
                error::uncertain(
                    failure.kind(),
                    ProviderStage::VerifyOwnership,
                    names.handle(),
                )
            })?;
        }

        let output = self
            .runtime(
                strings(["container", "start", names.container().as_str()]),
                None,
                self.options.operation_timeout(),
                CONTROL_OUTPUT_BYTES,
                cancellation,
            )
            .map_err(|failure| {
                error::uncertain(failure.kind(), ProviderStage::Start, handle.clone())
            })?;
        if !output.succeeded() {
            return Err(command_error(
                &output,
                ProviderStage::Start,
                OperationOutcome::Uncertain,
                Some(names.handle()),
            ));
        }
        let running = self
            .inspect_optional(names, cancellation)
            .map_err(|failure| {
                error::uncertain(failure.kind(), ProviderStage::Start, names.handle())
            })?
            .ok_or_else(|| {
                error::uncertain(
                    ProviderErrorKind::NotFound,
                    ProviderStage::Start,
                    names.handle(),
                )
            })?;
        validate_inspection(
            &running,
            names,
            spec.profile().attestation(),
            fingerprint,
            spec,
        )
        .map_err(|failure| {
            error::uncertain(failure.kind(), ProviderStage::Start, names.handle())
        })?;
        if !running.state.running || running.state.status != "running" {
            return Err(error::uncertain(
                ProviderErrorKind::InvalidState,
                ProviderStage::Start,
                names.handle(),
            ));
        }
        if let Err(failure) = self.probe_guest(names, cancellation) {
            let _ = self.terminate_container(names, &NeverCancelled);
            return Err(failure);
        }
        if lifecycle
            .snapshot
            .entries
            .get(handle.opaque())
            .is_some_and(|entry| entry.phase == DurableEntryPhase::Intent)
        {
            lifecycle
                .append(&DurableEvent::CreateRunning {
                    handle: handle.opaque().to_owned(),
                })
                .map_err(|_| {
                    error::uncertain(
                        ProviderErrorKind::LocalStorage,
                        ProviderStage::CreateSandbox,
                        handle,
                    )
                })?;
        }
        Ok(record(names, running.profile()?, SandboxState::Running))
    }

    fn verify_image(
        &self,
        spec: &SandboxSpec,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let image = spec.profile().image().ok_or_else(|| {
            error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let output = self.runtime(
            strings(["image", "inspect", image.reference()]),
            None,
            self.options.operation_timeout(),
            CONTROL_OUTPUT_BYTES,
            cancellation,
        )?;
        if !output.succeeded() {
            return Err(command_error(
                &output,
                ProviderStage::Validate,
                OperationOutcome::KnownNoEffect,
                None,
            ));
        }
        let images: Vec<ImageInspection> =
            serde_json::from_slice(output.stdout()).map_err(|_| {
                error::known(ProviderErrorKind::BackendRejected, ProviderStage::Validate)
            })?;
        if images.len() != 1
            || images[0].operating_system != "windows"
            || images[0].architecture != "amd64"
            || images[0]
                .config
                .volumes
                .as_ref()
                .is_some_and(|volumes| !volumes.is_empty())
            || !images[0]
                .repo_digests
                .iter()
                .any(|digest| digest == image.reference())
        {
            return Err(error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            ));
        }
        Ok(())
    }

    fn probe_guest(
        &self,
        names: &ResourceName,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        self.probe_non_admin(names, cancellation)?;
        let request = automata_ci_sandbox_guest::GuestRequest::Probe {
            protocol: automata_ci_sandbox_guest::GUEST_PROTOCOL_VERSION,
            operation_id: format!("create-{}", names.identifier()),
        };
        let response = self.guest_request(
            names,
            &request,
            self.options.operation_timeout(),
            cancellation,
            ProviderStage::Start,
        )?;
        if !matches!(
            response,
            automata_ci_sandbox_guest::GuestResponse::Ready {
                protocol: automata_ci_sandbox_guest::GUEST_PROTOCOL_VERSION
            }
        ) {
            return Err(error::uncertain(
                ProviderErrorKind::BackendRejected,
                ProviderStage::Start,
                names.handle(),
            ));
        }
        Ok(())
    }

    fn probe_non_admin(
        &self,
        names: &ResourceName,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        const SCRIPT: &str = "$i=[Security.Principal.WindowsIdentity]::GetCurrent();\
$p=[Security.Principal.WindowsPrincipal]::new($i);\
if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 91};exit 0";
        let output = self.runtime(
            strings([
                "container",
                "exec",
                "--user",
                "ContainerUser",
                "--workdir",
                r"C:\",
                names.container().as_str(),
                POWERSHELL,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "RemoteSigned",
                "-Command",
                SCRIPT,
            ]),
            None,
            self.options.operation_timeout(),
            1024,
            cancellation,
        )?;
        if output.succeeded() && output.stdout().is_empty() && output.stderr().is_empty() {
            Ok(())
        } else {
            Err(command_error(
                &output,
                ProviderStage::VerifyOwnership,
                OperationOutcome::Uncertain,
                Some(names.handle()),
            ))
        }
    }

    pub(crate) fn guest_request(
        &self,
        names: &ResourceName,
        request: &automata_ci_sandbox_guest::GuestRequest,
        timeout: Duration,
        cancellation: &dyn Cancellation,
        stage: ProviderStage,
    ) -> Result<automata_ci_sandbox_guest::GuestResponse, ProviderError> {
        let frame = automata_ci_sandbox_guest::encode_frame(request)
            .map_err(|_| error::known(ProviderErrorKind::InvalidConfiguration, stage))?;
        let arguments = vec![
            OsString::from("container"),
            OsString::from("exec"),
            OsString::from("--interactive"),
            OsString::from("--user"),
            OsString::from("ContainerUser"),
            OsString::from(names.container()),
            OsString::from(self.options.guest_agent_path().as_str()),
            OsString::from("stdio-once"),
        ];
        let output = self.runtime(
            arguments,
            Some(frame),
            timeout,
            automata_ci_sandbox_guest::MAX_GUEST_FRAME_BYTES + 4,
            cancellation,
        )?;
        if !output.succeeded()
            || !output.stderr().is_empty()
            || !output.stdin_was_fully_written()
            || output.was_truncated()
        {
            return Err(command_error(
                &output,
                stage,
                OperationOutcome::Uncertain,
                Some(names.handle()),
            ));
        }
        automata_ci_sandbox_guest::decode_frame(output.stdout()).map_err(|_| {
            error::uncertain(ProviderErrorKind::BackendRejected, stage, names.handle())
        })
    }

    pub(crate) fn inspect_owned(
        &self,
        names: &ResourceName,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        let entry = {
            let lifecycle = self.lifecycle.lock().map_err(|_| {
                error::known(ProviderErrorKind::LocalStorage, ProviderStage::Inspect)
            })?;
            if let Some(tombstone) = lifecycle.snapshot.tombstones.get(names.handle().opaque()) {
                if tombstone.generation != names.generation().get() {
                    return Err(error::known(
                        ProviderErrorKind::OwnershipMismatch,
                        ProviderStage::VerifyOwnership,
                    ));
                }
                return Ok(SandboxInspection::new(
                    names.handle(),
                    names.generation(),
                    tombstone.custody,
                    tombstone.profile.clone(),
                    SandboxState::Absent,
                ));
            }
            lifecycle
                .snapshot
                .entries
                .get(names.handle().opaque())
                .cloned()
                .ok_or_else(|| error::known(ProviderErrorKind::NotFound, ProviderStage::Inspect))?
        };
        validate_durable_entry_shape(&entry, names)?;
        let Some(inspection) = self.inspect_optional(names, cancellation)? else {
            return Ok(SandboxInspection::new(
                names.handle(),
                names.generation(),
                entry.custody,
                entry.profile,
                SandboxState::Degraded,
            ));
        };
        validate_durable_inspection(&inspection, names, &entry)?;
        Ok(SandboxInspection::new(
            names.handle(),
            names.generation(),
            entry.custody,
            entry.profile,
            inspection.sandbox_state(),
        ))
    }

    pub(crate) fn process_limit(
        &self,
        names: &ResourceName,
        cancellation: &dyn Cancellation,
    ) -> Result<u32, ProviderError> {
        let entry = {
            let lifecycle = self.lifecycle.lock().map_err(|_| {
                error::known(ProviderErrorKind::LocalStorage, ProviderStage::Inspect)
            })?;
            lifecycle
                .snapshot
                .entries
                .get(names.handle().opaque())
                .cloned()
                .ok_or_else(|| error::known(ProviderErrorKind::NotFound, ProviderStage::Inspect))?
        };
        let inspection = self
            .inspect_optional(names, cancellation)?
            .ok_or_else(|| error::known(ProviderErrorKind::NotFound, ProviderStage::Inspect))?;
        validate_durable_inspection(&inspection, names, &entry)?;
        inspection.process_limit()
    }

    fn inspect_optional(
        &self,
        names: &ResourceName,
        cancellation: &dyn Cancellation,
    ) -> Result<Option<ContainerInspection>, ProviderError> {
        let output = self.runtime(
            strings(["container", "inspect", names.container().as_str()]),
            None,
            self.options.operation_timeout(),
            CONTROL_OUTPUT_BYTES,
            cancellation,
        )?;
        if !output.succeeded() {
            if runtime_reports_not_found(&output) {
                return Ok(None);
            }
            return Err(command_error(
                &output,
                ProviderStage::Inspect,
                OperationOutcome::KnownNoEffect,
                None,
            ));
        }
        let mut records: Vec<ContainerInspection> = serde_json::from_slice(output.stdout())
            .map_err(|_| {
                error::known(ProviderErrorKind::BackendRejected, ProviderStage::Inspect)
            })?;
        if records.len() != 1 {
            return Err(error::known(
                ProviderErrorKind::BackendRejected,
                ProviderStage::Inspect,
            ));
        }
        Ok(records.pop())
    }

    #[allow(clippy::too_many_lines)] // WAL intent, cleanup, and completion must stay visibly ordered.
    fn destroy(
        &self,
        request: &DestroySandbox,
        names: &ResourceName,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        if cancellation.disposition().requires_termination() {
            return Err(error::known(
                ProviderErrorKind::Cancelled,
                ProviderStage::DestroySandbox,
            ));
        }
        let handle = names.handle();
        let mut lifecycle = self.lifecycle.lock().map_err(|_| {
            error::known(
                ProviderErrorKind::LocalStorage,
                ProviderStage::DestroySandbox,
            )
        })?;
        if let Some(replay) = lifecycle.snapshot.destroys.get(&request.operation_id()) {
            if replay.handle != handle.opaque()
                || replay.generation != request.generation().get()
                || replay.custody != request.custody()
            {
                return Err(error::known(
                    ProviderErrorKind::Conflict,
                    ProviderStage::DestroySandbox,
                ));
            }
            return Ok(match replay.disposition {
                DurableDestroyDisposition::Destroyed => DestroyDisposition::Destroyed,
                DurableDestroyDisposition::AlreadyAbsent => DestroyDisposition::AlreadyAbsent,
            });
        }

        let pending = if let Some(pending) = lifecycle
            .snapshot
            .pending_destroys
            .get(&request.operation_id())
            .cloned()
        {
            if pending.handle != handle.opaque()
                || pending.generation != request.generation().get()
                || pending.custody != request.custody()
            {
                return Err(error::known(
                    ProviderErrorKind::Conflict,
                    ProviderStage::DestroySandbox,
                ));
            }
            pending
        } else if lifecycle
            .snapshot
            .pending_destroys
            .values()
            .any(|pending| pending.handle == handle.opaque())
        {
            return Err(error::known(
                ProviderErrorKind::Conflict,
                ProviderStage::DestroySandbox,
            ));
        } else if let Some(tombstone) = lifecycle.snapshot.tombstones.get(handle.opaque()).cloned()
        {
            if tombstone.generation != request.generation().get()
                || tombstone.custody != request.custody()
            {
                return Err(error::known(
                    ProviderErrorKind::OwnershipMismatch,
                    ProviderStage::VerifyOwnership,
                ));
            }
            let durable = DurableDestroyRequest {
                operation_id: request.operation_id(),
                handle: handle.opaque().to_owned(),
                generation: request.generation().get(),
                profile: tombstone.profile,
                custody: request.custody(),
            };
            lifecycle
                .append(&DurableEvent::DestroyAbsent { request: durable })
                .map_err(|_| {
                    error::uncertain(
                        ProviderErrorKind::LocalStorage,
                        ProviderStage::DestroySandbox,
                        handle.clone(),
                    )
                })?;
            return Ok(DestroyDisposition::AlreadyAbsent);
        } else {
            let entry = lifecycle
                .snapshot
                .entries
                .get(handle.opaque())
                .cloned()
                .ok_or_else(|| {
                    error::known(ProviderErrorKind::NotFound, ProviderStage::DestroySandbox)
                })?;
            if entry.generation != request.generation().get() || entry.custody != request.custody()
            {
                return Err(error::known(
                    ProviderErrorKind::OwnershipMismatch,
                    ProviderStage::VerifyOwnership,
                ));
            }
            let durable = DurableDestroyRequest {
                operation_id: request.operation_id(),
                handle: handle.opaque().to_owned(),
                generation: request.generation().get(),
                profile: entry.profile,
                custody: request.custody(),
            };
            lifecycle
                .append(&DurableEvent::DestroyIntent {
                    request: durable.clone(),
                })
                .map_err(|_| {
                    error::uncertain(
                        ProviderErrorKind::LocalStorage,
                        ProviderStage::DestroySandbox,
                        handle.clone(),
                    )
                })?;
            durable
        };

        let entry = lifecycle
            .snapshot
            .entries
            .get(handle.opaque())
            .cloned()
            .ok_or_else(invalid_lifecycle)?;
        if entry.generation != pending.generation
            || entry.profile != pending.profile
            || entry.custody != pending.custody
            || pending.custody != request.custody()
        {
            return Err(invalid_lifecycle());
        }
        if let Some(inspection) = self
            .inspect_optional(names, cancellation)
            .map_err(|failure| {
                error::uncertain(
                    failure.kind(),
                    ProviderStage::DestroyContainer,
                    handle.clone(),
                )
            })?
        {
            validate_durable_inspection(&inspection, names, &entry)?;
            self.remove_container(names, cancellation)?;
        }
        if self.inspect_optional(names, &NeverCancelled)?.is_some() {
            return Err(error::uncertain(
                ProviderErrorKind::InvalidState,
                ProviderStage::DestroyContainer,
                handle.clone(),
            ));
        }
        lifecycle
            .append(&DurableEvent::DestroyComplete {
                operation_id: pending.operation_id,
            })
            .map_err(|_| {
                error::uncertain(
                    ProviderErrorKind::LocalStorage,
                    ProviderStage::DestroySandbox,
                    handle.clone(),
                )
            })?;
        self.endpoint_replay
            .lock()
            .map_err(|_| {
                error::known(
                    ProviderErrorKind::LocalStorage,
                    ProviderStage::DestroySandbox,
                )
            })?
            .remove_handle(&handle);
        Ok(DestroyDisposition::Destroyed)
    }

    fn remove_container(
        &self,
        names: &ResourceName,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let output = self.runtime(
            strings([
                "container",
                "rm",
                "--force",
                "--volumes",
                names.container().as_str(),
            ]),
            None,
            self.options.operation_timeout(),
            CONTROL_OUTPUT_BYTES,
            cancellation,
        )?;
        if output.succeeded() {
            Ok(())
        } else {
            Err(command_error(
                &output,
                ProviderStage::DestroyContainer,
                OperationOutcome::Uncertain,
                Some(names.handle()),
            ))
        }
    }

    pub(crate) fn terminate_container(
        &self,
        names: &ResourceName,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let Some(inspection) = self.inspect_optional(names, cancellation)? else {
            return Err(error::known(
                ProviderErrorKind::NotFound,
                ProviderStage::Start,
            ));
        };
        validate_owned_shape(&inspection, names)?;
        if !inspection.state.running {
            return Ok(());
        }
        let output = self.runtime(
            strings(["container", "kill", names.container().as_str()]),
            None,
            self.options.operation_timeout(),
            CONTROL_OUTPUT_BYTES,
            cancellation,
        )?;
        if output.succeeded() {
            Ok(())
        } else {
            Err(command_error(
                &output,
                ProviderStage::Start,
                OperationOutcome::Uncertain,
                Some(names.handle()),
            ))
        }
    }

    pub(crate) fn wait_container(
        &self,
        names: &ResourceName,
        timeout: Duration,
        cancellation: &dyn Cancellation,
    ) -> Result<i32, ProviderError> {
        let inspection = self.inspect_owned(names, cancellation)?;
        if !matches!(
            inspection.state(),
            SandboxState::Running | SandboxState::Stopped
        ) {
            return Err(error::known(
                ProviderErrorKind::InvalidState,
                ProviderStage::Inspect,
            ));
        }
        let output = self.runtime(
            strings(["container", "wait", names.container().as_str()]),
            None,
            timeout,
            128,
            cancellation,
        )?;
        if !output.succeeded() {
            return Err(command_error(
                &output,
                ProviderStage::Inspect,
                OperationOutcome::KnownNoEffect,
                None,
            ));
        }
        std::str::from_utf8(output.stdout())
            .ok()
            .map(str::trim)
            .and_then(|value| value.parse::<i32>().ok())
            .ok_or_else(|| error::known(ProviderErrorKind::BackendRejected, ProviderStage::Inspect))
    }

    fn runtime(
        &self,
        arguments: Vec<OsString>,
        stdin: Option<Vec<u8>>,
        timeout: Duration,
        output_limit: usize,
        cancellation: &dyn Cancellation,
    ) -> Result<RuntimeCommandOutput, ProviderError> {
        let request = self.runtime_request(arguments, stdin, timeout, output_limit)?;
        Ok(self.executor.execute(&request, cancellation))
    }

    fn runtime_request(
        &self,
        mut arguments: Vec<OsString>,
        stdin: Option<Vec<u8>>,
        timeout: Duration,
        output_limit: usize,
    ) -> Result<RuntimeCommandRequest, ProviderError> {
        prepare_empty_runtime_config(self.options.state_root())?;
        let mut complete = vec![
            OsString::from("--config"),
            self.options
                .state_root()
                .join(DOCKER_CONFIG_DIRECTORY)
                .into_os_string(),
            OsString::from("--host"),
            OsString::from(DOCKER_HOST),
        ];
        complete.append(&mut arguments);
        let mut request = RuntimeCommandRequest::new(
            self.options.runtime_executable().to_path_buf(),
            complete,
            timeout,
            output_limit,
        )
        .map_err(|_| {
            error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        if let Some(stdin) = stdin {
            request = request.with_stdin(stdin).map_err(|_| {
                error::known(
                    ProviderErrorKind::InvalidConfiguration,
                    ProviderStage::Validate,
                )
            })?;
        }
        Ok(request)
    }
}

fn create_arguments(spec: &SandboxSpec, names: &ResourceName, fingerprint: &str) -> Vec<OsString> {
    let image = spec.profile().image().expect("validated image");
    let keepalive = spec.profile().keepalive().expect("validated keepalive");
    let mut arguments = strings([
        "container",
        "create",
        "--pull",
        "never",
        "--name",
        names.container().as_str(),
        "--isolation",
        "hyperv",
        "--network",
        "none",
        "--restart",
        "no",
        "--log-driver",
        "none",
        "--no-healthcheck",
        "--user",
        "ContainerUser",
        "--workdir",
        spec.workspace().as_str(),
        "--memory",
        spec.resources().memory_bytes().to_string().as_str(),
        "--cpus",
        format_cpu(spec.resources().cpu_millis()).as_str(),
    ]);
    for (name, value) in expected_labels(spec, names, fingerprint) {
        arguments.push(OsString::from("--label"));
        arguments.push(OsString::from(format!("{name}={value}")));
    }
    arguments.push(OsString::from("--entrypoint"));
    arguments.push(OsString::from(keepalive.program().as_str()));
    arguments.push(OsString::from(image.reference()));
    arguments.extend(keepalive.arguments().iter().map(OsString::from));
    arguments
}

fn format_cpu(cpu_millis: u32) -> String {
    format!("{}.{:03}", cpu_millis / 1_000, cpu_millis % 1_000)
}

fn expected_labels(
    spec: &SandboxSpec,
    names: &ResourceName,
    fingerprint: &str,
) -> BTreeMap<String, String> {
    let (custody_kind, custody_runner, custody_slot) = match spec.custody() {
        SandboxCustody::ProfileAdmission { runner_id } => {
            ("profile-admission", runner_id.to_string(), "0".to_owned())
        }
        SandboxCustody::Job {
            runner_id,
            slot_ordinal,
        } => ("job", runner_id.to_string(), slot_ordinal.get().to_string()),
    };
    BTreeMap::from([
        (OWNER_LABEL.to_owned(), OWNER_VALUE.to_owned()),
        (RESOURCE_SCHEMA_LABEL.to_owned(), RESOURCE_SCHEMA.to_owned()),
        (CUSTODY_KIND_LABEL.to_owned(), custody_kind.to_owned()),
        (CUSTODY_RUNNER_LABEL.to_owned(), custody_runner),
        (CUSTODY_SLOT_LABEL.to_owned(), custody_slot),
        (SANDBOX_LABEL.to_owned(), names.identifier().to_owned()),
        (
            GENERATION_LABEL.to_owned(),
            names.generation().get().to_string(),
        ),
        (
            PROFILE_LABEL.to_owned(),
            spec.profile().id().as_str().to_owned(),
        ),
        (
            PROFILE_DIGEST_LABEL.to_owned(),
            spec.profile().digest().to_string(),
        ),
        (SPEC_DIGEST_LABEL.to_owned(), fingerprint.to_owned()),
        (
            IMAGE_LABEL.to_owned(),
            spec.profile()
                .image()
                .expect("validated image")
                .reference()
                .to_owned(),
        ),
        (
            WORKSPACE_LABEL.to_owned(),
            spec.workspace().as_str().to_owned(),
        ),
        (HYPERV_LABEL.to_owned(), "true".to_owned()),
        (
            MEMORY_LIMIT_LABEL.to_owned(),
            spec.resources().memory_bytes().to_string(),
        ),
        (
            CPU_LIMIT_LABEL.to_owned(),
            spec.resources().cpu_millis().to_string(),
        ),
        (
            PROCESS_LIMIT_LABEL.to_owned(),
            spec.resources().pids().to_string(),
        ),
    ])
}

fn validate_spec(
    spec: &SandboxSpec,
    authorization_consumer_configured: bool,
) -> Result<(), ProviderError> {
    let SandboxLaunch::WindowsHyperVContainer { .. } = spec.profile().launch() else {
        return Err(error::known(
            ProviderErrorKind::UnsupportedCapability,
            ProviderStage::Validate,
        ));
    };
    if !spec.has_coherent_resource_contract()
        || spec.network() != automata_ci_execution::NetworkPolicy::Disabled
        || spec.root_filesystem() != RootFilesystemPolicy::Writable
        || spec.privilege() != SandboxPrivilegePolicy::Unprivileged
        || !spec.services().is_empty()
        || !spec.runtime_service_routes().is_empty()
        || spec.scratch().is_some()
        || spec.workspace().platform() != TargetPlatform::Windows
        || !windows_descendant_or_equal(spec.workspace(), spec.profile().workspace())
        || spec.resource_allocation().is_some_and(|allocation| {
            allocation.limits().ephemeral_disk_bytes() != 0 || allocation.limits().gpu_count() != 0
        })
    {
        return Err(error::known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
        ));
    }
    sandbox_authorization(spec, authorization_consumer_configured)?;
    Ok(())
}

fn sandbox_authorization(
    spec: &SandboxSpec,
    authorization_consumer_configured: bool,
) -> Result<Option<&SandboxAuthorization>, ProviderError> {
    let authorizations = spec.sandbox_authorizations().as_slice();
    match spec.custody() {
        SandboxCustody::ProfileAdmission { .. } if authorizations.is_empty() => Ok(None),
        SandboxCustody::Job { .. } if authorization_consumer_configured => {
            let [authorization] = authorizations else {
                return Err(error::known(
                    ProviderErrorKind::InvalidConfiguration,
                    ProviderStage::Validate,
                ));
            };
            if spec.resource_allocation().is_none() || spec.execution_binding().is_none() {
                return Err(error::known(
                    ProviderErrorKind::InvalidConfiguration,
                    ProviderStage::Validate,
                ));
            }
            Ok(Some(authorization))
        }
        SandboxCustody::ProfileAdmission { .. } | SandboxCustody::Job { .. } => Err(error::known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
        )),
    }
}

fn resource_from_durable(
    provider_id: &ProviderId,
    entry: &DurableEntry,
) -> Result<ResourceName, ProviderError> {
    let handle = SandboxHandle::new(provider_id.clone(), entry.handle.clone())
        .map_err(|_| invalid_lifecycle())?;
    let names = ResourceName::from_handle(&handle, provider_id)?;
    validate_durable_entry_shape(entry, &names)?;
    Ok(names)
}

#[allow(clippy::too_many_lines)] // The full durable cross-reference audit is intentionally linear.
fn validate_durable_snapshot(
    provider_id: &ProviderId,
    snapshot: &DurableSnapshot,
) -> Result<(), ProviderError> {
    for (operation_id, create) in &snapshot.creates {
        let handle = SandboxHandle::new(provider_id.clone(), create.handle.clone())
            .map_err(|_| invalid_lifecycle())?;
        let names =
            ResourceName::from_handle(&handle, provider_id).map_err(|_| invalid_lifecycle())?;
        if operation_id != &create.operation_id
            || names.identifier() != create.operation_id.as_uuid().simple().to_string()
            || !valid_fingerprint(&create.fingerprint)
            || snapshot
                .entries
                .get(&create.handle)
                .map(|entry| entry.custody)
                .or_else(|| {
                    snapshot
                        .tombstones
                        .get(&create.handle)
                        .map(|tombstone| tombstone.custody)
                })
                != Some(create.custody)
        {
            return Err(invalid_lifecycle());
        }
    }
    for (handle, entry) in &snapshot.entries {
        let names = resource_from_durable(provider_id, entry)?;
        if handle != &entry.handle
            || !snapshot
                .creates
                .values()
                .any(|create| create.handle == entry.handle)
            || names.generation().get() != entry.generation
        {
            return Err(invalid_lifecycle());
        }
    }
    for (handle, tombstone) in &snapshot.tombstones {
        let parsed = SandboxHandle::new(provider_id.clone(), tombstone.handle.clone())
            .map_err(|_| invalid_lifecycle())?;
        let names =
            ResourceName::from_handle(&parsed, provider_id).map_err(|_| invalid_lifecycle())?;
        if handle != &tombstone.handle
            || names.generation().get() != tombstone.generation
            || tombstone.completed_sequence == 0
            || !snapshot
                .creates
                .values()
                .any(|create| create.handle == tombstone.handle)
        {
            return Err(invalid_lifecycle());
        }
    }
    for (operation_id, pending) in &snapshot.pending_destroys {
        if operation_id != &pending.operation_id
            || snapshot.entries.get(&pending.handle).is_none_or(|entry| {
                entry.phase != DurableEntryPhase::Destroying
                    || entry.generation != pending.generation
                    || entry.profile != pending.profile
                    || entry.custody != pending.custody
            })
        {
            return Err(invalid_lifecycle());
        }
    }
    for (operation_id, destroy) in &snapshot.destroys {
        if operation_id != &destroy.operation_id
            || destroy.completed_sequence == 0
            || snapshot
                .tombstones
                .get(&destroy.handle)
                .is_none_or(|tombstone| {
                    tombstone.generation != destroy.generation
                        || tombstone.custody != destroy.custody
                })
        {
            return Err(invalid_lifecycle());
        }
    }
    Ok(())
}

fn validate_durable_entry(
    entry: &DurableEntry,
    names: &ResourceName,
    fingerprint: &str,
    profile: &EnvironmentProfile,
    custody: SandboxCustody,
) -> Result<(), ProviderError> {
    validate_durable_entry_shape(entry, names)?;
    if entry.fingerprint != fingerprint || entry.profile != *profile || entry.custody != custody {
        return Err(invalid_lifecycle());
    }
    Ok(())
}

fn validate_durable_entry_shape(
    entry: &DurableEntry,
    names: &ResourceName,
) -> Result<(), ProviderError> {
    if entry.handle != names.handle().opaque()
        || entry.generation != names.generation().get()
        || entry.container != names.container()
        || !valid_fingerprint(&entry.fingerprint)
    {
        return Err(invalid_lifecycle());
    }
    Ok(())
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_durable_inspection(
    inspection: &ContainerInspection,
    names: &ResourceName,
    entry: &DurableEntry,
) -> Result<(), ProviderError> {
    validate_durable_entry_shape(entry, names)?;
    validate_owned_shape(inspection, names)?;
    let memory = inspection
        .label(MEMORY_LIMIT_LABEL)
        .and_then(|value| value.parse::<u64>().ok());
    let cpu = inspection
        .label(CPU_LIMIT_LABEL)
        .and_then(|value| value.parse::<u32>().ok());
    if inspection.profile()? != entry.profile
        || inspection.custody()? != entry.custody
        || inspection.label(SPEC_DIGEST_LABEL) != Some(entry.fingerprint.as_str())
        || inspection.label(IMAGE_LABEL) != Some(inspection.config.image.as_str())
        || inspection.label(WORKSPACE_LABEL) != Some(inspection.config.working_directory.as_str())
        || memory != Some(inspection.host_config.memory)
        || cpu
            .map(i64::from)
            .and_then(|value| value.checked_mul(1_000_000))
            != Some(inspection.host_config.nano_cpus)
        || inspection.process_limit()? == 0
    {
        return Err(error::known(
            ProviderErrorKind::OwnershipMismatch,
            ProviderStage::VerifyOwnership,
        ));
    }
    Ok(())
}

fn invalid_lifecycle() -> ProviderError {
    error::known(
        ProviderErrorKind::InvalidConfiguration,
        ProviderStage::Validate,
    )
}

fn validate_inspection(
    inspection: &ContainerInspection,
    names: &ResourceName,
    profile: &EnvironmentProfile,
    fingerprint: &str,
    spec: &SandboxSpec,
) -> Result<(), ProviderError> {
    validate_owned_shape(inspection, names)?;
    let labels = expected_labels(spec, names, fingerprint);
    if inspection.profile()? != *profile
        || labels
            .iter()
            .any(|(name, value)| inspection.label(name) != Some(value.as_str()))
        || inspection.config.image != spec.profile().image().expect("validated image").reference()
        || inspection.config.working_directory != spec.workspace().as_str()
        || inspection.label(IMAGE_LABEL) != Some(inspection.config.image.as_str())
        || inspection.host_config.memory != spec.resources().memory_bytes()
        || inspection.host_config.nano_cpus != i64::from(spec.resources().cpu_millis()) * 1_000_000
        || inspection.process_limit()? != spec.resources().pids()
        || inspection.config.entrypoint.as_deref()
            != Some(&[spec
                .profile()
                .keepalive()
                .expect("keepalive")
                .program()
                .as_str()
                .to_owned()])
        || inspection.config.command.as_deref()
            != Some(spec.profile().keepalive().expect("keepalive").arguments())
    {
        return Err(error::known(
            ProviderErrorKind::Conflict,
            ProviderStage::VerifyOwnership,
        ));
    }
    Ok(())
}

fn validate_owned_shape(
    inspection: &ContainerInspection,
    names: &ResourceName,
) -> Result<(), ProviderError> {
    let labels = &inspection.config.labels;
    let owned = inspection.name.trim_start_matches('/') == names.container()
        && inspection
            .host_config
            .isolation
            .eq_ignore_ascii_case("hyperv")
        && inspection
            .host_config
            .network_mode
            .eq_ignore_ascii_case("none")
        && !inspection.host_config.privileged.0
        && !inspection.host_config.readonly_rootfs.0
        && inspection
            .host_config
            .binds
            .as_ref()
            .is_none_or(Vec::is_empty)
        && inspection
            .host_config
            .volumes_from
            .as_ref()
            .is_none_or(Vec::is_empty)
        && inspection
            .host_config
            .tmpfs
            .as_ref()
            .is_none_or(BTreeMap::is_empty)
        && inspection
            .host_config
            .mounts
            .as_ref()
            .is_none_or(Vec::is_empty)
        && inspection
            .host_config
            .devices
            .as_ref()
            .is_none_or(Vec::is_empty)
        && inspection
            .host_config
            .device_requests
            .as_ref()
            .is_none_or(Vec::is_empty)
        && inspection
            .host_config
            .security_opt
            .as_ref()
            .is_none_or(Vec::is_empty)
        && !inspection.host_config.auto_remove.0
        && inspection
            .host_config
            .restart_policy
            .name
            .eq_ignore_ascii_case("no")
        && inspection.host_config.restart_policy.maximum_retry_count == 0
        && inspection
            .host_config
            .log_config
            .kind
            .eq_ignore_ascii_case("none")
        && inspection.host_config.log_config.config.is_empty()
        && inspection
            .host_config
            .port_bindings
            .as_ref()
            .is_none_or(BTreeMap::is_empty)
        && !inspection.host_config.publish_all_ports.0
        && inspection.mounts.is_empty()
        && inspection
            .config
            .volumes
            .as_ref()
            .is_none_or(BTreeMap::is_empty)
        && inspection.config.user.eq_ignore_ascii_case("ContainerUser")
        && !inspection.config.attach_stdin.0
        && !inspection.config.open_stdin.0
        && !inspection.config.stdin_once.0
        && !inspection.config.tty.0
        && inspection
            .config
            .healthcheck
            .as_ref()
            .is_some_and(|healthcheck| healthcheck.test == ["NONE"])
        && inspection.network_settings.has_no_connectivity()
        && labels.get(OWNER_LABEL).map(String::as_str) == Some(OWNER_VALUE)
        && labels.get(RESOURCE_SCHEMA_LABEL).map(String::as_str) == Some(RESOURCE_SCHEMA)
        && labels.get(SANDBOX_LABEL).map(String::as_str) == Some(names.identifier())
        && labels.get(GENERATION_LABEL).map(String::as_str)
            == Some(names.generation().get().to_string().as_str())
        && labels.get(HYPERV_LABEL).map(String::as_str) == Some("true")
        && inspection.process_limit().is_ok()
        && inspection.custody().is_ok();
    if !owned {
        return Err(error::known(
            ProviderErrorKind::OwnershipMismatch,
            ProviderStage::VerifyOwnership,
        ));
    }
    Ok(())
}

fn record(names: &ResourceName, profile: EnvironmentProfile, state: SandboxState) -> SandboxRecord {
    SandboxRecord::new(names.handle(), names.generation(), profile, state)
}

fn spec_fingerprint(spec: &SandboxSpec) -> String {
    let mut hash = Sha256::new();
    hash_field(&mut hash, b"automata-windows-hyperv-spec-v3");
    hash_custody(&mut hash, spec.custody());
    for value in [
        spec.profile().id().as_str(),
        &spec.profile().digest().to_string(),
        spec.profile().image().expect("validated image").reference(),
        spec.profile()
            .keepalive()
            .expect("validated keepalive")
            .program()
            .as_str(),
        spec.profile().workspace().as_str(),
        spec.workspace().as_str(),
        &spec.generation().get().to_string(),
        &spec.resources().memory_bytes().to_string(),
        &spec.resources().cpu_millis().to_string(),
        &spec.resources().pids().to_string(),
    ] {
        hash_field(&mut hash, value.as_bytes());
    }
    for argument in spec
        .profile()
        .keepalive()
        .expect("validated keepalive")
        .arguments()
    {
        hash_field(&mut hash, argument.as_bytes());
    }
    for variable in spec.profile().default_environment().values() {
        hash_field(&mut hash, variable.name().as_str().as_bytes());
        hash_field(&mut hash, variable.value().expose().as_bytes());
    }
    if let Some(allocation) = spec.resource_allocation() {
        hash_field(&mut hash, b"allocation-present");
        for capacity in [allocation.requests(), allocation.limits()] {
            hash_field(&mut hash, &capacity.cpu_millis().to_be_bytes());
            hash_field(&mut hash, &capacity.memory_bytes().to_be_bytes());
            hash_field(&mut hash, &capacity.ephemeral_disk_bytes().to_be_bytes());
            hash_field(&mut hash, &capacity.gpu_count().to_be_bytes());
        }
    } else {
        hash_field(&mut hash, b"allocation-absent");
    }
    if let Some(binding) = spec.execution_binding() {
        hash_field(&mut hash, b"execution-binding-present");
        hash_field(&mut hash, binding.runner_session_id().as_uuid().as_bytes());
        hash_field(&mut hash, binding.run_id().as_uuid().as_bytes());
        hash_field(&mut hash, binding.job_id().as_uuid().as_bytes());
        hash_field(&mut hash, binding.attempt_id().as_uuid().as_bytes());
        hash_field(&mut hash, binding.guard().lease_id().as_uuid().as_bytes());
        hash_field(
            &mut hash,
            &binding.guard().fencing_token().get().to_be_bytes(),
        );
        hash_field(
            &mut hash,
            binding.accepted_offer_operation_id().as_uuid().as_bytes(),
        );
        hash_field(
            &mut hash,
            &binding.accepted_offer_sequence().get().to_be_bytes(),
        );
        hash_field(&mut hash, &binding.job_ir_version().get().to_be_bytes());
        hash_field(&mut hash, binding.job_ir_digest().as_bytes());
    } else {
        hash_field(&mut hash, b"execution-binding-absent");
    }
    for authorization in spec.sandbox_authorizations().as_slice() {
        hash_field(&mut hash, authorization.name().as_str().as_bytes());
        hash_field(
            &mut hash,
            &authorization.payload_schema_version().to_be_bytes(),
        );
        hash_field(&mut hash, authorization.payload_sha256().as_bytes());
    }
    hex_digest(hash.finalize().into())
}

fn hash_custody(hash: &mut Sha256, custody: SandboxCustody) {
    match custody {
        SandboxCustody::ProfileAdmission { runner_id } => {
            hash_field(hash, b"profile-admission");
            hash_field(hash, runner_id.as_uuid().as_bytes());
        }
        SandboxCustody::Job {
            runner_id,
            slot_ordinal,
        } => {
            hash_field(hash, b"job");
            hash_field(hash, runner_id.as_uuid().as_bytes());
            hash_field(hash, &slot_ordinal.get().to_be_bytes());
        }
    }
}

fn hash_field(hash: &mut Sha256, value: &[u8]) {
    hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(value);
}

fn hex_digest(bytes: [u8; 32]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut value, byte| {
            use std::fmt::Write as _;
            write!(&mut value, "{byte:02x}").expect("writing to String is infallible");
            value
        })
}

fn command_error(
    output: &RuntimeCommandOutput,
    stage: ProviderStage,
    outcome: OperationOutcome,
    recovery_handle: Option<SandboxHandle>,
) -> ProviderError {
    let kind = match output.termination() {
        RuntimeCommandTermination::Cancelled => ProviderErrorKind::Cancelled,
        RuntimeCommandTermination::TimedOut => ProviderErrorKind::TimedOut,
        RuntimeCommandTermination::FailedToStart => ProviderErrorKind::AdapterUnavailable,
        RuntimeCommandTermination::Exited(_) if output.was_truncated() => {
            ProviderErrorKind::OutputLimitExceeded
        }
        RuntimeCommandTermination::Exited(_) => ProviderErrorKind::BackendRejected,
    };
    error::provider(kind, stage, outcome, recovery_handle)
}

fn runtime_reports_not_found(output: &RuntimeCommandOutput) -> bool {
    if !matches!(
        output.termination(),
        RuntimeCommandTermination::Exited(Some(1))
    ) || output.was_truncated()
        || !output.stdout().is_empty()
        || !output.stdin_was_fully_written()
    {
        return false;
    }
    let stderr = String::from_utf8_lossy(output.stderr()).to_ascii_lowercase();
    stderr.contains("no such object") || stderr.contains("no such container")
}

fn strings<const N: usize>(values: [&str; N]) -> Vec<OsString> {
    values.into_iter().map(OsString::from).collect()
}

fn windows_descendant_or_equal(path: &TargetPath, root: &TargetPath) -> bool {
    if path.platform() != TargetPlatform::Windows || root.platform() != TargetPlatform::Windows {
        return false;
    }
    let path = path.as_str().trim_end_matches('\\').to_ascii_lowercase();
    let root = root.as_str().trim_end_matches('\\').to_ascii_lowercase();
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|suffix| suffix.starts_with('\\'))
}

fn safe_host_path(path: &Path, executable: bool) -> bool {
    if !path.is_absolute() || path.parent().is_none() {
        return false;
    }
    let Some(text) = path.to_str() else {
        return false;
    };
    if text.contains('%')
        || text.contains('/')
        || text.starts_with("\\\\")
        || text.encode_utf16().count() > MAX_HOST_PATH_UTF16
        || text.chars().any(char::is_control)
        || executable
            && path
                .extension()
                .and_then(|value| value.to_str())
                .is_none_or(|value| !value.eq_ignore_ascii_case("exe"))
    {
        return false;
    }
    let mut saw_prefix = false;
    let mut saw_root = false;
    let mut normal = 0_usize;
    for component in path.components() {
        match component {
            Component::Prefix(prefix)
                if matches!(prefix.kind(), std::path::Prefix::Disk(_)) && !saw_prefix =>
            {
                saw_prefix = true;
            }
            Component::RootDir if saw_prefix && !saw_root => saw_root = true,
            Component::Normal(value)
                if saw_root && value.to_str().is_some_and(valid_windows_component) =>
            {
                normal += 1;
            }
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir
            | Component::Normal(_) => return false,
        }
    }
    saw_prefix && saw_root && normal > usize::from(executable)
}

fn valid_windows_component(value: &str) -> bool {
    if value.is_empty()
        || value.ends_with([' ', '.'])
        || value
            .bytes()
            .any(|byte| matches!(byte, b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|'))
    {
        return false;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) && !(stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        && !(["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix)
                .is_some_and(|suffix| matches!(suffix, "¹" | "²" | "³"))
        }))
}

fn prepare_state_root(path: &Path) -> Result<(), ProviderError> {
    let mut existing = path;
    while !existing.exists() {
        existing = existing.parent().ok_or_else(|| {
            error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
    }
    require_no_reparse_chain(existing, true)?;
    fs::create_dir_all(path)
        .map_err(|_| error::known(ProviderErrorKind::LocalStorage, ProviderStage::Validate))?;
    require_no_reparse_chain(path, true)
}

fn prepare_empty_runtime_config(state_root: &Path) -> Result<(), ProviderError> {
    let path = state_root.join(DOCKER_CONFIG_DIRECTORY);
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(failure) if failure.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => {
            return Err(error::known(
                ProviderErrorKind::LocalStorage,
                ProviderStage::Validate,
            ));
        }
    }
    require_no_reparse_chain(&path, true)?;
    let mut entries = fs::read_dir(path)
        .map_err(|_| error::known(ProviderErrorKind::LocalStorage, ProviderStage::Validate))?;
    if entries
        .next()
        .transpose()
        .map_err(|_| error::known(ProviderErrorKind::LocalStorage, ProviderStage::Validate))?
        .is_some()
    {
        return Err(error::known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
        ));
    }
    Ok(())
}

fn verify_runtime_binary(
    options: &WindowsHyperVContainerProviderOptions,
) -> Result<File, ProviderError> {
    require_no_reparse_chain(options.runtime_executable(), false)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(options.runtime_executable())
        .map_err(|_| {
            error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
    let metadata = file.metadata().map_err(|_| {
        error::known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
        )
    })?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() == 0
        || metadata.len() > MAX_RUNTIME_BINARY_BYTES
    {
        return Err(error::known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
        ));
    }
    let mut hash = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer).map_err(|_| {
            error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                error::known(
                    ProviderErrorKind::InvalidConfiguration,
                    ProviderStage::Validate,
                )
            })?;
        if copied > MAX_RUNTIME_BINARY_BYTES {
            return Err(error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            ));
        }
        hash.update(&buffer[..read]);
    }
    let actual = Sha256Digest::from_bytes(hash.finalize().into());
    if copied != metadata.len() || actual != options.runtime_sha256() {
        return Err(error::known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
        ));
    }
    Ok(file)
}

fn require_no_reparse_chain(path: &Path, leaf_is_directory: bool) -> Result<(), ProviderError> {
    for (index, candidate) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(candidate).map_err(|_| {
            error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || if index == 0 {
                leaf_is_directory && !metadata.is_dir() || !leaf_is_directory && !metadata.is_file()
            } else {
                !metadata.is_dir()
            }
        {
            return Err(error::known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            ));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct ImageInspection {
    #[serde(rename = "RepoDigests", default)]
    repo_digests: Vec<String>,
    #[serde(rename = "Os")]
    operating_system: String,
    #[serde(rename = "Architecture")]
    architecture: String,
    #[serde(rename = "Config")]
    config: ImageConfig,
}

#[derive(Deserialize)]
struct ImageConfig {
    #[serde(rename = "Volumes")]
    volumes: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Deserialize)]
pub(crate) struct ContainerInspection {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "State")]
    state: ContainerState,
    #[serde(rename = "Config")]
    config: ContainerConfig,
    #[serde(rename = "HostConfig")]
    host_config: HostConfig,
    #[serde(rename = "Mounts", default)]
    mounts: Vec<serde_json::Value>,
    #[serde(rename = "NetworkSettings")]
    network_settings: NetworkSettings,
}

impl ContainerInspection {
    fn label(&self, name: &str) -> Option<&str> {
        self.config.labels.get(name).map(String::as_str)
    }

    fn profile(&self) -> Result<EnvironmentProfile, ProviderError> {
        let id = self
            .label(PROFILE_LABEL)
            .and_then(|value| EnvironmentProfileId::new(value.to_owned()).ok());
        let digest = self
            .label(PROFILE_DIGEST_LABEL)
            .and_then(|value| Sha256Digest::from_str(value).ok());
        match (id, digest) {
            (Some(id), Some(digest)) => Ok(EnvironmentProfile::new(id, digest)),
            _ => Err(error::known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
            )),
        }
    }

    fn custody(&self) -> Result<SandboxCustody, ProviderError> {
        let runner_id = self
            .label(CUSTODY_RUNNER_LABEL)
            .and_then(|value| RunnerId::from_str(value).ok())
            .ok_or_else(ownership_mismatch)?;
        let slot = self
            .label(CUSTODY_SLOT_LABEL)
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(ownership_mismatch)?;
        match self.label(CUSTODY_KIND_LABEL) {
            Some("profile-admission") if slot == 0 => {
                Ok(SandboxCustody::ProfileAdmission { runner_id })
            }
            Some("job") => NonZeroU16::new(slot)
                .map(|slot_ordinal| SandboxCustody::Job {
                    runner_id,
                    slot_ordinal,
                })
                .ok_or_else(ownership_mismatch),
            _ => Err(ownership_mismatch()),
        }
    }

    fn sandbox_state(&self) -> SandboxState {
        match self.state.status.as_str() {
            "created" => SandboxState::Created,
            "running" if self.state.running => SandboxState::Running,
            "exited" | "dead" if !self.state.running => SandboxState::Stopped,
            _ => SandboxState::Degraded,
        }
    }

    fn process_limit(&self) -> Result<u32, ProviderError> {
        self.label(PROCESS_LIMIT_LABEL)
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| (1..=MAX_PROCESS_LIMIT).contains(value))
            .ok_or_else(|| {
                error::known(
                    ProviderErrorKind::OwnershipMismatch,
                    ProviderStage::VerifyOwnership,
                )
            })
    }
}

fn ownership_mismatch() -> ProviderError {
    error::known(
        ProviderErrorKind::OwnershipMismatch,
        ProviderStage::VerifyOwnership,
    )
}

#[derive(Deserialize)]
struct ContainerState {
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Running")]
    running: bool,
}

#[derive(Deserialize)]
struct ContainerConfig {
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "Labels", default)]
    labels: BTreeMap<String, String>,
    #[serde(rename = "User")]
    user: String,
    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd")]
    command: Option<Vec<String>>,
    #[serde(rename = "Volumes")]
    volumes: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(rename = "WorkingDir")]
    working_directory: String,
    #[serde(rename = "AttachStdin", default)]
    attach_stdin: DockerFlag,
    #[serde(rename = "OpenStdin", default)]
    open_stdin: DockerFlag,
    #[serde(rename = "StdinOnce", default)]
    stdin_once: DockerFlag,
    #[serde(rename = "Tty", default)]
    tty: DockerFlag,
    #[serde(rename = "Healthcheck")]
    healthcheck: Option<Healthcheck>,
}

#[derive(Deserialize)]
struct Healthcheck {
    #[serde(rename = "Test", default)]
    test: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(transparent)]
struct DockerFlag(bool);

#[derive(Deserialize)]
struct HostConfig {
    #[serde(rename = "Isolation")]
    isolation: String,
    #[serde(rename = "NetworkMode")]
    network_mode: String,
    #[serde(rename = "Privileged", default)]
    privileged: DockerFlag,
    #[serde(rename = "ReadonlyRootfs", default)]
    readonly_rootfs: DockerFlag,
    #[serde(rename = "Binds")]
    binds: Option<Vec<String>>,
    #[serde(rename = "VolumesFrom")]
    volumes_from: Option<Vec<String>>,
    #[serde(rename = "Tmpfs")]
    tmpfs: Option<BTreeMap<String, String>>,
    #[serde(rename = "Mounts")]
    mounts: Option<Vec<serde_json::Value>>,
    #[serde(rename = "Devices")]
    devices: Option<Vec<serde_json::Value>>,
    #[serde(rename = "DeviceRequests")]
    device_requests: Option<Vec<serde_json::Value>>,
    #[serde(rename = "SecurityOpt")]
    security_opt: Option<Vec<String>>,
    #[serde(rename = "AutoRemove", default)]
    auto_remove: DockerFlag,
    #[serde(rename = "RestartPolicy")]
    restart_policy: RestartPolicy,
    #[serde(rename = "LogConfig")]
    log_config: LogConfig,
    #[serde(rename = "PortBindings")]
    port_bindings: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(rename = "PublishAllPorts", default)]
    publish_all_ports: DockerFlag,
    #[serde(rename = "Memory")]
    memory: u64,
    #[serde(rename = "NanoCpus")]
    nano_cpus: i64,
}

#[derive(Deserialize)]
struct RestartPolicy {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "MaximumRetryCount", default)]
    maximum_retry_count: i64,
}

#[derive(Deserialize)]
struct LogConfig {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Config", default)]
    config: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct NetworkSettings {
    #[serde(rename = "Networks", default)]
    networks: BTreeMap<String, NetworkAttachment>,
    #[serde(rename = "Ports")]
    ports: Option<BTreeMap<String, serde_json::Value>>,
}

impl NetworkSettings {
    fn has_no_connectivity(&self) -> bool {
        self.ports.as_ref().is_none_or(BTreeMap::is_empty)
            && self.networks.iter().all(|(name, network)| {
                name.eq_ignore_ascii_case("none") && network.has_no_address()
            })
    }
}

#[derive(Deserialize)]
struct NetworkAttachment {
    #[serde(rename = "Gateway", default)]
    gateway: String,
    #[serde(rename = "IPAddress", default)]
    ip_address: String,
    #[serde(rename = "IPv6Gateway", default)]
    ipv6_gateway: String,
    #[serde(rename = "GlobalIPv6Address", default)]
    global_ipv6_address: String,
    #[serde(rename = "MacAddress", default)]
    mac_address: String,
}

impl NetworkAttachment {
    fn has_no_address(&self) -> bool {
        self.gateway.is_empty()
            && self.ip_address.is_empty()
            && self.ipv6_gateway.is_empty()
            && self.global_ipv6_address.is_empty()
            && self.mac_address.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        env, fs,
        num::{NonZeroU16, NonZeroU64},
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use super::*;
    use automata_ci_execution::{
        AttemptId, ExecutionArgv, ExecutionEnvironment, ImmutableImage, JobId, JobIrVersion,
        JobResourceAllocation, LeaseGuard, LeaseId, NetworkPolicy, ResourceCapacity,
        ResourceLimits, RunId, RunnerId, RunnerSessionId, SandboxAuthorization,
        SandboxAuthorizationName, SandboxAuthorizations, SandboxEnvironment,
        SandboxExecutionBinding, SandboxGeneration, SandboxPrivilegePolicy,
    };
    use serde_json::{Value, json};

    const TEST_WINDOWS_AUTHORIZATION_NAME: &str = "windows-hyperv";
    const TEST_WINDOWS_AUTHORIZATION_SCHEMA: u16 = 4;

    #[derive(Debug)]
    struct ScriptedExecutor {
        outputs: Mutex<VecDeque<RuntimeCommandOutput>>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl ScriptedExecutor {
        fn new(outputs: impl IntoIterator<Item = RuntimeCommandOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn assert_drained(&self) {
            assert!(self.outputs.lock().expect("outputs lock").is_empty());
        }
    }

    impl RuntimeCommandExecutor for ScriptedExecutor {
        fn execute(
            &self,
            request: &RuntimeCommandRequest,
            _cancellation: &dyn Cancellation,
        ) -> RuntimeCommandOutput {
            self.calls.lock().expect("calls lock").push(
                request
                    .arguments()
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect(),
            );
            self.outputs
                .lock()
                .expect("outputs lock")
                .pop_front()
                .expect("one scripted output per runtime call")
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ConsumedAuthorization {
        authorization: SandboxAuthorization,
        operation_id: OperationId,
        custody: SandboxCustody,
        execution_binding: SandboxExecutionBinding,
        environment_profile: EnvironmentProfile,
        generation: SandboxGeneration,
        resource_allocation: JobResourceAllocation,
        pids_limit: u32,
        network_disabled: bool,
    }

    #[derive(Debug)]
    struct RecordingAuthorizationConsumer {
        runtime: Arc<ScriptedExecutor>,
        calls: Mutex<Vec<ConsumedAuthorization>>,
    }

    impl RecordingAuthorizationConsumer {
        fn new(runtime: Arc<ScriptedExecutor>) -> Self {
            Self {
                runtime,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<ConsumedAuthorization> {
            self.calls.lock().expect("consumer calls lock").clone()
        }
    }

    impl WindowsHyperVSandboxAuthorizationConsumer for RecordingAuthorizationConsumer {
        fn consume(
            &self,
            authorization: &SandboxAuthorization,
            request: WindowsHyperVSandboxAuthorizationRequest<'_>,
        ) -> Result<(), ProviderError> {
            assert_eq!(
                self.runtime.calls.lock().expect("runtime calls lock").len(),
                1,
                "authorization must be consumed before any create-path runtime call"
            );
            self.calls
                .lock()
                .expect("consumer calls lock")
                .push(ConsumedAuthorization {
                    authorization: authorization.clone(),
                    operation_id: request.operation_id(),
                    custody: request.custody(),
                    execution_binding: request.execution_binding(),
                    environment_profile: request.environment_profile().clone(),
                    generation: request.generation(),
                    resource_allocation: request.resource_allocation(),
                    pids_limit: request.pids_limit(),
                    network_disabled: request.network_disabled(),
                });
            if authorization.name().as_str() != TEST_WINDOWS_AUTHORIZATION_NAME
                || authorization.payload_schema_version() != TEST_WINDOWS_AUTHORIZATION_SCHEMA
                || authorization.payload() != b"valid-grant"
            {
                return Err(error::known(
                    ProviderErrorKind::InvalidConfiguration,
                    ProviderStage::Validate,
                ));
            }
            Ok(())
        }
    }

    #[derive(Debug)]
    struct LedgerAuthorizationConsumer {
        runtime: Arc<ScriptedExecutor>,
        retained: Mutex<Option<ConsumedAuthorization>>,
        calls: Mutex<Vec<ConsumedAuthorization>>,
    }

    impl LedgerAuthorizationConsumer {
        fn new(runtime: Arc<ScriptedExecutor>) -> Self {
            Self {
                runtime,
                retained: Mutex::new(None),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<ConsumedAuthorization> {
            self.calls.lock().expect("consumer calls lock").clone()
        }
    }

    impl WindowsHyperVSandboxAuthorizationConsumer for LedgerAuthorizationConsumer {
        fn consume(
            &self,
            authorization: &SandboxAuthorization,
            request: WindowsHyperVSandboxAuthorizationRequest<'_>,
        ) -> Result<(), ProviderError> {
            assert!(
                !self
                    .runtime
                    .calls
                    .lock()
                    .expect("runtime calls lock")
                    .is_empty(),
                "provider must complete startup before authorization consumption"
            );
            let consumed = ConsumedAuthorization {
                authorization: authorization.clone(),
                operation_id: request.operation_id(),
                custody: request.custody(),
                execution_binding: request.execution_binding(),
                environment_profile: request.environment_profile().clone(),
                generation: request.generation(),
                resource_allocation: request.resource_allocation(),
                pids_limit: request.pids_limit(),
                network_disabled: request.network_disabled(),
            };
            self.calls
                .lock()
                .expect("consumer calls lock")
                .push(consumed.clone());
            let mut retained = self.retained.lock().expect("authorization ledger lock");
            match retained.as_ref() {
                None => {
                    *retained = Some(consumed);
                    Ok(())
                }
                Some(existing) if existing == &consumed => Ok(()),
                Some(_) => Err(error::known(
                    ProviderErrorKind::Conflict,
                    ProviderStage::Validate,
                )),
            }
        }
    }

    fn immutable_image() -> ImmutableImage {
        ImmutableImage::new(format!(
            "mcr.microsoft.com/windows/servercore@sha256:{}",
            "11".repeat(32)
        ))
        .expect("immutable image")
    }

    fn hyperv_spec() -> SandboxSpec {
        hyperv_spec_with_keepalive(vec!["keepalive".to_owned()])
    }

    fn hyperv_spec_with_keepalive(arguments: Vec<String>) -> SandboxSpec {
        hyperv_spec_with_custody(
            arguments,
            SandboxCustody::ProfileAdmission {
                runner_id: RunnerId::new(),
            },
        )
    }

    fn hyperv_spec_with_custody(arguments: Vec<String>, custody: SandboxCustody) -> SandboxSpec {
        let workspace = TargetPath::windows(r"C:\__w").expect("workspace");
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("example.com/windows-hyperv").expect("profile id"),
            Sha256Digest::from_bytes([7; 32]),
        );
        let keepalive = ExecutionArgv::new(
            TargetPath::windows(r"C:\automata\guest\automata-ci-sandbox-guest.exe")
                .expect("guest path"),
            arguments,
        )
        .expect("keepalive");
        let environment = SandboxEnvironment::windows_hyperv_container(
            profile,
            immutable_image(),
            keepalive,
            workspace.clone(),
            ExecutionEnvironment::empty(),
        )
        .expect("environment");
        SandboxSpec::new(
            OperationId::new(),
            SandboxGeneration::new(3).expect("generation"),
            custody,
            environment,
            workspace,
            NetworkPolicy::Disabled,
            RootFilesystemPolicy::Writable,
            ResourceLimits::new(2 * 1024 * 1024 * 1024, 2_500, 384).expect("limits"),
        )
    }

    fn sandbox_authorizations(
        name: &str,
        payload_schema_version: u16,
        payload: &[u8],
    ) -> SandboxAuthorizations {
        SandboxAuthorizations::new(vec![
            SandboxAuthorization::new(
                SandboxAuthorizationName::new(name).expect("authorization name"),
                payload_schema_version,
                payload.to_vec(),
            )
            .expect("authorization"),
        ])
        .expect("authorization set")
    }

    fn job_hyperv_spec(authorizations: SandboxAuthorizations) -> SandboxSpec {
        job_hyperv_spec_without_execution_binding(authorizations)
            .with_execution_binding(test_execution_binding())
    }

    fn job_hyperv_spec_without_execution_binding(
        authorizations: SandboxAuthorizations,
    ) -> SandboxSpec {
        let resources = ResourceCapacity::new(2_500, 2 * 1024 * 1024 * 1024, 0, 0);
        hyperv_spec_with_custody(
            vec!["keepalive".to_owned()],
            SandboxCustody::Job {
                runner_id: RunnerId::new(),
                slot_ordinal: NonZeroU16::new(1).expect("non-zero slot"),
            },
        )
        .with_resource_allocation(
            JobResourceAllocation::new(resources, resources).expect("resource allocation"),
        )
        .with_sandbox_authorizations(authorizations)
    }

    fn test_execution_binding() -> SandboxExecutionBinding {
        SandboxExecutionBinding::new(
            RunnerSessionId::new(),
            RunId::new(),
            JobId::new(),
            AttemptId::new(),
            LeaseGuard::new(
                LeaseId::new(),
                automata_ci_execution::FencingToken::new(3).expect("fencing token"),
            ),
            OperationId::new(),
            NonZeroU64::new(1).expect("offer sequence"),
            JobIrVersion::current(),
            Sha256Digest::from_bytes([0x5a; 32]),
        )
    }

    fn clone_job_spec_with_operation_id(
        spec: &SandboxSpec,
        operation_id: OperationId,
    ) -> SandboxSpec {
        let mut cloned = SandboxSpec::new(
            operation_id,
            spec.generation(),
            spec.custody(),
            spec.profile().clone(),
            spec.workspace().clone(),
            spec.network(),
            spec.root_filesystem(),
            spec.resources(),
        )
        .with_privilege(spec.privilege())
        .with_services(spec.services().clone())
        .with_runtime_service_routes(spec.runtime_service_routes().clone())
        .with_sandbox_authorizations(spec.sandbox_authorizations().clone())
        .with_execution_binding(spec.execution_binding().expect("execution binding"));
        if let Some(scratch) = spec.scratch() {
            cloned = cloned.with_scratch(scratch.clone());
        }
        if let Some(allocation) = spec.resource_allocation() {
            cloned = cloned.with_resource_allocation(allocation);
        }
        cloned
    }

    fn assert_no_durable_create(root: &TestRoot) {
        let (journal, snapshot) =
            LifecycleJournal::open(&root.path).expect("reopen lifecycle journal");
        assert!(snapshot.creates.is_empty());
        assert!(snapshot.entries.is_empty());
        drop(journal);
    }

    #[test]
    fn job_custody_without_consumer_or_exact_authorization_fails_before_provider_work() {
        for (label, authorizations, expected_consumer_calls) in [
            ("missing", SandboxAuthorizations::empty(), 0),
            (
                "wrong-name",
                sandbox_authorizations(
                    "another-provider",
                    TEST_WINDOWS_AUTHORIZATION_SCHEMA,
                    b"valid-grant",
                ),
                1,
            ),
            (
                "wrong-schema",
                sandbox_authorizations(
                    TEST_WINDOWS_AUTHORIZATION_NAME,
                    TEST_WINDOWS_AUTHORIZATION_SCHEMA - 1,
                    b"valid-grant",
                ),
                1,
            ),
        ] {
            let root = TestRoot::new(&format!("authorization-{label}"));
            let runtime = Arc::new(ScriptedExecutor::new([RuntimeCommandOutput::success(
                Vec::new(),
            )]));
            let consumer = Arc::new(RecordingAuthorizationConsumer::new(runtime.clone()));
            let provider =
                WindowsHyperVContainerProvider::open_with_executor_and_authorization_consumer(
                    root.options(),
                    runtime.clone(),
                    consumer.clone(),
                )
                .expect("open provider");
            let error = provider
                .create(&job_hyperv_spec(authorizations), &NeverCancelled)
                .expect_err("invalid job authorization must fail closed");
            assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
            assert_eq!(error.stage(), ProviderStage::Validate);
            assert_eq!(consumer.calls().len(), expected_consumer_calls);
            runtime.assert_drained();
            assert_eq!(runtime.calls.lock().expect("runtime calls lock").len(), 1);
            drop(provider);
            assert_no_durable_create(&root);
        }

        let root = TestRoot::new("authorization-no-consumer");
        let runtime = Arc::new(ScriptedExecutor::new([RuntimeCommandOutput::success(
            Vec::new(),
        )]));
        let provider =
            WindowsHyperVContainerProvider::open_with_executor(root.options(), runtime.clone())
                .expect("open provider");
        let spec = job_hyperv_spec(sandbox_authorizations(
            TEST_WINDOWS_AUTHORIZATION_NAME,
            TEST_WINDOWS_AUTHORIZATION_SCHEMA,
            b"valid-grant",
        ));
        assert_eq!(
            provider
                .create(&spec, &NeverCancelled)
                .expect_err("direct job provider must fail closed")
                .kind(),
            ProviderErrorKind::InvalidConfiguration
        );
        runtime.assert_drained();
        assert_eq!(runtime.calls.lock().expect("runtime calls lock").len(), 1);
        drop(provider);
        assert_no_durable_create(&root);

        let root = TestRoot::new("authorization-missing-execution-binding");
        let runtime = Arc::new(ScriptedExecutor::new([RuntimeCommandOutput::success(
            Vec::new(),
        )]));
        let consumer = Arc::new(RecordingAuthorizationConsumer::new(runtime.clone()));
        let provider =
            WindowsHyperVContainerProvider::open_with_executor_and_authorization_consumer(
                root.options(),
                runtime.clone(),
                consumer.clone(),
            )
            .expect("open provider");
        let spec = job_hyperv_spec_without_execution_binding(sandbox_authorizations(
            TEST_WINDOWS_AUTHORIZATION_NAME,
            TEST_WINDOWS_AUTHORIZATION_SCHEMA,
            b"valid-grant",
        ));
        let error = provider
            .create(&spec, &NeverCancelled)
            .expect_err("job custody requires an exact execution binding");
        assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
        assert_eq!(error.stage(), ProviderStage::Validate);
        assert!(consumer.calls().is_empty());
        runtime.assert_drained();
        assert_eq!(runtime.calls.lock().expect("runtime calls lock").len(), 1);
        drop(provider);
        assert_no_durable_create(&root);
    }

    #[test]
    fn consumer_receives_exact_stable_request_and_rejects_malformed_payload_before_provider_work() {
        let root = TestRoot::new("authorization-malformed");
        let runtime = Arc::new(ScriptedExecutor::new([RuntimeCommandOutput::success(
            Vec::new(),
        )]));
        let consumer = Arc::new(RecordingAuthorizationConsumer::new(runtime.clone()));
        let provider =
            WindowsHyperVContainerProvider::open_with_executor_and_authorization_consumer(
                root.options(),
                runtime.clone(),
                consumer.clone(),
            )
            .expect("open provider");
        let spec = job_hyperv_spec(sandbox_authorizations(
            TEST_WINDOWS_AUTHORIZATION_NAME,
            TEST_WINDOWS_AUTHORIZATION_SCHEMA,
            b"malformed-protobuf",
        ));
        let error = provider
            .create(&spec, &NeverCancelled)
            .expect_err("malformed broker payload must fail closed");
        assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
        assert_eq!(error.stage(), ProviderStage::Validate);
        let calls = consumer.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].authorization,
            spec.sandbox_authorizations().as_slice()[0]
        );
        assert_eq!(calls[0].operation_id, spec.operation_id());
        assert_eq!(calls[0].custody, spec.custody());
        assert_eq!(
            calls[0].execution_binding,
            spec.execution_binding().expect("execution binding")
        );
        assert_eq!(calls[0].environment_profile, *spec.profile().attestation());
        assert_eq!(calls[0].generation, spec.generation());
        assert_eq!(
            calls[0].resource_allocation,
            spec.resource_allocation().expect("allocation")
        );
        assert_eq!(calls[0].pids_limit, spec.resources().pids());
        assert!(calls[0].network_disabled);
        runtime.assert_drained();
        assert_eq!(runtime.calls.lock().expect("runtime calls lock").len(), 1);
        drop(provider);
        assert_no_durable_create(&root);
    }

    #[test]
    fn accepted_authorization_is_consumed_before_the_first_create_path_runtime_call() {
        let root = TestRoot::new("authorization-accepted");
        let runtime = Arc::new(ScriptedExecutor::new([
            RuntimeCommandOutput::success(Vec::new()),
            RuntimeCommandOutput::failure(1, b"runtime unavailable".to_vec()),
        ]));
        let consumer = Arc::new(RecordingAuthorizationConsumer::new(runtime.clone()));
        let provider =
            WindowsHyperVContainerProvider::open_with_executor_and_authorization_consumer(
                root.options(),
                runtime.clone(),
                consumer.clone(),
            )
            .expect("open provider");
        let spec = job_hyperv_spec(sandbox_authorizations(
            TEST_WINDOWS_AUTHORIZATION_NAME,
            TEST_WINDOWS_AUTHORIZATION_SCHEMA,
            b"valid-grant",
        ));
        let error = provider
            .create(&spec, &NeverCancelled)
            .expect_err("scripted runtime failure stops before create mutation");
        assert_eq!(error.kind(), ProviderErrorKind::BackendRejected);
        assert_eq!(error.stage(), ProviderStage::Inspect);
        assert_eq!(consumer.calls().len(), 1);
        runtime.assert_drained();
        assert_eq!(runtime.calls.lock().expect("runtime calls lock").len(), 2);
        drop(provider);
        assert_no_durable_create(&root);
    }

    #[test]
    fn authorization_ledger_replays_exact_consumption_and_rejects_attempt_substitution() {
        let root = TestRoot::new("authorization-ledger");
        let runtime = Arc::new(ScriptedExecutor::new([
            RuntimeCommandOutput::success(Vec::new()),
            RuntimeCommandOutput::failure(1, b"runtime unavailable".to_vec()),
            RuntimeCommandOutput::failure(1, b"runtime unavailable".to_vec()),
        ]));
        let consumer = Arc::new(LedgerAuthorizationConsumer::new(runtime.clone()));
        let provider =
            WindowsHyperVContainerProvider::open_with_executor_and_authorization_consumer(
                root.options(),
                runtime.clone(),
                consumer.clone(),
            )
            .expect("open provider");
        let spec = job_hyperv_spec(sandbox_authorizations(
            TEST_WINDOWS_AUTHORIZATION_NAME,
            TEST_WINDOWS_AUTHORIZATION_SCHEMA,
            b"valid-grant",
        ));

        for _ in 0..2 {
            let error = provider
                .create(&spec, &NeverCancelled)
                .expect_err("scripted failure occurs after authorization consumption");
            assert_eq!(error.kind(), ProviderErrorKind::BackendRejected);
            assert_eq!(error.stage(), ProviderStage::Inspect);
        }
        assert_eq!(consumer.calls().len(), 2);
        assert_eq!(runtime.calls.lock().expect("runtime calls lock").len(), 3);

        let substituted = spec
            .clone()
            .with_execution_binding(test_execution_binding());
        let error = provider
            .create(&substituted, &NeverCancelled)
            .expect_err("one grant cannot be first-spent for another execution binding");
        assert_eq!(error.kind(), ProviderErrorKind::Conflict);
        assert_eq!(error.stage(), ProviderStage::Validate);
        assert_eq!(consumer.calls().len(), 3);
        assert_eq!(runtime.calls.lock().expect("runtime calls lock").len(), 3);

        let substituted = clone_job_spec_with_operation_id(&spec, OperationId::new());
        let error = provider
            .create(&substituted, &NeverCancelled)
            .expect_err("one grant cannot be first-spent for another create operation");
        assert_eq!(error.kind(), ProviderErrorKind::Conflict);
        assert_eq!(error.stage(), ProviderStage::Validate);
        assert_eq!(consumer.calls().len(), 4);
        assert_eq!(runtime.calls.lock().expect("runtime calls lock").len(), 3);
        runtime.assert_drained();
        drop(provider);
        assert_no_durable_create(&root);
    }

    #[test]
    fn oversized_keepalive_is_rejected_before_durable_create_intent() {
        let root = TestRoot::new("oversized-keepalive");
        let executor = Arc::new(ScriptedExecutor::new([RuntimeCommandOutput::success(
            Vec::new(),
        )]));
        let provider =
            WindowsHyperVContainerProvider::open_with_executor(root.options(), executor.clone())
                .expect("open provider");
        let spec = hyperv_spec_with_keepalive(vec!["argument".to_owned(); 128]);
        assert_eq!(
            provider
                .create(&spec, &NeverCancelled)
                .expect_err("oversized runtime argv must fail before mutation")
                .kind(),
            ProviderErrorKind::InvalidConfiguration
        );
        executor.assert_drained();
        assert_eq!(executor.calls.lock().expect("calls lock").len(), 1);
        drop(provider);
        let (journal, snapshot) =
            LifecycleJournal::open(&root.path).expect("reopen empty lifecycle journal");
        assert!(snapshot.entries.is_empty());
        assert!(snapshot.creates.is_empty());
        drop(journal);
    }

    #[test]
    fn runtime_config_injection_is_rejected_before_every_invocation() {
        let root = TestRoot::new("runtime-config-injection");
        let executor = Arc::new(ScriptedExecutor::new([RuntimeCommandOutput::success(
            Vec::new(),
        )]));
        let provider =
            WindowsHyperVContainerProvider::open_with_executor(root.options(), executor.clone())
                .expect("open provider");
        fs::write(
            root.path.join(DOCKER_CONFIG_DIRECTORY).join("config.json"),
            b"{}",
        )
        .expect("inject runtime configuration");
        assert_eq!(
            provider
                .create(&hyperv_spec(), &NeverCancelled)
                .expect_err("a non-empty runtime configuration must fail closed")
                .kind(),
            ProviderErrorKind::InvalidConfiguration
        );
        executor.assert_drained();
        assert_eq!(executor.calls.lock().expect("calls lock").len(), 1);
    }

    #[test]
    fn host_paths_reject_namespaces_expansion_and_relative_values() {
        assert!(safe_host_path(Path::new(r"C:\automata\state"), false));
        assert!(safe_host_path(
            Path::new(r"C:\Program Files\Docker\docker.exe"),
            true
        ));
        for invalid in [
            r"relative\state",
            r"\\server\share\state",
            r"\\?\C:\state",
            r"C:\state\%JOB%",
            r"C:\state\..\escape",
            r"C:\state\CON",
            r"C:\state\nul.txt",
            r"C:\state\COM1\file",
            r"C:\state\CONOUT$",
            r"C:\state\COM¹\file",
            r"C:\state\bad?name",
        ] {
            assert!(!safe_host_path(Path::new(invalid), false), "{invalid}");
        }
    }

    #[test]
    fn cpu_renderer_is_exact_and_never_uses_locale() {
        assert_eq!(format_cpu(1), "0.001");
        assert_eq!(format_cpu(1_000), "1.000");
        assert_eq!(format_cpu(4_250), "4.250");
    }

    #[test]
    fn create_contract_selects_only_hyperv_isolation_without_host_mounts() {
        let spec = hyperv_spec();
        let names = ResourceName::for_create(spec.operation_id(), spec.generation());
        let arguments = create_arguments(&spec, &names, "fingerprint")
            .into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let joined = arguments.join(" ");

        for required in [
            "--pull never",
            "--isolation hyperv",
            "--network none",
            "--restart no",
            "--log-driver none",
            "--no-healthcheck",
            "--user ContainerUser",
            r"--workdir C:\__w",
            "--memory 2147483648",
            "--cpus 2.500",
            "io.automata.windows.process-limit=384",
            immutable_image().reference(),
        ] {
            assert!(joined.contains(required), "missing {required}: {joined}");
        }
        for forbidden in [
            "--pids-limit",
            "--mount",
            "--volume",
            "--privileged",
            "isolation process",
        ] {
            assert!(!joined.contains(forbidden), "found {forbidden}: {joined}");
        }
    }

    #[test]
    fn provider_rejects_every_non_hyperv_or_weakened_spec() {
        let spec = hyperv_spec();
        assert!(validate_spec(&spec, false).is_ok());
        assert!(
            validate_spec(
                &spec.clone().with_privilege(SandboxPrivilegePolicy::Host),
                false
            )
            .is_err()
        );
        assert!(
            validate_spec(
                &spec
                    .clone()
                    .with_root_filesystem(RootFilesystemPolicy::ReadOnly),
                false,
            )
            .is_err()
        );
        let workspace = TargetPath::posix("/workspace").expect("workspace");
        let generic_environment = SandboxEnvironment::new(
            EnvironmentProfile::new(
                EnvironmentProfileId::new("example.com/generic-container").expect("profile id"),
                Sha256Digest::from_bytes([8; 32]),
            ),
            immutable_image(),
            ExecutionArgv::new(
                TargetPath::posix("/bin/sleep").expect("program"),
                vec!["infinity".to_owned()],
            )
            .expect("keepalive"),
            workspace.clone(),
            ExecutionEnvironment::empty(),
        )
        .expect("generic environment");
        let generic = SandboxSpec::new(
            OperationId::new(),
            SandboxGeneration::new(4).expect("generation"),
            SandboxCustody::ProfileAdmission {
                runner_id: RunnerId::new(),
            },
            generic_environment,
            workspace,
            NetworkPolicy::Disabled,
            RootFilesystemPolicy::Writable,
            ResourceLimits::new(2 * 1024 * 1024 * 1024, 2_500, 384).expect("limits"),
        );
        assert_eq!(
            validate_spec(&generic, false)
                .expect_err("generic container must be rejected")
                .kind(),
            ProviderErrorKind::UnsupportedCapability
        );
    }

    #[test]
    fn effective_container_shape_rejects_every_isolation_downgrade() {
        let spec = hyperv_spec();
        let names = ResourceName::for_create(spec.operation_id(), spec.generation());
        let fingerprint = "ab".repeat(32);
        let baseline = inspection_value(&spec, &names, &fingerprint);
        let inspection: ContainerInspection =
            serde_json::from_value(baseline.clone()).expect("baseline inspection");
        validate_inspection(
            &inspection,
            &names,
            spec.profile().attestation(),
            &fingerprint,
            &spec,
        )
        .expect("exact effective contract");

        for (pointer, replacement) in [
            ("/HostConfig/Isolation", json!("process")),
            ("/HostConfig/NetworkMode", json!("nat")),
            ("/HostConfig/Privileged", json!(true)),
            ("/HostConfig/Binds", json!([r"C:\host:C:\guest"])),
            ("/HostConfig/AutoRemove", json!(true)),
            ("/HostConfig/RestartPolicy/Name", json!("always")),
            ("/HostConfig/LogConfig/Type", json!("json-file")),
            ("/HostConfig/Memory", json!(1_073_741_824_u64)),
            ("/HostConfig/NanoCpus", json!(1_000_000_000_i64)),
            ("/Config/User", json!("ContainerAdministrator")),
            ("/Config/WorkingDir", json!(r"C:\escape")),
            ("/Config/Healthcheck/Test", json!(["CMD", "whoami"])),
            ("/Mounts", json!([{"Type":"bind"}])),
            (
                "/NetworkSettings/Networks/none/IPAddress",
                json!("10.0.0.2"),
            ),
            ("/Config/Labels/io.automata.sandbox-schema", json!("1")),
            (
                "/Config/Labels/io.automata.custody-runner",
                json!(RunnerId::new().to_string()),
            ),
            ("/Config/Labels/io.automata.custody-slot", json!("1")),
        ] {
            let mut weakened = baseline.clone();
            *weakened
                .pointer_mut(pointer)
                .expect("fixture pointer must exist") = replacement;
            let inspection: ContainerInspection =
                serde_json::from_value(weakened).expect("weakened inspection parses");
            assert!(
                validate_inspection(
                    &inspection,
                    &names,
                    spec.profile().attestation(),
                    &fingerprint,
                    &spec,
                )
                .is_err(),
                "downgrade at {pointer} must fail closed"
            );
        }
    }

    #[test]
    fn durable_lifecycle_reconciles_orphans_and_replays_without_recreation() {
        let root = TestRoot::new("lifecycle");
        let options = root.options();
        let spec = hyperv_spec();
        let names = ResourceName::for_create(spec.operation_id(), spec.generation());
        let fingerprint = spec_fingerprint(&spec);
        let running = inspection_value(&spec, &names, &fingerprint);
        {
            let (mut journal, mut snapshot) =
                LifecycleJournal::open(&root.path).expect("open lifecycle WAL");
            journal
                .append_to_snapshot(
                    &mut snapshot,
                    &DurableEvent::CreateIntent {
                        create: DurableCreate {
                            operation_id: spec.operation_id(),
                            fingerprint: fingerprint.clone(),
                            handle: names.handle().opaque().to_owned(),
                            custody: spec.custody(),
                        },
                        entry: DurableEntry {
                            handle: names.handle().opaque().to_owned(),
                            generation: names.generation().get(),
                            profile: spec.profile().attestation().clone(),
                            custody: spec.custody(),
                            container: names.container(),
                            fingerprint,
                            phase: DurableEntryPhase::Intent,
                        },
                    },
                )
                .expect("persist create intent");
        }
        let executor = Arc::new(ScriptedExecutor::new([
            RuntimeCommandOutput::success(
                serde_json::to_vec(&vec![running]).expect("inspection JSON"),
            ),
            RuntimeCommandOutput::success(Vec::new()),
            RuntimeCommandOutput::failure(1, b"No such container".to_vec()),
            RuntimeCommandOutput::success(Vec::new()),
        ]));
        let provider =
            WindowsHyperVContainerProvider::open_with_executor(options, executor.clone())
                .expect("startup must remove a tracked orphan before exposure");
        let inspection = provider
            .inspect(&names.handle(), &NeverCancelled)
            .expect("reconciled tombstone remains inspectable");
        assert_eq!(inspection.state(), SandboxState::Absent);
        executor.assert_drained();
        drop(provider);

        let executor = Arc::new(ScriptedExecutor::new([RuntimeCommandOutput::success(
            Vec::new(),
        )]));
        let provider =
            WindowsHyperVContainerProvider::open_with_executor(root.options(), executor.clone())
                .expect("clean journal reopens");
        let replay = provider
            .create(&spec, &NeverCancelled)
            .expect("exact create replay returns its durable tombstone");
        assert_eq!(replay.state(), SandboxState::Absent);
        executor.assert_drained();
    }

    #[test]
    fn startup_recovery_rejects_wrong_runner_slot_and_old_resource_schema() {
        let runner_id = RunnerId::new();
        for (label, custody, pointer, replacement) in [
            (
                "schema",
                SandboxCustody::ProfileAdmission { runner_id },
                "/Config/Labels/io.automata.sandbox-schema",
                json!("1"),
            ),
            (
                "runner",
                SandboxCustody::ProfileAdmission { runner_id },
                "/Config/Labels/io.automata.custody-runner",
                json!(RunnerId::new().to_string()),
            ),
            (
                "slot",
                SandboxCustody::Job {
                    runner_id,
                    slot_ordinal: NonZeroU16::new(2).expect("non-zero slot"),
                },
                "/Config/Labels/io.automata.custody-slot",
                json!("1"),
            ),
        ] {
            let root = TestRoot::new(&format!("recovery-{label}"));
            let spec = hyperv_spec_with_custody(vec!["keepalive".to_owned()], custody);
            let names = ResourceName::for_create(spec.operation_id(), spec.generation());
            let fingerprint = spec_fingerprint(&spec);
            {
                let (mut journal, mut snapshot) =
                    LifecycleJournal::open(&root.path).expect("open lifecycle WAL");
                journal
                    .append_to_snapshot(
                        &mut snapshot,
                        &DurableEvent::CreateIntent {
                            create: DurableCreate {
                                operation_id: spec.operation_id(),
                                fingerprint: fingerprint.clone(),
                                handle: names.handle().opaque().to_owned(),
                                custody: spec.custody(),
                            },
                            entry: DurableEntry {
                                handle: names.handle().opaque().to_owned(),
                                generation: names.generation().get(),
                                profile: spec.profile().attestation().clone(),
                                custody: spec.custody(),
                                container: names.container(),
                                fingerprint: fingerprint.clone(),
                                phase: DurableEntryPhase::Intent,
                            },
                        },
                    )
                    .expect("persist current create intent");
            }
            let mut observed = inspection_value(&spec, &names, &fingerprint);
            *observed
                .pointer_mut(pointer)
                .expect("inspection mutation path") = replacement;
            let executor = Arc::new(ScriptedExecutor::new([RuntimeCommandOutput::success(
                serde_json::to_vec(&vec![observed]).expect("inspection JSON"),
            )]));

            let error = WindowsHyperVContainerProvider::open_with_executor(
                root.options(),
                executor.clone(),
            )
            .expect_err("startup recovery must bind current schema and exact custody");
            assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
            executor.assert_drained();
        }
    }

    #[test]
    fn startup_completes_the_exact_pending_destroy_operation() {
        let root = TestRoot::new("pending-destroy");
        let spec = hyperv_spec();
        let names = ResourceName::for_create(spec.operation_id(), spec.generation());
        let fingerprint = spec_fingerprint(&spec);
        let destroy_operation = OperationId::new();
        {
            let (mut journal, mut snapshot) =
                LifecycleJournal::open(&root.path).expect("open lifecycle WAL");
            let handle = names.handle().opaque().to_owned();
            journal
                .append_to_snapshot(
                    &mut snapshot,
                    &DurableEvent::CreateIntent {
                        create: DurableCreate {
                            operation_id: spec.operation_id(),
                            fingerprint: fingerprint.clone(),
                            handle: handle.clone(),
                            custody: spec.custody(),
                        },
                        entry: DurableEntry {
                            handle: handle.clone(),
                            generation: names.generation().get(),
                            profile: spec.profile().attestation().clone(),
                            custody: spec.custody(),
                            container: names.container(),
                            fingerprint: fingerprint.clone(),
                            phase: DurableEntryPhase::Intent,
                        },
                    },
                )
                .expect("persist create intent");
            journal
                .append_to_snapshot(
                    &mut snapshot,
                    &DurableEvent::CreateRunning {
                        handle: handle.clone(),
                    },
                )
                .expect("persist running state");
            journal
                .append_to_snapshot(
                    &mut snapshot,
                    &DurableEvent::DestroyIntent {
                        request: DurableDestroyRequest {
                            operation_id: destroy_operation,
                            handle,
                            generation: names.generation().get(),
                            profile: spec.profile().attestation().clone(),
                            custody: spec.custody(),
                        },
                    },
                )
                .expect("persist destroy intent");
        }
        let executor = Arc::new(ScriptedExecutor::new([
            RuntimeCommandOutput::success(
                serde_json::to_vec(&vec![inspection_value(&spec, &names, &fingerprint)])
                    .expect("inspection JSON"),
            ),
            RuntimeCommandOutput::success(Vec::new()),
            RuntimeCommandOutput::failure(1, b"No such container".to_vec()),
            RuntimeCommandOutput::success(Vec::new()),
        ]));
        let provider =
            WindowsHyperVContainerProvider::open_with_executor(root.options(), executor.clone())
                .expect("startup completes pending cleanup");
        let request = DestroySandbox::new(
            destroy_operation,
            names.handle(),
            names.generation(),
            spec.custody(),
        );
        assert_eq!(
            provider
                .destroy(&request, &NeverCancelled)
                .expect("pending destroy replays exact completion"),
            DestroyDisposition::Destroyed
        );
        executor.assert_drained();
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The ordered fake-runtime transcript is the assertion.
    fn create_destroy_and_exact_replays_are_generation_fenced_and_durable() {
        let root = TestRoot::new("create-destroy");
        let spec = hyperv_spec();
        let names = ResourceName::for_create(spec.operation_id(), spec.generation());
        let fingerprint = spec_fingerprint(&spec);
        let mut created = inspection_value(&spec, &names, &fingerprint);
        created["State"] = json!({"Status": "created", "Running": false});
        let running = inspection_value(&spec, &names, &fingerprint);
        let image = json!([{
            "RepoDigests": [spec.profile().image().expect("image").reference()],
            "Os": "windows",
            "Architecture": "amd64",
            "Config": {"Volumes": null}
        }]);
        let ready = automata_ci_sandbox_guest::encode_frame(
            &automata_ci_sandbox_guest::GuestResponse::Ready {
                protocol: automata_ci_sandbox_guest::GUEST_PROTOCOL_VERSION,
            },
        )
        .expect("ready frame");
        let executor = Arc::new(ScriptedExecutor::new([
            RuntimeCommandOutput::success(Vec::new()),
            RuntimeCommandOutput::failure(1, b"No such container".to_vec()),
            RuntimeCommandOutput::success(serde_json::to_vec(&image).expect("image JSON")),
            RuntimeCommandOutput::success(Vec::new()),
            RuntimeCommandOutput::success(
                serde_json::to_vec(&vec![created]).expect("created JSON"),
            ),
            RuntimeCommandOutput::success(Vec::new()),
            RuntimeCommandOutput::success(
                serde_json::to_vec(&vec![running.clone()]).expect("running JSON"),
            ),
            RuntimeCommandOutput::success(Vec::new()),
            RuntimeCommandOutput::success(ready),
            RuntimeCommandOutput::success(
                serde_json::to_vec(&vec![running]).expect("destroy inspection JSON"),
            ),
            RuntimeCommandOutput::success(Vec::new()),
            RuntimeCommandOutput::failure(1, b"No such container".to_vec()),
        ]));
        let provider =
            WindowsHyperVContainerProvider::open_with_executor(root.options(), executor.clone())
                .expect("open provider");
        let record = provider
            .create(&spec, &NeverCancelled)
            .expect("create exact sandbox");
        assert_eq!(record.state(), SandboxState::Running);

        let runtime_calls = executor.calls.lock().expect("calls lock").len();
        let SandboxCustody::ProfileAdmission { runner_id } = spec.custody() else {
            panic!("test spec uses profile-admission custody");
        };
        let wrong_custody = DestroySandbox::new(
            OperationId::new(),
            record.handle().clone(),
            record.generation(),
            SandboxCustody::Job {
                runner_id,
                slot_ordinal: NonZeroU16::new(1).expect("non-zero slot"),
            },
        );
        assert_eq!(
            provider
                .destroy(&wrong_custody, &NeverCancelled)
                .expect_err("wrong custody must not authorize container removal")
                .kind(),
            ProviderErrorKind::OwnershipMismatch
        );
        assert_eq!(
            executor.calls.lock().expect("calls lock").len(),
            runtime_calls,
            "custody rejection must precede every runtime mutation"
        );

        let destroy = DestroySandbox::new(
            OperationId::new(),
            record.handle().clone(),
            record.generation(),
            spec.custody(),
        );
        assert_eq!(
            provider
                .destroy(&destroy, &NeverCancelled)
                .expect("destroy sandbox"),
            DestroyDisposition::Destroyed
        );
        assert_eq!(
            provider
                .destroy(&destroy, &NeverCancelled)
                .expect("exact destroy replay"),
            DestroyDisposition::Destroyed
        );
        let already_absent = DestroySandbox::new(
            OperationId::new(),
            record.handle().clone(),
            record.generation(),
            spec.custody(),
        );
        assert_eq!(
            provider
                .destroy(&already_absent, &NeverCancelled)
                .expect("new destroy against tombstone"),
            DestroyDisposition::AlreadyAbsent
        );
        assert_eq!(
            provider
                .destroy(&already_absent, &NeverCancelled)
                .expect("exact absent replay"),
            DestroyDisposition::AlreadyAbsent
        );
        let inspection = provider
            .inspect(record.handle(), &NeverCancelled)
            .expect("inspect tombstone");
        assert_eq!(inspection.state(), SandboxState::Absent);
        assert_eq!(inspection.custody(), spec.custody());
        assert_eq!(
            provider
                .create(&spec, &NeverCancelled)
                .expect("create replay cannot recreate destroyed generation")
                .state(),
            SandboxState::Absent
        );
        executor.assert_drained();

        let calls = executor.calls.lock().expect("calls lock");
        let expected_config = root
            .path
            .join(DOCKER_CONFIG_DIRECTORY)
            .to_string_lossy()
            .into_owned();
        assert!(calls.iter().all(|call| {
            call.first().map(String::as_str) == Some("--config")
                && call.get(1).map(String::as_str) == Some(expected_config.as_str())
                && call.get(2).map(String::as_str) == Some("--host")
                && call.get(3).map(String::as_str) == Some(DOCKER_HOST)
        }));
        assert!(
            fs::read_dir(root.path.join(DOCKER_CONFIG_DIRECTORY))
                .expect("isolated Docker CLI config directory")
                .next()
                .is_none()
        );
        assert!(calls.iter().any(|call| {
            call.windows(2)
                .any(|pair| pair == ["--isolation", "hyperv"])
        }));
        assert!(calls.iter().any(|call| {
            call.iter()
                .any(|argument| argument.contains("WindowsPrincipal"))
        }));
    }

    #[test]
    fn open_fails_closed_on_untracked_owner_labels_and_wrong_runtime_pin() {
        let root = TestRoot::new("open-fencing");
        let executor = Arc::new(ScriptedExecutor::new([RuntimeCommandOutput::success(
            b"automata-windows-hyperv-untracked\r\n".to_vec(),
        )]));
        let error =
            WindowsHyperVContainerProvider::open_with_executor(root.options(), executor.clone())
                .expect_err("untracked owner-labelled resource must drain the provider");
        assert_eq!(error.kind(), ProviderErrorKind::Conflict);
        executor.assert_drained();

        let wrong = WindowsHyperVContainerProviderOptions::new(
            root.path.join("other-state"),
            &root.runtime,
            Sha256Digest::from_bytes([0; 32]),
            TargetPath::windows(r"C:\automata\guest\automata-ci-sandbox-guest.exe")
                .expect("guest path"),
        )
        .expect("syntactically valid options");
        let executor = Arc::new(ScriptedExecutor::new([]));
        let error = WindowsHyperVContainerProvider::open_with_executor(wrong, executor.clone())
            .expect_err("wrong executable digest must fail before runtime invocation");
        assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
        executor.assert_drained();
    }

    fn inspection_value(spec: &SandboxSpec, names: &ResourceName, fingerprint: &str) -> Value {
        let keepalive = spec.profile().keepalive().expect("keepalive");
        json!({
            "Name": format!("/{}", names.container()),
            "State": {"Status": "running", "Running": true},
            "Config": {
                "Image": spec.profile().image().expect("image").reference(),
                "Labels": expected_labels(spec, names, fingerprint),
                "User": "ContainerUser",
                "Entrypoint": [keepalive.program().as_str()],
                "Cmd": keepalive.arguments(),
                "Volumes": null,
                "WorkingDir": spec.workspace().as_str(),
                "AttachStdin": false,
                "OpenStdin": false,
                "StdinOnce": false,
                "Tty": false,
                "Healthcheck": {"Test": ["NONE"]}
            },
            "HostConfig": {
                "Isolation": "hyperv",
                "NetworkMode": "none",
                "Privileged": false,
                "ReadonlyRootfs": false,
                "Binds": null,
                "VolumesFrom": null,
                "Tmpfs": null,
                "Mounts": [],
                "Devices": [],
                "DeviceRequests": null,
                "SecurityOpt": null,
                "AutoRemove": false,
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "LogConfig": {"Type": "none", "Config": {}},
                "PortBindings": null,
                "PublishAllPorts": false,
                "Memory": spec.resources().memory_bytes(),
                "NanoCpus": i64::from(spec.resources().cpu_millis()) * 1_000_000
            },
            "Mounts": [],
            "NetworkSettings": {
                "Networks": {
                    "none": {
                        "Gateway": "",
                        "IPAddress": "",
                        "IPv6Gateway": "",
                        "GlobalIPv6Address": "",
                        "MacAddress": ""
                    }
                },
                "Ports": null
            }
        })
    }

    struct TestRoot {
        path: PathBuf,
        runtime: PathBuf,
        runtime_digest: Sha256Digest,
    }

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = env::temp_dir().join(format!(
                "automata-ci-windows-hyperv-provider-{label}-{}",
                OperationId::new()
            ));
            fs::create_dir_all(&path).expect("create test root");
            let runtime = path.join("docker.exe");
            let bytes = b"synthetic pinned docker client";
            fs::write(&runtime, bytes).expect("write synthetic runtime");
            let runtime_digest = Sha256Digest::from_bytes(Sha256::digest(bytes).into());
            Self {
                path,
                runtime,
                runtime_digest,
            }
        }

        fn options(&self) -> WindowsHyperVContainerProviderOptions {
            WindowsHyperVContainerProviderOptions::new(
                self.path.clone(),
                self.runtime.clone(),
                self.runtime_digest,
                TargetPath::windows(r"C:\automata\guest\automata-ci-sandbox-guest.exe")
                    .expect("guest path"),
            )
            .expect("provider options")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
