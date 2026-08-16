//! Evaluation-only Docker sandbox provider behind the installation relay.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    io::{Cursor, Read as _},
    num::NonZeroU16,
    str::FromStr as _,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use automata_ci_core::Sha256Digest;
use automata_ci_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, EnvironmentProfile, EnvironmentProfileId,
    ExecutionEndpoint, ImmutableImage, NetworkPolicy, NeverCancelled, OperationId,
    OperationOutcome, ProviderCapabilities, ProviderError, ProviderErrorKind, ProviderId,
    ProviderStage, RootFilesystemPolicy, RunnerId, SandboxCapability, SandboxCustody,
    SandboxGeneration, SandboxHandle, SandboxInspection, SandboxLaunch, SandboxPrivilegePolicy,
    SandboxProvider, SandboxRecord, SandboxSpec, SandboxState, TargetPlatform,
};
use automata_ci_sandbox_guest::{
    GUEST_PROTOCOL_VERSION, GuestRequest, GuestResponse, LOCAL_CONTROL_CLIENT,
    LOCAL_CONTROL_DIRECTORY, LOCAL_CONTROL_DIRECTORY_MODE_INITIAL, LOCAL_CONTROL_GID,
    LOCAL_CONTROL_SEAL_UID, LOCAL_CONTROL_TMPFS_BYTES, LOCAL_CONTROL_UID, MAX_GUEST_FRAME_BYTES,
    MAX_LOCAL_GUEST_BINARY_BYTES, decode_frame, encode_frame,
};
use sha2::{Digest as _, Sha256};
use tar::{Builder as TarBuilder, EntryType, Header};

use crate::{
    Installation, InstallationId, LocalEngineError, LocalEngineErrorCode,
    MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS, MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES,
    MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS,
    engine::{
        ContainerDefinition, EngineApiError, EngineContainerState, EngineExecRequest,
        InspectedContainer, InspectedImage, LOCAL_DOCKER_GUEST_ARCHIVE_BYTES,
        LOCAL_DOCKER_GUEST_IMAGE_BINARY, LOCAL_DOCKER_SANDBOX_GUEST_BINARY, PinnedDockerEngine,
        SandboxEngineApi, connect_relay_sandbox_engine, verify_installation_identity,
    },
    normalize_architecture,
};

mod endpoint;

use endpoint::LocalDockerEndpoint;

#[cfg(test)]
mod tests;

/// Stable provider identifier for the evaluation-only local Docker adapter.
pub const LOCAL_DOCKER_PROVIDER_ID: &str = "local-docker-v1";

const MANAGED_LABEL_PREFIX: &str = "io.automata.local.";
const LABEL_MANAGED: &str = "io.automata.local.managed";
const LABEL_JOB_SCHEMA: &str = "io.automata.local.job-schema";
const LABEL_INSTALLATION_ID: &str = "io.automata.local.installation-id";
const LABEL_INSTALLATION_KEY: &str = "io.automata.local.installation-key";
const LABEL_COMPOSE_PROJECT: &str = "io.automata.local.compose-project";
const LABEL_RUNNER_ID: &str = "io.automata.local.runner-id";
const LABEL_CUSTODY_KIND: &str = "io.automata.local.custody-kind";
const LABEL_SLOT: &str = "io.automata.local.slot";
const LABEL_OPERATION_ID: &str = "io.automata.local.operation-id";
const LABEL_GENERATION: &str = "io.automata.local.generation";
const LABEL_PROFILE: &str = "io.automata.local.profile";
const LABEL_PROFILE_DIGEST: &str = "io.automata.local.profile-sha256";
const LABEL_SPEC_DIGEST: &str = "io.automata.local.spec-sha256";
const LABEL_RESOURCE_KIND: &str = "io.automata.local.resource-kind";
const MANAGED_VALUE: &str = "true";
const JOB_SCHEMA: &str = "1";
const CUSTODY_ADMISSION: &str = "profile-admission";
const CUSTODY_JOB: &str = "job";
const KIND_JOB: &str = "job-container";
const KIND_GUEST_SOURCE: &str = "guest-source";
const HELPER_MEMORY_BYTES: i64 = 64 * 1024 * 1024;
const HELPER_NANO_CPUS: i64 = 500_000_000;
const HELPER_PIDS: i64 = 32;
const MAX_CONTAINER_LABELS: usize = 256;
const ENGINE_TRANSPORT_OVERHEAD: Duration = Duration::from_secs(5);

fn guest_client_user() -> String {
    format!("{LOCAL_CONTROL_UID}:{LOCAL_CONTROL_GID}")
}

fn guest_seal_user() -> String {
    format!("{LOCAL_CONTROL_SEAL_UID}:{LOCAL_CONTROL_GID}")
}

fn guest_control_tmpfs_options() -> String {
    format!(
        "rw,exec,nosuid,nodev,size={LOCAL_CONTROL_TMPFS_BYTES},mode={LOCAL_CONTROL_DIRECTORY_MODE_INITIAL:04o},uid={LOCAL_CONTROL_SEAL_UID},gid={LOCAL_CONTROL_GID}"
    )
}

fn max_guest_binary_bytes() -> usize {
    usize::try_from(MAX_LOCAL_GUEST_BINARY_BYTES)
        .expect("the protected guest binary ceiling fits usize")
}

const ENDPOINT_CAPABILITIES: [SandboxCapability; 4] = [
    SandboxCapability::Exec,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::EnvironmentInjection,
];
const PROVIDER_CAPABILITIES: [SandboxCapability; 12] = [
    SandboxCapability::WholeJob,
    SandboxCapability::Attach,
    SandboxCapability::Inspect,
    SandboxCapability::Exec,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::EnvironmentInjection,
    SandboxCapability::NetworkDisabled,
    SandboxCapability::WritableRootFilesystem,
    SandboxCapability::Administrator,
    SandboxCapability::ResourceLimits,
    SandboxCapability::ProcessLimits,
];

/// Evaluation-only Docker Engine provider for sibling Linux job containers.
///
/// The provider connects only to the installation relay at
/// `/run/automata-engine/docker.sock`. It never reads `DOCKER_HOST`, pulls an
/// image, accepts a host bind, or exposes an Engine endpoint to a job.
#[derive(Clone)]
pub struct LocalDockerProvider {
    inner: Arc<LocalDockerInner>,
}

struct LocalDockerInner {
    pinned: PinnedDockerEngine,
    engine: Arc<dyn SandboxEngineApi>,
    installation: Installation,
    guest_image: ImmutableImage,
    guest_image_id: String,
    guest_image_labels: BTreeMap<String, String>,
    guest_image_environment: Vec<String>,
    provider_id: ProviderId,
    capabilities: ProviderCapabilities,
    handle_locks: Mutex<BTreeMap<String, Weak<HandleOperationLock>>>,
}

type HandleOperationLock = tokio::sync::Mutex<()>;

impl LocalDockerProvider {
    /// Connects through the fixed private relay and verifies the exact
    /// installation anchor and already-present digest-pinned guest image.
    ///
    /// # Errors
    ///
    /// Returns a redacted failure when daemon identity, installation binding,
    /// image digest, platform, labels, or declared image volumes are invalid.
    pub async fn connect(
        installation: Installation,
        guest_image: ImmutableImage,
    ) -> Result<Self, LocalEngineError> {
        let (pinned, engine) = connect_relay_sandbox_engine().await?;
        verify_installation_identity(engine.as_ref(), &installation).await?;
        let image = engine
            .inspect_image(guest_image.reference())
            .await
            .map_err(|_| LocalEngineError::new(LocalEngineErrorCode::EngineRequestFailed))?
            .ok_or_else(|| LocalEngineError::new(LocalEngineErrorCode::ImageUnavailable))?;
        verify_image(&pinned, &guest_image, &image).map_err(LocalEngineError::new)?;
        let provider_id = ProviderId::new(LOCAL_DOCKER_PROVIDER_ID)
            .map_err(|_| LocalEngineError::new(LocalEngineErrorCode::InvalidEngineResponse))?;
        let capabilities = ProviderCapabilities::new(PROVIDER_CAPABILITIES)
            .map_err(|_| LocalEngineError::new(LocalEngineErrorCode::InvalidEngineResponse))?;
        pinned.verify().await?;
        verify_installation_identity(engine.as_ref(), &installation).await?;
        Ok(Self {
            inner: Arc::new(LocalDockerInner {
                pinned,
                engine,
                installation,
                guest_image,
                guest_image_id: image.id,
                guest_image_labels: image.labels,
                guest_image_environment: neutral_environment(&image.environment_names),
                provider_id,
                capabilities,
                handle_locks: Mutex::new(BTreeMap::new()),
            }),
        })
    }

    #[cfg(test)]
    fn with_test_engine(
        pinned: PinnedDockerEngine,
        engine: Arc<dyn SandboxEngineApi>,
        installation: Installation,
        guest_image: ImmutableImage,
        guest_image_id: String,
    ) -> Self {
        Self {
            inner: Arc::new(LocalDockerInner {
                pinned,
                engine,
                installation,
                guest_image,
                guest_image_id,
                guest_image_labels: BTreeMap::new(),
                guest_image_environment: Vec::new(),
                provider_id: ProviderId::new(LOCAL_DOCKER_PROVIDER_ID).expect("provider id"),
                capabilities: ProviderCapabilities::new(PROVIDER_CAPABILITIES)
                    .expect("capabilities"),
                handle_locks: Mutex::new(BTreeMap::new()),
            }),
        }
    }
}

impl fmt::Debug for LocalDockerProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalDockerProvider")
            .field("provider_id", &self.inner.provider_id)
            .field("installation", &self.inner.installation.id())
            .field("guest_image", &self.inner.guest_image)
            .field("capabilities", &self.inner.capabilities)
            .finish_non_exhaustive()
    }
}

impl SandboxProvider for LocalDockerProvider {
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
        validate_spec(spec)?;
        let names = ResourceNames::for_spec(&self.inner.installation, spec)?;
        let handle = names.handle(&self.inner.provider_id)?;
        let operation_lock = self.inner.handle_lock(&handle)?;
        run_provider(ProviderStage::CreateSandbox, async {
            let _operation = lock_handle(operation_lock, cancellation)
                .await
                .ok_or_else(|| known(ProviderErrorKind::Cancelled, ProviderStage::CreateSandbox))?;
            self.inner.create(spec, &names, &handle, cancellation).await
        })
    }

    fn attach(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError> {
        let names =
            ResourceNames::from_handle(&self.inner.provider_id, &self.inner.installation, handle)?;
        let operation_lock = self.inner.handle_lock(handle)?;
        let attached = run_provider(ProviderStage::Attach, async {
            let _operation = lock_handle(Arc::clone(&operation_lock), cancellation)
                .await
                .ok_or_else(|| known(ProviderErrorKind::Cancelled, ProviderStage::Attach))?;
            self.inner.attach_identity(&names, cancellation).await
        })?;
        Ok(Box::new(LocalDockerEndpoint::new(
            Arc::clone(&self.inner),
            handle.clone(),
            names,
            attached,
            operation_lock,
        )))
    }

    fn inspect(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        let names =
            ResourceNames::from_handle(&self.inner.provider_id, &self.inner.installation, handle)?;
        let operation_lock = self.inner.handle_lock(handle)?;
        run_provider(ProviderStage::Inspect, async {
            let _operation = lock_handle(operation_lock, cancellation)
                .await
                .ok_or_else(|| known(ProviderErrorKind::Cancelled, ProviderStage::Inspect))?;
            self.inner.inspect(handle, &names, cancellation).await
        })
    }

    fn destroy(
        &self,
        request: &DestroySandbox,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        let names = ResourceNames::from_handle(
            &self.inner.provider_id,
            &self.inner.installation,
            request.handle(),
        )?;
        if names.generation != request.generation().get() {
            return Err(known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::Validate,
            ));
        }
        let operation_lock = self.inner.handle_lock(request.handle())?;
        run_provider(ProviderStage::DestroySandbox, async {
            let _operation = lock_handle(operation_lock, cancellation)
                .await
                .ok_or_else(|| {
                    known(ProviderErrorKind::Cancelled, ProviderStage::DestroySandbox)
                })?;
            self.inner.destroy(request, &names, cancellation).await
        })
    }
}

impl LocalDockerInner {
    async fn verify_boundary(&self, stage: ProviderStage) -> Result<(), ProviderError> {
        self.verify_boundary_kind()
            .await
            .map_err(|kind| known(kind, stage))
    }

    pub(super) async fn verify_boundary_kind(&self) -> Result<(), ProviderErrorKind> {
        self.pinned
            .verify()
            .await
            .map_err(|_| ProviderErrorKind::AdapterUnavailable)?;
        verify_installation_identity(self.engine.as_ref(), &self.installation)
            .await
            .map_err(|_| ProviderErrorKind::OwnershipMismatch)
    }

    fn handle_lock(
        &self,
        handle: &SandboxHandle,
    ) -> Result<Arc<HandleOperationLock>, ProviderError> {
        let mut locks = self
            .handle_locks
            .lock()
            .map_err(|_| known(ProviderErrorKind::LocalStorage, ProviderStage::Validate))?;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(handle.opaque()).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        let lock = Arc::new(HandleOperationLock::new(()));
        locks.insert(handle.opaque().to_owned(), Arc::downgrade(&lock));
        Ok(lock)
    }

    #[allow(clippy::too_many_lines)]
    async fn create(
        &self,
        spec: &SandboxSpec,
        names: &ResourceNames,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::Validate)?;
        self.verify_boundary(ProviderStage::Validate).await?;
        let SandboxLaunch::Container { image, .. } = spec.profile().launch() else {
            return Err(invalid_configuration());
        };
        let job_image = self
            .verified_image(image)
            .await
            .map_err(|kind| known(kind, ProviderStage::Validate))?;
        let guest_image = self
            .verified_image(&self.guest_image)
            .await
            .map_err(|kind| known(kind, ProviderStage::Validate))?;
        if guest_image.id != self.guest_image_id
            || guest_image.labels != self.guest_image_labels
            || neutral_environment(&guest_image.environment_names) != self.guest_image_environment
        {
            return Err(known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::Validate,
            ));
        }

        let fingerprint = spec_fingerprint(spec, &self.installation, &self.guest_image)?;
        let base_labels = base_labels(spec, &self.installation, &fingerprint);
        let job_definition = job_definition(
            names,
            spec,
            image.reference(),
            &job_image.labels,
            &job_image.environment_names,
            &base_labels,
        )?;
        let helper_definition = helper_definition(
            names,
            self.guest_image.reference(),
            &self.guest_image_labels,
            &self.guest_image_environment,
            &base_labels,
        );
        if job_definition.labels.len() > MAX_CONTAINER_LABELS
            || helper_definition.labels.len() > MAX_CONTAINER_LABELS
        {
            return Err(invalid_configuration());
        }

        let existing_job = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::CreateSandbox, None))?;
        let existing_helper = self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::CreateSandbox, None))?;
        if let Some(helper) = existing_helper.as_ref() {
            verify_existing_helper(helper, &helper_definition, &guest_image.id)?;
        }

        if let Some(job) = existing_job.as_ref() {
            verify_container(job, &job_definition, &job_image.id, None)?;
            match job.state {
                EngineContainerState::Running if existing_helper.is_none() => {
                    if let Err(error) = self.probe(names, job, handle, &NeverCancelled).await {
                        self.destroy_container(
                            job,
                            &job_definition,
                            &job_image.id,
                            handle,
                            &NeverCancelled,
                        )
                        .await?;
                        return Err(error);
                    }
                    ensure_not_cancelled(cancellation, ProviderStage::CreateSandbox)?;
                    self.verify_boundary(ProviderStage::CreateSandbox)
                        .await
                        .map_err(|error| recovery(&error, handle))?;
                    self.require_exact_container(
                        job,
                        &job_definition,
                        &job_image.id,
                        EngineContainerState::Running,
                        handle,
                    )
                    .await?;
                    self.require_name_absent(&names.helper, handle).await?;
                    return Ok(record(handle, spec, SandboxState::Running));
                }
                EngineContainerState::Running
                | EngineContainerState::Exited(_)
                | EngineContainerState::Invalid => {
                    return Err(uncertain(
                        ProviderErrorKind::InvalidState,
                        ProviderStage::CreateSandbox,
                        handle,
                    ));
                }
                EngineContainerState::Created => {}
            }
        }

        let guest_bytes = self
            .prepare_guest(
                names,
                existing_helper.as_ref(),
                &helper_definition,
                &guest_image.id,
                handle,
                cancellation,
            )
            .await?;
        let sandbox_archive = sandbox_archive(spec.workspace().as_str(), &guest_bytes)?;

        let job = if let Some(job) = existing_job {
            job
        } else {
            ensure_not_cancelled(cancellation, ProviderStage::CreateContainer)?;
            self.require_name_absent(&names.job, handle).await?;
            self.verify_boundary(ProviderStage::CreateContainer).await?;
            let _untrusted_create = self.engine.create_container(job_definition.clone()).await;
            let job = self
                .require_container(
                    &names.job,
                    &job_definition,
                    &job_image.id,
                    EngineContainerState::Created,
                    handle,
                )
                .await?;
            ensure_not_cancelled_after_mutation(
                cancellation,
                ProviderStage::CreateContainer,
                handle,
            )?;
            job
        };

        let job = self
            .require_exact_container(
                &job,
                &job_definition,
                &job_image.id,
                EngineContainerState::Created,
                handle,
            )
            .await?;
        self.verify_boundary(ProviderStage::CreateContainer)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let _untrusted_upload = self
            .engine
            .upload_sandbox_archive(&job.id, &sandbox_archive)
            .await;
        let job = self
            .require_exact_container(
                &job,
                &job_definition,
                &job_image.id,
                EngineContainerState::Created,
                handle,
            )
            .await?;
        let realized_archive = self
            .engine
            .download_sandbox_guest(&job.id, LOCAL_DOCKER_GUEST_ARCHIVE_BYTES)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
            })?;
        let realized_guest =
            extract_single_guest(&realized_archive).map_err(|error| recovery(&error, handle))?;
        if realized_guest != guest_bytes {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
                handle,
            ));
        }
        ensure_not_cancelled_after_mutation(cancellation, ProviderStage::CreateContainer, handle)?;

        let job = self
            .require_exact_container(
                &job,
                &job_definition,
                &job_image.id,
                EngineContainerState::Created,
                handle,
            )
            .await?;
        self.verify_boundary(ProviderStage::Start)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let _untrusted_start = self.engine.start_container(&job.id).await;
        let running = self
            .require_exact_container(
                &job,
                &job_definition,
                &job_image.id,
                EngineContainerState::Running,
                handle,
            )
            .await?;
        if let Err(error) = self.bootstrap_client(names, &running, handle).await {
            self.destroy_container(
                &running,
                &job_definition,
                &job_image.id,
                handle,
                &NeverCancelled,
            )
            .await?;
            return Err(error);
        }
        if let Err(error) = self.probe(names, &running, handle, &NeverCancelled).await {
            self.destroy_container(
                &running,
                &job_definition,
                &job_image.id,
                handle,
                &NeverCancelled,
            )
            .await?;
            return Err(error);
        }
        if let Err(error) =
            ensure_not_cancelled_after_mutation(cancellation, ProviderStage::Start, handle)
        {
            self.destroy_container(
                &running,
                &job_definition,
                &job_image.id,
                handle,
                &NeverCancelled,
            )
            .await?;
            return Err(error);
        }
        self.verify_boundary(ProviderStage::CreateSandbox)
            .await
            .map_err(|error| recovery(&error, handle))?;
        self.require_exact_container(
            &running,
            &job_definition,
            &job_image.id,
            EngineContainerState::Running,
            handle,
        )
        .await?;
        self.require_name_absent(&names.helper, handle).await?;
        Ok(record(handle, spec, SandboxState::Running))
    }

    async fn verified_image(
        &self,
        image: &ImmutableImage,
    ) -> Result<InspectedImage, ProviderErrorKind> {
        let inspected = self
            .engine
            .inspect_image(image.reference())
            .await
            .map_err(map_engine_kind)?
            .ok_or(ProviderErrorKind::NotFound)?;
        verify_image(&self.pinned, image, &inspected)
            .map_err(|_| ProviderErrorKind::OwnershipMismatch)?;
        Ok(inspected)
    }

    async fn require_name_absent(
        &self,
        name: &str,
        handle: &SandboxHandle,
    ) -> Result<(), ProviderError> {
        if self
            .engine
            .inspect_container(name)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
            })?
            .is_some()
        {
            return Err(uncertain(
                ProviderErrorKind::Conflict,
                ProviderStage::VerifyOwnership,
                handle,
            ));
        }
        Ok(())
    }

    async fn require_container(
        &self,
        name: &str,
        definition: &ContainerDefinition,
        image_id: &str,
        state: EngineContainerState,
        handle: &SandboxHandle,
    ) -> Result<InspectedContainer, ProviderError> {
        let inspected = self.engine.inspect_container(name).await.map_err(|error| {
            map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
        })?;
        let Some(inspected) = inspected else {
            return Err(uncertain(
                ProviderErrorKind::AdapterUnavailable,
                ProviderStage::VerifyOwnership,
                handle,
            ));
        };
        verify_container(&inspected, definition, image_id, Some(state))
            .map_err(|error| recovery(&error, handle))?;
        Ok(inspected)
    }

    async fn require_exact_container(
        &self,
        expected: &InspectedContainer,
        definition: &ContainerDefinition,
        image_id: &str,
        state: EngineContainerState,
        handle: &SandboxHandle,
    ) -> Result<InspectedContainer, ProviderError> {
        let current = self
            .require_container(&definition.name, definition, image_id, state, handle)
            .await?;
        if current.id != expected.id {
            return Err(uncertain(
                ProviderErrorKind::Conflict,
                ProviderStage::VerifyOwnership,
                handle,
            ));
        }
        Ok(current)
    }

    async fn prepare_guest(
        &self,
        names: &ResourceNames,
        existing: Option<&InspectedContainer>,
        definition: &ContainerDefinition,
        image_id: &str,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::CreateContainer)?;
        let helper = if let Some(helper) = existing {
            helper.clone()
        } else {
            self.require_name_absent(&names.helper, handle).await?;
            self.verify_boundary(ProviderStage::CreateContainer).await?;
            let _untrusted_create = self.engine.create_container(definition.clone()).await;
            let helper = self
                .require_container(
                    &names.helper,
                    definition,
                    image_id,
                    EngineContainerState::Created,
                    handle,
                )
                .await?;
            ensure_not_cancelled_after_mutation(
                cancellation,
                ProviderStage::CreateContainer,
                handle,
            )?;
            helper
        };

        let helper = self
            .require_exact_container(
                &helper,
                definition,
                image_id,
                EngineContainerState::Created,
                handle,
            )
            .await?;
        let archive = self
            .engine
            .download_guest_image_binary(&helper.id, LOCAL_DOCKER_GUEST_ARCHIVE_BYTES)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
            })?;
        let guest = extract_single_guest(&archive).map_err(|error| recovery(&error, handle))?;

        let helper = self
            .require_exact_container(
                &helper,
                definition,
                image_id,
                EngineContainerState::Created,
                handle,
            )
            .await?;
        self.verify_boundary(ProviderStage::DestroyContainer)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let _untrusted_remove = self.engine.remove_container(&helper.id).await;
        self.require_removed(&names.helper, &helper.id, handle)
            .await?;
        ensure_not_cancelled_after_mutation(cancellation, ProviderStage::DestroyContainer, handle)?;
        Ok(guest)
    }

    async fn require_removed(
        &self,
        name: &str,
        removed_id: &str,
        handle: &SandboxHandle,
    ) -> Result<(), ProviderError> {
        match self.engine.inspect_container(name).await.map_err(|error| {
            map_provider_engine(error, ProviderStage::DestroyContainer, Some(handle))
        })? {
            None => Ok(()),
            Some(current) if current.id != removed_id => Err(uncertain(
                ProviderErrorKind::Conflict,
                ProviderStage::DestroyContainer,
                handle,
            )),
            Some(_) => Err(uncertain(
                ProviderErrorKind::AdapterUnavailable,
                ProviderStage::DestroyContainer,
                handle,
            )),
        }
    }

    async fn probe(
        &self,
        names: &ResourceNames,
        container: &InspectedContainer,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::Start)?;
        let guest_request = GuestRequest::Probe {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: format!("{}:provider-probe", handle.opaque()),
        };
        let request = EngineExecRequest {
            container_id: container.id.clone(),
            command: vec![LOCAL_CONTROL_CLIENT.to_owned(), "local-client".to_owned()],
            user: guest_client_user(),
            stdin: encode_frame(&guest_request).map_err(|_| invalid_configuration())?,
            stdout_limit: MAX_GUEST_FRAME_BYTES + 4,
            stderr_limit: 1_024,
            timeout: ENGINE_TRANSPORT_OVERHEAD,
        };
        self.verify_boundary(ProviderStage::Start)
            .await
            .map_err(|error| recovery(&error, handle))?;
        ensure_not_cancelled(cancellation, ProviderStage::Start)?;
        let prepared = self
            .engine
            .create_exec(&request.container_id, &request.command, &request.user)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Start, Some(handle)))?;
        self.verify_boundary(ProviderStage::Start)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let result = tokio::select! {
            biased;
            () = cancellation_requested(cancellation) => {
                self.stop_exact_running_job(names, container, handle, ProviderStage::Start).await?;
                return Err(uncertain(ProviderErrorKind::Cancelled, ProviderStage::Start, handle));
            }
            result = self.engine.start_exec(&prepared, &request) => result,
        };
        if cancellation.disposition().requires_termination() {
            self.stop_exact_running_job(names, container, handle, ProviderStage::Start)
                .await?;
            return Err(uncertain(
                ProviderErrorKind::Cancelled,
                ProviderStage::Start,
                handle,
            ));
        }
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                self.stop_exact_running_job(names, container, handle, ProviderStage::Start)
                    .await?;
                return Err(map_provider_engine(
                    error,
                    ProviderStage::Start,
                    Some(handle),
                ));
            }
        };
        if result.exit_code != 0
            || !result.stderr.is_empty()
            || decode_frame::<GuestResponse>(&result.stdout).ok()
                != Some(GuestResponse::Ready {
                    protocol: GUEST_PROTOCOL_VERSION,
                })
        {
            return Err(uncertain(
                ProviderErrorKind::BackendRejected,
                ProviderStage::Start,
                handle,
            ));
        }
        if cancellation.disposition().requires_termination() {
            self.stop_exact_running_job(names, container, handle, ProviderStage::Start)
                .await?;
            return Err(uncertain(
                ProviderErrorKind::Cancelled,
                ProviderStage::Start,
                handle,
            ));
        }
        Ok(())
    }

    async fn bootstrap_client(
        &self,
        names: &ResourceNames,
        container: &InspectedContainer,
        handle: &SandboxHandle,
    ) -> Result<(), ProviderError> {
        let request = EngineExecRequest {
            container_id: container.id.clone(),
            command: vec![
                LOCAL_DOCKER_SANDBOX_GUEST_BINARY.to_owned(),
                "bootstrap-local-client".to_owned(),
            ],
            user: guest_seal_user(),
            stdin: Vec::new(),
            stdout_limit: 1,
            stderr_limit: 1,
            timeout: ENGINE_TRANSPORT_OVERHEAD + Duration::from_secs(10),
        };
        self.verify_boundary(ProviderStage::Start)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let prepared = self
            .engine
            .create_exec(&request.container_id, &request.command, &request.user)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Start, Some(handle)))?;
        self.verify_boundary(ProviderStage::Start)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let result = match self.engine.start_exec(&prepared, &request).await {
            Ok(result) => result,
            Err(error) => {
                self.stop_exact_running_job(names, container, handle, ProviderStage::Start)
                    .await?;
                return Err(map_provider_engine(
                    error,
                    ProviderStage::Start,
                    Some(handle),
                ));
            }
        };
        if result.exit_code != 0 || !result.stdout.is_empty() || !result.stderr.is_empty() {
            return Err(uncertain(
                ProviderErrorKind::BackendRejected,
                ProviderStage::Start,
                handle,
            ));
        }
        Ok(())
    }

    async fn attach_identity(
        &self,
        names: &ResourceNames,
        cancellation: &dyn Cancellation,
    ) -> Result<AttachedIdentity, ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::Attach)?;
        self.verify_boundary(ProviderStage::Attach).await?;
        let container = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Attach, None))?
            .ok_or_else(|| known(ProviderErrorKind::NotFound, ProviderStage::Attach))?;
        self.verify_job(names, &container, ProviderStage::Attach)
            .await?;
        if container.state != EngineContainerState::Running {
            return Err(known(
                ProviderErrorKind::InvalidState,
                ProviderStage::Attach,
            ));
        }
        if self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Attach, None))?
            .is_some()
        {
            return Err(known(
                ProviderErrorKind::InvalidState,
                ProviderStage::Attach,
            ));
        }
        let handle = names.handle(&self.provider_id)?;
        self.probe(names, &container, &handle, cancellation).await?;
        self.verify_boundary(ProviderStage::Attach).await?;
        let container = self
            .require_exact_container(
                &container,
                &container.definition,
                &container.image_id,
                EngineContainerState::Running,
                &handle,
            )
            .await?;
        self.require_name_absent(&names.helper, &handle).await?;
        let identity = self
            .verify_job(names, &container, ProviderStage::Attach)
            .await?;
        ensure_not_cancelled_after_mutation(cancellation, ProviderStage::Attach, &handle)?;
        Ok(AttachedIdentity {
            container_id: container.id,
            definition: container.definition,
            base_labels: identity.base_labels,
        })
    }

    async fn verify_attached(
        &self,
        names: &ResourceNames,
        attached: &AttachedIdentity,
    ) -> Result<InspectedContainer, ProviderErrorKind> {
        self.verify_boundary_kind().await?;
        let container = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(map_engine_kind)?
            .ok_or(ProviderErrorKind::NotFound)?;
        if container.id != attached.container_id
            || container.definition != attached.definition
            || container.state != EngineContainerState::Running
            || !container.isolated
        {
            return Err(ProviderErrorKind::OwnershipMismatch);
        }
        if self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(map_engine_kind)?
            .is_some()
        {
            return Err(ProviderErrorKind::InvalidState);
        }
        let identity = self
            .verify_job(names, &container, ProviderStage::VerifyOwnership)
            .await
            .map_err(|error| error.kind())?;
        if identity.base_labels != attached.base_labels {
            return Err(ProviderErrorKind::OwnershipMismatch);
        }
        Ok(container)
    }

    async fn stop_exact_running_job(
        &self,
        names: &ResourceNames,
        expected: &InspectedContainer,
        handle: &SandboxHandle,
        stage: ProviderStage,
    ) -> Result<(), ProviderError> {
        let current = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?
            .ok_or_else(|| uncertain(ProviderErrorKind::Conflict, stage, handle))?;
        let helper = self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?;
        if current.id != expected.id
            || current.image_id != expected.image_id
            || current.definition != expected.definition
            || current.state != EngineContainerState::Running
            || !current.isolated
            || helper.is_some()
        {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                stage,
                handle,
            ));
        }
        self.verify_boundary(stage)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let _untrusted_kill = self.engine.kill_container(&current.id).await;
        let stopped = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?
            .ok_or_else(|| uncertain(ProviderErrorKind::AdapterUnavailable, stage, handle))?;
        let helper = self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?;
        if stopped.id != current.id
            || stopped.image_id != current.image_id
            || stopped.definition != current.definition
            || !matches!(stopped.state, EngineContainerState::Exited(_))
            || !stopped.isolated
            || helper.is_some()
        {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                stage,
                handle,
            ));
        }
        self.verify_boundary(stage)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let final_job = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?;
        let final_helper = self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, stage, Some(handle)))?;
        if final_job.as_ref() != Some(&stopped) || final_helper.is_some() {
            return Err(uncertain(
                ProviderErrorKind::OwnershipMismatch,
                stage,
                handle,
            ));
        }
        Ok(())
    }

    async fn verify_job(
        &self,
        names: &ResourceNames,
        container: &InspectedContainer,
        stage: ProviderStage,
    ) -> Result<BaseIdentity, ProviderError> {
        let identity = parse_identity(
            &container.definition.labels,
            names,
            &self.installation,
            KIND_JOB,
            stage,
        )?;
        let image = ImmutableImage::new(container.definition.image.clone())
            .map_err(|_| known(ProviderErrorKind::OwnershipMismatch, stage))?;
        let inspected = self
            .verified_image(&image)
            .await
            .map_err(|kind| known(kind, stage))?;
        if inspected.id != container.image_id {
            return Err(known(ProviderErrorKind::OwnershipMismatch, stage));
        }
        verify_job_definition(
            container,
            names,
            &inspected.labels,
            &inspected.environment_names,
            &identity.base_labels,
            stage,
        )?;
        Ok(identity)
    }

    fn verify_helper(
        &self,
        names: &ResourceNames,
        helper: &InspectedContainer,
        stage: ProviderStage,
    ) -> Result<BaseIdentity, ProviderError> {
        let identity = parse_identity(
            &helper.definition.labels,
            names,
            &self.installation,
            KIND_GUEST_SOURCE,
            stage,
        )?;
        let expected = helper_definition(
            names,
            self.guest_image.reference(),
            &self.guest_image_labels,
            &self.guest_image_environment,
            &identity.base_labels,
        );
        verify_container(helper, &expected, &self.guest_image_id, None)
            .map_err(|_| known(ProviderErrorKind::OwnershipMismatch, stage))?;
        Ok(identity)
    }

    async fn inspect(
        &self,
        handle: &SandboxHandle,
        names: &ResourceNames,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::Inspect)?;
        self.verify_boundary(ProviderStage::Inspect).await?;
        let job = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Inspect, None))?;
        let helper = self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Inspect, None))?;
        let job_identity = match job.as_ref() {
            Some(job) => Some(self.verify_job(names, job, ProviderStage::Inspect).await?),
            None => None,
        };
        let helper_identity = match helper.as_ref() {
            Some(helper) => Some(self.verify_helper(names, helper, ProviderStage::Inspect)?),
            None => None,
        };
        let identity = if job.is_none() && helper.is_none() {
            None
        } else {
            Some(matching_identity(
                job_identity.as_ref(),
                helper_identity.as_ref(),
                ProviderStage::Inspect,
            )?)
        };
        let state = match (job.as_ref(), helper.as_ref()) {
            (None, None) => None,
            (None | Some(_), Some(_)) => Some(SandboxState::Degraded),
            (Some(job), None) => Some(match job.state {
                EngineContainerState::Created => SandboxState::Created,
                EngineContainerState::Running => SandboxState::Running,
                EngineContainerState::Exited(_) => SandboxState::Stopped,
                EngineContainerState::Invalid => SandboxState::Degraded,
            }),
        };
        ensure_not_cancelled(cancellation, ProviderStage::Inspect)?;
        self.verify_boundary(ProviderStage::Inspect).await?;
        let current_job = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Inspect, None))?;
        let current_helper = self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::Inspect, None))?;
        if current_job != job || current_helper != helper {
            return Err(known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::Inspect,
            ));
        }
        let (Some(identity), Some(state)) = (identity, state) else {
            return Err(known(ProviderErrorKind::NotFound, ProviderStage::Inspect));
        };
        Ok(SandboxInspection::new(
            handle.clone(),
            names.generation_value()?,
            identity.custody,
            identity.profile.clone(),
            state,
        ))
    }

    async fn destroy(
        &self,
        request: &DestroySandbox,
        names: &ResourceNames,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::DestroySandbox)?;
        self.verify_boundary(ProviderStage::DestroySandbox).await?;
        let job = self
            .engine
            .inspect_container(&names.job)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::DestroySandbox, None))?;
        let helper = self
            .engine
            .inspect_container(&names.helper)
            .await
            .map_err(|error| map_provider_engine(error, ProviderStage::DestroySandbox, None))?;
        if job.is_none() && helper.is_none() {
            ensure_not_cancelled(cancellation, ProviderStage::DestroySandbox)?;
            self.verify_boundary(ProviderStage::DestroySandbox).await?;
            self.require_name_absent(&names.job, request.handle())
                .await?;
            self.require_name_absent(&names.helper, request.handle())
                .await?;
            return Ok(DestroyDisposition::AlreadyAbsent);
        }
        let job_identity = match job.as_ref() {
            Some(job) => Some(
                self.verify_job(names, job, ProviderStage::VerifyOwnership)
                    .await?,
            ),
            None => None,
        };
        let helper_identity = match helper.as_ref() {
            Some(helper) => {
                Some(self.verify_helper(names, helper, ProviderStage::VerifyOwnership)?)
            }
            None => None,
        };
        let _identity = matching_identity(
            job_identity.as_ref(),
            helper_identity.as_ref(),
            ProviderStage::VerifyOwnership,
        )?;
        ensure_not_cancelled(cancellation, ProviderStage::DestroySandbox)?;

        if let Some(helper) = helper.as_ref() {
            self.destroy_container(
                helper,
                &helper.definition,
                &helper.image_id,
                request.handle(),
                cancellation,
            )
            .await?;
        }
        if let Some(job) = job.as_ref() {
            self.destroy_container(
                job,
                &job.definition,
                &job.image_id,
                request.handle(),
                cancellation,
            )
            .await?;
        }
        self.verify_boundary(ProviderStage::DestroySandbox)
            .await
            .map_err(|error| recovery(&error, request.handle()))?;
        self.require_name_absent(&names.job, request.handle())
            .await?;
        self.require_name_absent(&names.helper, request.handle())
            .await?;
        Ok(DestroyDisposition::Destroyed)
    }

    async fn destroy_container(
        &self,
        snapshot: &InspectedContainer,
        definition: &ContainerDefinition,
        image_id: &str,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ProviderError> {
        let mut current = self
            .engine
            .inspect_container(&definition.name)
            .await
            .map_err(|error| {
                map_provider_engine(error, ProviderStage::VerifyOwnership, Some(handle))
            })?
            .ok_or_else(|| {
                uncertain(
                    ProviderErrorKind::Conflict,
                    ProviderStage::VerifyOwnership,
                    handle,
                )
            })?;
        verify_container(&current, definition, image_id, None)
            .map_err(|error| recovery(&error, handle))?;
        if current.id != snapshot.id {
            return Err(uncertain(
                ProviderErrorKind::Conflict,
                ProviderStage::VerifyOwnership,
                handle,
            ));
        }
        match current.state {
            EngineContainerState::Running => {
                self.verify_boundary(ProviderStage::DestroyContainer)
                    .await
                    .map_err(|error| recovery(&error, handle))?;
                let _untrusted_kill = self.engine.kill_container(&current.id).await;
                current = self
                    .engine
                    .inspect_container(&definition.name)
                    .await
                    .map_err(|error| {
                        map_provider_engine(error, ProviderStage::DestroyContainer, Some(handle))
                    })?
                    .ok_or_else(|| {
                        uncertain(
                            ProviderErrorKind::AdapterUnavailable,
                            ProviderStage::DestroyContainer,
                            handle,
                        )
                    })?;
                verify_container(&current, definition, image_id, None)
                    .map_err(|error| recovery(&error, handle))?;
                if current.id != snapshot.id
                    || !matches!(current.state, EngineContainerState::Exited(_))
                {
                    return Err(uncertain(
                        ProviderErrorKind::InvalidState,
                        ProviderStage::DestroyContainer,
                        handle,
                    ));
                }
                ensure_not_cancelled_after_mutation(
                    cancellation,
                    ProviderStage::DestroyContainer,
                    handle,
                )?;
            }
            EngineContainerState::Created | EngineContainerState::Exited(_) => {}
            EngineContainerState::Invalid => {
                return Err(known(
                    ProviderErrorKind::InvalidState,
                    ProviderStage::DestroyContainer,
                ));
            }
        }
        self.verify_boundary(ProviderStage::DestroyContainer)
            .await
            .map_err(|error| recovery(&error, handle))?;
        let _untrusted_remove = self.engine.remove_container(&current.id).await;
        self.require_removed(&definition.name, &current.id, handle)
            .await?;
        ensure_not_cancelled_after_mutation(cancellation, ProviderStage::DestroyContainer, handle)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResourceNames {
    installation_id: String,
    operation_id: OperationId,
    generation: u64,
    job: String,
    helper: String,
}

impl ResourceNames {
    fn for_spec(installation: &Installation, spec: &SandboxSpec) -> Result<Self, ProviderError> {
        Self::new(installation, spec.operation_id(), spec.generation().get())
    }

    fn from_handle(
        provider: &ProviderId,
        installation: &Installation,
        handle: &SandboxHandle,
    ) -> Result<Self, ProviderError> {
        if handle.provider() != provider {
            return Err(invalid_handle());
        }
        let mut fields = handle.opaque().split('.');
        if fields.next() != Some("ld") {
            return Err(invalid_handle());
        }
        let installation_text = fields.next().ok_or_else(invalid_handle)?;
        let operation_text = fields.next().ok_or_else(invalid_handle)?;
        let generation_text = fields.next().ok_or_else(invalid_handle)?;
        if fields.next().is_some()
            || InstallationId::parse_canonical(installation_text) != Some(installation.id())
        {
            return Err(invalid_handle());
        }
        let operation_id = OperationId::from_str(operation_text).map_err(|_| invalid_handle())?;
        let generation = generation_text
            .parse::<u64>()
            .ok()
            .filter(|value| value.to_string() == generation_text)
            .ok_or_else(invalid_handle)?;
        SandboxGeneration::new(generation).map_err(|_| invalid_handle())?;
        if operation_id.to_string() != operation_text {
            return Err(invalid_handle());
        }
        Self::new(installation, operation_id, generation)
    }

    fn new(
        installation: &Installation,
        operation_id: OperationId,
        generation: u64,
    ) -> Result<Self, ProviderError> {
        SandboxGeneration::new(generation).map_err(|_| invalid_handle())?;
        let base = format!(
            "automata-local-{}-{}-{generation}",
            installation.id().as_uuid().simple(),
            operation_id.as_uuid().simple()
        );
        Ok(Self {
            installation_id: installation.id().to_string(),
            operation_id,
            generation,
            job: format!("{base}-job"),
            helper: format!("{base}-guest-source"),
        })
    }

    fn handle(&self, provider: &ProviderId) -> Result<SandboxHandle, ProviderError> {
        SandboxHandle::new(
            provider.clone(),
            format!(
                "ld.{}.{}.{}",
                self.installation_id, self.operation_id, self.generation
            ),
        )
        .map_err(|_| invalid_handle())
    }

    fn generation_value(&self) -> Result<SandboxGeneration, ProviderError> {
        SandboxGeneration::new(self.generation).map_err(|_| invalid_handle())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BaseIdentity {
    base_labels: BTreeMap<String, String>,
    custody: SandboxCustody,
    profile: EnvironmentProfile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AttachedIdentity {
    container_id: String,
    definition: ContainerDefinition,
    base_labels: BTreeMap<String, String>,
}

fn validate_spec(spec: &SandboxSpec) -> Result<(), ProviderError> {
    let SandboxLaunch::Container { .. } = spec.profile().launch() else {
        return Err(known(
            ProviderErrorKind::UnsupportedPlatform,
            ProviderStage::Validate,
        ));
    };
    let profile_workspace = spec.profile().workspace();
    let workspace = spec.workspace();
    let workspace_prefix = format!("{}/", profile_workspace.as_str().trim_end_matches('/'));
    let workspace_conflicts_with_control = workspace.as_str() == "/"
        || workspace.as_str() == "/automata"
        || workspace.as_str().starts_with("/automata/")
        || workspace.as_str() == LOCAL_CONTROL_DIRECTORY
        || workspace
            .as_str()
            .starts_with(&format!("{LOCAL_CONTROL_DIRECTORY}/"));
    if workspace.platform() != TargetPlatform::Posix
        || profile_workspace.platform() != TargetPlatform::Posix
        || (workspace != profile_workspace && !workspace.as_str().starts_with(&workspace_prefix))
        || workspace_conflicts_with_control
        || spec.scratch().is_some()
        || !spec.services().is_empty()
        || spec.network() != NetworkPolicy::Disabled
        || spec.root_filesystem() != RootFilesystemPolicy::Writable
        || spec.privilege() != SandboxPrivilegePolicy::Administrator
    {
        return Err(known(
            ProviderErrorKind::UnsupportedCapability,
            ProviderStage::Validate,
        ));
    }
    if !spec.has_coherent_resource_contract() {
        return Err(invalid_configuration());
    }
    let resources = spec.resources();
    if resources.memory_bytes() < MINIMUM_LOCAL_DOCKER_SANDBOX_MEMORY_BYTES
        || resources.cpu_millis() < MINIMUM_LOCAL_DOCKER_SANDBOX_CPU_MILLIS
        || resources.pids() < MINIMUM_LOCAL_DOCKER_SANDBOX_PIDS
    {
        return Err(invalid_configuration());
    }
    if spec.resource_allocation().is_some_and(|allocation| {
        allocation.limits().ephemeral_disk_bytes() != 0
            || allocation.limits().gpu_count() != 0
            || allocation.requests().ephemeral_disk_bytes() != 0
            || allocation.requests().gpu_count() != 0
    }) {
        return Err(known(
            ProviderErrorKind::UnsupportedCapability,
            ProviderStage::Validate,
        ));
    }
    Ok(())
}

fn base_labels(
    spec: &SandboxSpec,
    installation: &Installation,
    fingerprint: &str,
) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::from([
        (LABEL_MANAGED.to_owned(), MANAGED_VALUE.to_owned()),
        (LABEL_JOB_SCHEMA.to_owned(), JOB_SCHEMA.to_owned()),
        (
            LABEL_INSTALLATION_ID.to_owned(),
            installation.id().to_string(),
        ),
        (
            LABEL_INSTALLATION_KEY.to_owned(),
            installation.selector_key().to_string(),
        ),
        (
            LABEL_COMPOSE_PROJECT.to_owned(),
            installation.compose_project().to_string(),
        ),
        (
            LABEL_RUNNER_ID.to_owned(),
            spec.custody().runner_id().to_string(),
        ),
        (
            LABEL_OPERATION_ID.to_owned(),
            spec.operation_id().to_string(),
        ),
        (
            LABEL_GENERATION.to_owned(),
            spec.generation().get().to_string(),
        ),
        (
            LABEL_PROFILE.to_owned(),
            spec.profile().id().as_str().to_owned(),
        ),
        (
            LABEL_PROFILE_DIGEST.to_owned(),
            spec.profile().digest().to_string(),
        ),
        (LABEL_SPEC_DIGEST.to_owned(), fingerprint.to_owned()),
    ]);
    match spec.custody() {
        SandboxCustody::ProfileAdmission { .. } => {
            labels.insert(LABEL_CUSTODY_KIND.to_owned(), CUSTODY_ADMISSION.to_owned());
        }
        SandboxCustody::Job { slot_ordinal, .. } => {
            labels.insert(LABEL_CUSTODY_KIND.to_owned(), CUSTODY_JOB.to_owned());
            labels.insert(LABEL_SLOT.to_owned(), slot_ordinal.get().to_string());
        }
    }
    labels
}

fn resource_labels(
    image_labels: &BTreeMap<String, String>,
    base: &BTreeMap<String, String>,
    kind: &str,
) -> BTreeMap<String, String> {
    let mut labels = image_labels.clone();
    labels.extend(base.clone());
    labels.insert(LABEL_RESOURCE_KIND.to_owned(), kind.to_owned());
    labels
}

fn helper_definition(
    names: &ResourceNames,
    guest_image: &str,
    image_labels: &BTreeMap<String, String>,
    environment: &[String],
    base_labels: &BTreeMap<String, String>,
) -> ContainerDefinition {
    ContainerDefinition {
        name: names.helper.clone(),
        image: guest_image.to_owned(),
        entrypoint: LOCAL_DOCKER_GUEST_IMAGE_BINARY.to_owned(),
        arguments: Vec::new(),
        labels: resource_labels(image_labels, base_labels, KIND_GUEST_SOURCE),
        environment: environment.to_vec(),
        tmpfs: BTreeMap::new(),
        working_directory: "/".to_owned(),
        user: guest_client_user(),
        read_only_root: true,
        memory_bytes: HELPER_MEMORY_BYTES,
        nano_cpus: HELPER_NANO_CPUS,
        pids_limit: HELPER_PIDS,
    }
}

fn job_definition(
    names: &ResourceNames,
    spec: &SandboxSpec,
    image: &str,
    image_labels: &BTreeMap<String, String>,
    environment_names: &[String],
    base_labels: &BTreeMap<String, String>,
) -> Result<ContainerDefinition, ProviderError> {
    let resources = spec.resources();
    let memory_bytes =
        i64::try_from(resources.memory_bytes()).map_err(|_| invalid_configuration())?;
    let nano_cpus = i64::from(resources.cpu_millis())
        .checked_mul(1_000_000)
        .ok_or_else(invalid_configuration)?;
    Ok(ContainerDefinition {
        name: names.job.clone(),
        image: image.to_owned(),
        entrypoint: LOCAL_DOCKER_SANDBOX_GUEST_BINARY.to_owned(),
        arguments: vec!["serve-local".to_owned()],
        labels: resource_labels(image_labels, base_labels, KIND_JOB),
        environment: neutral_environment(environment_names),
        tmpfs: BTreeMap::from([
            (
                spec.workspace().as_str().to_owned(),
                job_tmpfs_options(memory_bytes),
            ),
            (
                LOCAL_CONTROL_DIRECTORY.to_owned(),
                guest_control_tmpfs_options(),
            ),
        ]),
        working_directory: spec.workspace().as_str().to_owned(),
        user: "0:0".to_owned(),
        read_only_root: false,
        memory_bytes,
        nano_cpus,
        pids_limit: i64::from(resources.pids()),
    })
}

fn job_tmpfs_options(memory_bytes: i64) -> String {
    format!("rw,exec,nosuid,nodev,size={memory_bytes},mode=0777,uid=0,gid=0")
}

fn extract_single_guest(archive: &[u8]) -> Result<Vec<u8>, ProviderError> {
    if archive.is_empty() || archive.len() > LOCAL_DOCKER_GUEST_ARCHIVE_BYTES {
        return Err(known(
            ProviderErrorKind::OutputLimitExceeded,
            ProviderStage::VerifyOwnership,
        ));
    }
    let mut tar = tar::Archive::new(Cursor::new(archive));
    let mut entries = tar.entries().map_err(|_| {
        known(
            ProviderErrorKind::BackendRejected,
            ProviderStage::VerifyOwnership,
        )
    })?;
    let mut entry = entries
        .next()
        .transpose()
        .map_err(|_| {
            known(
                ProviderErrorKind::BackendRejected,
                ProviderStage::VerifyOwnership,
            )
        })?
        .ok_or_else(|| {
            known(
                ProviderErrorKind::BackendRejected,
                ProviderStage::VerifyOwnership,
            )
        })?;
    let path = entry.path().map_err(|_| {
        known(
            ProviderErrorKind::BackendRejected,
            ProviderStage::VerifyOwnership,
        )
    })?;
    let expected_size = usize::try_from(entry.size()).map_err(|_| {
        known(
            ProviderErrorKind::OutputLimitExceeded,
            ProviderStage::VerifyOwnership,
        )
    })?;
    let expected_path = std::path::Path::new(LOCAL_DOCKER_GUEST_IMAGE_BINARY)
        .file_name()
        .ok_or_else(invalid_configuration)?;
    if path.as_ref() != std::path::Path::new(expected_path)
        || !entry.header().entry_type().is_file()
        || expected_size == 0
        || expected_size > max_guest_binary_bytes()
    {
        return Err(known(
            ProviderErrorKind::BackendRejected,
            ProviderStage::VerifyOwnership,
        ));
    }
    let mut bytes = Vec::with_capacity(expected_size);
    (&mut entry)
        .take(MAX_LOCAL_GUEST_BINARY_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            known(
                ProviderErrorKind::BackendRejected,
                ProviderStage::VerifyOwnership,
            )
        })?;
    drop(entry);
    if entries
        .next()
        .transpose()
        .map_err(|_| {
            known(
                ProviderErrorKind::BackendRejected,
                ProviderStage::VerifyOwnership,
            )
        })?
        .is_some()
        || bytes.len() != expected_size
        || bytes.len() > max_guest_binary_bytes()
    {
        return Err(known(
            ProviderErrorKind::BackendRejected,
            ProviderStage::VerifyOwnership,
        ));
    }
    Ok(bytes)
}

fn sandbox_archive(workspace: &str, guest: &[u8]) -> Result<Vec<u8>, ProviderError> {
    if guest.is_empty() || guest.len() > max_guest_binary_bytes() {
        return Err(invalid_configuration());
    }
    let mut directories = BTreeSet::from(["automata".to_owned(), "automata/bin".to_owned()]);
    let mut current = String::new();
    for component in workspace.trim_start_matches('/').split('/') {
        if component.is_empty() {
            return Err(invalid_configuration());
        }
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(component);
        directories.insert(current.clone());
    }
    let mut builder = TarBuilder::new(Vec::new());
    for directory in directories {
        let mode = if directory == "automata" || directory == "automata/bin" {
            0o755
        } else {
            0o777
        };
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Directory);
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(0);
        header
            .set_path(&directory)
            .map_err(|_| invalid_configuration())?;
        header.set_cksum();
        builder
            .append(&header, std::io::empty())
            .map_err(|_| invalid_configuration())?;
    }
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    header.set_mode(0o555);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(u64::try_from(guest.len()).map_err(|_| invalid_configuration())?);
    header
        .set_path(
            LOCAL_DOCKER_SANDBOX_GUEST_BINARY
                .strip_prefix('/')
                .ok_or_else(invalid_configuration)?,
        )
        .map_err(|_| invalid_configuration())?;
    header.set_cksum();
    builder
        .append(&header, guest)
        .map_err(|_| invalid_configuration())?;
    let archive = builder.into_inner().map_err(|_| invalid_configuration())?;
    if archive.len() > LOCAL_DOCKER_GUEST_ARCHIVE_BYTES {
        return Err(invalid_configuration());
    }
    Ok(archive)
}

fn spec_fingerprint(
    spec: &SandboxSpec,
    installation: &Installation,
    guest_image: &ImmutableImage,
) -> Result<String, ProviderError> {
    let mut digest = Sha256::new();
    hash_field(&mut digest, b"automata-local-docker-sandbox-spec-v1");
    hash_field(&mut digest, installation.id().as_uuid().as_bytes());
    hash_field(
        &mut digest,
        installation.selector_key().to_string().as_bytes(),
    );
    hash_field(
        &mut digest,
        installation.compose_project().as_str().as_bytes(),
    );
    hash_field(&mut digest, spec.operation_id().as_uuid().as_bytes());
    hash_field(&mut digest, &spec.generation().get().to_be_bytes());
    hash_custody(&mut digest, spec.custody());
    hash_field(&mut digest, spec.profile().id().as_str().as_bytes());
    hash_field(&mut digest, spec.profile().digest().as_bytes());
    let SandboxLaunch::Container { image, keepalive } = spec.profile().launch() else {
        return Err(invalid_configuration());
    };
    hash_field(&mut digest, image.reference().as_bytes());
    hash_field(&mut digest, keepalive.program().as_str().as_bytes());
    for argument in keepalive.arguments() {
        hash_field(&mut digest, argument.as_bytes());
    }
    hash_field(&mut digest, spec.profile().workspace().as_str().as_bytes());
    for variable in spec.profile().default_environment().values() {
        hash_field(&mut digest, variable.name().as_str().as_bytes());
        hash_field(&mut digest, variable.value().expose().as_bytes());
        hash_field(&mut digest, &[u8::from(variable.is_secret())]);
    }
    hash_field(&mut digest, spec.workspace().as_str().as_bytes());
    hash_field(
        &mut digest,
        &[
            spec.network() as u8,
            spec.root_filesystem() as u8,
            spec.privilege() as u8,
        ],
    );
    let resources = spec.resources();
    hash_field(&mut digest, &resources.memory_bytes().to_be_bytes());
    hash_field(&mut digest, &resources.cpu_millis().to_be_bytes());
    hash_field(&mut digest, &resources.pids().to_be_bytes());
    match spec.resource_allocation() {
        Some(allocation) => {
            hash_field(&mut digest, &[1]);
            for resources in [allocation.requests(), allocation.limits()] {
                hash_field(&mut digest, &resources.cpu_millis().to_be_bytes());
                hash_field(&mut digest, &resources.memory_bytes().to_be_bytes());
                hash_field(&mut digest, &resources.ephemeral_disk_bytes().to_be_bytes());
                hash_field(&mut digest, &resources.gpu_count().to_be_bytes());
            }
        }
        None => hash_field(&mut digest, &[0]),
    }
    hash_field(&mut digest, guest_image.reference().as_bytes());
    Ok(Sha256Digest::from_bytes(digest.finalize().into()).to_string())
}

fn hash_custody(digest: &mut Sha256, custody: SandboxCustody) {
    match custody {
        SandboxCustody::ProfileAdmission { runner_id } => {
            hash_field(digest, CUSTODY_ADMISSION.as_bytes());
            hash_field(digest, runner_id.as_uuid().as_bytes());
        }
        SandboxCustody::Job {
            runner_id,
            slot_ordinal,
        } => {
            hash_field(digest, CUSTODY_JOB.as_bytes());
            hash_field(digest, runner_id.as_uuid().as_bytes());
            hash_field(digest, &slot_ordinal.get().to_be_bytes());
        }
    }
}

fn hash_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(
        u64::try_from(value.len())
            .expect("sandbox fingerprint fields fit in u64")
            .to_be_bytes(),
    );
    digest.update(value);
}

fn parse_identity(
    labels: &BTreeMap<String, String>,
    names: &ResourceNames,
    installation: &Installation,
    resource_kind: &str,
    stage: ProviderStage,
) -> Result<BaseIdentity, ProviderError> {
    let managed = managed_labels(labels);
    let required = |key: &str| {
        managed
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))
    };
    if required(LABEL_MANAGED)? != MANAGED_VALUE
        || required(LABEL_JOB_SCHEMA)? != JOB_SCHEMA
        || required(LABEL_INSTALLATION_ID)? != installation.id().to_string()
        || required(LABEL_INSTALLATION_KEY)? != installation.selector_key().to_string()
        || required(LABEL_COMPOSE_PROJECT)? != installation.compose_project().as_str()
        || required(LABEL_OPERATION_ID)? != names.operation_id.to_string()
        || required(LABEL_GENERATION)? != names.generation.to_string()
        || required(LABEL_RESOURCE_KIND)? != resource_kind
    {
        return Err(known(ProviderErrorKind::OwnershipMismatch, stage));
    }
    let runner_text = required(LABEL_RUNNER_ID)?;
    let runner_id = RunnerId::from_str(runner_text)
        .ok()
        .filter(|value| value.to_string() == runner_text)
        .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))?;
    let custody = match required(LABEL_CUSTODY_KIND)? {
        CUSTODY_ADMISSION if !managed.contains_key(LABEL_SLOT) => {
            if managed.len() != 13 {
                return Err(known(ProviderErrorKind::OwnershipMismatch, stage));
            }
            SandboxCustody::ProfileAdmission { runner_id }
        }
        CUSTODY_JOB => {
            let slot_text = required(LABEL_SLOT)?;
            let slot_ordinal = slot_text
                .parse::<u16>()
                .ok()
                .and_then(NonZeroU16::new)
                .filter(|value| value.get().to_string() == slot_text)
                .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))?;
            if managed.len() != 14 {
                return Err(known(ProviderErrorKind::OwnershipMismatch, stage));
            }
            SandboxCustody::Job {
                runner_id,
                slot_ordinal,
            }
        }
        _ => return Err(known(ProviderErrorKind::OwnershipMismatch, stage)),
    };
    let profile_id = EnvironmentProfileId::from_str(required(LABEL_PROFILE)?)
        .map_err(|_| known(ProviderErrorKind::OwnershipMismatch, stage))?;
    let profile_digest = canonical_digest(required(LABEL_PROFILE_DIGEST)?)
        .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))?;
    canonical_digest(required(LABEL_SPEC_DIGEST)?)
        .ok_or_else(|| known(ProviderErrorKind::OwnershipMismatch, stage))?;
    let mut base_labels = managed;
    base_labels.remove(LABEL_RESOURCE_KIND);
    Ok(BaseIdentity {
        base_labels,
        custody,
        profile: EnvironmentProfile::new(profile_id, profile_digest),
    })
}

fn matching_identity<'a>(
    first: Option<&'a BaseIdentity>,
    second: Option<&'a BaseIdentity>,
    stage: ProviderStage,
) -> Result<&'a BaseIdentity, ProviderError> {
    match (first, second) {
        (Some(first), Some(second)) if first == second => Ok(first),
        (Some(identity), None) | (None, Some(identity)) => Ok(identity),
        (Some(_), Some(_)) => Err(known(ProviderErrorKind::OwnershipMismatch, stage)),
        (None, None) => Err(known(ProviderErrorKind::NotFound, stage)),
    }
}

fn canonical_digest(value: &str) -> Option<Sha256Digest> {
    Sha256Digest::from_str(value)
        .ok()
        .filter(|digest| digest.to_string() == value)
}

fn managed_labels(labels: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    labels
        .iter()
        .filter(|(key, _)| key.starts_with(MANAGED_LABEL_PREFIX))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn verify_existing_helper(
    container: &InspectedContainer,
    definition: &ContainerDefinition,
    image_id: &str,
) -> Result<(), ProviderError> {
    verify_container(
        container,
        definition,
        image_id,
        Some(EngineContainerState::Created),
    )
}

fn verify_container(
    container: &InspectedContainer,
    definition: &ContainerDefinition,
    image_id: &str,
    state: Option<EngineContainerState>,
) -> Result<(), ProviderError> {
    if container.id.is_empty()
        || container.image_id != image_id
        || !container.isolated
        || container.definition != *definition
        || state.is_some_and(|expected| container.state != expected)
    {
        return Err(known(
            ProviderErrorKind::Conflict,
            ProviderStage::VerifyOwnership,
        ));
    }
    Ok(())
}

fn verify_job_definition(
    container: &InspectedContainer,
    names: &ResourceNames,
    image_labels: &BTreeMap<String, String>,
    image_environment_names: &[String],
    base_labels: &BTreeMap<String, String>,
    stage: ProviderStage,
) -> Result<(), ProviderError> {
    let definition = &container.definition;
    let workspace = automata_ci_execution::TargetPath::posix(definition.working_directory.clone())
        .map_err(|_| known(ProviderErrorKind::OwnershipMismatch, stage))?;
    let resource_limits_valid = definition.memory_bytes > 0
        && definition.nano_cpus > 0
        && definition.nano_cpus % 1_000_000 == 0
        && definition.pids_limit > 0
        && u64::try_from(definition.memory_bytes)
            .ok()
            .zip(u32::try_from(definition.nano_cpus / 1_000_000).ok())
            .zip(u32::try_from(definition.pids_limit).ok())
            .is_some_and(|((memory, cpu), pids)| {
                automata_ci_execution::ResourceLimits::new(memory, cpu, pids).is_ok()
            });
    if container.id.is_empty()
        || !container.isolated
        || definition.name != names.job
        || definition.entrypoint != LOCAL_DOCKER_SANDBOX_GUEST_BINARY
        || definition.arguments != ["serve-local"]
        || definition.labels != resource_labels(image_labels, base_labels, KIND_JOB)
        || definition.environment != neutral_environment(image_environment_names)
        || definition.tmpfs
            != BTreeMap::from([
                (
                    workspace.as_str().to_owned(),
                    job_tmpfs_options(definition.memory_bytes),
                ),
                (
                    LOCAL_CONTROL_DIRECTORY.to_owned(),
                    guest_control_tmpfs_options(),
                ),
            ])
        || workspace.as_str() == "/"
        || workspace.as_str() == "/automata"
        || workspace.as_str().starts_with("/automata/")
        || workspace.as_str() == LOCAL_CONTROL_DIRECTORY
        || workspace
            .as_str()
            .starts_with(&format!("{LOCAL_CONTROL_DIRECTORY}/"))
        || definition.user != "0:0"
        || definition.read_only_root
        || !resource_limits_valid
    {
        return Err(known(ProviderErrorKind::OwnershipMismatch, stage));
    }
    Ok(())
}

fn neutral_environment(names: &[String]) -> Vec<String> {
    names.iter().map(|name| format!("{name}=")).collect()
}

fn verify_image(
    pinned: &PinnedDockerEngine,
    image: &ImmutableImage,
    inspected: &InspectedImage,
) -> Result<(), LocalEngineErrorCode> {
    let valid_id = inspected
        .id
        .strip_prefix("sha256:")
        .and_then(canonical_digest)
        .is_some();
    if !valid_id
        || inspected.operating_system != "linux"
        || !inspected.declared_volumes.is_empty()
        || inspected
            .labels
            .keys()
            .any(|key| key.starts_with(MANAGED_LABEL_PREFIX))
        || normalize_architecture(&inspected.architecture) != Some(pinned.architecture())
        || !inspected
            .repo_digests
            .iter()
            .any(|digest| digest == image.reference())
    {
        return Err(LocalEngineErrorCode::ImageMismatch);
    }
    Ok(())
}

fn record(handle: &SandboxHandle, spec: &SandboxSpec, state: SandboxState) -> SandboxRecord {
    SandboxRecord::new(
        handle.clone(),
        spec.generation(),
        spec.profile().attestation().clone(),
        state,
    )
}

fn invalid_handle() -> ProviderError {
    known(
        ProviderErrorKind::OwnershipMismatch,
        ProviderStage::Validate,
    )
}

fn invalid_configuration() -> ProviderError {
    known(
        ProviderErrorKind::InvalidConfiguration,
        ProviderStage::Validate,
    )
}

const fn known(kind: ProviderErrorKind, stage: ProviderStage) -> ProviderError {
    ProviderError::new(kind, stage, OperationOutcome::KnownNoEffect, None)
}

fn uncertain(
    kind: ProviderErrorKind,
    stage: ProviderStage,
    handle: &SandboxHandle,
) -> ProviderError {
    ProviderError::new(
        kind,
        stage,
        OperationOutcome::Uncertain,
        Some(handle.clone()),
    )
}

fn recovery(error: &ProviderError, handle: &SandboxHandle) -> ProviderError {
    ProviderError::new(
        error.kind(),
        error.stage(),
        OperationOutcome::Uncertain,
        Some(handle.clone()),
    )
}

fn map_provider_engine(
    error: EngineApiError,
    stage: ProviderStage,
    recovery_handle: Option<&SandboxHandle>,
) -> ProviderError {
    let kind = map_engine_kind(error);
    match recovery_handle {
        Some(handle) => uncertain(kind, stage, handle),
        None => known(kind, stage),
    }
}

const fn map_engine_kind(error: EngineApiError) -> ProviderErrorKind {
    match error {
        EngineApiError::RequestFailed => ProviderErrorKind::AdapterUnavailable,
        EngineApiError::InvalidResponse => ProviderErrorKind::BackendRejected,
        EngineApiError::OutputLimit => ProviderErrorKind::OutputLimitExceeded,
    }
}

fn ensure_not_cancelled(
    cancellation: &dyn Cancellation,
    stage: ProviderStage,
) -> Result<(), ProviderError> {
    if cancellation.disposition().requires_termination() {
        return Err(known(ProviderErrorKind::Cancelled, stage));
    }
    Ok(())
}

fn ensure_not_cancelled_after_mutation(
    cancellation: &dyn Cancellation,
    stage: ProviderStage,
    handle: &SandboxHandle,
) -> Result<(), ProviderError> {
    if cancellation.disposition().requires_termination() {
        return Err(uncertain(ProviderErrorKind::Cancelled, stage, handle));
    }
    Ok(())
}

async fn cancellation_requested(cancellation: &dyn Cancellation) {
    while !cancellation.disposition().requires_termination() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn lock_handle(
    operation_lock: Arc<HandleOperationLock>,
    cancellation: &dyn Cancellation,
) -> Option<tokio::sync::OwnedMutexGuard<()>> {
    if cancellation.disposition().requires_termination() {
        return None;
    }
    tokio::select! {
        biased;
        () = cancellation_requested(cancellation) => None,
        guard = operation_lock.lock_owned() => Some(guard),
    }
}

fn run_provider<T, F>(stage: ProviderStage, future: F) -> Result<T, ProviderError>
where
    T: Send,
    F: Future<Output = Result<T, ProviderError>> + Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| known(ProviderErrorKind::AdapterUnavailable, stage))?
                    .block_on(future)
            })
            .join()
            .map_err(|_| known(ProviderErrorKind::AdapterUnavailable, stage))?
    })
}
