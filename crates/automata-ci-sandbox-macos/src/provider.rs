use rustix::fs::{FlockOperation, flock};
use std::{
    collections::HashMap,
    fmt,
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex, MutexGuard, TryLockError},
    time::{Duration, Instant},
};

use automata_ci_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, EnvironmentProfile, ExecutionEndpoint,
    NetworkPolicy, OperationId, OperationOutcome, ProviderCapabilities, ProviderError,
    ProviderErrorKind, ProviderId, ProviderStage, ResourceLimits, RootFilesystemPolicy,
    SandboxCapability, SandboxCustody, SandboxGeneration, SandboxHandle, SandboxInspection,
    SandboxLaunch, SandboxPrivilegePolicy, SandboxProvider, SandboxRecord, SandboxSpec,
    SandboxState, Sha256Digest, TargetPath, TargetPlatform,
};
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};

use crate::{
    endpoint::MacosVirtualizationEndpoint,
    filesystem::SecureRoot,
    path::{is_strict_descendant, overlaps, validate_posix_path},
    persistence::{
        DurableCreate, DurableDestroyRequest, DurableEntry, DurableEntryPhase, DurableEvent,
        DurableSnapshot, DurableTombstone, LifecycleJournal, recovered_generation,
    },
    template::{VerifiedTemplate, load_template, plist_to_json, verify_helper},
    vm::VmProcess,
};

const QUIESCE_TIMEOUT: Duration = Duration::from_secs(5);
const QUIESCE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const GIBIBYTE: u64 = 1024 * 1024 * 1024;
const MINIMUM_STORAGE_HEADROOM: u64 = 32 * GIBIBYTE;
const MAX_DISKUTIL_PLIST_BYTES: usize = 4 * 1024 * 1024;

const PROVIDER_CAPABILITIES: [SandboxCapability; 11] = [
    SandboxCapability::WholeJob,
    SandboxCapability::Attach,
    SandboxCapability::Inspect,
    SandboxCapability::Exec,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::EnvironmentInjection,
    SandboxCapability::NetworkDisabled,
    SandboxCapability::WritableRootFilesystem,
    SandboxCapability::ResourceLimits,
    SandboxCapability::ProcessLimits,
];

pub(crate) const ENDPOINT_CAPABILITIES: [SandboxCapability; 4] = [
    SandboxCapability::Exec,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::EnvironmentInjection,
];

/// Immutable host state, helper, and template inputs for macOS virtualization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacosVirtualizationProviderOptions {
    provider_root: PathBuf,
    provider_target: TargetPath,
    helper_executable: PathBuf,
    helper_digest: Sha256Digest,
    helper_code_requirement: String,
    template_manifest: PathBuf,
    template_manifest_digest: Sha256Digest,
    storage_volume_uuid: String,
    storage_quota_bytes: u64,
    boot_timeout: Duration,
    stop_timeout: Duration,
}

impl MacosVirtualizationProviderOptions {
    /// Creates a provider configuration rooted at one dedicated private state path.
    ///
    /// # Errors
    ///
    /// Rejects non-absolute, non-Unicode, root, non-normalized, or mismatched
    /// POSIX paths.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_root: impl Into<PathBuf>,
        helper_executable: impl Into<PathBuf>,
        helper_digest: Sha256Digest,
        helper_code_requirement: String,
        template_manifest: impl Into<PathBuf>,
        template_manifest_digest: Sha256Digest,
        storage_volume_uuid: &str,
        storage_quota_bytes: u64,
        boot_timeout: Duration,
        stop_timeout: Duration,
    ) -> Result<Self, ProviderError> {
        let provider_root = provider_root.into();
        let helper_executable = helper_executable.into();
        let template_manifest = template_manifest.into();
        let storage_volume_uuid = normalized_volume_uuid(storage_volume_uuid).ok_or_else(|| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let provider = provider_root.to_str().ok_or_else(|| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let provider_target = TargetPath::posix(provider.to_owned()).map_err(|_| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        if !validate_posix_path(&provider_target)
            || !normalized_absolute_host_path(&helper_executable)
            || !normalized_absolute_host_path(&template_manifest)
            || helper_code_requirement.is_empty()
            || helper_code_requirement.len() > 4_096
            || !helper_code_requirement.is_ascii()
            || helper_code_requirement
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || !valid_helper_code_requirement(&helper_code_requirement)
            || !(64 * GIBIBYTE..=1024 * GIBIBYTE).contains(&storage_quota_bytes)
            || !storage_quota_bytes.is_multiple_of(GIBIBYTE)
            || !(Duration::from_secs(30)..=Duration::from_mins(15)).contains(&boot_timeout)
            || !(Duration::from_secs(1)..=Duration::from_secs(30)).contains(&stop_timeout)
        {
            return Err(known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            ));
        }
        Ok(Self {
            provider_root,
            provider_target,
            helper_executable,
            helper_digest,
            helper_code_requirement,
            template_manifest,
            template_manifest_digest,
            storage_volume_uuid,
            storage_quota_bytes,
            boot_timeout,
            stop_timeout,
        })
    }

    /// Returns the dedicated provider-owned root.
    #[must_use]
    pub fn provider_root(&self) -> &Path {
        &self.provider_root
    }

    /// Returns the exact signed Swift helper executable.
    #[must_use]
    pub fn helper_executable(&self) -> &Path {
        &self.helper_executable
    }

    pub(crate) const fn helper_digest(&self) -> Sha256Digest {
        self.helper_digest
    }

    pub(crate) fn helper_code_requirement(&self) -> &str {
        &self.helper_code_requirement
    }

    pub(crate) fn template_manifest(&self) -> &Path {
        &self.template_manifest
    }

    pub(crate) const fn template_manifest_digest(&self) -> Sha256Digest {
        self.template_manifest_digest
    }

    pub(crate) fn storage_volume_uuid(&self) -> &str {
        &self.storage_volume_uuid
    }

    pub(crate) const fn storage_quota_bytes(&self) -> u64 {
        self.storage_quota_bytes
    }

    pub(crate) const fn boot_timeout(&self) -> Duration {
        self.boot_timeout
    }

    pub(crate) const fn stop_timeout(&self) -> Duration {
        self.stop_timeout
    }

    pub(crate) const fn provider_target(&self) -> &TargetPath {
        &self.provider_target
    }
}

/// macOS provider backed by one disposable Virtualization.framework VM per job.
///
/// Clones share the exclusive lifecycle lock and all operation-replay state.
/// The host kernel and Apple hypervisor remain in the trusted computing base.
#[derive(Clone)]
pub struct MacosVirtualizationProvider {
    inner: Arc<ProviderInner>,
}

impl MacosVirtualizationProvider {
    /// Opens and exclusively locks the provider root, then reconciles orphaned
    /// lifecycle entries before accepting work.
    ///
    /// # Errors
    ///
    /// Rejects unsupported macOS hosts, insecure roots, unsigned helpers,
    /// concurrent opens, corrupt state, and failed recovery cleanup.
    pub fn open(options: MacosVirtualizationProviderOptions) -> Result<Self, ProviderError> {
        require_supported_host()?;
        verify_helper(
            options.helper_executable(),
            options.helper_digest(),
            options.helper_code_requirement(),
        )
        .map_err(|_| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let template = load_template(
            options.template_manifest(),
            options.template_manifest_digest(),
        )
        .map_err(|_| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        if !trust_material_is_separate(&options, &template) {
            return Err(known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            ));
        }
        require_root_owned_provider_ancestry(options.provider_root()).map_err(|_| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let root =
            SecureRoot::open_or_create(options.provider_root(), options.provider_target().clone())
                .map_err(|_| {
                    known(
                        ProviderErrorKind::InvalidConfiguration,
                        ProviderStage::CreateWorkspace,
                    )
                })?;
        verify_vm_storage(&options, &template, false).map_err(|_| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let provider_id = ProviderId::new("macos-virtualization").map_err(|_| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let capabilities = ProviderCapabilities::new(PROVIDER_CAPABILITIES).map_err(|_| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let (mut journal, mut snapshot) = LifecycleJournal::open(&root).map_err(|error| {
            let kind = if error.kind() == std::io::ErrorKind::WouldBlock {
                ProviderErrorKind::Conflict
            } else {
                ProviderErrorKind::LocalStorage
            };
            known(kind, ProviderStage::Validate)
        })?;
        validate_snapshot_paths(&snapshot)?;
        reconcile_orphans(&options, &root, &mut journal, &mut snapshot)?;
        verify_vm_storage(&options, &template, true).map_err(|_| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let state = restore_state(&provider_id, journal, snapshot)?;
        Ok(Self {
            inner: Arc::new(ProviderInner {
                provider_id,
                capabilities,
                options,
                template,
                root,
                state: Mutex::new(state),
            }),
        })
    }
}

impl fmt::Debug for MacosVirtualizationProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosVirtualizationProvider")
            .field("provider_id", &self.inner.provider_id)
            .field("capabilities", &self.inner.capabilities)
            .finish_non_exhaustive()
    }
}

impl SandboxProvider for MacosVirtualizationProvider {
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
        self.inner.create(spec, cancellation)
    }

    fn attach(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError> {
        self.inner.attach(handle, cancellation)
    }

    fn inspect(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        self.inner.inspect(handle, cancellation)
    }

    fn destroy(
        &self,
        request: &DestroySandbox,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        self.inner.destroy(request, cancellation)
    }
}

pub(crate) struct SandboxEntry {
    pub(crate) handle: SandboxHandle,
    pub(crate) generation: SandboxGeneration,
    pub(crate) profile: EnvironmentProfile,
    pub(crate) custody: SandboxCustody,
    pub(crate) workspace: TargetPath,
    pub(crate) scratch: TargetPath,
    pub(crate) operation_lock: Mutex<()>,
    pub(crate) endpoint_state: Mutex<crate::endpoint::EndpointState>,
    pub(crate) vm: Mutex<Option<VmProcess>>,
    resources: ResourceLimits,
    phase: Mutex<DurableEntryPhase>,
}

impl SandboxEntry {
    pub(crate) fn state(&self) -> Result<SandboxState, ()> {
        self.phase
            .lock()
            .map(|phase| match *phase {
                DurableEntryPhase::Intent => SandboxState::Created,
                DurableEntryPhase::Running => SandboxState::Running,
                DurableEntryPhase::Destroying => SandboxState::Stopped,
            })
            .map_err(|_| ())
    }

    fn set_phase(&self, phase: DurableEntryPhase) -> Result<(), ()> {
        *self.phase.lock().map_err(|_| ())? = phase;
        Ok(())
    }

    fn record(&self) -> Result<SandboxRecord, ProviderError> {
        Ok(SandboxRecord::new(
            self.handle.clone(),
            self.generation,
            self.profile.clone(),
            self.state().map_err(|()| local(ProviderStage::Inspect))?,
        ))
    }

    fn inspection(&self) -> Result<SandboxInspection, ProviderError> {
        Ok(SandboxInspection::new(
            self.handle.clone(),
            self.generation,
            self.custody,
            self.profile.clone(),
            self.state().map_err(|()| local(ProviderStage::Inspect))?,
        ))
    }
}

pub(crate) struct ProviderInner {
    provider_id: ProviderId,
    capabilities: ProviderCapabilities,
    pub(crate) options: MacosVirtualizationProviderOptions,
    template: VerifiedTemplate,
    pub(crate) root: SecureRoot,
    state: Mutex<ProviderState>,
}

impl fmt::Debug for ProviderInner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderInner")
            .field("provider_id", &self.provider_id)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl ProviderInner {
    fn lock_state(
        &self,
        stage: ProviderStage,
    ) -> Result<MutexGuard<'_, ProviderState>, ProviderError> {
        self.state.lock().map_err(|_| local(stage))
    }

    fn create(
        &self,
        spec: &SandboxSpec,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError> {
        validate_spec(&self.options, &self.template, spec)?;
        require_not_cancelled(cancellation, ProviderStage::Validate)?;
        let fingerprint = spec_fingerprint(spec)?;
        let mut state = self.lock_state(ProviderStage::CreateSandbox)?;
        if let Some(replay) = state.create_operations.get(&spec.operation_id()) {
            if replay.fingerprint != fingerprint || replay.custody != spec.custody() {
                return Err(known(ProviderErrorKind::Conflict, ProviderStage::Validate));
            }
            if let Some(entry) = state.entries.get(&replay.handle).cloned() {
                return resume_create(self, &mut state, &entry, cancellation);
            }
            if let Some(tombstone) = state.tombstones.get(&replay.handle) {
                return Ok(SandboxRecord::new(
                    tombstone.handle.clone(),
                    tombstone.generation,
                    tombstone.profile.clone(),
                    SandboxState::Absent,
                ));
            }
            return Err(known(
                ProviderErrorKind::InvalidState,
                ProviderStage::CreateSandbox,
            ));
        }
        if !state.entries.is_empty() {
            return Err(known(ProviderErrorKind::Conflict, ProviderStage::Validate));
        }
        let scratch = spec.scratch().ok_or_else(|| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        let handle = SandboxHandle::new(self.provider_id.clone(), OperationId::new().to_string())
            .map_err(|_| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::CreateSandbox,
            )
        })?;
        let attempt = attempt_target(&self.options, handle.opaque())?;
        self.root
            .require_directory_absent(&attempt)
            .map_err(|error| preflight_error(&error))?;
        let resources = spec.resources();
        let entry = Arc::new(SandboxEntry {
            handle: handle.clone(),
            generation: spec.generation(),
            profile: spec.profile().attestation().clone(),
            custody: spec.custody(),
            workspace: spec.workspace().clone(),
            scratch: scratch.clone(),
            operation_lock: Mutex::new(()),
            endpoint_state: Mutex::new(crate::endpoint::EndpointState::default()),
            vm: Mutex::new(None),
            resources,
            phase: Mutex::new(DurableEntryPhase::Intent),
        });
        let event = DurableEvent::CreateIntent {
            create: DurableCreate {
                operation_id: spec.operation_id(),
                fingerprint,
                handle: handle.opaque().to_owned(),
                custody: spec.custody(),
            },
            entry: durable_entry(&entry, DurableEntryPhase::Intent),
        };
        state.journal.append(event).map_err(|_| {
            uncertain(
                ProviderErrorKind::LocalStorage,
                ProviderStage::CreateSandbox,
                handle.clone(),
            )
        })?;
        state.create_operations.insert(
            spec.operation_id(),
            CreateReplay {
                fingerprint,
                handle: handle.clone(),
                custody: spec.custody(),
            },
        );
        state.entries.insert(handle, Arc::clone(&entry));
        resume_create(self, &mut state, &entry, cancellation)
    }

    fn attach(
        self: &Arc<Self>,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError> {
        require_not_cancelled(cancellation, ProviderStage::Attach)?;
        self.require_owned_handle(handle, ProviderStage::Attach)?;
        let state = self.lock_state(ProviderStage::Attach)?;
        let entry = state
            .entries
            .get(handle)
            .ok_or_else(|| known(ProviderErrorKind::NotFound, ProviderStage::Attach))?;
        if entry.state().map_err(|()| local(ProviderStage::Attach))? != SandboxState::Running {
            return Err(known(
                ProviderErrorKind::InvalidState,
                ProviderStage::Attach,
            ));
        }
        Ok(Box::new(MacosVirtualizationEndpoint::new(
            Arc::clone(self),
            Arc::clone(entry),
        )))
    }

    fn inspect(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        require_not_cancelled(cancellation, ProviderStage::Inspect)?;
        self.require_owned_handle(handle, ProviderStage::Inspect)?;
        let state = self.lock_state(ProviderStage::Inspect)?;
        if let Some(entry) = state.entries.get(handle) {
            return entry.inspection();
        }
        state
            .tombstones
            .get(handle)
            .map(Tombstone::inspection)
            .ok_or_else(|| known(ProviderErrorKind::NotFound, ProviderStage::Inspect))
    }

    fn destroy(
        &self,
        request: &DestroySandbox,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        require_not_cancelled(cancellation, ProviderStage::DestroySandbox)?;
        self.require_owned_handle(request.handle(), ProviderStage::VerifyOwnership)?;
        let mut state = self.lock_state(ProviderStage::DestroySandbox)?;
        if let Some(replay) = state.destroy_operations.get(&request.operation_id()) {
            return if replay.request == *request {
                Ok(replay.disposition)
            } else {
                Err(known(
                    ProviderErrorKind::Conflict,
                    ProviderStage::VerifyOwnership,
                ))
            };
        }
        if let Some(pending) = state
            .pending_destroy_operations
            .get(&request.operation_id())
            .cloned()
        {
            if pending.request != *request {
                return Err(known(
                    ProviderErrorKind::Conflict,
                    ProviderStage::VerifyOwnership,
                ));
            }
            let entry = state
                .entries
                .get(request.handle())
                .cloned()
                .ok_or_else(invalid_journal)?;
            return complete_destroy(self, &mut state, &entry, &pending, cancellation);
        }
        if state
            .pending_destroy_operations
            .values()
            .any(|pending| pending.request.handle() == request.handle())
        {
            return Err(known(
                ProviderErrorKind::Conflict,
                ProviderStage::VerifyOwnership,
            ));
        }
        if let Some(tombstone) = state.tombstones.get(request.handle()) {
            if tombstone.generation != request.generation() {
                return Err(known(
                    ProviderErrorKind::OwnershipMismatch,
                    ProviderStage::VerifyOwnership,
                ));
            }
            let event = DurableEvent::DestroyAbsent {
                request: durable_destroy_request(request, &tombstone.profile, tombstone.custody),
            };
            state.journal.append(event).map_err(|_| {
                uncertain(
                    ProviderErrorKind::LocalStorage,
                    ProviderStage::DestroySandbox,
                    request.handle().clone(),
                )
            })?;
            state.destroy_operations.insert(
                request.operation_id(),
                DestroyReplay {
                    request: request.clone(),
                    disposition: DestroyDisposition::AlreadyAbsent,
                },
            );
            return Ok(DestroyDisposition::AlreadyAbsent);
        }
        let entry = state
            .entries
            .get(request.handle())
            .cloned()
            .ok_or_else(|| known(ProviderErrorKind::NotFound, ProviderStage::VerifyOwnership))?;
        if entry.generation != request.generation() {
            return Err(known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
            ));
        }
        let durable = durable_destroy_request(request, &entry.profile, entry.custody);
        state
            .journal
            .append(DurableEvent::DestroyIntent { request: durable })
            .map_err(|_| {
                uncertain(
                    ProviderErrorKind::LocalStorage,
                    ProviderStage::DestroySandbox,
                    entry.handle.clone(),
                )
            })?;
        let pending = PendingDestroy {
            request: request.clone(),
            profile: entry.profile.clone(),
        };
        state
            .pending_destroy_operations
            .insert(request.operation_id(), pending.clone());
        entry
            .set_phase(DurableEntryPhase::Destroying)
            .map_err(|()| local(ProviderStage::DestroySandbox))?;
        complete_destroy(self, &mut state, &entry, &pending, cancellation)
    }

    fn require_owned_handle(
        &self,
        handle: &SandboxHandle,
        stage: ProviderStage,
    ) -> Result<(), ProviderError> {
        if handle.provider() == &self.provider_id {
            Ok(())
        } else {
            Err(known(ProviderErrorKind::OwnershipMismatch, stage))
        }
    }
}

fn complete_destroy(
    provider: &ProviderInner,
    state: &mut ProviderState,
    entry: &Arc<SandboxEntry>,
    pending: &PendingDestroy,
    cancellation: &dyn Cancellation,
) -> Result<DestroyDisposition, ProviderError> {
    if pending.request.handle() != &entry.handle
        || pending.request.generation() != entry.generation
        || pending.profile != entry.profile
    {
        return Err(invalid_journal());
    }
    let operation = quiesce(entry, cancellation)?;
    if let Some(mut vm) = entry
        .vm
        .lock()
        .map_err(|_| local(ProviderStage::DestroySandbox))?
        .take()
    {
        vm.stop().map_err(|_| {
            uncertain(
                ProviderErrorKind::AdapterUnavailable,
                ProviderStage::DestroySandbox,
                entry.handle.clone(),
            )
        })?;
    }
    remove_attempt(&provider.options, &provider.root, entry.handle.opaque()).map_err(|_| {
        uncertain(
            ProviderErrorKind::LocalStorage,
            ProviderStage::DestroyWorkspace,
            entry.handle.clone(),
        )
    })?;
    let operation_id = pending.request.operation_id();
    state
        .journal
        .append(DurableEvent::DestroyComplete { operation_id })
        .map_err(|_| {
            uncertain(
                ProviderErrorKind::LocalStorage,
                ProviderStage::DestroySandbox,
                entry.handle.clone(),
            )
        })?;
    state.pending_destroy_operations.remove(&operation_id);
    state.entries.remove(&entry.handle);
    state.tombstones.insert(
        entry.handle.clone(),
        Tombstone {
            handle: entry.handle.clone(),
            generation: entry.generation,
            profile: entry.profile.clone(),
            custody: entry.custody,
        },
    );
    state.destroy_operations.insert(
        operation_id,
        DestroyReplay {
            request: pending.request.clone(),
            disposition: DestroyDisposition::Destroyed,
        },
    );
    drop(operation);
    Ok(DestroyDisposition::Destroyed)
}

struct ProviderState {
    journal: LifecycleJournal,
    create_operations: HashMap<OperationId, CreateReplay>,
    pending_destroy_operations: HashMap<OperationId, PendingDestroy>,
    destroy_operations: HashMap<OperationId, DestroyReplay>,
    entries: HashMap<SandboxHandle, Arc<SandboxEntry>>,
    tombstones: HashMap<SandboxHandle, Tombstone>,
}

struct CreateReplay {
    fingerprint: [u8; 32],
    handle: SandboxHandle,
    custody: SandboxCustody,
}

#[derive(Clone)]
struct PendingDestroy {
    request: DestroySandbox,
    profile: EnvironmentProfile,
}

struct DestroyReplay {
    request: DestroySandbox,
    disposition: DestroyDisposition,
}

struct Tombstone {
    handle: SandboxHandle,
    generation: SandboxGeneration,
    profile: EnvironmentProfile,
    custody: SandboxCustody,
}

impl Tombstone {
    fn inspection(&self) -> SandboxInspection {
        SandboxInspection::new(
            self.handle.clone(),
            self.generation,
            self.custody,
            self.profile.clone(),
            SandboxState::Absent,
        )
    }
}

fn resume_create(
    provider: &ProviderInner,
    state: &mut ProviderState,
    entry: &Arc<SandboxEntry>,
    cancellation: &dyn Cancellation,
) -> Result<SandboxRecord, ProviderError> {
    if entry
        .state()
        .map_err(|()| local(ProviderStage::CreateSandbox))?
        == SandboxState::Running
    {
        return entry.record();
    }
    if cancellation.is_cancelled() {
        return Err(uncertain(
            ProviderErrorKind::Cancelled,
            ProviderStage::CreateWorkspace,
            entry.handle.clone(),
        ));
    }
    let attempt = attempt_target(&provider.options, entry.handle.opaque())?;
    let mut vm = entry
        .vm
        .lock()
        .map_err(|_| local(ProviderStage::CreateSandbox))?;
    if vm.is_none() {
        provider
            .root
            .remove_owned_tree(&attempt)
            .and_then(|()| provider.root.ensure_owned_directory(&attempt))
            .map_err(|_| {
                uncertain(
                    ProviderErrorKind::LocalStorage,
                    ProviderStage::CreateWorkspace,
                    entry.handle.clone(),
                )
            })?;
        let mut launched = VmProcess::launch(
            &provider.options,
            &provider.template,
            entry.handle.opaque(),
            &attempt_path(&provider.options, entry.handle.opaque()),
            entry.resources,
            cancellation,
        )
        .map_err(|error| {
            let kind = match error.kind() {
                std::io::ErrorKind::Interrupted => ProviderErrorKind::Cancelled,
                std::io::ErrorKind::TimedOut => ProviderErrorKind::TimedOut,
                _ => ProviderErrorKind::AdapterUnavailable,
            };
            uncertain(kind, ProviderStage::CreateSandbox, entry.handle.clone())
        })?;
        launched
            .prepare_directories(&entry.workspace, &entry.scratch, cancellation)
            .map_err(|error| {
                let kind = match error.kind() {
                    std::io::ErrorKind::Interrupted => ProviderErrorKind::Cancelled,
                    std::io::ErrorKind::TimedOut => ProviderErrorKind::TimedOut,
                    _ => ProviderErrorKind::AdapterUnavailable,
                };
                uncertain(kind, ProviderStage::CreateWorkspace, entry.handle.clone())
            })?;
        *vm = Some(launched);
    }
    state
        .journal
        .append(DurableEvent::CreateReady {
            handle: entry.handle.opaque().to_owned(),
        })
        .map_err(|_| {
            uncertain(
                ProviderErrorKind::LocalStorage,
                ProviderStage::CreateSandbox,
                entry.handle.clone(),
            )
        })?;
    entry
        .set_phase(DurableEntryPhase::Running)
        .map_err(|()| local(ProviderStage::CreateSandbox))?;
    drop(vm);
    entry.record()
}

fn validate_spec(
    _options: &MacosVirtualizationProviderOptions,
    template: &VerifiedTemplate,
    spec: &SandboxSpec,
) -> Result<(), ProviderError> {
    let scratch = spec.scratch().ok_or_else(|| {
        known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
        )
    })?;
    let valid = matches!(
        spec.profile().launch(),
        SandboxLaunch::VirtualMachine { template_manifest }
            if *template_manifest == template.manifest_digest
    ) && spec.profile().id() == &template.profile_id
        && spec.profile().workspace().platform() == TargetPlatform::Posix
        && spec.workspace().platform() == TargetPlatform::Posix
        && scratch.platform() == TargetPlatform::Posix
        && is_strict_descendant(spec.workspace(), spec.profile().workspace())
        && !overlaps(spec.workspace(), scratch)
        && spec.network() == NetworkPolicy::Disabled
        && spec.root_filesystem() == RootFilesystemPolicy::Writable
        && spec.privilege() == SandboxPrivilegePolicy::Unprivileged
        && spec.resources().cpu_millis().is_multiple_of(1_000)
        && spec.resources().cpu_millis() / 1_000 >= template.minimum_cpu_count
        && spec.resources().memory_bytes() >= template.minimum_memory_bytes
        && spec.resources().pids() == template.process_limit
        && spec.services().is_empty()
        && spec.has_coherent_resource_contract()
        && !spec
            .profile()
            .default_environment()
            .values()
            .iter()
            .any(automata_ci_execution::EnvironmentVariable::is_secret);
    valid.then_some(()).ok_or_else(|| {
        known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
        )
    })
}

fn spec_fingerprint(spec: &SandboxSpec) -> Result<[u8; 32], ProviderError> {
    let mut digest = Sha256::new();
    fingerprint_field(&mut digest, b"automata-macos-virtualization-spec-v2");
    fingerprint_custody(&mut digest, spec.custody());
    fingerprint_field(&mut digest, &spec.generation().get().to_le_bytes());
    fingerprint_field(
        &mut digest,
        &serde_json::to_vec(spec.profile().attestation())
            .map_err(|_| local(ProviderStage::Validate))?,
    );
    fingerprint_field(&mut digest, spec.profile().workspace().as_str().as_bytes());
    fingerprint_field(&mut digest, spec.workspace().as_str().as_bytes());
    if let Some(scratch) = spec.scratch() {
        fingerprint_field(&mut digest, b"scratch-present");
        fingerprint_field(&mut digest, scratch.as_str().as_bytes());
    } else {
        fingerprint_field(&mut digest, b"scratch-absent");
    }
    fingerprint_field(
        &mut digest,
        &[
            spec.network() as u8,
            spec.root_filesystem() as u8,
            spec.privilege() as u8,
            0,
        ],
    );
    let resources = spec.resources();
    fingerprint_field(&mut digest, &resources.memory_bytes().to_le_bytes());
    fingerprint_field(&mut digest, &resources.cpu_millis().to_le_bytes());
    fingerprint_field(&mut digest, &resources.pids().to_le_bytes());
    if let SandboxLaunch::VirtualMachine { template_manifest } = spec.profile().launch() {
        fingerprint_field(&mut digest, template_manifest.as_bytes());
    }
    if let Some(allocation) = spec.resource_allocation() {
        fingerprint_field(
            &mut digest,
            &serde_json::to_vec(&allocation).map_err(|_| local(ProviderStage::Validate))?,
        );
    }
    for variable in spec.profile().default_environment().values() {
        fingerprint_field(&mut digest, variable.name().as_str().as_bytes());
        fingerprint_field(&mut digest, variable.value().expose().as_bytes());
        fingerprint_field(&mut digest, &[u8::from(variable.is_secret())]);
    }
    Ok(digest.finalize().into())
}

fn fingerprint_custody(digest: &mut Sha256, custody: SandboxCustody) {
    match custody {
        SandboxCustody::ProfileAdmission { runner_id } => {
            fingerprint_field(digest, b"profile-admission");
            fingerprint_field(digest, runner_id.as_uuid().as_bytes());
        }
        SandboxCustody::Job {
            runner_id,
            slot_ordinal,
        } => {
            fingerprint_field(digest, b"job");
            fingerprint_field(digest, runner_id.as_uuid().as_bytes());
            fingerprint_field(digest, &slot_ordinal.get().to_be_bytes());
        }
    }
}

fn fingerprint_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(
        u64::try_from(value.len())
            .expect("sandbox fingerprint fields fit in u64")
            .to_le_bytes(),
    );
    digest.update(value);
}

fn durable_entry(entry: &SandboxEntry, phase: DurableEntryPhase) -> DurableEntry {
    DurableEntry {
        handle: entry.handle.opaque().to_owned(),
        generation: entry.generation.get(),
        profile: entry.profile.clone(),
        custody: entry.custody,
        workspace: entry.workspace.as_str().to_owned(),
        scratch: entry.scratch.as_str().to_owned(),
        phase,
    }
}

fn durable_destroy_request(
    request: &DestroySandbox,
    profile: &EnvironmentProfile,
    custody: SandboxCustody,
) -> DurableDestroyRequest {
    DurableDestroyRequest {
        operation_id: request.operation_id(),
        handle: request.handle().opaque().to_owned(),
        generation: request.generation().get(),
        profile: profile.clone(),
        custody,
    }
}

fn restore_state(
    provider_id: &ProviderId,
    journal: LifecycleJournal,
    snapshot: DurableSnapshot,
) -> Result<ProviderState, ProviderError> {
    let mut state = ProviderState {
        journal,
        create_operations: HashMap::new(),
        pending_destroy_operations: HashMap::new(),
        destroy_operations: HashMap::new(),
        entries: HashMap::new(),
        tombstones: HashMap::new(),
    };
    if !snapshot.entries.is_empty() || !snapshot.pending_destroys.is_empty() {
        return Err(invalid_journal());
    }
    for durable in snapshot.tombstones.into_values() {
        let tombstone = restored_tombstone(provider_id, durable)?;
        if state
            .tombstones
            .insert(tombstone.handle.clone(), tombstone)
            .is_some()
        {
            return Err(invalid_journal());
        }
    }
    for durable in snapshot.creates.into_values() {
        let handle = recovered_handle(provider_id, &durable.handle)?;
        let observed_custody = state
            .entries
            .get(&handle)
            .map(|entry| entry.custody)
            .or_else(|| {
                state
                    .tombstones
                    .get(&handle)
                    .map(|tombstone| tombstone.custody)
            });
        if observed_custody != Some(durable.custody)
            || state
                .create_operations
                .insert(
                    durable.operation_id,
                    CreateReplay {
                        fingerprint: durable.fingerprint,
                        handle,
                        custody: durable.custody,
                    },
                )
                .is_some()
        {
            return Err(invalid_journal());
        }
    }
    for durable in snapshot.destroys.into_values() {
        let handle = recovered_handle(provider_id, &durable.request.handle)?;
        let request = DestroySandbox::new(
            durable.request.operation_id,
            handle,
            recovered_generation(durable.request.generation).map_err(|_| invalid_journal())?,
        );
        if state
            .destroy_operations
            .insert(
                request.operation_id(),
                DestroyReplay {
                    request,
                    disposition: durable.disposition.into(),
                },
            )
            .is_some()
        {
            return Err(invalid_journal());
        }
    }
    Ok(state)
}

fn validate_snapshot_paths(snapshot: &DurableSnapshot) -> Result<(), ProviderError> {
    let mut paths: Vec<(TargetPath, TargetPath)> = Vec::new();
    for entry in snapshot.entries.values() {
        let workspace =
            TargetPath::posix(entry.workspace.clone()).map_err(|_| invalid_journal())?;
        let scratch = TargetPath::posix(entry.scratch.clone()).map_err(|_| invalid_journal())?;
        if !validate_posix_path(&workspace)
            || !validate_posix_path(&scratch)
            || overlaps(&workspace, &scratch)
            || paths.iter().any(|(other_workspace, other_scratch)| {
                overlaps(&workspace, other_workspace)
                    || overlaps(&workspace, other_scratch)
                    || overlaps(&scratch, other_workspace)
                    || overlaps(&scratch, other_scratch)
            })
        {
            return Err(invalid_journal());
        }
        paths.push((workspace, scratch));
    }
    Ok(())
}

fn reconcile_orphans(
    options: &MacosVirtualizationProviderOptions,
    root: &SecureRoot,
    journal: &mut LifecycleJournal,
    snapshot: &mut DurableSnapshot,
) -> Result<(), ProviderError> {
    let entries: Vec<_> = snapshot.entries.values().cloned().collect();
    for entry in entries {
        let pending = snapshot
            .pending_destroys
            .values()
            .find(|request| request.handle == entry.handle)
            .cloned();
        let request = if let Some(pending) = pending {
            pending
        } else {
            let request = DurableDestroyRequest {
                operation_id: OperationId::new(),
                handle: entry.handle.clone(),
                generation: entry.generation,
                profile: entry.profile.clone(),
                custody: entry.custody,
            };
            journal
                .append_to_snapshot(
                    snapshot,
                    &DurableEvent::DestroyIntent {
                        request: request.clone(),
                    },
                )
                .map_err(|_| local(ProviderStage::DestroySandbox))?;
            request
        };
        remove_attempt(options, root, &entry.handle)
            .map_err(|_| local(ProviderStage::DestroyWorkspace))?;
        journal
            .append_to_snapshot(
                snapshot,
                &DurableEvent::DestroyComplete {
                    operation_id: request.operation_id,
                },
            )
            .map_err(|_| local(ProviderStage::DestroySandbox))?;
    }
    Ok(())
}

fn restored_tombstone(
    provider_id: &ProviderId,
    durable: DurableTombstone,
) -> Result<Tombstone, ProviderError> {
    if durable.completed_sequence == 0 {
        return Err(invalid_journal());
    }
    Ok(Tombstone {
        handle: recovered_handle(provider_id, &durable.handle)?,
        generation: recovered_generation(durable.generation).map_err(|_| invalid_journal())?,
        profile: durable.profile,
        custody: durable.custody,
    })
}

fn recovered_handle(
    provider_id: &ProviderId,
    opaque: &str,
) -> Result<SandboxHandle, ProviderError> {
    SandboxHandle::new(provider_id.clone(), opaque.to_owned()).map_err(|_| invalid_journal())
}

fn quiesce<'a>(
    entry: &'a SandboxEntry,
    _cancellation: &dyn Cancellation,
) -> Result<MutexGuard<'a, ()>, ProviderError> {
    let deadline = Instant::now() + QUIESCE_TIMEOUT;
    loop {
        match entry.operation_lock.try_lock() {
            Ok(operation) => return Ok(operation),
            Err(TryLockError::Poisoned(_)) => return Err(local(ProviderStage::DestroySandbox)),
            Err(TryLockError::WouldBlock) if Instant::now() >= deadline => {
                return Err(uncertain(
                    ProviderErrorKind::TimedOut,
                    ProviderStage::DestroySandbox,
                    entry.handle.clone(),
                ));
            }
            Err(TryLockError::WouldBlock) => {
                std::thread::sleep(QUIESCE_POLL_INTERVAL);
            }
        }
    }
}

fn attempt_target(
    options: &MacosVirtualizationProviderOptions,
    handle: &str,
) -> Result<TargetPath, ProviderError> {
    TargetPath::posix(format!(
        "{}/attempts/{handle}",
        options.provider_target().as_str().trim_end_matches('/')
    ))
    .map_err(|_| invalid_journal())
}

fn attempt_path(options: &MacosVirtualizationProviderOptions, handle: &str) -> PathBuf {
    options.provider_root().join("attempts").join(handle)
}

fn acquire_attempt_lock(root: &Path, handle: &str, timeout: Duration) -> std::io::Result<File> {
    let lock_path = root.join("attempts").join(handle).join(".vm.lock");
    let deadline = Instant::now() + timeout;
    loop {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(file),
            Err(_) if Instant::now() >= deadline => {
                return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
            }
            Err(_) => std::thread::sleep(QUIESCE_POLL_INTERVAL),
        }
    }
}

fn remove_attempt(
    options: &MacosVirtualizationProviderOptions,
    root: &SecureRoot,
    handle: &str,
) -> std::io::Result<()> {
    let attempt = attempt_target(options, handle).map_err(|_| std::io::ErrorKind::InvalidData)?;
    match root.require_directory_absent(&attempt) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _lock = acquire_attempt_lock(
                options.provider_root(),
                handle,
                options.stop_timeout() + QUIESCE_TIMEOUT,
            )?;
            root.remove_owned_tree(&attempt)
        }
        Err(error) => Err(error),
    }
}

fn require_supported_host() -> Result<(), ProviderError> {
    if !cfg!(target_arch = "aarch64") {
        return Err(known(
            ProviderErrorKind::UnsupportedPlatform,
            ProviderStage::Validate,
        ));
    }
    let output = Command::new("/usr/bin/sw_vers")
        .args(["-productVersion"])
        .env_clear()
        .output()
        .map_err(|_| {
            known(
                ProviderErrorKind::UnsupportedPlatform,
                ProviderStage::Validate,
            )
        })?;
    if output.status.success() && supported_product_version(&output.stdout) {
        Ok(())
    } else {
        Err(known(
            ProviderErrorKind::UnsupportedPlatform,
            ProviderStage::Validate,
        ))
    }
}

fn supported_product_version(output: &[u8]) -> bool {
    std::str::from_utf8(output)
        .ok()
        .and_then(|version| version.trim().split('.').next())
        .and_then(|major| major.parse::<u32>().ok())
        .is_some_and(|major| major >= 15)
}

fn normalized_absolute_host_path(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(Component::RootDir))
        && components.clone().next().is_some()
        && components.all(|component| matches!(component, Component::Normal(_)))
        && path.to_str().is_some()
}

fn normalized_volume_uuid(value: &str) -> Option<String> {
    let normalized = value.to_ascii_uppercase();
    let valid = normalized.len() == 36
        && normalized.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase()
            }
        });
    valid.then_some(normalized)
}

fn valid_helper_code_requirement(value: &str) -> bool {
    const PREFIX: &str = "identifier \"";
    const MIDDLE: &str = "\" and anchor apple generic and certificate leaf[subject.OU] = \"";
    let Some(remainder) = value.strip_prefix(PREFIX) else {
        return false;
    };
    let Some((identifier, team)) = remainder.split_once(MIDDLE) else {
        return false;
    };
    let Some(team) = team.strip_suffix('"') else {
        return false;
    };
    let identifier_valid = identifier.len() <= 255
        && identifier.split('.').count() >= 2
        && identifier.split('.').all(|component| {
            !component.is_empty()
                && component.len() <= 63
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && component
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && component
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        });
    identifier_valid
        && team.len() == 10
        && team
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

#[derive(serde::Deserialize)]
struct DiskInfo {
    #[serde(rename = "VolumeUUID")]
    volume_uuid: String,
    #[serde(rename = "DeviceIdentifier")]
    device_identifier: String,
    #[serde(rename = "FilesystemType")]
    filesystem_type: String,
    #[serde(rename = "Writable")]
    writable: bool,
    #[serde(rename = "GlobalPermissionsEnabled")]
    global_permissions_enabled: bool,
    #[serde(rename = "APFSContainerReference")]
    apfs_container_reference: String,
}

#[derive(serde::Deserialize)]
struct ApfsInventory {
    #[serde(rename = "Containers")]
    containers: Vec<ApfsContainer>,
}

#[derive(serde::Deserialize)]
struct ApfsContainer {
    #[serde(rename = "ContainerReference")]
    container_reference: String,
    #[serde(rename = "CapacityCeiling")]
    capacity_ceiling: u64,
    #[serde(rename = "CapacityFree")]
    capacity_free: u64,
    #[serde(rename = "PhysicalStores")]
    physical_stores: Vec<ApfsPhysicalStore>,
    #[serde(rename = "Volumes")]
    volumes: Vec<ApfsVolume>,
}

#[derive(serde::Deserialize)]
struct ApfsPhysicalStore {
    #[serde(rename = "DeviceIdentifier")]
    device_identifier: String,
}

#[derive(Clone, serde::Deserialize)]
struct ApfsVolume {
    #[serde(rename = "APFSVolumeUUID")]
    volume_uuid: String,
    #[serde(rename = "DeviceIdentifier")]
    device_identifier: String,
    #[serde(rename = "CapacityQuota")]
    capacity_quota: u64,
    #[serde(rename = "CapacityInUse")]
    capacity_in_use: u64,
    #[serde(rename = "Roles")]
    roles: Vec<String>,
}

struct DedicatedApfsStorage {
    container_reference: String,
    capacity_ceiling: u64,
    capacity_free: u64,
    physical_stores: Vec<ApfsPhysicalStore>,
    volume: ApfsVolume,
}

#[derive(serde::Deserialize)]
struct PhysicalStoreInfo {
    #[serde(rename = "ParentWholeDisk")]
    parent_whole_disk: String,
}

#[derive(serde::Deserialize)]
struct WholeDiskInfo {
    #[serde(rename = "DeviceIdentifier")]
    device_identifier: String,
    #[serde(rename = "WholeDisk")]
    whole_disk: bool,
    #[serde(rename = "VirtualOrPhysical")]
    virtual_or_physical: String,
    #[serde(rename = "BusProtocol")]
    bus_protocol: String,
    #[serde(rename = "Internal")]
    internal: bool,
    #[serde(rename = "SystemImage")]
    system_image: bool,
}

fn diskutil_plist(arguments: &[&str]) -> std::io::Result<Vec<u8>> {
    let output = Command::new("/usr/sbin/diskutil")
        .args(arguments)
        .env_clear()
        .output()?;
    if !output.status.success()
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_DISKUTIL_PLIST_BYTES
    {
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    Ok(output.stdout)
}

fn filesystem_device(path: &Path) -> std::io::Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    let output = Command::new("/bin/df")
        .args(["-P", "--", value])
        .env_clear()
        .output()?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let output = std::str::from_utf8(&output.stdout)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    let device = output
        .lines()
        .last()
        .and_then(|line| line.split_ascii_whitespace().next())
        .and_then(|device| device.strip_prefix("/dev/"))
        .filter(|device| {
            device.starts_with("disk") && device.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    Ok(device.to_owned())
}

fn disk_info<T: DeserializeOwned>(device: &str) -> std::io::Result<T> {
    let plist = diskutil_plist(&["info", "-plist", device])?;
    let json = plist_to_json(&plist, MAX_DISKUTIL_PLIST_BYTES)?;
    serde_json::from_slice(&json).map_err(|_| std::io::ErrorKind::InvalidData.into())
}

fn physical_storage_is_non_virtual(stores: &[ApfsPhysicalStore]) -> std::io::Result<bool> {
    if stores.is_empty() {
        return Ok(false);
    }
    for store in stores {
        let store_info: PhysicalStoreInfo = disk_info(&store.device_identifier)?;
        let whole: WholeDiskInfo = disk_info(&store_info.parent_whole_disk)?;
        if !whole_disk_is_physical(&whole)
            || whole.device_identifier != store_info.parent_whole_disk
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn whole_disk_is_physical(info: &WholeDiskInfo) -> bool {
    let physical = info.virtual_or_physical.eq_ignore_ascii_case("physical");
    // Apple Silicon internal media currently reports `Unknown` with the
    // Apple Fabric bus even on physical hardware. Accept only that narrowly
    // identifiable case; all other unknown and virtual backing is rejected.
    let apple_fabric = info.virtual_or_physical.eq_ignore_ascii_case("unknown")
        && info.internal
        && info.bus_protocol.eq_ignore_ascii_case("apple fabric");
    info.whole_disk
        && (physical || apple_fabric)
        && !info.bus_protocol.eq_ignore_ascii_case("disk image")
        && !info.system_image
}

fn dedicated_apfs_storage(uuid: &str) -> std::io::Result<DedicatedApfsStorage> {
    let plist = diskutil_plist(&["apfs", "list", "-plist"])?;
    let json = plist_to_json(&plist, MAX_DISKUTIL_PLIST_BYTES)?;
    let inventory: ApfsInventory =
        serde_json::from_slice(&json).map_err(|_| std::io::ErrorKind::InvalidData)?;
    select_dedicated_apfs_storage(inventory, uuid)
}

fn select_dedicated_apfs_storage(
    inventory: ApfsInventory,
    uuid: &str,
) -> std::io::Result<DedicatedApfsStorage> {
    let container = inventory
        .containers
        .into_iter()
        .find(|container| {
            container
                .volumes
                .iter()
                .any(|volume| normalized_volume_uuid(&volume.volume_uuid).as_deref() == Some(uuid))
        })
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    if container.volumes.len() != 1 {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let volume = container
        .volumes
        .first()
        .cloned()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    Ok(DedicatedApfsStorage {
        container_reference: container.container_reference,
        capacity_ceiling: container.capacity_ceiling,
        capacity_free: container.capacity_free,
        physical_stores: container.physical_stores,
        volume,
    })
}

fn verify_vm_storage(
    options: &MacosVirtualizationProviderOptions,
    template: &VerifiedTemplate,
    require_clone_capacity: bool,
) -> std::io::Result<()> {
    let paths = [
        options.provider_root(),
        options.template_manifest(),
        &template.disk_image,
        &template.auxiliary_storage,
    ];
    let device = filesystem_device(options.provider_root())?;
    let root_device = options.provider_root().metadata()?.dev();
    if paths.into_iter().any(|path| {
        !path
            .metadata()
            .is_ok_and(|metadata| metadata.dev() == root_device)
    }) {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let info: DiskInfo = disk_info(&device)?;
    let boot_info: DiskInfo = disk_info(&filesystem_device(Path::new("/"))?)?;
    let storage = dedicated_apfs_storage(options.storage_volume_uuid())?;
    let physical_storage = physical_storage_is_non_virtual(&storage.physical_stores)?;
    let required_free = template
        .disk_image
        .metadata()?
        .len()
        .checked_add(template.auxiliary_storage.metadata()?.len())
        .and_then(|bytes| bytes.checked_add(MINIMUM_STORAGE_HEADROOM))
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    let quota_free = storage
        .volume
        .capacity_quota
        .checked_sub(storage.volume.capacity_in_use)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::PermissionDenied))?;
    let valid = info.filesystem_type == "apfs"
        && info.writable
        && info.global_permissions_enabled
        && normalized_volume_uuid(&info.volume_uuid).as_deref()
            == Some(options.storage_volume_uuid())
        && info.device_identifier == device
        && info.device_identifier == storage.volume.device_identifier
        && info.apfs_container_reference == storage.container_reference
        && storage.container_reference != boot_info.apfs_container_reference
        && physical_storage
        && storage.volume.roles.is_empty()
        && storage.volume.capacity_quota == options.storage_quota_bytes()
        && storage.capacity_ceiling >= storage.volume.capacity_quota
        && (!require_clone_capacity
            || quota_free >= required_free && storage.capacity_free >= required_free);
    valid
        .then_some(())
        .ok_or_else(|| std::io::ErrorKind::PermissionDenied.into())
}

fn require_root_owned_provider_ancestry(provider_root: &Path) -> std::io::Result<()> {
    let parent = provider_root
        .parent()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    for ancestor in parent.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
    }
    Ok(())
}

fn trust_material_is_separate(
    options: &MacosVirtualizationProviderOptions,
    template: &VerifiedTemplate,
) -> bool {
    let paths = [
        options.helper_executable(),
        options.template_manifest(),
        &template.disk_image,
        &template.auxiliary_storage,
    ];
    paths
        .iter()
        .all(|path| !path.starts_with(options.provider_root()))
        && paths
            .iter()
            .enumerate()
            .all(|(index, path)| paths[index + 1..].iter().all(|other| path != other))
}

fn preflight_error(error: &std::io::Error) -> ProviderError {
    let kind = if error.kind() == std::io::ErrorKind::AlreadyExists {
        ProviderErrorKind::Conflict
    } else {
        ProviderErrorKind::LocalStorage
    };
    known(kind, ProviderStage::CreateWorkspace)
}

fn require_not_cancelled(
    cancellation: &dyn Cancellation,
    stage: ProviderStage,
) -> Result<(), ProviderError> {
    if cancellation.is_cancelled() {
        Err(known(ProviderErrorKind::Cancelled, stage))
    } else {
        Ok(())
    }
}

fn invalid_journal() -> ProviderError {
    known(
        ProviderErrorKind::InvalidConfiguration,
        ProviderStage::Validate,
    )
}

const fn known(kind: ProviderErrorKind, stage: ProviderStage) -> ProviderError {
    ProviderError::new(kind, stage, OperationOutcome::KnownNoEffect, None)
}

const fn local(stage: ProviderStage) -> ProviderError {
    known(ProviderErrorKind::LocalStorage, stage)
}

fn uncertain(
    kind: ProviderErrorKind,
    stage: ProviderStage,
    handle: SandboxHandle,
) -> ProviderError {
    ProviderError::new(kind, stage, OperationOutcome::Uncertain, Some(handle))
}

#[cfg(test)]
mod tests {
    use super::{
        ApfsContainer, ApfsInventory, ApfsPhysicalStore, ApfsVolume, WholeDiskInfo,
        normalized_volume_uuid, select_dedicated_apfs_storage, supported_product_version,
        valid_helper_code_requirement, whole_disk_is_physical,
    };

    #[test]
    fn virtualization_provider_requires_macos_15_or_newer() {
        for supported in [b"15.0\n".as_slice(), b"15.7.1", b"26.0"] {
            assert!(supported_product_version(supported));
        }
        for unsupported in [b"14.7.6\n".as_slice(), b"0", b"", b"macOS 15", &[0xff]] {
            assert!(!supported_product_version(unsupported));
        }
    }

    #[test]
    fn storage_uuid_is_strict_and_canonical() {
        assert_eq!(
            normalized_volume_uuid("01234567-89ab-cdef-0123-456789abcdef").as_deref(),
            Some("01234567-89AB-CDEF-0123-456789ABCDEF")
        );
        for invalid in [
            "",
            "0123456789ABCDEF0123456789ABCDEF",
            "01234567-89AB-CDEG-0123-456789ABCDEF",
            "01234567-89AB-CDEF-0123-456789ABCDEFF",
        ] {
            assert!(normalized_volume_uuid(invalid).is_none());
        }
    }

    #[test]
    fn helper_requirement_is_exactly_identifier_anchor_and_team() {
        assert!(valid_helper_code_requirement(
            "identifier \"dev.automata.macos-vm-helper\" and anchor apple generic and certificate leaf[subject.OU] = \"ABCDEFGHIJ\""
        ));
        for invalid in [
            "identifier \"dev.automata.macos-vm-helper\" and anchor apple generic",
            "identifier \"dev.automata.macos-vm-helper\" or anchor apple generic and certificate leaf[subject.OU] = \"ABCDEFGHIJ\"",
            "identifier \"dev..helper\" and anchor apple generic and certificate leaf[subject.OU] = \"ABCDEFGHIJ\"",
            "identifier \"dev.automata.helper\" and anchor apple generic and certificate leaf[subject.OU] = \"teamid1234\"",
        ] {
            assert!(!valid_helper_code_requirement(invalid));
        }
    }

    #[test]
    fn storage_volume_must_be_alone_in_its_apfs_container() {
        let uuid = "01234567-89AB-CDEF-0123-456789ABCDEF";
        let target = ApfsVolume {
            volume_uuid: uuid.to_owned(),
            device_identifier: "disk9s1".to_owned(),
            capacity_quota: 256 * 1024 * 1024 * 1024,
            capacity_in_use: 16 * 1024 * 1024 * 1024,
            roles: Vec::new(),
        };
        let inventory = |volumes| ApfsInventory {
            containers: vec![ApfsContainer {
                container_reference: "disk9".to_owned(),
                capacity_ceiling: 300 * 1024 * 1024 * 1024,
                capacity_free: 280 * 1024 * 1024 * 1024,
                physical_stores: vec![ApfsPhysicalStore {
                    device_identifier: "disk8s2".to_owned(),
                }],
                volumes,
            }],
        };

        let selected = select_dedicated_apfs_storage(inventory(vec![target.clone()]), uuid)
            .expect("one dedicated volume");
        assert_eq!(selected.volume.device_identifier, "disk9s1");
        assert!(
            select_dedicated_apfs_storage(inventory(vec![target.clone(), target]), uuid).is_err(),
            "a sibling volume weakens the fixed storage boundary"
        );
    }

    #[test]
    fn physical_store_classification_is_fail_closed() {
        let info = |classification: &str, bus: &str, internal: bool| WholeDiskInfo {
            device_identifier: "disk0".to_owned(),
            whole_disk: true,
            virtual_or_physical: classification.to_owned(),
            bus_protocol: bus.to_owned(),
            internal,
            system_image: false,
        };

        assert!(whole_disk_is_physical(&info("Physical", "USB", false)));
        assert!(whole_disk_is_physical(&info(
            "Unknown",
            "Apple Fabric",
            true
        )));
        assert!(!whole_disk_is_physical(&info("Virtual", "PCI", true)));
        assert!(!whole_disk_is_physical(&info("Unknown", "USB", true)));
        assert!(!whole_disk_is_physical(&info(
            "Unknown",
            "Apple Fabric",
            false
        )));

        let mut system_image = info("Physical", "USB", false);
        system_image.system_image = true;
        assert!(!whole_disk_is_physical(&system_image));
    }
}
