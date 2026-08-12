use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex, MutexGuard, TryLockError},
    time::{Duration, Instant},
};

use automata_ci_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, EnvironmentProfile, ExecutionEndpoint,
    NetworkPolicy, OperationId, OperationOutcome, ProviderCapabilities, ProviderError,
    ProviderErrorKind, ProviderId, ProviderStage, RootFilesystemPolicy, SandboxCapability,
    SandboxGeneration, SandboxHandle, SandboxInspection, SandboxLaunch, SandboxPrivilegePolicy,
    SandboxProvider, SandboxRecord, SandboxResourcePolicy, SandboxSpec, SandboxState, TargetPath,
    TargetPlatform,
};
use sha2::{Digest as _, Sha256};

use crate::{
    endpoint::MacosExecutionEndpoint,
    filesystem::{SecureRoot, require_executable},
    path::{is_strict_descendant, overlaps, validate_posix_path},
    persistence::{
        DurableCreate, DurableDestroyRequest, DurableEntry, DurableEntryPhase, DurableEvent,
        DurableSnapshot, DurableTombstone, LifecycleJournal, recovered_generation,
    },
};

const QUIESCE_TIMEOUT: Duration = Duration::from_secs(5);
const QUIESCE_POLL_INTERVAL: Duration = Duration::from_millis(10);

const PROVIDER_CAPABILITIES: [SandboxCapability; 11] = [
    SandboxCapability::WholeJob,
    SandboxCapability::Attach,
    SandboxCapability::Inspect,
    SandboxCapability::Exec,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::EnvironmentInjection,
    SandboxCapability::HostNetwork,
    SandboxCapability::HostFilesystem,
    SandboxCapability::HostIdentity,
    SandboxCapability::HostResources,
];

pub(crate) const ENDPOINT_CAPABILITIES: [SandboxCapability; 4] = [
    SandboxCapability::Exec,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::EnvironmentInjection,
];

/// Immutable host roots and same-binary supervisor executable for native macOS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacosSandboxProviderOptions {
    provider_root: PathBuf,
    provider_target: TargetPath,
    supervisor_executable: PathBuf,
}

impl MacosSandboxProviderOptions {
    /// Creates a provider configuration rooted at one dedicated private path.
    ///
    /// Sandbox workspace and scratch directories must be distinct strict
    /// descendants of this root. `supervisor_executable` must be the absolute
    /// path of the shipped `automata-runner` binary.
    ///
    /// # Errors
    ///
    /// Rejects non-absolute, non-Unicode, root, non-normalized, or mismatched
    /// POSIX paths.
    pub fn new(
        provider_root: impl Into<PathBuf>,
        supervisor_executable: impl Into<PathBuf>,
    ) -> Result<Self, ProviderError> {
        let provider_root = provider_root.into();
        let supervisor_executable = supervisor_executable.into();
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
            || !supervisor_executable.is_absolute()
            || supervisor_executable.to_str().is_none()
        {
            return Err(known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            ));
        }
        Ok(Self {
            provider_root,
            provider_target,
            supervisor_executable,
        })
    }

    /// Returns the dedicated provider-owned root.
    #[must_use]
    pub fn provider_root(&self) -> &Path {
        &self.provider_root
    }

    /// Returns the exact same-binary supervisor executable.
    #[must_use]
    pub fn supervisor_executable(&self) -> &Path {
        &self.supervisor_executable
    }

    pub(crate) const fn provider_target(&self) -> &TargetPath {
        &self.provider_target
    }
}

/// Trusted native macOS provider backed by supervised POSIX process groups.
///
/// Clones share the exclusive lifecycle lock and all operation-replay state.
/// The provider exposes host-shared semantics and must not be used for
/// untrusted workflows.
#[derive(Clone)]
pub struct MacosSandboxProvider {
    inner: Arc<ProviderInner>,
}

impl MacosSandboxProvider {
    /// Opens and exclusively locks the provider root, then reconciles orphaned
    /// lifecycle entries before accepting work.
    ///
    /// # Errors
    ///
    /// Rejects unsupported macOS hosts, insecure roots or supervisor paths,
    /// concurrent opens, corrupt state, and failed recovery cleanup.
    pub fn open(options: MacosSandboxProviderOptions) -> Result<Self, ProviderError> {
        require_supported_host()?;
        let supervisor = options
            .supervisor_executable()
            .to_str()
            .and_then(|path| TargetPath::posix(path.to_owned()).ok())
            .ok_or_else(|| {
                known(
                    ProviderErrorKind::InvalidConfiguration,
                    ProviderStage::Validate,
                )
            })?;
        require_executable(&supervisor).map_err(|_| {
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
        let provider_id = ProviderId::new("macos-native").map_err(|_| {
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
        validate_snapshot_paths(&options, &snapshot)?;
        reconcile_orphans(&root, &mut journal, &mut snapshot)?;
        let state = restore_state(&provider_id, journal, snapshot)?;
        Ok(Self {
            inner: Arc::new(ProviderInner {
                provider_id,
                capabilities,
                options,
                root,
                state: Mutex::new(state),
            }),
        })
    }
}

impl fmt::Debug for MacosSandboxProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosSandboxProvider")
            .field("provider_id", &self.inner.provider_id)
            .field("capabilities", &self.inner.capabilities)
            .finish_non_exhaustive()
    }
}

impl SandboxProvider for MacosSandboxProvider {
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
    pub(crate) workspace: TargetPath,
    pub(crate) scratch: TargetPath,
    pub(crate) operation_lock: Mutex<()>,
    pub(crate) endpoint_state: Mutex<crate::endpoint::EndpointState>,
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
            self.profile.clone(),
            self.state().map_err(|()| local(ProviderStage::Inspect))?,
        ))
    }
}

pub(crate) struct ProviderInner {
    provider_id: ProviderId,
    capabilities: ProviderCapabilities,
    pub(crate) options: MacosSandboxProviderOptions,
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
        validate_spec(&self.options, spec)?;
        require_not_cancelled(cancellation, ProviderStage::Validate)?;
        let fingerprint = spec_fingerprint(spec)?;
        let mut state = self.lock_state(ProviderStage::CreateSandbox)?;
        if let Some(replay) = state.create_operations.get(&spec.operation_id()) {
            if replay.fingerprint != fingerprint {
                return Err(known(ProviderErrorKind::Conflict, ProviderStage::Validate));
            }
            if let Some(entry) = state.entries.get(&replay.handle).cloned() {
                return resume_create(&self.root, &mut state, &entry, cancellation);
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
        self.root
            .require_directory_absent(spec.workspace())
            .and_then(|()| self.root.require_directory_absent(scratch))
            .map_err(|error| preflight_error(&error))?;
        let handle = SandboxHandle::new(self.provider_id.clone(), OperationId::new().to_string())
            .map_err(|_| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::CreateSandbox,
            )
        })?;
        let entry = Arc::new(SandboxEntry {
            handle: handle.clone(),
            generation: spec.generation(),
            profile: spec.profile().attestation().clone(),
            workspace: spec.workspace().clone(),
            scratch: scratch.clone(),
            operation_lock: Mutex::new(()),
            endpoint_state: Mutex::new(crate::endpoint::EndpointState::default()),
            phase: Mutex::new(DurableEntryPhase::Intent),
        });
        let event = DurableEvent::CreateIntent {
            create: DurableCreate {
                operation_id: spec.operation_id(),
                fingerprint,
                handle: handle.opaque().to_owned(),
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
            },
        );
        state.entries.insert(handle, Arc::clone(&entry));
        resume_create(&self.root, &mut state, &entry, cancellation)
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
        Ok(Box::new(MacosExecutionEndpoint::new(
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
            return complete_destroy(&self.root, &mut state, &entry, &pending, cancellation);
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
                request: durable_destroy_request(request, &tombstone.profile),
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
        let durable = durable_destroy_request(request, &entry.profile);
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
        complete_destroy(&self.root, &mut state, &entry, &pending, cancellation)
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
    root: &SecureRoot,
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
    root.remove_owned_tree(&entry.scratch)
        .and_then(|()| root.remove_owned_tree(&entry.workspace))
        .map_err(|_| {
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
}

impl Tombstone {
    fn inspection(&self) -> SandboxInspection {
        SandboxInspection::new(
            self.handle.clone(),
            self.generation,
            self.profile.clone(),
            SandboxState::Absent,
        )
    }
}

fn resume_create(
    root: &SecureRoot,
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
    root.ensure_owned_directory(&entry.workspace)
        .and_then(|()| root.ensure_owned_directory(&entry.scratch))
        .map_err(|_| {
            uncertain(
                ProviderErrorKind::LocalStorage,
                ProviderStage::CreateWorkspace,
                entry.handle.clone(),
            )
        })?;
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
    entry.record()
}

fn validate_spec(
    options: &MacosSandboxProviderOptions,
    spec: &SandboxSpec,
) -> Result<(), ProviderError> {
    let scratch = spec.scratch().ok_or_else(|| {
        known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
        )
    })?;
    let valid = matches!(spec.profile().launch(), SandboxLaunch::Native)
        && spec.profile().workspace().platform() == TargetPlatform::Posix
        && spec.workspace().platform() == TargetPlatform::Posix
        && scratch.platform() == TargetPlatform::Posix
        && is_strict_descendant(spec.profile().workspace(), options.provider_target())
        && is_strict_descendant(spec.workspace(), spec.profile().workspace())
        && is_strict_descendant(scratch, options.provider_target())
        && !overlaps(spec.workspace(), scratch)
        && spec.network() == NetworkPolicy::Host
        && spec.root_filesystem() == RootFilesystemPolicy::Host
        && spec.privilege() == SandboxPrivilegePolicy::Host
        && spec.resource_policy() == SandboxResourcePolicy::HostShared
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
    fingerprint_field(&mut digest, b"automata-macos-sandbox-spec-v1");
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
            match spec.resource_policy() {
                SandboxResourcePolicy::Enforced(_) => 0,
                SandboxResourcePolicy::HostShared => 1,
            },
        ],
    );
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

fn fingerprint_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    digest.update(value);
}

fn durable_entry(entry: &SandboxEntry, phase: DurableEntryPhase) -> DurableEntry {
    DurableEntry {
        handle: entry.handle.opaque().to_owned(),
        generation: entry.generation.get(),
        profile: entry.profile.clone(),
        workspace: entry.workspace.as_str().to_owned(),
        scratch: entry.scratch.as_str().to_owned(),
        phase,
    }
}

fn durable_destroy_request(
    request: &DestroySandbox,
    profile: &EnvironmentProfile,
) -> DurableDestroyRequest {
    DurableDestroyRequest {
        operation_id: request.operation_id(),
        handle: request.handle().opaque().to_owned(),
        generation: request.generation().get(),
        profile: profile.clone(),
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
    for durable in snapshot.entries.into_values() {
        let handle = recovered_handle(provider_id, &durable.handle)?;
        let entry = Arc::new(SandboxEntry {
            handle: handle.clone(),
            generation: recovered_generation(durable.generation).map_err(|_| invalid_journal())?,
            profile: durable.profile,
            workspace: TargetPath::posix(durable.workspace).map_err(|_| invalid_journal())?,
            scratch: TargetPath::posix(durable.scratch).map_err(|_| invalid_journal())?,
            operation_lock: Mutex::new(()),
            endpoint_state: Mutex::new(crate::endpoint::EndpointState::default()),
            phase: Mutex::new(durable.phase),
        });
        if state.entries.insert(handle, entry).is_some() {
            return Err(invalid_journal());
        }
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
        if !(state.entries.contains_key(&handle) || state.tombstones.contains_key(&handle))
            || state
                .create_operations
                .insert(
                    durable.operation_id,
                    CreateReplay {
                        fingerprint: durable.fingerprint,
                        handle,
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
    if !snapshot.pending_destroys.is_empty() {
        return Err(invalid_journal());
    }
    Ok(state)
}

fn validate_snapshot_paths(
    options: &MacosSandboxProviderOptions,
    snapshot: &DurableSnapshot,
) -> Result<(), ProviderError> {
    let mut paths: Vec<(TargetPath, TargetPath)> = Vec::new();
    for entry in snapshot.entries.values() {
        let workspace =
            TargetPath::posix(entry.workspace.clone()).map_err(|_| invalid_journal())?;
        let scratch = TargetPath::posix(entry.scratch.clone()).map_err(|_| invalid_journal())?;
        if !is_strict_descendant(&workspace, options.provider_target())
            || !is_strict_descendant(&scratch, options.provider_target())
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
        let workspace = TargetPath::posix(entry.workspace).map_err(|_| invalid_journal())?;
        let scratch = TargetPath::posix(entry.scratch).map_err(|_| invalid_journal())?;
        root.remove_owned_tree(&scratch)
            .and_then(|()| root.remove_owned_tree(&workspace))
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
    use super::supported_product_version;

    #[test]
    fn native_provider_requires_macos_15_or_newer() {
        for supported in [b"15.0\n".as_slice(), b"15.7.1", b"26.0"] {
            assert!(supported_product_version(supported));
        }
        for unsupported in [b"14.7.6\n".as_slice(), b"0", b"", b"macOS 15", &[0xff]] {
            assert!(!supported_product_version(unsupported));
        }
    }
}
