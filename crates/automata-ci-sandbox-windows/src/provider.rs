use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use automata_ci_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, EnvironmentProfile, ExecutionEndpoint,
    NetworkPolicy, OperationId, OperationOutcome, ProviderCapabilities, ProviderError,
    ProviderErrorKind, ProviderId, ProviderStage, ResourceLimits, RootFilesystemPolicy,
    SandboxCapability, SandboxGeneration, SandboxHandle, SandboxInspection, SandboxLaunch,
    SandboxPrivilegePolicy, SandboxProvider, SandboxRecord, SandboxSpec, SandboxState, TargetPath,
    TargetPlatform,
};
use processkit::{Mechanism, ProcessGroup, ProcessGroupOptions};
use sha2::{Digest as _, Sha256};

use crate::{
    endpoint::WindowsExecutionEndpoint,
    filesystem::{
        ensure_base_directory, ensure_owned_directory, remove_owned_tree,
        require_owned_directory_absent,
    },
    path::{is_strict_descendant, overlaps, validate_windows_path},
    persistence::{
        DurableCreate, DurableDestroy, DurableDestroyDisposition, DurableDestroyRequest,
        DurableEntry, DurableEntryPhase, DurableEvent, DurableSnapshot, DurableTombstone,
        LifecycleJournal,
    },
};

const DESTROY_QUIESCE_TIMEOUT: Duration = Duration::from_secs(5);
const DESTROY_POLL_INTERVAL: Duration = Duration::from_millis(10);

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
    SandboxCapability::ResourceLimits,
];

pub(crate) const ENDPOINT_CAPABILITIES: [SandboxCapability; 4] = [
    SandboxCapability::Exec,
    SandboxCapability::CopyTo,
    SandboxCapability::CopyFrom,
    SandboxCapability::EnvironmentInjection,
];

/// Immutable host root admitted for trusted native Windows sandboxes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsSandboxProviderOptions {
    provider_root: PathBuf,
    provider_target: TargetPath,
}

impl WindowsSandboxProviderOptions {
    /// Creates a provider configuration from one dedicated durable host root.
    ///
    /// Sandbox requests must choose distinct workspace and scratch directories
    /// that are strict descendants of this root.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration failure for a non-Unicode, non-Windows,
    /// ambiguous, or drive-root path.
    pub fn new(provider_root: impl Into<PathBuf>) -> Result<Self, ProviderError> {
        let provider_root = provider_root.into();
        let provider_target = provider_root
            .to_str()
            .ok_or_else(|| {
                known(
                    ProviderErrorKind::InvalidConfiguration,
                    ProviderStage::Validate,
                )
            })?
            .trim_end_matches('\\');
        let provider_target = TargetPath::windows(provider_target.to_owned()).map_err(|_| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        if !validate_windows_path(&provider_target) {
            return Err(known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            ));
        }
        Ok(Self {
            provider_root,
            provider_target,
        })
    }

    /// Returns the dedicated host root for all provider-owned directories.
    #[must_use]
    pub fn provider_root(&self) -> &Path {
        &self.provider_root
    }

    pub(crate) const fn provider_target(&self) -> &TargetPath {
        &self.provider_target
    }
}

/// Trusted native Windows provider backed by one Job Object per sandbox.
///
/// Clones share exact lifecycle and replay state. This adapter provides process
/// containment and hard resource limits but deliberately advertises host
/// network and host filesystem semantics rather than container isolation.
#[derive(Clone)]
pub struct WindowsSandboxProvider {
    inner: Arc<ProviderInner>,
}

impl WindowsSandboxProvider {
    /// Opens the provider and prepares its dedicated allowlist root.
    ///
    /// Every existing component is checked for a Windows reparse point before
    /// use. Missing roots are created and checked again before the provider is
    /// exposed.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the roots cannot be prepared without
    /// following a reparse point or when fixed capabilities cannot be built.
    pub fn open(options: WindowsSandboxProviderOptions) -> Result<Self, ProviderError> {
        ensure_base_directory(options.provider_target()).map_err(|_| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::CreateWorkspace,
            )
        })?;
        let provider_id = ProviderId::new("windows-native").map_err(|_| {
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
        let (journal, snapshot) =
            LifecycleJournal::open(options.provider_root()).map_err(|_| {
                known(
                    ProviderErrorKind::InvalidConfiguration,
                    ProviderStage::Validate,
                )
            })?;
        let mut state = restore_state(&options, &provider_id, journal, snapshot)?;
        reconcile_recovered_entries(&mut state)?;
        Ok(Self {
            inner: Arc::new(ProviderInner {
                provider_id,
                capabilities,
                options,
                state: Mutex::new(state),
            }),
        })
    }
}

impl fmt::Debug for WindowsSandboxProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsSandboxProvider")
            .field("provider_id", &self.inner.provider_id)
            .field("capabilities", &self.inner.capabilities)
            .finish_non_exhaustive()
    }
}

impl SandboxProvider for WindowsSandboxProvider {
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
    memory_bytes: u64,
    cpu_millis: u32,
    pids: u32,
    pub(crate) group: Mutex<Option<Arc<ProcessGroup>>>,
    pub(crate) operation_lock: Mutex<()>,
    pub(crate) endpoint_state: Mutex<crate::endpoint::EndpointState>,
    phase: Mutex<DurableEntryPhase>,
    quiesced: AtomicBool,
}

impl SandboxEntry {
    pub(crate) fn state(&self) -> Result<SandboxState, ()> {
        let phase = *self.phase.lock().map_err(|_| ())?;
        if self.quiesced.load(Ordering::Acquire) && phase != DurableEntryPhase::Degraded {
            Ok(SandboxState::Stopped)
        } else {
            Ok(phase_state(phase))
        }
    }

    fn phase(&self) -> Result<DurableEntryPhase, ()> {
        self.phase.lock().map(|phase| *phase).map_err(|_| ())
    }

    fn set_phase(&self, phase: DurableEntryPhase) -> Result<(), ()> {
        *self.phase.lock().map_err(|_| ())? = phase;
        Ok(())
    }

    pub(crate) fn group(&self) -> Result<Option<Arc<ProcessGroup>>, ()> {
        self.group.lock().map(|group| group.clone()).map_err(|_| ())
    }

    fn set_group(&self, group: Option<Arc<ProcessGroup>>) -> Result<(), ()> {
        *self.group.lock().map_err(|_| ())? = group;
        Ok(())
    }

    fn quiesce(&self) {
        self.quiesced.store(true, Ordering::Release);
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

const fn phase_state(phase: DurableEntryPhase) -> SandboxState {
    match phase {
        DurableEntryPhase::Intent
        | DurableEntryPhase::WorkspaceReady
        | DurableEntryPhase::ScratchReady => SandboxState::Created,
        DurableEntryPhase::Running => SandboxState::Running,
        DurableEntryPhase::Destroying => SandboxState::Stopped,
        DurableEntryPhase::Degraded => SandboxState::Degraded,
    }
}

pub(crate) struct ProviderInner {
    provider_id: ProviderId,
    capabilities: ProviderCapabilities,
    options: WindowsSandboxProviderOptions,
    state: Mutex<ProviderState>,
}

impl fmt::Debug for ProviderInner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderInner")
            .field("provider_id", &self.provider_id)
            .field("capabilities", &self.capabilities)
            .field("options", &self.options)
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
        let fingerprint = spec_fingerprint(spec);
        if cancellation.is_cancelled() {
            return Err(known(ProviderErrorKind::Cancelled, ProviderStage::Validate));
        }
        let mut state = self.lock_state(ProviderStage::CreateSandbox)?;
        if let Some(replay) = state.create_operations.get(&spec.operation_id()) {
            if replay.fingerprint != fingerprint {
                return Err(known(ProviderErrorKind::Conflict, ProviderStage::Validate));
            }
            if let Some(entry) = state.entries.get(&replay.handle).cloned() {
                return resume_create(&mut state, spec, &entry, cancellation);
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
        if active_paths_conflict(&state, spec) {
            return Err(known(ProviderErrorKind::Conflict, ProviderStage::Validate));
        }

        let scratch = spec.scratch().ok_or_else(|| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::Validate,
            )
        })?;
        require_owned_directory_absent(spec.workspace())
            .map_err(|error| preflight_error(&error))?;
        require_owned_directory_absent(scratch).map_err(|error| preflight_error(&error))?;

        let handle = SandboxHandle::new(self.provider_id.clone(), OperationId::new().to_string())
            .map_err(|_| {
            known(
                ProviderErrorKind::InvalidConfiguration,
                ProviderStage::CreateSandbox,
            )
        })?;
        let group = create_process_group(spec)?;
        let resources = spec.resources();
        let entry = Arc::new(SandboxEntry {
            handle: handle.clone(),
            generation: spec.generation(),
            profile: spec.profile().attestation().clone(),
            workspace: spec.workspace().clone(),
            scratch: scratch.clone(),
            memory_bytes: resources.memory_bytes(),
            cpu_millis: resources.cpu_millis(),
            pids: resources.pids(),
            group: Mutex::new(Some(group)),
            operation_lock: Mutex::new(()),
            endpoint_state: Mutex::new(crate::endpoint::EndpointState::default()),
            phase: Mutex::new(DurableEntryPhase::Intent),
            quiesced: AtomicBool::new(false),
        });
        let event = DurableEvent::CreateIntent {
            create: DurableCreate {
                operation_id: spec.operation_id(),
                fingerprint,
                handle: handle.opaque().to_owned(),
            },
            entry: durable_entry(&entry, DurableEntryPhase::Intent),
        };
        if state
            .append_event(event, ProviderStage::CreateSandbox)
            .is_err()
        {
            state.create_operations.insert(
                spec.operation_id(),
                CreateReplay {
                    fingerprint,
                    handle: handle.clone(),
                },
            );
            state.entries.insert(handle.clone(), Arc::clone(&entry));
            if let Ok(Some(group)) = entry.group() {
                let _ = group.kill_all();
            }
            return Err(uncertain_handle_error(
                ProviderErrorKind::LocalStorage,
                ProviderStage::CreateSandbox,
                handle,
            ));
        }
        state.create_operations.insert(
            spec.operation_id(),
            CreateReplay {
                fingerprint,
                handle: handle.clone(),
            },
        );
        state.entries.insert(handle.clone(), Arc::clone(&entry));
        resume_create(&mut state, spec, &entry, cancellation)
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
        if entry
            .group()
            .map_err(|()| local(ProviderStage::Attach))?
            .is_none()
        {
            return Err(known(
                ProviderErrorKind::InvalidState,
                ProviderStage::Attach,
            ));
        }
        Ok(Box::new(WindowsExecutionEndpoint::new(
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
            let exact = replay.request == *request;
            let disposition = replay.disposition;
            return if exact {
                Ok(disposition)
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
            return complete_pending_destroy(&mut state, &entry, &pending);
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
            let disposition = DestroyDisposition::AlreadyAbsent;
            let event = DurableEvent::DestroyAbsent {
                request: durable_destroy_request(request, &tombstone.profile),
            };
            let sequence = state
                .append_event(event, ProviderStage::DestroySandbox)
                .map_err(|_| {
                    uncertain_handle_error(
                        ProviderErrorKind::LocalStorage,
                        ProviderStage::DestroySandbox,
                        request.handle().clone(),
                    )
                })?;
            state.destroy_operations.insert(
                request.operation_id(),
                DestroyReplay {
                    request: request.clone(),
                    disposition,
                    completed_sequence: sequence,
                },
            );
            return Ok(disposition);
        }
        let entry =
            Arc::clone(state.entries.get(request.handle()).ok_or_else(|| {
                known(ProviderErrorKind::NotFound, ProviderStage::VerifyOwnership)
            })?);
        if entry.generation != request.generation() {
            return Err(known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::VerifyOwnership,
            ));
        }
        let pending = PendingDestroy {
            request: request.clone(),
            profile: entry.profile.clone(),
        };
        begin_destroy_intent(&mut state, &entry, pending.clone())?;
        complete_pending_destroy(&mut state, &entry, &pending)
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

fn begin_destroy_intent(
    state: &mut ProviderState,
    entry: &SandboxEntry,
    pending: PendingDestroy,
) -> Result<(), ProviderError> {
    let operation_id = pending.request.operation_id();
    let event = DurableEvent::DestroyIntent {
        request: durable_destroy_request(&pending.request, &pending.profile),
    };
    let append = state.append_event(event, ProviderStage::DestroySandbox);
    if state
        .pending_destroy_operations
        .insert(operation_id, pending)
        .is_some()
    {
        return Err(invalid_journal());
    }
    entry.quiesce();
    if append.is_err() {
        let _ = entry.set_phase(DurableEntryPhase::Destroying);
        drop(quiesce_entry(entry));
        return Err(uncertain_handle_error(
            ProviderErrorKind::LocalStorage,
            ProviderStage::DestroySandbox,
            entry.handle.clone(),
        ));
    }
    if entry.set_phase(DurableEntryPhase::Destroying).is_err() {
        drop(quiesce_entry(entry));
        return Err(uncertain_handle_error(
            ProviderErrorKind::LocalStorage,
            ProviderStage::DestroySandbox,
            entry.handle.clone(),
        ));
    }
    Ok(())
}

fn complete_pending_destroy(
    state: &mut ProviderState,
    entry: &Arc<SandboxEntry>,
    pending: &PendingDestroy,
) -> Result<DestroyDisposition, ProviderError> {
    if state.durability_failed {
        return Err(uncertain_handle_error(
            ProviderErrorKind::LocalStorage,
            ProviderStage::DestroySandbox,
            entry.handle.clone(),
        ));
    }
    if pending.request.handle() != &entry.handle
        || pending.request.generation() != entry.generation
        || pending.profile != entry.profile
    {
        return Err(invalid_journal());
    }
    let operation = match quiesce_entry(entry) {
        Ok(operation) => operation,
        Err(error) => {
            let _ = transition_entry_phase_at(
                state,
                entry,
                DurableEntryPhase::Degraded,
                ProviderStage::DestroySandbox,
            );
            return Err(error);
        }
    };
    let removed = remove_owned_tree(&crate::filesystem::target_to_host(&entry.scratch))
        .and_then(|()| remove_owned_tree(&crate::filesystem::target_to_host(&entry.workspace)));
    if removed.is_err() {
        let _ = transition_entry_phase_at(
            state,
            entry,
            DurableEntryPhase::Degraded,
            ProviderStage::DestroyWorkspace,
        );
        return Err(uncertain_handle_error(
            ProviderErrorKind::LocalStorage,
            ProviderStage::DestroyWorkspace,
            entry.handle.clone(),
        ));
    }
    let operation_id = pending.request.operation_id();
    let sequence = state
        .append_event(
            DurableEvent::DestroyComplete { operation_id },
            ProviderStage::DestroySandbox,
        )
        .map_err(|_| {
            uncertain_handle_error(
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
            completed_sequence: sequence,
        },
    );
    let disposition = DestroyDisposition::Destroyed;
    state.destroy_operations.insert(
        operation_id,
        DestroyReplay {
            request: pending.request.clone(),
            disposition,
            completed_sequence: sequence,
        },
    );
    drop(operation);
    Ok(disposition)
}

fn resume_create(
    state: &mut ProviderState,
    spec: &SandboxSpec,
    entry: &Arc<SandboxEntry>,
    cancellation: &dyn Cancellation,
) -> Result<SandboxRecord, ProviderError> {
    if state.durability_failed {
        return Err(uncertain_handle_error(
            ProviderErrorKind::LocalStorage,
            ProviderStage::CreateSandbox,
            entry.handle.clone(),
        ));
    }
    let mut phase = entry
        .phase()
        .map_err(|()| local(ProviderStage::CreateSandbox))?;
    if phase == DurableEntryPhase::Running {
        if entry
            .group()
            .map_err(|()| local(ProviderStage::CreateSandbox))?
            .is_some()
        {
            return entry.record();
        }
        return Err(uncertain_handle_error(
            ProviderErrorKind::InvalidState,
            ProviderStage::CreateSandbox,
            entry.handle.clone(),
        ));
    }
    if phase == DurableEntryPhase::Destroying {
        return entry.record();
    }
    if phase == DurableEntryPhase::Degraded {
        return Err(known(
            ProviderErrorKind::InvalidState,
            ProviderStage::CreateSandbox,
        ));
    }
    require_create_not_cancelled(cancellation, entry, ProviderStage::CreateWorkspace)?;

    if phase == DurableEntryPhase::Intent {
        prepare_workspace(state, entry)?;
        phase = DurableEntryPhase::WorkspaceReady;
    }
    require_create_not_cancelled(cancellation, entry, ProviderStage::CreateWorkspace)?;
    if phase == DurableEntryPhase::WorkspaceReady {
        prepare_scratch(state, entry)?;
        phase = DurableEntryPhase::ScratchReady;
    }
    require_create_not_cancelled(cancellation, entry, ProviderStage::CreateSandbox)?;
    if phase == DurableEntryPhase::ScratchReady {
        activate_entry(state, spec, entry)?;
    }
    entry.record()
}

fn prepare_workspace(state: &mut ProviderState, entry: &SandboxEntry) -> Result<(), ProviderError> {
    ensure_create_directory(&entry.workspace, entry)?;
    transition_entry_phase(state, entry, DurableEntryPhase::WorkspaceReady)?;
    Ok(())
}

fn prepare_scratch(state: &mut ProviderState, entry: &SandboxEntry) -> Result<(), ProviderError> {
    ensure_create_directory(&entry.workspace, entry)?;
    ensure_create_directory(&entry.scratch, entry)?;
    transition_entry_phase(state, entry, DurableEntryPhase::ScratchReady)?;
    Ok(())
}

fn activate_entry(
    state: &mut ProviderState,
    spec: &SandboxSpec,
    entry: &SandboxEntry,
) -> Result<(), ProviderError> {
    ensure_create_directory(&entry.workspace, entry)?;
    ensure_create_directory(&entry.scratch, entry)?;
    let group = entry
        .group()
        .map_err(|()| local(ProviderStage::CreateSandbox))?
        .map_or_else(|| create_process_group(spec), Ok)
        .map_err(|error| uncertain_from(&error, &entry.handle))?;
    entry.set_group(Some(Arc::clone(&group))).map_err(|()| {
        let _ = group.kill_all();
        uncertain_handle_error(
            ProviderErrorKind::LocalStorage,
            ProviderStage::CreateSandbox,
            entry.handle.clone(),
        )
    })?;
    if transition_entry_phase(state, entry, DurableEntryPhase::Running).is_err() {
        let _ = group.kill_all();
        let _ = entry.set_group(None);
        return Err(uncertain_handle_error(
            ProviderErrorKind::LocalStorage,
            ProviderStage::CreateSandbox,
            entry.handle.clone(),
        ));
    }
    Ok(())
}

fn ensure_create_directory(path: &TargetPath, entry: &SandboxEntry) -> Result<(), ProviderError> {
    ensure_owned_directory(path).map_err(|_| {
        uncertain_handle_error(
            ProviderErrorKind::LocalStorage,
            ProviderStage::CreateWorkspace,
            entry.handle.clone(),
        )
    })?;
    Ok(())
}

fn require_create_not_cancelled(
    cancellation: &dyn Cancellation,
    entry: &SandboxEntry,
    stage: ProviderStage,
) -> Result<(), ProviderError> {
    if cancellation.is_cancelled() {
        Err(uncertain_handle_error(
            ProviderErrorKind::Cancelled,
            stage,
            entry.handle.clone(),
        ))
    } else {
        Ok(())
    }
}

fn transition_entry_phase(
    state: &mut ProviderState,
    entry: &SandboxEntry,
    phase: DurableEntryPhase,
) -> Result<u64, ProviderError> {
    transition_entry_phase_at(state, entry, phase, ProviderStage::CreateSandbox)
}

fn transition_entry_phase_at(
    provider_state: &mut ProviderState,
    entry: &SandboxEntry,
    phase: DurableEntryPhase,
    failure_stage: ProviderStage,
) -> Result<u64, ProviderError> {
    let event = DurableEvent::EntryPhase {
        handle: entry.handle.opaque().to_owned(),
        phase,
    };
    let sequence = provider_state
        .append_event(event, failure_stage)
        .map_err(|_| {
            uncertain_handle_error(
                ProviderErrorKind::LocalStorage,
                failure_stage,
                entry.handle.clone(),
            )
        })?;
    entry.set_phase(phase).map_err(|()| {
        uncertain_handle_error(
            ProviderErrorKind::LocalStorage,
            failure_stage,
            entry.handle.clone(),
        )
    })?;
    Ok(sequence)
}

fn durable_entry(entry: &SandboxEntry, phase: DurableEntryPhase) -> DurableEntry {
    DurableEntry {
        handle: entry.handle.opaque().to_owned(),
        generation: entry.generation.get(),
        profile: entry.profile.clone(),
        workspace: entry.workspace.as_str().to_owned(),
        scratch: entry.scratch.as_str().to_owned(),
        memory_bytes: entry.memory_bytes,
        cpu_millis: entry.cpu_millis,
        pids: entry.pids,
        phase,
    }
}

fn preflight_error(error: &std::io::Error) -> ProviderError {
    let kind = if error.kind() == std::io::ErrorKind::AlreadyExists {
        ProviderErrorKind::Conflict
    } else {
        ProviderErrorKind::LocalStorage
    };
    known(kind, ProviderStage::CreateWorkspace)
}

fn create_process_group(spec: &SandboxSpec) -> Result<Arc<ProcessGroup>, ProviderError> {
    let limits = spec.resources();
    create_process_group_with_limits(limits.memory_bytes(), limits.cpu_millis(), limits.pids())
}

fn create_process_group_with_limits(
    memory_bytes: u64,
    cpu_millis: u32,
    pids: u32,
) -> Result<Arc<ProcessGroup>, ProviderError> {
    let options = ProcessGroupOptions::default()
        .max_memory(memory_bytes)
        .max_processes(pids)
        .cpu_quota(f64::from(cpu_millis) / 1_000.0);
    let group = ProcessGroup::with_options(options).map_err(|_| {
        known(
            ProviderErrorKind::BackendRejected,
            ProviderStage::CreateSandbox,
        )
    })?;
    if group.mechanism() != Mechanism::JobObject {
        return Err(known(
            ProviderErrorKind::UnsupportedPlatform,
            ProviderStage::CreateSandbox,
        ));
    }
    Ok(Arc::new(group))
}

fn active_paths_conflict(state: &ProviderState, spec: &SandboxSpec) -> bool {
    state.entries.values().any(|entry| {
        spec.scratch().is_some_and(|scratch| {
            overlaps(&entry.workspace, spec.workspace())
                || overlaps(&entry.scratch, spec.workspace())
                || overlaps(&entry.workspace, scratch)
                || overlaps(&entry.scratch, scratch)
        })
    })
}

fn quiesce_entry(entry: &SandboxEntry) -> Result<MutexGuard<'_, ()>, ProviderError> {
    entry.quiesce();
    kill_entry_group(entry)?;
    let deadline = Instant::now() + DESTROY_QUIESCE_TIMEOUT;
    loop {
        match entry.operation_lock.try_lock() {
            Ok(operation) => {
                kill_entry_group(entry)?;
                return Ok(operation);
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(uncertain_entry_error(
                    entry,
                    ProviderErrorKind::LocalStorage,
                    ProviderStage::DestroySandbox,
                ));
            }
            Err(TryLockError::WouldBlock) if Instant::now() >= deadline => {
                return Err(uncertain_entry_error(
                    entry,
                    ProviderErrorKind::BackendRejected,
                    ProviderStage::DestroySandbox,
                ));
            }
            Err(TryLockError::WouldBlock) => {
                kill_entry_group(entry)?;
                std::thread::sleep(DESTROY_POLL_INTERVAL);
            }
        }
    }
}

fn kill_entry_group(entry: &SandboxEntry) -> Result<(), ProviderError> {
    if let Some(group) = entry.group().map_err(|()| {
        uncertain_entry_error(
            entry,
            ProviderErrorKind::LocalStorage,
            ProviderStage::DestroySandbox,
        )
    })? {
        group.kill_all().map_err(|_| {
            uncertain_entry_error(
                entry,
                ProviderErrorKind::BackendRejected,
                ProviderStage::DestroySandbox,
            )
        })?;
    }
    Ok(())
}

fn uncertain_entry_error(
    entry: &SandboxEntry,
    kind: ProviderErrorKind,
    stage: ProviderStage,
) -> ProviderError {
    let _ = entry.set_phase(DurableEntryPhase::Degraded);
    ProviderError::new(
        kind,
        stage,
        OperationOutcome::Uncertain,
        Some(entry.handle.clone()),
    )
}

impl Drop for ProviderInner {
    fn drop(&mut self) {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        for entry in state.entries.values() {
            entry.quiesce();
            if let Ok(Some(group)) = entry.group() {
                let _ = group.kill_all();
            }
        }
    }
}

struct ProviderState {
    journal: LifecycleJournal,
    durability_failed: bool,
    create_operations: HashMap<OperationId, CreateReplay>,
    pending_destroy_operations: HashMap<OperationId, PendingDestroy>,
    destroy_operations: HashMap<OperationId, DestroyReplay>,
    entries: HashMap<SandboxHandle, Arc<SandboxEntry>>,
    tombstones: HashMap<SandboxHandle, Tombstone>,
}

impl ProviderState {
    fn append_event(
        &mut self,
        event: DurableEvent,
        stage: ProviderStage,
    ) -> Result<u64, ProviderError> {
        if self.durability_failed {
            return Err(local(stage));
        }
        let sequence = self.journal.append(event).map_err(|_| {
            self.durability_failed = true;
            local(stage)
        })?;
        Ok(sequence)
    }
}

fn restore_state(
    options: &WindowsSandboxProviderOptions,
    provider_id: &ProviderId,
    journal: LifecycleJournal,
    snapshot: DurableSnapshot,
) -> Result<ProviderState, ProviderError> {
    let mut state = ProviderState {
        journal,
        durability_failed: false,
        create_operations: HashMap::new(),
        pending_destroy_operations: HashMap::new(),
        destroy_operations: HashMap::new(),
        entries: HashMap::new(),
        tombstones: HashMap::new(),
    };
    restore_entries(
        &mut state,
        options,
        provider_id,
        snapshot.entries.into_values(),
    )?;
    restore_tombstones(&mut state, provider_id, snapshot.tombstones.into_values())?;
    restore_create_operations(&mut state, provider_id, snapshot.creates.into_values())?;
    restore_pending_destroys(
        &mut state,
        provider_id,
        snapshot.pending_destroys.into_values(),
    )?;
    restore_destroy_operations(&mut state, provider_id, snapshot.destroys.into_values())?;
    Ok(state)
}

fn restore_entries(
    state: &mut ProviderState,
    options: &WindowsSandboxProviderOptions,
    provider_id: &ProviderId,
    entries: impl IntoIterator<Item = DurableEntry>,
) -> Result<(), ProviderError> {
    for durable in entries {
        let handle = recovered_handle(provider_id, &durable.handle)?;
        let generation = recovered_generation(durable.generation)?;
        let workspace = recovered_path(&durable.workspace)?;
        let scratch = recovered_path(&durable.scratch)?;
        ResourceLimits::new(durable.memory_bytes, durable.cpu_millis, durable.pids)
            .map_err(|_| invalid_journal())?;
        if !is_strict_descendant(&workspace, options.provider_target())
            || !is_strict_descendant(&scratch, options.provider_target())
            || overlaps(&workspace, &scratch)
            || state.entries.values().any(|entry| {
                overlaps(&entry.workspace, &workspace)
                    || overlaps(&entry.scratch, &workspace)
                    || overlaps(&entry.workspace, &scratch)
                    || overlaps(&entry.scratch, &scratch)
            })
        {
            return Err(invalid_journal());
        }
        let entry = Arc::new(SandboxEntry {
            handle: handle.clone(),
            generation,
            profile: durable.profile,
            workspace,
            scratch,
            memory_bytes: durable.memory_bytes,
            cpu_millis: durable.cpu_millis,
            pids: durable.pids,
            group: Mutex::new(None),
            operation_lock: Mutex::new(()),
            endpoint_state: Mutex::new(crate::endpoint::EndpointState::default()),
            phase: Mutex::new(durable.phase),
            quiesced: AtomicBool::new(false),
        });
        if state.entries.insert(handle, entry).is_some() {
            return Err(invalid_journal());
        }
    }
    Ok(())
}

fn restore_tombstones(
    state: &mut ProviderState,
    provider_id: &ProviderId,
    tombstones: impl IntoIterator<Item = DurableTombstone>,
) -> Result<(), ProviderError> {
    for durable in tombstones {
        if durable.completed_sequence == 0 {
            return Err(invalid_journal());
        }
        let handle = recovered_handle(provider_id, &durable.handle)?;
        let tombstone = Tombstone {
            handle: handle.clone(),
            generation: recovered_generation(durable.generation)?,
            profile: durable.profile,
            completed_sequence: durable.completed_sequence,
        };
        if state.entries.contains_key(&handle)
            || state.tombstones.insert(handle, tombstone).is_some()
        {
            return Err(invalid_journal());
        }
    }
    Ok(())
}

fn restore_create_operations(
    state: &mut ProviderState,
    provider_id: &ProviderId,
    creates: impl IntoIterator<Item = DurableCreate>,
) -> Result<(), ProviderError> {
    let mut replayed_handles = std::collections::HashSet::new();
    for durable in creates {
        let handle = recovered_handle(provider_id, &durable.handle)?;
        if !(state.entries.contains_key(&handle) || state.tombstones.contains_key(&handle))
            || !replayed_handles.insert(handle.clone())
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
    if state
        .entries
        .keys()
        .chain(state.tombstones.keys())
        .any(|handle| {
            !state
                .create_operations
                .values()
                .any(|replay| &replay.handle == handle)
        })
    {
        return Err(invalid_journal());
    }
    Ok(())
}

fn restore_pending_destroys(
    state: &mut ProviderState,
    provider_id: &ProviderId,
    pending_destroys: impl IntoIterator<Item = DurableDestroyRequest>,
) -> Result<(), ProviderError> {
    let mut pending_handles = std::collections::HashSet::new();
    for durable in pending_destroys {
        let handle = recovered_handle(provider_id, &durable.handle)?;
        let generation = recovered_generation(durable.generation)?;
        let Some(entry) = state.entries.get(&handle) else {
            return Err(invalid_journal());
        };
        if entry.generation != generation
            || entry.profile != durable.profile
            || !matches!(
                entry.phase().map_err(|()| invalid_journal())?,
                DurableEntryPhase::Destroying | DurableEntryPhase::Degraded
            )
            || !pending_handles.insert(handle.clone())
            || state
                .pending_destroy_operations
                .insert(
                    durable.operation_id,
                    PendingDestroy {
                        request: DestroySandbox::new(durable.operation_id, handle, generation),
                        profile: durable.profile,
                    },
                )
                .is_some()
        {
            return Err(invalid_journal());
        }
    }
    if state.entries.values().any(|entry| {
        entry.phase().map_or(true, |phase| {
            matches!(
                phase,
                DurableEntryPhase::Destroying | DurableEntryPhase::Degraded
            ) != pending_handles.contains(&entry.handle)
        })
    }) {
        return Err(invalid_journal());
    }
    Ok(())
}

fn restore_destroy_operations(
    state: &mut ProviderState,
    provider_id: &ProviderId,
    destroys: impl IntoIterator<Item = DurableDestroy>,
) -> Result<(), ProviderError> {
    for durable in destroys {
        let handle = recovered_handle(provider_id, &durable.handle)?;
        let generation = recovered_generation(durable.generation)?;
        let Some(tombstone) = state.tombstones.get(&handle) else {
            return Err(invalid_journal());
        };
        if tombstone.generation != generation {
            return Err(invalid_journal());
        }
        let disposition = match durable.disposition {
            DurableDestroyDisposition::Destroyed => DestroyDisposition::Destroyed,
            DurableDestroyDisposition::AlreadyAbsent => DestroyDisposition::AlreadyAbsent,
        };
        if durable.completed_sequence == 0
            || durable.completed_sequence < tombstone.completed_sequence
            || (disposition == DestroyDisposition::Destroyed
                && durable.completed_sequence != tombstone.completed_sequence)
        {
            return Err(invalid_journal());
        }
        if state
            .destroy_operations
            .insert(
                durable.operation_id,
                DestroyReplay {
                    request: DestroySandbox::new(durable.operation_id, handle, generation),
                    disposition,
                    completed_sequence: durable.completed_sequence,
                },
            )
            .is_some()
        {
            return Err(invalid_journal());
        }
    }
    if state.tombstones.values().any(|tombstone| {
        !state.destroy_operations.values().any(|replay| {
            replay.request.handle() == &tombstone.handle
                && replay.request.generation() == tombstone.generation
                && replay.disposition == DestroyDisposition::Destroyed
                && replay.completed_sequence == tombstone.completed_sequence
        })
    }) {
        return Err(invalid_journal());
    }
    Ok(())
}

fn reconcile_recovered_entries(state: &mut ProviderState) -> Result<(), ProviderError> {
    let entries = state.entries.values().cloned().collect::<Vec<_>>();
    for entry in entries {
        let pending = state
            .pending_destroy_operations
            .values()
            .find(|pending| pending.request.handle() == &entry.handle)
            .cloned();
        let pending = if let Some(pending) = pending {
            pending
        } else {
            let pending = PendingDestroy {
                request: DestroySandbox::new(
                    OperationId::new(),
                    entry.handle.clone(),
                    entry.generation,
                ),
                profile: entry.profile.clone(),
            };
            begin_destroy_intent(state, &entry, pending.clone())?;
            pending
        };
        complete_pending_destroy(state, &entry, &pending)?;
    }
    Ok(())
}

fn recovered_handle(
    provider_id: &ProviderId,
    opaque: &str,
) -> Result<SandboxHandle, ProviderError> {
    SandboxHandle::new(provider_id.clone(), opaque.to_owned()).map_err(|_| invalid_journal())
}

fn recovered_generation(value: u64) -> Result<SandboxGeneration, ProviderError> {
    SandboxGeneration::new(value).map_err(|_| invalid_journal())
}

fn recovered_path(value: &str) -> Result<TargetPath, ProviderError> {
    let path = TargetPath::windows(value.to_owned()).map_err(|_| invalid_journal())?;
    validate_windows_path(&path)
        .then_some(path)
        .ok_or_else(invalid_journal)
}

fn invalid_journal() -> ProviderError {
    known(
        ProviderErrorKind::InvalidConfiguration,
        ProviderStage::Validate,
    )
}

fn spec_fingerprint(spec: &SandboxSpec) -> [u8; 32] {
    let mut digest = Sha256::new();
    fingerprint_field(&mut digest, b"automata-windows-sandbox-spec-v2");
    fingerprint_field(&mut digest, &spec.generation().get().to_le_bytes());
    fingerprint_field(
        &mut digest,
        spec.profile().attestation().id().as_str().as_bytes(),
    );
    fingerprint_field(
        &mut digest,
        spec.profile().attestation().digest().as_bytes(),
    );
    fingerprint_field(&mut digest, spec.profile().workspace().as_str().as_bytes());
    let default_environment = spec.profile().default_environment().values();
    fingerprint_field(
        &mut digest,
        &u64::try_from(default_environment.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for variable in default_environment {
        fingerprint_field(&mut digest, variable.name().as_str().as_bytes());
        fingerprint_field(&mut digest, &[u8::from(variable.is_secret())]);
        fingerprint_field(&mut digest, variable.value().expose().as_bytes());
    }
    fingerprint_field(&mut digest, spec.workspace().as_str().as_bytes());
    if let Some(scratch) = spec.scratch() {
        fingerprint_field(&mut digest, b"scratch-present");
        fingerprint_field(&mut digest, scratch.as_str().as_bytes());
    } else {
        fingerprint_field(&mut digest, b"scratch-absent");
    }
    let resources = spec.resources();
    fingerprint_field(&mut digest, &resources.memory_bytes().to_le_bytes());
    fingerprint_field(&mut digest, &resources.cpu_millis().to_le_bytes());
    fingerprint_field(&mut digest, &resources.pids().to_le_bytes());
    digest.finalize().into()
}

fn fingerprint_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    digest.update(value);
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
    completed_sequence: u64,
}

struct Tombstone {
    handle: SandboxHandle,
    generation: SandboxGeneration,
    profile: EnvironmentProfile,
    completed_sequence: u64,
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

fn validate_spec(
    options: &WindowsSandboxProviderOptions,
    spec: &SandboxSpec,
) -> Result<(), ProviderError> {
    if spec.workspace().platform() != TargetPlatform::Windows
        || spec
            .scratch()
            .is_none_or(|scratch| scratch.platform() != TargetPlatform::Windows)
    {
        return Err(known(
            ProviderErrorKind::UnsupportedPlatform,
            ProviderStage::Validate,
        ));
    }
    let Some(scratch) = spec.scratch() else {
        return Err(known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
        ));
    };
    if !matches!(spec.profile().launch(), SandboxLaunch::Native)
        || spec.network() != NetworkPolicy::Host
        || spec.root_filesystem() != RootFilesystemPolicy::Host
        || spec.privilege() != SandboxPrivilegePolicy::Host
        || !spec.services().is_empty()
    {
        return Err(known(
            ProviderErrorKind::UnsupportedCapability,
            ProviderStage::Validate,
        ));
    }
    if spec.profile().workspace().platform() != TargetPlatform::Windows
        || !validate_windows_path(spec.profile().workspace())
        || !validate_windows_path(spec.workspace())
        || !validate_windows_path(scratch)
        || !is_strict_descendant(spec.profile().workspace(), options.provider_target())
        || !is_strict_descendant(spec.workspace(), spec.profile().workspace())
        || !is_strict_descendant(scratch, options.provider_target())
        || overlaps(spec.workspace(), scratch)
        || !case_unique_environment(spec.profile().default_environment())
        || spec
            .profile()
            .default_environment()
            .values()
            .iter()
            .any(automata_ci_execution::EnvironmentVariable::is_secret)
    {
        return Err(known(
            ProviderErrorKind::InvalidConfiguration,
            ProviderStage::Validate,
        ));
    }
    Ok(())
}

pub(crate) fn case_unique_environment(
    environment: &automata_ci_execution::ExecutionEnvironment,
) -> bool {
    let mut names = std::collections::BTreeSet::new();
    environment
        .values()
        .iter()
        .all(|variable| names.insert(variable.name().as_str().to_lowercase()))
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

fn known(kind: ProviderErrorKind, stage: ProviderStage) -> ProviderError {
    ProviderError::new(kind, stage, OperationOutcome::KnownNoEffect, None)
}

fn uncertain_handle_error(
    kind: ProviderErrorKind,
    stage: ProviderStage,
    handle: SandboxHandle,
) -> ProviderError {
    ProviderError::new(kind, stage, OperationOutcome::Uncertain, Some(handle))
}

fn uncertain_from(error: &ProviderError, handle: &SandboxHandle) -> ProviderError {
    uncertain_handle_error(error.kind(), error.stage(), handle.clone())
}

fn local(stage: ProviderStage) -> ProviderError {
    known(ProviderErrorKind::LocalStorage, stage)
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        path::{Path, PathBuf},
        process::Command as StdCommand,
        thread,
        time::{Duration, Instant},
    };

    use automata_ci_execution::{
        EnvironmentName, EnvironmentProfileId, EnvironmentValue, EnvironmentVariable,
        ExecutionArgv, ExecutionCommand, ExecutionEnvironment, NeverCancelled, SandboxEnvironment,
        Sha256Digest,
    };

    use super::*;

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn ambiguous_destroy_intent_append_kills_live_tree_before_provider_drop() {
        let root = env::temp_dir().join(format!(
            "automata-ci-sandbox-windows-destroy-append-failure-{}",
            OperationId::new()
        ));
        let _root_guard = TestRoot { path: root.clone() };
        let options = WindowsSandboxProviderOptions::new(root.clone()).expect("provider options");
        let provider = WindowsSandboxProvider::open(options.clone()).expect("open provider");
        let profile_workspace = root.join("workspaces");
        let workspace = profile_workspace.join(format!("job-{}", OperationId::new()));
        let scratch = root.join(format!("scratch-{}", OperationId::new()));
        let spec = native_spec(&profile_workspace, &workspace, &scratch);
        let record = provider
            .create(&spec, &NeverCancelled)
            .expect("create sandbox");
        let endpoint = provider
            .attach(record.handle(), &NeverCancelled)
            .expect("attach sandbox");
        let pid_file = scratch.join("descendant.pid");
        let command = descendant_command(&workspace, &pid_file);
        let execution = thread::spawn(move || endpoint.exec(&command, &NeverCancelled));
        let descendant = wait_for_pid(&pid_file, Duration::from_secs(8))
            .expect("long-running descendant publishes its PID");
        assert!(
            wait_for_process_alive(descendant, Duration::from_secs(5)),
            "descendant process {descendant} never became observable"
        );

        provider
            .inner
            .state
            .lock()
            .expect("provider state")
            .journal
            .fail_next_append_after_sync();
        let destroy = DestroySandbox::new(
            OperationId::new(),
            record.handle().clone(),
            record.generation(),
        );
        let error = provider
            .destroy(&destroy, &NeverCancelled)
            .expect_err("ambiguous synced append must fail uncertain");
        assert_eq!(error.kind(), ProviderErrorKind::LocalStorage);
        assert_eq!(error.stage(), ProviderStage::DestroySandbox);
        assert_eq!(error.outcome(), OperationOutcome::Uncertain);
        assert_eq!(error.recovery_handle(), Some(record.handle()));
        assert_process_exited(descendant);
        let _ = execution.join().expect("execution worker must not panic");

        drop(provider);
        let reopened = WindowsSandboxProvider::open(options).expect("reopen provider");
        assert_eq!(
            reopened
                .inspect(record.handle(), &NeverCancelled)
                .expect("inspect reconciled handle")
                .state(),
            SandboxState::Absent
        );
        assert_eq!(
            reopened
                .destroy(&destroy, &NeverCancelled)
                .expect("replay exact durable destroy"),
            DestroyDisposition::Destroyed
        );
        assert!(!workspace.exists());
        assert!(!scratch.exists());
    }

    fn native_spec(profile_workspace: &Path, workspace: &Path, scratch: &Path) -> SandboxSpec {
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.dev/windows-native-x86-64-v1").expect("profile ID"),
            Sha256Digest::from_bytes([0x57; 32]),
        );
        let environment = SandboxEnvironment::native(
            profile,
            target(profile_workspace),
            ExecutionEnvironment::empty(),
        )
        .expect("native environment");
        SandboxSpec::new(
            OperationId::new(),
            SandboxGeneration::new(1).expect("generation"),
            environment,
            target(workspace),
            NetworkPolicy::Host,
            RootFilesystemPolicy::Host,
            ResourceLimits::new(512 * MIB, 4_000, 16).expect("resource limits"),
        )
        .with_privilege(SandboxPrivilegePolicy::Host)
        .with_scratch(target(scratch))
    }

    fn descendant_command(workspace: &Path, pid_file: &Path) -> ExecutionCommand {
        let system_root = system_root();
        let powershell = system_root
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        let script = "$child = Start-Process -FilePath $env:COMSPEC \
                      -ArgumentList '/d','/c','ping -n 30 127.0.0.1 > nul' -PassThru; \
                      [System.IO.File]::WriteAllText(\
                        $env:AUTOMATA_PID_FILE, [string]$child.Id); \
                      [System.Threading.Thread]::Sleep(30000)";
        let arguments = [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let comspec = system_root.join("System32").join("cmd.exe");
        let temp = env::temp_dir();
        let environment = ExecutionEnvironment::new(vec![
            variable("SystemRoot", &system_root),
            variable("WINDIR", &system_root),
            variable("COMSPEC", &comspec),
            variable("TEMP", &temp),
            variable("TMP", &temp),
            variable("AUTOMATA_PID_FILE", pid_file),
        ])
        .expect("execution environment");
        ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(target(&powershell), arguments).expect("PowerShell argv"),
            target(workspace),
            environment,
            Duration::from_mins(1),
            1024 * 1024,
        )
        .expect("execution command")
    }

    fn variable(name: &str, value: &Path) -> EnvironmentVariable {
        EnvironmentVariable::new(
            EnvironmentName::new(name).expect("environment name"),
            EnvironmentValue::new(value.to_str().expect("Unicode test path"))
                .expect("environment value"),
        )
    }

    fn target(path: &Path) -> TargetPath {
        TargetPath::windows(path.to_str().expect("Unicode test path").replace('/', "\\"))
            .expect("absolute Windows target path")
    }

    fn system_root() -> PathBuf {
        PathBuf::from(env::var_os("SystemRoot").expect("SystemRoot is defined"))
    }

    fn wait_for_pid(path: &Path, timeout: Duration) -> Option<u32> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(value) = fs::read_to_string(path)
                && let Ok(pid) = value.trim().parse()
            {
                return Some(pid);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn assert_process_exited(pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while process_is_alive(pid) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(25));
        }
        assert!(!process_is_alive(pid), "descendant process {pid} survived");
    }

    fn wait_for_process_alive(pid: u32, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if process_is_alive(pid) {
                return true;
            }
            thread::sleep(Duration::from_millis(25));
        }
        process_is_alive(pid)
    }

    fn process_is_alive(pid: u32) -> bool {
        let output = StdCommand::new(system_root().join("System32").join("tasklist.exe"))
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
            .expect("query Windows process table");
        let expected = format!("\"{pid}\"");
        String::from_utf8_lossy(&output.stdout).lines().any(|line| {
            line.split(',')
                .nth(1)
                .is_some_and(|value| value == expected)
        })
    }

    struct TestRoot {
        path: PathBuf,
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
