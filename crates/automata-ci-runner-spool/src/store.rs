use std::{
    collections::HashSet,
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError},
    time::Instant,
};

use automata_ci_core::Sha256Digest;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::{
    ContentCommitmentDomain, ContentKind, ContentProtectionError, DurableContentRef,
    KeyedContentCommitment, NoopSpoolObserver, OpaqueContentIdentity, ProtectionId,
    RetainedContentError, SpoolCapacityResource, SpoolError, SpoolEvent, SpoolFailureKind,
    SpoolInvariantError, SpoolLimits, SpoolObserver, SpoolOperation, SpoolOperationOutcome,
    SpoolProtectionOperation, SpoolProtectionOutcome, SpoolRoot,
    platform::{PlatformDirectory, SpoolUsage},
};

/// Atomic content-commit boundary exposed to deterministic fault tests.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ContentCommitStage {
    /// A mode-restricted, exclusively created staging file exists.
    StagingCreated,
    /// All protected bytes were written to the staging file but not yet synced.
    DataWritten,
    /// The staging file and its protected bytes were synchronized.
    FileSynced,
    /// The staging entry was atomically renamed to its content-addressed name.
    Renamed,
    /// The containing directory was synchronized after publication.
    DirectorySynced,
}

/// Marker returned by a content-commit fault injector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentCommitFault;

/// Hook for deterministic storage-fault simulation.
pub trait ContentCommitFaultInjector: Send + Sync {
    /// Interrupts a content commit at `stage`.
    ///
    /// # Errors
    ///
    /// Returns [`ContentCommitFault`] when interruption should be simulated.
    fn check(&self, stage: ContentCommitStage) -> Result<(), ContentCommitFault>;
}

/// Fault injector used by ordinary production construction.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoContentCommitFaults;

impl ContentCommitFaultInjector for NoContentCommitFaults {
    fn check(&self, _stage: ContentCommitStage) -> Result<(), ContentCommitFault> {
        Ok(())
    }
}

/// Replaceable authenticated protection boundary for content at rest.
///
/// Implementations must use authenticated encryption and bind the complete
/// [`DurableContentRef`] as associated data. Errors must not contain key or
/// plaintext material.
pub trait ContentProtector: Send + Sync {
    /// Returns a bounded, non-secret key/cipher identifier.
    fn protection_id(&self) -> &ProtectionId;

    /// Reports whether this adapter can authenticate content under `protection_id`.
    ///
    /// Single-key adapters support only their active ID. Rotation-aware
    /// adapters override this method for explicitly configured decrypt-only
    /// IDs. The spool performs this check before observing whether a referenced
    /// object exists, so an unknown key never degrades into an idempotent
    /// removal or missing-content result.
    fn supports_protection_id(&self, protection_id: &ProtectionId) -> bool {
        protection_id == self.protection_id()
    }

    /// Computes a domain-separated PRF commitment with the exact named key.
    ///
    /// The implementation must use secret key material unavailable to a reader
    /// of spool files or journal metadata. Errors must not contain commitment
    /// input or key material.
    ///
    /// # Errors
    ///
    /// Returns [`ContentProtectionError`] when the exact key is unavailable or
    /// the protected commitment operation fails.
    fn keyed_commitment(
        &self,
        protection_id: &ProtectionId,
        domain: ContentCommitmentDomain,
        material_digest: &[u8; 32],
    ) -> Result<[u8; 32], ContentProtectionError>;

    /// Returns the exact encoded bytes this protector will produce for an
    /// endpoint result of `plaintext_bytes` under its active key.
    ///
    /// Implementations must apply the current opaque padded-allocation
    /// contract. This is a protection-authority preflight: success promises
    /// that [`Self::protect`] will emit exactly the returned byte count for the
    /// matching endpoint-result reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContentProtectionError`] when the active protection authority
    /// is unavailable or the plaintext length cannot be protected.
    fn endpoint_result_protected_bytes(
        &self,
        plaintext_bytes: u64,
    ) -> Result<u64, ContentProtectionError>;

    /// Protects plaintext before any filesystem write.
    ///
    /// # Errors
    ///
    /// Returns a secret-free typed failure.
    fn protect(
        &self,
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError>;

    /// Authenticates and opens bytes read from the filesystem.
    ///
    /// # Errors
    ///
    /// Returns a secret-free typed failure.
    fn unprotect(
        &self,
        reference: &DurableContentRef,
        protected: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError>;
}

/// Source of the complete protected-content retain set.
///
/// Reconciliation invokes this object while publication is exclusively fenced,
/// so implementations must capture their durable snapshot inside the call.
pub trait RetainedContentSource: Send + Sync {
    /// Captures all content identities referenced by durable recovery state.
    ///
    /// # Errors
    ///
    /// Returns a bounded, secret-free availability failure.
    fn retained_content(&self) -> Result<Vec<DurableContentRef>, RetainedContentError>;
}

#[derive(Debug, Default)]
struct PublicationState {
    active: u32,
}

#[derive(Debug, Default)]
struct PublicationGate {
    state: Mutex<PublicationState>,
}

impl PublicationGate {
    fn lock(&self) -> MutexGuard<'_, PublicationState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn begin(&self) -> Result<PublicationPermit<'_>, SpoolError> {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Err(SpoolError::ReconciliationInProgress),
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
        };
        state.active = state
            .active
            .checked_add(1)
            .ok_or(SpoolError::CapacityExhausted)?;
        Ok(PublicationPermit {
            gate: self,
            active: true,
        })
    }
}

struct PublicationPermit<'a> {
    gate: &'a PublicationGate,
    active: bool,
}

impl PublicationPermit<'_> {
    fn adopted(&mut self) {
        if self.active {
            let mut state = self.gate.lock();
            state.active -= 1;
            self.active = false;
        }
    }

    fn abandoned(&mut self) {
        if self.active {
            let mut state = self.gate.lock();
            state.active -= 1;
            self.active = false;
        }
    }
}

impl Drop for PublicationPermit<'_> {
    fn drop(&mut self) {
        self.abandoned();
    }
}

/// Payload-first publication receipt held until its journal adoption commits.
///
/// The receipt borrows its spool, so the process lock cannot be released while
/// publication is in flight. Use [`Self::commit_with`] for the journal mutation;
/// a failed attempt returns the still-active receipt for exact retry.
#[must_use = "content publication must be journaled with commit_with or explicitly aborted"]
pub struct DurableContentPublication<'a> {
    reference: DurableContentRef,
    permit: PublicationPermit<'a>,
}

impl fmt::Debug for DurableContentPublication<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableContentPublication")
            .field("reference", &self.reference)
            .field("state", &"in-flight")
            .finish()
    }
}

impl<'a> DurableContentPublication<'a> {
    /// Executes one journal adoption attempt while reconciliation is fenced.
    ///
    /// Success resolves the publication. Failure returns both the exact caller
    /// error and this still-active receipt so the journal can be reopened and
    /// the same semantic mutation retried without exposing an unfenced handle.
    ///
    /// # Errors
    ///
    /// Returns [`PublicationCommitFailure`] with the caller's journal error and
    /// the still-active publication when `commit` fails.
    pub fn commit_with<T, E>(
        mut self,
        commit: impl FnOnce(&DurableContentRef) -> Result<T, E>,
    ) -> Result<T, PublicationCommitFailure<'a, E>> {
        match commit(&self.reference) {
            Ok(value) => {
                self.permit.adopted();
                Ok(value)
            }
            Err(error) => Err(PublicationCommitFailure {
                error,
                publication: self,
            }),
        }
    }

    /// Explicitly abandons publication after a known-not-committed journal
    /// outcome. The next successful reconciliation will reclaim the orphan.
    pub fn abort(mut self) {
        self.permit.abandoned();
    }
}

/// Failed journal adoption paired with the still-fenced publication receipt.
#[must_use = "retry the journal mutation or explicitly abort the publication"]
pub struct PublicationCommitFailure<'a, E> {
    error: E,
    publication: DurableContentPublication<'a>,
}

/// Capacity reserved globally before invoking one endpoint operation.
///
/// The reservation owns one object slot and the protected allocation class for
/// the declared maximum result. Dropping it releases both. Endpoint results can
/// only be published by consuming this value.
#[must_use = "endpoint-result capacity must be consumed or released"]
pub trait EndpointResultCapacityReservation<'store>: Send {
    /// Protects and durably publishes the result while atomically consuming the
    /// reserved capacity.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] for an oversized result, protection, commit, or
    /// poisoned-store failure. Every failure releases the reservation.
    fn persist(
        self: Box<Self>,
        plaintext: &[u8],
    ) -> Result<DurableContentPublication<'store>, SpoolError>;
}

impl<E> fmt::Debug for PublicationCommitFailure<'_, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicationCommitFailure")
            .field("error", &"[REDACTED]")
            .field("publication", &self.publication)
            .finish()
    }
}

impl<'a, E> PublicationCommitFailure<'a, E> {
    /// Splits the caller error from the still-active publication for retry.
    pub fn into_parts(self) -> (E, DurableContentPublication<'a>) {
        (self.error, self.publication)
    }
}

/// Object-safe protected content-store port.
pub trait DurableContentStore: Send + Sync {
    /// Computes a new commitment under the active protection key.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the protection authority is unavailable.
    fn create_keyed_commitment(
        &self,
        domain: ContentCommitmentDomain,
        material_digest: &[u8; 32],
    ) -> Result<KeyedContentCommitment, SpoolError>;

    /// Recomputes a commitment under the exact key named by durable state.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when that exact key is unavailable or protection fails.
    fn recreate_keyed_commitment(
        &self,
        protection_id: &ProtectionId,
        domain: ContentCommitmentDomain,
        material_digest: &[u8; 32],
    ) -> Result<KeyedContentCommitment, SpoolError>;

    /// Reserves global capacity for one endpoint result before provider invocation.
    ///
    /// The reservation accounts for one object and the deterministic padded
    /// protected allocation of `maximum_plaintext_bytes`. It blocks every
    /// competing publisher or reservation that would consume that capacity.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] for an invalid maximum, unavailable protection
    /// authority, exhausted capacity, or poisoned store.
    fn reserve_endpoint_result(
        &self,
        maximum_plaintext_bytes: u64,
    ) -> Result<Box<dyn EndpointResultCapacityReservation<'_> + '_>, SpoolError>;

    /// Protects, verifies, and durably commits immutable content.
    ///
    /// A successful return occurs only after file and directory synchronization.
    /// Re-persisting an identical kind, plaintext, and protection ID authenticates
    /// and reuses the existing object, but returns a fresh publication receipt
    /// that still requires journal adoption.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] for protection, capacity, security, or I/O failure.
    fn persist(
        &self,
        kind: ContentKind,
        plaintext: &[u8],
    ) -> Result<DurableContentPublication<'_>, SpoolError>;

    /// Loads, authenticates, and digest-verifies immutable content.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] if content is missing, altered, inaccessible, or
    /// protected by a different configured adapter.
    fn load(&self, reference: &DurableContentRef) -> Result<Vec<u8>, SpoolError>;

    /// Durably removes content after every journal reference to it is gone.
    ///
    /// Exact content identities may be shared, so callers must not remove a
    /// reference while any recovery record still uses it. Returns `true` when
    /// an object was removed and `false` when the validated, supported reference
    /// was already absent.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] if existing bytes fail authentication, deletion
    /// cannot be synchronized, or the handle is poisoned.
    fn remove(&self, reference: &DurableContentRef) -> Result<bool, SpoolError>;

    /// Retains exactly the identities referenced by one complete durable
    /// journal snapshot and removes payload-first crash leftovers.
    ///
    /// The source is invoked only after excluding every payload-first
    /// publication. Existing retained objects are authenticated before any
    /// orphan is removed. A publication dropped or explicitly aborted before
    /// journal adoption is reclaimed as an unreferenced orphan.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] for a missing/corrupt retained object, unsafe
    /// directory entry, uncertain synchronized deletion, or poisoned handle.
    fn reconcile(&self, retained: &dyn RetainedContentSource) -> Result<(), SpoolError>;
}

/// Trusted construction options for the file spool.
#[derive(Clone)]
pub struct FileSpoolOptions {
    limits: SpoolLimits,
    fault_injector: Arc<dyn ContentCommitFaultInjector>,
    observer: Arc<dyn SpoolObserver>,
}

impl FileSpoolOptions {
    /// Creates options with bounded defaults, no injected faults, and no observer effects.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the object-count and byte limits enforced at open and mutation time.
    #[must_use]
    pub fn with_limits(mut self, limits: SpoolLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces the deterministic commit-boundary fault hook.
    ///
    /// Production callers should retain [`NoContentCommitFaults`]; injectors
    /// exist to verify crash recovery and uncertain-outcome handling.
    #[must_use]
    pub fn with_fault_injector(mut self, injector: Arc<dyn ContentCommitFaultInjector>) -> Self {
        self.fault_injector = injector;
        self
    }

    /// Installs an infallible, identifier-free observer for spool operations.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn SpoolObserver>) -> Self {
        self.observer = observer;
        self
    }
}

impl Default for FileSpoolOptions {
    fn default() -> Self {
        Self {
            limits: SpoolLimits::default(),
            fault_injector: Arc::new(NoContentCommitFaults),
            observer: Arc::new(NoopSpoolObserver),
        }
    }
}

impl fmt::Debug for FileSpoolOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileSpoolOptions")
            .field("limits", &self.limits)
            .field("fault_injector", &"configured")
            .field("observer", &"configured")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct MemoryState {
    usage: SpoolUsage,
    reserved_objects: u32,
    reserved_protected_bytes: u64,
    poisoned: bool,
}

/// Crash-durable immutable content cache with mandatory at-rest protection.
///
/// The filesystem implementation confines no-follow operations beneath one
/// validated host root and holds an exclusive process lock for the lifetime of
/// the value. Publication fencing is process-local; after restart, the caller's
/// durable journal and [`DurableContentStore::reconcile`] are authoritative.
pub struct FileSpool {
    root: SpoolRoot,
    directory: PlatformDirectory,
    protector: Arc<dyn ContentProtector>,
    memory: Mutex<MemoryState>,
    publications: PublicationGate,
    options: FileSpoolOptions,
}

struct FileEndpointResultReservation<'store> {
    spool: &'store FileSpool,
    maximum_plaintext_bytes: u64,
    reserved_protected_bytes: u64,
    active: bool,
}

impl fmt::Debug for FileEndpointResultReservation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointResultCapacityReservation")
            .field("maximum_plaintext_bytes", &self.maximum_plaintext_bytes)
            .field("reserved_protected_bytes", &self.reserved_protected_bytes)
            .field("state", &if self.active { "reserved" } else { "consumed" })
            .finish()
    }
}

impl<'store> FileEndpointResultReservation<'store> {
    fn release(&mut self) {
        if !self.active {
            return;
        }
        let mut memory = self
            .spool
            .memory
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match (
            memory.reserved_objects.checked_sub(1),
            memory
                .reserved_protected_bytes
                .checked_sub(self.reserved_protected_bytes),
        ) {
            (Some(objects), Some(bytes)) => {
                memory.reserved_objects = objects;
                memory.reserved_protected_bytes = bytes;
            }
            _ => memory.poisoned = true,
        }
        self.active = false;
    }

    fn persist_inner(
        &mut self,
        plaintext: &[u8],
        operation: SpoolOperation,
    ) -> Result<DurableContentPublication<'store>, SpoolError> {
        let protection_id = self.spool.protector.protection_id();
        let reference = self
            .spool
            .endpoint_result_reference_for(protection_id, plaintext)?;
        let actual_allocation = reference
            .endpoint_result_allocation_bytes()
            .ok_or(SpoolInvariantError::InvalidContentIdentity)?;
        if actual_allocation > self.reserved_protected_bytes {
            return Err(SpoolError::CapacityExhausted);
        }
        let permit = self.spool.publications.begin()?;
        let mut memory = self.spool.memory.lock().map_err(|_| SpoolError::Poisoned)?;
        if memory.poisoned {
            return Err(SpoolError::Poisoned);
        }
        if let Some(existing) = self.spool.load_protected(&reference)? {
            self.spool.open_and_verify(&reference, &existing)?;
            let reserved_objects = memory
                .reserved_objects
                .checked_sub(1)
                .ok_or(SpoolError::Poisoned)?;
            let reserved_protected_bytes = memory
                .reserved_protected_bytes
                .checked_sub(self.reserved_protected_bytes)
                .ok_or(SpoolError::Poisoned)?;
            memory.reserved_objects = reserved_objects;
            memory.reserved_protected_bytes = reserved_protected_bytes;
            self.active = false;
            return Ok(DurableContentPublication { reference, permit });
        }
        let protected = self.spool.protector.protect(&reference, plaintext);
        self.spool.options.observer.observe(SpoolEvent::Protection {
            operation: SpoolProtectionOperation::Protect,
            outcome: if protected.is_ok() {
                SpoolProtectionOutcome::Success
            } else {
                SpoolProtectionOutcome::Error
            },
        });
        let protected = protected?;
        let protected_bytes = u64::try_from(protected.len())
            .map_err(|_| SpoolInvariantError::ProtectionOverheadExceeded)?;
        self.spool
            .validate_protected_size(&reference, protected_bytes)?;
        if protected_bytes > self.reserved_protected_bytes {
            return Err(SpoolError::CapacityExhausted);
        }
        let reserved_objects = memory
            .reserved_objects
            .checked_sub(1)
            .ok_or(SpoolError::Poisoned)?;
        let reserved_bytes = memory
            .reserved_protected_bytes
            .checked_sub(self.reserved_protected_bytes)
            .ok_or(SpoolError::Poisoned)?;
        let objects = memory
            .usage
            .objects
            .checked_add(1)
            .ok_or(SpoolError::Poisoned)?;
        let usage_bytes = memory
            .usage
            .protected_bytes
            .checked_add(protected_bytes)
            .ok_or(SpoolError::Poisoned)?;
        match self.spool.directory.commit(
            &reference,
            &protected,
            self.spool.options.fault_injector.as_ref(),
        ) {
            Ok(()) => {
                memory.reserved_objects = reserved_objects;
                memory.reserved_protected_bytes = reserved_bytes;
                memory.usage.objects = objects;
                memory.usage.protected_bytes = usage_bytes;
                self.active = false;
                Ok(DurableContentPublication { reference, permit })
            }
            Err(failure) if failure.renamed() => {
                memory.poisoned = true;
                self.spool
                    .options
                    .observer
                    .observe(SpoolEvent::Poisoned { operation });
                Err(SpoolError::CommitOutcomeUnknown)
            }
            Err(failure) => Err(failure.into_public()),
        }
    }
}

impl Drop for FileEndpointResultReservation<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

impl<'store> EndpointResultCapacityReservation<'store> for FileEndpointResultReservation<'store> {
    fn persist(
        mut self: Box<Self>,
        plaintext: &[u8],
    ) -> Result<DurableContentPublication<'store>, SpoolError> {
        let plaintext_bytes =
            u64::try_from(plaintext.len()).map_err(|_| SpoolInvariantError::ObjectTooLarge)?;
        if plaintext_bytes > self.maximum_plaintext_bytes {
            return Err(SpoolInvariantError::ObjectTooLarge.into());
        }
        let observed_bytes = crate::endpoint_result_allocation(plaintext_bytes)?;

        let operation = SpoolOperation::Persist;
        let started = Instant::now();
        self.spool
            .options
            .observer
            .observe(SpoolEvent::OperationStarted { operation });
        let result = self.persist_inner(plaintext, operation);
        if result.is_ok() {
            self.spool
                .options
                .observer
                .observe(SpoolEvent::ContentBytes {
                    operation,
                    content_kind: ContentKind::EndpointResult,
                    bytes: observed_bytes,
                });
        }
        self.spool.observe_completion(
            operation,
            Some(ContentKind::EndpointResult),
            SpoolOperationOutcome::Success,
            started,
            &result,
        );
        result
    }
}

impl fmt::Debug for FileSpool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileSpool")
            .field("root", &self.root)
            .field("protection_id", self.protector.protection_id())
            .field("limits", &self.options.limits)
            .finish_non_exhaustive()
    }
}

impl FileSpool {
    /// Opens and exclusively locks a protected content spool.
    ///
    /// There is intentionally no constructor without a protection adapter.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] for unsafe paths, lock contention, incoherent
    /// existing usage, or storage failures.
    pub fn open(root: SpoolRoot, protector: Arc<dyn ContentProtector>) -> Result<Self, SpoolError> {
        Self::open_with_options(root, protector, FileSpoolOptions::default())
    }

    /// Opens with explicit capacity and deterministic fault options.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::open`].
    pub fn open_with_options(
        root: SpoolRoot,
        protector: Arc<dyn ContentProtector>,
        options: FileSpoolOptions,
    ) -> Result<Self, SpoolError> {
        let directory = PlatformDirectory::open(&root)?;
        directory.cleanup_staging()?;
        let usage = directory.scan_usage(options.limits)?;
        Ok(Self {
            root,
            directory,
            protector,
            memory: Mutex::new(MemoryState {
                usage,
                reserved_objects: 0,
                reserved_protected_bytes: 0,
                poisoned: false,
            }),
            publications: PublicationGate::default(),
            options,
        })
    }

    /// Returns the validated host root exclusively owned by this open spool.
    #[must_use]
    pub const fn root(&self) -> &SpoolRoot {
        &self.root
    }

    /// Returns the capacity policy applied to existing and newly published objects.
    #[must_use]
    pub const fn limits(&self) -> SpoolLimits {
        self.options.limits
    }

    /// Returns current usage as `(object_count, protected_bytes)`.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Poisoned`] after an uncertain commit.
    pub fn usage(&self) -> Result<(u32, u64), SpoolError> {
        let memory = self.memory.lock().map_err(|_| SpoolError::Poisoned)?;
        if memory.poisoned {
            return Err(SpoolError::Poisoned);
        }
        Ok((memory.usage.objects, memory.usage.protected_bytes))
    }

    fn public_reference_for(
        &self,
        kind: ContentKind,
        plaintext: &[u8],
    ) -> Result<DurableContentRef, SpoolError> {
        let size =
            u64::try_from(plaintext.len()).map_err(|_| SpoolInvariantError::ObjectTooLarge)?;
        if size > self.options.limits.max_object_bytes() {
            self.options.observer.observe(SpoolEvent::CapacityRejected {
                resource: SpoolCapacityResource::ObjectBytes,
            });
            return Err(SpoolInvariantError::ObjectTooLarge.into());
        }
        let digest = Sha256Digest::from_bytes(Sha256::digest(plaintext).into());
        DurableContentRef::after_public_commit(
            kind,
            size,
            digest,
            self.protector.protection_id().clone(),
        )
        .map_err(Into::into)
    }

    fn endpoint_result_reference_for(
        &self,
        protection_id: &ProtectionId,
        plaintext: &[u8],
    ) -> Result<DurableContentRef, SpoolError> {
        const MATERIAL_DOMAIN: &[u8] = b"automata.runner.endpoint-result.material.v1\0";
        let plaintext_bytes =
            u64::try_from(plaintext.len()).map_err(|_| SpoolInvariantError::ObjectTooLarge)?;
        if plaintext_bytes > self.options.limits.max_object_bytes() {
            return Err(SpoolInvariantError::ObjectTooLarge.into());
        }
        let plaintext_sha256: [u8; 32] = Sha256::digest(plaintext).into();
        let mut material = Sha256::new();
        material.update(MATERIAL_DOMAIN);
        material.update(plaintext_bytes.to_be_bytes());
        material.update(plaintext_sha256);
        let material_digest: [u8; 32] = material.finalize().into();
        let opaque = self.protector.keyed_commitment(
            protection_id,
            ContentCommitmentDomain::EndpointResultIdentity,
            &material_digest,
        )?;
        let protected_allocation_bytes = crate::endpoint_result_allocation(plaintext_bytes)?;
        DurableContentRef::after_endpoint_result_commit(
            protected_allocation_bytes,
            OpaqueContentIdentity::from_bytes(opaque),
            protection_id.clone(),
        )
        .map_err(Into::into)
    }

    fn load_protected(&self, reference: &DurableContentRef) -> Result<Option<Vec<u8>>, SpoolError> {
        match (
            reference.public_plaintext_bytes(),
            reference.endpoint_result_allocation_bytes(),
        ) {
            (Some(bytes), None) if bytes <= self.options.limits.max_object_bytes() => {}
            (None, Some(bytes)) if bytes <= self.options.limits.max_encoded_object_bytes() => {}
            _ => return Err(SpoolInvariantError::ObjectTooLarge.into()),
        }
        if !self
            .protector
            .supports_protection_id(reference.protection_id())
        {
            return Err(ContentProtectionError::KeyUnavailable.into());
        }
        self.directory
            .read(reference, self.options.limits.max_encoded_object_bytes())
    }

    fn open_and_verify(
        &self,
        reference: &DurableContentRef,
        protected: &[u8],
    ) -> Result<Vec<u8>, SpoolError> {
        let plaintext = self.protector.unprotect(reference, protected);
        self.options.observer.observe(SpoolEvent::Protection {
            operation: SpoolProtectionOperation::Unprotect,
            outcome: if plaintext.is_ok() {
                SpoolProtectionOutcome::Success
            } else {
                SpoolProtectionOutcome::Error
            },
        });
        let plaintext = plaintext?;
        self.verify_plaintext(reference, &plaintext)?;
        Ok(plaintext)
    }

    fn capacity_after(
        &self,
        memory: &MemoryState,
        additional_objects: u32,
        additional_protected_bytes: u64,
    ) -> Result<(), SpoolError> {
        let objects = memory
            .usage
            .objects
            .checked_add(memory.reserved_objects)
            .and_then(|objects| objects.checked_add(additional_objects))
            .ok_or(SpoolError::CapacityExhausted)?;
        let bytes = memory
            .usage
            .protected_bytes
            .checked_add(memory.reserved_protected_bytes)
            .and_then(|bytes| bytes.checked_add(additional_protected_bytes))
            .ok_or(SpoolError::CapacityExhausted)?;
        if objects > self.options.limits.max_objects() {
            self.options.observer.observe(SpoolEvent::CapacityRejected {
                resource: SpoolCapacityResource::ObjectCount,
            });
            return Err(SpoolError::CapacityExhausted);
        }
        if bytes > self.options.limits.max_total_bytes() {
            self.options.observer.observe(SpoolEvent::CapacityRejected {
                resource: SpoolCapacityResource::ProtectedBytes,
            });
            return Err(SpoolError::CapacityExhausted);
        }
        Ok(())
    }

    fn validate_protected_size(
        &self,
        reference: &DurableContentRef,
        protected_bytes: u64,
    ) -> Result<(), SpoolError> {
        let allowed = match (
            reference.public_plaintext_bytes(),
            reference.endpoint_result_allocation_bytes(),
        ) {
            (Some(plaintext_bytes), None) => plaintext_bytes
                .checked_add(self.options.limits.max_protection_overhead_bytes())
                .is_some_and(|maximum| protected_bytes <= maximum),
            (None, Some(allocation_bytes)) => protected_bytes == allocation_bytes,
            _ => false,
        } && protected_bytes <= self.options.limits.max_encoded_object_bytes();
        if allowed {
            Ok(())
        } else {
            Err(SpoolInvariantError::ProtectionOverheadExceeded.into())
        }
    }

    fn verify_plaintext(
        &self,
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<(), SpoolError> {
        if let (Some(expected_bytes), Some(expected_digest)) = (
            reference.public_plaintext_bytes(),
            reference.public_plaintext_sha256(),
        ) {
            let size = u64::try_from(plaintext.len()).unwrap_or(u64::MAX);
            let digest = Sha256Digest::from_bytes(Sha256::digest(plaintext).into());
            return if size == expected_bytes && digest == expected_digest {
                Ok(())
            } else {
                Err(SpoolInvariantError::ContentMismatch.into())
            };
        }
        let expected = self.endpoint_result_reference_for(reference.protection_id(), plaintext)?;
        let expected_identity = expected
            .endpoint_result_identity()
            .ok_or(SpoolInvariantError::InvalidContentIdentity)?;
        let actual_identity = reference
            .endpoint_result_identity()
            .ok_or(SpoolInvariantError::InvalidContentIdentity)?;
        if bool::from(
            expected_identity
                .as_bytes()
                .ct_eq(actual_identity.as_bytes()),
        ) && expected.endpoint_result_allocation_bytes()
            == reference.endpoint_result_allocation_bytes()
        {
            Ok(())
        } else {
            Err(SpoolInvariantError::ContentMismatch.into())
        }
    }

    fn observe_completion<T>(
        &self,
        operation: SpoolOperation,
        content_kind: Option<ContentKind>,
        successful_outcome: SpoolOperationOutcome,
        started: Instant,
        result: &Result<T, SpoolError>,
    ) {
        let (outcome, failure) = match result {
            Ok(_) => (successful_outcome, None),
            Err(error) => (
                SpoolOperationOutcome::Error,
                Some(SpoolFailureKind::from_error(error)),
            ),
        };
        self.options
            .observer
            .observe(SpoolEvent::OperationCompleted {
                operation,
                content_kind,
                outcome,
                failure,
                duration: started.elapsed(),
            });
    }
}

impl DurableContentStore for FileSpool {
    fn create_keyed_commitment(
        &self,
        domain: ContentCommitmentDomain,
        material_digest: &[u8; 32],
    ) -> Result<KeyedContentCommitment, SpoolError> {
        self.recreate_keyed_commitment(self.protector.protection_id(), domain, material_digest)
    }

    fn recreate_keyed_commitment(
        &self,
        protection_id: &ProtectionId,
        domain: ContentCommitmentDomain,
        material_digest: &[u8; 32],
    ) -> Result<KeyedContentCommitment, SpoolError> {
        if !self.protector.supports_protection_id(protection_id) {
            return Err(ContentProtectionError::KeyUnavailable.into());
        }
        let commitment = self
            .protector
            .keyed_commitment(protection_id, domain, material_digest);
        self.options.observer.observe(SpoolEvent::Protection {
            operation: SpoolProtectionOperation::Commitment,
            outcome: if commitment.is_ok() {
                SpoolProtectionOutcome::Success
            } else {
                SpoolProtectionOutcome::Error
            },
        });
        Ok(KeyedContentCommitment::new(
            protection_id.clone(),
            commitment?,
        ))
    }

    fn reserve_endpoint_result(
        &self,
        maximum_plaintext_bytes: u64,
    ) -> Result<Box<dyn EndpointResultCapacityReservation<'_> + '_>, SpoolError> {
        if maximum_plaintext_bytes > self.options.limits.max_object_bytes() {
            self.options.observer.observe(SpoolEvent::CapacityRejected {
                resource: SpoolCapacityResource::ObjectBytes,
            });
            return Err(SpoolInvariantError::ObjectTooLarge.into());
        }
        let protected_bytes = crate::endpoint_result_allocation(maximum_plaintext_bytes)?;
        let protector_bytes = self
            .protector
            .endpoint_result_protected_bytes(maximum_plaintext_bytes)?;
        if protector_bytes != protected_bytes {
            return Err(SpoolInvariantError::ProtectionOverheadExceeded.into());
        }
        let maximum_encoded = maximum_plaintext_bytes
            .checked_add(self.options.limits.max_protection_overhead_bytes())
            .ok_or(SpoolInvariantError::ProtectionOverheadExceeded)?;
        if protected_bytes > maximum_encoded
            || protected_bytes > self.options.limits.max_encoded_object_bytes()
        {
            return Err(SpoolInvariantError::ProtectionOverheadExceeded.into());
        }
        let mut memory = self.memory.lock().map_err(|_| SpoolError::Poisoned)?;
        if memory.poisoned {
            return Err(SpoolError::Poisoned);
        }
        self.capacity_after(&memory, 1, protected_bytes)?;
        let reserved_objects = memory
            .reserved_objects
            .checked_add(1)
            .ok_or(SpoolError::CapacityExhausted)?;
        let reserved_protected_bytes = memory
            .reserved_protected_bytes
            .checked_add(protected_bytes)
            .ok_or(SpoolError::CapacityExhausted)?;
        memory.reserved_objects = reserved_objects;
        memory.reserved_protected_bytes = reserved_protected_bytes;
        Ok(Box::new(FileEndpointResultReservation {
            spool: self,
            maximum_plaintext_bytes,
            reserved_protected_bytes: protected_bytes,
            active: true,
        }))
    }

    fn persist(
        &self,
        kind: ContentKind,
        plaintext: &[u8],
    ) -> Result<DurableContentPublication<'_>, SpoolError> {
        let operation = SpoolOperation::Persist;
        let started = Instant::now();
        self.options
            .observer
            .observe(SpoolEvent::OperationStarted { operation });
        let result = (|| {
            if kind == ContentKind::EndpointResult {
                return Err(SpoolInvariantError::EndpointResultReservationRequired.into());
            }
            let reference = self.public_reference_for(kind, plaintext)?;
            let permit = self.publications.begin()?;
            let mut memory = self.memory.lock().map_err(|_| SpoolError::Poisoned)?;
            if memory.poisoned {
                return Err(SpoolError::Poisoned);
            }
            if let Some(existing) = self.load_protected(&reference)? {
                self.open_and_verify(&reference, &existing)?;
                return Ok(DurableContentPublication { reference, permit });
            }
            let protected = self.protector.protect(&reference, plaintext);
            self.options.observer.observe(SpoolEvent::Protection {
                operation: SpoolProtectionOperation::Protect,
                outcome: if protected.is_ok() {
                    SpoolProtectionOutcome::Success
                } else {
                    SpoolProtectionOutcome::Error
                },
            });
            let protected = protected?;
            let protected_bytes = u64::try_from(protected.len())
                .map_err(|_| SpoolInvariantError::ProtectionOverheadExceeded)?;
            self.validate_protected_size(&reference, protected_bytes)?;
            self.capacity_after(&memory, 1, protected_bytes)?;
            let next_objects = memory
                .usage
                .objects
                .checked_add(1)
                .ok_or(SpoolError::CapacityExhausted)?;
            let next_protected_bytes = memory
                .usage
                .protected_bytes
                .checked_add(protected_bytes)
                .ok_or(SpoolError::CapacityExhausted)?;
            match self.directory.commit(
                &reference,
                &protected,
                self.options.fault_injector.as_ref(),
            ) {
                Ok(()) => {
                    memory.usage.objects = next_objects;
                    memory.usage.protected_bytes = next_protected_bytes;
                    Ok(DurableContentPublication { reference, permit })
                }
                Err(failure) if failure.renamed() => {
                    memory.poisoned = true;
                    self.options
                        .observer
                        .observe(SpoolEvent::Poisoned { operation });
                    Err(SpoolError::CommitOutcomeUnknown)
                }
                Err(failure) => Err(failure.into_public()),
            }
        })();
        if result.is_ok() {
            self.options.observer.observe(SpoolEvent::ContentBytes {
                operation,
                content_kind: kind,
                bytes: u64::try_from(plaintext.len()).unwrap_or(u64::MAX),
            });
        }
        self.observe_completion(
            operation,
            Some(kind),
            SpoolOperationOutcome::Success,
            started,
            &result,
        );
        result
    }

    fn load(&self, reference: &DurableContentRef) -> Result<Vec<u8>, SpoolError> {
        let operation = SpoolOperation::Load;
        let started = Instant::now();
        self.options
            .observer
            .observe(SpoolEvent::OperationStarted { operation });
        let result = (|| {
            reference.validate()?;
            let memory = self.memory.lock().map_err(|_| SpoolError::Poisoned)?;
            if memory.poisoned {
                return Err(SpoolError::Poisoned);
            }
            let protected = self
                .load_protected(reference)?
                .ok_or(SpoolError::ContentMissing)?;
            self.open_and_verify(reference, &protected)
        })();
        if let Ok(plaintext) = &result {
            self.options.observer.observe(SpoolEvent::ContentBytes {
                operation,
                content_kind: reference.kind(),
                bytes: if reference.kind() == ContentKind::EndpointResult {
                    reference.accounted_bytes()
                } else {
                    u64::try_from(plaintext.len()).unwrap_or(u64::MAX)
                },
            });
        }
        self.observe_completion(
            operation,
            Some(reference.kind()),
            SpoolOperationOutcome::Success,
            started,
            &result,
        );
        result
    }

    fn remove(&self, reference: &DurableContentRef) -> Result<bool, SpoolError> {
        let operation = SpoolOperation::Remove;
        let started = Instant::now();
        self.options
            .observer
            .observe(SpoolEvent::OperationStarted { operation });
        let result = (|| {
            reference.validate()?;
            let publications = self.publications.lock();
            if publications.active != 0 {
                return Err(SpoolError::PublicationsInFlight);
            }
            let mut memory = self.memory.lock().map_err(|_| SpoolError::Poisoned)?;
            if memory.poisoned {
                return Err(SpoolError::Poisoned);
            }
            let Some(protected) = self.load_protected(reference)? else {
                return Ok(false);
            };
            self.open_and_verify(reference, &protected)?;
            let protected_bytes = u64::try_from(protected.len()).unwrap_or(u64::MAX);
            let next_objects = memory
                .usage
                .objects
                .checked_sub(1)
                .ok_or(SpoolError::Poisoned)?;
            let next_protected_bytes = memory
                .usage
                .protected_bytes
                .checked_sub(protected_bytes)
                .ok_or(SpoolError::Poisoned)?;
            match self.directory.remove(reference) {
                Ok(false) => return Ok(false),
                Ok(true) => {}
                Err(failure) if failure.renamed() => {
                    memory.poisoned = true;
                    self.options
                        .observer
                        .observe(SpoolEvent::Poisoned { operation });
                    return Err(SpoolError::RemovalOutcomeUnknown {
                        reference: reference.clone(),
                    });
                }
                Err(failure) => return Err(failure.into_public()),
            }
            memory.usage.objects = next_objects;
            memory.usage.protected_bytes = next_protected_bytes;
            Ok(true)
        })();
        if matches!(result, Ok(true)) {
            self.options.observer.observe(SpoolEvent::ContentBytes {
                operation,
                content_kind: reference.kind(),
                bytes: reference.accounted_bytes(),
            });
        }
        let successful_outcome = if matches!(result, Ok(false)) {
            SpoolOperationOutcome::AlreadyAbsent
        } else {
            SpoolOperationOutcome::Success
        };
        self.observe_completion(
            operation,
            Some(reference.kind()),
            successful_outcome,
            started,
            &result,
        );
        result
    }

    fn reconcile(&self, retained: &dyn RetainedContentSource) -> Result<(), SpoolError> {
        let operation = SpoolOperation::Reconcile;
        let started = Instant::now();
        self.options
            .observer
            .observe(SpoolEvent::OperationStarted { operation });
        let result = (|| {
            let publications = self.publications.lock();
            if publications.active != 0 {
                return Err(SpoolError::PublicationsInFlight);
            }
            let retained = retained.retained_content()?;
            let maximum_objects =
                usize::try_from(self.options.limits.max_objects()).unwrap_or(usize::MAX);
            let mut memory = self.memory.lock().map_err(|_| SpoolError::Poisoned)?;
            if memory.poisoned {
                return Err(SpoolError::Poisoned);
            }
            let previous = memory.usage;
            let mut retained_names = HashSet::with_capacity(retained.len().min(maximum_objects));
            for reference in retained {
                reference.validate()?;
                let retained_name = format!("{}.blob", reference.cache_key().as_str()).into_bytes();
                if retained_names.contains(&retained_name) {
                    continue;
                }
                if retained_names.len() >= maximum_objects {
                    self.options.observer.observe(SpoolEvent::CapacityRejected {
                        resource: SpoolCapacityResource::ObjectCount,
                    });
                    return Err(SpoolError::CapacityExhausted);
                }
                let protected = self
                    .load_protected(&reference)?
                    .ok_or(SpoolError::ContentMissing)?;
                self.open_and_verify(&reference, &protected)?;
                retained_names.insert(retained_name);
            }
            match self
                .directory
                .prune_except(&retained_names, self.options.limits)
            {
                Ok(usage) => {
                    memory.usage = usage;
                    self.options.observer.observe(SpoolEvent::Reclaimed {
                        objects: u64::from(previous.objects.saturating_sub(usage.objects)),
                        protected_bytes: previous
                            .protected_bytes
                            .saturating_sub(usage.protected_bytes),
                    });
                    Ok(())
                }
                Err(failure) if failure.renamed() => {
                    memory.poisoned = true;
                    self.options
                        .observer
                        .observe(SpoolEvent::Poisoned { operation });
                    Err(SpoolError::ReconciliationOutcomeUnknown)
                }
                Err(failure) => Err(failure.into_public()),
            }
        })();
        self.observe_completion(
            operation,
            None,
            SpoolOperationOutcome::Success,
            started,
            &result,
        );
        result
    }
}
