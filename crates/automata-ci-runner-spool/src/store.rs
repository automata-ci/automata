use std::{
    collections::HashSet,
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError},
    time::Instant,
};

use automata_ci_core::Sha256Digest;
use sha2::{Digest as _, Sha256};

use crate::{
    ContentCommitmentDomain, ContentKind, ContentProtectionError, DurableContentRef,
    KeyedContentCommitment, NoopSpoolObserver, ProtectionId, RetainedContentError,
    SpoolCapacityResource, SpoolError, SpoolEvent, SpoolFailureKind, SpoolInvariantError,
    SpoolLimits, SpoolObserver, SpoolOperation, SpoolOperationOutcome, SpoolProtectionOperation,
    SpoolProtectionOutcome, SpoolRoot,
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

    fn reference_for(
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
        DurableContentRef::after_commit(kind, size, digest, self.protector.protection_id().clone())
            .map_err(Into::into)
    }

    fn load_protected(&self, reference: &DurableContentRef) -> Result<Option<Vec<u8>>, SpoolError> {
        if reference.size() > self.options.limits.max_object_bytes() {
            return Err(SpoolInvariantError::ObjectTooLarge.into());
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
        verify_plaintext(reference, &plaintext)?;
        Ok(plaintext)
    }

    fn capacity_after(&self, usage: SpoolUsage, protected_bytes: u64) -> Result<(), SpoolError> {
        let objects = usage
            .objects
            .checked_add(1)
            .ok_or(SpoolError::CapacityExhausted)?;
        let bytes = usage
            .protected_bytes
            .checked_add(protected_bytes)
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
            let reference = self.reference_for(kind, plaintext)?;
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
            let allowed = reference
                .size()
                .checked_add(self.options.limits.max_protection_overhead_bytes())
                .is_some_and(|maximum| protected_bytes <= maximum)
                && protected_bytes <= self.options.limits.max_encoded_object_bytes();
            if !allowed {
                return Err(SpoolInvariantError::ProtectionOverheadExceeded.into());
            }
            self.capacity_after(memory.usage, protected_bytes)?;
            match self.directory.commit(
                &reference,
                &protected,
                self.options.fault_injector.as_ref(),
            ) {
                Ok(()) => {
                    memory.usage.objects += 1;
                    memory.usage.protected_bytes += protected_bytes;
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
                bytes: u64::try_from(plaintext.len()).unwrap_or(u64::MAX),
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
            memory.usage.objects = memory
                .usage
                .objects
                .checked_sub(1)
                .ok_or(SpoolError::Poisoned)?;
            memory.usage.protected_bytes = memory
                .usage
                .protected_bytes
                .checked_sub(protected_bytes)
                .ok_or(SpoolError::Poisoned)?;
            Ok(true)
        })();
        if matches!(result, Ok(true)) {
            self.options.observer.observe(SpoolEvent::ContentBytes {
                operation,
                content_kind: reference.kind(),
                bytes: reference.size(),
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
            if retained.len()
                > usize::try_from(self.options.limits.max_objects()).unwrap_or(usize::MAX)
            {
                self.options.observer.observe(SpoolEvent::CapacityRejected {
                    resource: SpoolCapacityResource::ObjectCount,
                });
                return Err(SpoolError::CapacityExhausted);
            }
            let mut memory = self.memory.lock().map_err(|_| SpoolError::Poisoned)?;
            if memory.poisoned {
                return Err(SpoolError::Poisoned);
            }
            let previous = memory.usage;
            let mut retained_names = HashSet::with_capacity(retained.len());
            for reference in retained {
                reference.validate()?;
                let protected = self
                    .load_protected(&reference)?
                    .ok_or(SpoolError::ContentMissing)?;
                self.open_and_verify(&reference, &protected)?;
                retained_names
                    .insert(format!("{}.blob", reference.cache_key().as_str()).into_bytes());
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

fn verify_plaintext(reference: &DurableContentRef, plaintext: &[u8]) -> Result<(), SpoolError> {
    let size = u64::try_from(plaintext.len()).unwrap_or(u64::MAX);
    let digest = Sha256Digest::from_bytes(Sha256::digest(plaintext).into());
    if size == reference.size() && digest == reference.sha256() {
        Ok(())
    } else {
        Err(SpoolInvariantError::ContentMismatch.into())
    }
}
