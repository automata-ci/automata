use std::{
    collections::HashSet,
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError},
};

use automata_core::Sha256Digest;
use sha2::{Digest as _, Sha256};

use crate::{
    ContentKind, ContentProtectionError, DurableContentRef, ProtectionId, RetainedContentError,
    SpoolError, SpoolInvariantError, SpoolLimits, SpoolRoot,
    platform::{PlatformDirectory, SpoolUsage},
};

/// Atomic content-commit boundary exposed to deterministic fault tests.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ContentCommitStage {
    StagingCreated,
    DataWritten,
    FileSynced,
    Renamed,
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
/// Implementations should use authenticated encryption and bind the complete
/// [`DurableContentRef`] as associated data. Errors must not contain key or
/// plaintext material.
pub trait ContentProtector: Send + Sync {
    /// Returns a bounded, non-secret key/cipher identifier.
    fn protection_id(&self) -> &ProtectionId;

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
    abandoned: bool,
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
            state.abandoned = true;
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
    /// Protects, verifies, and durably commits immutable content.
    ///
    /// A successful return occurs only after file and directory synchronization.
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
    /// reference while any recovery record still uses it.
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
}

impl FileSpoolOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_limits(mut self, limits: SpoolLimits) -> Self {
        self.limits = limits;
        self
    }

    #[must_use]
    pub fn with_fault_injector(mut self, injector: Arc<dyn ContentCommitFaultInjector>) -> Self {
        self.fault_injector = injector;
        self
    }
}

impl Default for FileSpoolOptions {
    fn default() -> Self {
        Self {
            limits: SpoolLimits::default(),
            fault_injector: Arc::new(NoContentCommitFaults),
        }
    }
}

impl fmt::Debug for FileSpoolOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileSpoolOptions")
            .field("limits", &self.limits)
            .field("fault_injector", &"configured")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct MemoryState {
    usage: SpoolUsage,
    poisoned: bool,
}

/// Crash-durable immutable content cache with mandatory at-rest protection.
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

    #[must_use]
    pub const fn root(&self) -> &SpoolRoot {
        &self.root
    }

    #[must_use]
    pub const fn limits(&self) -> SpoolLimits {
        self.options.limits
    }

    /// Returns current protected-byte and object usage.
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
        if reference.protection_id() != self.protector.protection_id() {
            return Err(SpoolInvariantError::ContentMismatch.into());
        }
        self.directory
            .read(reference, self.options.limits.max_encoded_object_bytes())
    }

    fn open_and_verify(
        &self,
        reference: &DurableContentRef,
        protected: &[u8],
    ) -> Result<Vec<u8>, SpoolError> {
        let plaintext = self.protector.unprotect(reference, protected)?;
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
        if objects > self.options.limits.max_objects()
            || bytes > self.options.limits.max_total_bytes()
        {
            Err(SpoolError::CapacityExhausted)
        } else {
            Ok(())
        }
    }
}

impl DurableContentStore for FileSpool {
    fn persist(
        &self,
        kind: ContentKind,
        plaintext: &[u8],
    ) -> Result<DurableContentPublication<'_>, SpoolError> {
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
        let protected = self.protector.protect(&reference, plaintext)?;
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
        match self
            .directory
            .commit(&reference, &protected, self.options.fault_injector.as_ref())
        {
            Ok(()) => {
                memory.usage.objects += 1;
                memory.usage.protected_bytes += protected_bytes;
                Ok(DurableContentPublication { reference, permit })
            }
            Err(failure) if failure.renamed() => {
                memory.poisoned = true;
                Err(SpoolError::CommitOutcomeUnknown)
            }
            Err(failure) => Err(failure.into_public()),
        }
    }

    fn load(&self, reference: &DurableContentRef) -> Result<Vec<u8>, SpoolError> {
        reference.validate()?;
        let memory = self.memory.lock().map_err(|_| SpoolError::Poisoned)?;
        if memory.poisoned {
            return Err(SpoolError::Poisoned);
        }
        let protected = self
            .load_protected(reference)?
            .ok_or(SpoolError::ContentMissing)?;
        self.open_and_verify(reference, &protected)
    }

    fn remove(&self, reference: &DurableContentRef) -> Result<bool, SpoolError> {
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
    }

    fn reconcile(&self, retained: &dyn RetainedContentSource) -> Result<(), SpoolError> {
        let mut publications = self.publications.lock();
        if publications.active != 0 {
            return Err(SpoolError::PublicationsInFlight);
        }
        let retained = retained.retained_content()?;
        if retained.len() > usize::try_from(self.options.limits.max_objects()).unwrap_or(usize::MAX)
        {
            return Err(SpoolError::CapacityExhausted);
        }
        let mut memory = self.memory.lock().map_err(|_| SpoolError::Poisoned)?;
        if memory.poisoned {
            return Err(SpoolError::Poisoned);
        }
        let mut retained_names = HashSet::with_capacity(retained.len());
        for reference in retained {
            reference.validate()?;
            let protected = self
                .load_protected(&reference)?
                .ok_or(SpoolError::ContentMissing)?;
            self.open_and_verify(&reference, &protected)?;
            retained_names.insert(format!("{}.blob", reference.cache_key().as_str()).into_bytes());
        }
        match self
            .directory
            .prune_except(&retained_names, self.options.limits)
        {
            Ok(usage) => {
                memory.usage = usage;
                publications.abandoned = false;
                Ok(())
            }
            Err(failure) if failure.renamed() => {
                memory.poisoned = true;
                Err(SpoolError::ReconciliationOutcomeUnknown)
            }
            Err(failure) => Err(failure.into_public()),
        }
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
