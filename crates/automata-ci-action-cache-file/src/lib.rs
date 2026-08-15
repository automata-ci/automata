#![forbid(unsafe_code)]
//! Crash-durable local index for immutable repository action bundles.
//!
//! The index stores only credential-free provenance and exact blob
//! descriptors. Archive content remains in the configured immutable blob
//! store. A process-exclusive lock, bounded canonical JSON, and atomic
//! file-plus-directory synchronization provide a small local authority that
//! can be safely consulted before contacting SCM.

#[cfg(unix)]
mod archive_cache;
mod codec;
mod platform;
mod root;

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use automata_ci_action::{
    ActionReferenceIndex, ActionReferenceIndexError, ActionReferenceIndexErrorKind,
    ImmutableActionReference, IndexedActionBundle, PutActionReferenceOutcome,
};

use self::{codec::StoredIndex, platform::PlatformDirectory};
#[cfg(unix)]
pub use archive_cache::{
    ActionArchiveCacheLimits, ActionArchiveCacheRoot, DEFAULT_MAXIMUM_ARCHIVE_BYTES,
    DEFAULT_MAXIMUM_ARCHIVE_ENTRIES, DEFAULT_MAXIMUM_SINGLE_ARCHIVE_BYTES, FileActionArchiveCache,
};
pub use root::ActionReferenceIndexRoot;

/// Current durable action-reference index schema.
pub const ACTION_REFERENCE_INDEX_SCHEMA_VERSION: u16 = 1;
/// Default retained immutable reference count.
pub const DEFAULT_MAXIMUM_INDEX_ENTRIES: usize = 4_096;
/// Default hard ceiling for the canonical index document.
pub const DEFAULT_MAXIMUM_INDEX_BYTES: usize = 8 * 1_024 * 1_024;

const HARD_MAXIMUM_INDEX_ENTRIES: usize = 65_536;
const HARD_MAXIMUM_INDEX_BYTES: usize = 64 * 1_024 * 1_024;
const MINIMUM_INDEX_BYTES: usize = 1_024;

/// Explicit bounds for one file-backed action reference index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionReferenceIndexLimits {
    maximum_entries: usize,
    maximum_bytes: usize,
}

impl ActionReferenceIndexLimits {
    /// Creates defensive entry and encoded-file ceilings.
    ///
    /// # Errors
    ///
    /// Rejects zero, tiny, or excessive bounds.
    pub const fn new(
        maximum_entries: usize,
        maximum_bytes: usize,
    ) -> Result<Self, ActionReferenceIndexError> {
        if maximum_entries == 0
            || maximum_entries > HARD_MAXIMUM_INDEX_ENTRIES
            || maximum_bytes < MINIMUM_INDEX_BYTES
            || maximum_bytes > HARD_MAXIMUM_INDEX_BYTES
        {
            return Err(ActionReferenceIndexError::new(
                ActionReferenceIndexErrorKind::ResourceExhausted,
            ));
        }
        Ok(Self {
            maximum_entries,
            maximum_bytes,
        })
    }

    #[must_use]
    pub const fn maximum_entries(self) -> usize {
        self.maximum_entries
    }

    #[must_use]
    pub const fn maximum_bytes(self) -> usize {
        self.maximum_bytes
    }
}

impl Default for ActionReferenceIndexLimits {
    fn default() -> Self {
        Self {
            maximum_entries: DEFAULT_MAXIMUM_INDEX_ENTRIES,
            maximum_bytes: DEFAULT_MAXIMUM_INDEX_BYTES,
        }
    }
}

#[derive(Debug)]
struct MemoryState {
    index: StoredIndex,
    poisoned: bool,
}

struct Inner {
    root: ActionReferenceIndexRoot,
    directory: PlatformDirectory,
    limits: ActionReferenceIndexLimits,
    memory: Mutex<MemoryState>,
}

impl fmt::Debug for Inner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileActionReferenceIndexInner")
            .field("root", &self.root)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Secure, bounded, crash-durable immutable action reference index.
#[derive(Clone, Debug)]
pub struct FileActionReferenceIndex {
    inner: Arc<Inner>,
}

impl FileActionReferenceIndex {
    /// Opens and process-exclusively locks an index at an existing runner state
    /// root, creating an empty index when none exists.
    ///
    /// # Errors
    ///
    /// Fails closed for path-policy violations, lock contention, malformed or
    /// oversized state, unsafe files, and I/O failures.
    pub fn open(
        root: ActionReferenceIndexRoot,
        limits: ActionReferenceIndexLimits,
    ) -> Result<Self, ActionReferenceIndexError> {
        let directory = PlatformDirectory::open(&root)?;
        directory.cleanup_staging()?;
        let index = directory.read_index(limits.maximum_bytes())?.map_or_else(
            || Ok(StoredIndex::default()),
            |bytes| StoredIndex::decode(&bytes, limits.maximum_entries()),
        )?;
        Ok(Self {
            inner: Arc::new(Inner {
                root,
                directory,
                limits,
                memory: Mutex::new(MemoryState {
                    index,
                    poisoned: false,
                }),
            }),
        })
    }

    fn get_sync(
        &self,
        reference: &ImmutableActionReference,
    ) -> Result<Option<IndexedActionBundle>, ActionReferenceIndexError> {
        let memory = self.inner.memory.lock().map_err(|_| unavailable())?;
        if memory.poisoned {
            return Err(unavailable());
        }
        Ok(memory.index.get(reference).cloned())
    }

    fn put_sync(
        &self,
        bundle: IndexedActionBundle,
    ) -> Result<PutActionReferenceOutcome, ActionReferenceIndexError> {
        let mut memory = self.inner.memory.lock().map_err(|_| unavailable())?;
        if memory.poisoned {
            return Err(unavailable());
        }
        if let Some(existing) = memory.index.get(bundle.reference()) {
            return if existing == &bundle {
                Ok(PutActionReferenceOutcome::AlreadyPresent)
            } else {
                Err(ActionReferenceIndexError::new(
                    ActionReferenceIndexErrorKind::Conflict,
                ))
            };
        }

        let mut candidate = memory.index.clone();
        candidate.insert(bundle)?;
        candidate.evict_to_entry_bound(self.inner.limits.maximum_entries())?;
        let encoded = loop {
            let encoded = candidate.encode()?;
            if encoded.len() <= self.inner.limits.maximum_bytes() {
                break encoded;
            }
            if candidate.len() <= 1 {
                return Err(ActionReferenceIndexError::new(
                    ActionReferenceIndexErrorKind::ResourceExhausted,
                ));
            }
            candidate.evict_oldest()?;
        };

        match self
            .inner
            .directory
            .commit(candidate.generation(), &encoded)
        {
            Ok(()) => {
                memory.index = candidate;
                Ok(PutActionReferenceOutcome::Created)
            }
            Err(failure) if failure.renamed() => {
                memory.poisoned = true;
                Err(unavailable())
            }
            Err(_) => Err(unavailable()),
        }
    }
}

#[async_trait]
impl ActionReferenceIndex for FileActionReferenceIndex {
    async fn get(
        &self,
        reference: &ImmutableActionReference,
    ) -> Result<Option<IndexedActionBundle>, ActionReferenceIndexError> {
        self.get_sync(reference)
    }

    async fn put_if_absent(
        &self,
        bundle: IndexedActionBundle,
    ) -> Result<PutActionReferenceOutcome, ActionReferenceIndexError> {
        let index = self.clone();
        tokio::task::spawn_blocking(move || index.put_sync(bundle))
            .await
            .map_err(|_| unavailable())?
    }
}

const fn unavailable() -> ActionReferenceIndexError {
    ActionReferenceIndexError::new(ActionReferenceIndexErrorKind::Unavailable)
}
