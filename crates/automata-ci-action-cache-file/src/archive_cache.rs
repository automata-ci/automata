use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::SystemTime,
};

use async_trait::async_trait;
use automata_ci_blob::{
    BlobDescriptor, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    PutBlobOutcome, VerifiedBlob,
};
use bytes::Bytes;
use rustix::fs::{FlockOperation, flock};

use crate::ActionReferenceIndexRoot;

const ARCHIVE_PREFIX: &str = "action-archive-v1-";
const ARCHIVE_SUFFIX: &str = ".tar.gz";
const LOCK_FILE: &str = ".action-archive-cache.lock";
const STAGING_PREFIX: &str = ".action-archive-cache.stage-";
const ACTION_KEY_PREFIX: &str = "actions/v1/sha256/";
const ACTION_MEDIA_TYPE: &str = "application/gzip";

/// Default number of immutable action archives retained by each runner.
pub const DEFAULT_MAXIMUM_ARCHIVE_ENTRIES: usize = 256;
/// Default local archive-cache byte budget for each runner (512 MiB).
pub const DEFAULT_MAXIMUM_ARCHIVE_BYTES: u64 = 512 * 1_024 * 1_024;
/// Default ceiling for one compressed action archive (16 MiB).
pub const DEFAULT_MAXIMUM_SINGLE_ARCHIVE_BYTES: u64 = 16 * 1_024 * 1_024;

/// Explicit bounds for one runner-local immutable archive cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionArchiveCacheLimits {
    maximum_entries: usize,
    maximum_bytes: u64,
    maximum_single_archive_bytes: u64,
}

impl ActionArchiveCacheLimits {
    /// Creates a bounded local archive policy.
    ///
    /// # Errors
    ///
    /// Rejects zero, inconsistent, or excessive bounds.
    pub const fn new(
        maximum_entries: usize,
        maximum_bytes: u64,
        maximum_single_archive_bytes: u64,
    ) -> Result<Self, BlobStoreError> {
        if maximum_entries == 0
            || maximum_entries > 65_536
            || maximum_bytes == 0
            || maximum_bytes > 64 * 1_024 * 1_024 * 1_024
            || maximum_single_archive_bytes == 0
            || maximum_single_archive_bytes > maximum_bytes
            || maximum_single_archive_bytes > 64 * 1_024 * 1_024
        {
            return Err(BlobStoreError::new(BlobStoreErrorKind::InvalidResponse));
        }
        Ok(Self {
            maximum_entries,
            maximum_bytes,
            maximum_single_archive_bytes,
        })
    }

    /// Returns the retained archive count ceiling.
    #[must_use]
    pub const fn maximum_entries(self) -> usize {
        self.maximum_entries
    }

    /// Returns the aggregate encoded byte ceiling.
    #[must_use]
    pub const fn maximum_bytes(self) -> u64 {
        self.maximum_bytes
    }

    /// Returns the per-archive encoded byte ceiling.
    #[must_use]
    pub const fn maximum_single_archive_bytes(self) -> u64 {
        self.maximum_single_archive_bytes
    }
}

impl Default for ActionArchiveCacheLimits {
    fn default() -> Self {
        Self {
            maximum_entries: DEFAULT_MAXIMUM_ARCHIVE_ENTRIES,
            maximum_bytes: DEFAULT_MAXIMUM_ARCHIVE_BYTES,
            maximum_single_archive_bytes: DEFAULT_MAXIMUM_SINGLE_ARCHIVE_BYTES,
        }
    }
}

/// Validated non-temporary root for a runner-local archive cache.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionArchiveCacheRoot(PathBuf);

impl ActionArchiveCacheRoot {
    /// Validates one explicitly configured archive-cache root.
    ///
    /// # Errors
    ///
    /// Rejects the same unsafe paths as [`ActionReferenceIndexRoot`].
    pub fn explicit(path: impl Into<PathBuf>) -> Result<Self, BlobStoreError> {
        let path = path.into();
        ActionReferenceIndexRoot::explicit(path.clone())
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::InvalidResponse))?;
        Ok(Self(path))
    }

    /// Returns the validated filesystem path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

#[derive(Debug)]
struct Inner {
    root: ActionArchiveCacheRoot,
    limits: ActionArchiveCacheLimits,
    gate: Mutex<()>,
    _lock: File,
}

/// Process-exclusive, bounded, content-verified local action archive cache.
#[derive(Clone, Debug)]
pub struct FileActionArchiveCache {
    inner: Arc<Inner>,
}

impl FileActionArchiveCache {
    /// Opens the cache, creates its private root, and removes incomplete writes.
    ///
    /// # Errors
    ///
    /// Fails closed for unsafe files, lock contention, or I/O failures.
    pub fn open(
        root: ActionArchiveCacheRoot,
        limits: ActionArchiveCacheLimits,
    ) -> Result<Self, BlobStoreError> {
        fs::create_dir_all(root.as_path()).map_err(|_| unavailable())?;
        let metadata = fs::symlink_metadata(root.as_path()).map_err(|_| unavailable())?;
        if !metadata.file_type().is_dir() || metadata.nlink() != 2 {
            return Err(integrity());
        }
        fs::set_permissions(root.as_path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| unavailable())?;
        let lock = open_file(&root.as_path().join(LOCK_FILE), true, false)?;
        ensure_regular(&lock)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| unavailable())?;
        cleanup_staging(root.as_path())?;
        Ok(Self {
            inner: Arc::new(Inner {
                root,
                limits,
                gate: Mutex::new(()),
                _lock: lock,
            }),
        })
    }

    fn get_sync(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        let _guard = self.inner.gate.lock().map_err(|_| unavailable())?;
        validate_descriptor(descriptor, self.inner.limits, maximum_bytes)?;
        read_verified(self.inner.root.as_path(), descriptor)
    }

    fn put_sync(&self, payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        let _guard = self.inner.gate.lock().map_err(|_| unavailable())?;
        let descriptor = payload.descriptor();
        validate_descriptor(
            descriptor,
            self.inner.limits,
            self.inner.limits.maximum_single_archive_bytes(),
        )?;
        match read_verified(self.inner.root.as_path(), descriptor) {
            Ok(existing) if existing.bytes() == payload.bytes() => {
                return Ok(PutBlobOutcome::AlreadyPresent);
            }
            Ok(_) => return Err(integrity()),
            Err(error) if error.kind() == BlobStoreErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        evict_for(
            self.inner.root.as_path(),
            self.inner.limits,
            descriptor.size(),
        )?;
        let final_name = archive_name(descriptor);
        let stage_name = format!("{STAGING_PREFIX}{}", descriptor.digest());
        let stage_path = self.inner.root.as_path().join(&stage_name);
        let mut stage = open_file(&stage_path, true, true)?;
        ensure_regular(&stage)?;
        stage
            .write_all(payload.bytes())
            .map_err(|_| unavailable())?;
        stage.sync_all().map_err(|_| unavailable())?;
        drop(stage);
        fs::rename(&stage_path, self.inner.root.as_path().join(final_name))
            .map_err(|_| unavailable())?;
        sync_root(self.inner.root.as_path())?;
        Ok(PutBlobOutcome::Created)
    }
}

#[async_trait]
impl ImmutableBlobStore for FileActionArchiveCache {
    async fn put_if_absent(&self, payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        let cache = self.clone();
        tokio::task::spawn_blocking(move || cache.put_sync(payload))
            .await
            .map_err(|_| unavailable())?
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        let cache = self.clone();
        let descriptor = descriptor.clone();
        tokio::task::spawn_blocking(move || cache.get_sync(&descriptor, maximum_bytes))
            .await
            .map_err(|_| unavailable())?
    }
}

fn validate_descriptor(
    descriptor: &BlobDescriptor,
    limits: ActionArchiveCacheLimits,
    maximum_bytes: u64,
) -> Result<(), BlobStoreError> {
    if descriptor.size() == 0
        || descriptor.size() > maximum_bytes
        || descriptor.size() > limits.maximum_single_archive_bytes()
        || descriptor.media_type().as_str() != ACTION_MEDIA_TYPE
        || descriptor.key().as_str() != format!("{ACTION_KEY_PREFIX}{}.tar.gz", descriptor.digest())
    {
        return Err(BlobStoreError::new(BlobStoreErrorKind::InvalidResponse));
    }
    Ok(())
}

fn archive_name(descriptor: &BlobDescriptor) -> String {
    format!("{ARCHIVE_PREFIX}{}{ARCHIVE_SUFFIX}", descriptor.digest())
}

fn read_verified(root: &Path, descriptor: &BlobDescriptor) -> Result<VerifiedBlob, BlobStoreError> {
    let path = root.join(archive_name(descriptor));
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(not_found()),
        Err(_) => return Err(unavailable()),
    };
    ensure_regular(&file)?;
    let received = file.metadata().map_err(|_| unavailable())?.len();
    if received != descriptor.size() {
        return Err(integrity());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(received).map_err(|_| too_large())?);
    file.take(received.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    let payload =
        BlobPayload::verify(descriptor.clone(), Bytes::from(bytes)).map_err(|_| integrity())?;
    Ok(VerifiedBlob::from_payload(payload))
}

fn evict_for(
    root: &Path,
    limits: ActionArchiveCacheLimits,
    incoming: u64,
) -> Result<(), BlobStoreError> {
    let mut entries = Vec::new();
    let mut total = 0_u64;
    for entry in fs::read_dir(root).map_err(|_| unavailable())? {
        let entry = entry.map_err(|_| unavailable())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(ARCHIVE_PREFIX) || !name.ends_with(ARCHIVE_SUFFIX) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| unavailable())?;
        if !metadata.file_type().is_file() || metadata.nlink() != 1 {
            return Err(integrity());
        }
        total = total.checked_add(metadata.len()).ok_or_else(too_large)?;
        entries.push((
            metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            name.into_owned(),
            metadata.len(),
        ));
    }
    entries.sort_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)));
    let mut changed = false;
    while entries.len() >= limits.maximum_entries()
        || total
            .checked_add(incoming)
            .is_none_or(|size| size > limits.maximum_bytes())
    {
        let (_, name, size) = entries.first().cloned().ok_or_else(too_large)?;
        fs::remove_file(root.join(&name)).map_err(|_| unavailable())?;
        entries.remove(0);
        total = total.checked_sub(size).ok_or_else(integrity)?;
        changed = true;
    }
    if changed {
        sync_root(root)?;
    }
    Ok(())
}

fn cleanup_staging(root: &Path) -> Result<(), BlobStoreError> {
    let mut changed = false;
    for entry in fs::read_dir(root).map_err(|_| unavailable())? {
        let entry = entry.map_err(|_| unavailable())?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(STAGING_PREFIX)
        {
            fs::remove_file(entry.path()).map_err(|_| unavailable())?;
            changed = true;
        }
    }
    if changed {
        sync_root(root)?;
    }
    Ok(())
}

fn open_file(path: &Path, write: bool, create_new: bool) -> Result<File, BlobStoreError> {
    let mut options = OpenOptions::new();
    options
        .read(!write)
        .write(write)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    options.open(path).map_err(|_| unavailable())
}

fn ensure_regular(file: &File) -> Result<(), BlobStoreError> {
    let metadata = file.metadata().map_err(|_| unavailable())?;
    if metadata.file_type().is_file() && metadata.nlink() == 1 {
        Ok(())
    } else {
        Err(integrity())
    }
}

fn sync_root(root: &Path) -> Result<(), BlobStoreError> {
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| unavailable())
}

const fn not_found() -> BlobStoreError {
    BlobStoreError::new(BlobStoreErrorKind::NotFound)
}

const fn integrity() -> BlobStoreError {
    BlobStoreError::new(BlobStoreErrorKind::Integrity)
}

const fn too_large() -> BlobStoreError {
    BlobStoreError::new(BlobStoreErrorKind::TooLarge)
}

const fn unavailable() -> BlobStoreError {
    BlobStoreError::new(BlobStoreErrorKind::Unavailable)
}
