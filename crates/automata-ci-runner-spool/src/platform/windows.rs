use std::{
    collections::HashSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use automata_ci_core::OperationId;

use crate::{
    ContentCommitFaultInjector, ContentCommitStage, DurableContentRef, SpoolError, SpoolLimits,
    SpoolRoot,
};

const LOCK_FILE: &str = ".runner-spool.lock";
const CONTENT_SUFFIX: &str = ".blob";
const STAGING_PREFIX: &str = ".runner-spool.stage-";

// Win32 constants exposed through safe standard-library extension traits.
// Omitting delete sharing stabilizes every retained directory and file handle.
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SpoolUsage {
    pub(crate) objects: u32,
    pub(crate) protected_bytes: u64,
}

pub(crate) struct PlatformDirectory {
    root_path: PathBuf,
    // Spool bytes are authenticated ciphertext. Windows deployments must still
    // pre-provision restrictive ACLs on the configured root and its ancestors;
    // these handles provide topology stability rather than ACL attestation.
    _directory_handles: Vec<File>,
    _lock_file: File,
}

impl fmt::Debug for PlatformDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlatformDirectory")
            .field("root_path", &self.root_path)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct CommitFailure {
    error: SpoolError,
    renamed: bool,
}

impl CommitFailure {
    const fn new(error: SpoolError, renamed: bool) -> Self {
        Self { error, renamed }
    }

    pub(crate) const fn renamed(&self) -> bool {
        self.renamed
    }

    pub(crate) fn into_public(self) -> SpoolError {
        self.error
    }
}

impl PlatformDirectory {
    pub(crate) fn open(root: &SpoolRoot) -> Result<Self, SpoolError> {
        let root_path = root.as_path().to_path_buf();
        let directory_handles = open_or_create_directory_chain(&root_path)?;
        let lock_file = open_lock(&root_path)?;
        Ok(Self {
            root_path,
            _directory_handles: directory_handles,
            _lock_file: lock_file,
        })
    }

    pub(crate) fn cleanup_staging(&self) -> Result<(), SpoolError> {
        let entries = self.read_directory("scan content staging files")?;
        let mut removed = false;
        for entry in entries {
            let entry = entry.map_err(|error| {
                SpoolError::io("read content staging entry", self.root_path.clone(), error)
            })?;
            if !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(STAGING_PREFIX))
            {
                continue;
            }
            let path = entry.path();
            let Some(file) = open_regular_file(&path, false, "open content staging file")? else {
                continue;
            };
            drop(file);
            match fs::remove_file(&path) {
                Ok(()) => removed = true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(SpoolError::io(
                        "remove abandoned content staging file",
                        path,
                        error,
                    ));
                }
            }
        }
        if removed {
            self.sync_directory("sync spool root after recovery")?;
        }
        Ok(())
    }

    pub(crate) fn scan_usage(&self, limits: SpoolLimits) -> Result<SpoolUsage, SpoolError> {
        let entries = self.read_directory("scan durable content")?;
        let mut usage = SpoolUsage::default();
        for entry in entries {
            let entry = entry.map_err(|error| {
                SpoolError::io("read durable content entry", self.root_path.clone(), error)
            })?;
            let name = entry_name(&entry)?;
            if is_ignored_entry(&name) {
                continue;
            }
            if !name.ends_with(CONTENT_SUFFIX) {
                return Err(SpoolError::PathSecurity);
            }
            let path = entry.path();
            let file =
                open_required_regular_file(&path, false, "open durable content during scan")?;
            let protected_bytes = regular_file_size(&file, &path)?;
            add_retained_usage(&mut usage, protected_bytes, limits)?;
        }
        Ok(usage)
    }

    pub(crate) fn prune_except(
        &self,
        retained: &HashSet<Vec<u8>>,
        limits: SpoolLimits,
    ) -> Result<SpoolUsage, CommitFailure> {
        let entries = self
            .read_directory("scan content for reconciliation")
            .map_err(|error| CommitFailure::new(error, false))?;
        let mut usage = SpoolUsage::default();
        let mut removed = false;
        for entry in entries {
            let entry = entry.map_err(|error| {
                CommitFailure::new(
                    SpoolError::io(
                        "read content reconciliation entry",
                        self.root_path.clone(),
                        error,
                    ),
                    removed,
                )
            })?;
            let name = entry_name(&entry).map_err(|error| CommitFailure::new(error, removed))?;
            if is_ignored_entry(&name) {
                continue;
            }
            if !name.ends_with(CONTENT_SUFFIX) {
                return Err(CommitFailure::new(SpoolError::PathSecurity, removed));
            }
            let path = entry.path();
            let file = open_required_regular_file(
                &path,
                false,
                "open durable content during reconciliation",
            )
            .map_err(|error| CommitFailure::new(error, removed))?;
            let protected_bytes = regular_file_size(&file, &path)
                .map_err(|error| CommitFailure::new(error, removed))?;
            if retained.contains(name.as_bytes()) {
                add_retained_usage(&mut usage, protected_bytes, limits)
                    .map_err(|error| CommitFailure::new(error, removed))?;
                continue;
            }
            drop(file);
            fs::remove_file(&path).map_err(|error| {
                CommitFailure::new(
                    SpoolError::io("remove unreferenced protected content", path, error),
                    removed,
                )
            })?;
            removed = true;
        }
        if removed {
            self.sync_directory("sync protected-content reconciliation")
                .map_err(|error| CommitFailure::new(error, true))?;
        }
        Ok(usage)
    }

    pub(crate) fn read(
        &self,
        reference: &DurableContentRef,
        maximum: u64,
    ) -> Result<Option<Vec<u8>>, SpoolError> {
        let path = self.root_path.join(content_filename(reference));
        let Some(mut file) = open_regular_file(&path, false, "open protected content")? else {
            return Ok(None);
        };
        let received = regular_file_size(&file, &path)?;
        if received > maximum {
            return Err(SpoolError::CapacityExhausted);
        }
        let mut bytes = Vec::with_capacity(usize::try_from(received).unwrap_or(0));
        Read::by_ref(&mut file)
            .take(maximum.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| SpoolError::io("read protected content", path, error))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
            return Err(SpoolError::CapacityExhausted);
        }
        Ok(Some(bytes))
    }

    pub(crate) fn remove(&self, reference: &DurableContentRef) -> Result<bool, CommitFailure> {
        let path = self.root_path.join(content_filename(reference));
        let file = open_regular_file(&path, false, "open protected content for removal")
            .map_err(|error| CommitFailure::new(error, false))?;
        let Some(file) = file else {
            return Ok(false);
        };
        drop(file);
        match fs::remove_file(&path) {
            Ok(()) => {
                self.sync_directory("sync protected-content removal")
                    .map_err(|error| CommitFailure::new(error, true))?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(CommitFailure::new(
                SpoolError::io("remove protected content", path, error),
                false,
            )),
        }
    }

    pub(crate) fn commit(
        &self,
        reference: &DurableContentRef,
        bytes: &[u8],
        faults: &dyn ContentCommitFaultInjector,
    ) -> Result<(), CommitFailure> {
        let staging_name = format!("{STAGING_PREFIX}{}", OperationId::new());
        let staging_path = self.root_path.join(staging_name);
        let mut staging = create_regular_file(&staging_path, "create content staging file")
            .map_err(|error| CommitFailure::new(error, false))?;
        inject(faults, ContentCommitStage::StagingCreated, false)?;
        staging.write_all(bytes).map_err(|error| {
            CommitFailure::new(
                SpoolError::io("write protected content", staging_path.clone(), error),
                false,
            )
        })?;
        inject(faults, ContentCommitStage::DataWritten, false)?;
        staging.sync_all().map_err(|error| {
            CommitFailure::new(
                SpoolError::io("sync protected content", staging_path.clone(), error),
                false,
            )
        })?;
        inject(faults, ContentCommitStage::FileSynced, false)?;
        drop(staging);

        let target = self.root_path.join(content_filename(reference));
        fs::rename(&staging_path, &target).map_err(|error| {
            CommitFailure::new(
                SpoolError::io("atomically publish protected content", target, error),
                false,
            )
        })?;
        inject(faults, ContentCommitStage::Renamed, true)?;
        self.sync_directory("sync protected content directory")
            .map_err(|error| CommitFailure::new(error, true))?;
        inject(faults, ContentCommitStage::DirectorySynced, true)?;
        Ok(())
    }

    fn read_directory(&self, operation: &'static str) -> Result<fs::ReadDir, SpoolError> {
        fs::read_dir(&self.root_path)
            .map_err(|error| SpoolError::io(operation, self.root_path.clone(), error))
    }

    fn sync_directory(&self, operation: &'static str) -> Result<(), SpoolError> {
        sync_directory_path(&self.root_path, operation)
    }
}

fn open_or_create_directory_chain(root_path: &Path) -> Result<Vec<File>, SpoolError> {
    let mut paths = root_path.ancestors().collect::<Vec<_>>();
    paths.reverse();
    let mut handles = Vec::with_capacity(paths.len());
    for (index, path) in paths.into_iter().enumerate() {
        let handle = match open_directory(path, false) {
            Ok(handle) => handle,
            Err(error) if error.kind() == io::ErrorKind::NotFound && index > 0 => {
                match fs::create_dir(path) {
                    Ok(()) => sync_directory_path(
                        path.parent().ok_or(SpoolError::PathSecurity)?,
                        "sync newly created spool-root directory entry",
                    )?,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(SpoolError::io(
                            "create spool-root directory",
                            path.to_path_buf(),
                            error,
                        ));
                    }
                }
                open_directory(path, false)
                    .map_err(|error| map_path_open("open spool-root directory", root_path, error))?
            }
            Err(error) => {
                return Err(map_path_open("open spool-root directory", root_path, error));
            }
        };
        ensure_directory(&handle, path)?;
        handles.push(handle);
    }
    Ok(handles)
}

fn open_lock(root_path: &Path) -> Result<File, SpoolError> {
    let path = root_path.join(LOCK_FILE);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let lock = options
        .open(&path)
        .map_err(|error| map_path_open("open content-spool lock", &path, error))?;
    ensure_regular_file(&lock, &path)?;
    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(fs::TryLockError::WouldBlock) => Err(SpoolError::AlreadyLocked),
        Err(fs::TryLockError::Error(error)) => {
            Err(SpoolError::io("lock content spool", path, error))
        }
    }
}

fn open_regular_file(
    path: &Path,
    writable: bool,
    operation: &'static str,
) -> Result<Option<File>, SpoolError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    match options.open(path) {
        Ok(file) => {
            ensure_regular_file(&file, path)?;
            Ok(Some(file))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(map_path_open(operation, path, error)),
    }
}

fn open_required_regular_file(
    path: &Path,
    writable: bool,
    operation: &'static str,
) -> Result<File, SpoolError> {
    open_regular_file(path, writable, operation)?.ok_or_else(|| {
        SpoolError::io(
            operation,
            path.to_path_buf(),
            io::Error::new(io::ErrorKind::NotFound, "filesystem entry disappeared"),
        )
    })
}

fn create_regular_file(path: &Path, operation: &'static str) -> Result<File, SpoolError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|error| map_path_open(operation, path, error))?;
    ensure_regular_file(&file, path)?;
    Ok(file)
}

fn open_directory(path: &Path, writable: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(!writable)
        .write(writable)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

fn sync_directory_path(path: &Path, operation: &'static str) -> Result<(), SpoolError> {
    let directory =
        open_directory(path, true).map_err(|error| map_path_open(operation, path, error))?;
    ensure_directory(&directory, path)?;
    directory
        .sync_all()
        .map_err(|error| SpoolError::io(operation, path.to_path_buf(), error))
}

fn entry_name(entry: &fs::DirEntry) -> Result<String, SpoolError> {
    entry
        .file_name()
        .to_str()
        .map(str::to_owned)
        .ok_or(SpoolError::PathSecurity)
}

fn is_ignored_entry(name: &str) -> bool {
    name == LOCK_FILE || name.starts_with(STAGING_PREFIX)
}

fn content_filename(reference: &DurableContentRef) -> String {
    format!("{}{CONTENT_SUFFIX}", reference.cache_key().as_str())
}

fn ensure_directory(file: &File, path: &Path) -> Result<(), SpoolError> {
    let metadata = file
        .metadata()
        .map_err(|error| SpoolError::io("inspect spool directory", path.to_path_buf(), error))?;
    if metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        Ok(())
    } else {
        Err(SpoolError::PathSecurity)
    }
}

fn ensure_regular_file(file: &File, path: &Path) -> Result<(), SpoolError> {
    let metadata = file
        .metadata()
        .map_err(|error| SpoolError::io("inspect spool file", path.to_path_buf(), error))?;
    if metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        Ok(())
    } else {
        Err(SpoolError::PathSecurity)
    }
}

fn regular_file_size(file: &File, path: &Path) -> Result<u64, SpoolError> {
    ensure_regular_file(file, path)?;
    file.metadata()
        .map(|metadata| metadata.len())
        .map_err(|error| SpoolError::io("inspect content size", path.to_path_buf(), error))
}

fn add_retained_usage(
    usage: &mut SpoolUsage,
    protected_bytes: u64,
    limits: SpoolLimits,
) -> Result<(), SpoolError> {
    if protected_bytes > limits.max_encoded_object_bytes() {
        return Err(SpoolError::CapacityExhausted);
    }
    usage.objects = usage
        .objects
        .checked_add(1)
        .ok_or(SpoolError::CapacityExhausted)?;
    usage.protected_bytes = usage
        .protected_bytes
        .checked_add(protected_bytes)
        .ok_or(SpoolError::CapacityExhausted)?;
    if usage.objects > limits.max_objects() || usage.protected_bytes > limits.max_total_bytes() {
        Err(SpoolError::CapacityExhausted)
    } else {
        Ok(())
    }
}

fn inject(
    faults: &dyn ContentCommitFaultInjector,
    stage: ContentCommitStage,
    renamed: bool,
) -> Result<(), CommitFailure> {
    faults
        .check(stage)
        .map_err(|_| CommitFailure::new(SpoolError::InjectedFault(stage), renamed))
}

fn map_path_open(operation: &'static str, path: &Path, error: io::Error) -> SpoolError {
    if matches!(
        error.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::NotADirectory
    ) {
        SpoolError::PathSecurity
    } else {
        SpoolError::io(operation, path.to_path_buf(), error)
    }
}

#[cfg(test)]
mod tests {
    use automata_ci_core::Sha256Digest;

    use super::*;
    use crate::{ContentKind, NoContentCommitFaults, ProtectionId};

    #[test]
    fn protected_content_round_trips_and_lock_is_exclusive() {
        let path = std::env::temp_dir().join(format!(
            "automata-spool-windows-test-{}",
            OperationId::new()
        ));
        let root = SpoolRoot::explicit(&path).expect("valid test spool root");
        let directory = PlatformDirectory::open(&root).expect("open spool root");
        assert!(matches!(
            PlatformDirectory::open(&root),
            Err(SpoolError::AlreadyLocked)
        ));
        let reference = DurableContentRef::after_commit(
            ContentKind::LogSpool,
            7,
            Sha256Digest::from_bytes([7; 32]),
            ProtectionId::new("test-key").expect("valid protection identifier"),
        )
        .expect("valid durable content reference");
        directory
            .commit(&reference, b"ciphertext", &NoContentCommitFaults)
            .expect("commit protected content");
        directory
            .commit(&reference, b"ciphertext", &NoContentCommitFaults)
            .expect("replace protected content idempotently");
        assert_eq!(
            directory.read(&reference, 32).expect("read content"),
            Some(b"ciphertext".to_vec())
        );
        assert!(directory.remove(&reference).expect("remove content"));
        drop(directory);
        fs::remove_dir_all(path).expect("remove test spool root");
    }
}
