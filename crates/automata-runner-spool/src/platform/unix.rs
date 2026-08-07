use std::{
    collections::HashSet,
    ffi::{CStr, OsString},
    fmt,
    fs::File,
    io::{self, Read, Write},
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
};

use automata_core::OperationId;
use rustix::{
    fd::OwnedFd,
    fs::{
        self, AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, fchmod, flock, fstat, mkdirat,
        openat, renameat, unlinkat,
    },
    io::Errno,
};

use crate::{
    ContentCommitFaultInjector, ContentCommitStage, DurableContentRef, SpoolError, SpoolLimits,
    SpoolRoot,
};

const LOCK_FILE: &str = ".runner-spool.lock";
const CONTENT_SUFFIX: &[u8] = b".blob";
const STAGING_PREFIX: &[u8] = b".runner-spool.stage-";
const DIRECTORY_MODE: Mode = Mode::from_raw_mode(0o700);
const FILE_MODE: Mode = Mode::from_raw_mode(0o600);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SpoolUsage {
    pub(crate) objects: u32,
    pub(crate) protected_bytes: u64,
}

pub(crate) struct PlatformDirectory {
    root_path: PathBuf,
    root_fd: OwnedFd,
    _lock_fd: OwnedFd,
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
        let components: Vec<OsString> = root
            .as_path()
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(value) => Some(value.to_os_string()),
                _ => None,
            })
            .collect();
        let directory_flags =
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        let mut current = fs::open("/", directory_flags, Mode::empty()).map_err(|error| {
            SpoolError::io("open filesystem root", root_path.clone(), error.into())
        })?;
        for component in components {
            current = open_or_create_directory(&current, &component, &root_path, directory_flags)?;
        }
        ensure_directory(&current, &root_path)?;
        fchmod(&current, DIRECTORY_MODE).map_err(|error| {
            SpoolError::io(
                "set spool-root permissions",
                root_path.clone(),
                error.into(),
            )
        })?;
        let lock_fd = open_lock(&current, &root_path)?;
        Ok(Self {
            root_path,
            root_fd: current,
            _lock_fd: lock_fd,
        })
    }

    pub(crate) fn cleanup_staging(&self) -> Result<(), SpoolError> {
        let mut directory = self.read_directory("scan content staging files")?;
        let mut removed = false;
        while let Some(entry) = directory.read() {
            let entry = entry.map_err(|error| {
                SpoolError::io(
                    "read content staging entry",
                    self.root_path.clone(),
                    error.into(),
                )
            })?;
            if entry.file_name().to_bytes().starts_with(STAGING_PREFIX) {
                match unlinkat(&self.root_fd, entry.file_name(), AtFlags::empty()) {
                    Ok(()) | Err(Errno::NOENT) => removed = true,
                    Err(error) => {
                        return Err(SpoolError::io(
                            "remove abandoned content staging file",
                            self.root_path.clone(),
                            error.into(),
                        ));
                    }
                }
            }
        }
        if removed {
            self.sync_directory("sync spool root after recovery")?;
        }
        Ok(())
    }

    pub(crate) fn scan_usage(&self, limits: SpoolLimits) -> Result<SpoolUsage, SpoolError> {
        let mut directory = self.read_directory("scan durable content")?;
        let mut usage = SpoolUsage::default();
        while let Some(entry) = directory.read() {
            let entry = entry.map_err(|error| {
                SpoolError::io(
                    "read durable content entry",
                    self.root_path.clone(),
                    error.into(),
                )
            })?;
            let name = entry.file_name();
            if is_ignored_entry(name) {
                continue;
            }
            if !name.to_bytes().ends_with(CONTENT_SUFFIX) {
                return Err(SpoolError::PathSecurity);
            }
            let file = self.open_content_name(name, "open durable content during scan")?;
            secure_file_permissions(&file, &self.root_path)?;
            let protected_bytes = regular_file_size(&file, &self.root_path)?;
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
            if usage.objects > limits.max_objects()
                || usage.protected_bytes > limits.max_total_bytes()
            {
                return Err(SpoolError::CapacityExhausted);
            }
        }
        Ok(usage)
    }

    pub(crate) fn prune_except(
        &self,
        retained: &HashSet<Vec<u8>>,
        limits: SpoolLimits,
    ) -> Result<SpoolUsage, CommitFailure> {
        let mut directory = self
            .read_directory("scan content for reconciliation")
            .map_err(|error| CommitFailure::new(error, false))?;
        let mut usage = SpoolUsage::default();
        let mut removed = false;
        while let Some(entry) = directory.read() {
            let entry = entry.map_err(|error| {
                CommitFailure::new(
                    SpoolError::io(
                        "read content reconciliation entry",
                        self.root_path.clone(),
                        error.into(),
                    ),
                    removed,
                )
            })?;
            let name = entry.file_name();
            if is_ignored_entry(name) {
                continue;
            }
            if !name.to_bytes().ends_with(CONTENT_SUFFIX) {
                return Err(CommitFailure::new(SpoolError::PathSecurity, removed));
            }
            let file = self
                .open_content_name(name, "open durable content during reconciliation")
                .map_err(|error| CommitFailure::new(error, removed))?;
            secure_file_permissions(&file, &self.root_path)
                .map_err(|error| CommitFailure::new(error, removed))?;
            let protected_bytes = regular_file_size(&file, &self.root_path)
                .map_err(|error| CommitFailure::new(error, removed))?;
            if retained.contains(name.to_bytes()) {
                add_retained_usage(&mut usage, protected_bytes, limits)
                    .map_err(|error| CommitFailure::new(error, removed))?;
                continue;
            }
            unlinkat(&self.root_fd, name, AtFlags::empty()).map_err(|error| {
                CommitFailure::new(
                    SpoolError::io(
                        "remove unreferenced protected content",
                        self.root_path.clone(),
                        error.into(),
                    ),
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
        let name = content_filename(reference);
        let path = self.root_path.join(&name);
        let file = match openat(
            &self.root_fd,
            name.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(map_path_open("open protected content", &path, error)),
        };
        secure_file_permissions(&file, &path)?;
        let received = regular_file_size(&file, &path)?;
        if received > maximum {
            return Err(SpoolError::CapacityExhausted);
        }
        let mut bytes = Vec::with_capacity(usize::try_from(received).unwrap_or(0));
        File::from(file)
            .take(maximum.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| SpoolError::io("read protected content", path, error))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
            return Err(SpoolError::CapacityExhausted);
        }
        Ok(Some(bytes))
    }

    pub(crate) fn remove(&self, reference: &DurableContentRef) -> Result<bool, CommitFailure> {
        let name = content_filename(reference);
        match unlinkat(&self.root_fd, name.as_str(), AtFlags::empty()) {
            Ok(()) => {
                self.sync_directory("sync protected-content removal")
                    .map_err(|error| CommitFailure::new(error, true))?;
                Ok(true)
            }
            Err(Errno::NOENT) => Ok(false),
            Err(error) => Err(CommitFailure::new(
                SpoolError::io(
                    "remove protected content",
                    self.root_path.join(name),
                    error.into(),
                ),
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
        let staging_name = format!(".runner-spool.stage-{}", OperationId::new());
        let staging_path = self.root_path.join(&staging_name);
        let staging_fd = openat(
            &self.root_fd,
            staging_name.as_str(),
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            FILE_MODE,
        )
        .map_err(|error| {
            CommitFailure::new(
                map_path_open("create content staging file", &staging_path, error),
                false,
            )
        })?;
        ensure_regular_file(&staging_fd, &staging_path)
            .map_err(|error| CommitFailure::new(error, false))?;
        fchmod(&staging_fd, FILE_MODE).map_err(|error| {
            CommitFailure::new(
                SpoolError::io(
                    "set content staging permissions",
                    staging_path.clone(),
                    error.into(),
                ),
                false,
            )
        })?;
        inject(faults, ContentCommitStage::StagingCreated, false)?;
        let mut staging = File::from(staging_fd);
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
        let target = content_filename(reference);
        renameat(
            &self.root_fd,
            staging_name.as_str(),
            &self.root_fd,
            target.as_str(),
        )
        .map_err(|error| {
            CommitFailure::new(
                SpoolError::io(
                    "atomically publish protected content",
                    self.root_path.join(&target),
                    error.into(),
                ),
                false,
            )
        })?;
        inject(faults, ContentCommitStage::Renamed, true)?;
        self.sync_directory("sync protected content directory")
            .map_err(|error| CommitFailure::new(error, true))?;
        inject(faults, ContentCommitStage::DirectorySynced, true)?;
        Ok(())
    }

    fn read_directory(&self, operation: &'static str) -> Result<Dir, SpoolError> {
        Dir::read_from(&self.root_fd)
            .map_err(|error| SpoolError::io(operation, self.root_path.clone(), error.into()))
    }

    fn open_content_name(
        &self,
        name: &CStr,
        operation: &'static str,
    ) -> Result<OwnedFd, SpoolError> {
        let path = self
            .root_path
            .join(std::ffi::OsStr::from_bytes(name.to_bytes()));
        openat(
            &self.root_fd,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| map_path_open(operation, &path, error))
    }

    fn sync_directory(&self, operation: &'static str) -> Result<(), SpoolError> {
        fs::fsync(&self.root_fd)
            .map_err(|error| SpoolError::io(operation, self.root_path.clone(), error.into()))
    }
}

fn open_or_create_directory(
    current: &OwnedFd,
    component: &OsString,
    root_path: &Path,
    flags: OFlags,
) -> Result<OwnedFd, SpoolError> {
    match openat(current, component, flags, Mode::empty()) {
        Ok(next) => Ok(next),
        Err(Errno::NOENT) => {
            match mkdirat(current, component, DIRECTORY_MODE) {
                Ok(()) => fs::fsync(current).map_err(|error| {
                    SpoolError::io(
                        "sync newly created spool-root directory entry",
                        root_path.to_path_buf(),
                        error.into(),
                    )
                })?,
                Err(Errno::EXIST) => {}
                Err(error) => {
                    return Err(SpoolError::io(
                        "create spool-root directory",
                        root_path.to_path_buf(),
                        error.into(),
                    ));
                }
            }
            openat(current, component, flags, Mode::empty())
                .map_err(|error| map_path_open("open spool-root directory", root_path, error))
        }
        Err(error) => Err(map_path_open("open spool-root directory", root_path, error)),
    }
}

fn open_lock(root: &OwnedFd, root_path: &Path) -> Result<OwnedFd, SpoolError> {
    let path = root_path.join(LOCK_FILE);
    let lock = openat(
        root,
        LOCK_FILE,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        FILE_MODE,
    )
    .map_err(|error| map_path_open("open content-spool lock", &path, error))?;
    ensure_regular_file(&lock, &path)?;
    fchmod(&lock, FILE_MODE).map_err(|error| {
        SpoolError::io(
            "set content-spool lock permissions",
            path.clone(),
            error.into(),
        )
    })?;
    if let Err(error) = flock(&lock, FlockOperation::NonBlockingLockExclusive) {
        if error == Errno::AGAIN || error == Errno::WOULDBLOCK {
            return Err(SpoolError::AlreadyLocked);
        }
        return Err(SpoolError::io("lock content spool", path, error.into()));
    }
    Ok(lock)
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

fn content_filename(reference: &DurableContentRef) -> String {
    format!("{}.blob", reference.cache_key().as_str())
}

fn is_ignored_entry(name: &CStr) -> bool {
    matches!(name.to_bytes(), b"." | b".." | b".runner-spool.lock")
        || name.to_bytes().starts_with(STAGING_PREFIX)
}

fn ensure_directory(fd: &OwnedFd, path: &Path) -> Result<(), SpoolError> {
    let stat = fstat(fd).map_err(|error| {
        SpoolError::io("inspect spool directory", path.to_path_buf(), error.into())
    })?;
    if FileType::from_raw_mode(stat.st_mode).is_dir() {
        Ok(())
    } else {
        Err(SpoolError::PathSecurity)
    }
}

fn ensure_regular_file(fd: &OwnedFd, path: &Path) -> Result<(), SpoolError> {
    let stat = fstat(fd)
        .map_err(|error| SpoolError::io("inspect spool file", path.to_path_buf(), error.into()))?;
    if FileType::from_raw_mode(stat.st_mode).is_file() && stat.st_nlink == 1 {
        Ok(())
    } else {
        Err(SpoolError::PathSecurity)
    }
}

fn regular_file_size(fd: &OwnedFd, path: &Path) -> Result<u64, SpoolError> {
    ensure_regular_file(fd, path)?;
    let stat = fstat(fd).map_err(|error| {
        SpoolError::io("inspect content size", path.to_path_buf(), error.into())
    })?;
    u64::try_from(stat.st_size).map_err(|_| SpoolError::PathSecurity)
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

fn secure_file_permissions(fd: &OwnedFd, path: &Path) -> Result<(), SpoolError> {
    fchmod(fd, FILE_MODE).map_err(|error| {
        SpoolError::io(
            "set protected-content permissions",
            path.into(),
            error.into(),
        )
    })?;
    fs::fsync(fd).map_err(|error| {
        SpoolError::io(
            "sync protected-content permissions",
            path.into(),
            error.into(),
        )
    })
}

fn map_path_open(operation: &'static str, path: &Path, error: Errno) -> SpoolError {
    if error == Errno::LOOP || error == Errno::NOTDIR {
        SpoolError::PathSecurity
    } else {
        SpoolError::io(operation, path.to_path_buf(), io::Error::from(error))
    }
}
