use std::{
    ffi::OsString,
    fmt,
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
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

use crate::{CommitFaultInjector, CommitStage, JournalError, MAX_JOURNAL_BYTES, StateRoot};

const STATE_FILE: &str = "runner-journal.json";
const LEGACY_STATE_FILE: &str = "runner-journal-v1.json";
const LOCK_FILE: &str = ".runner-journal.lock";
const STAGING_PREFIX: &[u8] = b".runner-journal.stage-";
const DIRECTORY_MODE: Mode = Mode::from_raw_mode(0o700);
const FILE_MODE: Mode = Mode::from_raw_mode(0o600);

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
    error: JournalError,
    renamed: bool,
}

impl CommitFailure {
    const fn new(error: JournalError, renamed: bool) -> Self {
        Self { error, renamed }
    }

    pub(crate) const fn renamed(&self) -> bool {
        self.renamed
    }

    pub(crate) fn into_public(self) -> JournalError {
        self.error
    }
}

impl PlatformDirectory {
    pub(crate) fn open(root: &StateRoot) -> Result<Self, JournalError> {
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
            JournalError::io("open filesystem root", root_path.clone(), error.into())
        })?;
        for component in components {
            current = match openat(&current, &component, directory_flags, Mode::empty()) {
                Ok(next) => next,
                Err(Errno::NOENT) => {
                    match mkdirat(&current, &component, DIRECTORY_MODE) {
                        Ok(()) => fs::fsync(&current).map_err(|error| {
                            JournalError::io(
                                "sync newly created state-root directory entry",
                                root_path.clone(),
                                error.into(),
                            )
                        })?,
                        Err(Errno::EXIST) => {}
                        Err(error) => {
                            return Err(JournalError::io(
                                "create state-root directory",
                                root_path.clone(),
                                error.into(),
                            ));
                        }
                    }
                    openat(&current, &component, directory_flags, Mode::empty()).map_err(
                        |error| map_path_open("open state-root directory", &root_path, error),
                    )?
                }
                Err(error) => {
                    return Err(map_path_open(
                        "open state-root directory",
                        &root_path,
                        error,
                    ));
                }
            };
        }
        ensure_directory(&current, &root_path)?;
        fchmod(&current, DIRECTORY_MODE).map_err(|error| {
            JournalError::io(
                "set state-root permissions",
                root_path.clone(),
                error.into(),
            )
        })?;

        let lock_path = root_path.join(LOCK_FILE);
        let lock_fd = openat(
            &current,
            LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            FILE_MODE,
        )
        .map_err(|error| map_path_open("open journal lock", &lock_path, error))?;
        ensure_regular_file(&lock_fd, &lock_path)?;
        fchmod(&lock_fd, FILE_MODE).map_err(|error| {
            JournalError::io(
                "set journal lock permissions",
                lock_path.clone(),
                error.into(),
            )
        })?;
        if let Err(error) = flock(&lock_fd, FlockOperation::NonBlockingLockExclusive) {
            if error == Errno::AGAIN || error == Errno::WOULDBLOCK {
                return Err(JournalError::AlreadyLocked);
            }
            return Err(JournalError::io(
                "lock runner journal",
                lock_path,
                error.into(),
            ));
        }

        Ok(Self {
            root_path,
            root_fd: current,
            _lock_fd: lock_fd,
        })
    }

    pub(crate) fn cleanup_staging(&self) -> Result<(), JournalError> {
        let mut directory = Dir::read_from(&self.root_fd).map_err(|error| {
            JournalError::io(
                "scan journal staging files",
                self.root_path.clone(),
                error.into(),
            )
        })?;
        let mut removed = false;
        while let Some(entry) = directory.read() {
            let entry = entry.map_err(|error| {
                JournalError::io(
                    "read journal staging entry",
                    self.root_path.clone(),
                    error.into(),
                )
            })?;
            if entry.file_name().to_bytes().starts_with(STAGING_PREFIX) {
                match unlinkat(&self.root_fd, entry.file_name(), AtFlags::empty()) {
                    Ok(()) | Err(Errno::NOENT) => removed = true,
                    Err(error) => {
                        return Err(JournalError::io(
                            "remove abandoned journal staging file",
                            self.root_path.clone(),
                            error.into(),
                        ));
                    }
                }
            }
        }
        if removed {
            fs::fsync(&self.root_fd).map_err(|error| {
                JournalError::io(
                    "sync state root after recovery",
                    self.root_path.clone(),
                    error.into(),
                )
            })?;
        }
        Ok(())
    }

    pub(crate) fn read_state(&self) -> Result<Option<Vec<u8>>, JournalError> {
        let state_path = self.root_path.join(STATE_FILE);
        let (state_fd, state_path) =
            if let Some(file) = self.open_state_file(STATE_FILE, &state_path)? {
                (file, state_path)
            } else {
                let legacy_path = self.root_path.join(LEGACY_STATE_FILE);
                match self.open_state_file(LEGACY_STATE_FILE, &legacy_path)? {
                    Some(file) => (file, legacy_path),
                    None => return Ok(None),
                }
            };
        ensure_regular_file(&state_fd, &state_path)?;
        fchmod(&state_fd, FILE_MODE).map_err(|error| {
            JournalError::io("set journal permissions", state_path.clone(), error.into())
        })?;
        let stat = fstat(&state_fd).map_err(|error| {
            JournalError::io("inspect runner journal", state_path.clone(), error.into())
        })?;
        let received = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
        if received > u64::try_from(MAX_JOURNAL_BYTES).unwrap_or(u64::MAX) {
            return Err(JournalError::Oversized {
                maximum: MAX_JOURNAL_BYTES,
                received,
            });
        }
        let mut bytes = Vec::with_capacity(usize::try_from(received).unwrap_or(0));
        File::from(state_fd)
            .take(u64::try_from(MAX_JOURNAL_BYTES).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| JournalError::io("read runner journal", state_path, error))?;
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err(JournalError::Oversized {
                maximum: MAX_JOURNAL_BYTES,
                received: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            });
        }
        Ok(Some(bytes))
    }

    fn open_state_file(
        &self,
        name: &str,
        path: &std::path::Path,
    ) -> Result<Option<OwnedFd>, JournalError> {
        match openat(
            &self.root_fd,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(file) => Ok(Some(file)),
            Err(Errno::NOENT) => Ok(None),
            Err(error) => Err(map_path_open("open runner journal", path, error)),
        }
    }

    pub(crate) fn commit(
        &self,
        revision: u64,
        bytes: &[u8],
        faults: &dyn CommitFaultInjector,
    ) -> Result<(), CommitFailure> {
        let staging_name = format!(".runner-journal.stage-{revision}-{}", OperationId::new());
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
                map_path_open("create journal staging file", &staging_path, error),
                false,
            )
        })?;
        ensure_regular_file(&staging_fd, &staging_path)
            .map_err(|error| CommitFailure::new(error, false))?;
        fchmod(&staging_fd, FILE_MODE).map_err(|error| {
            CommitFailure::new(
                JournalError::io(
                    "set journal staging permissions",
                    staging_path.clone(),
                    error.into(),
                ),
                false,
            )
        })?;
        inject(faults, CommitStage::StagingCreated, false)?;

        let mut staging = File::from(staging_fd);
        staging.write_all(bytes).map_err(|error| {
            CommitFailure::new(
                JournalError::io("write journal staging file", staging_path.clone(), error),
                false,
            )
        })?;
        inject(faults, CommitStage::DataWritten, false)?;
        staging.sync_all().map_err(|error| {
            CommitFailure::new(
                JournalError::io("sync journal staging file", staging_path.clone(), error),
                false,
            )
        })?;
        inject(faults, CommitStage::FileSynced, false)?;
        drop(staging);

        renameat(
            &self.root_fd,
            staging_name.as_str(),
            &self.root_fd,
            STATE_FILE,
        )
        .map_err(|error| {
            CommitFailure::new(
                JournalError::io(
                    "atomically replace runner journal",
                    self.root_path.join(STATE_FILE),
                    error.into(),
                ),
                false,
            )
        })?;
        inject(faults, CommitStage::Renamed, true)?;
        fs::fsync(&self.root_fd).map_err(|error| {
            CommitFailure::new(
                JournalError::io(
                    "sync state-root directory",
                    self.root_path.clone(),
                    error.into(),
                ),
                true,
            )
        })?;
        inject(faults, CommitStage::DirectorySynced, true)?;
        Ok(())
    }
}

fn inject(
    faults: &dyn CommitFaultInjector,
    stage: CommitStage,
    renamed: bool,
) -> Result<(), CommitFailure> {
    faults
        .check(stage)
        .map_err(|_| CommitFailure::new(JournalError::InjectedFault(stage), renamed))
}

fn ensure_directory(fd: &OwnedFd, path: &std::path::Path) -> Result<(), JournalError> {
    let stat = fstat(fd).map_err(|error| {
        JournalError::io(
            "inspect state-root directory",
            path.to_path_buf(),
            error.into(),
        )
    })?;
    if FileType::from_raw_mode(stat.st_mode).is_dir() {
        Ok(())
    } else {
        Err(JournalError::PathSecurity)
    }
}

fn ensure_regular_file(fd: &OwnedFd, path: &std::path::Path) -> Result<(), JournalError> {
    let stat = fstat(fd).map_err(|error| {
        JournalError::io("inspect journal file", path.to_path_buf(), error.into())
    })?;
    if FileType::from_raw_mode(stat.st_mode).is_file() && stat.st_nlink == 1 {
        Ok(())
    } else {
        Err(JournalError::PathSecurity)
    }
}

fn map_path_open(operation: &'static str, path: &std::path::Path, error: Errno) -> JournalError {
    if error == Errno::LOOP || error == Errno::NOTDIR {
        JournalError::PathSecurity
    } else {
        JournalError::io(operation, path.to_path_buf(), io::Error::from(error))
    }
}
