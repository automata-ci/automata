use std::{
    ffi::OsString,
    fs::File,
    io::{Read as _, Write as _},
};

use automata_ci_action::{ActionReferenceIndexError, ActionReferenceIndexErrorKind};
use rustix::{
    fd::OwnedFd,
    fs::{
        self, AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, fchmod, flock, fstat, mkdirat,
        openat, renameat, unlinkat,
    },
    io::Errno,
};

use super::super::ActionReferenceIndexRoot;

const INDEX_FILE: &str = "action-reference-index-v1.json";
const LOCK_FILE: &str = ".action-reference-index.lock";
const STAGING_PREFIX: &[u8] = b".action-reference-index.stage-";
const DIRECTORY_MODE: Mode = Mode::from_raw_mode(0o700);
const FILE_MODE: Mode = Mode::from_raw_mode(0o600);

pub(crate) struct PlatformDirectory {
    root_fd: OwnedFd,
    lock_fd: OwnedFd,
}

impl PlatformDirectory {
    pub(crate) fn open(root: &ActionReferenceIndexRoot) -> Result<Self, ActionReferenceIndexError> {
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
        let mut current =
            fs::open("/", directory_flags, Mode::empty()).map_err(|_| unavailable())?;
        for component in components {
            current = match openat(&current, &component, directory_flags, Mode::empty()) {
                Ok(next) => next,
                Err(Errno::NOENT) => {
                    match mkdirat(&current, &component, DIRECTORY_MODE) {
                        Ok(()) => fs::fsync(&current).map_err(|_| unavailable())?,
                        Err(Errno::EXIST) => {}
                        Err(_) => return Err(unavailable()),
                    }
                    openat(&current, &component, directory_flags, Mode::empty())
                        .map_err(map_open_error)?
                }
                Err(error) => return Err(map_open_error(error)),
            };
        }
        ensure_directory(&current)?;
        fchmod(&current, DIRECTORY_MODE).map_err(|_| unavailable())?;

        let lock_fd = openat(
            &current,
            LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            FILE_MODE,
        )
        .map_err(map_open_error)?;
        ensure_regular_file(&lock_fd)?;
        fchmod(&lock_fd, FILE_MODE).map_err(|_| unavailable())?;
        if let Err(error) = flock(&lock_fd, FlockOperation::NonBlockingLockExclusive) {
            if error == Errno::AGAIN || error == Errno::WOULDBLOCK {
                return Err(ActionReferenceIndexError::new(
                    ActionReferenceIndexErrorKind::AlreadyLocked,
                ));
            }
            return Err(unavailable());
        }
        Ok(Self {
            root_fd: current,
            lock_fd,
        })
    }

    #[cfg(test)]
    pub(crate) fn duplicate_lock_for_test(&self) -> OwnedFd {
        rustix::io::dup(&self.lock_fd).expect("duplicate action-reference index lock")
    }

    pub(crate) fn cleanup_staging(&self) -> Result<(), ActionReferenceIndexError> {
        let mut directory = Dir::read_from(&self.root_fd).map_err(|_| unavailable())?;
        let mut removed = false;
        while let Some(entry) = directory.read() {
            let entry = entry.map_err(|_| unavailable())?;
            if entry.file_name().to_bytes().starts_with(STAGING_PREFIX) {
                match unlinkat(&self.root_fd, entry.file_name(), AtFlags::empty()) {
                    Ok(()) | Err(Errno::NOENT) => removed = true,
                    Err(_) => return Err(unavailable()),
                }
            }
        }
        if removed {
            fs::fsync(&self.root_fd).map_err(|_| unavailable())?;
        }
        Ok(())
    }

    pub(crate) fn read_index(
        &self,
        maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, ActionReferenceIndexError> {
        let file = match openat(
            &self.root_fd,
            INDEX_FILE,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(map_open_error(error)),
        };
        ensure_regular_file(&file)?;
        fchmod(&file, FILE_MODE).map_err(|_| unavailable())?;
        let metadata = fstat(&file).map_err(|_| unavailable())?;
        let received = usize::try_from(metadata.st_size).map_err(|_| exhausted())?;
        if received > maximum_bytes {
            return Err(exhausted());
        }
        let mut bytes = Vec::with_capacity(received);
        File::from(file)
            .take(u64::try_from(maximum_bytes).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| unavailable())?;
        if bytes.len() > maximum_bytes {
            return Err(exhausted());
        }
        Ok(Some(bytes))
    }

    pub(crate) fn commit(&self, generation: u64, bytes: &[u8]) -> Result<(), CommitFailure> {
        let staging_name = format!(".action-reference-index.stage-{generation}");
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
        .map_err(|error| CommitFailure::new(map_open_error(error), false))?;
        ensure_regular_file(&staging_fd).map_err(|error| CommitFailure::new(error, false))?;
        fchmod(&staging_fd, FILE_MODE).map_err(|_| CommitFailure::new(unavailable(), false))?;
        let mut staging = File::from(staging_fd);
        staging
            .write_all(bytes)
            .map_err(|_| CommitFailure::new(unavailable(), false))?;
        staging
            .sync_all()
            .map_err(|_| CommitFailure::new(unavailable(), false))?;
        drop(staging);
        renameat(
            &self.root_fd,
            staging_name.as_str(),
            &self.root_fd,
            INDEX_FILE,
        )
        .map_err(|_| CommitFailure::new(unavailable(), false))?;
        fs::fsync(&self.root_fd).map_err(|_| CommitFailure::new(unavailable(), true))?;
        Ok(())
    }
}

impl Drop for PlatformDirectory {
    fn drop(&mut self) {
        // A fork inherits this open file description before `CLOEXEC` can
        // close its descriptor. Unlock explicitly so teardown does not wait
        // for every inherited duplicate to close.
        let _ = flock(&self.lock_fd, FlockOperation::Unlock);
    }
}

pub(crate) struct CommitFailure {
    _error: ActionReferenceIndexError,
    renamed: bool,
}

impl CommitFailure {
    const fn new(error: ActionReferenceIndexError, renamed: bool) -> Self {
        Self {
            _error: error,
            renamed,
        }
    }

    pub(crate) const fn renamed(&self) -> bool {
        self.renamed
    }
}

fn ensure_directory(fd: &OwnedFd) -> Result<(), ActionReferenceIndexError> {
    let metadata = fstat(fd).map_err(|_| unavailable())?;
    if FileType::from_raw_mode(metadata.st_mode).is_dir() {
        Ok(())
    } else {
        Err(corrupt())
    }
}

fn ensure_regular_file(fd: &OwnedFd) -> Result<(), ActionReferenceIndexError> {
    let metadata = fstat(fd).map_err(|_| unavailable())?;
    if FileType::from_raw_mode(metadata.st_mode).is_file() && metadata.st_nlink == 1 {
        Ok(())
    } else {
        Err(corrupt())
    }
}

fn map_open_error(error: Errno) -> ActionReferenceIndexError {
    if error == Errno::LOOP || error == Errno::NOTDIR {
        corrupt()
    } else {
        unavailable()
    }
}

const fn corrupt() -> ActionReferenceIndexError {
    ActionReferenceIndexError::new(ActionReferenceIndexErrorKind::Corrupt)
}

const fn exhausted() -> ActionReferenceIndexError {
    ActionReferenceIndexError::new(ActionReferenceIndexErrorKind::ResourceExhausted)
}

const fn unavailable() -> ActionReferenceIndexError {
    ActionReferenceIndexError::new(ActionReferenceIndexErrorKind::Unavailable)
}
