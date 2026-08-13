use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use automata_ci_core::OperationId;

use crate::{CommitFaultInjector, CommitStage, JournalError, MAX_JOURNAL_BYTES, StateRoot};

const STATE_FILE: &str = "runner-journal.json";
const OBSOLETE_STATE_FILE: &str = "runner-journal-v1.json";
const LOCK_FILE: &str = ".runner-journal.lock";
const STAGING_PREFIX: &str = ".runner-journal.stage-";

// Win32 constants exposed by `OpenOptionsExt` without requiring an unsafe FFI
// boundary. Delete sharing is deliberately omitted so every retained handle
// stabilizes the path component it names.
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

pub(crate) struct PlatformDirectory {
    root_path: PathBuf,
    // Retaining the entire chain without delete sharing prevents any opened
    // ancestor or the root itself from being renamed out from under path-based
    // std operations.
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
        let directory_handles = open_or_create_directory_chain(&root_path)?;
        let lock_file = open_lock(&root_path)?;
        Ok(Self {
            root_path,
            _directory_handles: directory_handles,
            _lock_file: lock_file,
        })
    }

    pub(crate) fn cleanup_staging(&self) -> Result<(), JournalError> {
        let entries = fs::read_dir(&self.root_path).map_err(|error| {
            JournalError::io("scan journal staging files", self.root_path.clone(), error)
        })?;
        let mut removed = false;
        for entry in entries {
            let entry = entry.map_err(|error| {
                JournalError::io("read journal staging entry", self.root_path.clone(), error)
            })?;
            if !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(STAGING_PREFIX))
            {
                continue;
            }
            let path = entry.path();
            let Some(file) = open_regular_file(&path, false, "open journal staging file")? else {
                continue;
            };
            drop(file);
            match fs::remove_file(&path) {
                Ok(()) => removed = true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(JournalError::io(
                        "remove abandoned journal staging file",
                        path,
                        error,
                    ));
                }
            }
        }
        if removed {
            self.sync_directory("sync state root after recovery")?;
        }
        Ok(())
    }

    pub(crate) fn read_state(&self) -> Result<Option<Vec<u8>>, JournalError> {
        let obsolete_path = self.root_path.join(OBSOLETE_STATE_FILE);
        if open_regular_file(&obsolete_path, false, "open obsolete runner journal")?.is_some() {
            return Err(JournalError::ObsoleteState);
        }

        let state_path = self.root_path.join(STATE_FILE);
        let Some(mut state_file) = open_regular_file(&state_path, false, "open runner journal")?
        else {
            return Ok(None);
        };
        let received = regular_file_size(&state_file, &state_path)?;
        if received > u64::try_from(MAX_JOURNAL_BYTES).unwrap_or(u64::MAX) {
            return Err(JournalError::Oversized {
                maximum: MAX_JOURNAL_BYTES,
                received,
            });
        }
        let mut bytes = Vec::with_capacity(usize::try_from(received).unwrap_or(0));
        Read::by_ref(&mut state_file)
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

    pub(crate) fn commit(
        &self,
        revision: u64,
        bytes: &[u8],
        faults: &dyn CommitFaultInjector,
    ) -> Result<(), CommitFailure> {
        let staging_name = format!("{STAGING_PREFIX}{revision}-{}", OperationId::new());
        let staging_path = self.root_path.join(&staging_name);
        let mut staging = create_regular_file(&staging_path, "create journal staging file")
            .map_err(|error| CommitFailure::new(error, false))?;
        inject(faults, CommitStage::StagingCreated, false)?;

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

        let state_path = self.root_path.join(STATE_FILE);
        fs::rename(&staging_path, &state_path).map_err(|error| {
            CommitFailure::new(
                JournalError::io("atomically replace runner journal", state_path, error),
                false,
            )
        })?;
        inject(faults, CommitStage::Renamed, true)?;
        self.sync_directory("sync state-root directory")
            .map_err(|error| CommitFailure::new(error, true))?;
        inject(faults, CommitStage::DirectorySynced, true)?;
        Ok(())
    }

    fn sync_directory(&self, operation: &'static str) -> Result<(), JournalError> {
        let directory = open_directory(&self.root_path, true)
            .map_err(|error| map_path_open(operation, &self.root_path, error))?;
        ensure_directory(&directory, &self.root_path)?;
        directory
            .sync_all()
            .map_err(|error| JournalError::io(operation, self.root_path.clone(), error))
    }
}

fn open_or_create_directory_chain(root_path: &Path) -> Result<Vec<File>, JournalError> {
    let mut paths = root_path.ancestors().collect::<Vec<_>>();
    paths.reverse();
    let mut handles = Vec::with_capacity(paths.len());
    for (index, path) in paths.into_iter().enumerate() {
        let handle = match open_directory(path, false) {
            Ok(handle) => handle,
            Err(error) if error.kind() == io::ErrorKind::NotFound && index > 0 => {
                match fs::create_dir(path) {
                    Ok(()) => sync_directory_path(
                        path.parent().ok_or(JournalError::PathSecurity)?,
                        "sync newly created state-root directory entry",
                    )?,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(JournalError::io(
                            "create state-root directory",
                            path.to_path_buf(),
                            error,
                        ));
                    }
                }
                open_directory(path, false)
                    .map_err(|error| map_path_open("open state-root directory", root_path, error))?
            }
            Err(error) => {
                return Err(map_path_open("open state-root directory", root_path, error));
            }
        };
        ensure_directory(&handle, path)?;
        handles.push(handle);
    }
    Ok(handles)
}

fn open_lock(root_path: &Path) -> Result<File, JournalError> {
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
        .map_err(|error| map_path_open("open journal lock", &path, error))?;
    ensure_regular_file(&lock, &path)?;
    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(fs::TryLockError::WouldBlock) => Err(JournalError::AlreadyLocked),
        Err(fs::TryLockError::Error(error)) => {
            Err(JournalError::io("lock runner journal", path, error))
        }
    }
}

fn open_regular_file(
    path: &Path,
    writable: bool,
    operation: &'static str,
) -> Result<Option<File>, JournalError> {
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

fn create_regular_file(path: &Path, operation: &'static str) -> Result<File, JournalError> {
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

fn sync_directory_path(path: &Path, operation: &'static str) -> Result<(), JournalError> {
    let directory =
        open_directory(path, true).map_err(|error| map_path_open(operation, path, error))?;
    ensure_directory(&directory, path)?;
    directory
        .sync_all()
        .map_err(|error| JournalError::io(operation, path.to_path_buf(), error))
}

fn ensure_directory(file: &File, path: &Path) -> Result<(), JournalError> {
    let metadata = file.metadata().map_err(|error| {
        JournalError::io("inspect state-root directory", path.to_path_buf(), error)
    })?;
    if metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        Ok(())
    } else {
        Err(JournalError::PathSecurity)
    }
}

fn ensure_regular_file(file: &File, path: &Path) -> Result<(), JournalError> {
    let metadata = file
        .metadata()
        .map_err(|error| JournalError::io("inspect journal file", path.to_path_buf(), error))?;
    if metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        Ok(())
    } else {
        Err(JournalError::PathSecurity)
    }
}

fn regular_file_size(file: &File, path: &Path) -> Result<u64, JournalError> {
    ensure_regular_file(file, path)?;
    file.metadata()
        .map(|metadata| metadata.len())
        .map_err(|error| JournalError::io("inspect runner journal", path.to_path_buf(), error))
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

fn map_path_open(operation: &'static str, path: &Path, error: io::Error) -> JournalError {
    if matches!(
        error.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::NotADirectory
    ) {
        JournalError::PathSecurity
    } else {
        JournalError::io(operation, path.to_path_buf(), error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoCommitFaults;

    #[test]
    fn commit_round_trips_and_lock_is_exclusive() {
        let path = std::env::temp_dir().join(format!(
            "automata-journal-windows-test-{}",
            OperationId::new()
        ));
        let root = StateRoot::explicit(&path).expect("valid test state root");
        let directory = PlatformDirectory::open(&root).expect("open state root");
        assert!(matches!(
            PlatformDirectory::open(&root),
            Err(JournalError::AlreadyLocked)
        ));
        directory
            .commit(1, b"journal", &NoCommitFaults)
            .expect("commit journal");
        directory
            .commit(2, b"journal-2", &NoCommitFaults)
            .expect("replace journal");
        assert_eq!(
            directory.read_state().expect("read journal"),
            Some(b"journal-2".to_vec())
        );
        drop(directory);
        fs::remove_dir_all(path).expect("remove test state root");
    }
}
