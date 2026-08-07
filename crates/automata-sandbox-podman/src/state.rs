use std::{
    ffi::OsStr,
    fmt,
    path::{Component, Path, PathBuf},
};

use crate::PodmanStateRootError;

const TEMPORARY_COMPONENT: &str = "tmp";

/// Explicit, pre-created local state root used for Podman workspaces and the
/// adapter lock. The exact canonical path is retained so callers cannot switch
/// it through a symlink after validation.
#[derive(Clone, Eq, PartialEq)]
pub struct PodmanStateRoot(PathBuf);

impl PodmanStateRoot {
    /// Validates an existing absolute, canonical, owner-only directory.
    ///
    /// # Errors
    ///
    /// Rejects filesystem roots, traversal, symlinks, temporary hierarchies,
    /// foreign ownership, and permissions broader than `0700`.
    pub fn existing(path: impl Into<PathBuf>) -> Result<Self, PodmanStateRootError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(PodmanStateRootError::Relative);
        }
        if path.parent().is_none() {
            return Err(PodmanStateRootError::FilesystemRoot);
        }
        if path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(PodmanStateRootError::Traversal);
        }
        if path
            .components()
            .any(|component| component.as_os_str() == OsStr::new(TEMPORARY_COMPONENT))
        {
            return Err(PodmanStateRootError::TemporaryHierarchy);
        }
        let canonical = std::fs::canonicalize(&path).map_err(|_| PodmanStateRootError::Io {
            operation: "canonicalize state root",
            path: path.clone(),
        })?;
        if canonical != path {
            return Err(PodmanStateRootError::NotCanonical);
        }
        validate_root_metadata(&path)?;
        Ok(Self(path))
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl fmt::Debug for PodmanStateRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PodmanStateRoot")
            .field(&self.0)
            .finish()
    }
}

#[cfg(unix)]
fn validate_root_metadata(path: &Path) -> Result<(), PodmanStateRootError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(path).map_err(|_| PodmanStateRootError::Io {
        operation: "inspect state root",
        path: path.to_path_buf(),
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(PodmanStateRootError::PathSecurity);
    }
    let current_uid: u32 = rustix::process::geteuid().as_raw();
    if metadata.uid() != current_uid || metadata.mode() & 0o777 != 0o700 {
        return Err(PodmanStateRootError::NotOwnerOnly);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_root_metadata(_path: &Path) -> Result<(), PodmanStateRootError> {
    Err(PodmanStateRootError::UnsupportedPlatform)
}

#[cfg(unix)]
mod local {
    use std::{
        fmt,
        fs::File,
        io::{Read as _, Write as _},
        os::unix::ffi::OsStrExt as _,
        path::{Path, PathBuf},
    };

    use automata_execution::OperationId;
    use rustix::{
        fd::OwnedFd,
        fs::{
            self, AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, fchmod, flock, fstat,
            mkdirat, openat, unlinkat,
        },
        io::Errno,
    };

    use super::PodmanStateRoot;
    use crate::PodmanStateRootError;

    const DIRECTORY_MODE: Mode = Mode::from_raw_mode(0o700);
    const FILE_MODE: Mode = Mode::from_raw_mode(0o600);
    const LOCK_NAME: &str = ".automata-podman.lock";
    const WORKSPACES_NAME: &str = "workspaces";
    const HOOKS_NAME: &str = "empty-hooks";
    const TRANSFERS_NAME: &str = "transfers";
    const ENGINES_NAME: &str = "job-engines";
    const PROCESS_TRANSIENT_NAME: &str = "process-transient";
    const PAYLOAD_NAME: &str = "payload";

    pub(crate) struct LocalState {
        root_path: PathBuf,
        root_fd: OwnedFd,
        workspaces_fd: OwnedFd,
        transfers_fd: OwnedFd,
        engines_fd: OwnedFd,
        _lock_fd: OwnedFd,
    }

    impl fmt::Debug for LocalState {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("LocalState")
                .field("root_path", &self.root_path)
                .finish_non_exhaustive()
        }
    }

    impl LocalState {
        pub(crate) fn open(root: &PodmanStateRoot) -> Result<Self, PodmanStateRootError> {
            let root_path = root.as_path().to_path_buf();
            let directory_flags =
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            let root_fd = fs::open(&root_path, directory_flags, Mode::empty())
                .map_err(|error| map_open("open state root", &root_path, error))?;
            ensure_owned_directory(&root_fd, &root_path)?;
            let lock_fd = open_lock(&root_fd, &root_path)?;
            let workspaces_fd =
                open_or_create_child(&root_fd, WORKSPACES_NAME, &root_path, directory_flags)?;
            let _hooks_fd =
                open_or_create_child(&root_fd, HOOKS_NAME, &root_path, directory_flags)?;
            let transfers_fd =
                open_or_create_child(&root_fd, TRANSFERS_NAME, &root_path, directory_flags)?;
            let engines_fd =
                open_or_create_child(&root_fd, ENGINES_NAME, &root_path, directory_flags)?;
            let _process_transient_fd = open_or_create_child(
                &root_fd,
                PROCESS_TRANSIENT_NAME,
                &root_path,
                directory_flags,
            )?;
            cleanup_abandoned_transfers(&transfers_fd, &root_path.join(TRANSFERS_NAME))?;
            Ok(Self {
                root_path,
                root_fd,
                workspaces_fd,
                transfers_fd,
                engines_fd,
                _lock_fd: lock_fd,
            })
        }

        pub(crate) fn hooks_path(&self) -> PathBuf {
            self.root_path.join(HOOKS_NAME)
        }

        pub(crate) fn ensure_workspace(&self, name: &str) -> Result<PathBuf, PodmanStateRootError> {
            validate_internal_name(name)?;
            let path = self.root_path.join(WORKSPACES_NAME).join(name);
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            let fd = open_or_create_child(&self.workspaces_fd, name, &path, flags)?;
            ensure_owned_directory(&fd, &path)?;
            Ok(path)
        }

        pub(crate) fn workspace_cleanup_target(
            &self,
            name: &str,
        ) -> Result<Option<PathBuf>, PodmanStateRootError> {
            validate_internal_name(name)?;
            let path = self.root_path.join(WORKSPACES_NAME).join(name);
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            let fd = match openat(&self.workspaces_fd, name, flags, Mode::empty()) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => return Ok(None),
                Err(error) => return Err(map_open("open workspace for deletion", &path, error)),
            };
            ensure_owned_directory(&fd, &path)?;
            Ok(Some(path))
        }

        pub(crate) fn confirm_workspace_removed(
            &self,
            name: &str,
        ) -> Result<(), PodmanStateRootError> {
            validate_internal_name(name)?;
            let path = self.root_path.join(WORKSPACES_NAME).join(name);
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            match openat(&self.workspaces_fd, name, flags, Mode::empty()) {
                Err(Errno::NOENT) => {}
                Ok(fd) => {
                    ensure_owned_directory(&fd, &path)?;
                    return Err(PodmanStateRootError::Io {
                        operation: "verify exact workspace deletion",
                        path,
                    });
                }
                Err(error) => {
                    return Err(map_open("verify exact workspace deletion", &path, error));
                }
            }
            fs::fsync(&self.workspaces_fd).map_err(|_| PodmanStateRootError::Io {
                operation: "sync workspace directory",
                path: self.root_path.join(WORKSPACES_NAME),
            })?;
            Ok(())
        }

        pub(crate) fn workspace_exists(&self, name: &str) -> Result<bool, PodmanStateRootError> {
            validate_internal_name(name)?;
            let path = self.root_path.join(WORKSPACES_NAME).join(name);
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            match openat(&self.workspaces_fd, name, flags, Mode::empty()) {
                Ok(fd) => {
                    ensure_owned_directory(&fd, &path)?;
                    Ok(true)
                }
                Err(Errno::NOENT) => Ok(false),
                Err(error) => Err(map_open("inspect workspace", &path, error)),
            }
        }

        pub(crate) fn ensure_job_engine(
            &self,
            name: &str,
        ) -> Result<JobEnginePaths, PodmanStateRootError> {
            validate_internal_name(name)?;
            let (backend_name, public_name) = job_engine_socket_names(name)?;
            let path = self.root_path.join(ENGINES_NAME).join(name);
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            let engine = open_or_create_child(&self.engines_fd, name, &path, flags)?;
            for child in ["graph", "run"] {
                let child_path = path.join(child);
                let child_fd = open_or_create_child(&engine, child, &child_path, flags)?;
                ensure_owned_directory(&child_fd, &child_path)?;
            }
            let public_directory = self.root_path.join(&public_name);
            let public =
                open_or_create_child(&self.root_fd, &public_name, &public_directory, flags)?;
            ensure_owned_directory(&public, &public_directory)?;
            fs::fsync(&engine).map_err(|_| PodmanStateRootError::Io {
                operation: "sync job engine directory",
                path: path.clone(),
            })?;
            Ok(JobEnginePaths {
                graph_root: path.join("graph"),
                run_root: path.join("run"),
                backend_socket: self.root_path.join(backend_name),
                public_socket: public_directory.join("docker.sock"),
                public_directory,
            })
        }

        pub(crate) fn remove_job_engine(&self, name: &str) -> Result<bool, PodmanStateRootError> {
            validate_internal_name(name)?;
            let (backend_name, public_name) = job_engine_socket_names(name)?;
            let path = self.root_path.join(ENGINES_NAME).join(name);
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            let engine = match openat(&self.engines_fd, name, flags, Mode::empty()) {
                Ok(fd) => {
                    ensure_owned_directory(&fd, &path)?;
                    Some(fd)
                }
                Err(Errno::NOENT) => None,
                Err(error) => return Err(map_open("open job engine for deletion", &path, error)),
            };
            let mut removed = remove_owned_socket_if_present(
                &self.root_path.join(&backend_name),
                "remove job engine backend socket",
            )?;
            let public_path = self.root_path.join(&public_name);
            let public = match openat(&self.root_fd, &public_name, flags, Mode::empty()) {
                Ok(public) => {
                    ensure_owned_directory(&public, &public_path)?;
                    Some(public)
                }
                Err(Errno::NOENT) => None,
                Err(error) => {
                    return Err(map_open(
                        "open job engine public socket directory",
                        &public_path,
                        error,
                    ));
                }
            };
            if let Some(public) = public {
                let _socket_removed = remove_owned_socket_if_present(
                    &public_path.join("docker.sock"),
                    "remove job engine public socket",
                )?;
                drop(public);
                unlinkat(&self.root_fd, &public_name, AtFlags::REMOVEDIR).map_err(|_| {
                    PodmanStateRootError::Io {
                        operation: "remove job engine public socket directory",
                        path: public_path,
                    }
                })?;
                removed = true;
            }
            if let Some(engine) = engine {
                drop(engine);
                std::fs::remove_dir_all(&path).map_err(|_| PodmanStateRootError::Io {
                    operation: "remove exact job engine tree",
                    path: path.clone(),
                })?;
                removed = true;
            }
            if !removed {
                return Ok(false);
            }
            fs::fsync(&self.engines_fd).map_err(|_| PodmanStateRootError::Io {
                operation: "sync job engine root",
                path: self.root_path.join(ENGINES_NAME),
            })?;
            fs::fsync(&self.root_fd).map_err(|_| PodmanStateRootError::Io {
                operation: "sync state root after job engine cleanup",
                path: self.root_path.clone(),
            })?;
            Ok(removed)
        }

        pub(crate) fn stage_input(
            &self,
            prefix: &str,
            operation_id: OperationId,
            content: &[u8],
        ) -> Result<StagedInput<'_>, PodmanStateRootError> {
            validate_internal_name(prefix)?;
            let name = format!("{prefix}-{}", operation_id.as_uuid().simple());
            validate_internal_name(&name)?;
            let path = self.root_path.join(TRANSFERS_NAME).join(&name);
            let fd = openat(
                &self.transfers_fd,
                &name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                FILE_MODE,
            )
            .map_err(|error| map_open("create transfer input", &path, error))?;
            if let Err(error) = ensure_owned_regular_file(&fd, &path) {
                let _ignored = unlinkat(&self.transfers_fd, &name, AtFlags::empty());
                return Err(error);
            }
            if fchmod(&fd, FILE_MODE).is_err() {
                let _ignored = unlinkat(&self.transfers_fd, &name, AtFlags::empty());
                return Err(PodmanStateRootError::Io {
                    operation: "set transfer input permissions",
                    path,
                });
            }
            let identity = match FileIdentity::read(&fd, &path) {
                Ok(identity) => identity,
                Err(error) => {
                    let _ignored = unlinkat(&self.transfers_fd, &name, AtFlags::empty());
                    return Err(error);
                }
            };
            let mut file = File::from(fd);
            if file
                .write_all(content)
                .and_then(|()| file.sync_all())
                .is_err()
            {
                let _ignored = unlinkat(&self.transfers_fd, &name, AtFlags::empty());
                return Err(PodmanStateRootError::Io {
                    operation: "write and sync transfer input",
                    path: path.clone(),
                });
            }
            if let Err(error) = self.sync_transfers() {
                let _ignored = unlinkat(&self.transfers_fd, &name, AtFlags::empty());
                return Err(error);
            }
            Ok(StagedInput {
                state: self,
                name,
                path,
                identity,
                _file: file,
                active: true,
            })
        }

        pub(crate) fn stage_output(
            &self,
            operation_id: OperationId,
        ) -> Result<StagedOutput<'_>, PodmanStateRootError> {
            let name = format!("copy-out-{}", operation_id.as_uuid().simple());
            validate_internal_name(&name)?;
            let path = self.root_path.join(TRANSFERS_NAME).join(&name);
            mkdirat(&self.transfers_fd, &name, DIRECTORY_MODE)
                .map_err(|error| map_open("create transfer output directory", &path, error))?;
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            let directory = match openat(&self.transfers_fd, &name, flags, Mode::empty()) {
                Ok(directory) => directory,
                Err(error) => {
                    let _ignored = unlinkat(&self.transfers_fd, &name, AtFlags::REMOVEDIR);
                    return Err(map_open("open transfer output directory", &path, error));
                }
            };
            if let Err(error) = ensure_owned_directory(&directory, &path) {
                let _ignored = unlinkat(&self.transfers_fd, &name, AtFlags::REMOVEDIR);
                return Err(error);
            }
            let identity = match FileIdentity::read(&directory, &path) {
                Ok(identity) => identity,
                Err(error) => {
                    let _ignored = unlinkat(&self.transfers_fd, &name, AtFlags::REMOVEDIR);
                    return Err(error);
                }
            };
            if let Err(error) = self.sync_transfers() {
                let _ignored = unlinkat(&self.transfers_fd, &name, AtFlags::REMOVEDIR);
                return Err(error);
            }
            Ok(StagedOutput {
                state: self,
                name,
                path,
                directory,
                identity,
                active: true,
            })
        }

        fn remove_staged_file(
            &self,
            name: &str,
            identity: FileIdentity,
            path: &Path,
        ) -> Result<(), PodmanStateRootError> {
            let current = openat(
                &self.transfers_fd,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| map_open("open transfer input for cleanup", path, error))?;
            ensure_owned_regular_file(&current, path)?;
            if FileIdentity::read(&current, path)? != identity {
                return Err(PodmanStateRootError::PathSecurity);
            }
            unlinkat(&self.transfers_fd, name, AtFlags::empty()).map_err(|_| {
                PodmanStateRootError::Io {
                    operation: "remove transfer input",
                    path: path.to_path_buf(),
                }
            })?;
            self.sync_transfers()
        }

        fn remove_staged_output(
            &self,
            name: &str,
            identity: FileIdentity,
            path: &Path,
        ) -> Result<(), PodmanStateRootError> {
            let current = openat(
                &self.transfers_fd,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| map_open("open transfer output for cleanup", path, error))?;
            ensure_owned_directory(&current, path)?;
            if FileIdentity::read(&current, path)? != identity {
                return Err(PodmanStateRootError::PathSecurity);
            }
            drop(current);
            std::fs::remove_dir_all(path).map_err(|_| PodmanStateRootError::Io {
                operation: "remove exact transfer output tree",
                path: path.to_path_buf(),
            })?;
            self.sync_transfers()
        }

        fn sync_transfers(&self) -> Result<(), PodmanStateRootError> {
            fs::fsync(&self.transfers_fd).map_err(|_| PodmanStateRootError::Io {
                operation: "sync transfer directory",
                path: self.root_path.join(TRANSFERS_NAME),
            })
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct JobEnginePaths {
        graph_root: PathBuf,
        run_root: PathBuf,
        backend_socket: PathBuf,
        public_socket: PathBuf,
        public_directory: PathBuf,
    }

    impl JobEnginePaths {
        pub(crate) fn graph_root(&self) -> &Path {
            &self.graph_root
        }

        pub(crate) fn run_root(&self) -> &Path {
            &self.run_root
        }

        pub(crate) fn backend_socket(&self) -> &Path {
            &self.backend_socket
        }

        pub(crate) fn public_socket(&self) -> &Path {
            &self.public_socket
        }

        pub(crate) fn public_directory(&self) -> &Path {
            &self.public_directory
        }
    }

    fn job_engine_socket_names(name: &str) -> Result<(String, String), PodmanStateRootError> {
        let identifier = name
            .strip_prefix("job-")
            .filter(|value| value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or(PodmanStateRootError::PathSecurity)?;
        Ok((format!(".b{identifier}.sock"), format!(".d{identifier}")))
    }

    fn remove_owned_socket_if_present(
        path: &Path,
        operation: &'static str,
    ) -> Result<bool, PodmanStateRootError> {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => {
                return Err(PodmanStateRootError::Io {
                    operation,
                    path: path.to_path_buf(),
                });
            }
        };
        if !metadata.file_type().is_socket()
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(PodmanStateRootError::PathSecurity);
        }
        std::fs::remove_file(path)
            .map(|()| true)
            .map_err(|_| PodmanStateRootError::Io {
                operation,
                path: path.to_path_buf(),
            })
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
    }

    impl FileIdentity {
        fn read(fd: &OwnedFd, path: &Path) -> Result<Self, PodmanStateRootError> {
            let stat = fstat(fd).map_err(|_| PodmanStateRootError::Io {
                operation: "inspect staged filesystem object",
                path: path.to_path_buf(),
            })?;
            Ok(Self {
                device: stat.st_dev,
                inode: stat.st_ino,
            })
        }
    }

    pub(crate) struct StagedInput<'a> {
        state: &'a LocalState,
        name: String,
        path: PathBuf,
        identity: FileIdentity,
        _file: File,
        active: bool,
    }

    impl StagedInput<'_> {
        pub(crate) fn path(&self) -> &Path {
            &self.path
        }

        pub(crate) fn verify(&self) -> Result<(), PodmanStateRootError> {
            let current = openat(
                &self.state.transfers_fd,
                &self.name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| map_open("verify transfer input", &self.path, error))?;
            ensure_owned_regular_file(&current, &self.path)?;
            let stat = fstat(&current).map_err(|_| PodmanStateRootError::Io {
                operation: "inspect transfer input permissions",
                path: self.path.clone(),
            })?;
            if stat.st_mode & 0o777 != 0o600 {
                return Err(PodmanStateRootError::PathSecurity);
            }
            if FileIdentity::read(&current, &self.path)? != self.identity {
                return Err(PodmanStateRootError::PathSecurity);
            }
            Ok(())
        }

        pub(crate) fn cleanup(mut self) -> Result<(), PodmanStateRootError> {
            let result = self
                .state
                .remove_staged_file(&self.name, self.identity, &self.path);
            self.active = result.is_err();
            result
        }
    }

    impl fmt::Debug for StagedInput<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("StagedInput")
                .field("path", &self.path)
                .field("content", &"[REDACTED]")
                .finish()
        }
    }

    impl Drop for StagedInput<'_> {
        fn drop(&mut self) {
            if self.active {
                let _ignored = self
                    .state
                    .remove_staged_file(&self.name, self.identity, &self.path);
            }
        }
    }

    pub(crate) struct StagedOutput<'a> {
        state: &'a LocalState,
        name: String,
        path: PathBuf,
        directory: OwnedFd,
        identity: FileIdentity,
        active: bool,
    }

    impl StagedOutput<'_> {
        pub(crate) fn payload_path(&self) -> PathBuf {
            self.path.join(PAYLOAD_NAME)
        }

        pub(crate) fn verify(&self) -> Result<(), PodmanStateRootError> {
            let current = openat(
                &self.state.transfers_fd,
                &self.name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| map_open("verify transfer output", &self.path, error))?;
            ensure_owned_directory(&current, &self.path)?;
            if FileIdentity::read(&current, &self.path)? != self.identity {
                return Err(PodmanStateRootError::PathSecurity);
            }
            Ok(())
        }

        pub(crate) fn read_payload(
            &self,
            byte_limit: usize,
        ) -> Result<Vec<u8>, PodmanStateRootError> {
            let path = self.payload_path();
            let fd = openat(
                &self.directory,
                PAYLOAD_NAME,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| map_open("open transfer output payload", &path, error))?;
            ensure_owned_regular_file(&fd, &path)?;
            fchmod(&fd, FILE_MODE).map_err(|_| PodmanStateRootError::Io {
                operation: "set transfer output permissions",
                path: path.clone(),
            })?;
            let stat = fstat(&fd).map_err(|_| PodmanStateRootError::Io {
                operation: "inspect transfer output size",
                path: path.clone(),
            })?;
            let size = usize::try_from(stat.st_size)
                .map_err(|_| PodmanStateRootError::TransferLimitExceeded)?;
            if size > byte_limit {
                return Err(PodmanStateRootError::TransferLimitExceeded);
            }
            let read_limit = u64::try_from(byte_limit)
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            let mut file = File::from(fd).take(read_limit);
            let mut content = Vec::with_capacity(size);
            file.read_to_end(&mut content)
                .map_err(|_| PodmanStateRootError::Io {
                    operation: "read transfer output",
                    path: path.clone(),
                })?;
            if content.len() > byte_limit {
                return Err(PodmanStateRootError::TransferLimitExceeded);
            }
            Ok(content)
        }

        pub(crate) fn cleanup(mut self) -> Result<(), PodmanStateRootError> {
            let result = self
                .state
                .remove_staged_output(&self.name, self.identity, &self.path);
            self.active = result.is_err();
            result
        }
    }

    impl fmt::Debug for StagedOutput<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("StagedOutput")
                .field("path", &self.path)
                .field("content", &"[REDACTED]")
                .finish()
        }
    }

    impl Drop for StagedOutput<'_> {
        fn drop(&mut self) {
            if self.active {
                let _ignored =
                    self.state
                        .remove_staged_output(&self.name, self.identity, &self.path);
            }
        }
    }

    fn open_lock(root: &OwnedFd, root_path: &Path) -> Result<OwnedFd, PodmanStateRootError> {
        let path = root_path.join(LOCK_NAME);
        let lock = openat(
            root,
            LOCK_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            FILE_MODE,
        )
        .map_err(|error| map_open("open state-root lock", &path, error))?;
        ensure_owned_regular_file(&lock, &path)?;
        fchmod(&lock, FILE_MODE).map_err(|_| PodmanStateRootError::Io {
            operation: "set state-root lock permissions",
            path: path.clone(),
        })?;
        if let Err(error) = flock(&lock, FlockOperation::NonBlockingLockExclusive) {
            if error == Errno::AGAIN {
                return Err(PodmanStateRootError::AlreadyLocked);
            }
            return Err(PodmanStateRootError::Io {
                operation: "lock state root",
                path,
            });
        }
        Ok(lock)
    }

    fn cleanup_abandoned_transfers(
        transfers: &OwnedFd,
        transfers_path: &Path,
    ) -> Result<(), PodmanStateRootError> {
        let mut directory = Dir::read_from(transfers).map_err(|_| PodmanStateRootError::Io {
            operation: "scan abandoned transfers",
            path: transfers_path.to_path_buf(),
        })?;
        let mut removed = false;
        while let Some(entry) = directory.read() {
            let entry = entry.map_err(|_| PodmanStateRootError::Io {
                operation: "read abandoned transfer entry",
                path: transfers_path.to_path_buf(),
            })?;
            let name = std::str::from_utf8(entry.file_name().to_bytes())
                .map_err(|_| PodmanStateRootError::PathSecurity)?;
            if matches!(name, "." | "..") {
                continue;
            }
            if !transfer_name(name) {
                return Err(PodmanStateRootError::PathSecurity);
            }
            let path =
                transfers_path.join(std::ffi::OsStr::from_bytes(entry.file_name().to_bytes()));
            match entry.file_type() {
                FileType::RegularFile => {
                    let file = openat(
                        transfers,
                        entry.file_name(),
                        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(|error| map_open("open abandoned transfer file", &path, error))?;
                    ensure_owned_regular_file(&file, &path)?;
                    let stat = fstat(&file).map_err(|_| PodmanStateRootError::Io {
                        operation: "inspect abandoned transfer permissions",
                        path: path.clone(),
                    })?;
                    if stat.st_mode & 0o777 != 0o600 {
                        return Err(PodmanStateRootError::PathSecurity);
                    }
                    unlinkat(transfers, entry.file_name(), AtFlags::empty()).map_err(|_| {
                        PodmanStateRootError::Io {
                            operation: "remove abandoned transfer file",
                            path: path.clone(),
                        }
                    })?;
                }
                FileType::Directory => {
                    let child = openat(
                        transfers,
                        entry.file_name(),
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(|error| map_open("open abandoned transfer directory", &path, error))?;
                    ensure_owned_directory(&child, &path)?;
                    drop(child);
                    std::fs::remove_dir_all(&path).map_err(|_| PodmanStateRootError::Io {
                        operation: "remove abandoned transfer directory",
                        path: path.clone(),
                    })?;
                }
                _ => return Err(PodmanStateRootError::PathSecurity),
            }
            removed = true;
        }
        if removed {
            fs::fsync(transfers).map_err(|_| PodmanStateRootError::Io {
                operation: "sync abandoned transfer cleanup",
                path: transfers_path.to_path_buf(),
            })?;
        }
        Ok(())
    }

    fn transfer_name(name: &str) -> bool {
        validate_internal_name(name).is_ok()
            && ["copy-in-", "copy-out-", "exec-env-"].iter().any(|prefix| {
                name.strip_prefix(prefix).is_some_and(|identifier| {
                    identifier.len() == 32
                        && identifier.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            })
    }

    fn open_or_create_child(
        parent: &OwnedFd,
        name: &str,
        display_path: &Path,
        flags: OFlags,
    ) -> Result<OwnedFd, PodmanStateRootError> {
        match openat(parent, name, flags, Mode::empty()) {
            Ok(fd) => {
                ensure_owned_directory(&fd, display_path)?;
                Ok(fd)
            }
            Err(Errno::NOENT) => {
                match mkdirat(parent, name, DIRECTORY_MODE) {
                    Ok(()) => fs::fsync(parent).map_err(|_| PodmanStateRootError::Io {
                        operation: "sync new state directory",
                        path: display_path.to_path_buf(),
                    })?,
                    Err(Errno::EXIST) => {}
                    Err(_) => {
                        return Err(PodmanStateRootError::Io {
                            operation: "create state directory",
                            path: display_path.to_path_buf(),
                        });
                    }
                }
                let fd = openat(parent, name, flags, Mode::empty())
                    .map_err(|error| map_open("open new state directory", display_path, error))?;
                ensure_owned_directory(&fd, display_path)?;
                Ok(fd)
            }
            Err(error) => Err(map_open("open state directory", display_path, error)),
        }
    }

    fn ensure_owned_directory(fd: &OwnedFd, path: &Path) -> Result<(), PodmanStateRootError> {
        let stat = fstat(fd).map_err(|_| PodmanStateRootError::Io {
            operation: "inspect state directory",
            path: path.to_path_buf(),
        })?;
        if !FileType::from_raw_mode(stat.st_mode).is_dir()
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o777 != 0o700
        {
            return Err(PodmanStateRootError::NotOwnerOnly);
        }
        Ok(())
    }

    fn ensure_owned_regular_file(fd: &OwnedFd, path: &Path) -> Result<(), PodmanStateRootError> {
        let stat = fstat(fd).map_err(|_| PodmanStateRootError::Io {
            operation: "inspect state file",
            path: path.to_path_buf(),
        })?;
        if !FileType::from_raw_mode(stat.st_mode).is_file()
            || stat.st_nlink != 1
            || stat.st_uid != rustix::process::geteuid().as_raw()
        {
            return Err(PodmanStateRootError::PathSecurity);
        }
        Ok(())
    }

    fn validate_internal_name(name: &str) -> Result<(), PodmanStateRootError> {
        let valid = !name.is_empty()
            && name.len() <= 96
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        valid
            .then_some(())
            .ok_or(PodmanStateRootError::PathSecurity)
    }

    fn map_open(operation: &'static str, path: &Path, error: Errno) -> PodmanStateRootError {
        if matches!(error, Errno::LOOP | Errno::NOTDIR) {
            PodmanStateRootError::PathSecurity
        } else {
            PodmanStateRootError::Io {
                operation,
                path: path.to_path_buf(),
            }
        }
    }
}

#[cfg(unix)]
pub(crate) use local::{JobEnginePaths, LocalState};

#[cfg(not(unix))]
#[derive(Debug)]
pub(crate) struct LocalState {
    root_path: PathBuf,
}

#[cfg(not(unix))]
impl LocalState {
    pub(crate) fn open(_root: &PodmanStateRoot) -> Result<Self, PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }

    pub(crate) fn hooks_path(&self) -> PathBuf {
        self.root_path.join("empty-hooks")
    }

    pub(crate) fn ensure_workspace(&self, _name: &str) -> Result<PathBuf, PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }

    pub(crate) fn workspace_cleanup_target(
        &self,
        _name: &str,
    ) -> Result<Option<PathBuf>, PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }

    pub(crate) fn confirm_workspace_removed(
        &self,
        _name: &str,
    ) -> Result<(), PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }

    pub(crate) fn workspace_exists(&self, _name: &str) -> Result<bool, PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }

    pub(crate) fn ensure_job_engine(
        &self,
        _name: &str,
    ) -> Result<JobEnginePaths, PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }

    pub(crate) fn remove_job_engine(&self, _name: &str) -> Result<bool, PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }

    pub(crate) fn stage_input(
        &self,
        _prefix: &str,
        _operation_id: automata_execution::OperationId,
        _content: &[u8],
    ) -> Result<StagedInput<'_>, PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }

    pub(crate) fn stage_output(
        &self,
        _operation_id: automata_execution::OperationId,
    ) -> Result<StagedOutput<'_>, PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }
}

#[cfg(not(unix))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JobEnginePaths {
    root: PathBuf,
}

#[cfg(not(unix))]
impl JobEnginePaths {
    pub(crate) fn graph_root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn run_root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn backend_socket(&self) -> &Path {
        &self.root
    }

    pub(crate) fn public_socket(&self) -> &Path {
        &self.root
    }

    pub(crate) fn public_directory(&self) -> &Path {
        &self.root
    }
}

#[cfg(not(unix))]
#[derive(Debug)]
pub(crate) struct StagedInput<'a> {
    _state: &'a LocalState,
}

#[cfg(not(unix))]
impl StagedInput<'_> {
    pub(crate) fn path(&self) -> &Path {
        unreachable!("non-Unix staging is unsupported")
    }

    pub(crate) fn verify(&self) -> Result<(), PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }

    pub(crate) fn cleanup(self) -> Result<(), PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }
}

#[cfg(not(unix))]
#[derive(Debug)]
pub(crate) struct StagedOutput<'a> {
    _state: &'a LocalState,
}

#[cfg(not(unix))]
impl StagedOutput<'_> {
    pub(crate) fn payload_path(&self) -> PathBuf {
        unreachable!("non-Unix staging is unsupported")
    }

    pub(crate) fn verify(&self) -> Result<(), PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }

    pub(crate) fn read_payload(&self, _byte_limit: usize) -> Result<Vec<u8>, PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }

    pub(crate) fn cleanup(self) -> Result<(), PodmanStateRootError> {
        Err(PodmanStateRootError::UnsupportedPlatform)
    }
}
