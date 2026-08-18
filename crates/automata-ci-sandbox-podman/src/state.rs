use std::{
    ffi::OsStr,
    fmt,
    path::{Component, Path, PathBuf},
};

use crate::PodmanStateRootError;

const TEMPORARY_COMPONENT: &str = "tmp";
pub(crate) const SHARED_GRAPH_ROOT_NAME: &str = "podman-graph";
pub(crate) const PODMAN_RUNTIME_ROOT_NAME: &str = "automata-ci-podman";
pub(crate) const SHARED_RUN_ROOT_NAME: &str = "shared-run";

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

    /// Returns the exact canonical state-root path validated at construction.
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

#[cfg(target_os = "linux")]
mod local {
    use std::{
        fmt,
        fs::File,
        io::{Read as _, Write as _},
        path::{Path, PathBuf},
    };

    use rustix::{
        fd::OwnedFd,
        fs::{
            self, AtFlags, FileType, FlockOperation, Mode, OFlags, fchmod, flock, fstat, mkdirat,
            openat, renameat, unlinkat,
        },
        io::Errno,
    };

    use super::{PODMAN_RUNTIME_ROOT_NAME, SHARED_GRAPH_ROOT_NAME, SHARED_RUN_ROOT_NAME};
    use crate::{PodmanOptions, PodmanStateRootError};

    const DIRECTORY_MODE: Mode = Mode::from_raw_mode(0o700);
    const FILE_MODE: Mode = Mode::from_raw_mode(0o600);
    const LOCK_NAME: &str = ".automata-podman.lock";
    const WORKSPACES_NAME: &str = "workspaces";
    const HOOKS_NAME: &str = "empty-hooks";
    const TRANSFERS_NAME: &str = "transfers";
    const ENGINES_NAME: &str = "job-engines";
    const SERVICES_NAME: &str = "service-manifests";
    const PROCESS_TRANSIENT_NAME: &str = "process-transient";
    const SYSTEM_CONFIG_NAME: &str = "podman-system-config";
    const CDI_NAME: &str = "empty-cdi";
    const SHARED_TMP_NAME: &str = "shared-tmp";
    const MAX_SERVICE_MANIFEST_BYTES: usize = 1024 * 1024;

    pub(crate) fn prepare(options: &PodmanOptions) -> Result<(), PodmanStateRootError> {
        let environment = options.process_environment();
        let root_path = options.state_root().as_path();
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        let root_fd = fs::open(root_path, flags, Mode::empty())
            .map_err(|error| map_open("open state root for preparation", root_path, error))?;
        ensure_owned_directory(&root_fd, root_path)?;
        reject_obsolete_transfer_state(&root_fd, root_path)?;

        for name in [
            WORKSPACES_NAME,
            HOOKS_NAME,
            ENGINES_NAME,
            SERVICES_NAME,
            PROCESS_TRANSIENT_NAME,
            SHARED_GRAPH_ROOT_NAME,
        ] {
            let path = root_path.join(name);
            let directory = open_or_create_child(&root_fd, name, &path, flags)?;
            if name == HOOKS_NAME {
                ensure_empty_directory(&path)?;
            }
            if name == SHARED_GRAPH_ROOT_NAME {
                for child in ["networks", "volumes"] {
                    let child_path = path.join(child);
                    open_or_create_child(&directory, child, &child_path, flags)?;
                }
            }
        }

        let system_path = root_path.join(SYSTEM_CONFIG_NAME);
        let system_fd = open_or_create_child(&root_fd, SYSTEM_CONFIG_NAME, &system_path, flags)?;
        let cdi_path = system_path.join(CDI_NAME);
        open_or_create_child(&system_fd, CDI_NAME, &cdi_path, flags)?;
        ensure_empty_directory(&cdi_path)?;
        for (name, contents) in [
            ("containers.conf", environment.containers_conf_contents()),
            ("storage.conf", environment.storage_conf_contents()),
            ("registries.conf", environment.registries_conf_contents()),
            ("policy.json", environment.policy_contents()),
            ("mounts.conf", environment.mounts_conf_contents()),
            ("auth.json", environment.auth_file_contents()),
        ] {
            ensure_exact_file(&system_fd, &system_path, name, contents)?;
        }

        let runtime_directory = environment.runtime_directory();
        let runtime_directory_fd =
            fs::open(runtime_directory, flags, Mode::empty()).map_err(|error| {
                map_open(
                    "open rootless runtime directory for preparation",
                    runtime_directory,
                    error,
                )
            })?;
        ensure_owned_directory(&runtime_directory_fd, runtime_directory)?;
        let runtime_root_path = runtime_directory.join(PODMAN_RUNTIME_ROOT_NAME);
        let runtime_root_fd = open_or_create_child(
            &runtime_directory_fd,
            PODMAN_RUNTIME_ROOT_NAME,
            &runtime_root_path,
            flags,
        )?;
        for name in [SHARED_RUN_ROOT_NAME, SHARED_TMP_NAME, ENGINES_NAME] {
            open_or_create_child(&runtime_root_fd, name, &runtime_root_path.join(name), flags)?;
        }
        Ok(())
    }

    pub(crate) struct LocalState {
        root_path: PathBuf,
        runtime_root_path: PathBuf,
        root_fd: OwnedFd,
        workspaces_fd: OwnedFd,
        engines_fd: OwnedFd,
        runtime_engines_fd: OwnedFd,
        services_fd: OwnedFd,
        _shared_graph_root_fd: OwnedFd,
        _runtime_root_fd: OwnedFd,
        _shared_run_root_fd: OwnedFd,
        _shared_tmp_fd: OwnedFd,
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
        pub(crate) fn open(options: &PodmanOptions) -> Result<Self, PodmanStateRootError> {
            prepare(options)?;
            let root = options.state_root();
            let root_path = root.as_path().to_path_buf();
            let directory_flags =
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            let root_fd = fs::open(&root_path, directory_flags, Mode::empty())
                .map_err(|error| map_open("open state root", &root_path, error))?;
            ensure_owned_directory(&root_fd, &root_path)?;
            let lock_fd = open_lock(&root_fd, &root_path)?;
            reject_obsolete_transfer_state(&root_fd, &root_path)?;
            let workspaces_fd =
                open_or_create_child(&root_fd, WORKSPACES_NAME, &root_path, directory_flags)?;
            let _hooks_fd =
                open_or_create_child(&root_fd, HOOKS_NAME, &root_path, directory_flags)?;
            let engines_fd =
                open_or_create_child(&root_fd, ENGINES_NAME, &root_path, directory_flags)?;
            let services_fd =
                open_or_create_child(&root_fd, SERVICES_NAME, &root_path, directory_flags)?;
            let shared_graph_root_fd = open_or_create_child(
                &root_fd,
                SHARED_GRAPH_ROOT_NAME,
                &root_path.join(SHARED_GRAPH_ROOT_NAME),
                directory_flags,
            )?;
            let runtime_directory = options.process_environment().runtime_directory();
            let runtime_directory_fd = fs::open(runtime_directory, directory_flags, Mode::empty())
                .map_err(|error| {
                    map_open("open rootless runtime directory", runtime_directory, error)
                })?;
            ensure_owned_directory(&runtime_directory_fd, runtime_directory)?;
            let runtime_root_path = runtime_directory.join(PODMAN_RUNTIME_ROOT_NAME);
            let runtime_root_fd = open_or_create_child(
                &runtime_directory_fd,
                PODMAN_RUNTIME_ROOT_NAME,
                &runtime_root_path,
                directory_flags,
            )?;
            let shared_run_root_fd = open_or_create_child(
                &runtime_root_fd,
                SHARED_RUN_ROOT_NAME,
                &runtime_root_path.join(SHARED_RUN_ROOT_NAME),
                directory_flags,
            )?;
            let shared_tmp_fd = open_or_create_child(
                &runtime_root_fd,
                SHARED_TMP_NAME,
                &runtime_root_path.join(SHARED_TMP_NAME),
                directory_flags,
            )?;
            let runtime_engines_fd = open_or_create_child(
                &runtime_root_fd,
                ENGINES_NAME,
                &runtime_root_path.join(ENGINES_NAME),
                directory_flags,
            )?;
            let _process_transient_fd = open_or_create_child(
                &root_fd,
                PROCESS_TRANSIENT_NAME,
                &root_path,
                directory_flags,
            )?;
            Ok(Self {
                root_path,
                runtime_root_path,
                root_fd,
                workspaces_fd,
                engines_fd,
                runtime_engines_fd,
                services_fd,
                _shared_graph_root_fd: shared_graph_root_fd,
                _runtime_root_fd: runtime_root_fd,
                _shared_run_root_fd: shared_run_root_fd,
                _shared_tmp_fd: shared_tmp_fd,
                _lock_fd: lock_fd,
            })
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
            let graph_path = path.join("graph");
            let graph = open_or_create_child(&engine, "graph", &graph_path, flags)?;
            ensure_owned_directory(&graph, &graph_path)?;
            for graph_child in ["networks", "volumes"] {
                let graph_child_path = graph_path.join(graph_child);
                open_or_create_child(&graph, graph_child, &graph_child_path, flags)?;
            }
            let runtime_path = self.runtime_root_path.join(ENGINES_NAME).join(name);
            let runtime_engine =
                open_or_create_child(&self.runtime_engines_fd, name, &runtime_path, flags)?;
            for child in ["run", "tmp"] {
                let child_path = runtime_path.join(child);
                open_or_create_child(&runtime_engine, child, &child_path, flags)?;
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
                run_root: runtime_path.join("run"),
                tmp_dir: runtime_path.join("tmp"),
                backend_socket: self.root_path.join(backend_name),
                public_socket: public_directory.join("docker.sock"),
                public_directory,
            })
        }

        pub(crate) fn remove_job_engine(&self, name: &str) -> Result<bool, PodmanStateRootError> {
            validate_internal_name(name)?;
            let (backend_name, public_name) = job_engine_socket_names(name)?;
            let path = self.root_path.join(ENGINES_NAME).join(name);
            let runtime_path = self.runtime_root_path.join(ENGINES_NAME).join(name);
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            let engine = match openat(&self.engines_fd, name, flags, Mode::empty()) {
                Ok(fd) => {
                    ensure_owned_directory(&fd, &path)?;
                    Some(fd)
                }
                Err(Errno::NOENT) => None,
                Err(error) => return Err(map_open("open job engine for deletion", &path, error)),
            };
            let runtime_engine = match openat(&self.runtime_engines_fd, name, flags, Mode::empty())
            {
                Ok(fd) => {
                    ensure_owned_directory(&fd, &runtime_path)?;
                    Some(fd)
                }
                Err(Errno::NOENT) => None,
                Err(error) => {
                    return Err(map_open(
                        "open job runtime engine for deletion",
                        &runtime_path,
                        error,
                    ));
                }
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
            if let Some(runtime_engine) = runtime_engine {
                drop(runtime_engine);
                std::fs::remove_dir_all(&runtime_path).map_err(|_| PodmanStateRootError::Io {
                    operation: "remove exact job runtime tree",
                    path: runtime_path.clone(),
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
            fs::fsync(&self.runtime_engines_fd).map_err(|_| PodmanStateRootError::Io {
                operation: "sync job runtime root",
                path: self.runtime_root_path.join(ENGINES_NAME),
            })?;
            fs::fsync(&self.root_fd).map_err(|_| PodmanStateRootError::Io {
                operation: "sync state root after job engine cleanup",
                path: self.root_path.clone(),
            })?;
            Ok(removed)
        }

        pub(crate) fn read_service_manifest(
            &self,
            name: &str,
        ) -> Result<Option<Vec<u8>>, PodmanStateRootError> {
            validate_internal_name(name)?;
            let path = self.root_path.join(SERVICES_NAME).join(name);
            let fd = match openat(
                &self.services_fd,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => return Ok(None),
                Err(error) => return Err(map_open("open service manifest", &path, error)),
            };
            ensure_owned_regular_file(&fd, &path)?;
            let stat = fstat(&fd).map_err(|_| PodmanStateRootError::Io {
                operation: "inspect service manifest",
                path: path.clone(),
            })?;
            if stat.st_mode & 0o777 != 0o600 {
                return Err(PodmanStateRootError::PathSecurity);
            }
            let size = usize::try_from(stat.st_size)
                .map_err(|_| PodmanStateRootError::TransferLimitExceeded)?;
            if size > MAX_SERVICE_MANIFEST_BYTES {
                return Err(PodmanStateRootError::TransferLimitExceeded);
            }
            let mut content = Vec::with_capacity(size);
            File::from(fd)
                .take(
                    u64::try_from(MAX_SERVICE_MANIFEST_BYTES)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                )
                .read_to_end(&mut content)
                .map_err(|_| PodmanStateRootError::Io {
                    operation: "read service manifest",
                    path,
                })?;
            if content.len() > MAX_SERVICE_MANIFEST_BYTES {
                return Err(PodmanStateRootError::TransferLimitExceeded);
            }
            Ok(Some(content))
        }

        pub(crate) fn write_service_manifest(
            &self,
            name: &str,
            content: &[u8],
        ) -> Result<(), PodmanStateRootError> {
            validate_internal_name(name)?;
            if content.len() > MAX_SERVICE_MANIFEST_BYTES {
                return Err(PodmanStateRootError::TransferLimitExceeded);
            }
            let staging_name = format!("stage-{name}");
            validate_internal_name(&staging_name)?;
            let staging_path = self.root_path.join(SERVICES_NAME).join(&staging_name);
            remove_stale_manifest_staging(&self.services_fd, &staging_name, &staging_path)?;
            let fd = openat(
                &self.services_fd,
                &staging_name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                FILE_MODE,
            )
            .map_err(|error| map_open("create service manifest staging", &staging_path, error))?;
            ensure_owned_regular_file(&fd, &staging_path)?;
            fchmod(&fd, FILE_MODE).map_err(|_| PodmanStateRootError::Io {
                operation: "set service manifest permissions",
                path: staging_path.clone(),
            })?;
            let mut file = File::from(fd);
            file.write_all(content)
                .and_then(|()| file.sync_all())
                .map_err(|_| PodmanStateRootError::Io {
                    operation: "write and sync service manifest",
                    path: staging_path.clone(),
                })?;
            drop(file);
            renameat(&self.services_fd, &staging_name, &self.services_fd, name).map_err(|_| {
                PodmanStateRootError::Io {
                    operation: "publish service manifest",
                    path: self.root_path.join(SERVICES_NAME).join(name),
                }
            })?;
            fs::fsync(&self.services_fd).map_err(|_| PodmanStateRootError::Io {
                operation: "sync service manifest directory",
                path: self.root_path.join(SERVICES_NAME),
            })
        }

        pub(crate) fn remove_service_manifest(
            &self,
            name: &str,
        ) -> Result<bool, PodmanStateRootError> {
            validate_internal_name(name)?;
            let path = self.root_path.join(SERVICES_NAME).join(name);
            let fd = match openat(
                &self.services_fd,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => return Ok(false),
                Err(error) => {
                    return Err(map_open("open service manifest for deletion", &path, error));
                }
            };
            ensure_owned_regular_file(&fd, &path)?;
            let stat = fstat(&fd).map_err(|_| PodmanStateRootError::Io {
                operation: "inspect service manifest for deletion",
                path: path.clone(),
            })?;
            if stat.st_mode & 0o777 != 0o600 {
                return Err(PodmanStateRootError::PathSecurity);
            }
            drop(fd);
            unlinkat(&self.services_fd, name, AtFlags::empty()).map_err(|_| {
                PodmanStateRootError::Io {
                    operation: "remove service manifest",
                    path,
                }
            })?;
            fs::fsync(&self.services_fd).map_err(|_| PodmanStateRootError::Io {
                operation: "sync service manifest removal",
                path: self.root_path.join(SERVICES_NAME),
            })?;
            Ok(true)
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct JobEnginePaths {
        graph_root: PathBuf,
        run_root: PathBuf,
        tmp_dir: PathBuf,
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

        pub(crate) fn tmp_dir(&self) -> &Path {
            &self.tmp_dir
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

    fn remove_stale_manifest_staging(
        directory: &OwnedFd,
        name: &str,
        path: &Path,
    ) -> Result<(), PodmanStateRootError> {
        let fd = match openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(()),
            Err(error) => return Err(map_open("open stale service manifest staging", path, error)),
        };
        ensure_owned_regular_file(&fd, path)?;
        let stat = fstat(&fd).map_err(|_| PodmanStateRootError::Io {
            operation: "inspect stale service manifest staging",
            path: path.to_path_buf(),
        })?;
        if stat.st_mode & 0o777 != 0o600 {
            return Err(PodmanStateRootError::PathSecurity);
        }
        drop(fd);
        unlinkat(directory, name, AtFlags::empty()).map_err(|_| PodmanStateRootError::Io {
            operation: "remove stale service manifest staging",
            path: path.to_path_buf(),
        })?;
        fs::fsync(directory).map_err(|_| PodmanStateRootError::Io {
            operation: "sync stale service manifest cleanup",
            path: path
                .parent()
                .map_or_else(|| path.to_path_buf(), Path::to_path_buf),
        })
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

    fn reject_obsolete_transfer_state(
        root: &OwnedFd,
        root_path: &Path,
    ) -> Result<(), PodmanStateRootError> {
        let path = root_path.join(TRANSFERS_NAME);
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        match openat(root, TRANSFERS_NAME, flags, Mode::empty()) {
            Err(Errno::NOENT) => Ok(()),
            Ok(_) | Err(Errno::LOOP | Errno::NOTDIR) => Err(PodmanStateRootError::PathSecurity),
            Err(error) => Err(map_open("reject obsolete transfer state", &path, error)),
        }
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

    fn ensure_empty_directory(path: &Path) -> Result<(), PodmanStateRootError> {
        let mut entries = std::fs::read_dir(path).map_err(|_| PodmanStateRootError::Io {
            operation: "read exact empty state directory",
            path: path.to_path_buf(),
        })?;
        match entries.next() {
            None => Ok(()),
            Some(Ok(_) | Err(_)) => Err(PodmanStateRootError::PathSecurity),
        }
    }

    fn ensure_exact_file(
        parent: &OwnedFd,
        parent_path: &Path,
        name: &str,
        expected: &[u8],
    ) -> Result<(), PodmanStateRootError> {
        let path = parent_path.join(name);
        let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        let fd = match openat(parent, name, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => {
                let fd = openat(
                    parent,
                    name,
                    OFlags::RDWR
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::CLOEXEC
                        | OFlags::NOFOLLOW,
                    FILE_MODE,
                )
                .map_err(|error| map_open("create exact Podman configuration", &path, error))?;
                ensure_owned_regular_file(&fd, &path)?;
                let mut file = File::from(fd);
                file.write_all(expected)
                    .and_then(|()| file.sync_all())
                    .map_err(|_| PodmanStateRootError::Io {
                        operation: "write exact Podman configuration",
                        path: path.clone(),
                    })?;
                drop(file);
                fs::fsync(parent).map_err(|_| PodmanStateRootError::Io {
                    operation: "sync Podman configuration directory",
                    path: parent_path.to_path_buf(),
                })?;
                openat(parent, name, flags, Mode::empty())
                    .map_err(|error| map_open("reopen exact Podman configuration", &path, error))?
            }
            Err(error) => {
                return Err(map_open("open exact Podman configuration", &path, error));
            }
        };
        ensure_owned_regular_file(&fd, &path)?;
        let stat = fstat(&fd).map_err(|_| PodmanStateRootError::Io {
            operation: "inspect exact Podman configuration",
            path: path.clone(),
        })?;
        if stat.st_mode & 0o777 != 0o600 || stat.st_size < 0 {
            return Err(PodmanStateRootError::PathSecurity);
        }
        let size = usize::try_from(stat.st_size).map_err(|_| PodmanStateRootError::PathSecurity)?;
        if size != expected.len() {
            return Err(PodmanStateRootError::PathSecurity);
        }
        let mut actual = Vec::with_capacity(size);
        File::from(fd)
            .take(
                u64::try_from(expected.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut actual)
            .map_err(|_| PodmanStateRootError::Io {
                operation: "read exact Podman configuration",
                path,
            })?;
        if actual != expected {
            return Err(PodmanStateRootError::PathSecurity);
        }
        Ok(())
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

#[cfg(target_os = "linux")]
pub(crate) use local::{JobEnginePaths, LocalState, prepare};

#[cfg(not(target_os = "linux"))]
pub(crate) fn prepare(_options: &crate::PodmanOptions) -> Result<(), PodmanStateRootError> {
    Err(PodmanStateRootError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub(crate) struct LocalState(std::convert::Infallible);

#[cfg(not(target_os = "linux"))]
impl LocalState {
    pub(crate) fn ensure_workspace(&self, _name: &str) -> Result<PathBuf, PodmanStateRootError> {
        match self.0 {}
    }

    pub(crate) fn workspace_cleanup_target(
        &self,
        _name: &str,
    ) -> Result<Option<PathBuf>, PodmanStateRootError> {
        match self.0 {}
    }

    pub(crate) fn confirm_workspace_removed(
        &self,
        _name: &str,
    ) -> Result<(), PodmanStateRootError> {
        match self.0 {}
    }

    pub(crate) fn workspace_exists(&self, _name: &str) -> Result<bool, PodmanStateRootError> {
        match self.0 {}
    }

    pub(crate) fn ensure_job_engine(
        &self,
        _name: &str,
    ) -> Result<JobEnginePaths, PodmanStateRootError> {
        match self.0 {}
    }

    pub(crate) fn remove_job_engine(&self, _name: &str) -> Result<bool, PodmanStateRootError> {
        match self.0 {}
    }

    pub(crate) fn read_service_manifest(
        &self,
        _name: &str,
    ) -> Result<Option<Vec<u8>>, PodmanStateRootError> {
        match self.0 {}
    }

    pub(crate) fn write_service_manifest(
        &self,
        _name: &str,
        _content: &[u8],
    ) -> Result<(), PodmanStateRootError> {
        match self.0 {}
    }

    pub(crate) fn remove_service_manifest(
        &self,
        _name: &str,
    ) -> Result<bool, PodmanStateRootError> {
        match self.0 {}
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JobEnginePaths {
    root: PathBuf,
}

#[cfg(not(target_os = "linux"))]
impl JobEnginePaths {
    pub(crate) fn graph_root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn run_root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn tmp_dir(&self) -> &Path {
        &self.root
    }

    pub(crate) fn public_socket(&self) -> &Path {
        &self.root
    }

    pub(crate) fn public_directory(&self) -> &Path {
        &self.root
    }
}
