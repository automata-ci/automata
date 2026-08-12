use std::{
    ffi::{CStr, OsString},
    fs::File,
    io::{self, Read as _, Write as _},
    os::unix::ffi::OsStrExt as _,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use automata_ci_execution::{TargetPath, TargetPlatform};
use rustix::{
    fd::OwnedFd,
    fs::{
        self, AtFlags, Dir, FileType, Mode, OFlags, fchmod, fstat, mkdirat, open, openat, unlinkat,
    },
    io::Errno,
};

use crate::path::is_strict_descendant;

const DIRECTORY_MODE: Mode = Mode::from_raw_mode(0o700);
const FILE_MODE: Mode = Mode::from_raw_mode(0o600);
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);

#[derive(Debug)]
pub(crate) struct SecureRoot {
    path: PathBuf,
    target: TargetPath,
    descriptor: Arc<OwnedFd>,
}

impl SecureRoot {
    pub(crate) fn open_or_create(path: &Path, target: TargetPath) -> io::Result<Self> {
        let descriptor = open_or_create_absolute_directory(path)?;
        require_private_owned_directory(&descriptor)?;
        Ok(Self {
            path: path.to_path_buf(),
            target,
            descriptor: Arc::new(descriptor),
        })
    }

    pub(crate) fn descriptor(&self) -> &OwnedFd {
        &self.descriptor
    }

    pub(crate) fn ensure_owned_directory(&self, target: &TargetPath) -> io::Result<()> {
        let components = self.relative_components(target)?;
        let mut current = self.descriptor.try_clone()?;
        for component in components {
            current = open_or_create_child_directory(&current, &component)?;
            require_private_owned_directory(&current)?;
        }
        Ok(())
    }

    pub(crate) fn require_directory_absent(&self, target: &TargetPath) -> io::Result<()> {
        let components = self.relative_components(target)?;
        let (name, parents) = components
            .split_last()
            .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
        let mut parent = self.descriptor.try_clone()?;
        for component in parents {
            parent = match openat(&parent, component, DIRECTORY_FLAGS, Mode::empty()) {
                Ok(directory) => directory,
                Err(Errno::NOENT) => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            require_private_owned_directory(&parent)?;
        }
        match openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Err(Errno::NOENT) => Ok(()),
            Ok(_) | Err(Errno::LOOP | Errno::NOTDIR) => {
                Err(io::Error::from(io::ErrorKind::AlreadyExists))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn remove_owned_tree(&self, target: &TargetPath) -> io::Result<()> {
        let components = self.relative_components(target)?;
        let (parent, name) = self.open_parent(&components)?;
        let directory = match openat(&parent, &name, DIRECTORY_FLAGS, Mode::empty()) {
            Ok(directory) => directory,
            Err(Errno::NOENT) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        require_private_owned_directory(&directory)?;
        remove_directory_contents(&directory)?;
        unlinkat(&parent, &name, AtFlags::REMOVEDIR).map_err(io::Error::from)?;
        fs::fsync(&parent).map_err(io::Error::from)
    }

    pub(crate) fn resolve_owned_target(
        &self,
        target: &TargetPath,
        workspace: &TargetPath,
        scratch: &TargetPath,
    ) -> io::Result<OwnedTarget> {
        let boundary = if target == workspace || is_strict_descendant(target, workspace) {
            workspace
        } else if target == scratch || is_strict_descendant(target, scratch) {
            scratch
        } else {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        };
        let boundary_components = self.relative_components(boundary)?;
        let boundary_descriptor = self.open_directory_components(&boundary_components)?;
        let relative = Path::new(target.as_str())
            .strip_prefix(Path::new(boundary.as_str()))
            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?
            .components()
            .map(component_name)
            .collect::<io::Result<Vec<_>>>()?;
        Ok(OwnedTarget {
            host: PathBuf::from(target.as_str()),
            boundary: Arc::new(boundary_descriptor),
            relative,
        })
    }

    fn relative_components(&self, target: &TargetPath) -> io::Result<Vec<OsString>> {
        if target.platform() != TargetPlatform::Posix || !is_strict_descendant(target, &self.target)
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Path::new(target.as_str())
            .strip_prefix(&self.path)
            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?
            .components()
            .map(component_name)
            .collect()
    }

    fn open_parent(&self, components: &[OsString]) -> io::Result<(OwnedFd, OsString)> {
        let (name, parents) = components
            .split_last()
            .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
        Ok((self.open_directory_components(parents)?, name.clone()))
    }

    fn open_directory_components(&self, components: &[OsString]) -> io::Result<OwnedFd> {
        let mut current = self.descriptor.try_clone()?;
        for component in components {
            current = openat(&current, component, DIRECTORY_FLAGS, Mode::empty())
                .map_err(io::Error::from)?;
            require_private_owned_directory(&current)?;
        }
        Ok(current)
    }
}

#[derive(Debug)]
pub(crate) struct OwnedTarget {
    host: PathBuf,
    boundary: Arc<OwnedFd>,
    relative: Vec<OsString>,
}

impl OwnedTarget {
    fn open_parent(&self) -> io::Result<(OwnedFd, &OsString)> {
        let (name, parents) = self
            .relative
            .split_last()
            .ok_or_else(|| io::Error::from(io::ErrorKind::IsADirectory))?;
        let mut current = self.boundary.try_clone()?;
        for component in parents {
            current = openat(&current, component, DIRECTORY_FLAGS, Mode::empty())
                .map_err(io::Error::from)?;
            require_owned_directory(&current)?;
        }
        Ok((current, name))
    }
}

pub(crate) fn require_directory(target: &OwnedTarget) -> io::Result<PathBuf> {
    let mut current = target.boundary.try_clone()?;
    for component in &target.relative {
        current =
            openat(&current, component, DIRECTORY_FLAGS, Mode::empty()).map_err(io::Error::from)?;
        require_owned_directory(&current)?;
    }
    Ok(target.host.clone())
}

pub(crate) fn require_executable(target: &TargetPath) -> io::Result<PathBuf> {
    if target.platform() != TargetPlatform::Posix || target.as_str() == "/" {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let path = Path::new(target.as_str());
    let (name, parent) = path
        .file_name()
        .zip(path.parent())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let parent = open_absolute_directory(parent)?;
    let executable = openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let stat = fstat(&executable).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_mode & 0o111 == 0 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(path.to_path_buf())
}

pub(crate) fn write_owned_file(target: &OwnedTarget, content: &[u8]) -> io::Result<()> {
    let (parent, name) = target.open_parent()?;
    let descriptor = openat(
        &parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        FILE_MODE,
    )
    .map_err(open_error)?;
    require_single_link_regular_file(&descriptor)?;
    fs::ftruncate(&descriptor, 0).map_err(io::Error::from)?;
    fchmod(&descriptor, FILE_MODE).map_err(io::Error::from)?;
    let mut file = File::from(descriptor);
    file.write_all(content)?;
    file.sync_all()?;
    fs::fsync(&parent).map_err(io::Error::from)
}

pub(crate) fn read_owned_file(target: &OwnedTarget, byte_limit: usize) -> io::Result<Vec<u8>> {
    let (parent, name) = target.open_parent()?;
    let descriptor = openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(open_error)?;
    require_single_link_regular_file(&descriptor)?;
    let mut content = Vec::new();
    File::from(descriptor)
        .take(
            u64::try_from(byte_limit)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut content)?;
    if content.len() > byte_limit {
        return Err(io::Error::from(io::ErrorKind::FileTooLarge));
    }
    Ok(content)
}

fn open_or_create_absolute_directory(path: &Path) -> io::Result<OwnedFd> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut current = open("/", DIRECTORY_FLAGS, Mode::empty()).map_err(io::Error::from)?;
    let components = path
        .components()
        .skip(1)
        .map(component_name)
        .collect::<io::Result<Vec<_>>>()?;
    for component in components {
        current = open_or_create_child_directory(&current, &component)?;
    }
    Ok(current)
}

fn open_absolute_directory(path: &Path) -> io::Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut current = open("/", DIRECTORY_FLAGS, Mode::empty()).map_err(io::Error::from)?;
    for component in path.components().skip(1) {
        current = openat(
            &current,
            component_name(component)?,
            DIRECTORY_FLAGS,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
    }
    Ok(current)
}

fn open_or_create_child_directory(parent: &OwnedFd, name: &OsString) -> io::Result<OwnedFd> {
    match openat(parent, name, DIRECTORY_FLAGS, Mode::empty()) {
        Ok(directory) => Ok(directory),
        Err(Errno::NOENT) => {
            match mkdirat(parent, name, DIRECTORY_MODE) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
            fs::fsync(parent).map_err(io::Error::from)?;
            openat(parent, name, DIRECTORY_FLAGS, Mode::empty()).map_err(io::Error::from)
        }
        Err(error) => Err(error.into()),
    }
}

fn remove_directory_contents(directory: &OwnedFd) -> io::Result<()> {
    let entries = Dir::read_from(directory).map_err(io::Error::from)?;
    for entry in entries {
        let entry = entry.map_err(io::Error::from)?;
        let name = entry.file_name();
        if is_dot(name) {
            continue;
        }
        match openat(directory, name, DIRECTORY_FLAGS, Mode::empty()) {
            Ok(child) => {
                require_owned_directory(&child)?;
                remove_directory_contents(&child)?;
                unlinkat(directory, name, AtFlags::REMOVEDIR).map_err(io::Error::from)?;
            }
            Err(Errno::NOTDIR | Errno::LOOP) => {
                unlinkat(directory, name, AtFlags::empty()).map_err(io::Error::from)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    fs::fsync(directory).map_err(io::Error::from)
}

fn require_private_owned_directory(descriptor: &OwnedFd) -> io::Result<()> {
    require_owned_directory(descriptor)?;
    let stat = fstat(descriptor).map_err(io::Error::from)?;
    if stat.st_mode & 0o077 != 0 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

fn require_owned_directory(descriptor: &OwnedFd) -> io::Result<()> {
    let stat = fstat(descriptor).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

fn require_single_link_regular_file(descriptor: &OwnedFd) -> io::Result<()> {
    let stat = fstat(descriptor).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_nlink != 1
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

fn component_name(component: Component<'_>) -> io::Result<OsString> {
    match component {
        Component::Normal(value) if !value.as_bytes().is_empty() => Ok(value.to_os_string()),
        _ => Err(io::Error::from(io::ErrorKind::InvalidInput)),
    }
}

fn is_dot(name: &CStr) -> bool {
    matches!(name.to_bytes(), b"." | b"..")
}

fn open_error(error: Errno) -> io::Error {
    if error == Errno::LOOP {
        io::Error::from(io::ErrorKind::PermissionDenied)
    } else {
        error.into()
    }
}
