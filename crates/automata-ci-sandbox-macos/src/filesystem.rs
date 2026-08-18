use std::{
    ffi::{CStr, OsString},
    io,
    os::unix::ffi::OsStrExt as _,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use automata_ci_execution::{TargetPath, TargetPlatform};
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, Dir, FileType, Mode, OFlags, fstat, mkdirat, open, openat, unlinkat},
    io::Errno,
};

use crate::path::is_strict_descendant;

const DIRECTORY_MODE: Mode = Mode::from_raw_mode(0o700);
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
        let (parent, name) = match self.open_parent(&components) {
            Ok(parent) => parent,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
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

fn component_name(component: Component<'_>) -> io::Result<OsString> {
    match component {
        Component::Normal(value) if !value.as_bytes().is_empty() => Ok(value.to_os_string()),
        _ => Err(io::Error::from(io::ErrorKind::InvalidInput)),
    }
}

fn is_dot(name: &CStr) -> bool {
    matches!(name.to_bytes(), b"." | b"..")
}

#[cfg(test)]
mod tests {
    use std::{fs, time::SystemTime};

    use automata_ci_execution::TargetPath;

    use super::SecureRoot;

    #[test]
    fn removing_an_absent_tree_with_an_absent_parent_is_idempotent() {
        let parent = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary root");
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let path = parent.join(format!(
            "automata-macos-secure-root-{}-{unique}",
            std::process::id()
        ));
        let root_target = TargetPath::posix(path.to_string_lossy().into_owned()).expect("root");
        let attempt_path = path.join("attempts/first");
        let attempt =
            TargetPath::posix(attempt_path.to_string_lossy().into_owned()).expect("attempt");
        let root = SecureRoot::open_or_create(&path, root_target).expect("secure root");

        root.remove_owned_tree(&attempt)
            .expect("an absent parent means the tree is already absent");
        root.ensure_owned_directory(&attempt)
            .expect("the following create makes the missing parent hierarchy");
        assert!(attempt_path.is_dir());

        drop(root);
        fs::remove_dir_all(path).expect("remove test root");
    }
}
