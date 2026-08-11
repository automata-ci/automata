use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::windows::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

use automata_ci_execution::TargetPath;

use crate::path::{is_within, validate_windows_path};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

pub(crate) fn target_to_host(path: &TargetPath) -> PathBuf {
    PathBuf::from(path.as_str())
}

pub(crate) fn ensure_base_directory(path: &TargetPath) -> io::Result<PathBuf> {
    let host = target_to_host(path);
    ensure_existing_ancestors_safe(&host)?;
    fs::create_dir_all(&host)?;
    require_directory(&host)?;
    Ok(host)
}

pub(crate) fn create_owned_directory(path: &TargetPath) -> io::Result<PathBuf> {
    let host = target_to_host(path);
    let parent = host
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    ensure_existing_ancestors_safe(parent)?;
    fs::create_dir_all(parent)?;
    require_directory(parent)?;
    fs::create_dir(&host)?;
    require_directory(&host)?;
    Ok(host)
}

pub(crate) fn require_owned_directory_absent(path: &TargetPath) -> io::Result<()> {
    let host = target_to_host(path);
    let parent = host
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    ensure_existing_ancestors_safe(parent)?;
    match fs::symlink_metadata(&host) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(io::Error::from(io::ErrorKind::AlreadyExists)),
        Err(error) => Err(error),
    }
}

pub(crate) fn ensure_owned_directory(path: &TargetPath) -> io::Result<PathBuf> {
    match create_owned_directory(path) {
        Ok(host) => Ok(host),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let host = target_to_host(path);
            require_directory(&host)?;
            Ok(host)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn require_directory(path: &Path) -> io::Result<()> {
    require_no_reparse(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    }
}

pub(crate) fn require_executable(path: &TargetPath) -> io::Result<PathBuf> {
    if !validate_windows_path(path) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let host = target_to_host(path);
    let supported_extension = host
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("exe") || extension.eq_ignore_ascii_case("com")
        });
    if !supported_extension {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    require_no_reparse(&host)?;
    let metadata = fs::symlink_metadata(&host)?;
    if metadata.is_file() {
        Ok(host)
    } else {
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    }
}

pub(crate) fn resolve_owned_target(
    path: &TargetPath,
    workspace: &TargetPath,
    scratch: &TargetPath,
) -> io::Result<PathBuf> {
    if !validate_windows_path(path) || !(is_within(path, workspace) || is_within(path, scratch)) {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(target_to_host(path))
}

pub(crate) fn write_owned_file(path: &Path, content: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    require_directory(parent)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            reject_reparse(&metadata)?;
            if !metadata.is_file() {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(content)?;
    file.flush()
}

pub(crate) fn read_owned_file(path: &Path, byte_limit: usize) -> io::Result<Vec<u8>> {
    require_no_reparse(path)?;
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let hard_read = u64::try_from(byte_limit)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut content = Vec::with_capacity(byte_limit.min(64 * 1024));
    file.take(hard_read).read_to_end(&mut content)?;
    if content.len() > byte_limit {
        return Err(io::Error::from(io::ErrorKind::FileTooLarge));
    }
    Ok(content)
}

pub(crate) fn remove_owned_tree(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    reject_reparse(&metadata)?;
    if !metadata.is_dir() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    for child in fs::read_dir(path)? {
        let child = child?;
        let child_path = child.path();
        let child_metadata = fs::symlink_metadata(&child_path)?;
        if is_reparse(&child_metadata) {
            remove_reparse_leaf(&child_path, &child_metadata)?;
        } else if child_metadata.is_dir() {
            remove_owned_tree(&child_path)?;
        } else if child_metadata.is_file() {
            fs::remove_file(&child_path)?;
        } else {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
    }
    fs::remove_dir(path)
}

fn remove_reparse_leaf(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if metadata.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0 {
        fs::remove_dir(path)
    } else {
        fs::remove_file(path)
    }
}

fn ensure_existing_ancestors_safe(path: &Path) -> io::Result<()> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                reject_reparse(&metadata)?;
                if !metadata.is_dir() {
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                }
                return require_no_reparse(candidate);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                current = candidate.parent();
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::from(io::ErrorKind::InvalidInput))
}

fn require_no_reparse(path: &Path) -> io::Result<()> {
    for component in path.ancestors() {
        let metadata = fs::symlink_metadata(component)?;
        reject_reparse(&metadata)?;
    }
    Ok(())
}

fn reject_reparse(metadata: &fs::Metadata) -> io::Result<()> {
    if is_reparse(metadata) {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    } else {
        Ok(())
    }
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}
