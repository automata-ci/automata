use std::path::Path;

use thiserror::Error;

use super::files::{SecureInputError, validate_absolute_path};

/// Sanitized failure while preparing a provider-owned state directory.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProductStateRootError {
    /// The configured path was not safe and absolute.
    #[error("runner provider state root is invalid")]
    InvalidPath,
    /// A path component was a symlink, non-directory, or inaccessible.
    #[error("runner provider state root violates path security")]
    PathSecurity,
    /// The final directory is not owned by the runner process.
    #[error("runner provider state root ownership is invalid")]
    Ownership,
    /// Directory creation or synchronization failed.
    #[error("runner provider state root is unavailable")]
    Unavailable,
    /// The current platform cannot enforce the required descriptor policy.
    #[error("runner provider state roots are unsupported on this platform")]
    UnsupportedPlatform,
}

#[cfg(unix)]
pub(crate) fn ensure_private_directory(path: &Path) -> Result<(), ProductStateRootError> {
    use rustix::{
        fd::OwnedFd,
        fs::{self, FileType, Mode, OFlags, fchmod, fstat, mkdirat, openat},
        io::Errno,
    };

    validate_absolute_path(path).map_err(map_path_error)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut directory: OwnedFd = fs::open("/", directory_flags, Mode::empty())
        .map_err(|_| ProductStateRootError::Unavailable)?;
    let components = path.components().filter_map(|component| match component {
        std::path::Component::Normal(value) => Some(value),
        _ => None,
    });
    for component in components {
        directory = match openat(&directory, component, directory_flags, Mode::empty()) {
            Ok(next) => next,
            Err(Errno::NOENT) => {
                match mkdirat(&directory, component, Mode::from_raw_mode(0o700)) {
                    Ok(()) => {
                        fs::fsync(&directory).map_err(|_| ProductStateRootError::Unavailable)?;
                    }
                    Err(Errno::EXIST) => {}
                    Err(_) => return Err(ProductStateRootError::Unavailable),
                }
                openat(&directory, component, directory_flags, Mode::empty())
                    .map_err(|_| ProductStateRootError::PathSecurity)?
            }
            Err(_) => return Err(ProductStateRootError::PathSecurity),
        };
        let metadata = fstat(&directory).map_err(|_| ProductStateRootError::Unavailable)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
            return Err(ProductStateRootError::PathSecurity);
        }
    }
    let metadata = fstat(&directory).map_err(|_| ProductStateRootError::Unavailable)?;
    if metadata.st_uid != rustix::process::geteuid().as_raw() {
        return Err(ProductStateRootError::Ownership);
    }
    fchmod(&directory, Mode::from_raw_mode(0o700))
        .map_err(|_| ProductStateRootError::Unavailable)?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn ensure_private_directory(_path: &Path) -> Result<(), ProductStateRootError> {
    Err(ProductStateRootError::UnsupportedPlatform)
}

const fn map_path_error(_error: SecureInputError) -> ProductStateRootError {
    ProductStateRootError::InvalidPath
}
