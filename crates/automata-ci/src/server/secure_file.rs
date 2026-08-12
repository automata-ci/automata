//! Secure bounded private-file input boundary.
//!
//! This module owns the platform seam behind file-backed private server
//! inputs. A platform adapter must prove the complete capability contract:
//! reach the file without following links or reparse points, verify every
//! ancestor from a trusted handle, verify file type and ownership, reject
//! access broader than the owning identity, and bound the read before and
//! after it happens. A platform without a reviewed adapter returns
//! a typed unavailable error and never falls back to an ordinary read.

use std::{io, path::Path};

use thiserror::Error;
use zeroize::Zeroizing;

/// Sanitized secure private-file read failure.
#[derive(Debug, Error)]
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(crate) enum SecureFileError {
    /// The path or file did not satisfy the owner-private input policy.
    #[error("file does not satisfy the owner-private input policy")]
    Insecure,
    /// The file exceeded the caller's byte ceiling.
    #[error("file exceeds the {maximum}-byte limit")]
    TooLarge {
        /// Inclusive context-specific byte ceiling.
        maximum: usize,
    },
    /// The opened file could not be read.
    #[error("secured file could not be read")]
    Read(#[source] io::Error),
    /// No reviewed platform adapter provides the secure-file contract.
    #[cfg(not(any(unix, windows)))]
    #[error("secure private-file input has no reviewed adapter on this platform")]
    Unavailable,
}

/// Reads an owner-private regular file of at most `maximum_bytes` bytes.
///
/// The Unix adapter requires an absolute path without `.` or `..`, opens every
/// ancestor without following symlinks, opens the file itself without
/// following symlinks, and requires a regular file owned by the effective
/// user, readable by its owner, with no group or other permission bits. The
/// size is bounded before and after the read.
///
/// # Errors
///
/// Returns a sanitized [`SecureFileError`] when the platform has no reviewed
/// adapter, the file fails the policy, the bound is exceeded, or the read
/// fails.
#[cfg(unix)]
pub(crate) fn read_owner_private(
    path: &Path,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecureFileError> {
    use std::{ffi::OsString, fs::File, io::Read as _, path::Component};

    use rustix::{
        fd::OwnedFd,
        fs::{FileType, Mode, OFlags, fstat, openat},
    };

    if !path.is_absolute() || maximum_bytes == 0 {
        return Err(SecureFileError::Insecure);
    }
    let mut components = Vec::<OsString>::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {}
            Component::Normal(value) => components.push(value.to_os_string()),
            Component::CurDir | Component::ParentDir => {
                return Err(SecureFileError::Insecure);
            }
        }
    }
    let (file_name, parents) = components.split_last().ok_or(SecureFileError::Insecure)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut directory: OwnedFd = rustix::fs::open("/", directory_flags, Mode::empty())
        .map_err(|_| SecureFileError::Insecure)?;
    for component in parents {
        directory = openat(&directory, component, directory_flags, Mode::empty())
            .map_err(|_| SecureFileError::Insecure)?;
        let metadata = fstat(&directory).map_err(|_| SecureFileError::Insecure)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
            return Err(SecureFileError::Insecure);
        }
    }
    let file = openat(
        &directory,
        file_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| SecureFileError::Insecure)?;
    let metadata = fstat(&file).map_err(|_| SecureFileError::Insecure)?;
    let permission_bits = metadata.st_mode & 0o777;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || permission_bits & 0o400 == 0
        || permission_bits & 0o077 != 0
    {
        return Err(SecureFileError::Insecure);
    }
    let received = u64::try_from(metadata.st_size).unwrap_or(u64::MAX);
    if received > u64::try_from(maximum_bytes).unwrap_or(u64::MAX) {
        return Err(SecureFileError::TooLarge {
            maximum: maximum_bytes,
        });
    }
    let capacity = usize::try_from(received).unwrap_or(maximum_bytes);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity.min(maximum_bytes)));
    let take_limit = u64::try_from(maximum_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    File::from(file)
        .take(take_limit)
        .read_to_end(&mut bytes)
        .map_err(SecureFileError::Read)?;
    if bytes.len() > maximum_bytes {
        return Err(SecureFileError::TooLarge {
            maximum: maximum_bytes,
        });
    }
    Ok(bytes)
}

#[cfg(windows)]
pub(crate) fn read_owner_private(
    path: &Path,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecureFileError> {
    automata_ci_secure_file_windows::read_owner_private(path, maximum_bytes).map_err(|error| {
        match error {
            automata_ci_secure_file_windows::SecureFileError::Insecure => SecureFileError::Insecure,
            automata_ci_secure_file_windows::SecureFileError::TooLarge { maximum } => {
                SecureFileError::TooLarge { maximum }
            }
            automata_ci_secure_file_windows::SecureFileError::Read(error) => {
                SecureFileError::Read(error)
            }
        }
    })
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn read_owner_private(
    _path: &Path,
    _maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecureFileError> {
    Err(SecureFileError::Unavailable)
}
