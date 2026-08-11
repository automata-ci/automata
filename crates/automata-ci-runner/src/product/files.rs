use std::{
    ffi::{OsStr, OsString},
    fmt,
    path::{Component, Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

/// Maximum supported path length at the product configuration boundary.
const MAX_PATH_BYTES: usize = 4_096;
const TEMPORARY_COMPONENT: &str = "tmp";

/// A secret-bearing input location. Secret bytes are never accepted directly
/// in process arguments or in the runner configuration document.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretSource {
    /// Read bytes from an owner-only, descriptor-opened regular file.
    File {
        /// Absolute non-temporary path to the secret-bearing regular file.
        path: PathBuf,
    },
    /// Read bytes from one explicitly named process environment variable.
    Environment {
        /// Canonical environment-variable name; the value is never formatted.
        name: String,
    },
}

impl SecretSource {
    pub(crate) fn validate(&self) -> Result<(), SecureInputError> {
        match self {
            Self::File { path } => validate_absolute_path(path),
            Self::Environment { name } => validate_environment_name(name),
        }
    }

    pub(crate) fn read(
        &self,
        maximum_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
        if maximum_bytes == 0 {
            return Err(SecureInputError::InvalidLimit);
        }
        match self {
            Self::File { path } => {
                read_file(path, maximum_bytes, FileTrust::OwnerOnly).map(Zeroizing::new)
            }
            Self::Environment { name } => {
                validate_environment_name(name)?;
                let value = std::env::var_os(name).ok_or(SecureInputError::Unavailable)?;
                let value = value
                    .into_string()
                    .map_err(|_| SecureInputError::InvalidEncoding)?;
                if value.is_empty() || value.len() > maximum_bytes {
                    return Err(SecureInputError::InvalidSize);
                }
                Ok(Zeroizing::new(value.into_bytes()))
            }
        }
    }

    /// Loads one bounded scalar secret, accepting a conventional terminal line
    /// ending only for file-backed sources.
    ///
    /// Exactly one trailing LF or CRLF is removed from a file. Environment
    /// values are never normalized. Empty values, content over the post-
    /// normalization limit, embedded line endings, and multiple trailing line
    /// endings are rejected.
    ///
    /// # Errors
    ///
    /// Returns a sanitized secure-input category when the source cannot be
    /// loaded securely or is not one bounded scalar value.
    pub fn read_scalar(
        &self,
        maximum_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
        if maximum_bytes == 0 {
            return Err(SecureInputError::InvalidLimit);
        }
        let input_limit = match self {
            Self::File { .. } => maximum_bytes
                .checked_add(2)
                .ok_or(SecureInputError::InvalidLimit)?,
            Self::Environment { .. } => maximum_bytes,
        };
        let mut bytes = self.read(input_limit)?;
        if matches!(self, Self::File { .. }) {
            if bytes.ends_with(b"\r\n") {
                let scalar_len = bytes.len() - 2;
                bytes.truncate(scalar_len);
            } else if bytes.ends_with(b"\n") {
                let scalar_len = bytes.len() - 1;
                bytes.truncate(scalar_len);
            }
        }
        if bytes.is_empty() || bytes.len() > maximum_bytes {
            return Err(SecureInputError::InvalidSize);
        }
        if bytes.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err(SecureInputError::InvalidEncoding);
        }
        Ok(bytes)
    }
}

impl fmt::Debug for SecretSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File { path } => formatter
                .debug_struct("SecretSource")
                .field("kind", &"file")
                .field("path", path)
                .field("value", &"[REDACTED]")
                .finish(),
            Self::Environment { name } => formatter
                .debug_struct("SecretSource")
                .field("kind", &"environment")
                .field("name", name)
                .field("value", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Bounded failures at a file/environment configuration boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecureInputError {
    /// The configured resource ceiling was zero.
    #[error("secure input limit is invalid")]
    InvalidLimit,
    /// A path was relative, traversing, too long, or selected a temporary hierarchy.
    #[error("secure input path is invalid")]
    InvalidPath,
    /// An environment-variable name was not canonical.
    #[error("secure input environment name is invalid")]
    InvalidEnvironmentName,
    /// The source was absent or inaccessible.
    #[error("secure input is unavailable")]
    Unavailable,
    /// The input was empty or exceeded its configured bound.
    #[error("secure input size is invalid")]
    InvalidSize,
    /// A secret value had invalid text encoding or scalar line structure.
    #[error("secure input encoding is invalid")]
    InvalidEncoding,
    /// A file, owner, permission, or symlink invariant was violated.
    #[error("secure input file security policy was violated")]
    PathSecurity,
    /// The current platform cannot enforce the required file policy.
    #[error("secure file inputs are unsupported on this platform")]
    UnsupportedPlatform,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileTrust {
    Configuration,
    PublicMaterial,
    OwnerOnly,
}

pub(crate) fn read_configuration_file(
    path: &Path,
    maximum_bytes: usize,
) -> Result<Vec<u8>, SecureInputError> {
    read_file(path, maximum_bytes, FileTrust::Configuration)
}

pub(crate) fn read_public_material(
    source: &SecretSource,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    match source {
        SecretSource::Environment { .. } => source.read(maximum_bytes),
        SecretSource::File { path } => {
            read_file(path, maximum_bytes, FileTrust::PublicMaterial).map(Zeroizing::new)
        }
    }
}

pub(crate) fn validate_absolute_path(path: &Path) -> Result<(), SecureInputError> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || path.parent().is_none()
    {
        return Err(SecureInputError::InvalidPath);
    }
    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {}
            Component::Normal(value) => {
                normal_components += 1;
                if value == OsStr::new(TEMPORARY_COMPONENT) {
                    return Err(SecureInputError::InvalidPath);
                }
            }
            Component::CurDir | Component::ParentDir => {
                return Err(SecureInputError::InvalidPath);
            }
        }
    }
    if normal_components == 0 {
        return Err(SecureInputError::InvalidPath);
    }
    Ok(())
}

fn validate_environment_name(name: &str) -> Result<(), SecureInputError> {
    let valid = !name.is_empty()
        && name.len() <= 128
        && name
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_uppercase() || *byte == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
    valid
        .then_some(())
        .ok_or(SecureInputError::InvalidEnvironmentName)
}

#[cfg(unix)]
fn read_file(
    path: &Path,
    maximum_bytes: usize,
    trust: FileTrust,
) -> Result<Vec<u8>, SecureInputError> {
    use std::{fs::File, io::Read as _};

    use rustix::{
        fd::OwnedFd,
        fs::{FileType, Mode, OFlags, fstat, openat},
    };

    validate_absolute_path(path)?;
    if maximum_bytes == 0 {
        return Err(SecureInputError::InvalidLimit);
    }
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect::<Vec<OsString>>();
    let (file_name, parents) = components
        .split_last()
        .ok_or(SecureInputError::InvalidPath)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut directory: OwnedFd = rustix::fs::open("/", directory_flags, Mode::empty())
        .map_err(|_| SecureInputError::Unavailable)?;
    for component in parents {
        directory = openat(&directory, component, directory_flags, Mode::empty())
            .map_err(|_| SecureInputError::PathSecurity)?;
        let metadata = fstat(&directory).map_err(|_| SecureInputError::Unavailable)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
            return Err(SecureInputError::PathSecurity);
        }
    }
    let file = openat(
        &directory,
        file_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| SecureInputError::Unavailable)?;
    let metadata = fstat(&file).map_err(|_| SecureInputError::Unavailable)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
        return Err(SecureInputError::PathSecurity);
    }
    let trusted = file_is_trusted(
        metadata.st_uid,
        metadata.st_mode & 0o777,
        trust,
        rustix::process::geteuid().as_raw(),
    );
    if !trusted {
        return Err(SecureInputError::PathSecurity);
    }
    let received = u64::try_from(metadata.st_size).unwrap_or(u64::MAX);
    if received == 0 || received > u64::try_from(maximum_bytes).unwrap_or(u64::MAX) {
        return Err(SecureInputError::InvalidSize);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(received).unwrap_or(0));
    File::from(file)
        .take(
            u64::try_from(maximum_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|_| SecureInputError::Unavailable)?;
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(SecureInputError::InvalidSize);
    }
    Ok(bytes)
}

#[cfg(unix)]
const fn file_is_trusted(
    owner: u32,
    permission_bits: u32,
    trust: FileTrust,
    effective_uid: u32,
) -> bool {
    match trust {
        FileTrust::OwnerOnly => owner == effective_uid && permission_bits.trailing_zeros() >= 6,
        FileTrust::Configuration | FileTrust::PublicMaterial => {
            (owner == 0 || owner == effective_uid) && permission_bits & 0o022 == 0
        }
    }
}

#[cfg(not(unix))]
fn read_file(
    _path: &Path,
    _maximum_bytes: usize,
    _trust: FileTrust,
) -> Result<Vec<u8>, SecureInputError> {
    Err(SecureInputError::UnsupportedPlatform)
}

#[cfg(all(test, unix))]
mod tests {
    use super::{FileTrust, file_is_trusted};

    #[test]
    fn configuration_and_public_files_require_a_trusted_owner() {
        for trust in [FileTrust::Configuration, FileTrust::PublicMaterial] {
            assert!(file_is_trusted(1_000, 0o644, trust, 1_000));
            assert!(file_is_trusted(0, 0o444, trust, 1_000));
            assert!(!file_is_trusted(2_000, 0o444, trust, 1_000));
            assert!(!file_is_trusted(0, 0o664, trust, 1_000));
        }
    }

    #[test]
    fn private_files_require_owner_only_permissions() {
        assert!(file_is_trusted(1_000, 0o600, FileTrust::OwnerOnly, 1_000));
        assert!(!file_is_trusted(0, 0o600, FileTrust::OwnerOnly, 1_000));
        assert!(!file_is_trusted(1_000, 0o640, FileTrust::OwnerOnly, 1_000));
    }
}
