//! Owner-private bounded file reads proven against Windows handles.
//!
//! The adapter accepts only unambiguous absolute drive paths, walks every
//! ancestor without following reparse points while pinning each verified
//! directory handle against replacement, opens the file itself without
//! following reparse points, and then proves the owner and every DACL entry
//! from the opened handle before a bounded read. Failures are sanitized and
//! never reflect the path or file content.

use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, Read as _},
    os::windows::{ffi::OsStrExt as _, fs::OpenOptionsExt as _},
    path::{Component, Path, PathBuf, Prefix},
};

use thiserror::Error;
use windows_permissions::{
    Sid,
    constants::{AceType, SeObjectType, SecurityInformation},
    utilities::current_process_sid,
    wrappers::{ConvertSidToStringSid, EqualSid, GetSecurityInfo},
};
use zeroize::Zeroizing;

const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_DIRECTORY: u64 = 0x0010;
const FILE_ATTRIBUTE_REPARSE_POINT: u64 = 0x0400;
/// `WELL_KNOWN_SID_TYPE` value for `WinLocalSystemSid` (`S-1-5-18`).
const WIN_LOCAL_SYSTEM_SID: u32 = 22;
/// `WELL_KNOWN_SID_TYPE` value for `WinBuiltinAdministratorsSid` (`S-1-5-32-544`).
const WIN_BUILTIN_ADMINISTRATORS_SID: u32 = 26;

/// Sanitized secure private-file read failure.
#[derive(Debug, Error)]
pub enum SecureFileError {
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
}

/// Reads an owner-private regular file of at most `maximum_bytes` bytes.
///
/// The path must be an absolute `C:\`-style drive path without `.` or `..`
/// components, alternate data streams, reserved device names, trailing dots
/// or spaces, or UNC, device, or verbatim prefixes. Every ancestor directory
/// is opened without following reparse points and stays pinned by an open
/// handle without delete sharing until the read completes, so a verified
/// component cannot be replaced mid-walk. The file itself is opened without
/// following reparse points, must be a plain non-reparse file owned by the
/// current process user, and every DACL entry must be an allow entry for the
/// owner, `SYSTEM`, or the built-in `Administrators` group. The size is
/// bounded before and after the read.
///
/// # Errors
///
/// Returns a sanitized [`SecureFileError`] when the path is ambiguous, the
/// walk or open fails, the file fails the owner-private policy, the bound is
/// exceeded, or the read fails.
pub fn read_owner_private(
    path: &Path,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecureFileError> {
    if maximum_bytes == 0 {
        return Err(SecureFileError::Insecure);
    }
    let (root, components) = validated_components(path)?;
    let (file_name, ancestors) = components.split_last().ok_or(SecureFileError::Insecure)?;
    let mut current = root;
    let mut pinned = Vec::with_capacity(ancestors.len());
    for ancestor in ancestors {
        current.push(ancestor);
        pinned.push(open_pinned_directory(&current)?);
    }
    current.push(file_name);
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&current)
        .map_err(|_| SecureFileError::Insecure)?;
    let information =
        winapi_util::file::information(&file).map_err(|_| SecureFileError::Insecure)?;
    if information.file_attributes() & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
        != 0
    {
        return Err(SecureFileError::Insecure);
    }
    verify_owner_private_security(&file)?;
    let maximum = u64::try_from(maximum_bytes).unwrap_or(u64::MAX);
    if information.file_size() > maximum {
        return Err(SecureFileError::TooLarge {
            maximum: maximum_bytes,
        });
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(information.file_size())
            .unwrap_or(maximum_bytes)
            .min(maximum_bytes),
    ));
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(SecureFileError::Read)?;
    if bytes.len() > maximum_bytes {
        return Err(SecureFileError::TooLarge {
            maximum: maximum_bytes,
        });
    }
    drop(pinned);
    Ok(bytes)
}

/// Returns the current process user's SID in `S-1-…` string form.
///
/// Test fixtures use this to grant the exact test identity when building
/// restricted directories; it is not a custody decision by itself.
///
/// # Errors
///
/// Returns the underlying token or conversion failure.
pub fn current_user_sid_text() -> io::Result<String> {
    let user = current_process_sid()?;
    ConvertSidToStringSid(&user)?
        .into_string()
        .map_err(|_| io::Error::other("non-Unicode SID text"))
}

/// Accepts only an unambiguous absolute disk path and returns its pieces.
fn validated_components(path: &Path) -> Result<(PathBuf, Vec<&OsStr>), SecureFileError> {
    let mut components = path.components();
    let root = match (components.next(), components.next()) {
        (Some(Component::Prefix(prefix)), Some(Component::RootDir)) => match prefix.kind() {
            Prefix::Disk(_) => {
                let mut root = prefix.as_os_str().to_os_string();
                root.push("\\");
                PathBuf::from(root)
            }
            Prefix::Verbatim(_)
            | Prefix::VerbatimUNC(_, _)
            | Prefix::VerbatimDisk(_)
            | Prefix::DeviceNS(_)
            | Prefix::UNC(_, _) => return Err(SecureFileError::Insecure),
        },
        _ => return Err(SecureFileError::Insecure),
    };
    let mut normals = Vec::new();
    for component in components {
        match component {
            Component::Normal(name) if unambiguous_component(name) => normals.push(name),
            Component::Normal(_)
            | Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => return Err(SecureFileError::Insecure),
        }
    }
    if normals.is_empty() {
        return Err(SecureFileError::Insecure);
    }
    Ok((root, normals))
}

/// Rejects stream syntax, normalization-ambiguous names, and device names.
fn unambiguous_component(name: &OsStr) -> bool {
    let units: Vec<u16> = name.encode_wide().collect();
    let Some(&last) = units.last() else {
        return false;
    };
    if last == u16::from(b'.') || last == u16::from(b' ') {
        return false;
    }
    if units.contains(&u16::from(b':')) {
        return false;
    }
    !reserved_device_stem(&units)
}

/// Reports whether the name's stem selects a Win32 device.
fn reserved_device_stem(units: &[u16]) -> bool {
    let stem_length = units
        .iter()
        .position(|&unit| unit == u16::from(b'.'))
        .unwrap_or(units.len());
    let stem = units[..stem_length]
        .iter()
        .map(|&unit| {
            if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
                unit - 0x20
            } else {
                unit
            }
        })
        .collect::<Vec<u16>>();
    let Ok(stem) = String::from_utf16(&stem) else {
        return false;
    };
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || (stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.as_bytes()[3].is_ascii_digit()
        && stem.as_bytes()[3] != b'0')
}

/// Opens one ancestor without following reparse points and verifies it.
///
/// The returned handle is held without delete sharing, so the verified
/// directory cannot be renamed or replaced while the walk continues.
fn open_pinned_directory(path: &Path) -> Result<File, SecureFileError> {
    let directory = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| SecureFileError::Insecure)?;
    let information =
        winapi_util::file::information(&directory).map_err(|_| SecureFileError::Insecure)?;
    let attributes = information.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(SecureFileError::Insecure);
    }
    Ok(directory)
}

/// Proves the opened file is owner-private from its own handle.
fn verify_owner_private_security(file: &File) -> Result<(), SecureFileError> {
    let descriptor = GetSecurityInfo(
        file,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl,
    )
    .map_err(|_| SecureFileError::Insecure)?;
    let owner = descriptor.owner().ok_or(SecureFileError::Insecure)?;
    let user = current_process_sid().map_err(|_| SecureFileError::Insecure)?;
    if !EqualSid(owner, &user) {
        return Err(SecureFileError::Insecure);
    }
    let dacl = descriptor.dacl().ok_or(SecureFileError::Insecure)?;
    let system =
        Sid::well_known_sid(WIN_LOCAL_SYSTEM_SID).map_err(|_| SecureFileError::Insecure)?;
    let administrators = Sid::well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)
        .map_err(|_| SecureFileError::Insecure)?;
    for index in 0..dacl.len() {
        let ace = dacl.get_ace(index).ok_or(SecureFileError::Insecure)?;
        if ace.ace_type() != AceType::ACCESS_ALLOWED_ACE_TYPE {
            return Err(SecureFileError::Insecure);
        }
        let grantee = ace.sid().ok_or(SecureFileError::Insecure)?;
        if !(EqualSid(grantee, &user)
            || EqualSid(grantee, &system)
            || EqualSid(grantee, &administrators))
        {
            return Err(SecureFileError::Insecure);
        }
    }
    Ok(())
}
