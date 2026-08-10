use std::path::Path;

#[cfg(target_os = "linux")]
use std::io::Read as _;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt as _;

use thiserror::Error;

#[cfg(target_os = "linux")]
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
    /// A secret-bearing provider directory was not on verified non-swappable memory.
    #[error("runner provider transient storage boundary is invalid")]
    UnprotectedStorage,
    /// The current platform cannot enforce the required descriptor policy.
    #[error("runner provider state roots are unsupported on this platform")]
    UnsupportedPlatform,
}

#[cfg(target_os = "linux")]
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
    ensure_non_persistent_mount(&directory)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn ensure_private_directory(_path: &Path) -> Result<(), ProductStateRootError> {
    Err(ProductStateRootError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
const fn map_path_error(_error: SecureInputError) -> ProductStateRootError {
    ProductStateRootError::InvalidPath
}

#[cfg(target_os = "linux")]
const TMPFS_MAGIC: u64 = 0x0102_1994;
#[cfg(target_os = "linux")]
const MAX_MOUNTINFO_BYTES: usize = 1024 * 1024;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MountIdentity {
    id: u64,
    device_major: u32,
    device_minor: u32,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct MountEvidence {
    identity: MountIdentity,
    parent_id: u64,
    root: Vec<u8>,
    mount_point: Vec<u8>,
    mount_options: Vec<u8>,
    optional_fields: Vec<Vec<u8>>,
    filesystem_type: Vec<u8>,
    mount_source: Vec<u8>,
    super_options: Vec<u8>,
}

/// Exact dedicated runtime-mount evidence retained across Podman use.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct RuntimeMountSnapshot {
    evidence: MountEvidence,
    directory: std::sync::Arc<rustix::fd::OwnedFd>,
}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for RuntimeMountSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeMountSnapshot")
            .field("evidence", &self.evidence)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
impl PartialEq for RuntimeMountSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.evidence == other.evidence
    }
}

#[cfg(target_os = "linux")]
impl Eq for RuntimeMountSnapshot {}

#[cfg(target_os = "linux")]
impl RuntimeMountSnapshot {
    /// Revalidates the exact mount identity, topology, and option record.
    pub(crate) fn revalidate(&self, path: &Path) -> Result<(), ProductStateRootError> {
        let retained = capture_mount_snapshot(&self.directory, Some(path))?;
        let current = capture_dedicated_runtime_mount(path)?;
        (self.evidence == retained && self.evidence == current.evidence)
            .then_some(())
            .ok_or(ProductStateRootError::UnprotectedStorage)
    }

    #[cfg(test)]
    pub(crate) fn synthetic_for_test(path: &Path) -> Self {
        let directory = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .expect("open synthetic runtime directory");
        Self {
            evidence: MountEvidence {
                identity: MountIdentity {
                    id: 1,
                    device_major: 0,
                    device_minor: 1,
                },
                parent_id: 2,
                root: b"/".to_vec(),
                mount_point: path.as_os_str().as_bytes().to_vec(),
                mount_options: b"rw,nosuid,nodev".to_vec(),
                optional_fields: Vec::new(),
                filesystem_type: b"tmpfs".to_vec(),
                mount_source: b"tmpfs".to_vec(),
                super_options: b"rw,noswap,size=1g,mode=700".to_vec(),
            },
            directory: std::sync::Arc::new(directory),
        }
    }
}

/// Unsupported-platform placeholder used only to keep product composition portable.
#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeMountSnapshot;

/// Captures the exact dedicated mount backing the configured rootless runtime.
#[cfg(target_os = "linux")]
pub(crate) fn capture_dedicated_runtime_mount(
    path: &Path,
) -> Result<RuntimeMountSnapshot, ProductStateRootError> {
    let directory = open_existing_private_directory(path)?;
    let evidence = capture_mount_snapshot(&directory, Some(path))?;
    Ok(RuntimeMountSnapshot {
        evidence,
        directory: std::sync::Arc::new(directory),
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn capture_dedicated_runtime_mount(
    _path: &Path,
) -> Result<RuntimeMountSnapshot, ProductStateRootError> {
    Err(ProductStateRootError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn open_existing_private_directory(
    path: &Path,
) -> Result<rustix::fd::OwnedFd, ProductStateRootError> {
    use rustix::fs::{self, FileType, Mode, OFlags, fstat, openat};

    validate_absolute_path(path).map_err(map_path_error)?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut directory =
        fs::open("/", flags, Mode::empty()).map_err(|_| ProductStateRootError::Unavailable)?;
    let effective_user = rustix::process::geteuid().as_raw();
    let components = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        directory = openat(&directory, *component, flags, Mode::empty())
            .map_err(|_| ProductStateRootError::PathSecurity)?;
        let metadata = fstat(&directory).map_err(|_| ProductStateRootError::Unavailable)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
            return Err(ProductStateRootError::PathSecurity);
        }
        let final_component = index.checked_add(1) == Some(components.len());
        if final_component {
            if metadata.st_uid != effective_user || metadata.st_mode & 0o7777 != 0o700 {
                return Err(ProductStateRootError::Ownership);
            }
        } else if (metadata.st_uid != 0 && metadata.st_uid != effective_user)
            || metadata.st_mode & 0o022 != 0
        {
            return Err(ProductStateRootError::PathSecurity);
        }
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn ensure_non_persistent_mount(
    directory: &rustix::fd::OwnedFd,
) -> Result<(), ProductStateRootError> {
    capture_mount_snapshot(directory, None).map(|_| ())
}

#[cfg(target_os = "linux")]
fn capture_mount_snapshot(
    directory: &rustix::fd::OwnedFd,
    dedicated_path: Option<&Path>,
) -> Result<MountEvidence, ProductStateRootError> {
    use rustix::fs::fstatfs;

    let before = mount_identity(directory)?;
    let before_filesystem = fstatfs(directory).map_err(|_| ProductStateRootError::Unavailable)?;
    if u64::try_from(before_filesystem.f_type) != Ok(TMPFS_MAGIC) {
        return Err(ProductStateRootError::UnprotectedStorage);
    }
    let before_evidence = match dedicated_path {
        Some(path) => dedicated_runtime_evidence(&read_mountinfo()?, before, path)?,
        None => backing_mount_evidence(&read_mountinfo()?, before)?,
    };

    let after = mount_identity(directory)?;
    let after_filesystem = fstatfs(directory).map_err(|_| ProductStateRootError::Unavailable)?;
    if after != before || u64::try_from(after_filesystem.f_type) != Ok(TMPFS_MAGIC) {
        return Err(ProductStateRootError::UnprotectedStorage);
    }
    let after_evidence = match dedicated_path {
        Some(path) => dedicated_runtime_evidence(&read_mountinfo()?, after, path)?,
        None => backing_mount_evidence(&read_mountinfo()?, after)?,
    };
    (before_evidence == after_evidence)
        .then_some(after_evidence)
        .ok_or(ProductStateRootError::UnprotectedStorage)
}

#[cfg(target_os = "linux")]
fn mount_identity(directory: &rustix::fd::OwnedFd) -> Result<MountIdentity, ProductStateRootError> {
    use rustix::fs::{AtFlags, StatxFlags, statx};

    let metadata = statx(
        directory,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::MNT_ID | StatxFlags::BASIC_STATS,
    )
    .map_err(|_| ProductStateRootError::UnprotectedStorage)?;
    if metadata.stx_mask & StatxFlags::MNT_ID.bits() == 0 || metadata.stx_mnt_id == 0 {
        return Err(ProductStateRootError::UnprotectedStorage);
    }
    Ok(MountIdentity {
        id: metadata.stx_mnt_id,
        device_major: metadata.stx_dev_major,
        device_minor: metadata.stx_dev_minor,
    })
}

#[cfg(target_os = "linux")]
fn read_mountinfo() -> Result<Vec<u8>, ProductStateRootError> {
    use std::fs::File;

    use rustix::fs::{FileType, Mode, OFlags, fstat, open};

    let descriptor = open(
        "/proc/thread-self/mountinfo",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ProductStateRootError::UnprotectedStorage)?;
    let metadata = fstat(&descriptor).map_err(|_| ProductStateRootError::UnprotectedStorage)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
        return Err(ProductStateRootError::UnprotectedStorage);
    }
    let mut bytes = Vec::with_capacity(MAX_MOUNTINFO_BYTES.min(64 * 1024));
    File::from(descriptor)
        .take(u64::try_from(MAX_MOUNTINFO_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| ProductStateRootError::UnprotectedStorage)?;
    if bytes.is_empty() || bytes.len() > MAX_MOUNTINFO_BYTES || bytes.last() != Some(&b'\n') {
        return Err(ProductStateRootError::UnprotectedStorage);
    }
    Ok(bytes)
}

#[cfg(all(test, target_os = "linux"))]
fn require_noswap_tmpfs(
    mountinfo: &[u8],
    expected: MountIdentity,
) -> Result<(), ProductStateRootError> {
    backing_mount_evidence(mountinfo, expected).map(|_| ())
}

#[cfg(target_os = "linux")]
fn backing_mount_evidence(
    mountinfo: &[u8],
    expected: MountIdentity,
) -> Result<MountEvidence, ProductStateRootError> {
    validate_mountinfo_document(mountinfo)?;
    let mut matched = None;
    let mut has_child_mount = false;
    for raw_line in mountinfo[..mountinfo.len() - 1].split(|byte| *byte == b'\n') {
        let record = parse_mountinfo_record(raw_line)?;
        has_child_mount |= record.parent_id == expected.id;
        if record.identity.id != expected.id {
            continue;
        }
        if matched.is_some()
            || record.identity != expected
            || record.filesystem_type != b"tmpfs"
            || !has_exact_noswap(record.super_options)
        {
            return Err(ProductStateRootError::UnprotectedStorage);
        }
        matched = Some(record.into_evidence());
    }
    match (matched, has_child_mount) {
        (Some(evidence), false) => Ok(evidence),
        _ => Err(ProductStateRootError::UnprotectedStorage),
    }
}

#[cfg(target_os = "linux")]
fn dedicated_runtime_evidence(
    mountinfo: &[u8],
    expected: MountIdentity,
    configured_path: &Path,
) -> Result<MountEvidence, ProductStateRootError> {
    validate_mountinfo_document(mountinfo)?;
    let configured = configured_path.as_os_str().as_bytes();
    if configured.first() != Some(&b'/') || configured.last() == Some(&b'/') {
        return Err(ProductStateRootError::UnprotectedStorage);
    }

    let mut matched = None;
    let mut has_child_or_alias = false;
    for raw_line in mountinfo[..mountinfo.len() - 1].split(|byte| *byte == b'\n') {
        let record = parse_mountinfo_record(raw_line)?;
        let same_device = record.identity.device_major == expected.device_major
            && record.identity.device_minor == expected.device_minor;
        let within_runtime = same_or_descendant(&record.mount_point, configured);
        if record.identity.id == expected.id {
            if matched.is_some()
                || record.identity != expected
                || record.root != b"/"
                || record.mount_point != configured
                || record.filesystem_type != b"tmpfs"
                || !has_exact_noswap(record.super_options)
            {
                return Err(ProductStateRootError::UnprotectedStorage);
            }
            matched = Some(record.into_evidence());
        } else if within_runtime || same_device || record.parent_id == expected.id {
            has_child_or_alias = true;
        }
    }
    match (matched, has_child_or_alias) {
        (Some(evidence), false) => Ok(evidence),
        _ => Err(ProductStateRootError::UnprotectedStorage),
    }
}

#[cfg(target_os = "linux")]
fn validate_mountinfo_document(mountinfo: &[u8]) -> Result<(), ProductStateRootError> {
    if mountinfo.is_empty()
        || mountinfo.len() > MAX_MOUNTINFO_BYTES
        || mountinfo.last() != Some(&b'\n')
    {
        return Err(ProductStateRootError::UnprotectedStorage);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct ParsedMountinfoRecord<'a> {
    identity: MountIdentity,
    parent_id: u64,
    root: Vec<u8>,
    mount_point: Vec<u8>,
    mount_options: &'a [u8],
    optional_fields: Vec<&'a [u8]>,
    filesystem_type: &'a [u8],
    mount_source: &'a [u8],
    super_options: &'a [u8],
}

#[cfg(target_os = "linux")]
impl ParsedMountinfoRecord<'_> {
    fn into_evidence(self) -> MountEvidence {
        MountEvidence {
            identity: self.identity,
            parent_id: self.parent_id,
            root: self.root,
            mount_point: self.mount_point,
            mount_options: self.mount_options.to_vec(),
            optional_fields: self
                .optional_fields
                .into_iter()
                .map(<[u8]>::to_vec)
                .collect(),
            filesystem_type: self.filesystem_type.to_vec(),
            mount_source: self.mount_source.to_vec(),
            super_options: self.super_options.to_vec(),
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_mountinfo_record(
    raw_line: &[u8],
) -> Result<ParsedMountinfoRecord<'_>, ProductStateRootError> {
    if raw_line.is_empty()
        || raw_line
            .iter()
            .any(|byte| byte.is_ascii_whitespace() && *byte != b' ')
    {
        return Err(ProductStateRootError::UnprotectedStorage);
    }
    let fields = raw_line.split(|byte| *byte == b' ').collect::<Vec<_>>();
    if fields.len() < 10 || fields.iter().any(|field| field.is_empty()) {
        return Err(ProductStateRootError::UnprotectedStorage);
    }
    let separators = fields
        .iter()
        .enumerate()
        .filter(|(_, field)| **field == b"-")
        .collect::<Vec<_>>();
    let separator = match separators.as_slice() {
        [(separator, _)] if *separator >= 6 && separator.checked_add(4) == Some(fields.len()) => {
            *separator
        }
        _ => return Err(ProductStateRootError::UnprotectedStorage),
    };
    let identity = MountIdentity {
        id: parse_decimal_u64(fields[0])?,
        device_major: parse_device(fields[2])?.0,
        device_minor: parse_device(fields[2])?.1,
    };
    let parent_id = parse_decimal_u64(fields[1])?;
    validate_option_list(fields[5])?;
    validate_option_list(fields[separator + 3])?;
    Ok(ParsedMountinfoRecord {
        identity,
        parent_id,
        root: decode_mountinfo_path(fields[3])?,
        mount_point: decode_mountinfo_path(fields[4])?,
        mount_options: fields[5],
        optional_fields: fields[6..separator].to_vec(),
        filesystem_type: fields[separator + 1],
        mount_source: fields[separator + 2],
        super_options: fields[separator + 3],
    })
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(value: &[u8]) -> Result<Vec<u8>, ProductStateRootError> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0_usize;
    while index < value.len() {
        if value[index] != b'\\' {
            decoded.push(value[index]);
            index += 1;
            continue;
        }
        let escape = value
            .get(index + 1..index + 4)
            .ok_or(ProductStateRootError::UnprotectedStorage)?;
        let byte = match escape {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err(ProductStateRootError::UnprotectedStorage),
        };
        decoded.push(byte);
        index += 4;
    }
    if decoded.first() != Some(&b'/') {
        return Err(ProductStateRootError::UnprotectedStorage);
    }
    Ok(decoded)
}

#[cfg(target_os = "linux")]
fn validate_option_list(value: &[u8]) -> Result<(), ProductStateRootError> {
    if value.is_empty() || value.split(|byte| *byte == b',').any(<[u8]>::is_empty) {
        Err(ProductStateRootError::UnprotectedStorage)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn same_or_descendant(candidate: &[u8], root: &[u8]) -> bool {
    candidate == root
        || (candidate.starts_with(root)
            && candidate
                .get(root.len())
                .is_some_and(|separator| *separator == b'/'))
}

#[cfg(target_os = "linux")]
fn has_exact_noswap(options: &[u8]) -> bool {
    let mut found = false;
    for option in options.split(|byte| *byte == b',') {
        if option.is_empty() || option == b"swap" || (option == b"noswap" && found) {
            return false;
        }
        found |= option == b"noswap";
    }
    found
}

#[cfg(target_os = "linux")]
fn parse_decimal_u64(value: &[u8]) -> Result<u64, ProductStateRootError> {
    let parsed = parse_decimal_u64_allow_zero(value)?;
    (parsed > 0)
        .then_some(parsed)
        .ok_or(ProductStateRootError::UnprotectedStorage)
}

#[cfg(target_os = "linux")]
fn parse_device(value: &[u8]) -> Result<(u32, u32), ProductStateRootError> {
    let separator = value
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(ProductStateRootError::UnprotectedStorage)?;
    let (major, minor_with_separator) = value.split_at(separator);
    let minor = minor_with_separator
        .get(1..)
        .ok_or(ProductStateRootError::UnprotectedStorage)?;
    if minor.contains(&b':') {
        return Err(ProductStateRootError::UnprotectedStorage);
    }
    let major = parse_decimal_u64_allow_zero(major)?;
    let minor = parse_decimal_u64_allow_zero(minor)?;
    Ok((
        u32::try_from(major).map_err(|_| ProductStateRootError::UnprotectedStorage)?,
        u32::try_from(minor).map_err(|_| ProductStateRootError::UnprotectedStorage)?,
    ))
}

#[cfg(target_os = "linux")]
fn parse_decimal_u64_allow_zero(value: &[u8]) -> Result<u64, ProductStateRootError> {
    if value.is_empty()
        || (value.len() > 1 && value.first() == Some(&b'0'))
        || !value.iter().all(u8::is_ascii_digit)
    {
        return Err(ProductStateRootError::UnprotectedStorage);
    }
    value.iter().try_fold(0_u64, |parsed, byte| {
        parsed
            .checked_mul(10)
            .and_then(|parsed| parsed.checked_add(u64::from(*byte - b'0')))
            .ok_or(ProductStateRootError::UnprotectedStorage)
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    const EXPECTED: MountIdentity = MountIdentity {
        id: 41,
        device_major: 0,
        device_minor: 77,
    };

    fn mountinfo(super_options: &str) -> Vec<u8> {
        format!(
            "29 1 8:1 / / rw,relatime - ext4 /dev/root rw\n\
             41 29 0:77 / /run/automata rw,nosuid,nodev shared:9 - tmpfs tmpfs {super_options}\n"
        )
        .into_bytes()
    }

    fn dedicated_mountinfo(
        root: &str,
        mount_point: &str,
        mount_options: &str,
        optional_fields: &str,
        super_options: &str,
    ) -> Vec<u8> {
        let optional_fields = if optional_fields.is_empty() {
            String::new()
        } else {
            format!(" {optional_fields}")
        };
        format!(
            "29 1 8:1 / / rw,relatime - ext4 /dev/root rw\n\
             41 29 0:77 {root} {mount_point} {mount_options}{optional_fields} - tmpfs tmpfs {super_options}\n"
        )
        .into_bytes()
    }

    #[test]
    fn exact_tmpfs_noswap_mount_is_admitted() {
        let document = mountinfo("rw,size=1g,noswap,mode=700");
        assert_eq!(require_noswap_tmpfs(&document, EXPECTED), Ok(()));
    }

    #[test]
    fn swappable_or_durable_storage_is_rejected() {
        for document in [
            mountinfo("rw,size=1g,mode=700"),
            mountinfo("rw,size=1g,no-swap,mode=700"),
            mountinfo("rw,noswap,swap"),
            mountinfo("rw,noswap,noswap"),
            mountinfo("rw,noswap,"),
            b"41 29 0:77 / /run/automata rw - ext4 /dev/root rw,noswap\n".to_vec(),
        ] {
            assert_eq!(
                require_noswap_tmpfs(&document, EXPECTED),
                Err(ProductStateRootError::UnprotectedStorage)
            );
        }
    }

    #[test]
    fn mount_identity_must_match_exactly_and_uniquely() {
        let wrong_device = String::from_utf8(mountinfo("rw,noswap"))
            .expect("ASCII fixture")
            .replace("0:77", "0:78")
            .into_bytes();
        let mut duplicate = mountinfo("rw,noswap");
        duplicate.extend_from_slice(b"41 29 0:77 / /other rw - tmpfs tmpfs rw,noswap\n");
        for document in [
            wrong_device,
            duplicate,
            b"42 29 0:77 / /run/automata rw - tmpfs tmpfs rw,noswap\n".to_vec(),
        ] {
            assert_eq!(
                require_noswap_tmpfs(&document, EXPECTED),
                Err(ProductStateRootError::UnprotectedStorage)
            );
        }
    }

    #[test]
    fn nested_mounts_cannot_bypass_the_admitted_backing_mount() {
        let mut nested = mountinfo("rw,noswap");
        nested.extend_from_slice(b"73 41 8:2 / /run/automata/workspaces rw - ext4 /dev/other rw\n");
        assert_eq!(
            require_noswap_tmpfs(&nested, EXPECTED),
            Err(ProductStateRootError::UnprotectedStorage)
        );
    }

    #[test]
    fn malformed_or_truncated_mount_evidence_is_rejected() {
        let mut oversized = vec![b'x'; MAX_MOUNTINFO_BYTES + 1];
        oversized.push(b'\n');
        for document in [
            Vec::new(),
            b"41 29 0:77 / /run rw - tmpfs tmpfs rw,noswap".to_vec(),
            b"41 29 broken / /run rw - tmpfs tmpfs rw,noswap\n".to_vec(),
            b"41 29 0:77 / /run rw tmpfs tmpfs rw,noswap\n".to_vec(),
            b"41 29 0:77 / /run rw - tmpfs tmpfs rw,noswap trailing\n".to_vec(),
            vec![0xff, b'\n'],
            oversized,
        ] {
            assert_eq!(
                require_noswap_tmpfs(&document, EXPECTED),
                Err(ProductStateRootError::UnprotectedStorage)
            );
        }
    }

    #[test]
    fn dedicated_runtime_mount_binds_decoded_root_and_mountpoint() {
        let document = dedicated_mountinfo(
            "/",
            "/run/automata\\040runner",
            "rw,nosuid,nodev",
            "shared:9",
            "rw,noswap,size=1g,nr_inodes=4096,mode=700",
        );
        let evidence =
            dedicated_runtime_evidence(&document, EXPECTED, Path::new("/run/automata runner"))
                .expect("escaped exact mountpoint must be decoded and admitted");
        assert_eq!(evidence.root, b"/");
        assert_eq!(evidence.mount_point, b"/run/automata runner");

        for rejected in [
            dedicated_mountinfo("/", "/run", "rw,nosuid,nodev", "", "rw,noswap,size=1g"),
            dedicated_mountinfo(
                "/runner-subtree",
                "/run/automata",
                "rw,nosuid,nodev",
                "",
                "rw,noswap,size=1g",
            ),
            dedicated_mountinfo(
                "/",
                "/run/automata\\999runner",
                "rw,nosuid,nodev",
                "",
                "rw,noswap,size=1g",
            ),
        ] {
            assert_eq!(
                dedicated_runtime_evidence(&rejected, EXPECTED, Path::new("/run/automata")),
                Err(ProductStateRootError::UnprotectedStorage)
            );
        }
    }

    #[test]
    fn dedicated_runtime_rejects_shared_device_aliases_and_all_descendant_mounts() {
        let base = dedicated_mountinfo(
            "/",
            "/run/automata",
            "rw,nosuid,nodev",
            "",
            "rw,noswap,size=1g",
        );
        for extra in [
            b"72 29 0:77 / /run/alias rw - tmpfs tmpfs rw,noswap,size=1g\n".as_slice(),
            b"73 41 8:2 / /run/automata/automata-ci-podman/shared-tmp rw - ext4 /dev/other rw\n",
            b"74 29 8:3 / /run/automata/automata-ci-podman/job-engines/job-a/run rw - ext4 /dev/other rw\n",
            b"75 29 8:4 / /run/automata rw - ext4 /dev/other rw\n",
        ] {
            let mut document = base.clone();
            document.extend_from_slice(extra);
            assert_eq!(
                dedicated_runtime_evidence(&document, EXPECTED, Path::new("/run/automata")),
                Err(ProductStateRootError::UnprotectedStorage)
            );
        }
    }

    #[test]
    fn mount_option_or_propagation_drift_changes_the_exact_snapshot() {
        let original = dedicated_mountinfo(
            "/",
            "/run/automata",
            "rw,nosuid,nodev",
            "shared:9",
            "rw,noswap,size=1g,nr_inodes=4096,mode=700",
        );
        let original = dedicated_runtime_evidence(&original, EXPECTED, Path::new("/run/automata"))
            .expect("original mount evidence");
        for changed in [
            dedicated_mountinfo(
                "/",
                "/run/automata",
                "rw,nosuid,nodev,noexec",
                "shared:9",
                "rw,noswap,size=1g,nr_inodes=4096,mode=700",
            ),
            dedicated_mountinfo(
                "/",
                "/run/automata",
                "rw,nosuid,nodev",
                "master:7",
                "rw,noswap,size=1g,nr_inodes=4096,mode=700",
            ),
            dedicated_mountinfo(
                "/",
                "/run/automata",
                "rw,nosuid,nodev",
                "shared:9",
                "rw,noswap,size=2g,nr_inodes=4096,mode=700",
            ),
        ] {
            let changed =
                dedicated_runtime_evidence(&changed, EXPECTED, Path::new("/run/automata"))
                    .expect("individually valid changed evidence");
            assert_ne!(original, changed, "exact option drift must be observable");
        }
    }

    #[test]
    fn mountinfo_requires_canonical_single_space_records() {
        for document in [
            b"041 29 0:77 / /run/automata rw - tmpfs tmpfs rw,noswap\n".to_vec(),
            b"41 029 0:77 / /run/automata rw - tmpfs tmpfs rw,noswap\n".to_vec(),
            b"41 29 00:77 / /run/automata rw - tmpfs tmpfs rw,noswap\n".to_vec(),
            b"41 29 0:77 /  /run/automata rw - tmpfs tmpfs rw,noswap\n".to_vec(),
            b"41\t29 0:77 / /run/automata rw - tmpfs tmpfs rw,noswap\n".to_vec(),
        ] {
            assert_eq!(
                require_noswap_tmpfs(&document, EXPECTED),
                Err(ProductStateRootError::UnprotectedStorage)
            );
        }
    }
}
