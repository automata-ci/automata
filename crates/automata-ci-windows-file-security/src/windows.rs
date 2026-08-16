use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read as _, Seek as _, SeekFrom},
    os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Component, Path, PathBuf, Prefix},
};

use stellar_agent_windows_identity::current_user_sid_string;
use windows_permissions::{
    constants::{AceType, SeObjectType, SecurityInformation},
    wrappers::{ConvertSecurityDescriptorToStringSecurityDescriptor, GetSecurityInfo},
};
use zeroize::Zeroizing;

#[cfg(test)]
use windows_permissions::wrappers::ConvertStringSidToSid;
#[cfg(any(test, feature = "test-support"))]
use windows_permissions::wrappers::{
    ConvertStringSecurityDescriptorToSecurityDescriptor, SetNamedSecurityInfo,
};

use crate::{
    AttestedFileError, ReadOptions,
    policy::{AceObservation, descriptor_is_trusted},
};

const MAX_PATH_BYTES: usize = 4_096;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_ATTRIBUTE_REPARSE_POINT: u64 = 0x0000_0400;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

#[derive(Debug)]
struct ValidatedPath {
    drive: u8,
    components: Vec<OsString>,
}

#[derive(Debug, Eq, PartialEq)]
struct FileSnapshot {
    volume_serial_number: u64,
    file_index: u64,
    number_of_links: u64,
    file_size: u64,
    creation_time: Option<u64>,
    last_write_time: Option<u64>,
    file_attributes: u64,
    security_descriptor: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectorySnapshot {
    volume_serial_number: u64,
    file_index: u64,
    file_attributes: u64,
}

impl DirectorySnapshot {
    fn from_information(information: &winapi_util::file::Information) -> Self {
        Self {
            volume_serial_number: information.volume_serial_number(),
            file_index: information.file_index(),
            file_attributes: information.file_attributes(),
        }
    }
}

/// Reads a Windows file only after proving its path, volume, identity, owner,
/// and DACL from retained handles.
///
/// The volume containing the running executable is the sole implicit approved
/// volume. Every target ancestor and the leaf must be a non-reparse disk object
/// on that same volume. The leaf is opened once, without write or delete
/// sharing, and the exact handle is read twice and re-attested before bytes are
/// returned.
///
/// # Errors
///
/// Returns only sanitized custody categories. No path, SID, descriptor, OS
/// error, or content bytes are included in an error.
pub fn read_attested_file(
    path: &Path,
    options: &ReadOptions,
) -> Result<Zeroizing<Vec<u8>>, AttestedFileError> {
    if options.maximum_bytes() == 0 {
        return Err(AttestedFileError::InvalidLimit);
    }
    let validated = validate_path(path)?;
    let approved_drive = executable_drive()?;
    if !validated.drive.eq_ignore_ascii_case(&approved_drive) {
        return Err(AttestedFileError::PathSecurity);
    }

    let root_path = PathBuf::from(format!("{}:\\", char::from(approved_drive)));
    prove_local_drive_resolution(&root_path, approved_drive)?;
    let root = open_directory(&root_path, None)?;
    let root_information = directory_information(&root, None)?;
    let approved_volume = root_information.volume_serial_number();
    if approved_volume == 0 {
        return Err(AttestedFileError::PathSecurity);
    }

    let mut retained_directories = Vec::with_capacity(validated.components.len());
    let mut directory_snapshots = Vec::with_capacity(validated.components.len());
    directory_snapshots.push(DirectorySnapshot::from_information(&root_information));
    retained_directories.push(root);
    let mut current_path = root_path;
    let (file_name, parents) = validated
        .components
        .split_last()
        .ok_or(AttestedFileError::InvalidPath)?;
    for component in parents {
        current_path.push(component);
        let directory = open_directory(&current_path, Some(approved_volume))?;
        let information = directory_information(&directory, Some(approved_volume))?;
        directory_snapshots.push(DirectorySnapshot::from_information(&information));
        retained_directories.push(directory);
    }

    current_path.push(file_name);
    let mut file = open_regular_file(&current_path, approved_volume)?;
    let current_sid = current_user_sid_string().map_err(|_| AttestedFileError::AccessSecurity)?;
    let before = snapshot(&file, options, &current_sid, approved_volume)?;
    let maximum = u64::try_from(options.maximum_bytes()).unwrap_or(u64::MAX);
    if before.file_size > maximum || (!options.allow_empty() && before.file_size == 0) {
        return Err(AttestedFileError::InvalidSize);
    }

    let first = read_once(&mut file, options)?;
    let second = read_once(&mut file, options)?;
    let after = snapshot(&file, options, &current_sid, approved_volume)?;
    if first.as_slice() != second.as_slice() || before != after {
        return Err(AttestedFileError::Unstable);
    }
    for (directory, expected) in retained_directories.iter().zip(directory_snapshots) {
        let information = directory_information(directory, Some(approved_volume))?;
        if DirectorySnapshot::from_information(&information) != expected {
            return Err(AttestedFileError::Unstable);
        }
    }
    drop(second);
    drop(retained_directories);
    Ok(first)
}

fn validate_path(path: &Path) -> Result<ValidatedPath, AttestedFileError> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || path.parent().is_none()
    {
        return Err(AttestedFileError::InvalidPath);
    }
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) if drive.is_ascii_alphabetic() => drive,
            _ => return Err(AttestedFileError::InvalidPath),
        },
        _ => return Err(AttestedFileError::InvalidPath),
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(AttestedFileError::InvalidPath);
    }
    let mut names = Vec::new();
    for component in components {
        let Component::Normal(name) = component else {
            return Err(AttestedFileError::InvalidPath);
        };
        validate_component(name)?;
        names.push(name.to_os_string());
    }
    if names.is_empty() {
        return Err(AttestedFileError::InvalidPath);
    }
    let mut canonical_syntax = PathBuf::from(format!("{}:\\", char::from(drive)));
    for name in &names {
        canonical_syntax.push(name);
    }
    if path.as_os_str() != canonical_syntax.as_os_str() {
        return Err(AttestedFileError::InvalidPath);
    }
    Ok(ValidatedPath {
        drive,
        components: names,
    })
}

fn validate_component(component: &OsStr) -> Result<(), AttestedFileError> {
    let value = component.to_str().ok_or(AttestedFileError::InvalidPath)?;
    if value.is_empty()
        || value.ends_with([' ', '.'])
        || value
            .chars()
            .any(|character| character.is_control() || r#"<>:"/\|?*"#.contains(character))
        || value
            .as_bytes()
            .windows(2)
            .any(|pair| pair[0] == b'~' && pair[1].is_ascii_digit())
        || is_reserved_dos_name(value)
    {
        return Err(AttestedFileError::InvalidPath);
    }
    Ok(())
}

fn is_reserved_dos_name(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
        .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

fn executable_drive() -> Result<u8, AttestedFileError> {
    let executable = std::env::current_exe().map_err(|_| AttestedFileError::PathSecurity)?;
    match executable.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) if drive.is_ascii_alphabetic() => {
                Ok(drive)
            }
            _ => Err(AttestedFileError::PathSecurity),
        },
        _ => Err(AttestedFileError::PathSecurity),
    }
}

fn prove_local_drive_resolution(root: &Path, drive: u8) -> Result<(), AttestedFileError> {
    let canonical = fs::canonicalize(root).map_err(|_| AttestedFileError::PathSecurity)?;
    let value = canonical.to_str().ok_or(AttestedFileError::PathSecurity)?;
    let value = value.strip_prefix(r"\\?\").unwrap_or(value);
    let bytes = value.as_bytes();
    if value.starts_with("UNC\\")
        || bytes.len() < 3
        || !bytes[0].eq_ignore_ascii_case(&drive)
        || bytes[1] != b':'
        || bytes[2] != b'\\'
    {
        return Err(AttestedFileError::PathSecurity);
    }
    Ok(())
}

fn open_directory(path: &Path, expected_volume: Option<u64>) -> Result<File, AttestedFileError> {
    let mut options = OpenOptions::new();
    options
        // Request real directory read access. Metadata-only handles do not
        // impose useful share compatibility on every Windows filesystem;
        // omission of delete sharing turns every retained ancestor into a
        // rename barrier. Write sharing remains enabled so unrelated volume
        // activity is not globally serialized; every ancestor is re-attested
        // from the retained handle before bytes are returned.
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let directory = options
        .open(path)
        .map_err(|_| AttestedFileError::PathSecurity)?;
    directory_information(&directory, expected_volume)?;
    Ok(directory)
}

fn directory_information(
    directory: &File,
    expected_volume: Option<u64>,
) -> Result<winapi_util::file::Information, AttestedFileError> {
    let metadata = directory
        .metadata()
        .map_err(|_| AttestedFileError::PathSecurity)?;
    let information =
        winapi_util::file::information(directory).map_err(|_| AttestedFileError::PathSecurity)?;
    if !metadata.is_dir()
        || u64::from(metadata.file_attributes()) & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !winapi_util::file::typ(directory)
            .map_err(|_| AttestedFileError::PathSecurity)?
            .is_disk()
        || information.volume_serial_number() == 0
        || information.file_index() == 0
        || expected_volume.is_some_and(|expected| information.volume_serial_number() != expected)
    {
        return Err(AttestedFileError::PathSecurity);
    }
    Ok(information)
}

fn open_regular_file(path: &Path, approved_volume: u64) -> Result<File, AttestedFileError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        // Existing readers may coexist. Write and delete sharing are omitted,
        // so no new mutator can enter after this custody handle is acquired.
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|_| AttestedFileError::PathSecurity)?;
    let metadata = file
        .metadata()
        .map_err(|_| AttestedFileError::PathSecurity)?;
    let information =
        winapi_util::file::information(&file).map_err(|_| AttestedFileError::PathSecurity)?;
    if !metadata.is_file()
        || u64::from(metadata.file_attributes()) & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.volume_serial_number() != approved_volume
        || information.file_index() == 0
        || information.number_of_links() != 1
        || information.file_size() != metadata.len()
        || !winapi_util::file::typ(&file)
            .map_err(|_| AttestedFileError::PathSecurity)?
            .is_disk()
    {
        return Err(AttestedFileError::PathSecurity);
    }
    Ok(file)
}

fn snapshot(
    file: &File,
    options: &ReadOptions,
    current_sid: &str,
    approved_volume: u64,
) -> Result<FileSnapshot, AttestedFileError> {
    let information =
        winapi_util::file::information(file).map_err(|_| AttestedFileError::PathSecurity)?;
    if information.volume_serial_number() != approved_volume
        || information.file_index() == 0
        || information.number_of_links() != 1
        || information.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !winapi_util::file::typ(file)
            .map_err(|_| AttestedFileError::PathSecurity)?
            .is_disk()
    {
        return Err(AttestedFileError::PathSecurity);
    }
    let security_descriptor = validate_security_descriptor(file, options, current_sid)?;
    Ok(FileSnapshot {
        volume_serial_number: information.volume_serial_number(),
        file_index: information.file_index(),
        number_of_links: information.number_of_links(),
        file_size: information.file_size(),
        creation_time: information.creation_time(),
        last_write_time: information.last_write_time(),
        file_attributes: information.file_attributes(),
        security_descriptor,
    })
}

fn validate_security_descriptor(
    file: &File,
    options: &ReadOptions,
    current_sid: &str,
) -> Result<String, AttestedFileError> {
    let requested = SecurityInformation::Owner | SecurityInformation::Dacl;
    let descriptor = GetSecurityInfo(file, SeObjectType::SE_FILE_OBJECT, requested)
        .map_err(|_| AttestedFileError::AccessSecurity)?;
    let owner = descriptor
        .owner()
        .map(ToString::to_string)
        .ok_or(AttestedFileError::AccessSecurity)?;
    let dacl = descriptor.dacl().ok_or(AttestedFileError::AccessSecurity)?;
    let ace_count = usize::try_from(dacl.len()).map_err(|_| AttestedFileError::AccessSecurity)?;
    if !(1..=16).contains(&ace_count) {
        return Err(AttestedFileError::AccessSecurity);
    }
    let mut aces = Vec::with_capacity(ace_count);
    for index in 0..dacl.len() {
        let ace = dacl
            .get_ace(index)
            .ok_or(AttestedFileError::AccessSecurity)?;
        let sid = ace
            .sid()
            .map(ToString::to_string)
            .ok_or(AttestedFileError::AccessSecurity)?;
        aces.push(AceObservation {
            sid,
            access_allowed: ace.ace_type() == AceType::ACCESS_ALLOWED_ACE_TYPE,
            flags: ace.flags().bits(),
            mask: ace.mask().bits(),
        });
    }
    let encoded = ConvertSecurityDescriptorToStringSecurityDescriptor(&descriptor, requested)
        .map_err(|_| AttestedFileError::AccessSecurity)?
        .to_str()
        .ok_or(AttestedFileError::AccessSecurity)?
        .to_owned();
    if !descriptor_is_trusted(
        &owner,
        current_sid,
        options.trusted_service_sids(),
        options.access(),
        has_protected_dacl(&encoded),
        &aces,
    ) {
        return Err(AttestedFileError::AccessSecurity);
    }
    Ok(encoded)
}

fn has_protected_dacl(encoded: &str) -> bool {
    let Some((_, dacl)) = encoded.split_once("D:") else {
        return false;
    };
    let flags = dacl.split_once('(').map_or(dacl, |(flags, _)| flags);
    // Windows can retain the AI history bit after replacing every inherited
    // ACE with a direct ACE. Protection plus the per-ACE inherited-flag check
    // is the effective invariant; AR would request future auto-inheritance.
    matches!(flags, "P" | "PAI")
}

fn read_once(
    file: &mut File,
    options: &ReadOptions,
) -> Result<Zeroizing<Vec<u8>>, AttestedFileError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AttestedFileError::Unstable)?;
    let maximum = u64::try_from(options.maximum_bytes()).unwrap_or(u64::MAX);
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::Read::by_ref(file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| AttestedFileError::Unstable)?;
    if bytes.len() > options.maximum_bytes() || (!options.allow_empty() && bytes.is_empty()) {
        return Err(AttestedFileError::InvalidSize);
    }
    Ok(bytes)
}

/// Applies the exact protected current-user-only DACL used by Windows tests.
///
/// This feature-gated helper exists solely so owning-crate fixtures exercise
/// the production custody seam instead of bypassing it.
///
/// # Errors
///
/// Returns a sanitized access-control category if the test fixture cannot be
/// restricted through the reviewed safe wrapper.
#[cfg(any(test, feature = "test-support"))]
pub fn restrict_file_to_current_user_for_test(path: &Path) -> Result<(), AttestedFileError> {
    let current_sid = current_user_sid_string().map_err(|_| AttestedFileError::AccessSecurity)?;
    let encoded = format!("D:P(A;;FA;;;{current_sid})");
    let descriptor = ConvertStringSecurityDescriptorToSecurityDescriptor(&encoded)
        .map_err(|_| AttestedFileError::AccessSecurity)?;
    let dacl = descriptor.dacl().ok_or(AttestedFileError::AccessSecurity)?;
    SetNamedSecurityInfo(
        path,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        Some(dacl),
        None,
    )
    .map_err(|_| AttestedFileError::AccessSecurity)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::ReadAccess;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn test_root(label: &str) -> PathBuf {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "automata-windows-file-security-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    fn secure_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write fixture");
        restrict_file_to_current_user_for_test(path).expect("restrict fixture DACL");
    }

    fn approved_volume() -> u64 {
        let drive = executable_drive().expect("executable drive");
        let root_path = PathBuf::from(format!("{}:\\", char::from(drive)));
        let root = open_directory(&root_path, None).expect("open approved drive root");
        directory_information(&root, None)
            .expect("query approved drive root")
            .volume_serial_number()
    }

    #[test]
    fn compliant_file_is_bounded_and_read_from_one_identity() {
        let root = test_root("compliant");
        fs::create_dir(&root).expect("create fixture root");
        let path = root.join("secret");
        secure_file(&path, b"secret");
        assert_eq!(
            read_attested_file(&path, &ReadOptions::new(6, false, ReadAccess::Private))
                .expect("read compliant file")
                .as_slice(),
            b"secret"
        );
        assert_eq!(
            read_attested_file(&path, &ReadOptions::new(5, false, ReadAccess::Private)),
            Err(AttestedFileError::InvalidSize)
        );
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    #[test]
    fn inherited_and_broader_dacls_fail_closed() {
        let root = test_root("dacl");
        fs::create_dir(&root).expect("create fixture root");
        let inherited = root.join("inherited");
        secure_file(&inherited, b"secret");
        let current_sid = current_user_sid_string().expect("current SID");
        let unprotected = ConvertStringSecurityDescriptorToSecurityDescriptor(&format!(
            "D:(A;;FA;;;{current_sid})"
        ))
        .expect("unprotected descriptor");
        let dacl = unprotected.dacl().expect("DACL");
        SetNamedSecurityInfo(
            &inherited,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::UnprotectedDacl,
            None,
            None,
            Some(dacl),
            None,
        )
        .expect("install unprotected DACL");
        assert_eq!(
            read_attested_file(
                &inherited,
                &ReadOptions::new(32, false, ReadAccess::Private)
            ),
            Err(AttestedFileError::AccessSecurity)
        );

        let broader = root.join("broader");
        secure_file(&broader, b"secret");
        let descriptor = ConvertStringSecurityDescriptorToSecurityDescriptor(&format!(
            "D:P(A;;FA;;;{current_sid})(A;;GR;;;WD)"
        ))
        .expect("broader descriptor");
        let dacl = descriptor.dacl().expect("DACL");
        SetNamedSecurityInfo(
            &broader,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
            None,
            None,
            Some(dacl),
            None,
        )
        .expect("install broader DACL");
        assert_eq!(
            read_attested_file(&broader, &ReadOptions::new(32, false, ReadAccess::Private)),
            Err(AttestedFileError::AccessSecurity)
        );

        let writable = root.join("world-writable");
        secure_file(&writable, b"public material");
        let descriptor = ConvertStringSecurityDescriptorToSecurityDescriptor(&format!(
            "D:P(A;;FA;;;{current_sid})(A;;GRGW;;;WD)"
        ))
        .expect("world-writable descriptor");
        let dacl = descriptor.dacl().expect("DACL");
        SetNamedSecurityInfo(
            &writable,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
            None,
            None,
            Some(dacl),
            None,
        )
        .expect("install world-writable DACL");
        assert_eq!(
            read_attested_file(
                &writable,
                &ReadOptions::new(32, false, ReadAccess::PublicRead)
            ),
            Err(AttestedFileError::AccessSecurity)
        );
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    #[test]
    fn mismatched_owner_fails_closed_when_the_host_allows_owner_reassignment() {
        let root = test_root("owner");
        fs::create_dir(&root).expect("create fixture root");
        let path = root.join("secret");
        secure_file(&path, b"secret");
        let administrators =
            ConvertStringSidToSid("S-1-5-32-544").expect("builtin Administrators SID");
        let reassignment = SetNamedSecurityInfo(
            &path,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Owner,
            Some(&administrators),
            None,
            None,
            None,
        );
        match reassignment {
            Ok(()) => assert_eq!(
                read_attested_file(&path, &ReadOptions::new(32, false, ReadAccess::Private)),
                Err(AttestedFileError::AccessSecurity)
            ),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    // Standard, non-elevated test tokens cannot assign a
                    // different owner. The platform-neutral policy test still
                    // exercises the negative decision on every host.
                    Some(5 | 1_307 | 1_314)
                ) => {}
            Err(error) => panic!("unexpected owner-reassignment error: {error}"),
        }
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    #[test]
    fn hardlinks_directories_and_alternate_streams_fail_closed() {
        let root = test_root("topology");
        fs::create_dir(&root).expect("create fixture root");
        let target = root.join("target");
        secure_file(&target, b"secret");
        let hardlink = root.join("hardlink");
        fs::hard_link(&target, &hardlink).expect("create hardlink");
        assert_eq!(
            read_attested_file(&target, &ReadOptions::new(32, false, ReadAccess::Private)),
            Err(AttestedFileError::PathSecurity)
        );
        assert_eq!(
            read_attested_file(&root, &ReadOptions::new(32, false, ReadAccess::Private)),
            Err(AttestedFileError::PathSecurity)
        );
        let stream = PathBuf::from(format!("{}:hidden", target.display()));
        assert_eq!(
            read_attested_file(&stream, &ReadOptions::new(32, false, ReadAccess::Private)),
            Err(AttestedFileError::InvalidPath)
        );
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    #[test]
    fn file_and_directory_reparse_points_fail_closed() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let root = test_root("reparse");
        fs::create_dir(&root).expect("create fixture root");
        let target = root.join("target");
        secure_file(&target, b"secret");
        let link = root.join("link");
        if let Err(error) = symlink_file(&target, &link) {
            if error.raw_os_error() == Some(1_314) {
                fs::remove_dir_all(root).expect("remove fixture root");
                return;
            }
            panic!("create file symlink: {error}");
        }
        assert_eq!(
            read_attested_file(&link, &ReadOptions::new(32, false, ReadAccess::Private)),
            Err(AttestedFileError::PathSecurity)
        );

        let directory = root.join("directory");
        fs::create_dir(&directory).expect("create target directory");
        let nested = directory.join("nested");
        secure_file(&nested, b"secret");
        let directory_link = root.join("directory-link");
        symlink_dir(&directory, &directory_link).expect("create directory symlink");
        assert_eq!(
            read_attested_file(
                &directory_link.join("nested"),
                &ReadOptions::new(32, false, ReadAccess::Private)
            ),
            Err(AttestedFileError::PathSecurity)
        );

        let target_root = root.join("target-root");
        let nested_directory = target_root.join("nested-directory");
        fs::create_dir_all(&nested_directory).expect("create target root tree");
        secure_file(&nested_directory.join("secret"), b"secret");
        let root_link = root.join("root-link");
        symlink_dir(&target_root, &root_link).expect("create root-level directory symlink");
        assert_eq!(
            read_attested_file(
                &root_link.join("nested-directory").join("secret"),
                &ReadOptions::new(32, false, ReadAccess::Private)
            ),
            Err(AttestedFileError::PathSecurity)
        );
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    #[test]
    fn retained_handles_block_swaps_and_reattest_volume_and_file_identity() {
        let root = test_root("retained-handles");
        let ancestor = root.join("ancestor");
        fs::create_dir_all(&ancestor).expect("create fixture tree");
        let path = ancestor.join("secret");
        secure_file(&path, b"secret");

        let volume = approved_volume();
        let retained_ancestor =
            open_directory(&ancestor, Some(volume)).expect("retain ancestor handle");
        let mut leaf = open_regular_file(&path, volume).expect("retain leaf handle");
        let current_sid = current_user_sid_string().expect("current SID");
        let options = ReadOptions::new(32, false, ReadAccess::Private);
        let before = snapshot(&leaf, &options, &current_sid, volume).expect("initial attestation");
        assert_eq!(before.volume_serial_number, volume);
        assert_ne!(before.file_index, 0);

        assert!(
            OpenOptions::new().write(true).open(&path).is_err(),
            "leaf handle must deny a new writer"
        );
        assert!(
            fs::rename(&path, ancestor.join("swapped-secret")).is_err(),
            "leaf handle must deny rename/delete sharing"
        );
        let first = read_once(&mut leaf, &options).expect("first bounded read");
        let second = read_once(&mut leaf, &options).expect("second bounded read");
        let after = snapshot(&leaf, &options, &current_sid, volume).expect("final attestation");
        assert_eq!(first.as_slice(), second.as_slice());
        assert_eq!(before, after);

        drop(first);
        drop(second);
        drop(leaf);
        let moved_ancestor = root.join("moved-ancestor");
        assert!(
            fs::rename(&ancestor, &moved_ancestor).is_err(),
            "retained ancestor must deny subtree rename"
        );
        drop(retained_ancestor);
        fs::rename(&ancestor, &moved_ancestor).expect("rename after handles close");
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    #[test]
    fn ambiguous_windows_namespaces_and_aliases_fail_closed() {
        for path in [
            Path::new(r"relative\secret"),
            Path::new(r"\\server\share\secret"),
            Path::new(r"\\?\C:\secret"),
            Path::new(r"\\.\C:\secret"),
            Path::new(r"C:\safe\..\secret"),
            Path::new(r"C:\safe\.\secret"),
            Path::new(r"C:\safe\\secret"),
            Path::new("C:/safe/secret"),
            Path::new(r"C:\safe\secret:stream"),
            Path::new(r"C:\AUTOMA~1\secret"),
            Path::new(r"C:\safe\NUL.txt"),
        ] {
            assert!(
                matches!(validate_path(path), Err(AttestedFileError::InvalidPath)),
                "{}",
                path.display()
            );
        }
    }
}
