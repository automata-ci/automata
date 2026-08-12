use std::{
    ffi::OsStr,
    fmt,
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::ffi::OsString;

use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

/// Maximum supported path length at the product configuration boundary.
const MAX_PATH_BYTES: usize = 4_096;
const MAX_KEYCHAIN_LOCATOR_BYTES: usize = 256;
const TEMPORARY_COMPONENT: &str = "tmp";
#[cfg(target_os = "macos")]
const KEYCHAIN_RESULT_LIMIT: i64 = 2;
#[cfg(target_os = "macos")]
const KEYCHAIN_SKIP_AUTHENTICATED_ITEMS: bool = true;
#[cfg(target_os = "macos")]
const KEYCHAIN_DISABLE_INTERACTION: bool = true;

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
    /// Read one generic-password item from the default macOS Keychain.
    MacosKeychain {
        /// Exact Keychain service attribute.
        service: String,
        /// Exact Keychain account attribute.
        account: String,
    },
}

impl SecretSource {
    pub(crate) fn validate(&self) -> Result<(), SecureInputError> {
        match self {
            Self::File { path } => validate_absolute_path(path),
            Self::Environment { name } => validate_environment_name(name),
            Self::MacosKeychain { service, account } => {
                validate_keychain_locator(service)?;
                validate_keychain_locator(account)?;
                if cfg!(target_os = "macos") {
                    Ok(())
                } else {
                    Err(SecureInputError::UnsupportedPlatform)
                }
            }
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
            Self::MacosKeychain { service, account } => {
                read_macos_keychain(service, account, maximum_bytes)
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
            Self::Environment { .. } | Self::MacosKeychain { .. } => maximum_bytes,
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
            Self::MacosKeychain { service, account } => formatter
                .debug_struct("SecretSource")
                .field("kind", &"macos_keychain")
                .field("service", service)
                .field("account", account)
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
    /// A Keychain service or account locator was empty, oversized, or non-canonical.
    #[error("secure input Keychain locator is invalid")]
    InvalidKeychainLocator,
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
        SecretSource::Environment { .. } | SecretSource::MacosKeychain { .. } => {
            source.read(maximum_bytes)
        }
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
    #[cfg(windows)]
    if !matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), std::path::Prefix::Disk(_))
    ) {
        // Security-sensitive Windows paths are local drive-qualified paths.
        // UNC, device, and verbatim namespaces have different alias and
        // reparse semantics and remain outside this adapter's proof boundary.
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

fn validate_keychain_locator(value: &str) -> Result<(), SecureInputError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_KEYCHAIN_LOCATOR_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic());
    valid
        .then_some(())
        .ok_or(SecureInputError::InvalidKeychainLocator)
}

#[cfg(target_os = "macos")]
fn read_macos_keychain(
    service: &str,
    account: &str,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    use std::sync::Mutex;

    use security_framework::{
        item::{ItemClass, ItemSearchOptions, Limit},
        os::macos::keychain::SecKeychain,
    };

    static KEYCHAIN_INTERACTION: Mutex<()> = Mutex::new(());

    validate_keychain_locator(service)?;
    validate_keychain_locator(account)?;
    let _serialized_interaction_policy = KEYCHAIN_INTERACTION
        .lock()
        .map_err(|_| SecureInputError::Unavailable)?;
    let interaction_allowed =
        SecKeychain::user_interaction_allowed().map_err(|_| SecureInputError::Unavailable)?;
    let _disabled_interaction = (interaction_allowed && KEYCHAIN_DISABLE_INTERACTION)
        .then(SecKeychain::disable_user_interaction)
        .transpose()
        .map_err(|_| SecureInputError::Unavailable)?;
    let keychain = SecKeychain::default().map_err(|_| SecureInputError::Unavailable)?;
    let mut search = ItemSearchOptions::new();
    let results = search
        .keychains(std::slice::from_ref(&keychain))
        .class(ItemClass::generic_password())
        .service(service)
        .account(account)
        .load_data(true)
        .limit(Limit::Max(KEYCHAIN_RESULT_LIMIT))
        .skip_authenticated_items(KEYCHAIN_SKIP_AUTHENTICATED_ITEMS)
        .search()
        .map_err(|_| SecureInputError::Unavailable)?;
    select_macos_keychain_password(results, maximum_bytes)
}

#[cfg(target_os = "macos")]
fn select_macos_keychain_password(
    mut results: Vec<security_framework::item::SearchResult>,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    use security_framework::item::SearchResult;

    if maximum_bytes == 0 {
        return Err(SecureInputError::InvalidLimit);
    }
    if results.len() != 1 {
        return Err(SecureInputError::Unavailable);
    }
    let SearchResult::Data(password) = results.pop().ok_or(SecureInputError::Unavailable)? else {
        return Err(SecureInputError::Unavailable);
    };
    if password.is_empty() || password.len() > maximum_bytes {
        return Err(SecureInputError::InvalidSize);
    }
    Ok(Zeroizing::new(password))
}

#[cfg(not(target_os = "macos"))]
fn read_macos_keychain(
    _service: &str,
    _account: &str,
    _maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    Err(SecureInputError::UnsupportedPlatform)
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
    permission_bits: rustix::fs::RawMode,
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

#[cfg(windows)]
fn read_file(
    path: &Path,
    maximum_bytes: usize,
    trust: FileTrust,
) -> Result<Vec<u8>, SecureInputError> {
    use std::{
        fs::{File, OpenOptions},
        io::Read as _,
        os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
    };

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    fn open_directory(path: &Path) -> Result<File, SecureInputError> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            // Omit delete sharing so each live handle stabilizes its component.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let directory = options
            .open(path)
            .map_err(|_| SecureInputError::PathSecurity)?;
        let metadata = directory
            .metadata()
            .map_err(|_| SecureInputError::Unavailable)?;
        if metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
            Ok(directory)
        } else {
            Err(SecureInputError::PathSecurity)
        }
    }

    validate_absolute_path(path)?;
    if maximum_bytes == 0 {
        return Err(SecureInputError::InvalidLimit);
    }
    // Safe std APIs cannot prove the effective Windows principal owns a file
    // and that its DACL grants no other principal access. Secret-bearing file
    // sources therefore remain closed until an ACL-attesting adapter exists.
    if trust == FileTrust::OwnerOnly {
        return Err(SecureInputError::UnsupportedPlatform);
    }

    let parent = path.parent().ok_or(SecureInputError::InvalidPath)?;
    let mut paths = parent.ancestors().collect::<Vec<_>>();
    paths.reverse();
    let mut directory_handles = Vec::with_capacity(paths.len());
    for directory_path in paths {
        directory_handles.push(open_directory(directory_path)?);
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = options
        .open(path)
        .map_err(|_| SecureInputError::Unavailable)?;
    let metadata = file.metadata().map_err(|_| SecureInputError::Unavailable)?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(SecureInputError::PathSecurity);
    }
    let received = metadata.len();
    if received == 0 || received > u64::try_from(maximum_bytes).unwrap_or(u64::MAX) {
        return Err(SecureInputError::InvalidSize);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(received).unwrap_or(0));
    std::io::Read::by_ref(&mut file)
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
    drop(directory_handles);
    Ok(bytes)
}

#[cfg(not(any(unix, windows)))]
fn read_file(
    _path: &Path,
    _maximum_bytes: usize,
    _trust: FileTrust,
) -> Result<Vec<u8>, SecureInputError> {
    Err(SecureInputError::UnsupportedPlatform)
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        FileTrust, SecretSource, SecureInputError, file_is_trusted, validate_keychain_locator,
    };

    #[cfg(target_os = "macos")]
    use super::{
        KEYCHAIN_DISABLE_INTERACTION, KEYCHAIN_RESULT_LIMIT, KEYCHAIN_SKIP_AUTHENTICATED_ITEMS,
        select_macos_keychain_password,
    };

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

    #[test]
    fn keychain_locators_are_bounded_visible_text() {
        for value in [
            "automata-ci.runner",
            "Automata CI Runner",
            "runner@example.com",
        ] {
            assert_eq!(validate_keychain_locator(value), Ok(()));
        }
        for value in ["", " leading", "trailing ", "line\nfeed"] {
            assert_eq!(
                validate_keychain_locator(value),
                Err(SecureInputError::InvalidKeychainLocator)
            );
        }
        assert_eq!(
            validate_keychain_locator(&"a".repeat(257)),
            Err(SecureInputError::InvalidKeychainLocator)
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn macos_keychain_source_fails_closed_on_other_unix_hosts() {
        let source = SecretSource::MacosKeychain {
            service: "automata-ci.runner".to_owned(),
            account: "runner@example.com".to_owned(),
        };
        assert_eq!(
            source.validate(),
            Err(SecureInputError::UnsupportedPlatform)
        );
        assert_eq!(source.read(64), Err(SecureInputError::UnsupportedPlatform));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn missing_macos_keychain_item_is_sanitized_without_interaction() {
        let source = SecretSource::MacosKeychain {
            service: format!(
                "automata-ci.missing-test.{}.{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ),
            account: "missing".to_owned(),
        };
        assert_eq!(source.validate(), Ok(()));
        assert_eq!(source.read(64), Err(SecureInputError::Unavailable));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_selection_rejects_ambiguous_oversized_and_malformed_values() {
        use security_framework::item::SearchResult;

        assert_eq!(
            select_macos_keychain_password(
                vec![
                    SearchResult::Data(b"first".to_vec()),
                    SearchResult::Data(b"second".to_vec())
                ],
                64,
            ),
            Err(SecureInputError::Unavailable)
        );
        assert_eq!(
            select_macos_keychain_password(vec![SearchResult::Data(vec![0x41; 65])], 64),
            Err(SecureInputError::InvalidSize)
        );
        assert_eq!(
            select_macos_keychain_password(vec![SearchResult::Data(Vec::new())], 64),
            Err(SecureInputError::InvalidSize)
        );
        assert_eq!(
            select_macos_keychain_password(vec![SearchResult::Other], 64),
            Err(SecureInputError::Unavailable)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn interactive_keychain_items_are_excluded_by_the_bounded_search_policy() {
        const {
            assert!(KEYCHAIN_DISABLE_INTERACTION);
            assert!(KEYCHAIN_SKIP_AUTHENTICATED_ITEMS);
            assert!(KEYCHAIN_RESULT_LIMIT == 2);
        }
        assert_eq!(
            select_macos_keychain_password(Vec::new(), 64),
            Err(SecureInputError::Unavailable)
        );
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "automata-files-{label}-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn configuration_and_public_material_are_bounded_regular_files() {
        let root = test_root("public");
        fs::create_dir(&root).expect("create test root");
        let path = root.join("input.pem");
        fs::write(&path, b"public-material").expect("write test input");

        assert_eq!(
            read_file(&path, 32, FileTrust::Configuration).expect("read configuration"),
            b"public-material"
        );
        assert_eq!(
            read_file(&path, 8, FileTrust::PublicMaterial),
            Err(SecureInputError::InvalidSize)
        );

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn owner_only_files_fail_closed_without_acl_attestation() {
        let root = test_root("owner-only");
        fs::create_dir(&root).expect("create test root");
        let path = root.join("secret");
        fs::write(&path, b"secret").expect("write test input");

        assert_eq!(
            read_file(&path, 32, FileTrust::OwnerOnly),
            Err(SecureInputError::UnsupportedPlatform)
        );

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn network_device_and_verbatim_namespaces_fail_closed() {
        for path in [
            Path::new(r"\\server\share\runner.json"),
            Path::new(r"\\?\C:\automata\runner.json"),
            Path::new(r"\\.\C:\automata\runner.json"),
        ] {
            assert_eq!(
                validate_absolute_path(path),
                Err(SecureInputError::InvalidPath),
                "unexpectedly admitted {}",
                path.display()
            );
        }
    }

    #[test]
    fn file_and_directory_reparse_points_are_rejected() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let root = test_root("reparse");
        fs::create_dir(&root).expect("create test root");
        let target = root.join("target");
        let link = root.join("link");
        fs::write(&target, b"public").expect("write target");
        if let Err(error) = symlink_file(&target, &link) {
            // Creating symlinks requires Developer Mode or the corresponding
            // privilege on some Windows hosts; topology checks remain covered
            // wherever the host permits constructing the fixture.
            if error.raw_os_error() == Some(1_314) {
                fs::remove_dir_all(root).expect("remove test root");
                return;
            }
            panic!("create file symlink: {error}");
        }

        assert_eq!(
            read_file(&link, 32, FileTrust::PublicMaterial),
            Err(SecureInputError::PathSecurity)
        );

        let target_directory = root.join("target-directory");
        let directory_link = root.join("directory-link");
        fs::create_dir(&target_directory).expect("create target directory");
        fs::write(target_directory.join("input"), b"public").expect("write nested target");
        symlink_dir(&target_directory, &directory_link).expect("create directory symlink");
        assert_eq!(
            read_file(&directory_link.join("input"), 32, FileTrust::PublicMaterial),
            Err(SecureInputError::PathSecurity)
        );

        fs::remove_dir_all(root).expect("remove test root");
    }
}
