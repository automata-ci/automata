//! CLI session custody through the operating system's Secret Service.
//!
//! Session bearers are sent to `secret-tool` only over stdin. Searches use an
//! exact versioned attribute set, enumerate every unlocked match, and accept
//! exactly zero or one item. Secret output is bounded and zeroized. There is no
//! plaintext credential-file fallback.

use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_auth::session_credential::SessionCredential;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustix::fs::{self, FileType, FlockOperation, Mode, OFlags, fstat, mkdirat, openat};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    process::{ChildStdin, ChildStdout, Command},
    time::timeout,
};
use zeroize::Zeroizing;

const SECRET_TOOL_PATHS: [&str; 2] = ["/usr/bin/secret-tool", "/bin/secret-tool"];
const APPLICATION_ATTRIBUTE: &str = "application";
const APPLICATION_VALUE: &str = "automata-ci";
const SCHEMA_ATTRIBUTE: &str = "credential-schema";
const SCHEMA_VALUE: &str = "automata-ci.cli-session.v1";
const ACCOUNT_ATTRIBUTE: &str = "account-id";
const SERVER_ATTRIBUTE: &str = "server-origin";
const ITEM_LABEL_OPTION: &str = "--label=Automata CI CLI session";
const MAX_SEARCH_OUTPUT_BYTES: usize = 16 * 1_024;
const MAX_STORED_CREDENTIAL_BYTES: usize = 512;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
const LOCK_DIRECTORY: &str = "automata-ci";

#[async_trait]
pub(crate) trait CliCredentialStore: fmt::Debug + Send + Sync {
    async fn load(
        &self,
        server_origin: &str,
    ) -> Result<Option<SessionCredential>, CredentialStoreError>;

    async fn store(
        &self,
        server_origin: &str,
        credential: &SessionCredential,
    ) -> Result<(), CredentialStoreError>;

    async fn remove(&self, server_origin: &str) -> Result<(), CredentialStoreError>;
}

/// Linux Secret Service adapter used by the operator CLI.
///
/// A missing or ambiguous Secret Service is a hard failure. Deployment policy
/// must select a Secret Service implementation whose backing store meets the
/// installation's encrypted-at-rest requirements.
#[derive(Clone)]
pub(crate) struct SecretServiceCredentialStore {
    program: PathBuf,
    operation_timeout: Duration,
}

impl SecretServiceCredentialStore {
    pub(crate) fn discover() -> Result<Self, CredentialStoreError> {
        SECRET_TOOL_PATHS
            .iter()
            .map(Path::new)
            .find(|candidate| candidate.is_file())
            .map(|program| Self {
                program: program.to_path_buf(),
                operation_timeout: OPERATION_TIMEOUT,
            })
            .ok_or(CredentialStoreError::Unavailable)
    }

    #[cfg(test)]
    pub(crate) fn with_program(program: PathBuf, operation_timeout: Duration) -> Self {
        Self {
            program,
            operation_timeout,
        }
    }

    fn command(&self, operation: &str, options: &[&str], server_origin: &str) -> Command {
        let mut command = Command::new(&self.program);
        command
            .arg(operation)
            .args(options)
            .arg(APPLICATION_ATTRIBUTE)
            .arg(APPLICATION_VALUE)
            .arg(SCHEMA_ATTRIBUTE)
            .arg(SCHEMA_VALUE)
            .arg(ACCOUNT_ATTRIBUTE)
            .arg(account_id(server_origin))
            .arg(SERVER_ATTRIBUTE)
            .arg(server_origin)
            .env_clear()
            .env("LC_ALL", "C")
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for name in ["DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "HOME"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
    }

    async fn run(
        &self,
        operation: &str,
        options: &[&str],
        server_origin: &str,
        input: Option<&str>,
        capture_stdout: bool,
    ) -> Result<SecretToolOutput, CredentialStoreError> {
        let mut command = self.command(operation, options, server_origin);
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        if capture_stdout {
            command.stdout(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let operation = async {
            let ((), stdout, status) = tokio::try_join!(
                write_secret_input(stdin, input),
                read_bounded_output(stdout),
                child.wait(),
            )?;
            Ok::<_, std::io::Error>((status, stdout))
        };
        let result = timeout(self.operation_timeout, operation).await;
        let Ok(Ok((status, stdout))) = result else {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(CredentialStoreError::Unavailable);
        };
        Ok(SecretToolOutput { status, stdout })
    }

    async fn search(&self, server_origin: &str) -> Result<SearchResult, CredentialStoreError> {
        let output = self
            .run("search", &["--all", "--unlock"], server_origin, None, true)
            .await?;
        if !output.status.success() {
            return Err(CredentialStoreError::Unavailable);
        }
        parse_search_output(&output.stdout)
    }

    async fn lookup(&self, server_origin: &str) -> Result<SessionCredential, CredentialStoreError> {
        let output = self.run("lookup", &[], server_origin, None, true).await?;
        if !output.status.success() {
            return Err(CredentialStoreError::Unavailable);
        }
        parse_lookup_output(&output.stdout)
    }

    async fn load_exact(
        &self,
        server_origin: &str,
    ) -> Result<Option<SessionCredential>, CredentialStoreError> {
        let item = match self.search(server_origin).await? {
            SearchResult::Missing => return Ok(None),
            SearchResult::One(item) => item,
            SearchResult::Ambiguous => return Err(CredentialStoreError::InvalidCredential),
        };
        let credential = self.lookup(server_origin).await?;
        match self.search(server_origin).await? {
            SearchResult::One(current) if current == item => Ok(Some(credential)),
            SearchResult::Missing | SearchResult::One(_) | SearchResult::Ambiguous => {
                Err(CredentialStoreError::InvalidCredential)
            }
        }
    }

    async fn clear_all(&self, server_origin: &str) -> Result<(), CredentialStoreError> {
        let output = self.run("clear", &[], server_origin, None, false).await?;
        if !output.status.success() {
            return Err(CredentialStoreError::Unavailable);
        }
        match self.search(server_origin).await? {
            SearchResult::Missing => Ok(()),
            SearchResult::One(_) | SearchResult::Ambiguous => {
                Err(CredentialStoreError::InvalidCredential)
            }
        }
    }
}

impl fmt::Debug for SecretServiceCredentialStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretServiceCredentialStore")
            .field("program", &self.program)
            .field("operation_timeout", &self.operation_timeout)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

#[async_trait]
impl CliCredentialStore for SecretServiceCredentialStore {
    async fn load(
        &self,
        server_origin: &str,
    ) -> Result<Option<SessionCredential>, CredentialStoreError> {
        validate_origin_attribute(server_origin)?;
        self.load_exact(server_origin).await
    }

    async fn store(
        &self,
        server_origin: &str,
        credential: &SessionCredential,
    ) -> Result<(), CredentialStoreError> {
        validate_origin_attribute(server_origin)?;
        if !matches!(self.search(server_origin).await?, SearchResult::Missing) {
            return Err(CredentialStoreError::AlreadyExists);
        }
        let output = self
            .run(
                "store",
                &[ITEM_LABEL_OPTION],
                server_origin,
                Some(credential.expose_secret()),
                false,
            )
            .await?;
        if !output.status.success() {
            return Err(CredentialStoreError::Unavailable);
        }
        let verified = match self.load_exact(server_origin).await {
            Ok(Some(stored)) => bool::from(
                stored
                    .expose_secret()
                    .as_bytes()
                    .ct_eq(credential.expose_secret().as_bytes()),
            ),
            Ok(None) => false,
            Err(error) => {
                let _ = self.clear_all(server_origin).await;
                return Err(error);
            }
        };
        if verified {
            return Ok(());
        }
        let _ = self.clear_all(server_origin).await;
        Err(CredentialStoreError::InvalidCredential)
    }

    async fn remove(&self, server_origin: &str) -> Result<(), CredentialStoreError> {
        validate_origin_attribute(server_origin)?;
        match self.search(server_origin).await? {
            SearchResult::Missing => Ok(()),
            SearchResult::One(_) | SearchResult::Ambiguous => self.clear_all(server_origin).await,
        }
    }
}

async fn write_secret_input(
    mut stdin: Option<ChildStdin>,
    input: Option<&str>,
) -> Result<(), std::io::Error> {
    match (stdin.as_mut(), input) {
        (Some(stdin), Some(input)) => {
            stdin.write_all(input.as_bytes()).await?;
            stdin.shutdown().await
        }
        (None, None) => Ok(()),
        _ => Err(std::io::Error::other("invalid secret-tool stdin state")),
    }
}

async fn read_bounded_output(
    stdout: Option<ChildStdout>,
) -> Result<Zeroizing<Vec<u8>>, std::io::Error> {
    let Some(stdout) = stdout else {
        return Ok(Zeroizing::new(Vec::new()));
    };
    let mut output = Zeroizing::new(Vec::with_capacity(MAX_SEARCH_OUTPUT_BYTES + 1));
    stdout
        .take((MAX_SEARCH_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut output)
        .await?;
    if output.len() > MAX_SEARCH_OUTPUT_BYTES {
        return Err(std::io::Error::other(
            "secret-tool output exceeded its fixed limit",
        ));
    }
    Ok(output)
}

struct SecretToolOutput {
    status: ExitStatus,
    stdout: Zeroizing<Vec<u8>>,
}

enum SearchResult {
    Missing,
    One(String),
    Ambiguous,
}

fn parse_search_output(output: &[u8]) -> Result<SearchResult, CredentialStoreError> {
    let text = std::str::from_utf8(output).map_err(|_| CredentialStoreError::InvalidCredential)?;
    if output.is_empty() {
        return Ok(SearchResult::Missing);
    }
    let mut item = None;
    let mut item_count = 0_usize;
    let mut current_has_secret = false;
    for line in text.lines() {
        if let Some(path) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            if item_count > 0 && !current_has_secret {
                return Ok(SearchResult::Ambiguous);
            }
            if !valid_secret_service_item_path(path) {
                return Ok(SearchResult::Ambiguous);
            }
            item_count = item_count.saturating_add(1);
            current_has_secret = false;
            if item.is_none() {
                item = Some(path.to_owned());
            }
            continue;
        }
        if item_count == 0 || !valid_secret_service_search_field(line) {
            return Ok(SearchResult::Ambiguous);
        }
        if line.starts_with("secret = ") {
            if current_has_secret {
                return Ok(SearchResult::Ambiguous);
            }
            current_has_secret = true;
        }
    }
    match (item_count, current_has_secret, item) {
        (1, true, Some(item)) => Ok(SearchResult::One(item)),
        _ => Ok(SearchResult::Ambiguous),
    }
}

fn valid_secret_service_item_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 2_048
        && path.starts_with('/')
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_'))
}

fn valid_secret_service_search_field(line: &str) -> bool {
    if line.is_empty() || line.len() > 4_096 || line.bytes().any(|byte| byte.is_ascii_control()) {
        return false;
    }
    [
        "label = ",
        "secret = ",
        "created = ",
        "modified = ",
        "schema = ",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
        || line
            .strip_prefix("attribute.")
            .and_then(|field| field.split_once(" = "))
            .is_some_and(|(name, _)| {
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
}

fn parse_lookup_output(output: &[u8]) -> Result<SessionCredential, CredentialStoreError> {
    if output.is_empty()
        || output.len() > MAX_STORED_CREDENTIAL_BYTES
        || output.iter().any(u8::is_ascii_control)
    {
        return Err(CredentialStoreError::InvalidCredential);
    }
    let value = std::str::from_utf8(output).map_err(|_| CredentialStoreError::InvalidCredential)?;
    SessionCredential::from_raw(value).map_err(|_| CredentialStoreError::InvalidCredential)
}

fn account_id(server_origin: &str) -> String {
    let digest = Sha256::digest(server_origin.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn validate_origin_attribute(server_origin: &str) -> Result<(), CredentialStoreError> {
    if server_origin.is_empty()
        || server_origin.len() > 2_048
        || !server_origin.is_ascii()
        || server_origin.chars().any(char::is_control)
    {
        return Err(CredentialStoreError::InvalidServerOrigin);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialStoreError {
    Unavailable,
    InvalidServerOrigin,
    InvalidCredential,
    AlreadyExists,
}

impl fmt::Display for CredentialStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "the operating-system credential manager is unavailable",
            Self::InvalidServerOrigin => "the credential server origin is invalid",
            Self::InvalidCredential => "the stored CLI session is invalid or ambiguous",
            Self::AlreadyExists => "a CLI session already exists for this server",
        })
    }
}

impl Error for CredentialStoreError {}

/// Exact per-origin process lock held across local and remote session lifecycle.
pub(crate) struct CliAuthProcessLock {
    _file: OwnedFd,
}

impl CliAuthProcessLock {
    pub(crate) fn acquire(server_origin: &str) -> Result<Self, CliAuthLockError> {
        validate_origin_attribute(server_origin).map_err(|_| CliAuthLockError::Unavailable)?;
        let root = std::env::var_os("XDG_RUNTIME_DIR").ok_or(CliAuthLockError::Unavailable)?;
        Self::acquire_in(Path::new(&root), server_origin)
    }

    fn acquire_in(root: &Path, server_origin: &str) -> Result<Self, CliAuthLockError> {
        let root = open_absolute_directory(root)?;
        verify_private_directory(&root)?;
        match mkdirat(&root, LOCK_DIRECTORY, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(CliAuthLockError::Unavailable),
        }
        let directory = openat(
            &root,
            LOCK_DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| CliAuthLockError::Unavailable)?;
        verify_private_directory(&directory)?;
        let filename = format!("auth-{}.lock", account_id(server_origin));
        let file = openat(
            &directory,
            filename,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| CliAuthLockError::Unavailable)?;
        let metadata = fstat(&file).map_err(|_| CliAuthLockError::Unavailable)?;
        let current_user = rustix::process::getuid().as_raw();
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_uid != current_user
            || metadata.st_nlink != 1
            || metadata.st_mode & 0o077 != 0
        {
            return Err(CliAuthLockError::Unavailable);
        }
        fs::flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::AGAIN {
                CliAuthLockError::Busy
            } else {
                CliAuthLockError::Unavailable
            }
        })?;
        Ok(Self { _file: file })
    }
}

impl fmt::Debug for CliAuthProcessLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CliAuthProcessLock(..)")
    }
}

fn open_absolute_directory(path: &Path) -> Result<OwnedFd, CliAuthLockError> {
    if !path.is_absolute() {
        return Err(CliAuthLockError::Unavailable);
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut current =
        fs::open("/", flags, Mode::empty()).map_err(|_| CliAuthLockError::Unavailable)?;
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(component) if component != OsStr::new("") => {
                current = openat(&current, component, flags, Mode::empty())
                    .map_err(|_| CliAuthLockError::Unavailable)?;
            }
            _ => return Err(CliAuthLockError::Unavailable),
        }
    }
    Ok(current)
}

fn verify_private_directory(directory: &OwnedFd) -> Result<(), CliAuthLockError> {
    let metadata = fstat(directory).map_err(|_| CliAuthLockError::Unavailable)?;
    let current_user = rustix::process::getuid().as_raw();
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != current_user
        || metadata.st_mode & 0o077 != 0
    {
        return Err(CliAuthLockError::Unavailable);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CliAuthLockError {
    Busy,
    Unavailable,
}

impl fmt::Display for CliAuthLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Busy => "another CLI authentication operation is already running for this server",
            Self::Unavailable => "a secure CLI authentication process lock is unavailable",
        })
    }
}

impl Error for CliAuthLockError {}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt as _,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    const SESSION: &str = "v1~key-1~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn errors_and_debug_never_contain_credentials() {
        let store = SecretServiceCredentialStore::with_program(
            PathBuf::from("/nonexistent"),
            Duration::from_millis(10),
        );
        let debug = format!("{store:?}");
        assert!(debug.contains("[REDACTED]"));
        for error in [
            CredentialStoreError::Unavailable,
            CredentialStoreError::InvalidServerOrigin,
            CredentialStoreError::InvalidCredential,
            CredentialStoreError::AlreadyExists,
        ] {
            assert!(!error.to_string().contains("v1~"));
        }
    }

    #[test]
    fn secret_service_attributes_are_bounded_nonsecret_origins() {
        assert!(validate_origin_attribute("https://ci.example").is_ok());
        assert!(validate_origin_attribute("").is_err());
        assert!(validate_origin_attribute("https://ci.example\nsecret").is_err());
        assert!(validate_origin_attribute(&"x".repeat(2_049)).is_err());
        assert_eq!(account_id("https://ci.example").len(), 43);
    }

    #[test]
    fn search_results_distinguish_missing_single_and_ambiguous() {
        assert!(matches!(
            parse_search_output(b"").unwrap(),
            SearchResult::Missing
        ));
        let one = format!(
            "[/org/freedesktop/secrets/item/1]\nlabel = Automata CI CLI session\nsecret = {SESSION}\ncreated = 2026-01-01\nmodified = 2026-01-01\n"
        );
        assert!(matches!(
            parse_search_output(one.as_bytes()).unwrap(),
            SearchResult::One(_)
        ));
        let duplicate = format!("{one}{one}");
        assert!(matches!(
            parse_search_output(duplicate.as_bytes()).unwrap(),
            SearchResult::Ambiguous
        ));
        assert!(matches!(
            parse_search_output(b"secret-tool error").unwrap(),
            SearchResult::Ambiguous
        ));
        let injected = format!(
            "[/org/freedesktop/secrets/item/1]\nsecret = {SESSION}\nmanaged-secret-sentinel\n"
        );
        assert!(matches!(
            parse_search_output(injected.as_bytes()).unwrap(),
            SearchResult::Ambiguous
        ));
        assert!(parse_lookup_output(SESSION.as_bytes()).is_ok());
        assert_eq!(
            parse_lookup_output(format!("{SESSION}\nextra").as_bytes()).unwrap_err(),
            CredentialStoreError::InvalidCredential
        );
    }

    #[test]
    fn per_origin_lock_is_private_exclusive_and_reacquirable() {
        let root = std::env::temp_dir().join(format!(
            "automata-auth-lock-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let first = CliAuthProcessLock::acquire_in(&root, "https://ci.example").unwrap();
        assert_eq!(
            CliAuthProcessLock::acquire_in(&root, "https://ci.example").unwrap_err(),
            CliAuthLockError::Busy
        );
        let other = CliAuthProcessLock::acquire_in(&root, "https://other.example").unwrap();
        drop((first, other));
        let reacquired = CliAuthProcessLock::acquire_in(&root, "https://ci.example").unwrap();
        drop(reacquired);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn secret_tool_subprocess_uses_exact_unique_attributes_and_readback() {
        let root = test_directory("secret-tool-roundtrip");
        let state = root.join("state");
        std::fs::write(&state, b"0").unwrap();
        let account = account_id("https://ci.example");
        let script = format!(
            r#"#!/bin/sh
set -eu
[ "${{LC_ALL-}}" = C ]
operation=$1
shift
case "$operation" in
  search)
    [ "$1" = --all ] && [ "$2" = --unlock ]
    shift 2
    ;;
  store)
    [ "$1" = '--label=Automata CI CLI session' ]
    shift
    ;;
  lookup) ;;
  clear) ;;
  *) exit 90 ;;
esac
[ "$#" -eq 8 ]
[ "$1" = application ] && [ "$2" = automata-ci ]
[ "$3" = credential-schema ] && [ "$4" = automata-ci.cli-session.v1 ]
[ "$5" = account-id ] && [ "$6" = '{account}' ]
[ "$7" = server-origin ] && [ "$8" = https://ci.example ]
case "$operation" in
  search)
    if [ "$(/bin/cat '{state}')" = 1 ]; then
      printf '%s\n' '[/org/freedesktop/secrets/item/1]' 'label = Automata CI CLI session' 'secret = {SESSION}' 'created = 2026-01-01' 'modified = 2026-01-01'
    fi
    ;;
  store)
    value=
    IFS= read -r value || [ -n "$value" ]
    [ "$value" = '{SESSION}' ]
    printf 1 > '{state}'
    ;;
  lookup)
    [ "$(/bin/cat '{state}')" = 1 ] || exit 1
    printf '%s' '{SESSION}'
    ;;
  clear) printf 0 > '{state}' ;;
esac
"#,
            state = state.display(),
        );
        let program = write_test_program(&root, &script);
        let store = SecretServiceCredentialStore::with_program(program, Duration::from_secs(2));
        assert!(store.load("https://ci.example").await.unwrap().is_none());
        let credential = SessionCredential::from_raw(SESSION).unwrap();
        store
            .store("https://ci.example", &credential)
            .await
            .unwrap();
        let loaded = store.load("https://ci.example").await.unwrap().unwrap();
        assert!(bool::from(
            loaded.expose_secret().as_bytes().ct_eq(SESSION.as_bytes())
        ));
        assert_eq!(
            store.store("https://ci.example", &credential).await,
            Err(CredentialStoreError::AlreadyExists)
        );
        store.remove("https://ci.example").await.unwrap();
        assert!(store.load("https://ci.example").await.unwrap().is_none());
        drop((loaded, credential, store));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn secret_tool_failure_is_never_misreported_as_missing() {
        let root = test_directory("secret-tool-failure");
        let program = write_test_program(&root, "#!/bin/sh\nexit 1\n");
        let store = SecretServiceCredentialStore::with_program(program, Duration::from_secs(1));
        assert!(matches!(
            store.load("https://ci.example").await,
            Err(CredentialStoreError::Unavailable)
        ));
        drop(store);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn secret_tool_deadline_kills_and_reaps_a_stuck_operation() {
        let root = test_directory("secret-tool-timeout");
        let program = write_test_program(&root, "#!/bin/sh\nwhile :; do :; done\n");
        let store = SecretServiceCredentialStore::with_program(program, Duration::from_millis(20));
        let started = std::time::Instant::now();
        assert!(matches!(
            store.load("https://ci.example").await,
            Err(CredentialStoreError::Unavailable)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(store);
        std::fs::remove_dir_all(&root).unwrap();
    }

    fn test_directory(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "automata-{label}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn write_test_program(root: &Path, contents: &str) -> PathBuf {
        let program = root.join("secret-tool");
        std::fs::write(&program, contents.as_bytes()).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        program
    }
}
