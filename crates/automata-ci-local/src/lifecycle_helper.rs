//! Fixed in-image helpers consumed only by local lifecycle convergence.

use std::{
    fs::File,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    os::fd::OwnedFd,
    time::Duration,
};

use automata_ci_core::Sha256Digest;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, fstat, openat, renameat};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    LOCAL_CONTROL_READY_LISTEN, LOCAL_CONTROL_READY_MAXIMUM_RESPONSE_BYTES,
    LOCAL_CONTROL_READY_REQUEST, LOCAL_CONTROL_READY_RESPONSE_PREFIX,
    LOCAL_CONTROL_READY_RESPONSE_SUFFIX, LOCAL_CONTROL_READY_TIMEOUT_SECONDS,
    MAX_LOCAL_DESIRED_SPEC_BYTES,
    init::{LocalInitError, LocalInitErrorCode},
};

const DESIRED_ROOT: &str = "/run/automata-desired";
const DESIRED_FILE: &str = "desired.json";
const CAS_ROOT: &str = "/run/automata-lifecycle-cas";
pub(crate) const CAS_SCHEMA: &str = "automata.local/lifecycle-cas/v1";
pub(crate) const MAX_CAS_REQUEST_BYTES: usize = 512 * 1024;
pub(crate) const MAX_CAS_CONTENT_BYTES: usize = 256 * 1024;
/// Emits the exact sealed Desired bytes from the sole read-only mount.
pub fn read_desired() -> Result<(), LocalInitError> {
    let directory = open_exact_root(DESIRED_ROOT, 0, 0, 0o555)?;
    let bytes = read_exact_file(
        &directory,
        DESIRED_FILE,
        MAX_LOCAL_DESIRED_SPEC_BYTES,
        0,
        0,
        0o444,
    )?
    .ok_or_else(helper_failed)?;
    std::io::stdout()
        .lock()
        .write_all(&bytes)
        .map_err(|_| helper_failed())
}

/// Atomically commits one root-owned fixed generated file under an
/// expected-old-digest compare-and-swap contract.
pub fn write_cas() -> Result<(), LocalInitError> {
    let mut request_bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(u64::try_from(MAX_CAS_REQUEST_BYTES + 1).expect("request bound fits u64"))
        .read_to_end(&mut request_bytes)
        .map_err(|_| helper_failed())?;
    if request_bytes.is_empty() || request_bytes.len() > MAX_CAS_REQUEST_BYTES {
        return Err(helper_failed());
    }
    let mut request: CasRequest =
        serde_json::from_slice(&request_bytes).map_err(|_| helper_failed())?;
    if request.schema != CAS_SCHEMA || canonical_bytes(&request)? != request_bytes.as_slice() {
        return Err(helper_failed());
    }
    let encoded = Zeroizing::new(std::mem::take(&mut request.contents_base64));
    let contents = Zeroizing::new(
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| helper_failed())?,
    );
    if contents.is_empty()
        || contents.len() > MAX_CAS_CONTENT_BYTES
        || digest(&contents) != request.replacement_sha256
    {
        return Err(helper_failed());
    }
    let contract = request.target.root_contract();
    let directory = open_exact_root(CAS_ROOT, contract.0, contract.1, contract.2)?;
    compare_and_swap(
        &directory,
        request.target.file_name(),
        request.expected_sha256,
        request.replacement_sha256,
        &contents,
        contract.0,
        contract.1,
        contract.3,
    )
}

/// Checks the fixed in-container control-plane readiness endpoint.
pub fn check_ready() -> Result<(), LocalInitError> {
    let address = LOCAL_CONTROL_READY_LISTEN
        .parse::<SocketAddr>()
        .map_err(|_| helper_failed())?;
    let timeout = Duration::from_secs(LOCAL_CONTROL_READY_TIMEOUT_SECONDS);
    let mut stream = TcpStream::connect_timeout(&address, timeout).map_err(|_| helper_failed())?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .and_then(|()| stream.write_all(LOCAL_CONTROL_READY_REQUEST.as_bytes()))
        .map_err(|_| helper_failed())?;
    let mut response = Vec::new();
    stream
        .take(
            u64::try_from(LOCAL_CONTROL_READY_MAXIMUM_RESPONSE_BYTES + 1)
                .expect("response bound fits u64"),
        )
        .read_to_end(&mut response)
        .map_err(|_| helper_failed())?;
    if response.len() > LOCAL_CONTROL_READY_MAXIMUM_RESPONSE_BYTES
        || !response.starts_with(LOCAL_CONTROL_READY_RESPONSE_PREFIX.as_bytes())
        || !response.ends_with(LOCAL_CONTROL_READY_RESPONSE_SUFFIX.as_bytes())
    {
        return Err(helper_failed());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CasTarget {
    BootstrapRequest,
    BootstrapToken,
    RelayBinding,
    RunnerConfig,
    RunnerS3AccessKey,
    RunnerS3Ca,
    RunnerS3SecretKey,
    RunnerSpoolKey,
}

impl CasTarget {
    pub(crate) const fn slug(self) -> &'static str {
        match self {
            Self::BootstrapRequest => "bootstrap-request",
            Self::BootstrapToken => "bootstrap-token",
            Self::RelayBinding => "relay-binding",
            Self::RunnerConfig => "runner-config",
            Self::RunnerS3AccessKey => "runner-s3-access-key",
            Self::RunnerS3Ca => "runner-s3-ca",
            Self::RunnerS3SecretKey => "runner-s3-secret-key",
            Self::RunnerSpoolKey => "runner-spool-key",
        }
    }

    const fn file_name(self) -> &'static str {
        match self {
            Self::BootstrapRequest => "request.json",
            Self::BootstrapToken => "runner-enrollment-token",
            Self::RelayBinding => "binding.json",
            Self::RunnerConfig => "runner.json",
            Self::RunnerS3AccessKey => "s3-access-key",
            Self::RunnerS3Ca => "s3-ca.pem",
            Self::RunnerS3SecretKey => "s3-secret-key",
            Self::RunnerSpoolKey => "spool-key-v1.hex",
        }
    }

    const fn root_contract(self) -> (u32, u32, u32, u32) {
        match self {
            Self::RelayBinding | Self::RunnerConfig => (0, 0, 0o555, 0o444),
            Self::BootstrapRequest
            | Self::BootstrapToken
            | Self::RunnerS3AccessKey
            | Self::RunnerS3Ca
            | Self::RunnerS3SecretKey
            | Self::RunnerSpoolKey => (65_532, 65_532, 0o700, 0o400),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CasRequest {
    schema: String,
    target: CasTarget,
    expected_sha256: Option<Sha256Digest>,
    replacement_sha256: Sha256Digest,
    contents_base64: String,
}

impl CasRequest {
    pub(crate) fn new(
        target: CasTarget,
        expected_sha256: Option<Sha256Digest>,
        contents: &[u8],
    ) -> Result<Self, LocalInitError> {
        if contents.is_empty() || contents.len() > MAX_CAS_CONTENT_BYTES {
            return Err(helper_failed());
        }
        Ok(Self {
            schema: CAS_SCHEMA.to_owned(),
            target,
            expected_sha256,
            replacement_sha256: digest(contents),
            contents_base64: STANDARD.encode(contents),
        })
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, LocalInitError> {
        canonical_bytes(self)
    }

    pub(crate) const fn target(&self) -> CasTarget {
        self.target
    }

    pub(crate) const fn replacement_sha256(&self) -> Sha256Digest {
        self.replacement_sha256
    }

    pub(crate) const fn expected_sha256(&self) -> Option<Sha256Digest> {
        self.expected_sha256
    }
}

impl Drop for CasRequest {
    fn drop(&mut self) {
        self.contents_base64.zeroize();
    }
}

fn compare_and_swap(
    directory: &OwnedFd,
    name: &str,
    expected: Option<Sha256Digest>,
    replacement: Sha256Digest,
    contents: &[u8],
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), LocalInitError> {
    let temporary = format!(".{name}.automata-write");
    let final_bytes = read_exact_file(directory, name, MAX_CAS_CONTENT_BYTES, uid, gid, mode)?;
    let mut staged =
        observe_staged_file(directory, &temporary, MAX_CAS_CONTENT_BYTES, uid, gid, mode)?;
    let final_digest = final_bytes.as_deref().map(digest);
    let staged_digest = staged.bytes().map(digest);

    if final_digest == Some(replacement) {
        if staged_digest.is_some_and(|digest| digest != replacement) {
            return Err(helper_failed());
        }
        if staged_digest == Some(replacement) {
            if staged.is_in_progress() {
                return Err(helper_failed());
            }
            remove_exact_stage(directory, &temporary, &staged, uid, gid, mode)?;
        }
        return verify_cas_postcondition(
            directory,
            name,
            &temporary,
            replacement,
            contents,
            uid,
            gid,
            mode,
        );
    }
    if final_digest != expected {
        return Err(helper_failed());
    }
    match &mut staged {
        StagedFile::Complete { bytes, .. } if digest(bytes) == replacement => {}
        StagedFile::Complete { .. } => return Err(helper_failed()),
        StagedFile::InProgress { bytes, .. } if bytes.as_slice() == contents => {
            normalize_staged_replacement(directory, &temporary, &mut staged, uid, gid, mode)?;
        }
        StagedFile::InProgress { .. } => {
            remove_exact_stage(directory, &temporary, &staged, uid, gid, mode)?;
            stage_replacement(directory, &temporary, contents, mode)?;
        }
        StagedFile::Absent => stage_replacement(directory, &temporary, contents, mode)?,
    }
    if read_exact_file(directory, name, MAX_CAS_CONTENT_BYTES, uid, gid, mode)?
        .as_deref()
        .map(digest)
        != expected
    {
        return Err(helper_failed());
    }
    renameat(directory, &temporary, directory, name).map_err(|_| helper_failed())?;
    fs::fsync(directory).map_err(|_| helper_failed())?;
    verify_cas_postcondition(
        directory,
        name,
        &temporary,
        replacement,
        contents,
        uid,
        gid,
        mode,
    )
}

enum StagedFile {
    Absent,
    Complete {
        file: File,
        metadata: rustix::fs::Stat,
        bytes: Vec<u8>,
    },
    InProgress {
        file: File,
        metadata: rustix::fs::Stat,
        bytes: Vec<u8>,
    },
}

impl StagedFile {
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Absent => None,
            Self::Complete { bytes, .. } | Self::InProgress { bytes, .. } => Some(bytes),
        }
    }

    const fn is_in_progress(&self) -> bool {
        matches!(self, Self::InProgress { .. })
    }
}

fn observe_staged_file(
    directory: &OwnedFd,
    name: &str,
    maximum: usize,
    expected_uid: u32,
    expected_gid: u32,
    final_mode: u32,
) -> Result<StagedFile, LocalInitError> {
    let descriptor = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(StagedFile::Absent),
        Err(_) => return Err(helper_failed()),
    };
    let before = fstat(&descriptor).map_err(|_| helper_failed())?;
    let size = usize::try_from(before.st_size).map_err(|_| helper_failed())?;
    let mode = before.st_mode & 0o7777;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_nlink != 1
        || before.st_uid != expected_uid
        || before.st_gid != expected_gid
        || (mode != 0o600 && mode != final_mode)
        || size > maximum
        || (mode == final_mode && size == 0)
    {
        return Err(helper_failed());
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(size);
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(maximum + 1).expect("file bound fits u64"))
        .read_to_end(&mut bytes)
        .map_err(|_| helper_failed())?;
    let after = fstat(&file).map_err(|_| helper_failed())?;
    if bytes.len() != size || !same_file(&before, &after) {
        return Err(helper_failed());
    }
    if mode == final_mode {
        Ok(StagedFile::Complete {
            file,
            metadata: after,
            bytes,
        })
    } else {
        Ok(StagedFile::InProgress {
            file,
            metadata: after,
            bytes,
        })
    }
}

fn remove_exact_stage(
    directory: &OwnedFd,
    name: &str,
    expected: &StagedFile,
    uid: u32,
    gid: u32,
    final_mode: u32,
) -> Result<(), LocalInitError> {
    let observed =
        observe_staged_file(directory, name, MAX_CAS_CONTENT_BYTES, uid, gid, final_mode)?;
    if !same_staged_file(expected, &observed) {
        return Err(helper_failed());
    }
    fs::unlinkat(directory, name, AtFlags::empty())
        .and_then(|()| fs::fsync(directory))
        .map_err(|_| helper_failed())?;
    if !matches!(
        observe_staged_file(directory, name, MAX_CAS_CONTENT_BYTES, uid, gid, final_mode)?,
        StagedFile::Absent
    ) {
        return Err(helper_failed());
    }
    Ok(())
}

fn normalize_staged_replacement(
    directory: &OwnedFd,
    name: &str,
    staged: &mut StagedFile,
    uid: u32,
    gid: u32,
    final_mode: u32,
) -> Result<(), LocalInitError> {
    let (file, metadata, bytes) = match staged {
        StagedFile::InProgress {
            file,
            metadata,
            bytes,
        } => (file, metadata, bytes),
        StagedFile::Absent | StagedFile::Complete { .. } => return Err(helper_failed()),
    };
    if !same_file(metadata, &fstat(&*file).map_err(|_| helper_failed())?) {
        return Err(helper_failed());
    }
    fs::fchmod(&*file, Mode::from_raw_mode(final_mode)).map_err(|_| helper_failed())?;
    file.sync_all().map_err(|_| helper_failed())?;
    fs::fsync(directory).map_err(|_| helper_failed())?;
    let normalized =
        observe_staged_file(directory, name, MAX_CAS_CONTENT_BYTES, uid, gid, final_mode)?;
    let (normalized_metadata, normalized_bytes) = match &normalized {
        StagedFile::Complete {
            metadata, bytes, ..
        } => (metadata, bytes),
        StagedFile::Absent | StagedFile::InProgress { .. } => return Err(helper_failed()),
    };
    if metadata.st_dev != normalized_metadata.st_dev
        || metadata.st_ino != normalized_metadata.st_ino
        || metadata.st_nlink != normalized_metadata.st_nlink
        || metadata.st_uid != normalized_metadata.st_uid
        || metadata.st_gid != normalized_metadata.st_gid
        || bytes != normalized_bytes
    {
        return Err(helper_failed());
    }
    *staged = normalized;
    Ok(())
}

fn same_staged_file(expected: &StagedFile, actual: &StagedFile) -> bool {
    match (expected, actual) {
        (StagedFile::Absent, StagedFile::Absent) => true,
        (
            StagedFile::Complete {
                file: expected_file,
                metadata: expected_metadata,
                bytes: expected_bytes,
            },
            StagedFile::Complete {
                file: actual_file,
                metadata: actual_metadata,
                bytes: actual_bytes,
            },
        )
        | (
            StagedFile::InProgress {
                file: expected_file,
                metadata: expected_metadata,
                bytes: expected_bytes,
            },
            StagedFile::InProgress {
                file: actual_file,
                metadata: actual_metadata,
                bytes: actual_bytes,
            },
        ) => {
            same_file(expected_metadata, actual_metadata)
                && fstat(expected_file).is_ok_and(|current| same_file(expected_metadata, &current))
                && fstat(actual_file).is_ok_and(|current| same_file(actual_metadata, &current))
                && expected_bytes == actual_bytes
        }
        _ => false,
    }
}

fn stage_replacement(
    directory: &OwnedFd,
    temporary: &str,
    contents: &[u8],
    mode: u32,
) -> Result<(), LocalInitError> {
    let descriptor = openat(
        directory,
        temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| helper_failed())?;
    let mut file = File::from(descriptor);
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|_| helper_failed())?;
    fs::fchmod(&file, Mode::from_raw_mode(mode)).map_err(|_| helper_failed())?;
    file.sync_all().map_err(|_| helper_failed())?;
    drop(file);
    fs::fsync(directory).map_err(|_| helper_failed())
}

fn verify_cas_postcondition(
    directory: &OwnedFd,
    name: &str,
    temporary: &str,
    replacement: Sha256Digest,
    contents: &[u8],
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), LocalInitError> {
    let actual = read_exact_file(directory, name, MAX_CAS_CONTENT_BYTES, uid, gid, mode)?
        .ok_or_else(helper_failed)?;
    if actual != contents
        || digest(&actual) != replacement
        || read_exact_file(directory, temporary, MAX_CAS_CONTENT_BYTES, uid, gid, mode)?.is_some()
    {
        return Err(helper_failed());
    }
    Ok(())
}

fn open_exact_root(
    path: &str,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<OwnedFd, LocalInitError> {
    let directory = fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| helper_failed())?;
    let metadata = fstat(&directory).map_err(|_| helper_failed())?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != expected_uid
        || metadata.st_gid != expected_gid
        || metadata.st_mode & 0o7777 != expected_mode
    {
        return Err(helper_failed());
    }
    Ok(directory)
}

fn read_exact_file(
    directory: &OwnedFd,
    name: &str,
    maximum: usize,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<Option<Vec<u8>>, LocalInitError> {
    let descriptor = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(helper_failed()),
    };
    let before = fstat(&descriptor).map_err(|_| helper_failed())?;
    let size = usize::try_from(before.st_size).map_err(|_| helper_failed())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_nlink != 1
        || before.st_uid != expected_uid
        || before.st_gid != expected_gid
        || before.st_mode & 0o7777 != expected_mode
        || size == 0
        || size > maximum
    {
        return Err(helper_failed());
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(size);
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(maximum + 1).expect("file bound fits u64"))
        .read_to_end(&mut bytes)
        .map_err(|_| helper_failed())?;
    let after = fstat(&file).map_err(|_| helper_failed())?;
    if bytes.len() != size || !same_file(&before, &after) {
        return Err(helper_failed());
    }
    Ok(Some(bytes))
}

fn same_file(before: &rustix::fs::Stat, after: &rustix::fs::Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_nlink == after.st_nlink
        && before.st_size == after.st_size
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_mode == after.st_mode
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, LocalInitError> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| helper_failed())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn helper_failed() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::MaterializationFailed)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self as std_fs, OpenOptions},
        io::Write as _,
        os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use rustix::process::{getegid, geteuid};

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    const FINAL_NAME: &str = "runner.json";
    const STAGED_NAME: &str = ".runner.json.automata-write";
    const FINAL_MODE: u32 = 0o400;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(2)
                .expect("crate is inside the workspace");
            let scratch = workspace.join("target/task-tmp/automata-ci-local");
            std_fs::create_dir_all(&scratch).unwrap();
            let path = scratch.join(format!(
                "automata-ci-local-cas-test-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            std_fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn descriptor(&self) -> OwnedFd {
            fs::open(
                &self.0,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .unwrap()
        }

        fn write(&self, name: &str, bytes: &[u8], mode: u32) {
            let path = self.0.join(name);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
            std_fs::set_permissions(path, std_fs::Permissions::from_mode(mode)).unwrap();
            file.sync_all().unwrap();
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            std_fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[derive(Clone, Copy)]
    enum CrashBoundary {
        StageCreated,
        PartialWrite,
        DataFsync,
        Chmod,
        Rename,
        AppliedResponseLost,
    }

    #[test]
    fn every_safe_cas_crash_boundary_reconciles_to_the_exact_replacement() {
        let replacement = b"canonical replacement\n";
        for boundary in [
            CrashBoundary::StageCreated,
            CrashBoundary::PartialWrite,
            CrashBoundary::DataFsync,
            CrashBoundary::Chmod,
            CrashBoundary::Rename,
            CrashBoundary::AppliedResponseLost,
        ] {
            let directory = TestDirectory::new();
            let descriptor = directory.descriptor();
            match boundary {
                CrashBoundary::StageCreated => directory.write(STAGED_NAME, b"", 0o600),
                CrashBoundary::PartialWrite => {
                    directory.write(STAGED_NAME, b"canonical", 0o600);
                }
                CrashBoundary::DataFsync => directory.write(STAGED_NAME, replacement, 0o600),
                CrashBoundary::Chmod => directory.write(STAGED_NAME, replacement, FINAL_MODE),
                CrashBoundary::Rename => directory.write(FINAL_NAME, replacement, FINAL_MODE),
                CrashBoundary::AppliedResponseLost => {
                    compare_and_swap(
                        &descriptor,
                        FINAL_NAME,
                        None,
                        digest(replacement),
                        replacement,
                        geteuid().as_raw(),
                        getegid().as_raw(),
                        FINAL_MODE,
                    )
                    .unwrap();
                }
            }

            compare_and_swap(
                &descriptor,
                FINAL_NAME,
                None,
                digest(replacement),
                replacement,
                geteuid().as_raw(),
                getegid().as_raw(),
                FINAL_MODE,
            )
            .unwrap();
            assert_eq!(
                std_fs::read(directory.0.join(FINAL_NAME)).unwrap(),
                replacement
            );
            assert_eq!(
                std_fs::metadata(directory.0.join(FINAL_NAME))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                FINAL_MODE
            );
            assert!(!directory.0.join(STAGED_NAME).exists());
        }
    }

    #[test]
    fn unsafe_or_finalized_wrong_staging_evidence_is_never_removed() {
        for mode in [0o644, FINAL_MODE] {
            let directory = TestDirectory::new();
            directory.write(STAGED_NAME, b"different bytes\n", mode);
            let descriptor = directory.descriptor();
            assert_eq!(
                compare_and_swap(
                    &descriptor,
                    FINAL_NAME,
                    None,
                    digest(b"replacement\n"),
                    b"replacement\n",
                    geteuid().as_raw(),
                    getegid().as_raw(),
                    FINAL_MODE,
                )
                .unwrap_err()
                .code(),
                LocalInitErrorCode::MaterializationFailed
            );
            assert_eq!(
                std_fs::read(directory.0.join(STAGED_NAME)).unwrap(),
                b"different bytes\n"
            );
            assert!(!directory.0.join(FINAL_NAME).exists());
        }
    }
}
