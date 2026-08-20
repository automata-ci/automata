#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Versioned, framed transport used to keep command arguments and environment
//! values out of Kubernetes Pod specifications, exec request URLs, and
//! Windows container-runtime command lines.

use std::{collections::BTreeMap, fmt, io, path::Path};

#[cfg(unix)]
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};
#[cfg(target_os = "linux")]
use std::{
    fs::File,
    io::{Read as _, Seek as _, Write as _},
    sync::atomic::{AtomicBool, Ordering},
};
#[cfg(any(unix, windows))]
use std::{process::Stdio, time::Duration};

#[cfg(target_os = "linux")]
use std::os::{
    linux::net::SocketAddrExt as _,
    unix::net::{
        SocketAddr as StdSocketAddr, UnixListener as StdUnixListener, UnixStream as StdUnixStream,
    },
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
#[cfg(target_os = "linux")]
use rustix::{
    fd::OwnedFd,
    fs::{
        self as unix_fs, AtFlags, FileType, Mode, OFlags, RenameFlags, StatVfsMountFlags, fstat,
        open, openat, renameat_with, unlinkat,
    },
    io::Errno,
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use sha2::{Digest as _, Sha256};
use thiserror::Error;
#[cfg(any(unix, windows))]
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::mpsc,
};
#[cfg(unix)]
use tokio::{
    net::{UnixListener, UnixStream},
    sync::watch,
    task::JoinSet,
};

/// Current guest protocol version.
///
/// Version 3 adds the one-shot standard-I/O probe and the optional
/// per-execution process-limit field used by Hyper-V-isolated Windows
/// containers. Earlier versions are rejected instead of being interpreted as
/// the current wire contract.
pub const GUEST_PROTOCOL_VERSION: u16 = 3;
/// Maximum encoded request or response frame.
pub const MAX_GUEST_FRAME_BYTES: usize = 32 * 1024 * 1024;
#[cfg(any(unix, windows))]
const OUTPUT_CHUNK_BYTES: usize = 16 * 1024;
#[cfg(any(unix, windows))]
const MAX_OUTPUT_DATA_RECORDS: usize = 65_534;
#[cfg(any(unix, windows))]
const MAX_OPERATION_ID_BYTES: usize = 128;
#[cfg(any(unix, windows))]
const MAX_TARGET_PATH_BYTES: usize = 4_096;
#[cfg(any(unix, windows))]
const MAX_EXECUTION_ARGUMENTS: usize = 4_096;
#[cfg(any(unix, windows))]
const MAX_EXECUTION_ARGV_BYTES: usize = 1024 * 1024;
#[cfg(any(unix, windows))]
const MAX_ENVIRONMENT_VARIABLES: usize = 1_024;
#[cfg(any(unix, windows))]
const MAX_ENVIRONMENT_NAME_BYTES: usize = 128;
#[cfg(any(unix, windows))]
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 1024 * 1024;
#[cfg(any(unix, windows))]
const MAX_ENVIRONMENT_BYTES: usize = 4 * 1024 * 1024;
#[cfg(any(unix, windows))]
const MAX_COMMAND_TIMEOUT_MILLIS: u64 = 24 * 60 * 60 * 1_000;
#[cfg(any(unix, windows))]
const MAX_EXECUTION_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
#[cfg(windows)]
const MAX_PROCESS_LIMIT: u32 = 1_000_000;
#[cfg(unix)]
const MAX_REPLAY_ENTRIES: usize = 256;
#[cfg(unix)]
const MAX_REPLAY_BYTES: usize = 64 * 1024 * 1024;

/// Largest guest executable admitted by the protected local bootstrap contract.
#[cfg(target_os = "linux")]
pub const MAX_LOCAL_GUEST_BINARY_BYTES: u64 = 24 * 1024 * 1024;
/// Exact tmpfs byte ceiling required by the protected local bootstrap contract.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_TMPFS_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(target_os = "linux")]
const LOCAL_CONTROL_TMPFS_MINIMUM_HEADROOM_BYTES: u64 = 8 * 1024 * 1024;
#[cfg(target_os = "linux")]
const _: () = assert!(
    LOCAL_CONTROL_TMPFS_BYTES
        >= MAX_LOCAL_GUEST_BINARY_BYTES * 2 + LOCAL_CONTROL_TMPFS_MINIMUM_HEADROOM_BYTES
);
/// Initial mode of the sealer-owned protected-control tmpfs mount.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_DIRECTORY_MODE_INITIAL: u32 = 0o733;
/// Final mode of the sealed protected-control directory.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_DIRECTORY_MODE_SEALED: u32 = 0o510;
/// Exact mode of the immutable bootstrap seed.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_SEED_MODE: u32 = 0o555;
/// Private construction mode used before the bootstrap seed is published.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_SEED_STAGE_MODE: u32 = 0o600;
/// Exact mode of the sealed protected client.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_CLIENT_MODE: u32 = 0o550;
/// Read-only staging mode used before the protected client is sealed.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_CLIENT_MODE_STAGED: u32 = 0o554;
#[cfg(target_os = "linux")]
const LOCAL_CONTROL_TMPFS_MAGIC: i64 = 0x0102_1994;
#[cfg(target_os = "linux")]
static LOCAL_EXECUTION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[cfg(target_os = "linux")]
const LOCAL_STAGE_REQUEST: &[u8] = b"\xff\xff\xff\xffautomata-local-client-stage-v1";
#[cfg(target_os = "linux")]
const LOCAL_STAGE_ACKNOWLEDGEMENT: &[u8] = b"automata-local-client-stage-ok-v1";
#[cfg(target_os = "linux")]
const LOCAL_SEAL_REQUEST: &[u8] = b"automata-local-client-seal-v1";
#[cfg(target_os = "linux")]
const LOCAL_SEAL_ACKNOWLEDGEMENT: &[u8] = b"automata-local-client-ready-v1";
#[cfg(target_os = "linux")]
const LOCAL_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const MAX_LOCAL_ID_MAP_BYTES: usize = 256;

/// Fixed Linux abstract socket used by the evaluation-only local broker.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_SOCKET: &str = "@automata-ci-control-v1";
/// Fixed tmpfs mount protecting the local broker client from the root job.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_DIRECTORY: &str = "/automata-control";
/// One-shot local broker seed executable, present only during startup.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_SEED: &str = "/automata-control/.seed";
/// Sealed local broker client executable used for all live operations.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_CLIENT: &str = "/automata-control/automata-ci-sandbox-guest";
/// Dedicated UID accepted by the Linux local broker.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_UID: u32 = 65_532;
/// Dedicated GID accepted by the Linux local broker.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_GID: u32 = 65_532;
/// One-shot UID that owns and seals the Linux local control tmpfs.
#[cfg(target_os = "linux")]
pub const LOCAL_CONTROL_SEAL_UID: u32 = 65_533;

/// One operation sent through anonymous stdin to the sandbox guest.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestRequest {
    /// Verifies that the exact guest executable understands this protocol.
    Probe {
        /// Protocol version selected by the caller.
        protocol: u16,
        /// Idempotent operation identifier.
        operation_id: String,
    },
    /// Proves the exact guest agent and sealed template before job traffic.
    Hello {
        /// Protocol version selected by the caller.
        protocol: u16,
        /// Idempotent operation identifier.
        operation_id: String,
        /// Fresh caller nonce returned verbatim by the guest.
        nonce: String,
    },
    /// Applies the hard process-count ceiling before any workflow command.
    Configure {
        /// Protocol version selected by the caller.
        protocol: u16,
        /// Idempotent operation identifier.
        operation_id: String,
        /// Hard per-UID process ceiling inherited by job commands.
        process_limit: u32,
    },
    /// Execute one literal argv with an ephemeral environment.
    Exec {
        /// Protocol version selected by the caller.
        protocol: u16,
        /// Idempotent operation identifier.
        operation_id: String,
        /// Absolute program path.
        program: String,
        /// Literal arguments excluding the program.
        arguments: Vec<String>,
        /// Complete process environment; values can be secret.
        environment: BTreeMap<String, String>,
        /// Absolute working directory.
        working_directory: String,
        /// Positive command deadline.
        timeout_millis: u64,
        /// Aggregate stdout/stderr byte limit.
        output_limit: usize,
        /// Optional whole-command-tree process ceiling.
        ///
        /// Windows Hyper-V containers require this value and enforce it with a
        /// nested Job Object. Unix guests reject it because their process limit
        /// is configured at guest-service admission instead.
        process_limit: Option<u32>,
    },
    /// Write one bounded file inside the sandbox.
    WriteFile {
        /// Protocol version selected by the caller.
        protocol: u16,
        /// Idempotent operation identifier.
        operation_id: String,
        /// Absolute destination path.
        path: String,
        /// Base64-encoded file content.
        content_base64: String,
    },
    /// Read one bounded file inside the sandbox.
    ReadFile {
        /// Protocol version selected by the caller.
        protocol: u16,
        /// Idempotent operation identifier.
        operation_id: String,
        /// Absolute source path.
        path: String,
        /// Maximum returned bytes.
        byte_limit: usize,
    },
}

impl fmt::Debug for GuestRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Probe {
                protocol,
                operation_id,
            } => formatter
                .debug_struct("GuestRequest::Probe")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .finish(),
            Self::Hello {
                protocol,
                operation_id,
                ..
            } => formatter
                .debug_struct("GuestRequest::Hello")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .field("nonce", &"[REDACTED]")
                .finish(),
            Self::Configure {
                protocol,
                operation_id,
                process_limit,
            } => formatter
                .debug_struct("GuestRequest::Configure")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .field("process_limit", process_limit)
                .finish(),
            Self::Exec {
                protocol,
                operation_id,
                arguments,
                environment,
                process_limit,
                ..
            } => formatter
                .debug_struct("GuestRequest::Exec")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .field("argument_count", &arguments.len())
                .field("environment_count", &environment.len())
                .field("process_limit", process_limit)
                .field("payload", &"[REDACTED]")
                .finish(),
            Self::WriteFile {
                protocol,
                operation_id,
                content_base64,
                ..
            } => formatter
                .debug_struct("GuestRequest::WriteFile")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .field("encoded_bytes", &content_base64.len())
                .field("payload", &"[REDACTED]")
                .finish(),
            Self::ReadFile {
                protocol,
                operation_id,
                byte_limit,
                ..
            } => formatter
                .debug_struct("GuestRequest::ReadFile")
                .field("protocol", protocol)
                .field("operation_id", operation_id)
                .field("byte_limit", byte_limit)
                .field("path", &"[REDACTED]")
                .finish(),
        }
    }
}

#[cfg(any(unix, windows))]
impl GuestRequest {
    fn protocol(&self) -> u16 {
        match self {
            Self::Probe { protocol, .. }
            | Self::Hello { protocol, .. }
            | Self::Configure { protocol, .. }
            | Self::Exec { protocol, .. }
            | Self::WriteFile { protocol, .. }
            | Self::ReadFile { protocol, .. } => *protocol,
        }
    }

    fn operation_id(&self) -> &str {
        match self {
            Self::Probe { operation_id, .. }
            | Self::Hello { operation_id, .. }
            | Self::Configure { operation_id, .. }
            | Self::Exec { operation_id, .. }
            | Self::WriteFile { operation_id, .. }
            | Self::ReadFile { operation_id, .. } => operation_id,
        }
    }
}

/// Process pipe carried by one ordered output record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestOutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// One ordered data or end-of-stream observation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuestOutputRecord {
    stream: GuestOutputStream,
    data_base64: String,
    end_of_stream: bool,
}

impl fmt::Debug for GuestOutputRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestOutputRecord")
            .field("stream", &self.stream)
            .field("encoded_bytes", &self.data_base64.len())
            .field("data", &"[REDACTED]")
            .field("end_of_stream", &self.end_of_stream)
            .finish()
    }
}

impl GuestOutputRecord {
    /// Returns the observed pipe.
    pub const fn stream(&self) -> GuestOutputStream {
        self.stream
    }

    /// Decodes the record payload.
    ///
    /// # Errors
    ///
    /// Returns [`GuestProtocolError::InvalidFrame`] for invalid base64.
    pub fn data(&self) -> Result<Vec<u8>, GuestProtocolError> {
        BASE64
            .decode(&self.data_base64)
            .map_err(|_| GuestProtocolError::InvalidFrame)
    }

    /// Returns whether this closes the selected pipe.
    pub const fn is_end_of_stream(&self) -> bool {
        self.end_of_stream
    }
}

/// Sanitized command termination returned by the guest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "code", rename_all = "snake_case")]
pub enum GuestTermination {
    /// Process exited with a platform status.
    Exited(i32),
    /// Process ended because of a signal.
    Signalled,
    /// Guest killed the process at its deadline.
    TimedOut,
}

/// Bounded response returned through the Kubernetes exec stream.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestResponse {
    /// The guest executable accepted the exact protocol version.
    Ready {
        /// Guest protocol version.
        protocol: u16,
    },
    /// Guest identity and nonce proof returned before job operations.
    Hello {
        /// Guest protocol version.
        protocol: u16,
        /// Fresh caller nonce.
        nonce: String,
        /// Exact admitted environment-profile identifier.
        profile_id: String,
        /// SHA-256 of the installed guest-agent executable.
        guest_agent_sha256: String,
        /// macOS product version verified by the guest agent at startup.
        macos_version: String,
        /// macOS build identifier verified by the guest agent at startup.
        macos_build: String,
        /// Guest architecture verified by the guest agent at startup.
        architecture: String,
        /// Effective UID used for workflow commands.
        job_uid: u32,
        /// Effective GID used for workflow commands.
        job_gid: u32,
        /// Hard per-UID process ceiling baked into the guest service.
        process_limit: u32,
    },
    /// Guest resource configuration completed.
    Configured {
        /// Guest protocol version.
        protocol: u16,
    },
    /// Command completed or was terminated by policy.
    Exec {
        /// Guest protocol version.
        protocol: u16,
        /// Sanitized process termination.
        termination: GuestTermination,
        /// Cross-pipe output observations.
        records: Vec<GuestOutputRecord>,
        /// Whether output exceeded the caller's bound.
        truncated: bool,
    },
    /// A file write completed.
    WriteFile {
        /// Guest protocol version.
        protocol: u16,
    },
    /// A file read completed.
    ReadFile {
        /// Guest protocol version.
        protocol: u16,
        /// Base64-encoded content.
        content_base64: String,
    },
    /// The request was rejected without returning sensitive diagnostics.
    Rejected {
        /// Guest protocol version.
        protocol: u16,
        /// Stable rejection category.
        kind: GuestRejection,
    },
}

impl GuestResponse {
    /// Returns the protocol version carried by this response.
    #[must_use]
    pub const fn protocol(&self) -> u16 {
        match self {
            Self::Ready { protocol }
            | Self::Hello { protocol, .. }
            | Self::Configured { protocol }
            | Self::Exec { protocol, .. }
            | Self::WriteFile { protocol }
            | Self::ReadFile { protocol, .. }
            | Self::Rejected { protocol, .. } => *protocol,
        }
    }
}

impl fmt::Debug for GuestResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready { protocol } => formatter
                .debug_struct("GuestResponse::Ready")
                .field("protocol", protocol)
                .finish(),
            Self::Hello {
                protocol,
                profile_id,
                ..
            } => formatter
                .debug_struct("GuestResponse::Hello")
                .field("protocol", protocol)
                .field("profile_id", profile_id)
                .field("attestation", &"[REDACTED]")
                .finish(),
            Self::Configured { protocol } => formatter
                .debug_struct("GuestResponse::Configured")
                .field("protocol", protocol)
                .finish(),
            Self::Exec {
                protocol,
                termination,
                records,
                truncated,
            } => formatter
                .debug_struct("GuestResponse::Exec")
                .field("protocol", protocol)
                .field("termination", termination)
                .field("record_count", &records.len())
                .field("output", &"[REDACTED]")
                .field("truncated", truncated)
                .finish(),
            Self::WriteFile { protocol } => formatter
                .debug_struct("GuestResponse::WriteFile")
                .field("protocol", protocol)
                .finish(),
            Self::ReadFile {
                protocol,
                content_base64,
            } => formatter
                .debug_struct("GuestResponse::ReadFile")
                .field("protocol", protocol)
                .field("encoded_bytes", &content_base64.len())
                .field("content", &"[REDACTED]")
                .finish(),
            Self::Rejected { protocol, kind } => formatter
                .debug_struct("GuestResponse::Rejected")
                .field("protocol", protocol)
                .field("kind", kind)
                .finish(),
        }
    }
}

/// Immutable identity baked beside the guest agent in a sealed VM template.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuestIdentity {
    /// Exact admitted environment-profile identifier.
    pub profile_id: String,
    /// SHA-256 of the installed guest-agent executable.
    pub guest_agent_sha256: String,
    /// Exact macOS product version in the sealed image.
    pub macos_version: String,
    /// Exact macOS build identifier in the sealed image.
    pub macos_build: String,
    /// Exact guest architecture.
    pub architecture: String,
    /// Dedicated non-administrative workflow UID.
    pub job_uid: u32,
    /// Dedicated non-administrative workflow GID.
    pub job_gid: u32,
    /// Hard process ceiling applied by launchd before the guest agent starts.
    pub process_limit: u32,
}

/// Stable, non-sensitive request rejection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestRejection {
    /// Caller and guest protocol versions differ.
    UnsupportedProtocol,
    /// Request violated a path, size, argv, or environment bound.
    InvalidRequest,
    /// Process or filesystem operation failed.
    OperationFailed,
    /// An operation identifier was reused with different request material.
    OperationConflict,
}

/// Guest framing, transport, or request failure.
#[derive(Debug, Error)]
pub enum GuestProtocolError {
    /// I/O transport failed.
    #[error("guest transport failed")]
    Io(#[from] io::Error),
    /// Frame was empty, oversized, malformed, or noncanonical enough to reject.
    #[error("guest frame is invalid")]
    InvalidFrame,
}

/// Encodes one length-prefixed request or response frame.
///
/// # Errors
///
/// Rejects serialization failure or a frame over [`MAX_GUEST_FRAME_BYTES`].
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, GuestProtocolError> {
    let payload = serde_json::to_vec(value).map_err(|_| GuestProtocolError::InvalidFrame)?;
    if payload.is_empty() || payload.len() > MAX_GUEST_FRAME_BYTES {
        return Err(GuestProtocolError::InvalidFrame);
    }
    let length = u32::try_from(payload.len()).map_err(|_| GuestProtocolError::InvalidFrame)?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decodes one exact length-prefixed frame.
///
/// # Errors
///
/// Rejects trailing bytes, malformed JSON, or invalid length evidence.
pub fn decode_frame<T: for<'de> Deserialize<'de>>(frame: &[u8]) -> Result<T, GuestProtocolError> {
    let length = frame
        .get(..4)
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .map(u32::from_be_bytes)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(GuestProtocolError::InvalidFrame)?;
    if length == 0 || length > MAX_GUEST_FRAME_BYTES || frame.len() != length + 4 {
        return Err(GuestProtocolError::InvalidFrame);
    }
    serde_json::from_slice(&frame[4..]).map_err(|_| GuestProtocolError::InvalidFrame)
}
#[cfg(target_os = "linux")]
struct LocalBootstrap {
    control: OwnedFd,
    seed: File,
    seed_device: u64,
    seed_inode: u64,
    seed_size: i64,
    seed_digest: [u8; 32],
    ready: AtomicBool,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalPeerRole {
    Unrestricted,
    #[cfg(target_os = "linux")]
    Sealer,
    #[cfg(target_os = "linux")]
    Client,
}

#[cfg(unix)]
#[derive(Clone)]
enum GuestServiceMode {
    Standard,
    #[cfg(target_os = "linux")]
    Local(Arc<LocalBootstrap>),
}

#[cfg(unix)]
impl GuestServiceMode {
    const fn local_pid_one(&self) -> bool {
        match self {
            Self::Standard => false,
            #[cfg(target_os = "linux")]
            Self::Local(_) => true,
        }
    }
}

#[cfg(target_os = "linux")]
impl LocalBootstrap {
    fn prepare() -> io::Result<Self> {
        if rustix::process::getpid().as_raw_pid() != 1
            || rustix::process::getuid().as_raw() != 0
            || rustix::process::geteuid().as_raw() != 0
            || rustix::process::getgid().as_raw() != 0
            || rustix::process::getegid().as_raw() != 0
        {
            return Err(local_contract_error());
        }
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
        if rustix::process::dumpable_behavior()? != rustix::process::DumpableBehavior::NotDumpable
            || !valid_local_process_envelope()?
        {
            return Err(local_contract_error());
        }
        let control = open(
            LOCAL_CONTROL_DIRECTORY,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if !valid_local_control(
            &control,
            LOCAL_CONTROL_DIRECTORY_MODE_INITIAL,
            LOCAL_CONTROL_SEAL_UID,
            LOCAL_CONTROL_GID,
        ) || !local_path_absent(&control, ".seed")?
            || !local_path_absent(&control, ".seed.stage")?
            || !local_path_absent(&control, "automata-ci-sandbox-guest")?
        {
            return Err(local_contract_error());
        }

        let seed = openat(
            &control,
            ".seed.stage",
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(LOCAL_CONTROL_SEED_STAGE_MODE),
        )?;
        let mut seed = File::from(seed);
        let source = File::open("/proc/self/exe")?;
        let source_size = source.metadata()?.len();
        if source_size == 0 || source_size > MAX_LOCAL_GUEST_BINARY_BYTES {
            return Err(local_contract_error());
        }
        let mut source = source.take(MAX_LOCAL_GUEST_BINARY_BYTES + 1);
        let mut digest = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(u64::try_from(read).map_err(|_| local_contract_error())?)
                .ok_or_else(local_contract_error)?;
            if copied > MAX_LOCAL_GUEST_BINARY_BYTES {
                return Err(local_contract_error());
            }
            digest.update(&buffer[..read]);
            seed.write_all(&buffer[..read])?;
        }
        if copied != source_size {
            return Err(local_contract_error());
        }
        seed.flush()?;
        unix_fs::fchmod(&seed, Mode::from_raw_mode(LOCAL_CONTROL_SEED_MODE))?;
        unix_fs::fsync(&seed)?;
        let written = fstat(&seed)?;
        if !valid_local_seed_stat(&written, 1) {
            return Err(local_contract_error());
        }
        drop(seed);

        renameat_with(
            &control,
            ".seed.stage",
            &control,
            ".seed",
            RenameFlags::NOREPLACE,
        )?;

        let seed = openat(
            &control,
            ".seed",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let seed = File::from(seed);
        let written = fstat(&seed)?;
        if !valid_local_seed_stat(&written, 1) {
            return Err(local_contract_error());
        }
        Ok(Self {
            control,
            seed,
            seed_device: written.st_dev,
            seed_inode: written.st_ino,
            seed_size: written.st_size,
            seed_digest: digest.finalize().into(),
            ready: AtomicBool::new(false),
        })
    }

    fn verify_staged(&self) -> io::Result<File> {
        if self.is_ready() {
            return Err(local_contract_error());
        }
        let seed = fstat(&self.seed)?;
        let control_valid = valid_local_control(
            &self.control,
            LOCAL_CONTROL_DIRECTORY_MODE_INITIAL,
            LOCAL_CONTROL_SEAL_UID,
            LOCAL_CONTROL_GID,
        );
        let seed_valid = valid_local_seed_stat(&seed, 0);
        let seed_absent = local_path_absent(&self.control, ".seed")?;
        let stage_absent = local_path_absent(&self.control, ".seed.stage")?;
        if !control_valid
            || !seed_valid
            || seed.st_dev != self.seed_device
            || seed.st_ino != self.seed_inode
            || seed.st_size != self.seed_size
            || !seed_absent
            || !stage_absent
        {
            return Err(local_contract_error());
        }
        let client = openat(
            &self.control,
            "automata-ci-sandbox-guest",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut client = File::from(client);
        let client_valid = valid_local_staged_client_stat(&fstat(&client)?);
        let digest_valid = file_has_digest(&mut client, self.seed_size, &self.seed_digest)?;
        if !client_valid || !digest_valid {
            return Err(local_contract_error());
        }
        Ok(client)
    }

    fn verify_sealed_and_mark_ready(&self, client: &mut File) -> io::Result<()> {
        let seed = fstat(&self.seed)?;
        if !valid_local_control(
            &self.control,
            LOCAL_CONTROL_DIRECTORY_MODE_SEALED,
            LOCAL_CONTROL_SEAL_UID,
            LOCAL_CONTROL_GID,
        ) || !valid_local_client_stat(&fstat(&*client)?)
            || !file_has_digest(client, self.seed_size, &self.seed_digest)?
            || !valid_local_seed_stat(&seed, 0)
            || seed.st_dev != self.seed_device
            || seed.st_ino != self.seed_inode
            || seed.st_size != self.seed_size
        {
            return Err(local_contract_error());
        }
        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

#[cfg(target_os = "linux")]
fn valid_local_process_envelope() -> io::Result<bool> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let uid_map = std::fs::read_to_string("/proc/self/uid_map")?;
    let gid_map = std::fs::read_to_string("/proc/self/gid_map")?;
    if status.len() > 64 * 1024 {
        return Ok(false);
    }
    let field = |name: &str| {
        status.lines().find_map(|line| {
            line.strip_prefix(name)
                .and_then(|value| value.strip_prefix(':'))
                .map(str::trim)
        })
    };
    // The local provider's administrator is deliberately attenuated to UID 0
    // in a daemon-remapped namespace. No POSIX capability is part of that
    // contract, including the bounding set from which an executable might
    // otherwise regain authority.
    let zero_credentials = |value: &str| value.split_ascii_whitespace().eq(["0", "0", "0", "0"]);
    let zero_capability = |name: &str| field(name) == Some("0000000000000000");
    let groups = rustix::process::getgroups()?;
    Ok(field("Uid").is_some_and(zero_credentials)
        && field("Gid").is_some_and(zero_credentials)
        && field("Groups").is_some_and(|value| value.split_ascii_whitespace().eq(["0"]))
        && groups.len() == 1
        && groups[0].as_raw() == 0
        && zero_capability("CapInh")
        && zero_capability("CapPrm")
        && zero_capability("CapEff")
        && zero_capability("CapBnd")
        && zero_capability("CapAmb")
        && field("NoNewPrivs") == Some("1")
        && field("Seccomp") == Some("2")
        && valid_local_id_map(&uid_map)
        && valid_local_id_map(&gid_map))
}

#[cfg(target_os = "linux")]
fn valid_local_id_map(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_LOCAL_ID_MAP_BYTES || !value.ends_with('\n') {
        return false;
    }
    let mut lines = value.lines();
    let Some(mapping) = lines.next() else {
        return false;
    };
    if lines.next().is_some() {
        return false;
    }
    let canonical_decimal = |field: &str| {
        field
            .parse::<u64>()
            .ok()
            .filter(|parsed| parsed.to_string() == field)
    };
    let mut fields = mapping.split_ascii_whitespace();
    let Some(inside_start) = fields.next().and_then(canonical_decimal) else {
        return false;
    };
    let Some(outside_start) = fields.next().and_then(canonical_decimal) else {
        return false;
    };
    let Some(length) = fields.next().and_then(canonical_decimal) else {
        return false;
    };
    inside_start == 0
        && outside_start != 0
        && length > u64::from(LOCAL_CONTROL_SEAL_UID)
        && fields.next().is_none()
        && outside_start
            .checked_add(length)
            .is_some_and(|end| end <= u64::from(u32::MAX) + 1)
}

#[cfg(target_os = "linux")]
fn valid_local_control<Fd: std::os::fd::AsFd>(control: Fd, mode: u32, uid: u32, gid: u32) -> bool {
    let Ok(stat) = fstat(&control) else {
        return false;
    };
    let Ok(filesystem_stats) = unix_fs::fstatfs(&control) else {
        return false;
    };
    let Ok(mount_stats) = unix_fs::fstatvfs(control) else {
        return false;
    };
    let required_flags = StatVfsMountFlags::NOSUID | StatVfsMountFlags::NODEV;
    let rejected_flags = StatVfsMountFlags::NOEXEC | StatVfsMountFlags::RDONLY;
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == uid
        && stat.st_gid == gid
        && stat.st_mode & 0o7777 == mode
        && stat.st_nlink == 2
        && filesystem_stats.f_type == LOCAL_CONTROL_TMPFS_MAGIC
        && mount_stats.f_flag.contains(required_flags)
        && !mount_stats.f_flag.intersects(rejected_flags)
        && mount_stats
            .f_frsize
            .checked_mul(mount_stats.f_blocks)
            .is_some_and(|bytes| bytes == LOCAL_CONTROL_TMPFS_BYTES)
}

#[cfg(target_os = "linux")]
fn valid_local_client_stat(stat: &unix_fs::Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == LOCAL_CONTROL_SEAL_UID
        && stat.st_gid == LOCAL_CONTROL_GID
        && stat.st_mode & 0o7777 == LOCAL_CONTROL_CLIENT_MODE
        && stat.st_nlink == 1
        && stat.st_size > 0
        && u64::try_from(stat.st_size).is_ok_and(|size| size <= MAX_LOCAL_GUEST_BINARY_BYTES)
}

#[cfg(target_os = "linux")]
fn valid_local_staged_client_stat(stat: &unix_fs::Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == LOCAL_CONTROL_SEAL_UID
        && stat.st_gid == LOCAL_CONTROL_GID
        && stat.st_mode & 0o7777 == LOCAL_CONTROL_CLIENT_MODE_STAGED
        && stat.st_nlink == 1
        && stat.st_size > 0
        && u64::try_from(stat.st_size).is_ok_and(|size| size <= MAX_LOCAL_GUEST_BINARY_BYTES)
}

#[cfg(target_os = "linux")]
fn valid_local_seed_stat(stat: &unix_fs::Stat, links: u64) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == 0
        && stat.st_gid == 0
        && stat.st_mode & 0o7777 == LOCAL_CONTROL_SEED_MODE
        && stat.st_nlink == links
        && stat.st_size > 0
        && u64::try_from(stat.st_size).is_ok_and(|size| size <= MAX_LOCAL_GUEST_BINARY_BYTES)
}

#[cfg(target_os = "linux")]
fn file_has_digest(file: &mut File, size: i64, expected: &[u8; 32]) -> io::Result<bool> {
    file.rewind()?;
    let mut digest = Sha256::new();
    let mut observed = 0_i64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(i64::try_from(read).map_err(|_| local_contract_error())?)
            .ok_or_else(local_contract_error)?;
        if observed > size {
            return Ok(false);
        }
        digest.update(&buffer[..read]);
    }
    Ok(observed == size && <[u8; 32]>::from(digest.finalize()) == *expected)
}

#[cfg(target_os = "linux")]
fn local_path_absent(control: &OwnedFd, name: &str) -> io::Result<bool> {
    match openat(
        control,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(_) => Ok(false),
        Err(Errno::NOENT) => Ok(true),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn stage_local_client() -> io::Result<OwnedFd> {
    if rustix::process::getuid().as_raw() != LOCAL_CONTROL_SEAL_UID
        || rustix::process::geteuid().as_raw() != LOCAL_CONTROL_SEAL_UID
        || rustix::process::getgid().as_raw() != LOCAL_CONTROL_GID
        || rustix::process::getegid().as_raw() != LOCAL_CONTROL_GID
    {
        return Err(local_contract_error());
    }
    let control = open(
        LOCAL_CONTROL_DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    if !valid_local_control(
        &control,
        LOCAL_CONTROL_DIRECTORY_MODE_INITIAL,
        LOCAL_CONTROL_SEAL_UID,
        LOCAL_CONTROL_GID,
    ) || !local_path_absent(&control, ".seed.stage")?
        || !local_path_absent(&control, "automata-ci-sandbox-guest")?
    {
        return Err(local_contract_error());
    }
    let seed = openat(
        &control,
        ".seed",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let seed_stat = fstat(&seed)?;
    let executable = File::open("/proc/self/exe")?;
    let executable_stat = fstat(&executable)?;
    if !valid_local_seed_stat(&seed_stat, 1)
        || seed_stat.st_dev != executable_stat.st_dev
        || seed_stat.st_ino != executable_stat.st_ino
        || seed_stat.st_size != executable_stat.st_size
    {
        return Err(local_contract_error());
    }
    let client = openat(
        &control,
        "automata-ci-sandbox-guest",
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(LOCAL_CONTROL_CLIENT_MODE_STAGED),
    )?;
    let mut client = File::from(client);
    let mut source = executable.take(MAX_LOCAL_GUEST_BINARY_BYTES + 1);
    let copied = io::copy(&mut source, &mut client)?;
    if copied == 0
        || copied > MAX_LOCAL_GUEST_BINARY_BYTES
        || i64::try_from(copied).ok() != Some(seed_stat.st_size)
    {
        return Err(local_contract_error());
    }
    client.flush()?;
    unix_fs::fchmod(
        &client,
        Mode::from_raw_mode(LOCAL_CONTROL_CLIENT_MODE_STAGED),
    )?;
    unix_fs::fsync(&client)?;
    if !valid_local_staged_client_stat(&fstat(&client)?) {
        return Err(local_contract_error());
    }
    drop(client);
    unlinkat(&control, ".seed", AtFlags::empty())?;
    unix_fs::fsync(&control)?;
    Ok(control)
}

#[cfg(target_os = "linux")]
fn validate_local_client_state(control: &OwnedFd) -> io::Result<()> {
    if !valid_local_control(
        control,
        LOCAL_CONTROL_DIRECTORY_MODE_SEALED,
        LOCAL_CONTROL_SEAL_UID,
        LOCAL_CONTROL_GID,
    ) || !local_path_absent(control, ".seed")?
        || !local_path_absent(control, ".seed.stage")?
    {
        return Err(local_contract_error());
    }
    let client = openat(
        control,
        "automata-ci-sandbox-guest",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut client = File::from(client);
    let mut executable = File::open("/proc/self/exe")?;
    let client_stat = fstat(&client)?;
    let executable_stat = fstat(&executable)?;
    if !valid_local_client_stat(&client_stat) || client_stat.st_size != executable_stat.st_size {
        return Err(local_contract_error());
    }
    let client_digest: [u8; 32] = Sha256::digest(read_bounded_local_file(&mut client)?).into();
    let executable_digest: [u8; 32] =
        Sha256::digest(read_bounded_local_file(&mut executable)?).into();
    if client_digest != executable_digest {
        return Err(local_contract_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_bounded_local_file(file: &mut File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(MAX_LOCAL_GUEST_BINARY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let size = u64::try_from(bytes.len()).map_err(|_| local_contract_error())?;
    if size == 0 || size > MAX_LOCAL_GUEST_BINARY_BYTES {
        return Err(local_contract_error());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
async fn exchange_local_seal(control: &OwnedFd) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + LOCAL_BOOTSTRAP_TIMEOUT;
    let mut stream = loop {
        match connect_stream(Path::new(LOCAL_CONTROL_SOCKET)).await {
            Ok(stream) => break stream,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => return Err(error),
        }
    };
    stream.write_all(LOCAL_STAGE_REQUEST).await?;
    let mut staged = vec![0; LOCAL_STAGE_ACKNOWLEDGEMENT.len()];
    stream.read_exact(&mut staged).await?;
    if staged != LOCAL_STAGE_ACKNOWLEDGEMENT {
        return Err(local_contract_error());
    }
    let client = openat(
        control,
        "automata-ci-sandbox-guest",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    unix_fs::fchmod(&client, Mode::from_raw_mode(LOCAL_CONTROL_CLIENT_MODE))?;
    unix_fs::fsync(&client)?;
    unix_fs::fchmod(
        control,
        Mode::from_raw_mode(LOCAL_CONTROL_DIRECTORY_MODE_SEALED),
    )?;
    unix_fs::fsync(control)?;
    stream.write_all(LOCAL_SEAL_REQUEST).await?;
    stream.shutdown().await?;
    let mut acknowledgement = vec![0; LOCAL_SEAL_ACKNOWLEDGEMENT.len()];
    stream.read_exact(&mut acknowledgement).await?;
    require_eof(&mut stream)
        .await
        .map_err(|error| match error {
            GuestProtocolError::Io(error) => error,
            GuestProtocolError::InvalidFrame => local_contract_error(),
        })?;
    if acknowledgement != LOCAL_SEAL_ACKNOWLEDGEMENT {
        return Err(local_contract_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn local_contract_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "local guest contract rejected",
    )
}

/// Runs the guest Unix-socket server until its listener fails.
///
/// # Errors
///
/// Returns a sanitized transport error when the socket cannot be bound or accepted.
#[cfg(unix)]
pub async fn serve(socket: &Path) -> Result<(), GuestProtocolError> {
    serve_internal(socket, None, GuestServiceMode::Standard).await
}

/// Runs the fixed Linux local broker as the container's non-dumpable PID 1.
///
/// # Errors
///
/// Rejects any process, control tmpfs, or seed state outside the closed local
/// contract, and returns a sanitized transport error when serving fails.
#[cfg(target_os = "linux")]
pub async fn serve_local_broker() -> Result<(), GuestProtocolError> {
    let bootstrap = Arc::new(LocalBootstrap::prepare()?);
    serve_internal(
        Path::new(LOCAL_CONTROL_SOCKET),
        None,
        GuestServiceMode::Local(bootstrap),
    )
    .await
}

/// Atomically seals the fixed Linux local client and authenticates it to PID 1.
///
/// This command is deliberately one-shot and must be invoked by the Docker
/// manager as UID 65533 and GID 65532 from [`LOCAL_CONTROL_SEED`] before any workflow
/// process exists.
///
/// # Errors
///
/// Rejects the wrong caller, executable, tmpfs, ownership, mode, link, or
/// prior setup state, as well as a broker that does not acknowledge the seal.
#[cfg(target_os = "linux")]
pub async fn seal_local_client() -> Result<(), GuestProtocolError> {
    let control = stage_local_client()?;
    exchange_local_seal(&control).await?;
    validate_local_client_state(&control)?;
    Ok(())
}

/// Waits for PID 1's exact seed and executes its one-shot local sealing mode.
///
/// The Docker manager invokes this pre-workload bootstrap through the exact
/// overlay guest it already uploaded and read back. The sealing child itself
/// is always executed from PID 1's independently copied seed.
///
/// # Errors
///
/// Returns a sanitized failure if the seed does not appear within the fixed
/// startup deadline or its sealing child does not exit successfully.
#[cfg(target_os = "linux")]
pub async fn bootstrap_local_client() -> Result<(), GuestProtocolError> {
    if rustix::process::getuid().as_raw() != LOCAL_CONTROL_SEAL_UID
        || rustix::process::geteuid().as_raw() != LOCAL_CONTROL_SEAL_UID
        || rustix::process::getgid().as_raw() != LOCAL_CONTROL_GID
        || rustix::process::getegid().as_raw() != LOCAL_CONTROL_GID
    {
        return Err(local_contract_error().into());
    }
    let deadline = tokio::time::Instant::now() + LOCAL_BOOTSTRAP_TIMEOUT;
    loop {
        match std::fs::symlink_metadata(LOCAL_CONTROL_SEED) {
            Ok(metadata) if metadata.file_type().is_file() => break,
            Ok(_) => return Err(local_contract_error().into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "local seed timed out").into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let status = tokio::time::timeout(
        LOCAL_BOOTSTRAP_TIMEOUT,
        Command::new(LOCAL_CONTROL_SEED)
            .arg("seal-local-client")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local seal timed out"))??;
    if !status.success() {
        return Err(local_contract_error().into());
    }
    Ok(())
}

/// Runs the macOS VM guest server with its mandatory sealed-template identity.
///
/// # Errors
///
/// Returns a sanitized transport error when the socket cannot be bound or accepted.
#[cfg(unix)]
pub async fn serve_vm(socket: &Path, identity: GuestIdentity) -> Result<(), GuestProtocolError> {
    serve_internal(socket, Some(identity), GuestServiceMode::Standard).await
}

#[cfg(unix)]
async fn serve_internal(
    socket: &Path,
    identity: Option<GuestIdentity>,
    service: GuestServiceMode,
) -> Result<(), GuestProtocolError> {
    let listener = bind_listener(socket).await?;
    let replay = Arc::new(Mutex::new(ReplayCache::default()));
    let mut connections = JoinSet::new();
    #[cfg(target_os = "linux")]
    if service.local_pid_one() {
        connections.spawn(reap_local_children());
    }
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                #[cfg(target_os = "linux")]
                let Some(peer_role) = local_peer_role(&stream, &service) else {
                    continue;
                };
                #[cfg(not(target_os = "linux"))]
                let peer_role = LocalPeerRole::Unrestricted;
                let replay = Arc::clone(&replay);
                let identity = identity.clone();
                let service = service.clone();
                connections.spawn(async move {
                    let _ = serve_connection(stream, replay, identity, service, peer_role).await;
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                let _ = result;
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn reap_local_children() {
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let _execution = LOCAL_EXECUTION_LOCK.lock().await;
        while let Ok(Some(_)) = rustix::process::wait(rustix::process::WaitOptions::NOHANG) {}
    }
}

#[cfg(target_os = "linux")]
fn local_peer_role(stream: &UnixStream, service: &GuestServiceMode) -> Option<LocalPeerRole> {
    let GuestServiceMode::Local(local) = service else {
        return Some(LocalPeerRole::Unrestricted);
    };
    local_stream_peer_role(stream, local.is_ready())
}

#[cfg(target_os = "linux")]
fn local_stream_peer_role(stream: &UnixStream, ready: bool) -> Option<LocalPeerRole> {
    let credentials = stream.peer_cred().ok()?;
    local_peer_role_for_credentials(ready, credentials.uid(), credentials.gid())
}

#[cfg(target_os = "linux")]
const fn local_peer_role_for_credentials(ready: bool, uid: u32, gid: u32) -> Option<LocalPeerRole> {
    if gid != LOCAL_CONTROL_GID {
        return None;
    }
    match (ready, uid) {
        (false, LOCAL_CONTROL_SEAL_UID) => Some(LocalPeerRole::Sealer),
        (true, LOCAL_CONTROL_UID) => Some(LocalPeerRole::Client),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn local_peer_role_is_current(
    captured: LocalPeerRole,
    current: Option<LocalPeerRole>,
    required: LocalPeerRole,
) -> bool {
    captured == required && current == Some(required)
}

/// Runs the guest Unix-socket server until its listener fails.
///
/// # Errors
///
/// Returns an unsupported transport error on non-Unix platforms.
#[cfg(not(unix))]
#[allow(clippy::unused_async)]
pub async fn serve(_socket: &Path) -> Result<(), GuestProtocolError> {
    Err(unsupported_unix_transport().into())
}

/// Rejects identity-bearing guest service on non-Unix platforms.
///
/// # Errors
///
/// Always returns an unsupported transport error.
#[cfg(not(unix))]
#[allow(clippy::unused_async)]
pub async fn serve_vm(_socket: &Path, _identity: GuestIdentity) -> Result<(), GuestProtocolError> {
    Err(unsupported_unix_transport().into())
}

/// Forwards one framed request between stdio and the guest Unix socket.
///
/// # Errors
///
/// Returns a transport failure without including request data.
#[cfg(unix)]
pub async fn forward_stdio(socket: &Path) -> Result<(), GuestProtocolError> {
    let mut input = tokio::io::stdin();
    let request = read_frame(&mut input).await?;
    let mut stream = connect_stream(socket).await?;
    stream.write_all(&request).await?;
    let response = read_frame(&mut stream).await?;
    let mut output = tokio::io::stdout();
    output.write_all(&response).await?;
    output.flush().await?;
    Ok(())
}

/// Forwards one exact framed request to the protected local broker.
///
/// Unlike the protocol-v3 standard client, this closed local transport
/// requires end-of-input and half-closes the broker request. The broker can
/// therefore execute the request only after Docker has delivered the complete
/// bounded input.
///
/// # Errors
///
/// Returns a sanitized framing or transport failure.
#[cfg(target_os = "linux")]
pub async fn forward_local_stdio() -> Result<(), GuestProtocolError> {
    let mut input = tokio::io::stdin();
    let request = read_frame(&mut input).await?;
    require_eof(&mut input).await?;
    let mut stream = connect_stream(Path::new(LOCAL_CONTROL_SOCKET)).await?;
    stream.write_all(&request).await?;
    stream.shutdown().await?;
    let response = read_frame(&mut stream).await?;
    let mut output = tokio::io::stdout();
    output.write_all(&response).await?;
    output.flush().await?;
    Ok(())
}

/// Forwards one framed request between stdio and the guest Unix socket.
///
/// # Errors
///
/// Returns an unsupported transport error on non-Unix platforms.
#[cfg(not(unix))]
#[allow(clippy::unused_async)]
pub async fn forward_stdio(_socket: &Path) -> Result<(), GuestProtocolError> {
    Err(unsupported_unix_transport().into())
}

/// Handles one framed request on standard input and writes one framed response.
///
/// This transport is used by Hyper-V-isolated Windows containers so argv,
/// environment values, and file bytes never enter the container-runtime
/// command line. It deliberately serves one request and exits; lifecycle and
/// replay fencing remain owned by the host provider.
///
/// # Errors
///
/// Returns a sanitized framing or standard-I/O failure.
#[cfg(any(unix, windows))]
pub async fn serve_stdio_once() -> Result<(), GuestProtocolError> {
    let mut input = tokio::io::stdin();
    let request = read_one_shot_request(&mut input).await?;
    let response = match immediate_rejection(&request) {
        Some(response) => response,
        None => handle_request(request, None, false).await,
    };
    let mut output = tokio::io::stdout();
    output.write_all(&encode_frame(&response)?).await?;
    output.flush().await?;
    Ok(())
}

/// Rejects the one-shot standard-I/O transport on unsupported platforms.
///
/// # Errors
///
/// Always returns an unsupported transport error.
#[cfg(not(any(unix, windows)))]
#[allow(clippy::unused_async)]
pub async fn serve_stdio_once() -> Result<(), GuestProtocolError> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "guest stdio transport is unavailable",
    )
    .into())
}

/// Checks whether the configured guest listener accepts connections.
#[must_use]
#[cfg(unix)]
pub fn probe(socket: &Path) -> bool {
    connect_probe(socket).is_ok()
}

/// Checks whether the configured guest listener accepts connections.
#[must_use]
#[cfg(not(unix))]
pub fn probe(_socket: &Path) -> bool {
    false
}

#[cfg(not(unix))]
fn unsupported_unix_transport() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "guest Unix-socket transport is unavailable",
    )
}

#[cfg(unix)]
async fn bind_listener(socket: &Path) -> io::Result<UnixListener> {
    if let Some(name) = abstract_socket_name(socket) {
        #[cfg(target_os = "linux")]
        {
            let address = StdSocketAddr::from_abstract_name(name)?;
            let listener = StdUnixListener::bind_addr(&address)?;
            listener.set_nonblocking(true)?;
            return UnixListener::from_std(listener);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "abstract Unix sockets require Linux",
            ));
        }
    }
    match tokio::fs::remove_file(socket).await {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    UnixListener::bind(socket)
}

#[cfg(unix)]
async fn connect_stream(socket: &Path) -> io::Result<UnixStream> {
    if let Some(name) = abstract_socket_name(socket) {
        #[cfg(target_os = "linux")]
        {
            let address = StdSocketAddr::from_abstract_name(name)?;
            let stream = StdUnixStream::connect_addr(&address)?;
            stream.set_nonblocking(true)?;
            return UnixStream::from_std(stream);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "abstract Unix sockets require Linux",
            ));
        }
    }
    UnixStream::connect(socket).await
}

#[cfg(unix)]
fn connect_probe(socket: &Path) -> io::Result<()> {
    if let Some(name) = abstract_socket_name(socket) {
        #[cfg(target_os = "linux")]
        {
            let address = StdSocketAddr::from_abstract_name(name)?;
            return StdUnixStream::connect_addr(&address).map(|_| ());
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "abstract Unix sockets require Linux",
            ));
        }
    }
    std::os::unix::net::UnixStream::connect(socket).map(|_| ())
}

#[cfg(unix)]
fn abstract_socket_name(socket: &Path) -> Option<&[u8]> {
    socket
        .to_str()
        .and_then(|value| value.strip_prefix('@'))
        .filter(|value| !value.is_empty())
        .map(str::as_bytes)
}

#[cfg(unix)]
async fn serve_connection(
    mut stream: UnixStream,
    replay: Arc<Mutex<ReplayCache>>,
    identity: Option<GuestIdentity>,
    service: GuestServiceMode,
    peer_role: LocalPeerRole,
) -> Result<(), GuestProtocolError> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    #[cfg(target_os = "linux")]
    if let GuestServiceMode::Local(local) = &service
        && handle_local_seal(&mut stream, &header, local, peer_role).await?
    {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if matches!(&service, GuestServiceMode::Local(_))
        && !local_peer_role_is_current(
            peer_role,
            local_peer_role(&stream, &service),
            LocalPeerRole::Client,
        )
    {
        return Err(GuestProtocolError::InvalidFrame);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = peer_role;
    let frame = read_frame_with_header(&mut stream, header).await?;
    let request: GuestRequest = decode_frame(&frame)?;
    let immediate_response = immediate_rejection(&request);
    if let Some(response) = immediate_response {
        stream.write_all(&encode_frame(&response)?).await?;
        stream.shutdown().await?;
        return Ok(());
    }

    if service.local_pid_one() {
        require_eof(&mut stream).await?;
        // Local endpoint replay is linearized and retained by the durable host.
        // A transport ambiguity leaves InvocationCommitted evidence and forces
        // exact sandbox destruction, so this broker must never retain or
        // re-invoke workflow operations on the host's behalf.
        let response = handle_request(request, identity, true).await;
        stream.write_all(&encode_frame(&response)?).await?;
        stream.shutdown().await?;
        return Ok(());
    }

    let (mut reader, mut writer) = stream.into_split();
    let operation = replay_request(request, replay, identity);
    tokio::pin!(operation);
    let response = tokio::select! {
        response = &mut operation => response,
        disconnected = wait_for_disconnect(&mut reader) => {
            disconnected?;
            return Ok(());
        }
    };
    writer.write_all(&encode_frame(&response)?).await?;
    writer.shutdown().await?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn handle_local_seal(
    stream: &mut UnixStream,
    header: &[u8; 4],
    local: &Arc<LocalBootstrap>,
    peer_role: LocalPeerRole,
) -> Result<bool, GuestProtocolError> {
    if header != &LOCAL_STAGE_REQUEST[..4] {
        return Ok(false);
    }
    if !local_peer_role_is_current(
        peer_role,
        local_stream_peer_role(stream, local.is_ready()),
        LocalPeerRole::Sealer,
    ) {
        return Err(GuestProtocolError::InvalidFrame);
    }
    let mut remainder = vec![0_u8; LOCAL_STAGE_REQUEST.len() - 4];
    stream.read_exact(&mut remainder).await?;
    if remainder != LOCAL_STAGE_REQUEST[4..] {
        return Err(GuestProtocolError::InvalidFrame);
    }
    let mut client = local.verify_staged()?;
    stream.write_all(LOCAL_STAGE_ACKNOWLEDGEMENT).await?;
    let mut seal = vec![0_u8; LOCAL_SEAL_REQUEST.len()];
    stream.read_exact(&mut seal).await?;
    if seal != LOCAL_SEAL_REQUEST {
        return Err(GuestProtocolError::InvalidFrame);
    }
    require_eof(stream).await?;
    local.verify_sealed_and_mark_ready(&mut client)?;
    stream.write_all(LOCAL_SEAL_ACKNOWLEDGEMENT).await?;
    stream.shutdown().await?;
    Ok(true)
}

#[cfg(any(unix, windows))]
fn immediate_rejection(request: &GuestRequest) -> Option<GuestResponse> {
    if request.protocol() != GUEST_PROTOCOL_VERSION {
        Some(GuestResponse::Rejected {
            protocol: GUEST_PROTOCOL_VERSION,
            kind: GuestRejection::UnsupportedProtocol,
        })
    } else if !valid_operation_id(request.operation_id()) {
        Some(rejected(GuestRejection::InvalidRequest))
    } else {
        None
    }
}

#[cfg(any(unix, windows))]
async fn require_eof<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(), GuestProtocolError> {
    let mut unexpected = [0_u8; 1];
    match reader.read(&mut unexpected).await {
        Ok(0) => Ok(()),
        Ok(_) => Err(GuestProtocolError::InvalidFrame),
        Err(error) => Err(GuestProtocolError::Io(error)),
    }
}

#[cfg(any(unix, windows))]
async fn read_one_shot_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<GuestRequest, GuestProtocolError> {
    let frame = read_frame(reader).await?;
    require_eof(reader).await?;
    decode_frame(&frame)
}

#[cfg(unix)]
async fn wait_for_disconnect<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(), GuestProtocolError> {
    require_eof(reader).await
}

#[cfg(unix)]
#[derive(Default)]
struct ReplayCache {
    entries: BTreeMap<String, ReplayEntry>,
    in_flight: BTreeMap<String, InFlightReplay>,
    order: VecDeque<String>,
    bytes: usize,
}

#[cfg(unix)]
struct InFlightReplay {
    fingerprint: [u8; 32],
    completion: watch::Sender<bool>,
}

#[cfg(unix)]
struct ReplayEntry {
    fingerprint: [u8; 32],
    response: GuestResponse,
    bytes: usize,
}

#[cfg(unix)]
impl ReplayCache {
    fn get(&self, operation_id: &str, fingerprint: &[u8; 32]) -> Option<GuestResponse> {
        self.entries.get(operation_id).map(|entry| {
            if &entry.fingerprint == fingerprint {
                entry.response.clone()
            } else {
                rejected(GuestRejection::OperationConflict)
            }
        })
    }

    fn insert(&mut self, operation_id: String, fingerprint: [u8; 32], response: GuestResponse) {
        let bytes = encode_frame(&response).map_or(MAX_REPLAY_BYTES + 1, |frame| frame.len());
        if bytes > MAX_REPLAY_BYTES {
            return;
        }
        while self.entries.len() >= MAX_REPLAY_ENTRIES
            || self.bytes.saturating_add(bytes) > MAX_REPLAY_BYTES
        {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(entry) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(entry.bytes);
            }
        }
        self.bytes = self.bytes.saturating_add(bytes);
        self.order.push_back(operation_id.clone());
        self.entries.insert(
            operation_id,
            ReplayEntry {
                fingerprint,
                response,
                bytes,
            },
        );
    }
}

#[cfg(unix)]
struct ReplayReservation {
    replay: Arc<Mutex<ReplayCache>>,
    operation_id: String,
    fingerprint: [u8; 32],
    completion: Option<watch::Sender<bool>>,
}

#[cfg(unix)]
impl ReplayReservation {
    fn commit(mut self, response: GuestResponse) {
        {
            let mut replay = lock_replay(&self.replay);
            replay.in_flight.remove(&self.operation_id);
            replay.insert(self.operation_id.clone(), self.fingerprint, response);
        }
        if let Some(completion) = self.completion.take() {
            let _ = completion.send(true);
        }
    }
}

#[cfg(unix)]
impl Drop for ReplayReservation {
    fn drop(&mut self) {
        let Some(completion) = self.completion.take() else {
            return;
        };
        lock_replay(&self.replay)
            .in_flight
            .remove(&self.operation_id);
        let _ = completion.send(true);
    }
}

#[cfg(unix)]
fn lock_replay(replay: &Mutex<ReplayCache>) -> MutexGuard<'_, ReplayCache> {
    replay
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(unix)]
enum ReplayDecision {
    Return(GuestResponse),
    Wait(watch::Receiver<bool>),
    Execute(ReplayReservation),
}

#[cfg(unix)]
fn replay_decision(
    replay: &Arc<Mutex<ReplayCache>>,
    operation_id: &str,
    fingerprint: &[u8; 32],
) -> ReplayDecision {
    let mut cache = lock_replay(replay);
    if let Some(response) = cache.get(operation_id, fingerprint) {
        return ReplayDecision::Return(response);
    }
    if let Some(in_flight) = cache.in_flight.get(operation_id) {
        return if &in_flight.fingerprint == fingerprint {
            ReplayDecision::Wait(in_flight.completion.subscribe())
        } else {
            ReplayDecision::Return(rejected(GuestRejection::OperationConflict))
        };
    }
    let (completion, receiver) = watch::channel(false);
    drop(receiver);
    cache.in_flight.insert(
        operation_id.to_owned(),
        InFlightReplay {
            fingerprint: *fingerprint,
            completion: completion.clone(),
        },
    );
    ReplayDecision::Execute(ReplayReservation {
        replay: Arc::clone(replay),
        operation_id: operation_id.to_owned(),
        fingerprint: *fingerprint,
        completion: Some(completion),
    })
}

#[cfg(unix)]
async fn replay_request(
    request: GuestRequest,
    replay: Arc<Mutex<ReplayCache>>,
    identity: Option<GuestIdentity>,
) -> GuestResponse {
    let fingerprint: [u8; 32] = Sha256::digest(
        serde_json::to_vec(&request).expect("validated guest request is serializable"),
    )
    .into();
    let operation_id = request.operation_id().to_owned();
    loop {
        match replay_decision(&replay, &operation_id, &fingerprint) {
            ReplayDecision::Return(response) => return response,
            ReplayDecision::Wait(mut completion) => {
                if !*completion.borrow() {
                    let _ = completion.changed().await;
                }
            }
            ReplayDecision::Execute(reservation) => {
                let response = handle_request(request, identity, false).await;
                reservation.commit(response.clone());
                return response;
            }
        }
    }
}

#[cfg(any(unix, windows))]
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, GuestProtocolError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header).await?;
    read_frame_with_header(reader, header).await
}

#[cfg(any(unix, windows))]
async fn read_frame_with_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    header: [u8; 4],
) -> Result<Vec<u8>, GuestProtocolError> {
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| GuestProtocolError::InvalidFrame)?;
    if length == 0 || length > MAX_GUEST_FRAME_BYTES {
        return Err(GuestProtocolError::InvalidFrame);
    }
    let mut frame = Vec::with_capacity(length + 4);
    frame.extend_from_slice(&header);
    frame.resize(length + 4, 0);
    reader.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}

#[cfg(any(unix, windows))]
async fn handle_request(
    request: GuestRequest,
    identity: Option<GuestIdentity>,
    local_pid_one: bool,
) -> GuestResponse {
    match request {
        GuestRequest::Probe { .. } => GuestResponse::Ready {
            protocol: GUEST_PROTOCOL_VERSION,
        },
        GuestRequest::Hello { nonce, .. } => {
            if valid_attestation_value(&nonce) {
                identity.map_or_else(
                    || rejected(GuestRejection::OperationFailed),
                    |identity| GuestResponse::Hello {
                        protocol: GUEST_PROTOCOL_VERSION,
                        nonce,
                        profile_id: identity.profile_id,
                        guest_agent_sha256: identity.guest_agent_sha256,
                        macos_version: identity.macos_version,
                        macos_build: identity.macos_build,
                        architecture: identity.architecture,
                        job_uid: identity.job_uid,
                        job_gid: identity.job_gid,
                        process_limit: identity.process_limit,
                    },
                )
            } else {
                rejected(GuestRejection::InvalidRequest)
            }
        }
        GuestRequest::Configure { process_limit, .. } => {
            if identity.as_ref().map(|value| value.process_limit) != Some(process_limit) {
                rejected(GuestRejection::InvalidRequest)
            } else if configure_process_limit(process_limit).is_err() {
                rejected(GuestRejection::OperationFailed)
            } else {
                GuestResponse::Configured {
                    protocol: GUEST_PROTOCOL_VERSION,
                }
            }
        }
        GuestRequest::Exec {
            program,
            arguments,
            environment,
            working_directory,
            timeout_millis,
            output_limit,
            process_limit,
            ..
        } => {
            execute(
                program,
                arguments,
                environment,
                working_directory,
                timeout_millis,
                output_limit,
                process_limit,
                local_pid_one,
            )
            .await
        }
        GuestRequest::WriteFile {
            path,
            content_base64,
            ..
        } => write_file(&path, &content_base64).await,
        GuestRequest::ReadFile {
            path, byte_limit, ..
        } => read_file(&path, byte_limit).await,
    }
}

#[cfg(any(unix, windows))]
fn valid_attestation_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPERATION_ID_BYTES
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

#[cfg(unix)]
fn configure_process_limit(process_limit: u32) -> io::Result<()> {
    let limit = u64::from(process_limit);
    rustix::process::setrlimit(
        rustix::process::Resource::Nproc,
        rustix::process::Rlimit {
            current: Some(limit),
            maximum: Some(limit),
        },
    )
    .map_err(Into::into)
}

#[cfg(windows)]
fn configure_process_limit(_process_limit: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows process limits are enforced by the container runtime",
    ))
}

#[cfg(any(unix, windows))]
#[allow(clippy::too_many_arguments)]
async fn execute(
    program: String,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    working_directory: String,
    timeout_millis: u64,
    output_limit: usize,
    process_limit: Option<u32>,
    local_pid_one: bool,
) -> GuestResponse {
    #[cfg(target_os = "linux")]
    let _execution = if local_pid_one {
        Some(LOCAL_EXECUTION_LOCK.lock().await)
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let _ = local_pid_one;
    if !valid_execution_request(
        &program,
        &arguments,
        &environment,
        &working_directory,
        timeout_millis,
        output_limit,
        process_limit,
    ) {
        return rejected(GuestRejection::InvalidRequest);
    }
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .envs(environment)
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let Ok((mut child, containment)) = spawn_contained(command, process_limit) else {
        return rejected(GuestRejection::OperationFailed);
    };
    let Some(stdout) = child.stdout.take() else {
        return rejected(GuestRejection::OperationFailed);
    };
    let Some(stderr) = child.stderr.take() else {
        return rejected(GuestRejection::OperationFailed);
    };
    let (sender, mut receiver) = mpsc::channel(64);
    let stdout_task = tokio::spawn(read_output(
        stdout,
        GuestOutputStream::Stdout,
        sender.clone(),
    ));
    let stderr_task = tokio::spawn(read_output(stderr, GuestOutputStream::Stderr, sender));
    let (status, mut records, truncated) = collect_process_output(
        &mut child,
        &mut receiver,
        &containment,
        output_limit,
        Duration::from_millis(timeout_millis),
    )
    .await;
    let (termination, truncated) = match status {
        Some(Ok(status)) => {
            let termination = status
                .code()
                .map_or(GuestTermination::Signalled, GuestTermination::Exited);
            (termination, truncated)
        }
        Some(Err(_)) => {
            stdout_task.abort();
            stderr_task.abort();
            containment.terminate();
            let _ = child.kill().await;
            let _ = child.wait().await;
            return rejected(GuestRejection::OperationFailed);
        }
        None => {
            stdout_task.abort();
            stderr_task.abort();
            containment.terminate();
            let _ = child.kill().await;
            let _ = child.wait().await;
            (GuestTermination::TimedOut, truncated)
        }
    };
    let _ = stdout_task.await;
    let _ = stderr_task.await;
    if !truncated {
        records.push(GuestOutputRecord {
            stream: GuestOutputStream::Stdout,
            data_base64: String::new(),
            end_of_stream: true,
        });
        records.push(GuestOutputRecord {
            stream: GuestOutputStream::Stderr,
            data_base64: String::new(),
            end_of_stream: true,
        });
    }
    GuestResponse::Exec {
        protocol: GUEST_PROTOCOL_VERSION,
        termination,
        records,
        truncated,
    }
}

#[cfg(any(unix, windows))]
async fn collect_process_output(
    child: &mut tokio::process::Child,
    receiver: &mut mpsc::Receiver<(GuestOutputStream, Vec<u8>)>,
    containment: &ProcessContainment,
    output_limit: usize,
    deadline: Duration,
) -> (
    Option<io::Result<std::process::ExitStatus>>,
    Vec<GuestOutputRecord>,
    bool,
) {
    let mut status = None;
    let mut output_open = true;
    let mut records = Vec::new();
    let mut bytes = 0_usize;
    let mut truncated = false;
    let deadline = tokio::time::sleep(deadline);
    tokio::pin!(deadline);
    while status.is_none() || output_open {
        tokio::select! {
            () = &mut deadline => return (None, records, truncated),
            result = child.wait(), if status.is_none() => {
                status = Some(result);
                containment.terminate();
            },
            record = receiver.recv(), if output_open => match record {
                Some((stream, data)) => {
                    let remaining = output_limit.saturating_sub(bytes);
                    let retained = data.len().min(remaining);
                    let can_store = records.len() < MAX_OUTPUT_DATA_RECORDS;
                    if retained > 0 && can_store {
                        records.push(GuestOutputRecord {
                            stream,
                            data_base64: BASE64.encode(&data[..retained]),
                            end_of_stream: false,
                        });
                    }
                    truncated |= retained != data.len()
                        || retained > 0 && !can_store;
                    bytes += retained;
                }
                None => output_open = false,
            },
        }
    }
    (status, records, truncated)
}

#[cfg(unix)]
struct ProcessContainment {
    process_group: u32,
}

#[cfg(windows)]
struct ProcessContainment {
    job: processkit::ProcessGroup,
}

#[cfg(unix)]
fn spawn_contained(
    mut command: Command,
    process_limit: Option<u32>,
) -> Result<(tokio::process::Child, ProcessContainment), ()> {
    if process_limit.is_some() {
        return Err(());
    }
    command.process_group(0);
    let child = command.spawn().map_err(|_| ())?;
    let process_group = child.id().ok_or(())?;
    Ok((child, ProcessContainment { process_group }))
}

#[cfg(windows)]
fn spawn_contained(
    command: Command,
    process_limit: Option<u32>,
) -> Result<(tokio::process::Child, ProcessContainment), ()> {
    let process_limit = process_limit
        .filter(|value| (1..=MAX_PROCESS_LIMIT).contains(value))
        .ok_or(())?;
    let job = processkit::ProcessGroup::with_options(
        processkit::ProcessGroupOptions::default().max_processes(process_limit),
    )
    .map_err(|_| ())?;
    let child = job.spawn(command).map_err(|_| ())?;
    Ok((child, ProcessContainment { job }))
}

#[cfg(unix)]
impl ProcessContainment {
    fn terminate(&self) {
        let Ok(process_group) = i32::try_from(self.process_group) else {
            return;
        };
        let Some(process_group) = rustix::process::Pid::from_raw(process_group) else {
            return;
        };
        let _ = rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
    }
}

#[cfg(windows)]
impl ProcessContainment {
    fn terminate(&self) {
        let _ = self.job.kill_all();
    }
}

#[cfg(any(unix, windows))]
async fn read_output<R: AsyncRead + Unpin>(
    mut reader: R,
    stream: GuestOutputStream,
    sender: mpsc::Sender<(GuestOutputStream, Vec<u8>)>,
) {
    loop {
        let mut buffer = vec![0_u8; OUTPUT_CHUNK_BYTES];
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(length) => {
                buffer.truncate(length);
                if sender.send((stream, buffer)).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(any(unix, windows))]
async fn write_file(path: &str, content_base64: &str) -> GuestResponse {
    let Ok(content) = BASE64.decode(content_base64) else {
        return rejected(GuestRejection::InvalidRequest);
    };
    if !valid_absolute_path(path) || content.len() > MAX_GUEST_FRAME_BYTES / 2 {
        return rejected(GuestRejection::InvalidRequest);
    }
    let Some(parent) = Path::new(path).parent() else {
        return rejected(GuestRejection::InvalidRequest);
    };
    if tokio::fs::create_dir_all(parent).await.is_err() {
        return rejected(GuestRejection::OperationFailed);
    }
    match tokio::fs::write(path, content).await {
        Ok(()) => GuestResponse::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
        },
        Err(_) => rejected(GuestRejection::OperationFailed),
    }
}

#[cfg(any(unix, windows))]
async fn read_file(path: &str, byte_limit: usize) -> GuestResponse {
    if !valid_absolute_path(path) || byte_limit == 0 || byte_limit > MAX_GUEST_FRAME_BYTES / 2 {
        return rejected(GuestRejection::InvalidRequest);
    }
    let Ok(file) = tokio::fs::File::open(path).await else {
        return rejected(GuestRejection::OperationFailed);
    };
    let mut content = Vec::with_capacity(byte_limit.min(OUTPUT_CHUNK_BYTES));
    let Ok(read_limit) = u64::try_from(byte_limit.saturating_add(1)) else {
        return rejected(GuestRejection::InvalidRequest);
    };
    if file
        .take(read_limit)
        .read_to_end(&mut content)
        .await
        .is_err()
    {
        return rejected(GuestRejection::OperationFailed);
    }
    if content.len() > byte_limit {
        return rejected(GuestRejection::InvalidRequest);
    }
    GuestResponse::ReadFile {
        protocol: GUEST_PROTOCOL_VERSION,
        content_base64: BASE64.encode(content),
    }
}

#[cfg(any(unix, windows))]
fn rejected(kind: GuestRejection) -> GuestResponse {
    GuestResponse::Rejected {
        protocol: GUEST_PROTOCOL_VERSION,
        kind,
    }
}

#[cfg(unix)]
fn valid_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= MAX_TARGET_PATH_BYTES
        && !value.contains("//")
        && value
            .split('/')
            .skip(1)
            .all(|part| !matches!(part, "." | ".."))
        && !value.contains('\0')
}

#[cfg(windows)]
fn valid_absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes.len() <= MAX_TARGET_PATH_BYTES
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !value.contains('/')
        && !value.contains("\\\\")
        && !value.contains('\0')
        && value.split('\\').skip(1).all(|component| {
            !matches!(component, "." | "..")
                && !component.ends_with([' ', '.'])
                && !component
                    .bytes()
                    .any(|byte| matches!(byte, b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|'))
        })
}

#[cfg(any(unix, windows))]
fn valid_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPERATION_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

#[cfg(any(unix, windows))]
fn valid_execution_request(
    program: &str,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
    working_directory: &str,
    timeout_millis: u64,
    output_limit: usize,
    process_limit: Option<u32>,
) -> bool {
    let argv_bytes = arguments.iter().try_fold(program.len(), |bytes, argument| {
        (!argument.contains('\0'))
            .then(|| bytes.checked_add(argument.len()))
            .flatten()
    });
    let environment_bytes = environment
        .iter()
        .try_fold(0_usize, |bytes, (name, value)| {
            let valid = !name.is_empty()
                && name.len() <= MAX_ENVIRONMENT_NAME_BYTES
                && !name.contains('=')
                && !name.chars().any(char::is_control)
                && value.len() <= MAX_ENVIRONMENT_VALUE_BYTES
                && !value.contains('\0');
            valid
                .then(|| bytes.checked_add(name.len())?.checked_add(value.len()))
                .flatten()
        });
    valid_absolute_path(program)
        && valid_absolute_path(working_directory)
        && arguments.len() <= MAX_EXECUTION_ARGUMENTS
        && argv_bytes.is_some_and(|bytes| bytes <= MAX_EXECUTION_ARGV_BYTES)
        && environment.len() <= MAX_ENVIRONMENT_VARIABLES
        && environment_bytes.is_some_and(|bytes| bytes <= MAX_ENVIRONMENT_BYTES)
        && (1..=MAX_COMMAND_TIMEOUT_MILLIS).contains(&timeout_millis)
        && (1..=MAX_EXECUTION_OUTPUT_BYTES).contains(&output_limit)
        && valid_process_limit(process_limit)
}

#[cfg(unix)]
const fn valid_process_limit(process_limit: Option<u32>) -> bool {
    process_limit.is_none()
}

#[cfg(windows)]
fn valid_process_limit(process_limit: Option<u32>) -> bool {
    process_limit.is_some_and(|value| (1..=MAX_PROCESS_LIMIT).contains(&value))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATION_ONE: &str = "00000000-0000-4000-8000-000000000001";

    #[cfg(any(unix, windows))]
    #[test]
    fn protocol_v3_rejects_every_prior_wire_version() {
        assert_eq!(GUEST_PROTOCOL_VERSION, 3);
        for protocol in [1, 2] {
            let request = GuestRequest::Probe {
                protocol,
                operation_id: OPERATION_ONE.into(),
            };
            assert_eq!(
                immediate_rejection(&request),
                Some(GuestResponse::Rejected {
                    protocol: GUEST_PROTOCOL_VERSION,
                    kind: GuestRejection::UnsupportedProtocol,
                })
            );
        }
        let current = GuestRequest::Probe {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
        };
        assert_eq!(immediate_rejection(&current), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_id_map_is_one_canonical_nonroot_range_covering_every_control_identity() {
        for valid in ["         0     231072      65534\n", "0 4294901762 65534\n"] {
            assert!(valid_local_id_map(valid), "valid map: {valid:?}");
        }

        for invalid in [
            "",
            "0 231072 65534",
            "0 0 65534\n",
            "1 231072 65534\n",
            "0 231072 65533\n",
            "0 4294901763 65534\n",
            "0 231072 65534 trailing\n",
            "0 231072 65534\n1 296606 1\n",
            "0 1000 1\n1 100000 65536\n",
            "00 231072 65534\n",
            "0 0231072 65534\n",
            "0 231072 +65534\n",
            "0 231072 -1\n",
        ] {
            assert!(!valid_local_id_map(invalid), "invalid map: {invalid:?}");
        }
        assert!(!valid_local_id_map(&format!(
            "0 231072 {}\n",
            "1".repeat(MAX_LOCAL_ID_MAP_BYTES)
        )));
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn write_file_creates_the_attempt_scoped_parent_directory() {
        let root = std::env::temp_dir().join(format!(
            "automata-guest-write-parent-{}",
            std::process::id()
        ));
        let target = root.join("attempt").join("commands").join("probe.txt");
        let target = target.to_string_lossy();
        assert!(matches!(
            write_file(&target, &BASE64.encode(b"probe")).await,
            GuestResponse::WriteFile {
                protocol: GUEST_PROTOCOL_VERSION
            }
        ));
        assert_eq!(tokio::fs::read(target.as_ref()).await.unwrap(), b"probe");
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_execution_requires_an_explicit_bounded_process_limit() {
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let valid = |process_limit| {
            valid_execution_request(
                r"C:\Windows\System32\cmd.exe",
                &[],
                &BTreeMap::new(),
                &working_directory,
                1_000,
                1_024,
                process_limit,
            )
        };
        assert!(valid(Some(8)));
        assert!(!valid(None));
        assert!(!valid(Some(0)));
        assert!(!valid(Some(MAX_PROCESS_LIMIT + 1)));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_nested_job_enforces_the_command_tree_process_ceiling() {
        let working_directory = std::env::temp_dir().to_string_lossy().into_owned();
        let arguments = vec![
            "/d".to_owned(),
            "/c".to_owned(),
            r"C:\Windows\System32\ping.exe -n 1 127.0.0.1 >nul".to_owned(),
        ];
        let limited = execute(
            r"C:\Windows\System32\cmd.exe".to_owned(),
            arguments.clone(),
            BTreeMap::new(),
            working_directory.clone(),
            5_000,
            4_096,
            Some(1),
            false,
        )
        .await;
        assert!(matches!(
            limited,
            GuestResponse::Exec {
                termination: GuestTermination::Exited(1),
                ..
            }
        ));

        let admitted = execute(
            r"C:\Windows\System32\cmd.exe".to_owned(),
            arguments,
            BTreeMap::new(),
            working_directory,
            5_000,
            4_096,
            Some(2),
            false,
        )
        .await;
        assert!(matches!(
            admitted,
            GuestResponse::Exec {
                termination: GuestTermination::Exited(0),
                ..
            }
        ));
    }

    #[test]
    fn frame_round_trip_redacts_debug() {
        let request = GuestRequest::Exec {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
            program: "/bin/echo".into(),
            arguments: vec!["secret-argument".into()],
            environment: BTreeMap::from([("TOKEN".into(), "secret-value".into())]),
            working_directory: "/tmp".into(),
            timeout_millis: 1_000,
            output_limit: 1_024,
            process_limit: None,
        };
        let frame = encode_frame(&request).expect("frame");
        assert_eq!(
            decode_frame::<GuestRequest>(&frame).expect("decode"),
            request
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains("secret-argument"));
        assert!(!debug.contains("secret-value"));
    }

    #[test]
    fn rejects_trailing_and_oversized_frames() {
        let response = GuestResponse::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
        };
        let mut frame = encode_frame(&response).expect("frame");
        frame.push(0);
        assert!(decode_frame::<GuestResponse>(&frame).is_err());
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn one_shot_stdio_rejects_trailing_input() {
        let request = GuestRequest::Probe {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
        };
        let mut input = encode_frame(&request).expect("request frame");
        input.push(0);

        assert!(matches!(
            read_one_shot_request(&mut input.as_slice()).await,
            Err(GuestProtocolError::InvalidFrame)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hello_returns_only_the_baked_identity_and_fresh_nonce() {
        let identity = GuestIdentity {
            profile_id: "automata.dev/macos-15-arm64-vm-v1".into(),
            guest_agent_sha256: "11".repeat(32),
            macos_version: "15.7".into(),
            macos_build: "24G222".into(),
            architecture: "arm64".into(),
            job_uid: 502,
            job_gid: 502,
            process_limit: 512,
        };
        let request = GuestRequest::Hello {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
            nonce: "fresh-nonce".into(),
        };
        assert_eq!(
            handle_request(request, Some(identity.clone()), false).await,
            GuestResponse::Hello {
                protocol: GUEST_PROTOCOL_VERSION,
                nonce: "fresh-nonce".into(),
                profile_id: identity.profile_id,
                guest_agent_sha256: identity.guest_agent_sha256,
                macos_version: identity.macos_version,
                macos_build: identity.macos_build,
                architecture: identity.architecture,
                job_uid: identity.job_uid,
                job_gid: identity.job_gid,
                process_limit: identity.process_limit,
            }
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_configuration_requires_the_exact_baked_vm_identity() {
        let identity = GuestIdentity {
            profile_id: "automata.dev/macos-15-arm64-vm-v1".into(),
            guest_agent_sha256: "11".repeat(32),
            macos_version: "15.7".into(),
            macos_build: "24G222".into(),
            architecture: "arm64".into(),
            job_uid: 502,
            job_gid: 502,
            process_limit: 512,
        };
        let request = GuestRequest::Configure {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
            process_limit: 511,
        };
        assert_eq!(
            handle_request(request.clone(), Some(identity), false).await,
            rejected(GuestRejection::InvalidRequest)
        );
        assert_eq!(
            handle_request(request, None, false).await,
            rejected(GuestRejection::InvalidRequest)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replay_is_exact_and_changed_material_fails_closed() {
        let path =
            std::env::temp_dir().join(format!("automata-guest-replay-{}", std::process::id()));
        let path = path.to_string_lossy().into_owned();
        let replay = Arc::new(Mutex::new(ReplayCache::default()));
        let request = GuestRequest::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
            path: path.clone(),
            content_base64: BASE64.encode(b"first"),
        };

        assert!(matches!(
            replay_request(request.clone(), Arc::clone(&replay), None).await,
            GuestResponse::WriteFile { .. }
        ));
        tokio::fs::write(&path, b"outside change")
            .await
            .expect("replace fixture");
        assert!(matches!(
            replay_request(request, Arc::clone(&replay), None).await,
            GuestResponse::WriteFile { .. }
        ));
        assert_eq!(
            tokio::fs::read(&path).await.expect("read fixture"),
            b"outside change"
        );

        let changed = GuestRequest::WriteFile {
            protocol: GUEST_PROTOCOL_VERSION,
            operation_id: OPERATION_ONE.into(),
            path: path.clone(),
            content_base64: BASE64.encode(b"different"),
        };
        assert_eq!(
            replay_request(changed, replay, None).await,
            rejected(GuestRejection::OperationConflict)
        );
        tokio::fs::remove_file(path).await.expect("remove fixture");
    }

    #[cfg(unix)]
    #[test]
    fn execution_request_budgets_match_the_public_endpoint_contract() {
        assert!(valid_operation_id(OPERATION_ONE));
        assert!(!valid_operation_id("line\nbreak"));
        assert!(valid_execution_request(
            "/bin/true",
            &[],
            &BTreeMap::new(),
            "/tmp",
            1,
            1,
            None,
        ));
        assert!(!valid_execution_request(
            "/bin/true",
            &vec![String::new(); MAX_EXECUTION_ARGUMENTS + 1],
            &BTreeMap::new(),
            "/tmp",
            1,
            1,
            None,
        ));
        assert!(!valid_execution_request(
            "/bin/true",
            &[],
            &BTreeMap::new(),
            "/tmp",
            MAX_COMMAND_TIMEOUT_MILLIS + 1,
            1,
            None,
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_retains_output_observed_before_process_termination() {
        let response = execute(
            "/bin/sh".into(),
            vec!["-c".into(), "printf retained; exec /bin/sleep 5".into()],
            BTreeMap::new(),
            "/tmp".into(),
            100,
            1_024,
            None,
            false,
        )
        .await;
        let GuestResponse::Exec {
            termination,
            records,
            truncated,
            ..
        } = response
        else {
            panic!("command should reach a typed termination");
        };
        let output = records
            .into_iter()
            .filter(|record| !record.is_end_of_stream())
            .flat_map(|record| record.data().expect("base64 output"))
            .collect::<Vec<_>>();
        assert_eq!(termination, GuestTermination::TimedOut);
        assert!(!truncated);
        assert_eq!(output, b"retained");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bounded_read_rejects_content_past_the_requested_limit() {
        let path = std::env::temp_dir().join(format!(
            "automata-guest-bounded-read-{}",
            std::process::id()
        ));
        tokio::fs::write(&path, vec![7_u8; OUTPUT_CHUNK_BYTES * 2])
            .await
            .expect("write fixture");
        assert_eq!(
            read_file(&path.to_string_lossy(), 8).await,
            rejected(GuestRejection::InvalidRequest)
        );
        tokio::fs::remove_file(path).await.expect("remove fixture");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn abstract_listener_is_connectable_without_a_filesystem_entry() {
        let socket =
            std::path::PathBuf::from(format!("@automata-ci-guest-test-{}", std::process::id()));
        let listener = bind_listener(&socket).await.expect("abstract listener");
        assert!(probe(&socket));
        assert!(tokio::fs::metadata(&socket).await.is_err());
        drop(listener);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_exited_process_leader_cannot_leave_background_work_running() {
        let marker =
            std::env::temp_dir().join(format!("automata-guest-descendant-{}", std::process::id()));
        let _ = tokio::fs::remove_file(&marker).await;
        let command = format!(
            "(/bin/sleep 1; /usr/bin/touch '{}') & exit 0",
            marker.display()
        );
        let response = execute(
            "/bin/sh".into(),
            vec!["-c".into(), command],
            BTreeMap::new(),
            "/tmp".into(),
            5_000,
            1_024,
            None,
            false,
        )
        .await;
        assert!(matches!(
            response,
            GuestResponse::Exec {
                termination: GuestTermination::Exited(0),
                ..
            }
        ));
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert!(
            tokio::fs::metadata(&marker).await.is_err(),
            "the background descendant survived its process-group leader"
        );
    }
}
