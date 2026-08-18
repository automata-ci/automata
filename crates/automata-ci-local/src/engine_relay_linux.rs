//! Linux-container-only attested relay for the local Docker Engine socket.
//!
//! The image contract has no configurable aliases: the host socket is
//! `/run/automata-host-engine/docker.sock`, the current canonical binding is
//! `/run/automata-engine-binding/binding.json`, and the published socket is
//! `/run/automata-engine/docker.sock`. The binding carries only schema 1,
//! installation UUID/full selector key/Compose project/plan digest, and the
//! selected Engine ID/API/server version/Linux-amd64 tuple.

use std::{
    fmt,
    fs::{self, File},
    future::Future,
    io::{self, Read as _},
    os::fd::{AsRawFd as _, OwnedFd},
    os::unix::net::UnixListener as StdUnixListener,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use bollard::{ClientVersion, Docker};
use rustix::{
    fs::{self as rustix_fs, AtFlags, FileType, FlockOperation, Mode, OFlags, flock},
    process::{self as rustix_process, Gid, Uid},
    thread as rustix_thread,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
    signal::unix::{Signal, SignalKind, signal},
    sync::watch,
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};
use tokio_util::sync::CancellationToken;

use crate::{
    InstallationId, LIFECYCLE_ENGINE_ID_MAXIMUM_BYTES, LIFECYCLE_SERVER_VERSION_MAXIMUM_BYTES,
    MIN_DOCKER_ENGINE_MAJOR, valid_lifecycle_engine_id, valid_lifecycle_server_version,
};

type Result<T, E = RelayError> = std::result::Result<T, E>;

#[derive(Debug)]
pub(super) struct RelayError {
    message: String,
}

impl RelayError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn with_source(context: impl fmt::Display, source: impl fmt::Display) -> Self {
        Self::new(format!("{context}: {source}"))
    }

    fn context(self, context: impl fmt::Display) -> Self {
        Self::with_source(context, self)
    }

    pub(super) fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

trait RelayContext<T> {
    fn context(self, context: impl fmt::Display) -> Result<T>;

    fn with_context<C>(self, context: C) -> Result<T>
    where
        C: FnOnce() -> String;
}

impl<T, E> RelayContext<T> for std::result::Result<T, E>
where
    E: fmt::Display,
{
    fn context(self, context: impl fmt::Display) -> Result<T> {
        self.map_err(|error| RelayError::with_source(context, error))
    }

    fn with_context<C>(self, context: C) -> Result<T>
    where
        C: FnOnce() -> String,
    {
        self.map_err(|error| RelayError::with_source(context(), error))
    }
}

impl<T> RelayContext<T> for Option<T> {
    fn context(self, context: impl fmt::Display) -> Result<T> {
        self.ok_or_else(|| RelayError::new(context.to_string()))
    }

    fn with_context<C>(self, context: C) -> Result<T>
    where
        C: FnOnce() -> String,
    {
        self.ok_or_else(|| RelayError::new(context()))
    }
}

macro_rules! relay_error {
    ($($argument:tt)*) => {
        RelayError::new(format!($($argument)*))
    };
}

macro_rules! bail {
    ($($argument:tt)*) => {
        return Err(relay_error!($($argument)*))
    };
}

macro_rules! ensure {
    ($condition:expr, $($argument:tt)*) => {
        if !$condition {
            bail!($($argument)*);
        }
    };
}

const UPSTREAM_DIRECTORY: &str = "/run/automata-host-engine";
const DOWNSTREAM_DIRECTORY: &str = "/run/automata-engine";
const BINDING_DIRECTORY: &str = "/run/automata-engine-binding";
const BINDING_FILE_NAME: &str = "binding.json";
const SOCKET_NAME: &str = "docker.sock";
const RELAY_UID: u32 = 65_532;
const RELAY_GID: u32 = 65_532;
const UPSTREAM_DIRECTORY_MODE: u32 = 0o755;
const DOWNSTREAM_DIRECTORY_MODE: u32 = 0o700;
const BINDING_DIRECTORY_MODE: u32 = 0o555;
const BINDING_FILE_MODE: u32 = 0o444;
const UPSTREAM_SOCKET_MODE: u32 = 0o660;
const DOWNSTREAM_SOCKET_MODE: u32 = 0o600;
const MAX_BINDING_BYTES: usize = 4 * 1_024;
const RELAY_BINDING_SCHEMA: u32 = 1;
const FIXED_ENGINE_API: &str = "1.48";
const FIXED_ENGINE_API_MAJOR: u16 = 1;
const FIXED_ENGINE_API_MINOR: u16 = 48;
const ENGINE_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;
const CAP_SETPCAP: u32 = 8;
const REQUIRED_STARTUP_CAPABILITIES: u64 =
    (1_u64 << CAP_SETGID) | (1_u64 << CAP_SETUID) | (1_u64 << CAP_SETPCAP);

const PRODUCTION_LIMITS: RelayLimits = RelayLimits {
    maximum_connections: 32,
    connect_timeout: Duration::from_secs(5),
    write_timeout: Duration::from_secs(30),
    idle_timeout: Duration::from_mins(30),
    shutdown_timeout: Duration::from_secs(5),
    copy_buffer_bytes: 16 * 1_024,
};

pub(crate) fn lifecycle_contract() -> serde_json::Value {
    serde_json::json!({
        "architecture": "amd64",
        "binding_directory": BINDING_DIRECTORY,
        "binding_directory_gid": 0,
        "binding_directory_mode": format!("{:04o}", BINDING_DIRECTORY_MODE),
        "binding_directory_uid": 0,
        "binding_file": format!("{BINDING_DIRECTORY}/{BINDING_FILE_NAME}"),
        "binding_file_gid": 0,
        "binding_file_maximum_bytes": MAX_BINDING_BYTES,
        "binding_file_mode": format!("{:04o}", BINDING_FILE_MODE),
        "binding_file_uid": 0,
        "binding_schema": RELAY_BINDING_SCHEMA,
        "downstream_directory": DOWNSTREAM_DIRECTORY,
        "downstream_directory_gid": RELAY_GID,
        "downstream_directory_mode": format!("{:04o}", DOWNSTREAM_DIRECTORY_MODE),
        "downstream_directory_uid": RELAY_UID,
        "downstream_socket": format!("{DOWNSTREAM_DIRECTORY}/{SOCKET_NAME}"),
        "downstream_socket_gid": RELAY_GID,
        "downstream_socket_mode": format!("{:04o}", DOWNSTREAM_SOCKET_MODE),
        "downstream_socket_uid": RELAY_UID,
        "engine_api": FIXED_ENGINE_API,
        "engine_id_maximum_bytes": LIFECYCLE_ENGINE_ID_MAXIMUM_BYTES,
        "engine_request_timeout_seconds": ENGINE_REQUEST_TIMEOUT.as_secs(),
        "gid": RELAY_GID,
        "initial_capabilities": ["SETGID", "SETUID", "SETPCAP"],
        "minimum_engine_major": MIN_DOCKER_ENGINE_MAJOR,
        "operating_system": "linux",
        "protocol_limits": {
            "connect_timeout_seconds": PRODUCTION_LIMITS.connect_timeout.as_secs(),
            "copy_buffer_bytes": PRODUCTION_LIMITS.copy_buffer_bytes,
            "idle_timeout_seconds": PRODUCTION_LIMITS.idle_timeout.as_secs(),
            "maximum_connections": PRODUCTION_LIMITS.maximum_connections,
            "shutdown_timeout_seconds": PRODUCTION_LIMITS.shutdown_timeout.as_secs(),
            "write_timeout_seconds": PRODUCTION_LIMITS.write_timeout.as_secs(),
        },
        "server_version_maximum_bytes": LIFECYCLE_SERVER_VERSION_MAXIMUM_BYTES,
        "uid": RELAY_UID,
        "upstream_directory": UPSTREAM_DIRECTORY,
        "upstream_directory_gid": 0,
        "upstream_directory_mode": format!("{:04o}", UPSTREAM_DIRECTORY_MODE),
        "upstream_directory_uid": 0,
        "upstream_socket": format!("{UPSTREAM_DIRECTORY}/{SOCKET_NAME}"),
        "upstream_socket_gid": "adopted-host-socket-group",
        "upstream_socket_mode": format!("{:04o}", UPSTREAM_SOCKET_MODE),
        "upstream_socket_uid": 0,
    })
}

#[derive(Clone, Copy)]
struct RelayLimits {
    maximum_connections: usize,
    connect_timeout: Duration,
    write_timeout: Duration,
    idle_timeout: Duration,
    shutdown_timeout: Duration,
    copy_buffer_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RelayBinding {
    schema: u32,
    installation: BoundInstallation,
    engine: BoundEngine,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundInstallation {
    id: String,
    selector_key: String,
    compose_project: String,
    plan_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundEngine {
    id: String,
    api_version: String,
    server_version: String,
    operating_system: String,
    architecture: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FixedEngineFacts {
    engine_id: String,
    selected_api_version: String,
    server_version: String,
    operating_system: String,
    architecture: String,
}

async fn inspect_fixed_unix_engine(socket: &Path) -> Result<FixedEngineFacts> {
    let path = socket
        .to_str()
        .context("fixed engine socket path is not UTF-8")?;
    let client_version = ClientVersion {
        major_version: usize::from(FIXED_ENGINE_API_MAJOR),
        minor_version: usize::from(FIXED_ENGINE_API_MINOR),
    };
    let docker = Docker::connect_with_unix(path, ENGINE_REQUEST_TIMEOUT.as_secs(), &client_version)
        .context("failed to connect to the fixed engine socket")?;
    ensure!(
        docker.client_version() == client_version,
        "fixed engine client did not retain API 1.48"
    );
    let (info, version) = timeout(ENGINE_REQUEST_TIMEOUT, async {
        tokio::try_join!(docker.info(), docker.version())
    })
    .await
    .context("fixed engine attestation timed out")?
    .context("fixed engine attestation request failed")?;

    let info_server_version = info
        .server_version
        .context("fixed engine info omitted its server version")?;
    let server_version = version
        .version
        .context("fixed engine version omitted its server version")?;
    let info_architecture = info
        .architecture
        .context("fixed engine info omitted its architecture")?;
    let architecture = version
        .arch
        .context("fixed engine version omitted its architecture")?;
    let info_operating_system = info
        .os_type
        .context("fixed engine info omitted its operating system")?;
    let operating_system = version
        .os
        .context("fixed engine version omitted its operating system")?;
    let minimum_api = version
        .min_api_version
        .context("fixed engine version omitted its minimum API")?;
    let maximum_api = version
        .api_version
        .context("fixed engine version omitted its maximum API")?;
    let engine_id = info.id.context("fixed engine info omitted its engine ID")?;

    let info_architecture = normalize_engine_architecture(&info_architecture)
        .context("fixed engine info reported an unsupported architecture")?;
    let architecture = normalize_engine_architecture(&architecture)
        .context("fixed engine version reported an unsupported architecture")?;
    ensure!(
        info_server_version == server_version
            && info_architecture == architecture
            && info_operating_system == operating_system,
        "fixed engine returned inconsistent info and version facts"
    );
    ensure!(
        operating_system == "linux"
            && architecture == "amd64"
            && valid_lifecycle_engine_id(&engine_id)
            && valid_lifecycle_server_version(&server_version)
            && api_includes_fixed(&minimum_api, &maximum_api),
        "fixed engine does not satisfy the Linux/amd64, Engine 28, API 1.48 contract"
    );

    Ok(FixedEngineFacts {
        engine_id,
        selected_api_version: FIXED_ENGINE_API.to_owned(),
        server_version,
        operating_system,
        architecture: architecture.to_owned(),
    })
}

struct DirectoryAnchor {
    descriptor: OwnedFd,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl DirectoryAnchor {
    fn open(path: &Path, owner: u32, group: u32, mode: u32) -> Result<Self> {
        let descriptor = rustix_fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("failed to open fixed relay directory {}", path.display()))?;
        let metadata = rustix_fs::fstat(&descriptor).with_context(|| {
            format!("failed to inspect fixed relay directory {}", path.display())
        })?;
        ensure!(
            FileType::from_raw_mode(metadata.st_mode) == FileType::Directory,
            "fixed relay path {} is not a directory",
            path.display()
        );
        ensure!(
            metadata.st_uid == owner
                && metadata.st_gid == group
                && permission_bits(metadata.st_mode) == mode,
            "fixed relay directory {} has the wrong owner, group, or mode",
            path.display()
        );
        Ok(Self {
            descriptor,
            path: path.to_owned(),
            device: metadata.st_dev,
            inode: metadata.st_ino,
        })
    }

    fn entry_path(&self, name: &str) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}/{name}",
            self.descriptor.as_raw_fd(),
        ))
    }

    fn entry_metadata(&self, name: &str) -> Result<Option<rustix_fs::Stat>> {
        match rustix_fs::statat(&self.descriptor, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(error) => Err(io::Error::from(error)).with_context(|| {
                format!(
                    "failed to inspect fixed relay entry in {}",
                    self.path.display()
                )
            }),
        }
    }

    fn revalidate(&self, owner: u32, group: u32, mode: u32) -> Result<()> {
        let reopened = Self::open(&self.path, owner, group, mode)?;
        ensure!(
            reopened.device == self.device && reopened.inode == self.inode,
            "fixed relay directory {} changed",
            self.path.display()
        );
        Ok(())
    }

    fn lock_exclusive(&self) -> Result<()> {
        flock(&self.descriptor, FlockOperation::NonBlockingLockExclusive)
            .map_err(io::Error::from)
            .with_context(|| {
                format!(
                    "another engine relay already owns fixed directory {}",
                    self.path.display()
                )
            })
    }
}

struct PreparedRelay {
    upstream: Arc<UpstreamSocket>,
    downstream: DirectoryAnchor,
    binding: RelayBinding,
}

struct UpstreamSocket {
    anchor: DirectoryAnchor,
    authority: [u64; 6],
    socket_owner: u32,
    directory_owner: u32,
    directory_group: u32,
    directory_mode: u32,
}

impl UpstreamSocket {
    fn path(&self) -> PathBuf {
        self.anchor.entry_path(SOCKET_NAME)
    }

    fn revalidate(&self) -> Result<()> {
        self.anchor.revalidate(
            self.directory_owner,
            self.directory_group,
            self.directory_mode,
        )?;
        let current = require_upstream_socket(&self.anchor, self.socket_owner)?;
        ensure!(
            upstream_authority(&current) == self.authority,
            "fixed upstream engine socket authority changed"
        );
        Ok(())
    }
}

struct BoundSocket {
    anchor: DirectoryAnchor,
    listener: Option<StdUnixListener>,
    device: u64,
    inode: u64,
    cleaned: bool,
}

impl BoundSocket {
    fn take_listener(&mut self) -> Result<StdUnixListener> {
        self.listener
            .take()
            .context("fixed downstream relay listener was already consumed")
    }

    fn cleanup(&mut self) -> Result<()> {
        self.listener.take();
        if self.cleaned {
            return Ok(());
        }
        let Some(metadata) = self.anchor.entry_metadata(SOCKET_NAME)? else {
            bail!("fixed downstream relay socket disappeared before cleanup");
        };
        ensure!(
            metadata.st_dev == self.device && metadata.st_ino == self.inode,
            "fixed downstream relay socket changed before cleanup"
        );
        rustix_fs::unlinkat(&self.anchor.descriptor, SOCKET_NAME, AtFlags::empty())
            .map_err(io::Error::from)
            .context("failed to remove the exact downstream relay socket")?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        self.listener.take();
        if self.cleaned {
            return;
        }
        let Ok(Some(metadata)) = self.anchor.entry_metadata(SOCKET_NAME) else {
            return;
        };
        if metadata.st_dev == self.device
            && metadata.st_ino == self.inode
            && rustix_fs::unlinkat(&self.anchor.descriptor, SOCKET_NAME, AtFlags::empty()).is_ok()
        {
            self.cleaned = true;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionEnd {
    Complete,
    Cancelled,
    AuthorityChanged,
    ConnectFailed,
    Idle,
    IoFailed,
}

pub(super) fn run_process() -> Result<()> {
    require_pre_runtime_dispatch()?;
    let prepared = prepare_process()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to construct the engine relay runtime")?
        .block_on(run_until_shutdown(prepared))
}

pub(super) fn check() -> Result<()> {
    require_pre_runtime_dispatch()?;
    require_single_threaded_root_process()?;
    drop_process_privileges(&[])?;
    let binding = load_binding()?;
    let downstream = DirectoryAnchor::open(
        Path::new(DOWNSTREAM_DIRECTORY),
        RELAY_UID,
        RELAY_GID,
        DOWNSTREAM_DIRECTORY_MODE,
    )?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to construct the engine relay check runtime")?
        .block_on(check_downstream(binding, downstream))
}

fn require_pre_runtime_dispatch() -> Result<()> {
    ensure!(
        tokio::runtime::Handle::try_current().is_err(),
        "fixed engine relay commands must be dispatched before constructing a Tokio runtime"
    );
    Ok(())
}

async fn check_downstream(binding: RelayBinding, downstream: DirectoryAnchor) -> Result<()> {
    let initial = require_downstream_socket(&downstream)?;
    let facts = inspect_fixed_unix_engine(&downstream.entry_path(SOCKET_NAME))
        .await
        .context("fixed downstream engine attestation failed")?;
    downstream.revalidate(RELAY_UID, RELAY_GID, DOWNSTREAM_DIRECTORY_MODE)?;
    let revalidated = require_downstream_socket(&downstream)?;
    ensure!(
        socket_authority(&initial) == socket_authority(&revalidated),
        "fixed downstream engine socket changed during attestation"
    );
    binding.verify_engine(&facts)
}

fn prepare_process() -> Result<PreparedRelay> {
    require_single_threaded_root_process()?;
    let upstream = DirectoryAnchor::open(
        Path::new(UPSTREAM_DIRECTORY),
        Uid::ROOT.as_raw(),
        Gid::ROOT.as_raw(),
        UPSTREAM_DIRECTORY_MODE,
    )?;
    let upstream_metadata = require_upstream_socket(&upstream, Uid::ROOT.as_raw())?;
    drop_process_privileges(&[Gid::from_raw(upstream_metadata.st_gid)])?;
    upstream.revalidate(
        Uid::ROOT.as_raw(),
        Gid::ROOT.as_raw(),
        UPSTREAM_DIRECTORY_MODE,
    )?;
    let revalidated_upstream = require_upstream_socket(&upstream, Uid::ROOT.as_raw())?;
    ensure!(
        same_upstream_authority(&upstream_metadata, &revalidated_upstream),
        "fixed upstream engine socket changed during privilege reduction"
    );
    let binding = load_binding()?;
    let downstream = DirectoryAnchor::open(
        Path::new(DOWNSTREAM_DIRECTORY),
        RELAY_UID,
        RELAY_GID,
        DOWNSTREAM_DIRECTORY_MODE,
    )?;
    downstream.lock_exclusive()?;
    Ok(PreparedRelay {
        upstream: Arc::new(UpstreamSocket {
            anchor: upstream,
            authority: upstream_authority(&upstream_metadata),
            socket_owner: Uid::ROOT.as_raw(),
            directory_owner: Uid::ROOT.as_raw(),
            directory_group: Gid::ROOT.as_raw(),
            directory_mode: UPSTREAM_DIRECTORY_MODE,
        }),
        downstream,
        binding,
    })
}

fn require_single_threaded_root_process() -> Result<()> {
    ensure!(
        rustix_process::getuid().is_root()
            && rustix_process::geteuid().is_root()
            && rustix_process::getgid().is_root()
            && rustix_process::getegid().is_root(),
        "engine relay must start with real and effective UID/GID 0"
    );
    let mut tasks =
        fs::read_dir("/proc/self/task").context("engine relay requires a mounted Linux procfs")?;
    let first = tasks
        .next()
        .transpose()
        .context("failed to inspect the relay process thread set")?;
    let second = tasks
        .next()
        .transpose()
        .context("failed to inspect the relay process thread set")?;
    ensure!(
        first.is_some() && second.is_none(),
        "engine relay privilege reduction requires a single-threaded process"
    );
    verify_initial_capability_state()?;
    Ok(())
}

fn verify_initial_capability_state() -> Result<()> {
    let status = fs::read_to_string("/proc/self/status")
        .context("engine relay requires readable Linux process status")?;
    ensure!(
        initial_capability_state_is_exact(&status),
        "engine relay must start with exactly SETGID, SETUID, and SETPCAP capabilities"
    );
    Ok(())
}

fn initial_capability_state_is_exact(status: &str) -> bool {
    capability_field(status, "CapInh") == Some(0)
        && capability_field(status, "CapPrm") == Some(REQUIRED_STARTUP_CAPABILITIES)
        && capability_field(status, "CapEff") == Some(REQUIRED_STARTUP_CAPABILITIES)
        && capability_field(status, "CapBnd") == Some(REQUIRED_STARTUP_CAPABILITIES)
        && capability_field(status, "CapAmb") == Some(0)
}

fn require_upstream_socket(
    anchor: &DirectoryAnchor,
    expected_owner: u32,
) -> Result<rustix_fs::Stat> {
    let metadata = anchor
        .entry_metadata(SOCKET_NAME)?
        .context("fixed upstream engine socket is absent")?;
    ensure!(
        FileType::from_raw_mode(metadata.st_mode) == FileType::Socket,
        "fixed upstream engine path is not a Unix socket"
    );
    ensure!(
        metadata.st_uid == expected_owner
            && permission_bits(metadata.st_mode) == UPSTREAM_SOCKET_MODE,
        "fixed upstream engine socket must be root-owned with mode 0660"
    );
    ensure!(
        metadata.st_nlink == 1,
        "fixed upstream engine socket must have exactly one filesystem link"
    );
    ensure!(
        metadata.st_gid != u32::MAX,
        "fixed upstream engine socket has an invalid group"
    );
    Ok(metadata)
}

fn require_downstream_socket(anchor: &DirectoryAnchor) -> Result<rustix_fs::Stat> {
    let metadata = anchor
        .entry_metadata(SOCKET_NAME)?
        .context("fixed downstream engine socket is absent")?;
    ensure!(
        downstream_socket_is_exact(&metadata),
        "fixed downstream engine socket has the wrong type, owner, group, mode, or link count"
    );
    Ok(metadata)
}

fn load_binding() -> Result<RelayBinding> {
    let directory = DirectoryAnchor::open(
        Path::new(BINDING_DIRECTORY),
        Uid::ROOT.as_raw(),
        Gid::ROOT.as_raw(),
        BINDING_DIRECTORY_MODE,
    )?;
    let descriptor = rustix_fs::openat(
        &directory.descriptor,
        BINDING_FILE_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)
    .context("failed to open the fixed engine relay binding")?;
    let initial = rustix_fs::fstat(&descriptor)
        .map_err(io::Error::from)
        .context("failed to inspect the fixed engine relay binding")?;
    ensure!(
        FileType::from_raw_mode(initial.st_mode) == FileType::RegularFile
            && initial.st_uid == Uid::ROOT.as_raw()
            && initial.st_gid == Gid::ROOT.as_raw()
            && permission_bits(initial.st_mode) == BINDING_FILE_MODE
            && initial.st_nlink == 1,
        "fixed engine relay binding has the wrong type, owner, group, mode, or link count"
    );
    let length = usize::try_from(initial.st_size)
        .ok()
        .filter(|length| *length > 0 && *length <= MAX_BINDING_BYTES)
        .context("fixed engine relay binding has an invalid length")?;
    let mut bytes = Vec::with_capacity(length);
    File::from(descriptor)
        .take(u64::try_from(MAX_BINDING_BYTES + 1).expect("binding limit fits in u64"))
        .read_to_end(&mut bytes)
        .context("failed to read the fixed engine relay binding")?;
    ensure!(
        bytes.len() == length,
        "fixed engine relay binding changed while it was read"
    );
    directory.revalidate(
        Uid::ROOT.as_raw(),
        Gid::ROOT.as_raw(),
        BINDING_DIRECTORY_MODE,
    )?;
    let current = directory
        .entry_metadata(BINDING_FILE_NAME)?
        .context("fixed engine relay binding disappeared while it was read")?;
    ensure!(
        file_authority(&initial) == file_authority(&current),
        "fixed engine relay binding changed while it was read"
    );
    decode_binding(&bytes)
}

fn decode_binding(bytes: &[u8]) -> Result<RelayBinding> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_BINDING_BYTES,
        "fixed engine relay binding has an invalid length"
    );
    let binding: RelayBinding = serde_json::from_slice(bytes)
        .context("fixed engine relay binding is not the current canonical schema")?;
    binding.validate()?;
    let mut canonical = serde_json::to_vec(&binding)
        .context("failed to canonicalize the fixed engine relay binding")?;
    canonical.push(b'\n');
    ensure!(
        bytes == canonical,
        "fixed engine relay binding is not canonically encoded"
    );
    Ok(binding)
}

impl RelayBinding {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == RELAY_BINDING_SCHEMA,
            "unsupported fixed engine relay binding schema"
        );
        ensure!(
            InstallationId::parse_canonical(&self.installation.id).is_some(),
            "fixed engine relay binding has an invalid installation ID"
        );
        ensure!(
            canonical_digest(&self.installation.selector_key)
                && canonical_digest(&self.installation.plan_digest),
            "fixed engine relay binding has an invalid installation digest"
        );
        ensure!(
            self.installation.compose_project
                == format!("automata-local-{}", &self.installation.selector_key[..32]),
            "fixed engine relay binding has an inconsistent Compose project"
        );
        ensure!(
            valid_lifecycle_engine_id(&self.engine.id),
            "fixed engine relay binding has an invalid engine ID"
        );
        ensure!(
            self.engine.api_version == FIXED_ENGINE_API,
            "fixed engine relay binding has an invalid engine API version"
        );
        ensure!(
            valid_lifecycle_server_version(&self.engine.server_version),
            "fixed engine relay binding has an invalid engine server version"
        );
        ensure!(
            self.engine.operating_system == "linux" && self.engine.architecture == "amd64",
            "fixed engine relay binding has an unsupported engine platform"
        );
        Ok(())
    }

    fn verify_engine(&self, facts: &FixedEngineFacts) -> Result<()> {
        ensure!(
            facts.engine_id == self.engine.id
                && facts.selected_api_version == self.engine.api_version
                && facts.server_version == self.engine.server_version
                && facts.operating_system == self.engine.operating_system
                && facts.architecture == self.engine.architecture,
            "Docker Engine facts do not match the fixed relay binding"
        );
        Ok(())
    }
}

fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_canonical_api_version(value: &str) -> Option<(u16, u16)> {
    let (major, minor) = value.split_once('.')?;
    let Ok(major) = major.parse::<u16>() else {
        return None;
    };
    let Ok(minor) = minor.parse::<u16>() else {
        return None;
    };
    (format!("{major}.{minor}") == value).then_some((major, minor))
}

fn api_includes_fixed(minimum: &str, maximum: &str) -> bool {
    let Some(minimum) = parse_canonical_api_version(minimum) else {
        return false;
    };
    let Some(maximum) = parse_canonical_api_version(maximum) else {
        return false;
    };
    let fixed = (FIXED_ENGINE_API_MAJOR, FIXED_ENGINE_API_MINOR);
    minimum <= fixed && fixed <= maximum
}

fn normalize_engine_architecture(value: &str) -> Option<&'static str> {
    matches!(value, "amd64" | "x86_64").then_some("amd64")
}

fn drop_process_privileges(supplementary_groups: &[Gid]) -> Result<()> {
    let relay_user = Uid::from_raw(RELAY_UID);
    let relay_group = Gid::from_raw(RELAY_GID);
    rustix_thread::set_thread_groups(supplementary_groups)
        .map_err(io::Error::from)
        .context("failed to reduce relay supplementary groups")?;
    drop_capability_bounding_set()?;
    rustix_thread::set_thread_res_gid(relay_group, relay_group, relay_group)
        .map_err(io::Error::from)
        .context("failed to drop relay group privileges")?;
    rustix_thread::set_thread_res_uid(relay_user, relay_user, relay_user)
        .map_err(io::Error::from)
        .context("failed to drop relay user privileges")?;
    rustix_thread::set_no_new_privs(true)
        .map_err(io::Error::from)
        .context("failed to prohibit relay privilege acquisition")?;

    ensure!(
        rustix_process::getuid() == relay_user
            && rustix_process::geteuid() == relay_user
            && rustix_process::getgid() == relay_group
            && rustix_process::getegid() == relay_group,
        "relay identity did not become the fixed unprivileged identity"
    );
    ensure!(
        rustix_process::getgroups()
            .map_err(io::Error::from)
            .context("failed to verify relay supplementary groups")?
            == supplementary_groups,
        "relay retained an unexpected supplementary group"
    );
    verify_linux_privilege_state()?;
    Ok(())
}

fn drop_capability_bounding_set() -> Result<()> {
    for number in 0..u64::BITS {
        let capability = rustix_thread::CapabilitySet::from_bits_retain(1_u64 << number);
        match rustix_thread::capability_is_in_bounding_set(capability) {
            Ok(false) | Err(rustix::io::Errno::INVAL) => {}
            Ok(true) => rustix_thread::remove_capability_from_bounding_set(capability)
                .map_err(io::Error::from)
                .with_context(|| {
                    format!("failed to remove Linux capability {number} from the bounding set")
                })?,
            Err(error) => {
                return Err(io::Error::from(error)).with_context(|| {
                    format!("failed to inspect Linux capability {number} in the bounding set")
                });
            }
        }
    }
    Ok(())
}

fn verify_linux_privilege_state() -> Result<()> {
    let status = fs::read_to_string("/proc/self/status")
        .context("engine relay requires readable Linux process status")?;
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        ensure!(
            status_field(&status, field) == Some("0000000000000000"),
            "engine relay retained Linux process capabilities"
        );
    }
    ensure!(
        status_field(&status, "NoNewPrivs") == Some("1"),
        "engine relay did not lock privilege acquisition"
    );
    Ok(())
}

fn capability_field(status: &str, name: &str) -> Option<u64> {
    let value = status_field(status, name)?;
    (value.len() == 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| u64::from_str_radix(value, 16).ok())
    .flatten()
}

fn status_field<'a>(status: &'a str, name: &str) -> Option<&'a str> {
    status.lines().find_map(|line| {
        let (field, value) = line.split_once(':')?;
        (field == name).then(|| value.trim())
    })
}

async fn run_until_shutdown(prepared: PreparedRelay) -> Result<()> {
    let (mut terminate, mut interrupt) = install_shutdown_signals()?;
    let cancellation = CancellationToken::new();
    let service_cancellation = cancellation.clone();
    let service = run_service(prepared, service_cancellation, PRODUCTION_LIMITS);
    tokio::pin!(service);
    tokio::select! {
        result = &mut service => result,
        shutdown = wait_for_shutdown(&mut terminate, &mut interrupt) => {
            cancellation.cancel();
            let service = service.await;
            match (shutdown, service) {
                (Ok(()), result) => result,
                (Err(shutdown), Ok(())) => Err(shutdown),
                (Err(shutdown), Err(service)) => Err(service.context(format!(
                    "shutdown signal stream also failed: {shutdown:#}"
                ))),
            }
        }
    }
}

fn install_shutdown_signals() -> Result<(Signal, Signal)> {
    install_shutdown_signals_using(signal)
}

fn install_shutdown_signals_using<T, F>(mut install: F) -> Result<(T, T)>
where
    F: FnMut(SignalKind) -> io::Result<T>,
{
    let terminate = install(SignalKind::terminate())
        .context("failed to register the engine relay SIGTERM handler")?;
    let interrupt = install(SignalKind::interrupt())
        .context("failed to register the engine relay SIGINT handler")?;
    Ok((terminate, interrupt))
}

async fn wait_for_shutdown(terminate: &mut Signal, interrupt: &mut Signal) -> Result<()> {
    wait_for_shutdown_event(terminate.recv(), interrupt.recv()).await
}

async fn wait_for_shutdown_event<T, I>(terminate: T, interrupt: I) -> Result<()>
where
    T: Future<Output = Option<()>>,
    I: Future<Output = Option<()>>,
{
    tokio::pin!(terminate);
    tokio::pin!(interrupt);
    tokio::select! {
        received = &mut terminate => ensure!(
            received.is_some(),
            "engine relay SIGTERM stream closed unexpectedly"
        ),
        received = &mut interrupt => ensure!(
            received.is_some(),
            "engine relay SIGINT stream closed unexpectedly"
        ),
    }
    Ok(())
}

async fn run_service(
    prepared: PreparedRelay,
    cancellation: CancellationToken,
    limits: RelayLimits,
) -> Result<()> {
    attest_upstream(&prepared.upstream, &prepared.binding, &cancellation).await?;
    if cancellation.is_cancelled() {
        return Ok(());
    }
    let Some(bound) = bind_downstream(prepared.downstream, &cancellation, limits).await? else {
        return Ok(());
    };
    serve_bound(bound, prepared.upstream, cancellation, limits).await
}

async fn attest_upstream(
    upstream: &UpstreamSocket,
    binding: &RelayBinding,
    cancellation: &CancellationToken,
) -> Result<()> {
    upstream.revalidate()?;
    let upstream_path = upstream.path();
    let facts = tokio::select! {
        () = cancellation.cancelled() => return Ok(()),
        result = inspect_fixed_unix_engine(&upstream_path) => result,
    };
    let facts = facts.context("fixed upstream engine attestation failed")?;
    upstream.revalidate()?;
    binding.verify_engine(&facts)
}

async fn bind_downstream(
    anchor: DirectoryAnchor,
    cancellation: &CancellationToken,
    limits: RelayLimits,
) -> Result<Option<BoundSocket>> {
    if let Some(metadata) = anchor.entry_metadata(SOCKET_NAME)? {
        ensure!(
            downstream_socket_is_exact(&metadata),
            "fixed downstream relay path contains foreign residue"
        );
        let existing = tokio::select! {
            () = cancellation.cancelled() => return Ok(None),
            result = timeout(
                limits.connect_timeout,
                UnixStream::connect(anchor.entry_path(SOCKET_NAME)),
            ) => result,
        };
        match existing {
            Ok(Ok(stream)) => {
                drop(stream);
                bail!("another engine relay already owns the fixed downstream socket");
            }
            Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => {}
            Ok(Err(error)) => {
                return Err(error).context("failed to verify stale downstream relay socket");
            }
            Err(_) => bail!("timed out while verifying the downstream relay socket"),
        }
        remove_exact_stale_downstream(&anchor, &metadata)?;
    }

    #[cfg(not(test))]
    let umask = UmaskGuard::restrict_to(DOWNSTREAM_SOCKET_MODE);
    let listener = StdUnixListener::bind(anchor.entry_path(SOCKET_NAME))
        .context("failed to bind the fixed downstream relay socket");
    #[cfg(not(test))]
    drop(umask);
    let listener = listener?;
    let metadata = anchor
        .entry_metadata(SOCKET_NAME)?
        .context("downstream relay socket disappeared after binding")?;
    let bound = BoundSocket {
        anchor,
        listener: Some(listener),
        device: metadata.st_dev,
        inode: metadata.st_ino,
        cleaned: false,
    };
    ensure!(
        downstream_socket_is_exact(&metadata),
        "downstream relay socket was not created with its exact owner and mode"
    );
    rustix::net::listen(
        bound
            .listener
            .as_ref()
            .context("fixed downstream relay listener is absent")?,
        i32::try_from(limits.maximum_connections).context("invalid relay connection limit")?,
    )
    .map_err(io::Error::from)
    .context("failed to apply the downstream relay connection backlog")?;
    bound
        .listener
        .as_ref()
        .context("fixed downstream relay listener is absent")?
        .set_nonblocking(true)
        .context("failed to make the downstream relay listener nonblocking")?;
    bound
        .anchor
        .revalidate(RELAY_UID, RELAY_GID, DOWNSTREAM_DIRECTORY_MODE)?;
    Ok(Some(bound))
}

#[cfg(not(test))]
struct UmaskGuard(Mode);

#[cfg(not(test))]
impl UmaskGuard {
    fn restrict_to(created_mode: u32) -> Self {
        let mask = Mode::from_raw_mode(0o777 & !created_mode);
        Self(rustix_process::umask(mask))
    }
}

#[cfg(not(test))]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        rustix_process::umask(self.0);
    }
}

async fn serve_bound(
    mut bound: BoundSocket,
    upstream: Arc<UpstreamSocket>,
    cancellation: CancellationToken,
    limits: RelayLimits,
) -> Result<()> {
    let listener = UnixListener::from_std(bound.take_listener()?)
        .context("failed to register the downstream relay listener")?;
    let result = serve_connections(listener, upstream, cancellation, limits).await;
    let cleanup = bound.cleanup();
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(error.context(format!(
            "downstream socket cleanup also failed: {cleanup:#}"
        ))),
    }
}

async fn serve_connections(
    listener: UnixListener,
    upstream: Arc<UpstreamSocket>,
    cancellation: CancellationToken,
    limits: RelayLimits,
) -> Result<()> {
    ensure!(
        limits.maximum_connections > 0,
        "engine relay connection limit must be positive"
    );
    let mut tasks = JoinSet::new();
    let mut failure = None;

    loop {
        if tasks.len() >= limits.maximum_connections {
            tokio::select! {
                () = cancellation.cancelled() => break,
                joined = tasks.join_next() => {
                    if let Some(error) = connection_task_failure(joined) {
                        failure = Some(error);
                        break;
                    }
                }
            }
            continue;
        }
        tokio::select! {
            () = cancellation.cancelled() => break,
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(error) = connection_task_failure(joined) {
                    failure = Some(error);
                    break;
                }
            }
            accepted = listener.accept() => {
                let (downstream, _) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        failure = Some(RelayError::with_source(
                            "downstream relay accept failed",
                            error,
                        ));
                        break;
                    }
                };
                let upstream = Arc::clone(&upstream);
                let connection_cancellation = cancellation.clone();
                tasks.spawn(async move {
                    relay_connection(
                        downstream,
                        &upstream,
                        &connection_cancellation,
                        limits,
                    )
                    .await
                });
            }
        }
    }

    cancellation.cancel();
    drop(listener);
    let drain = async {
        while let Some(joined) = tasks.join_next().await {
            joined.context("engine relay connection task failed during shutdown")?;
        }
        Result::<()>::Ok(())
    };
    if let Ok(result) = timeout(limits.shutdown_timeout, drain).await {
        result?;
    } else {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        bail!("engine relay connections did not stop before the shutdown deadline");
    }
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(())
}

fn connection_task_failure(
    joined: Option<Result<ConnectionEnd, tokio::task::JoinError>>,
) -> Option<RelayError> {
    match joined {
        Some(Ok(ConnectionEnd::AuthorityChanged)) => Some(relay_error!(
            "fixed upstream engine socket authority changed"
        )),
        Some(Err(error)) => Some(RelayError::with_source(
            "engine relay connection task failed",
            error,
        )),
        Some(Ok(
            ConnectionEnd::Complete
            | ConnectionEnd::Cancelled
            | ConnectionEnd::ConnectFailed
            | ConnectionEnd::Idle
            | ConnectionEnd::IoFailed,
        ))
        | None => None,
    }
}

async fn relay_connection(
    downstream: UnixStream,
    upstream_socket: &UpstreamSocket,
    cancellation: &CancellationToken,
    limits: RelayLimits,
) -> ConnectionEnd {
    relay_connection_using(downstream, upstream_socket, cancellation, limits, |path| {
        UnixStream::connect(path)
    })
    .await
}

async fn relay_connection_using<C, F>(
    downstream: UnixStream,
    upstream_socket: &UpstreamSocket,
    cancellation: &CancellationToken,
    limits: RelayLimits,
    connect: C,
) -> ConnectionEnd
where
    C: FnOnce(PathBuf) -> F,
    F: Future<Output = io::Result<UnixStream>>,
{
    if upstream_socket.revalidate().is_err() {
        return ConnectionEnd::AuthorityChanged;
    }
    let upstream_path = upstream_socket.path();
    let connected = tokio::select! {
        () = cancellation.cancelled() => return ConnectionEnd::Cancelled,
        result = timeout(limits.connect_timeout, connect(upstream_path)) => result,
    };
    if upstream_socket.revalidate().is_err() {
        return ConnectionEnd::AuthorityChanged;
    }
    let Ok(Ok(upstream)) = connected else {
        return ConnectionEnd::ConnectFailed;
    };

    let (downstream_read, downstream_write) = downstream.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();
    let (activity, mut observed_activity) = watch::channel(Instant::now());
    let downstream_to_upstream = pump(
        downstream_read,
        upstream_write,
        activity.clone(),
        cancellation,
        limits,
    );
    let upstream_to_downstream = pump(
        upstream_read,
        downstream_write,
        activity,
        cancellation,
        limits,
    );
    let directions = async {
        tokio::try_join!(downstream_to_upstream, upstream_to_downstream)?;
        Result::<(), ConnectionEnd>::Ok(())
    };
    tokio::pin!(directions);
    let idle = sleep_until(Instant::now() + limits.idle_timeout);
    tokio::pin!(idle);

    loop {
        tokio::select! {
            () = cancellation.cancelled() => return ConnectionEnd::Cancelled,
            result = &mut directions => {
                return match result {
                    Ok(()) => ConnectionEnd::Complete,
                    Err(end) => end,
                };
            }
            changed = observed_activity.changed() => {
                if changed.is_err() {
                    return ConnectionEnd::IoFailed;
                }
                idle.as_mut().reset(*observed_activity.borrow_and_update() + limits.idle_timeout);
            }
            () = &mut idle => {
                let deadline = *observed_activity.borrow_and_update() + limits.idle_timeout;
                if deadline <= Instant::now() {
                    return ConnectionEnd::Idle;
                }
                idle.as_mut().reset(deadline);
            }
        }
    }
}

async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    activity: watch::Sender<Instant>,
    cancellation: &CancellationToken,
    limits: RelayLimits,
) -> Result<(), ConnectionEnd>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; limits.copy_buffer_bytes];
    loop {
        let read = tokio::select! {
            () = cancellation.cancelled() => return Err(ConnectionEnd::Cancelled),
            result = reader.read(&mut buffer) => result,
        }
        .map_err(|_| ConnectionEnd::IoFailed)?;
        if read == 0 {
            let shutdown = tokio::select! {
                () = cancellation.cancelled() => return Err(ConnectionEnd::Cancelled),
                result = timeout(limits.write_timeout, writer.shutdown()) => result,
            };
            return shutdown
                .map_err(|_| ConnectionEnd::IoFailed)?
                .map_err(|_| ConnectionEnd::IoFailed);
        }
        let written = tokio::select! {
            () = cancellation.cancelled() => return Err(ConnectionEnd::Cancelled),
            result = timeout(limits.write_timeout, writer.write_all(&buffer[..read])) => result,
        };
        written
            .map_err(|_| ConnectionEnd::IoFailed)?
            .map_err(|_| ConnectionEnd::IoFailed)?;
        activity.send_replace(Instant::now());
    }
}

fn downstream_socket_is_exact(metadata: &rustix_fs::Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode) == FileType::Socket
        && metadata.st_uid == RELAY_UID
        && metadata.st_gid == RELAY_GID
        && permission_bits(metadata.st_mode) == DOWNSTREAM_SOCKET_MODE
        && metadata.st_nlink == 1
}

fn same_upstream_authority(left: &rustix_fs::Stat, right: &rustix_fs::Stat) -> bool {
    upstream_authority(left) == upstream_authority(right)
}

fn upstream_authority(metadata: &rustix_fs::Stat) -> [u64; 6] {
    socket_authority(metadata)
}

fn socket_authority(metadata: &rustix_fs::Stat) -> [u64; 6] {
    [
        metadata.st_dev,
        metadata.st_ino,
        u64::from(metadata.st_uid),
        u64::from(metadata.st_gid),
        u64::from(metadata.st_mode),
        metadata.st_nlink,
    ]
}

fn file_authority(metadata: &rustix_fs::Stat) -> [u64; 7] {
    let socket = socket_authority(metadata);
    [
        socket[0],
        socket[1],
        socket[2],
        socket[3],
        socket[4],
        socket[5],
        u64::try_from(metadata.st_size).unwrap_or(u64::MAX),
    ]
}

fn remove_exact_stale_downstream(
    anchor: &DirectoryAnchor,
    expected: &rustix_fs::Stat,
) -> Result<()> {
    let current = anchor
        .entry_metadata(SOCKET_NAME)?
        .context("stale downstream relay socket disappeared before removal")?;
    ensure!(
        downstream_socket_is_exact(&current)
            && current.st_dev == expected.st_dev
            && current.st_ino == expected.st_ino,
        "stale downstream relay socket changed before removal"
    );
    rustix_fs::unlinkat(&anchor.descriptor, SOCKET_NAME, AtFlags::empty())
        .map_err(io::Error::from)
        .context("failed to replace the exact stale downstream relay socket")
}

const fn permission_bits(mode: u32) -> u32 {
    mode & 0o7_777
}

#[cfg(test)]
mod tests {
    use std::{
        fs, io,
        os::unix::{fs::PermissionsExt as _, net::UnixListener as StdUnixListener},
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };

    use rustix::process::{self, Uid};

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{UnixListener, UnixStream},
        sync::oneshot,
        time::timeout,
    };
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use super::{
        ConnectionEnd, DirectoryAnchor, FixedEngineFacts, RelayBinding, RelayLimits,
        UpstreamSocket, api_includes_fixed, bind_downstream, decode_binding,
        initial_capability_state_is_exact, inspect_fixed_unix_engine,
        install_shutdown_signals_using, normalize_engine_architecture, relay_connection,
        relay_connection_using, remove_exact_stale_downstream, require_pre_runtime_dispatch,
        require_upstream_socket, same_upstream_authority, serve_connections, upstream_authority,
        wait_for_shutdown_event,
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(2);

    #[test]
    fn synchronous_relay_entrypoints_require_pre_runtime_dispatch() {
        require_pre_runtime_dispatch().expect("ordinary synchronous dispatch");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            assert!(require_pre_runtime_dispatch().is_err());
        });
    }

    fn test_limits(maximum_connections: usize) -> RelayLimits {
        RelayLimits {
            maximum_connections,
            connect_timeout: Duration::from_secs(1),
            write_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(5),
            shutdown_timeout: Duration::from_secs(1),
            copy_buffer_bytes: 1_024,
        }
    }

    fn canonical_binding() -> Vec<u8> {
        concat!(
            "{\"schema\":1,\"installation\":{",
            "\"id\":\"10000000-0000-4000-8000-000000000001\",",
            "\"selector_key\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
            "\"compose_project\":\"automata-local-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
            "\"plan_digest\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"},",
            "\"engine\":{\"id\":\"engine-id\",\"api_version\":\"1.48\",",
            "\"server_version\":\"28.3.3\",\"operating_system\":\"linux\",",
            "\"architecture\":\"amd64\"}}\n"
        )
        .as_bytes()
        .to_vec()
    }

    fn binding() -> RelayBinding {
        decode_binding(&canonical_binding()).expect("decode canonical binding")
    }

    #[test]
    fn relay_binding_accepts_only_the_exact_current_canonical_document() {
        let canonical = canonical_binding();
        let decoded = decode_binding(&canonical).expect("canonical binding");
        assert_eq!(
            serde_json::to_string(&decoded).expect("encode binding") + "\n",
            String::from_utf8(canonical.clone()).expect("UTF-8 binding")
        );

        let mut missing_newline = canonical.clone();
        missing_newline.pop();
        let mut extra_newline = canonical.clone();
        extra_newline.push(b'\n');
        let reordered = String::from_utf8(canonical.clone())
            .expect("UTF-8 binding")
            .replacen("{\"schema\":1,\"installation\":", "{\"installation\":", 1)
            .replacen("},\"engine\":", "},\"schema\":1,\"engine\":", 1)
            .into_bytes();
        let unknown = String::from_utf8(canonical.clone())
            .expect("UTF-8 binding")
            .replacen("{\"schema\":1,", "{\"schema\":1,\"legacy\":false,", 1)
            .into_bytes();
        let alias = String::from_utf8(canonical.clone())
            .expect("UTF-8 binding")
            .replace("\"api_version\"", "\"apiVersion\"")
            .into_bytes();
        let wrong_schema = String::from_utf8(canonical.clone())
            .expect("UTF-8 binding")
            .replace("\"schema\":1", "\"schema\":0")
            .into_bytes();
        let uppercase_digest = String::from_utf8(canonical.clone())
            .expect("UTF-8 binding")
            .replacen(&"a".repeat(64), &"A".repeat(64), 1)
            .into_bytes();
        let noncanonical_api = String::from_utf8(canonical.clone())
            .expect("UTF-8 binding")
            .replace("\"1.48\"", "\"01.48\"")
            .into_bytes();
        let wrong_api = String::from_utf8(canonical.clone())
            .expect("UTF-8 binding")
            .replace("\"1.48\"", "\"1.47\"")
            .into_bytes();
        let platform_alias = String::from_utf8(canonical.clone())
            .expect("UTF-8 binding")
            .replace("\"amd64\"", "\"x86_64\"")
            .into_bytes();
        let unsupported_architecture = String::from_utf8(canonical.clone())
            .expect("UTF-8 binding")
            .replace("\"amd64\"", "\"arm64\"")
            .into_bytes();
        let old_engine = String::from_utf8(canonical.clone())
            .expect("UTF-8 binding")
            .replace("\"28.3.3\"", "\"27.5.1\"")
            .into_bytes();
        let inconsistent_project = String::from_utf8(canonical)
            .expect("UTF-8 binding")
            .replace(
                "automata-local-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "automata-local-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .into_bytes();

        for invalid in [
            missing_newline,
            extra_newline,
            reordered,
            unknown,
            alias,
            wrong_schema,
            uppercase_digest,
            noncanonical_api,
            wrong_api,
            platform_alias,
            unsupported_architecture,
            old_engine,
            inconsistent_project,
            vec![b'x'; super::MAX_BINDING_BYTES + 1],
        ] {
            assert!(
                decode_binding(&invalid).is_err(),
                "non-current or non-canonical binding must fail closed"
            );
        }
    }

    #[test]
    fn relay_binding_matches_every_exact_engine_fact() {
        let binding = binding();
        let facts = FixedEngineFacts {
            engine_id: "engine-id".to_owned(),
            selected_api_version: "1.48".to_owned(),
            server_version: "28.3.3".to_owned(),
            operating_system: "linux".to_owned(),
            architecture: "amd64".to_owned(),
        };
        binding
            .verify_engine(&facts)
            .expect("exact bound Engine facts");

        let mut changed = facts.clone();
        changed.engine_id = "different-engine".to_owned();
        assert!(binding.verify_engine(&changed).is_err());
        let mut changed = facts.clone();
        changed.selected_api_version = "1.47".to_owned();
        assert!(binding.verify_engine(&changed).is_err());
        let mut changed = facts.clone();
        changed.server_version = "28.3.4".to_owned();
        assert!(binding.verify_engine(&changed).is_err());
        let mut changed = facts.clone();
        changed.operating_system = "windows".to_owned();
        assert!(binding.verify_engine(&changed).is_err());
        let mut changed = facts;
        changed.architecture = "arm64".to_owned();
        assert!(binding.verify_engine(&changed).is_err());
    }

    #[test]
    fn fixed_engine_contract_normalizes_only_current_amd64_aliases_and_spans_api_148() {
        assert_eq!(normalize_engine_architecture("amd64"), Some("amd64"));
        assert_eq!(normalize_engine_architecture("x86_64"), Some("amd64"));
        assert_eq!(normalize_engine_architecture("arm64"), None);
        assert!(api_includes_fixed("1.24", "1.48"));
        assert!(api_includes_fixed("1.48", "1.53"));
        assert!(!api_includes_fixed("1.49", "1.53"));
        assert!(!api_includes_fixed("1.24", "1.47"));
        assert!(!api_includes_fixed("01.24", "1.53"));
    }

    #[test]
    fn relay_startup_capabilities_are_exact() {
        let exact = concat!(
            "CapInh:\t0000000000000000\n",
            "CapPrm:\t00000000000001c0\n",
            "CapEff:\t00000000000001c0\n",
            "CapBnd:\t00000000000001c0\n",
            "CapAmb:\t0000000000000000\n",
        );
        assert!(initial_capability_state_is_exact(exact));

        for drifted in [
            exact.replace("CapEff:\t00000000000001c0", "CapEff:\t0000000000000000"),
            exact.replace("CapBnd:\t00000000000001c0", "CapBnd:\t00000000a80425fb"),
            exact.replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000040"),
            exact.replace("CapPrm:\t00000000000001c0", "CapPrm:\t00000000000001C0"),
        ] {
            assert!(
                !initial_capability_state_is_exact(&drifted),
                "missing, excess, ambient, or noncanonical capabilities must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn fixed_engine_attestation_uses_api_148_and_canonicalizes_amd64() {
        let (socket, server) = fake_engine_server("x86_64", "amd64", "1.24", "1.53");
        let facts = inspect_fixed_unix_engine(&socket)
            .await
            .expect("attest exact fake engine");
        assert_eq!(
            facts,
            FixedEngineFacts {
                engine_id: "engine-id".to_owned(),
                selected_api_version: "1.48".to_owned(),
                server_version: "28.3.3".to_owned(),
                operating_system: "linux".to_owned(),
                architecture: "amd64".to_owned(),
            }
        );
        let mut paths = server.await.expect("fake engine server");
        paths.sort();
        assert_eq!(paths, ["/info", "/version"]);
        fs::remove_file(socket).expect("remove fake engine socket");
    }

    #[tokio::test]
    async fn fixed_engine_attestation_rejects_paired_fact_and_api_drift() {
        for (label, info_architecture, version_architecture, minimum_api, maximum_api) in [
            ("architecture", "arm64", "amd64", "1.24", "1.53"),
            ("minimum-api", "x86_64", "amd64", "1.49", "1.53"),
            ("maximum-api", "x86_64", "amd64", "1.24", "1.47"),
        ] {
            let (socket, server) = fake_engine_server(
                info_architecture,
                version_architecture,
                minimum_api,
                maximum_api,
            );
            assert!(
                inspect_fixed_unix_engine(&socket).await.is_err(),
                "{label} drift must fail closed"
            );
            assert_eq!(server.await.expect("fake engine server").len(), 2);
            fs::remove_file(socket).expect("remove fake engine socket");
        }
    }

    fn fake_engine_server(
        info_architecture: &'static str,
        version_architecture: &'static str,
        minimum_api: &'static str,
        maximum_api: &'static str,
    ) -> (PathBuf, tokio::task::JoinHandle<Vec<String>>) {
        let socket = std::env::temp_dir().join(format!(
            "automata-engine-relay-facts-{}.sock",
            Uuid::new_v4().simple()
        ));
        let listener = UnixListener::bind(&socket).expect("bind fake engine socket");
        let server = tokio::spawn(async move {
            let mut paths = Vec::with_capacity(2);
            for _request in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept fake engine request");
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1_024];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let read = stream.read(&mut chunk).await.expect("read engine request");
                    assert_ne!(read, 0, "engine request ended before its headers");
                    request.extend_from_slice(&chunk[..read]);
                    assert!(request.len() <= 16 * 1_024, "engine request is bounded");
                }
                let request = std::str::from_utf8(&request).expect("UTF-8 engine request");
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .expect("engine request path")
                    .to_owned();
                let body = match path.as_str() {
                    "/info" => format!(
                        "{{\"ID\":\"engine-id\",\"ServerVersion\":\"28.3.3\",\"Architecture\":\"{info_architecture}\",\"OSType\":\"linux\"}}"
                    ),
                    "/version" => format!(
                        "{{\"Version\":\"28.3.3\",\"ApiVersion\":\"{maximum_api}\",\"MinAPIVersion\":\"{minimum_api}\",\"Os\":\"linux\",\"Arch\":\"{version_architecture}\"}}"
                    ),
                    _ => panic!("unexpected engine request path {path}"),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write fake engine response");
                stream.shutdown().await.expect("close fake engine response");
                paths.push(path);
            }
            paths
        });
        (socket, server)
    }

    #[test]
    fn shutdown_signal_registration_failures_are_terminal() {
        let first = install_shutdown_signals_using::<(), _>(|_kind| {
            Err(io::Error::other("forced SIGTERM registration failure"))
        })
        .expect_err("SIGTERM registration failure must be terminal");
        assert!(format!("{first:#}").contains("SIGTERM handler"));

        let mut calls = 0_u8;
        let second = install_shutdown_signals_using::<(), _>(|_kind| {
            calls += 1;
            if calls == 1 {
                Ok(())
            } else {
                Err(io::Error::other("forced SIGINT registration failure"))
            }
        })
        .expect_err("SIGINT registration failure must be terminal");
        assert_eq!(calls, 2);
        assert!(format!("{second:#}").contains("SIGINT handler"));
    }

    #[tokio::test]
    async fn closed_shutdown_signal_streams_are_terminal() {
        let terminate = wait_for_shutdown_event(
            std::future::ready(None),
            std::future::pending::<Option<()>>(),
        )
        .await
        .expect_err("closed SIGTERM stream must fail");
        assert!(format!("{terminate:#}").contains("SIGTERM stream closed"));

        let interrupt = wait_for_shutdown_event(
            std::future::pending::<Option<()>>(),
            std::future::ready(None),
        )
        .await
        .expect_err("closed SIGINT stream must fail");
        assert!(format!("{interrupt:#}").contains("SIGINT stream closed"));
    }

    #[tokio::test]
    async fn relay_is_bidirectional_and_preserves_both_half_closes() {
        let fixture = Fixture::new("bidirectional");
        let upstream_listener =
            UnixListener::bind(fixture.socket()).expect("bind upstream test socket");
        let (mut client, downstream) = UnixStream::pair().expect("create downstream pair");
        let cancellation = CancellationToken::new();
        let relay = tokio::spawn({
            let cancellation = cancellation.clone();
            let upstream = fixture.upstream();
            async move { relay_connection(downstream, &upstream, &cancellation, test_limits(1)).await }
        });
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("accept relay");
            let mut request = Vec::new();
            stream
                .read_to_end(&mut request)
                .await
                .expect("read request through relay");
            assert_eq!(request, b"request-body");
            stream
                .write_all(b"response-body")
                .await
                .expect("write response through relay");
            stream.shutdown().await.expect("half-close upstream write");
        });

        client
            .write_all(b"request-body")
            .await
            .expect("write downstream request");
        client
            .shutdown()
            .await
            .expect("half-close downstream write");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read downstream response");
        assert_eq!(response, b"response-body");
        assert_eq!(
            timeout(TEST_TIMEOUT, relay)
                .await
                .expect("relay completion deadline")
                .expect("relay task"),
            ConnectionEnd::Complete
        );
        timeout(TEST_TIMEOUT, upstream)
            .await
            .expect("upstream completion deadline")
            .expect("upstream task");
    }

    #[tokio::test]
    async fn cancellation_closes_an_idle_hijacked_stream() {
        let fixture = Fixture::new("cancel");
        let upstream_listener =
            UnixListener::bind(fixture.socket()).expect("bind upstream test socket");
        let (mut client, downstream) = UnixStream::pair().expect("create downstream pair");
        let cancellation = CancellationToken::new();
        let relay = tokio::spawn({
            let cancellation = cancellation.clone();
            let upstream = fixture.upstream();
            async move { relay_connection(downstream, &upstream, &cancellation, test_limits(1)).await }
        });
        let (mut upstream, _) = upstream_listener.accept().await.expect("accept relay");

        cancellation.cancel();
        assert_eq!(
            timeout(TEST_TIMEOUT, relay)
                .await
                .expect("cancelled relay deadline")
                .expect("relay task"),
            ConnectionEnd::Cancelled
        );
        let mut byte = [0_u8; 1];
        assert_eq!(
            timeout(TEST_TIMEOUT, client.read(&mut byte))
                .await
                .expect("downstream close deadline")
                .expect("read downstream close"),
            0
        );
        assert_eq!(
            timeout(TEST_TIMEOUT, upstream.read(&mut byte))
                .await
                .expect("upstream close deadline")
                .expect("read upstream close"),
            0
        );
    }

    #[tokio::test]
    async fn one_way_activity_resets_the_whole_connection_idle_deadline() {
        let fixture = Fixture::new("shared-idle");
        let upstream_listener =
            UnixListener::bind(fixture.socket()).expect("bind upstream test socket");
        let (mut client, downstream) = UnixStream::pair().expect("create downstream pair");
        let cancellation = CancellationToken::new();
        let mut limits = test_limits(1);
        limits.idle_timeout = Duration::from_millis(120);
        let relay = tokio::spawn({
            let cancellation = cancellation.clone();
            let upstream = fixture.upstream();
            async move { relay_connection(downstream, &upstream, &cancellation, limits).await }
        });
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.expect("accept relay");
            let mut request = [0_u8; 1];
            stream.read_exact(&mut request).await.expect("read request");
            for byte in b"abcd" {
                tokio::time::sleep(Duration::from_millis(70)).await;
                stream.write_all(&[*byte]).await.expect("write pulse");
            }
            stream.shutdown().await.expect("half-close upstream write");
            let mut remainder = Vec::new();
            stream
                .read_to_end(&mut remainder)
                .await
                .expect("await downstream half-close");
        });

        client.write_all(b"x").await.expect("write request");
        let mut response = [0_u8; 4];
        client
            .read_exact(&mut response)
            .await
            .expect("read one-way response activity");
        assert_eq!(&response, b"abcd");
        client
            .shutdown()
            .await
            .expect("half-close downstream write");
        let mut eof = [0_u8; 1];
        assert_eq!(client.read(&mut eof).await.expect("read response EOF"), 0);
        assert_eq!(
            timeout(TEST_TIMEOUT, relay)
                .await
                .expect("active relay completion deadline")
                .expect("relay task"),
            ConnectionEnd::Complete
        );
        upstream.await.expect("upstream task");
    }

    #[tokio::test]
    async fn connection_limit_prevents_an_extra_upstream_connection() {
        let fixture = Fixture::new("connection-bound");
        let downstream_path = fixture.path().join("downstream.sock");
        let upstream_path = fixture.socket().to_owned();
        let downstream_listener =
            UnixListener::bind(&downstream_path).expect("bind downstream test socket");
        let upstream_listener =
            UnixListener::bind(&upstream_path).expect("bind upstream test socket");
        let upstream = fixture.upstream();
        let cancellation = CancellationToken::new();
        let service = tokio::spawn({
            let cancellation = cancellation.clone();
            let upstream = Arc::clone(&upstream);
            async move {
                serve_connections(downstream_listener, upstream, cancellation, test_limits(2)).await
            }
        });

        let first_client = UnixStream::connect(&downstream_path)
            .await
            .expect("connect first downstream");
        let (first_upstream, _) = timeout(TEST_TIMEOUT, upstream_listener.accept())
            .await
            .expect("first upstream deadline")
            .expect("first upstream connection");
        let second_client = UnixStream::connect(&downstream_path)
            .await
            .expect("connect second downstream");
        let (second_upstream, _) = timeout(TEST_TIMEOUT, upstream_listener.accept())
            .await
            .expect("second upstream deadline")
            .expect("second upstream connection");
        let third_client = UnixStream::connect(&downstream_path)
            .await
            .expect("queue third downstream");
        assert!(
            timeout(Duration::from_millis(150), upstream_listener.accept())
                .await
                .is_err(),
            "a third active connection must not reach the upstream socket"
        );

        cancellation.cancel();
        timeout(TEST_TIMEOUT, service)
            .await
            .expect("service shutdown deadline")
            .expect("service task")
            .expect("clean service shutdown");
        drop((first_client, second_client, third_client));
        drop((first_upstream, second_upstream));
    }

    #[tokio::test]
    async fn every_connection_rejects_replaced_upstream_authority() {
        let fixture = Fixture::new("connection-authority");
        let original = UnixListener::bind(fixture.socket()).expect("bind original upstream");
        let upstream = fixture.upstream();
        drop(original);
        fs::remove_file(fixture.socket()).expect("remove original upstream socket");
        let replacement =
            UnixListener::bind(fixture.socket()).expect("bind replacement upstream socket");
        fs::set_permissions(fixture.socket(), fs::Permissions::from_mode(0o660))
            .expect("set replacement upstream mode");
        let (_client, downstream) = UnixStream::pair().expect("create downstream pair");
        let cancellation = CancellationToken::new();

        assert_eq!(
            relay_connection(downstream, &upstream, &cancellation, test_limits(1)).await,
            ConnectionEnd::AuthorityChanged
        );
        assert!(
            timeout(Duration::from_millis(100), replacement.accept())
                .await
                .is_err(),
            "authority drift must be rejected before an upstream connection"
        );
    }

    #[tokio::test]
    async fn failed_connect_revalidates_replaced_upstream_authority() {
        let fixture = Fixture::new("failed-connect-authority");
        let original = UnixListener::bind(fixture.socket()).expect("bind original upstream");
        let upstream = fixture.upstream();
        let (_client, downstream) = UnixStream::pair().expect("create downstream pair");
        let cancellation = CancellationToken::new();
        let (attempted, attempt_started) = oneshot::channel();
        let (finish_attempt, finish) = oneshot::channel();

        let relay = tokio::spawn({
            let upstream = Arc::clone(&upstream);
            let cancellation = cancellation.clone();
            async move {
                relay_connection_using(
                    downstream,
                    &upstream,
                    &cancellation,
                    test_limits(1),
                    move |_path| async move {
                        attempted.send(()).expect("signal connect attempt");
                        finish.await.expect("release failed connect attempt");
                        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                    },
                )
                .await
            }
        });

        attempt_started.await.expect("observe connect attempt");
        drop(original);
        fs::remove_file(fixture.socket()).expect("remove original upstream socket");
        let replacement =
            UnixListener::bind(fixture.socket()).expect("bind replacement upstream socket");
        fs::set_permissions(fixture.socket(), fs::Permissions::from_mode(0o660))
            .expect("set replacement upstream mode");
        finish_attempt
            .send(())
            .expect("finish failed connect attempt");

        assert_eq!(
            timeout(TEST_TIMEOUT, relay)
                .await
                .expect("failed connect authority deadline")
                .expect("relay task"),
            ConnectionEnd::AuthorityChanged
        );
        assert!(
            timeout(Duration::from_millis(100), replacement.accept())
                .await
                .is_err(),
            "failed connect authority drift must not reach the replacement"
        );
    }

    #[tokio::test]
    async fn successful_connect_revalidates_replaced_upstream_before_forwarding() {
        let fixture = Fixture::new("success-authority");
        let original = UnixListener::bind(fixture.socket()).expect("bind original upstream");
        let upstream = fixture.upstream();
        let (mut client, downstream) = UnixStream::pair().expect("create downstream pair");
        let (captured, mut captured_peer) =
            UnixStream::pair().expect("create captured upstream pair");
        let cancellation = CancellationToken::new();
        let (attempted, attempt_started) = oneshot::channel();
        let (finish_attempt, finish) = oneshot::channel();

        let relay = tokio::spawn({
            let upstream = Arc::clone(&upstream);
            let cancellation = cancellation.clone();
            async move {
                relay_connection_using(
                    downstream,
                    &upstream,
                    &cancellation,
                    test_limits(1),
                    move |_path| async move {
                        attempted.send(()).expect("signal connect attempt");
                        finish.await.expect("release successful connect attempt");
                        Ok(captured)
                    },
                )
                .await
            }
        });

        attempt_started.await.expect("observe connect attempt");
        client
            .write_all(b"must-not-reach-upstream")
            .await
            .expect("queue downstream payload");
        captured_peer
            .write_all(b"must-not-reach-downstream")
            .await
            .expect("queue upstream payload");
        drop(original);
        fs::remove_file(fixture.socket()).expect("remove original upstream socket");
        let replacement =
            UnixListener::bind(fixture.socket()).expect("bind replacement upstream socket");
        fs::set_permissions(fixture.socket(), fs::Permissions::from_mode(0o660))
            .expect("set replacement upstream mode");
        finish_attempt
            .send(())
            .expect("finish successful connect attempt");

        assert_eq!(
            timeout(TEST_TIMEOUT, relay)
                .await
                .expect("successful connect authority deadline")
                .expect("relay task"),
            ConnectionEnd::AuthorityChanged
        );
        assert_closed_without_payload(&mut client, "downstream").await;
        assert_closed_without_payload(&mut captured_peer, "captured upstream").await;
        assert!(
            timeout(Duration::from_millis(100), replacement.accept())
                .await
                .is_err(),
            "successful connect authority drift must not reach the replacement"
        );
    }

    async fn assert_closed_without_payload(stream: &mut UnixStream, label: &str) {
        let mut byte = [0_u8; 1];
        match timeout(TEST_TIMEOUT, stream.read(&mut byte))
            .await
            .unwrap_or_else(|_| panic!("{label} close deadline"))
        {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Ok(read) => panic!("{label} received {read} unexpected payload bytes"),
            Err(error) => panic!("{label} close failed: {error}"),
        }
    }

    #[test]
    fn fixed_directory_lock_has_one_live_owner_and_releases_exactly() {
        let fixture = Fixture::new("exclusive-owner");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("set exact relay fixture mode");
        let uid = process::getuid().as_raw();
        let gid = process::getgid().as_raw();
        let first = DirectoryAnchor::open(fixture.path(), uid, gid, 0o700)
            .expect("open first directory anchor");
        let second = DirectoryAnchor::open(fixture.path(), uid, gid, 0o700)
            .expect("open second directory anchor");

        first.lock_exclusive().expect("acquire first owner lock");
        assert!(
            second.lock_exclusive().is_err(),
            "a second live relay must not acquire the directory lock"
        );
        rustix::fs::flock(&first.descriptor, rustix::fs::FlockOperation::Unlock)
            .expect("release first owner lock without a fork-inheritance race");
        drop(first);
        second
            .lock_exclusive()
            .expect("acquire lock after the prior owner exits");
    }

    #[test]
    fn upstream_authority_includes_owner_group_mode_and_link_count() {
        let fixture = Fixture::new("upstream-authority");
        let listener = std::os::unix::net::UnixListener::bind(fixture.socket())
            .expect("bind upstream fixture");
        let metadata = rustix::fs::stat(fixture.socket()).expect("inspect upstream fixture");
        assert!(same_upstream_authority(&metadata, &metadata));

        let authority = upstream_authority(&metadata);
        for field in 2..authority.len() {
            let mut changed = authority;
            changed[field] = changed[field].wrapping_add(1);
            assert_ne!(authority, changed);
        }
        drop(listener);
    }

    #[test]
    fn stale_removal_rejects_a_replacement_inode() {
        let fixture = Fixture::new("stale-replacement");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("set exact relay fixture mode");
        let uid = process::getuid().as_raw();
        let gid = process::getgid().as_raw();
        let anchor = DirectoryAnchor::open(fixture.path(), uid, gid, 0o700)
            .expect("open relay fixture directory");
        let original =
            std::os::unix::net::UnixListener::bind(fixture.path().join(super::SOCKET_NAME))
                .expect("bind original stale socket");
        let expected = anchor
            .entry_metadata(super::SOCKET_NAME)
            .expect("inspect original stale socket")
            .expect("original stale socket");
        drop(original);
        fs::remove_file(fixture.path().join(super::SOCKET_NAME))
            .expect("remove original stale socket");
        let replacement =
            std::os::unix::net::UnixListener::bind(fixture.path().join(super::SOCKET_NAME))
                .expect("bind replacement socket");

        assert!(remove_exact_stale_downstream(&anchor, &expected).is_err());
        assert!(fixture.path().join(super::SOCKET_NAME).exists());
        drop(replacement);
    }

    #[tokio::test]
    async fn post_bind_validation_failure_removes_only_the_created_socket() {
        let fixture = Fixture::new("post-bind-cleanup");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("set exact relay fixture mode");
        let uid = process::getuid().as_raw();
        let gid = process::getgid().as_raw();
        let anchor = DirectoryAnchor::open(fixture.path(), uid, gid, 0o700)
            .expect("open relay fixture directory");
        anchor
            .lock_exclusive()
            .expect("lock relay fixture directory");
        let cancellation = CancellationToken::new();
        let mut limits = test_limits(1);
        limits.maximum_connections = usize::MAX;

        assert!(
            bind_downstream(anchor, &cancellation, limits)
                .await
                .is_err(),
            "invalid post-bind configuration must fail"
        );
        assert!(
            !fixture.path().join(super::SOCKET_NAME).exists(),
            "a post-bind failure must not leave the created socket behind"
        );
    }

    #[test]
    fn production_upstream_socket_contract_rejects_a_nonroot_owner() {
        if process::getuid().is_root() {
            return;
        }
        let fixture = Fixture::new("upstream-owner");
        let _listener = StdUnixListener::bind(fixture.socket()).expect("bind test upstream socket");
        fs::set_permissions(fixture.socket(), fs::Permissions::from_mode(0o660))
            .expect("set exact upstream socket mode");
        let owner = process::getuid().as_raw();
        let group = process::getgid().as_raw();
        let anchor = DirectoryAnchor::open(fixture.path(), owner, group, 0o700)
            .expect("open test upstream directory");
        assert!(require_upstream_socket(&anchor, Uid::ROOT.as_raw()).is_err());
        assert!(require_upstream_socket(&anchor, owner).is_ok());
    }

    struct Fixture {
        parent: PathBuf,
        path: PathBuf,
        socket: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let parent = std::env::temp_dir().join("automata-engine-relay-unit");
            fs::create_dir_all(&parent).expect("create relay fixture parent");
            let path = parent.join(format!("{label}-{}", Uuid::new_v4()));
            fs::create_dir(&path).expect("create unique relay fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("set searchable relay fixture mode");
            let socket = path.join(super::SOCKET_NAME);
            Self {
                parent,
                path,
                socket,
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn socket(&self) -> &Path {
            &self.socket
        }

        fn upstream(&self) -> Arc<UpstreamSocket> {
            fs::set_permissions(&self.socket, fs::Permissions::from_mode(0o660))
                .expect("set exact upstream socket mode");
            let owner = process::getuid().as_raw();
            let group = process::getgid().as_raw();
            let anchor = DirectoryAnchor::open(&self.path, owner, group, 0o700)
                .expect("open test upstream directory");
            let metadata =
                require_upstream_socket(&anchor, owner).expect("inspect test upstream socket");
            Arc::new(UpstreamSocket {
                anchor,
                authority: upstream_authority(&metadata),
                socket_owner: owner,
                directory_owner: owner,
                directory_group: group,
                directory_mode: 0o700,
            })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let exact_parent = self.path.parent() == Some(self.parent.as_path());
            let unique_name = self
                .path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name.contains('-'));
            if exact_parent && unique_name {
                let _ignored = fs::remove_dir_all(&self.path);
            }
        }
    }
}
