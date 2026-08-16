use std::{
    ffi::{OsStr, OsString},
    fmt, fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::Receiver,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(any(unix, test))]
use std::sync::mpsc;

use automata_ci_execution::{Cancellation, ExecutionOutputRecord, ExecutionOutputStream};
#[cfg(any(unix, test))]
use automata_ci_execution::{MAX_EXECUTION_OUTPUT_RECORD_BYTES, MAX_EXECUTION_OUTPUT_RECORDS};

use crate::{
    PodmanConfigurationError, PodmanLaunchTrustHandle, config, endpoint::EnvironmentDocument,
};

const POLL_INTERVAL: Duration = Duration::from_millis(20);
const TERMINATION_GRACE: Duration = Duration::from_millis(250);
const SYSTEM_CONFIG_DIRECTORY_NAME: &str = "podman-system-config";
const CONTAINERS_CONF_NAME: &str = "containers.conf";
const STORAGE_CONF_NAME: &str = "storage.conf";
const REGISTRIES_CONF_NAME: &str = "registries.conf";
const POLICY_NAME: &str = "policy.json";
const MOUNTS_CONF_NAME: &str = "mounts.conf";
const AUTH_FILE_NAME: &str = "auth.json";
const EMPTY_HOOKS_DIRECTORY_NAME: &str = "empty-hooks";
const EMPTY_CDI_DIRECTORY_NAME: &str = "empty-cdi";
const PROCESS_TRANSIENT_DIRECTORY_NAME: &str = "process-transient";
#[cfg(unix)]
const STORAGE_CONF_CONTENTS: &[u8] = b"[storage]\ndriver = \"vfs\"\ntransient_store = false\n";
#[cfg(unix)]
const REGISTRIES_CONF_CONTENTS: &[u8] = b"unqualified-search-registries = []\nshort-name-mode = \"disabled\"\ncredential-helpers = [\"containers-auth.json\"]\n";
#[cfg(unix)]
const POLICY_CONTENTS: &[u8] = b"{\"default\":[{\"type\":\"insecureAcceptAnything\"}]}\n";
#[cfg(unix)]
const MOUNTS_CONF_CONTENTS: &[u8] = b"";
#[cfg(unix)]
const AUTH_FILE_CONTENTS: &[u8] = b"{\"auths\":{}}";

/// Explicit allowlisted environment for local rootless Podman processes.
#[derive(Clone)]
pub struct PodmanProcessEnvironment {
    home: PathBuf,
    runtime_directory: PathBuf,
    state_root: PathBuf,
    approved_helper_directory: PathBuf,
    conmon_path: PathBuf,
    oci_runtime_path: PathBuf,
    init_path: PathBuf,
    seccomp_profile_path: PathBuf,
    system_config_directory: PathBuf,
    containers_conf_path: PathBuf,
    storage_conf_path: PathBuf,
    registries_conf_path: PathBuf,
    policy_path: PathBuf,
    mounts_conf_path: PathBuf,
    auth_file_path: PathBuf,
    empty_hooks_directory: PathBuf,
    empty_cdi_directory: PathBuf,
    process_transient_directory: PathBuf,
    dbus_session_bus_address: OsString,
    #[cfg(unix)]
    containers_conf_contents: Vec<u8>,
    launch_trust: Option<PodmanLaunchTrustHandle>,
}

impl PodmanProcessEnvironment {
    /// Creates the complete environment passed after `env_clear`.
    ///
    /// # Errors
    ///
    /// Rejects relative, traversing, non-text configuration paths and helper
    /// directories that cannot suppress Podman's host `/usr/sbin` fallback.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        home: impl Into<PathBuf>,
        runtime_directory: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        approved_helper_directory: impl Into<PathBuf>,
        conmon_path: impl Into<PathBuf>,
        oci_runtime_path: impl Into<PathBuf>,
        init_path: impl Into<PathBuf>,
        seccomp_profile_path: impl Into<PathBuf>,
    ) -> Result<Self, PodmanConfigurationError> {
        let home = home.into();
        let runtime_directory = runtime_directory.into();
        let state_root = state_root.into();
        let approved_helper_directory = approved_helper_directory.into();
        let conmon_path = conmon_path.into();
        let oci_runtime_path = oci_runtime_path.into();
        let init_path = init_path.into();
        let seccomp_profile_path = seccomp_profile_path.into();
        let paths: [&Path; 8] = [
            home.as_path(),
            runtime_directory.as_path(),
            state_root.as_path(),
            approved_helper_directory.as_path(),
            conmon_path.as_path(),
            oci_runtime_path.as_path(),
            init_path.as_path(),
            seccomp_profile_path.as_path(),
        ];
        let helper_text = approved_helper_directory.to_str();
        let runtime_text = runtime_directory.to_str();
        if !paths.into_iter().all(config::safe_host_path)
            || !approved_helper_directory.ends_with(Path::new("usr/sbin"))
            || helper_text
                .is_none_or(|value| value.contains(':') || value.chars().any(char::is_control))
            || runtime_text.is_none_or(|value| {
                value.contains([',', ';']) || value.chars().any(char::is_control)
            })
        {
            return Err(PodmanConfigurationError::InvalidProcessEnvironment);
        }

        let system_config_directory = state_root.join(SYSTEM_CONFIG_DIRECTORY_NAME);
        let containers_conf_path = system_config_directory.join(CONTAINERS_CONF_NAME);
        let storage_conf_path = system_config_directory.join(STORAGE_CONF_NAME);
        let registries_conf_path = system_config_directory.join(REGISTRIES_CONF_NAME);
        let policy_path = system_config_directory.join(POLICY_NAME);
        let mounts_conf_path = system_config_directory.join(MOUNTS_CONF_NAME);
        let auth_file_path = system_config_directory.join(AUTH_FILE_NAME);
        let empty_hooks_directory = state_root.join(EMPTY_HOOKS_DIRECTORY_NAME);
        let empty_cdi_directory = system_config_directory.join(EMPTY_CDI_DIRECTORY_NAME);
        let process_transient_directory = state_root.join(PROCESS_TRANSIENT_DIRECTORY_NAME);
        let containers_conf_contents = containers_conf_document(
            &approved_helper_directory,
            &conmon_path,
            &oci_runtime_path,
            &init_path,
            &seccomp_profile_path,
            &empty_hooks_directory,
            &empty_cdi_directory,
            None,
        )?;
        #[cfg(not(unix))]
        let _ = containers_conf_contents;
        let mut dbus_session_bus_address = OsString::from("unix:path=");
        dbus_session_bus_address.push(runtime_directory.join("no-systemd-bus"));

        Ok(Self {
            home,
            runtime_directory,
            state_root,
            approved_helper_directory,
            conmon_path,
            oci_runtime_path,
            init_path,
            seccomp_profile_path,
            system_config_directory,
            containers_conf_path,
            storage_conf_path,
            registries_conf_path,
            policy_path,
            mounts_conf_path,
            auth_file_path,
            empty_hooks_directory,
            empty_cdi_directory,
            process_transient_directory,
            dbus_session_bus_address,
            #[cfg(unix)]
            containers_conf_contents,
            launch_trust: None,
        })
    }

    /// Returns the exact home directory installed in the process environment.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Returns the exact rootless runtime directory.
    #[must_use]
    pub fn runtime_directory(&self) -> &Path {
        &self.runtime_directory
    }

    /// Returns the exact private Podman state root.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Returns the single directory installed as the process `PATH`.
    #[must_use]
    pub fn approved_helper_directory(&self) -> &Path {
        &self.approved_helper_directory
    }

    /// Returns the exact configured conmon executable.
    #[must_use]
    pub fn conmon_path(&self) -> &Path {
        &self.conmon_path
    }

    /// Returns the exact configured OCI runtime executable.
    #[must_use]
    pub fn oci_runtime_path(&self) -> &Path {
        &self.oci_runtime_path
    }

    /// Returns the exact configured container init executable.
    #[must_use]
    pub fn init_path(&self) -> &Path {
        &self.init_path
    }

    /// Returns the exact configured seccomp profile.
    #[must_use]
    pub fn seccomp_profile_path(&self) -> &Path {
        &self.seccomp_profile_path
    }

    /// Returns the directory containing all pinned Podman configuration files.
    #[must_use]
    pub fn system_config_directory(&self) -> &Path {
        &self.system_config_directory
    }

    /// Returns the exact `containers.conf` path.
    #[must_use]
    pub fn containers_conf_path(&self) -> &Path {
        &self.containers_conf_path
    }

    /// Returns the exact `storage.conf` path.
    #[must_use]
    pub fn storage_conf_path(&self) -> &Path {
        &self.storage_conf_path
    }

    /// Returns the exact `registries.conf` path.
    #[must_use]
    pub fn registries_conf_path(&self) -> &Path {
        &self.registries_conf_path
    }

    /// Returns the exact container image policy path.
    #[must_use]
    pub fn policy_path(&self) -> &Path {
        &self.policy_path
    }

    /// Returns the exact empty mounts configuration path.
    #[must_use]
    pub fn mounts_conf_path(&self) -> &Path {
        &self.mounts_conf_path
    }

    /// Returns the exact private registry authentication file path.
    #[must_use]
    pub fn auth_file_path(&self) -> &Path {
        &self.auth_file_path
    }

    pub(crate) fn enable_host_gateway_port(
        &mut self,
        port: u16,
    ) -> Result<(), PodmanConfigurationError> {
        #[cfg(unix)]
        {
            self.containers_conf_contents = containers_conf_document(
                &self.approved_helper_directory,
                &self.conmon_path,
                &self.oci_runtime_path,
                &self.init_path,
                &self.seccomp_profile_path,
                &self.empty_hooks_directory,
                &self.empty_cdi_directory,
                Some(port),
            )?;
        }
        #[cfg(not(unix))]
        let _ = port;
        Ok(())
    }

    /// Returns the exact empty hooks directory.
    #[must_use]
    pub fn empty_hooks_directory(&self) -> &Path {
        &self.empty_hooks_directory
    }

    /// Returns the exact empty CDI specification directory.
    #[must_use]
    pub fn empty_cdi_directory(&self) -> &Path {
        &self.empty_cdi_directory
    }

    /// Returns the private process temporary directory.
    #[must_use]
    pub fn process_transient_directory(&self) -> &Path {
        &self.process_transient_directory
    }

    /// Returns the deliberately unreachable private D-Bus address.
    #[must_use]
    pub fn dbus_session_bus_address(&self) -> &OsStr {
        &self.dbus_session_bus_address
    }

    #[cfg(unix)]
    pub(crate) fn containers_conf_contents(&self) -> &[u8] {
        &self.containers_conf_contents
    }

    #[cfg(unix)]
    #[allow(clippy::unused_self)]
    pub(crate) const fn storage_conf_contents(&self) -> &[u8] {
        STORAGE_CONF_CONTENTS
    }

    #[cfg(unix)]
    #[allow(clippy::unused_self)]
    pub(crate) const fn registries_conf_contents(&self) -> &[u8] {
        REGISTRIES_CONF_CONTENTS
    }

    #[cfg(unix)]
    #[allow(clippy::unused_self)]
    pub(crate) const fn policy_contents(&self) -> &[u8] {
        POLICY_CONTENTS
    }

    #[cfg(unix)]
    #[allow(clippy::unused_self)]
    pub(crate) const fn mounts_conf_contents(&self) -> &[u8] {
        MOUNTS_CONF_CONTENTS
    }

    #[cfg(unix)]
    #[allow(clippy::unused_self)]
    pub(crate) const fn auth_file_contents(&self) -> &[u8] {
        AUTH_FILE_CONTENTS
    }

    pub(crate) fn install_launch_trust(&mut self, trust: PodmanLaunchTrustHandle) {
        self.launch_trust = Some(trust);
    }

    /// Clears a command's inherited environment and installs the complete,
    /// fixed Podman provider environment.
    pub fn apply_to_command(&self, command: &mut Command) {
        command
            .env_clear()
            .env("HOME", self.home())
            .env("PATH", self.approved_helper_directory())
            .env("XDG_RUNTIME_DIR", self.runtime_directory())
            .env("TMPDIR", self.process_transient_directory())
            .env("CONTAINERS_CONF", self.containers_conf_path())
            .env("CONTAINERS_STORAGE_CONF", self.storage_conf_path())
            .env("CONTAINERS_REGISTRIES_CONF", self.registries_conf_path())
            .env("CONTAINERS_POLICY_JSON", self.policy_path())
            .env("REGISTRY_AUTH_FILE", self.auth_file_path())
            .env("DISABLE_HC_SYSTEMD", "true")
            .env("DBUS_SESSION_BUS_ADDRESS", self.dbus_session_bus_address());
    }

    /// Revalidates immutable Podman configuration and host admission gates
    /// immediately before a local Podman process is spawned.
    ///
    /// # Errors
    ///
    /// Returns a redacted configuration error if any file, directory, FIPS
    /// state, or pre-exec-hook gate is not exactly admissible.
    pub fn validate_launch(&self) -> Result<(), PodmanConfigurationError> {
        validate_launch_environment(self)
    }

    pub(crate) fn validate_provider_use(&self) -> Result<(), PodmanConfigurationError> {
        if self
            .launch_trust
            .as_ref()
            .is_some_and(|trust| !trust.revalidate())
        {
            Err(PodmanConfigurationError::InvalidProcessEnvironment)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for PodmanProcessEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PodmanProcessEnvironment")
            .field("home", &self.home)
            .field("runtime_directory", &self.runtime_directory)
            .field("state_root", &self.state_root)
            .field("approved_helper_directory", &self.approved_helper_directory)
            .field("conmon_path", &self.conmon_path)
            .field("oci_runtime_path", &self.oci_runtime_path)
            .field("init_path", &self.init_path)
            .field("seccomp_profile_path", &self.seccomp_profile_path)
            .field("launch_trust", &self.launch_trust.is_some())
            .field("forwarded_credentials", &false)
            .finish_non_exhaustive()
    }
}

#[allow(clippy::too_many_arguments)] // The renderer binds every validated private Podman path.
fn containers_conf_document(
    approved_helper_directory: &Path,
    conmon_path: &Path,
    oci_runtime_path: &Path,
    init_path: &Path,
    seccomp_profile_path: &Path,
    empty_hooks_directory: &Path,
    empty_cdi_directory: &Path,
    host_gateway_port: Option<u16>,
) -> Result<Vec<u8>, PodmanConfigurationError> {
    let values = [
        approved_helper_directory,
        conmon_path,
        oci_runtime_path,
        init_path,
        seccomp_profile_path,
        empty_hooks_directory,
        empty_cdi_directory,
    ]
    .map(toml_path)
    .into_iter()
    .collect::<Option<Vec<_>>>()
    .ok_or(PodmanConfigurationError::InvalidProcessEnvironment)?;
    let [helper, conmon, runtime, init, seccomp, hooks, cdi]: [String; 7] = values
        .try_into()
        .map_err(|_| PodmanConfigurationError::InvalidProcessEnvironment)?;
    let conmon_environment = approved_helper_directory
        .to_str()
        .map(|directory| format!("PATH={directory}"))
        .and_then(|value| toml_string(&value))
        .ok_or(PodmanConfigurationError::InvalidProcessEnvironment)?;
    let pasta_options = match host_gateway_port {
        Some(port) if port != 0 => {
            format!("pasta_options = [\"--tcp-ns\", \"{port}\"]\n")
        }
        Some(_) => return Err(PodmanConfigurationError::InvalidProcessEnvironment),
        None => String::new(),
    };
    Ok(format!(
        "[containers]\ninit_path = {init}\nlog_driver = \"k8s-file\"\nseccomp_profile = {seccomp}\n\n[engine]\ncdi_spec_dirs = [{cdi}]\ncompat_api_enforce_docker_hub = true\nconmon_env_vars = [{conmon_environment}]\nconmon_path = [{conmon}]\ndatabase_backend = \"sqlite\"\nevents_logger = \"none\"\nhelper_binaries_dir = [{helper}]\nhooks_dir = [{hooks}]\nruntime = {runtime}\n\n[network]\ndefault_rootless_network_cmd = \"pasta\"\nfirewall_driver = \"nftables\"\nnetavark_plugin_dirs = []\nnetwork_backend = \"netavark\"\n{pasta_options}rootless_port_forwarder = \"rootlessport\"\n"
    )
    .into_bytes())
}

fn toml_path(path: &Path) -> Option<String> {
    toml_string(path.to_str()?)
}

fn toml_string(value: &str) -> Option<String> {
    if value.chars().any(char::is_control) {
        return None;
    }
    Some(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

#[cfg(unix)]
fn validate_launch_environment(
    environment: &PodmanProcessEnvironment,
) -> Result<(), PodmanConfigurationError> {
    validate_launch_environment_unix(environment)
        .map_err(|()| PodmanConfigurationError::InvalidProcessEnvironment)
}

#[cfg(not(unix))]
fn validate_launch_environment(
    _environment: &PodmanProcessEnvironment,
) -> Result<(), PodmanConfigurationError> {
    Err(PodmanConfigurationError::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_launch_environment_unix(environment: &PodmanProcessEnvironment) -> Result<(), ()> {
    use rustix::fs::{Mode, OFlags, open, openat};
    use rustix::io::Errno;

    environment
        .launch_trust
        .as_ref()
        .filter(|trust| trust.revalidate())
        .map(|_| ())
        .ok_or(())?;

    let directory_flags =
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let state_root = open_absolute_directory_no_follow(environment.state_root())?;
    validate_private_directory(&state_root)?;
    let system_config = openat(
        &state_root,
        SYSTEM_CONFIG_DIRECTORY_NAME,
        directory_flags,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    validate_private_directory(&system_config)?;

    for (name, expected) in [
        (CONTAINERS_CONF_NAME, environment.containers_conf_contents()),
        (STORAGE_CONF_NAME, environment.storage_conf_contents()),
        (REGISTRIES_CONF_NAME, environment.registries_conf_contents()),
        (POLICY_NAME, environment.policy_contents()),
        (MOUNTS_CONF_NAME, environment.mounts_conf_contents()),
        (AUTH_FILE_NAME, environment.auth_file_contents()),
    ] {
        validate_exact_private_file(&system_config, name, expected)?;
    }
    validate_empty_private_directory(&state_root, EMPTY_HOOKS_DIRECTORY_NAME)?;
    validate_empty_private_directory(&system_config, EMPTY_CDI_DIRECTORY_NAME)?;

    let file_flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    match open("/proc/sys/crypto/fips_enabled", file_flags, Mode::empty()) {
        Err(Errno::NOENT) => {}
        Ok(descriptor) => {
            if read_bounded(descriptor, 3)? != b"0\n" {
                return Err(());
            }
        }
        Err(_) => return Err(()),
    }
    match open(
        "/etc/containers/podman_preexec_hooks.txt",
        file_flags,
        Mode::empty(),
    ) {
        Err(Errno::NOENT) => {}
        Ok(_) | Err(_) => return Err(()),
    }
    Ok(())
}

#[cfg(unix)]
fn open_absolute_directory_no_follow(path: &Path) -> Result<rustix::fd::OwnedFd, ()> {
    use std::path::Component;

    use rustix::fs::{Mode, OFlags, open, openat};

    let flags =
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let mut descriptor = open("/", flags, Mode::empty()).map_err(|_| ())?;
    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                descriptor = openat(&descriptor, name, flags, Mode::empty()).map_err(|_| ())?;
                normal_components = normal_components.checked_add(1).ok_or(())?;
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => return Err(()),
        }
    }
    (normal_components > 0).then_some(descriptor).ok_or(())
}

#[cfg(unix)]
fn validate_private_directory(descriptor: &impl std::os::fd::AsFd) -> Result<(), ()> {
    use rustix::fs::{FileType, fstat};

    let metadata = fstat(descriptor).map_err(|_| ())?;
    if FileType::from_raw_mode(metadata.st_mode).is_dir()
        && metadata.st_uid == rustix::process::geteuid().as_raw()
        && metadata.st_mode & 0o7777 == 0o700
    {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(unix)]
fn validate_exact_private_file(
    parent: &impl std::os::fd::AsFd,
    name: &str,
    expected: &[u8],
) -> Result<(), ()> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, openat};

    let descriptor = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    let metadata = fstat(&descriptor).map_err(|_| ())?;
    let actual_size = usize::try_from(metadata.st_size).map_err(|_| ())?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_nlink != 1
        || actual_size != expected.len()
    {
        return Err(());
    }
    (read_bounded(descriptor, expected.len().saturating_add(1))? == expected)
        .then_some(())
        .ok_or(())
}

#[cfg(unix)]
fn validate_empty_private_directory(parent: &impl std::os::fd::AsFd, name: &str) -> Result<(), ()> {
    use rustix::fs::{Dir, Mode, OFlags, openat};

    let descriptor = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    validate_private_directory(&descriptor)?;
    let mut entries = Dir::read_from(&descriptor).map_err(|_| ())?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|_| ())?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Err(());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_bounded(descriptor: rustix::fd::OwnedFd, limit: usize) -> Result<Vec<u8>, ()> {
    use std::{fs::File, io::Read as _};

    let mut contents = Vec::with_capacity(limit.min(256));
    File::from(descriptor)
        .take(u64::try_from(limit).map_err(|_| ())?)
        .read_to_end(&mut contents)
        .map_err(|_| ())?;
    Ok(contents)
}

enum CommandInput<'input> {
    Bytes(Arc<[u8]>),
    Environment(EnvironmentDocument<'input>),
}

impl CommandInput<'_> {
    fn byte_len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Environment(document) => document.byte_len(),
        }
    }

    fn segments(&self) -> CommandInputSegments<'_, '_> {
        CommandInputSegments {
            input: self,
            segment_index: 0,
        }
    }
}

struct CommandInputSegments<'a, 'input> {
    input: &'a CommandInput<'input>,
    segment_index: usize,
}

impl<'a> Iterator for CommandInputSegments<'a, '_> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        match self.input {
            CommandInput::Bytes(bytes) if self.segment_index == 0 => {
                self.segment_index = 1;
                Some(bytes)
            }
            CommandInput::Bytes(_) => None,
            CommandInput::Environment(document) => {
                let variable_index = self.segment_index / 4;
                let variable = document.variables().get(variable_index)?;
                if crate::endpoint::requires_process_inheritance(variable.value().expose()) {
                    self.segment_index = (variable_index + 1) * 4;
                    return self.next();
                }
                let segment = match self.segment_index % 4 {
                    0 => variable.name().as_str().as_bytes(),
                    1 => b"=",
                    2 => variable.value().expose().as_bytes(),
                    _ => b"\n",
                };
                self.segment_index += 1;
                Some(segment)
            }
        }
    }
}

/// One argv-only, bounded Podman process request.
pub struct CommandRequest<'input> {
    program: PathBuf,
    arguments: Vec<OsString>,
    timeout: Duration,
    aggregate_deadline: Instant,
    output_limit: usize,
    input: Option<CommandInput<'input>>,
}

impl<'input> CommandRequest<'input> {
    /// Creates a bounded argv-only process request with no child input.
    ///
    /// `output_limit` is one aggregate budget shared by standard output and
    /// standard error. Execution stops at the earlier of `timeout` after
    /// launch and `aggregate_deadline`.
    #[must_use]
    pub fn new(
        program: PathBuf,
        arguments: Vec<OsString>,
        timeout: Duration,
        aggregate_deadline: Instant,
        output_limit: usize,
    ) -> Self {
        Self {
            program,
            arguments,
            timeout,
            aggregate_deadline,
            output_limit,
            input: None,
        }
    }

    /// Supplies anonymous bytes to the child process's standard input.
    ///
    /// The bytes may contain credentials or other sensitive payloads. They
    /// remain in memory, are redacted from [`Debug`](fmt::Debug), and are never
    /// included in the child argv or environment.
    #[must_use]
    pub fn with_stdin(mut self, stdin: Vec<u8>) -> Self {
        self.input = Some(CommandInput::Bytes(Arc::from(stdin)));
        self
    }

    pub(crate) fn with_environment_stdin(
        mut self,
        environment: EnvironmentDocument<'input>,
    ) -> Self {
        self.input = Some(CommandInput::Environment(environment));
        self
    }

    /// Returns the exact executable path; executors must not perform shell expansion.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Returns the exact argument vector; its contents are sensitive diagnostics.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// Returns the per-process timeout measured from the execution attempt.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the operation-wide absolute deadline shared across commands.
    #[must_use]
    pub const fn aggregate_deadline(&self) -> Instant {
        self.aggregate_deadline
    }

    /// Returns the aggregate retained-byte budget shared by both output streams.
    #[must_use]
    pub const fn output_limit(&self) -> usize {
        self.output_limit
    }

    /// Returns the contiguous anonymous standard-input payload, when present.
    ///
    /// Typed environment input is deliberately not flattened and is instead
    /// available through [`Self::stdin_segments`]. Returned bytes may be
    /// secret and must not enter logs or durable diagnostics.
    #[must_use]
    pub fn stdin(&self) -> Option<&[u8]> {
        match self.input.as_ref() {
            Some(CommandInput::Bytes(bytes)) => Some(bytes),
            Some(CommandInput::Environment(_)) | None => None,
        }
    }

    /// Returns the exact anonymous-input byte count, when input is present.
    ///
    /// This exposes only a size. It does not flatten typed environment input.
    #[must_use]
    pub fn stdin_byte_len(&self) -> Option<usize> {
        self.input.as_ref().map(CommandInput::byte_len)
    }

    /// Iterates the exact anonymous-input byte segments in write order.
    ///
    /// Segment contents may include credentials. They must not enter logs,
    /// metrics, or durable diagnostics. Consumers must preserve every segment
    /// and report an incomplete input if any byte cannot be written.
    pub fn stdin_segments(&self) -> impl Iterator<Item = &[u8]> {
        self.input.iter().flat_map(CommandInput::segments)
    }

    /// Iterates workload values carried only in the anonymous Podman client
    /// environment because env-file framing cannot represent them.
    ///
    /// Values may be secret and must never enter logs or durable diagnostics.
    pub fn inherited_environment(&self) -> impl Iterator<Item = (&str, &str)> {
        self.input
            .iter()
            .filter_map(|input| match input {
                CommandInput::Environment(document) => Some(document),
                CommandInput::Bytes(_) => None,
            })
            .flat_map(EnvironmentDocument::inherited_variables)
            .map(|variable| (variable.name().as_str(), variable.value().expose()))
    }

    fn has_stdin_input(&self) -> bool {
        self.input.is_some()
    }
}

impl fmt::Debug for CommandRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandRequest")
            .field("program", &self.program)
            .field("argument_count", &self.arguments.len())
            .field("arguments", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("output_limit", &self.output_limit)
            .field("stdin_bytes", &self.stdin_byte_len())
            .field("stdin", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Bounded process termination classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandTermination {
    /// The process exited; `None` means no numeric exit code was available,
    /// such as when it was terminated by a signal.
    Exited(Option<i32>),
    /// The command or enclosing operation reached its deadline and was reaped.
    TimedOut,
    /// Caller cancellation terminated and reaped the command process group.
    Cancelled,
    /// The process could not be started or safely observed to completion.
    FailedToStart,
}

/// Bounded command output. Debug formatting redacts output bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct CommandOutput {
    termination: CommandTermination,
    records: Vec<ExecutionOutputRecord>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
    stdin_fully_written: bool,
}

impl CommandOutput {
    /// Constructs a successful synthetic result, primarily for injected executors.
    #[must_use]
    pub fn success(stdout: impl Into<Vec<u8>>) -> Self {
        let stdout = stdout.into();
        Self {
            termination: CommandTermination::Exited(Some(0)),
            records: split_output_records(&stdout, &[]),
            stdout,
            stderr: Vec::new(),
            truncated: false,
            stdin_fully_written: true,
        }
    }

    /// Constructs a nonzero synthetic result with the supplied exit code and error bytes.
    #[must_use]
    pub fn failure(code: i32, stderr: impl Into<Vec<u8>>) -> Self {
        let stderr = stderr.into();
        Self {
            termination: CommandTermination::Exited(Some(code)),
            records: split_output_records(&[], &stderr),
            stdout: Vec::new(),
            stderr,
            truncated: false,
            stdin_fully_written: true,
        }
    }

    /// Constructs a synthetic terminal result without captured output.
    ///
    /// This constructor is truthful only when no input was expected or all
    /// expected input was already written. Use
    /// [`Self::terminated_with_incomplete_stdin`] otherwise.
    #[must_use]
    pub fn terminated(termination: CommandTermination) -> Self {
        Self {
            termination,
            records: split_output_records(&[], &[]),
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
            stdin_fully_written: true,
        }
    }

    /// Constructs a terminal result whose expected standard input was incomplete.
    ///
    /// Injected executors use this when a child exits, rejects the pipe, or is
    /// interrupted before every supplied byte is written. The result can
    /// never represent successful command completion.
    #[must_use]
    pub fn terminated_with_incomplete_stdin(termination: CommandTermination) -> Self {
        let mut output = Self::terminated(termination);
        output.stdin_fully_written = false;
        output
    }

    pub(crate) fn terminated_before_input(
        request: &CommandRequest<'_>,
        termination: CommandTermination,
    ) -> Self {
        if request.has_stdin_input() {
            Self::terminated_with_incomplete_stdin(termination)
        } else {
            Self::terminated(termination)
        }
    }

    /// Returns the bounded process termination classification.
    #[must_use]
    pub const fn termination(&self) -> CommandTermination {
        self.termination
    }

    /// Returns output observations in their canonical cross-pipe order.
    ///
    /// Captured bytes may contain credentials. Consumers must apply output
    /// policy before persistence.
    #[must_use]
    pub fn records(&self) -> &[ExecutionOutputRecord] {
        &self.records
    }

    /// Returns retained standard-output bytes, which callers must treat as sensitive.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Returns retained standard-error bytes, which callers must treat as sensitive.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Reports whether the process returned numeric exit status zero.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(self.termination, CommandTermination::Exited(Some(0)))
    }

    /// Reports whether either output stream exceeded the shared retention budget.
    #[must_use]
    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns whether every supplied standard-input byte reached the child.
    ///
    /// This is always `true` for requests without a standard-input payload.
    #[must_use]
    pub const fn stdin_was_fully_written(&self) -> bool {
        self.stdin_fully_written
    }

    pub(crate) fn into_records(self) -> Vec<ExecutionOutputRecord> {
        self.records
    }
}

impl fmt::Debug for CommandOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandOutput")
            .field("termination", &self.termination)
            .field("records", &self.records.len())
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("output", &"[REDACTED]")
            .field("truncated", &self.truncated)
            .field("stdin_fully_written", &self.stdin_fully_written)
            .finish()
    }
}

/// Injectable Podman process boundary.
pub trait PodmanCommandExecutor: fmt::Debug + Send + Sync {
    /// Executes one request using only its exact program, argv, anonymous
    /// input, and allowlisted process environment.
    ///
    /// Implementations must honor cancellation and both deadlines, apply the
    /// shared output bound, reap all child processes, and keep argv, input,
    /// environment values, and output bytes out of diagnostics.
    fn execute(
        &self,
        request: &CommandRequest,
        environment: &PodmanProcessEnvironment,
        cancellation: &dyn Cancellation,
    ) -> CommandOutput;

    /// Returns the empty delegated cgroup beneath which Podman may create jobs.
    ///
    /// The returned cgroup has a live zero-swap ancestor limit and delegated
    /// CPU, memory, and process controllers. `None` fails sandbox creation.
    fn delegated_no_swap_cgroup(&self) -> Option<String>;

    /// Enforces the live whole-job cgroup contract for a container process.
    ///
    /// Implementations must prove that the stable process is a strict
    /// descendant of `pod_cgroup`, that the delegated ancestor still has a
    /// live zero-swap boundary, and that the exact pod cgroup has the requested
    /// aggregate `pids.max`. Requested Podman configuration is not evidence.
    fn enforces_job_cgroup(&self, process_id: u32, pod_cgroup: &str, aggregate_pids: u32) -> bool;
}

/// Safe-Rust local process adapter with process-group cancellation.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCommandExecutor;

impl PodmanCommandExecutor for SystemCommandExecutor {
    fn execute(
        &self,
        request: &CommandRequest,
        environment: &PodmanProcessEnvironment,
        cancellation: &dyn Cancellation,
    ) -> CommandOutput {
        execute_system(request, environment, cancellation)
    }

    fn delegated_no_swap_cgroup(&self) -> Option<String> {
        delegated_no_swap_cgroup().ok()
    }

    fn enforces_job_cgroup(&self, process_id: u32, pod_cgroup: &str, aggregate_pids: u32) -> bool {
        enforce_job_cgroup(process_id, pod_cgroup, aggregate_pids).is_ok()
    }
}

fn delegated_no_swap_cgroup() -> Result<String, ()> {
    let supervisor = process_cgroup(std::process::id())?;
    let separator = supervisor.rfind('/').filter(|index| *index > 0).ok_or(())?;
    let delegated = parse_cgroup_path(&supervisor[..separator])?;
    verify_zero_swap_boundary(&delegated)?;
    let procs = read_cgroup_file(&delegated, "cgroup.procs")?;
    if !procs.iter().all(u8::is_ascii_whitespace) {
        return Err(());
    }
    let available = read_cgroup_file(&delegated, "cgroup.controllers")?;
    verify_controllers(&available)?;
    fs::OpenOptions::new()
        .write(true)
        .open(cgroup_file_path(&delegated, "cgroup.subtree_control")?)
        .and_then(|mut file| file.write_all(b"+cpu +memory +pids"))
        .map_err(|_| ())?;
    let controllers = read_cgroup_file(&delegated, "cgroup.subtree_control")?;
    verify_controllers(&controllers)?;
    Ok(delegated)
}

fn verify_controllers(document: &[u8]) -> Result<(), ()> {
    for required in [b"cpu".as_slice(), b"memory".as_slice(), b"pids".as_slice()] {
        if !document
            .split(u8::is_ascii_whitespace)
            .any(|value| value == required)
        {
            return Err(());
        }
    }
    Ok(())
}

fn enforce_job_cgroup(
    process_id: u32,
    expected_pod_cgroup: &str,
    aggregate_pids: u32,
) -> Result<(), ()> {
    if aggregate_pids == 0 {
        return Err(());
    }
    let delegated = delegated_no_swap_cgroup()?;
    let pod_cgroup = parse_cgroup_path(expected_pod_cgroup)?;
    if !strict_cgroup_descendant(&pod_cgroup, &delegated) {
        return Err(());
    }
    let before = process_identity(process_id)?;
    let workload = &before.0;
    if !strict_cgroup_descendant(workload, &pod_cgroup) {
        return Err(());
    }
    verify_zero_swap_boundary(&delegated)?;
    fs::OpenOptions::new()
        .write(true)
        .open(cgroup_file_path(&pod_cgroup, "pids.max")?)
        .and_then(|mut file| file.write_all(aggregate_pids.to_string().as_bytes()))
        .map_err(|_| ())?;
    let configured = read_cgroup_file(&pod_cgroup, "pids.max")?;
    if configured != aggregate_pids.to_string().as_bytes()
        && configured != format!("{aggregate_pids}\n").as_bytes()
    {
        return Err(());
    }
    (process_identity(process_id)? == before)
        .then_some(())
        .ok_or(())
}

fn strict_cgroup_descendant(value: &str, ancestor: &str) -> bool {
    value
        .strip_prefix(ancestor)
        .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1)
}

fn verify_zero_swap_boundary(cgroup: &str) -> Result<(), ()> {
    match read_cgroup_file(cgroup, "memory.swap.max")?.as_slice() {
        b"0" | b"0\n" => {}
        _ => return Err(()),
    }
    match read_cgroup_file(cgroup, "memory.swap.current")?.as_slice() {
        b"0" | b"0\n" => Ok(()),
        _ => Err(()),
    }
}

fn read_cgroup_file(cgroup: &str, leaf: &str) -> Result<Vec<u8>, ()> {
    fs::read(cgroup_file_path(cgroup, leaf)?).map_err(|_| ())
}

fn cgroup_file_path(cgroup: &str, leaf: &str) -> Result<PathBuf, ()> {
    let relative = cgroup.strip_prefix('/').ok_or(())?;
    Ok(Path::new("/sys/fs/cgroup").join(relative).join(leaf))
}

fn parse_cgroup_path(value: &str) -> Result<String, ()> {
    let components = value.strip_prefix('/').ok_or(())?.split('/');
    if value.len() > 4_096
        || value.bytes().any(|byte| byte.is_ascii_control())
        || components
            .clone()
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(());
    }
    Ok(value.to_owned())
}

fn parse_unified_cgroup(document: &str) -> Result<String, ()> {
    let mut values = document.lines().filter_map(|line| line.strip_prefix("0::"));
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    parse_cgroup_path(value)
}

pub(crate) fn process_cgroup(process_id: u32) -> Result<String, ()> {
    if process_id <= 1 {
        return Err(());
    }
    let path = Path::new("/proc")
        .join(process_id.to_string())
        .join("cgroup");
    let document = fs::read_to_string(path).map_err(|_| ())?;
    parse_unified_cgroup(&document)
}

fn process_identity(process_id: u32) -> Result<(String, u64), ()> {
    let before = process_start_time(process_id)?;
    let cgroup = process_cgroup(process_id)?;
    let after = process_start_time(process_id)?;
    (before == after).then_some((cgroup, after)).ok_or(())
}

fn process_start_time(process_id: u32) -> Result<u64, ()> {
    let stat = fs::read_to_string(Path::new("/proc").join(process_id.to_string()).join("stat"))
        .map_err(|_| ())?;
    parse_process_start_time(&stat)
}

fn parse_process_start_time(document: &str) -> Result<u64, ()> {
    let closing_parenthesis = document.rfind(')').ok_or(())?;
    let start_time = document
        .get(closing_parenthesis + 1..)
        .ok_or(())?
        .split_ascii_whitespace()
        .nth(19)
        .ok_or(())?
        .parse::<u64>()
        .map_err(|_| ())?;
    (start_time > 0).then_some(start_time).ok_or(())
}

#[cfg(test)]
mod cgroup_tests {
    use super::{parse_process_start_time, parse_unified_cgroup, strict_cgroup_descendant};

    #[test]
    fn unified_cgroup_parser_accepts_one_bounded_absolute_path() {
        assert_eq!(
            parse_unified_cgroup("0::/runner.service/libpod/job.scope\n"),
            Ok("/runner.service/libpod/job.scope".to_owned())
        );
    }

    #[test]
    fn unified_cgroup_parser_rejects_ambiguous_or_escaping_paths() {
        for document in [
            "0::/\n",
            "0:://escape\n",
            "0::/runner//job\n",
            "0::/runner/./job\n",
            "0::/runner/../job\n",
            "0::/runner/job/\n",
            "0::/runner/job\n0::/runner/other\n",
        ] {
            assert!(parse_unified_cgroup(document).is_err(), "{document:?}");
        }
    }

    #[test]
    fn unified_cgroup_parser_rejects_legacy_or_unbounded_documents() {
        assert!(parse_unified_cgroup("1:name=systemd:/runner\n").is_err());
        assert!(parse_unified_cgroup(&format!("0::/{}\n", "a".repeat(4_096))).is_err());
    }

    #[test]
    fn process_start_time_parser_handles_spaces_and_parentheses_in_comm() {
        let fields = std::iter::once("S".to_owned())
            .chain((1..=18).map(|value| value.to_string()))
            .chain(std::iter::once("4242".to_owned()))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            parse_process_start_time(&format!("123 (worker ) name) {fields}\n")),
            Ok(4_242)
        );
    }

    #[test]
    fn process_start_time_parser_rejects_missing_truncated_or_zero_values() {
        for document in [
            "123 worker S 1 2",
            "123 (worker) S 1 2",
            "123 (worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 0",
        ] {
            assert!(parse_process_start_time(document).is_err(), "{document:?}");
        }
    }

    #[test]
    fn exact_pod_cgroup_membership_requires_a_strict_component_descendant() {
        assert!(strict_cgroup_descendant(
            "/runner/job/container.scope",
            "/runner/job"
        ));
        assert!(!strict_cgroup_descendant("/runner/job", "/runner/job"));
        assert!(!strict_cgroup_descendant(
            "/runner/job-other/container.scope",
            "/runner/job"
        ));
        assert!(!strict_cgroup_descendant(
            "/runner/other/container.scope",
            "/runner/job"
        ));
    }
}

/// Long-running, local Podman subprocess owned by one adapter operation.
#[cfg(unix)]
pub(crate) struct PersistentPodmanProcess {
    child: Child,
    active: bool,
}

#[cfg(unix)]
impl fmt::Debug for PersistentPodmanProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentPodmanProcess")
            .field("process_id", &self.child.id())
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl PersistentPodmanProcess {
    pub(crate) fn spawn(
        program: &Path,
        arguments: &[OsString],
        environment: &PodmanProcessEnvironment,
    ) -> Result<Self, ()> {
        let mut command = Command::new(program);
        environment.apply_to_command(&mut command);
        command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        environment.validate_launch().map_err(|_| ())?;
        command
            .spawn()
            .map(|child| Self {
                child,
                active: true,
            })
            .map_err(|_| ())
    }

    pub(crate) fn has_exited(&mut self) -> Result<bool, ()> {
        let exited = matches!(
            poll_child_exit(&mut self.child)?,
            ChildExitObservation::Exited(_)
        );
        if exited {
            self.stop();
        }
        Ok(exited)
    }

    pub(crate) fn stop(&mut self) {
        if self.active {
            terminate_process_group(&mut self.child, TERMINATION_GRACE);
            self.active = false;
        }
    }
}

#[cfg(unix)]
impl Drop for PersistentPodmanProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

fn execute_system(
    request: &CommandRequest<'_>,
    environment: &PodmanProcessEnvironment,
    cancellation: &dyn Cancellation,
) -> CommandOutput {
    if cancellation.disposition().requires_termination() {
        return interrupted_before_stdin(request, CommandTermination::Cancelled);
    }
    let now = Instant::now();
    if now >= request.aggregate_deadline() {
        return interrupted_before_stdin(request, CommandTermination::TimedOut);
    }
    let deadline = now
        .checked_add(request.timeout())
        .unwrap_or(now)
        .min(request.aggregate_deadline());
    let Ok((mut child, stdin, stdout, stderr)) = spawn_child(request, environment) else {
        return interrupted_before_stdin(request, CommandTermination::FailedToStart);
    };
    let Ok(output_capture) = OutputCapture::spawn(stdout, stderr, request.output_limit()) else {
        terminate_process_group(&mut child, Duration::ZERO);
        return interrupted_before_stdin(request, CommandTermination::FailedToStart);
    };
    thread::scope(|scope| {
        let stdin = match (stdin, request.input.as_ref()) {
            (Some(stdin), Some(input)) => {
                let Ok(writer) = InputWriter::spawn(scope, stdin, input) else {
                    terminate_process_group(&mut child, Duration::ZERO);
                    return interrupted_before_stdin(request, CommandTermination::FailedToStart);
                };
                Some(writer)
            }
            (None, None) => None,
            _ => {
                terminate_process_group(&mut child, Duration::ZERO);
                return interrupted_before_stdin(request, CommandTermination::FailedToStart);
            }
        };
        let termination = wait_for_child(&mut child, deadline, cancellation);
        #[cfg(target_os = "linux")]
        if matches!(termination, CommandTermination::Exited(_)) {
            terminate_remaining_process_group(&child);
            let _ = child.wait();
        }
        #[cfg(all(unix, not(target_os = "linux")))]
        if matches!(termination, CommandTermination::Exited(_)) {
            terminate_remaining_process_group(&child);
        }
        let captured = output_capture.finish(deadline);
        let stdin_fully_written = stdin.is_none_or(|writer| writer.finish(deadline));
        CommandOutput {
            termination,
            records: captured.records,
            stdout: captured.stdout,
            stderr: captured.stderr,
            truncated: captured.incomplete,
            stdin_fully_written,
        }
    })
}

fn interrupted_before_stdin(
    request: &CommandRequest<'_>,
    termination: CommandTermination,
) -> CommandOutput {
    CommandOutput::terminated_before_input(request, termination)
}

fn spawn_child(
    request: &CommandRequest,
    environment: &PodmanProcessEnvironment,
) -> Result<
    (
        Child,
        Option<std::process::ChildStdin>,
        std::process::ChildStdout,
        std::process::ChildStderr,
    ),
    (),
> {
    let mut command = Command::new(request.program());
    environment.apply_to_command(&mut command);
    for (name, value) in request.inherited_environment() {
        command.env(name, value);
    }
    command
        .args(request.arguments())
        .stdin(if request.has_stdin_input() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    environment.validate_launch().map_err(|_| ())?;
    let mut child = command.spawn().map_err(|_| ())?;
    let stdin = if request.has_stdin_input() {
        Some(child.stdin.take().ok_or_else(|| {
            terminate_process_group(&mut child, Duration::ZERO);
        })?)
    } else {
        None
    };
    let stdout = child.stdout.take().ok_or_else(|| {
        terminate_process_group(&mut child, Duration::ZERO);
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        terminate_process_group(&mut child, Duration::ZERO);
    })?;
    Ok((child, stdin, stdout, stderr))
}

pub(crate) fn provider_control_environment_name(name: &str) -> bool {
    name == "DISABLE_HC_SYSTEMD"
        || [
            "XDG_",
            "DOCKER_",
            "CONTAINER_",
            "CONTAINERS_",
            "_CONTAINERS_",
            "PODMAN_",
            "STORAGE_",
            "REGISTRY_",
            "REGISTRIES_",
            "NETAVARK_",
            "AARDVARK_",
            "BUILDAH_",
            "BUILD_REGISTRY_",
            "CONMON_",
            "RUN_OCI_",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn wait_for_child(
    child: &mut Child,
    deadline: Instant,
    cancellation: &dyn Cancellation,
) -> CommandTermination {
    loop {
        match poll_child_exit(child) {
            Ok(ChildExitObservation::Exited(status)) => {
                return CommandTermination::Exited(status);
            }
            Ok(ChildExitObservation::Running)
                if cancellation.disposition().requires_termination() =>
            {
                terminate_process_group(child, TERMINATION_GRACE);
                return CommandTermination::Cancelled;
            }
            Ok(ChildExitObservation::Running) if Instant::now() >= deadline => {
                terminate_process_group(child, Duration::ZERO);
                return CommandTermination::TimedOut;
            }
            Ok(ChildExitObservation::Running) => {
                thread::sleep(
                    POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(()) => {
                terminate_process_group(child, Duration::ZERO);
                return CommandTermination::FailedToStart;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildExitObservation {
    Running,
    Exited(Option<i32>),
}

#[cfg(target_os = "linux")]
fn poll_child_exit(child: &mut Child) -> Result<ChildExitObservation, ()> {
    let process = i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .ok_or(())?;
    let options = rustix::process::WaitIdOptions::EXITED
        | rustix::process::WaitIdOptions::NOHANG
        | rustix::process::WaitIdOptions::NOWAIT;
    rustix::process::waitid(rustix::process::WaitId::Pid(process), options)
        .map(|status| match status {
            Some(status) => ChildExitObservation::Exited(status.exit_status()),
            None => ChildExitObservation::Running,
        })
        .map_err(|_| ())
}

#[cfg(not(target_os = "linux"))]
fn poll_child_exit(child: &mut Child) -> Result<ChildExitObservation, ()> {
    child
        .try_wait()
        .map(|status| match status {
            Some(status) => ChildExitObservation::Exited(status.code()),
            None => ChildExitObservation::Running,
        })
        .map_err(|_| ())
}

#[derive(Debug)]
struct InputWriter<'scope> {
    receiver: Receiver<bool>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::ScopedJoinHandle<'scope, ()>>,
}

impl<'scope> InputWriter<'scope> {
    #[cfg(unix)]
    fn spawn(
        scope: &'scope thread::Scope<'scope, '_>,
        writer: std::process::ChildStdin,
        input: &'scope CommandInput<'_>,
    ) -> Result<Self, ()> {
        use std::os::fd::AsFd as _;

        let flags = rustix::fs::fcntl_getfl(writer.as_fd()).map_err(|_| ())?;
        rustix::fs::fcntl_setfl(writer.as_fd(), flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(|_| ())?;
        Ok(Self::spawn_interruptible(scope, writer, input))
    }

    #[cfg(not(unix))]
    fn spawn(
        _scope: &'scope thread::Scope<'scope, '_>,
        _writer: std::process::ChildStdin,
        _input: &'scope CommandInput<'_>,
    ) -> Result<Self, ()> {
        Err(())
    }

    #[cfg(any(unix, test))]
    fn spawn_interruptible<W>(
        scope: &'scope thread::Scope<'scope, '_>,
        writer: W,
        input: &'scope CommandInput<'_>,
    ) -> Self
    where
        W: std::io::Write + Send + 'scope,
    {
        let (sender, receiver) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = scope.spawn(move || {
            let _ = sender.send(write_input_interruptible(writer, input, &worker_stop));
        });
        Self {
            receiver,
            stop,
            worker: Some(worker),
        }
    }

    fn finish(mut self, deadline: Instant) -> bool {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let fully_written = self
            .receiver
            .recv_timeout(remaining.max(POLL_INTERVAL))
            .unwrap_or(false);
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
        fully_written
    }
}

impl Drop for InputWriter<'_> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}

#[cfg(any(unix, test))]
fn write_input_interruptible<W>(mut writer: W, input: &CommandInput<'_>, stop: &AtomicBool) -> bool
where
    W: std::io::Write,
{
    let mut written = 0_usize;
    for segment in input.segments() {
        let mut offset = 0_usize;
        while offset < segment.len() {
            if stop.load(Ordering::Acquire) {
                return false;
            }
            match writer.write(&segment[offset..]) {
                Ok(0) => return false,
                Ok(count) if count <= segment.len() - offset => {
                    offset += count;
                    let Some(total) = written.checked_add(count) else {
                        return false;
                    };
                    written = total;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::park_timeout(POLL_INTERVAL);
                }
                Ok(_) | Err(_) => return false,
            }
        }
    }
    written == input.byte_len()
}

#[cfg(test)]
mod input_writer_tests {
    use std::{
        io,
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use automata_ci_execution::{
        EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionEnvironment,
    };

    use super::{CommandInput, CommandRequest, InputWriter, write_input_interruptible};
    use crate::endpoint::environment_document;

    struct ShortWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
        drops: Arc<AtomicUsize>,
        maximum_write: usize,
    }

    impl io::Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = self.maximum_write.min(bytes.len());
            self.bytes
                .lock()
                .expect("short-writer bytes lock")
                .extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for ShortWriter {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Release);
        }
    }

    struct ZeroWriter {
        drops: Arc<AtomicUsize>,
    }

    impl io::Write for ZeroWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for ZeroWriter {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Release);
        }
    }

    struct BrokenPipeWriter {
        drops: Arc<AtomicUsize>,
    }

    impl io::Write for BrokenPipeWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for BrokenPipeWriter {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Release);
        }
    }

    struct CancellingWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
        stop: Arc<AtomicBool>,
    }

    impl io::Write for CancellingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = bytes.len().min(3);
            self.bytes
                .lock()
                .expect("cancelling-writer bytes lock")
                .extend_from_slice(&bytes[..count]);
            self.stop.store(true, Ordering::Release);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct BlockedAfterPrefixWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
        wrote_prefix: Arc<AtomicBool>,
        drops: Arc<AtomicUsize>,
    }

    impl io::Write for BlockedAfterPrefixWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.wrote_prefix.load(Ordering::Acquire) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let count = bytes.len().min(3);
            self.bytes
                .lock()
                .expect("blocked-writer bytes lock")
                .extend_from_slice(&bytes[..count]);
            self.wrote_prefix.store(true, Ordering::Release);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for BlockedAfterPrefixWriter {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Release);
        }
    }

    struct PointerWitnessWriter {
        expected_address: usize,
        expected_len: usize,
        observed: Arc<AtomicBool>,
    }

    impl io::Write for PointerWitnessWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.as_ptr().addr() == self.expected_address && bytes.len() == self.expected_len {
                self.observed.store(true, Ordering::Release);
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn environment(values: &[(&str, &str)]) -> ExecutionEnvironment {
        let variables = values
            .iter()
            .map(|(name, value)| {
                EnvironmentVariable::secret(
                    EnvironmentName::new(*name).expect("test environment name"),
                    EnvironmentValue::new(*value).expect("test environment value"),
                )
            })
            .collect();
        ExecutionEnvironment::new(variables).expect("test execution environment")
    }

    fn environment_input(environment: &ExecutionEnvironment) -> CommandInput<'_> {
        CommandInput::Environment(
            environment_document(environment).expect("Podman environment document"),
        )
    }

    fn finish_writer<W>(writer: W, input: &CommandInput<'_>) -> bool
    where
        W: io::Write + Send,
    {
        std::thread::scope(|scope| {
            InputWriter::spawn_interruptible(scope, writer, input).finish(deadline())
        })
    }

    fn deadline() -> Instant {
        Instant::now()
            .checked_add(Duration::from_secs(2))
            .expect("test deadline")
    }

    #[test]
    fn environment_segments_write_exact_bytes_and_join_on_full_short_writes() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let drops = Arc::new(AtomicUsize::new(0));
        let writer = ShortWriter {
            bytes: Arc::clone(&bytes),
            drops: Arc::clone(&drops),
            maximum_write: 2,
        };
        let environment = environment(&[("FIRST", "one"), ("EMPTY", ""), ("LAST", "three")]);
        let input = environment_input(&environment);

        assert!(finish_writer(writer, &input));
        assert_eq!(
            bytes.lock().expect("written bytes lock").as_slice(),
            b"FIRST=one\nEMPTY=\nLAST=three\n"
        );
        assert_eq!(drops.load(Ordering::Acquire), 1);
    }

    #[test]
    fn environment_writer_joins_and_reports_consumer_early_exit() {
        let drops = Arc::new(AtomicUsize::new(0));
        let writer = ZeroWriter {
            drops: Arc::clone(&drops),
        };
        let environment = environment(&[("TOKEN", "sentinel")]);
        let input = environment_input(&environment);

        assert!(!finish_writer(writer, &input));
        assert_eq!(drops.load(Ordering::Acquire), 1);
    }

    #[test]
    fn environment_writer_joins_and_reports_broken_pipe() {
        let drops = Arc::new(AtomicUsize::new(0));
        let writer = BrokenPipeWriter {
            drops: Arc::clone(&drops),
        };
        let environment = environment(&[("TOKEN", "sentinel")]);
        let input = environment_input(&environment);

        assert!(!finish_writer(writer, &input));
        assert_eq!(drops.load(Ordering::Acquire), 1);
    }

    #[test]
    fn environment_writer_stops_mid_segment_on_cancellation() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let writer = CancellingWriter {
            bytes: Arc::clone(&bytes),
            stop: Arc::clone(&stop),
        };
        let environment = environment(&[("LONG_NAME", "long-value")]);
        let input = environment_input(&environment);

        assert!(!write_input_interruptible(writer, &input, &stop));
        assert_eq!(bytes.lock().expect("written bytes lock").as_slice(), b"LON");
    }

    #[test]
    fn cancelling_environment_writer_mid_segment_joins_its_worker() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let wrote_prefix = Arc::new(AtomicBool::new(false));
        let drops = Arc::new(AtomicUsize::new(0));
        let writer = BlockedAfterPrefixWriter {
            bytes: Arc::clone(&bytes),
            wrote_prefix: Arc::clone(&wrote_prefix),
            drops: Arc::clone(&drops),
        };
        let environment = environment(&[("LONG_NAME", "value")]);
        let input = environment_input(&environment);
        std::thread::scope(|scope| {
            let input_writer = InputWriter::spawn_interruptible(scope, writer, &input);
            let observation_deadline = deadline();
            while !wrote_prefix.load(Ordering::Acquire) {
                assert!(
                    Instant::now() < observation_deadline,
                    "writer did not emit its prefix"
                );
                std::thread::yield_now();
            }
            input_writer.stop.store(true, Ordering::Release);
            input_writer
                .worker
                .as_ref()
                .expect("environment writer worker")
                .thread()
                .unpark();

            assert!(!input_writer.finish(deadline()));
        });
        assert_eq!(bytes.lock().expect("written bytes lock").as_slice(), b"LON");
        assert_eq!(drops.load(Ordering::Acquire), 1);
    }

    #[test]
    fn environment_input_size_and_debug_never_expose_values() {
        const SENTINEL: &str = "environment-diagnostics-sentinel";
        let environment = environment(&[("TOKEN", SENTINEL)]);
        let document = environment_document(&environment).expect("Podman environment document");
        let expected_len = b"TOKEN=\n".len() + SENTINEL.len();
        let document_debug = format!("{document:?}");
        let request = CommandRequest::new(
            PathBuf::from("/bin/true"),
            Vec::new(),
            Duration::from_secs(1),
            deadline(),
            1,
        )
        .with_environment_stdin(document);

        assert_eq!(request.stdin_byte_len(), Some(expected_len));
        assert!(request.stdin().is_none());
        assert!(!format!("{request:?}").contains(SENTINEL));
        assert!(!document_debug.contains(SENTINEL));
        assert!(
            !request
                .arguments()
                .iter()
                .any(|argument| argument.to_string_lossy().contains(SENTINEL))
        );
    }

    #[test]
    fn multiline_environment_is_inherited_without_entering_stdin_or_diagnostics() {
        const MULTILINE: &str = "first\nsecond";
        let environment = environment(&[("PLAIN", "scalar"), ("INPUT_PATH", MULTILINE)]);
        let document = environment_document(&environment).expect("Podman environment document");
        let request = CommandRequest::new(
            PathBuf::from("/bin/true"),
            Vec::new(),
            Duration::from_secs(1),
            deadline(),
            1,
        )
        .with_environment_stdin(document);

        assert_eq!(
            request
                .stdin_segments()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
            b"PLAIN=scalar\n"
        );
        assert_eq!(
            request.inherited_environment().collect::<Vec<_>>(),
            [("INPUT_PATH", MULTILINE)]
        );
        assert!(!format!("{request:?}").contains(MULTILINE));
        assert!(
            request
                .arguments()
                .iter()
                .all(|argument| argument != MULTILINE)
        );
    }

    #[test]
    fn environment_validation_and_request_reuse_original_value_allocation() {
        let environment = environment(&[("TOKEN", "original-allocation")]);
        let original = environment.values()[0].value().expose().as_bytes();
        let document = environment_document(&environment).expect("Podman environment document");
        assert!(std::ptr::eq(document.variables(), environment.values()));
        assert_eq!(
            document.variables()[0].value().expose().as_ptr(),
            original.as_ptr()
        );

        let request = CommandRequest::new(
            PathBuf::from("/bin/true"),
            Vec::new(),
            Duration::from_secs(1),
            deadline(),
            1,
        )
        .with_environment_stdin(document);
        let transported_value = request
            .stdin_segments()
            .nth(2)
            .expect("environment value segment");
        assert_eq!(transported_value.as_ptr(), original.as_ptr());
        assert_eq!(transported_value.len(), original.len());
        let observed = Arc::new(AtomicBool::new(false));
        let writer = PointerWitnessWriter {
            expected_address: original.as_ptr().addr(),
            expected_len: original.len(),
            observed: Arc::clone(&observed),
        };
        assert!(finish_writer(
            writer,
            request.input.as_ref().expect("environment request input")
        ));
        assert!(observed.load(Ordering::Acquire));
    }
}

struct OutputCapture {
    state: Arc<Mutex<OutputCaptureState>>,
    stop: Arc<AtomicBool>,
    readers: Vec<OutputReader>,
}

impl OutputCapture {
    #[cfg(unix)]
    fn spawn<Stdout, Stderr>(
        stdout: Stdout,
        stderr: Stderr,
        output_limit: usize,
    ) -> Result<Self, ()>
    where
        Stdout: std::io::Read + std::os::fd::AsFd + Send + 'static,
        Stderr: std::io::Read + std::os::fd::AsFd + Send + 'static,
    {
        let state = Arc::new(Mutex::new(OutputCaptureState::new(output_limit)));
        let stop = Arc::new(AtomicBool::new(false));
        let stdout = OutputReader::spawn(
            stdout,
            ExecutionOutputStream::Stdout,
            Arc::clone(&state),
            Arc::clone(&stop),
        )?;
        let stderr = OutputReader::spawn(
            stderr,
            ExecutionOutputStream::Stderr,
            Arc::clone(&state),
            Arc::clone(&stop),
        )?;
        Ok(Self {
            state,
            stop,
            readers: vec![stdout, stderr],
        })
    }

    #[cfg(not(unix))]
    fn spawn<Stdout, Stderr>(
        _stdout: Stdout,
        _stderr: Stderr,
        _output_limit: usize,
    ) -> Result<Self, ()>
    where
        Stdout: std::io::Read + Send + 'static,
        Stderr: std::io::Read + Send + 'static,
    {
        Err(())
    }

    fn finish(mut self, deadline: Instant) -> CapturedOutput {
        let mut incomplete = false;
        for reader in &self.readers {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if reader
                .receiver
                .recv_timeout(remaining.max(POLL_INTERVAL))
                .is_err()
            {
                incomplete = true;
                break;
            }
        }
        if incomplete {
            capture_state(&self.state).mark_incomplete();
        }
        self.stop.store(true, Ordering::Release);
        for reader in &mut self.readers {
            if let Some(worker) = reader.worker.take() {
                worker.thread().unpark();
                if worker.join().is_err() {
                    capture_state(&self.state).mark_incomplete();
                }
            }
        }
        capture_state(&self.state).take_output()
    }
}

impl Drop for OutputCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for reader in &mut self.readers {
            if let Some(worker) = reader.worker.take() {
                worker.thread().unpark();
                let _ = worker.join();
            }
        }
    }
}

#[derive(Debug)]
struct OutputReader {
    receiver: Receiver<()>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl OutputReader {
    #[cfg(unix)]
    fn spawn<R>(
        reader: R,
        stream: ExecutionOutputStream,
        state: Arc<Mutex<OutputCaptureState>>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self, ()>
    where
        R: std::io::Read + std::os::fd::AsFd + Send + 'static,
    {
        let flags = rustix::fs::fcntl_getfl(&reader).map_err(|_| ())?;
        rustix::fs::fcntl_setfl(&reader, flags | rustix::fs::OFlags::NONBLOCK).map_err(|_| ())?;
        Ok(Self::spawn_interruptible(reader, stream, state, stop))
    }

    #[cfg(unix)]
    fn spawn_interruptible<R>(
        reader: R,
        stream: ExecutionOutputStream,
        state: Arc<Mutex<OutputCaptureState>>,
        stop: Arc<AtomicBool>,
    ) -> Self
    where
        R: std::io::Read + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            read_ordered(reader, stream, &state, &worker_stop);
            let _ = sender.send(());
        });
        Self {
            receiver,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for OutputReader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}

struct OutputCaptureState {
    remaining: usize,
    records: Vec<CapturedRecord>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_ended: bool,
    stderr_ended: bool,
    incomplete: bool,
}

impl OutputCaptureState {
    #[cfg(any(unix, test))]
    const fn new(output_limit: usize) -> Self {
        Self {
            remaining: output_limit,
            records: Vec::new(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_ended: false,
            stderr_ended: false,
            incomplete: false,
        }
    }

    #[cfg(any(unix, test))]
    fn observe_data(&mut self, stream: ExecutionOutputStream, source: &[u8]) {
        if self.stream_ended(stream) {
            self.incomplete = true;
            return;
        }
        let allowed = self.remaining.min(source.len());
        let mut retained = 0;
        while retained < allowed {
            let extended = match self.records.last_mut() {
                Some(CapturedRecord::Data {
                    stream: previous,
                    bytes,
                }) if *previous == stream && bytes.len() < MAX_EXECUTION_OUTPUT_RECORD_BYTES => {
                    let count =
                        (MAX_EXECUTION_OUTPUT_RECORD_BYTES - bytes.len()).min(allowed - retained);
                    bytes.extend_from_slice(&source[retained..retained + count]);
                    retained += count;
                    true
                }
                Some(CapturedRecord::Data { .. } | CapturedRecord::End(_)) | None => false,
            };
            if extended {
                continue;
            }
            let remaining_ends = usize::from(!self.stdout_ended) + usize::from(!self.stderr_ended);
            if self.records.len() >= MAX_EXECUTION_OUTPUT_RECORDS.saturating_sub(remaining_ends) {
                break;
            }
            let count = MAX_EXECUTION_OUTPUT_RECORD_BYTES.min(allowed - retained);
            self.records.push(CapturedRecord::Data {
                stream,
                bytes: source[retained..retained + count].to_vec(),
            });
            retained += count;
        }
        let bytes = &source[..retained];
        match stream {
            ExecutionOutputStream::Stdout => self.stdout.extend_from_slice(bytes),
            ExecutionOutputStream::Stderr => self.stderr.extend_from_slice(bytes),
        }
        self.remaining -= retained;
        if retained < source.len() {
            self.incomplete = true;
        }
    }

    #[cfg(any(unix, test))]
    fn observe_end(&mut self, stream: ExecutionOutputStream) {
        if self.stream_ended(stream) || self.records.len() >= MAX_EXECUTION_OUTPUT_RECORDS {
            self.incomplete = true;
            return;
        }
        match stream {
            ExecutionOutputStream::Stdout => self.stdout_ended = true,
            ExecutionOutputStream::Stderr => self.stderr_ended = true,
        }
        self.records.push(CapturedRecord::End(stream));
    }

    #[cfg(any(unix, test))]
    fn stream_ended(&self, stream: ExecutionOutputStream) -> bool {
        match stream {
            ExecutionOutputStream::Stdout => self.stdout_ended,
            ExecutionOutputStream::Stderr => self.stderr_ended,
        }
    }

    const fn mark_incomplete(&mut self) {
        self.incomplete = true;
    }

    fn take_output(&mut self) -> CapturedOutput {
        if !(self.stdout_ended && self.stderr_ended) {
            self.incomplete = true;
        }
        CapturedOutput {
            records: std::mem::take(&mut self.records)
                .into_iter()
                .map(CapturedRecord::into_execution_record)
                .collect(),
            stdout: std::mem::take(&mut self.stdout),
            stderr: std::mem::take(&mut self.stderr),
            incomplete: self.incomplete,
        }
    }
}

impl fmt::Debug for OutputCaptureState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutputCaptureState")
            .field("remaining", &self.remaining)
            .field("records", &self.records.len())
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("output", &"[REDACTED]")
            .field("stdout_ended", &self.stdout_ended)
            .field("stderr_ended", &self.stderr_ended)
            .field("incomplete", &self.incomplete)
            .finish()
    }
}

enum CapturedRecord {
    #[cfg(any(unix, test))]
    Data {
        stream: ExecutionOutputStream,
        bytes: Vec<u8>,
    },
    #[cfg(any(unix, test))]
    End(ExecutionOutputStream),
}

impl CapturedRecord {
    fn into_execution_record(self) -> ExecutionOutputRecord {
        match self {
            #[cfg(any(unix, test))]
            Self::Data { stream, bytes } => ExecutionOutputRecord::data(stream, bytes)
                .expect("captured record bytes are non-empty and bounded"),
            #[cfg(any(unix, test))]
            Self::End(stream) => ExecutionOutputRecord::end_of_stream(stream),
        }
    }
}

struct CapturedOutput {
    records: Vec<ExecutionOutputRecord>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    incomplete: bool,
}

fn capture_state(
    state: &Mutex<OutputCaptureState>,
) -> std::sync::MutexGuard<'_, OutputCaptureState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(any(unix, test))]
fn read_ordered<R>(
    mut reader: R,
    stream: ExecutionOutputStream,
    state: &Mutex<OutputCaptureState>,
    stop: &AtomicBool,
) where
    R: std::io::Read,
{
    let mut buffer = [0_u8; 8 * 1024];
    while !stop.load(Ordering::Acquire) {
        match reader.read(&mut buffer) {
            Ok(0) => {
                capture_state(state).observe_end(stream);
                return;
            }
            Ok(count) => capture_state(state).observe_data(stream, &buffer[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::park_timeout(POLL_INTERVAL);
            }
            Err(_) => {
                capture_state(state).mark_incomplete();
                return;
            }
        }
    }
}

fn split_output_records(stdout: &[u8], stderr: &[u8]) -> Vec<ExecutionOutputRecord> {
    let mut records = Vec::new();
    for (stream, bytes) in [
        (ExecutionOutputStream::Stdout, stdout),
        (ExecutionOutputStream::Stderr, stderr),
    ] {
        for chunk in bytes.chunks(automata_ci_execution::MAX_EXECUTION_OUTPUT_RECORD_BYTES) {
            records.push(
                ExecutionOutputRecord::data(stream, chunk.to_vec())
                    .expect("synthetic output chunks are bounded and non-empty"),
            );
        }
        records.push(ExecutionOutputRecord::end_of_stream(stream));
    }
    records
}

#[cfg(unix)]
fn terminate_process_group(child: &mut Child, grace: Duration) {
    let group = child.id();
    let _ = signal_group(group, rustix::process::Signal::TERM);
    let grace_deadline = Instant::now()
        .checked_add(grace)
        .unwrap_or_else(Instant::now);
    while Instant::now() < grace_deadline {
        match poll_child_exit(child) {
            Ok(ChildExitObservation::Exited(_)) | Err(()) => break,
            Ok(ChildExitObservation::Running) => thread::sleep(POLL_INTERVAL),
        }
    }
    let _ = signal_group(group, rustix::process::Signal::KILL);
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn terminate_remaining_process_group(child: &Child) {
    let _ = signal_group(child.id(), rustix::process::Signal::KILL);
}

#[cfg(unix)]
fn signal_group(group: u32, signal: rustix::process::Signal) -> rustix::io::Result<()> {
    let group = i32::try_from(group).map_err(|_| rustix::io::Errno::INVAL)?;
    let group = rustix::process::Pid::from_raw(group).ok_or(rustix::io::Errno::INVAL)?;
    rustix::process::kill_process_group(group, signal)
}

#[cfg(not(unix))]
fn terminate_process_group(child: &mut Child, _grace: Duration) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(all(test, target_os = "linux"))]
mod process_supervision_tests {
    use super::{ChildExitObservation, POLL_INTERVAL, PersistentPodmanProcess, poll_child_exit};
    use std::{
        fs,
        os::unix::process::CommandExt as _,
        path::Path,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn child_exit_observation_keeps_the_process_leader_waitable() {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("exit 23").process_group(0);
        let mut child = command.spawn().expect("test child must start");
        let deadline = Instant::now() + Duration::from_secs(2);
        let observed = loop {
            match poll_child_exit(&mut child).expect("exit observation must succeed") {
                ChildExitObservation::Exited(status) => break status,
                ChildExitObservation::Running if Instant::now() < deadline => {
                    thread::sleep(POLL_INTERVAL);
                }
                ChildExitObservation::Running => panic!("test child did not exit in time"),
            }
        };

        assert_eq!(observed, Some(23));
        let reaped = child
            .try_wait()
            .expect("observed child must remain waitable")
            .expect("observed child must have exited");
        assert_eq!(reaped.code(), Some(23));
    }

    #[test]
    fn persistent_exit_observation_cleans_up_descendants_before_reaping() {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/podman-tests")
            .join(format!(
                "persistent-process-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&root).expect("test scratch must be creatable");
        let pid_file = root.join("descendant.pid");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; exit 17")
            .arg("automata-persistent-process-test")
            .arg(&pid_file)
            .process_group(0);
        let child = command.spawn().expect("persistent test child must start");
        let mut process = PersistentPodmanProcess {
            child,
            active: true,
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while !process.has_exited().expect("exit observation must succeed") {
            assert!(Instant::now() < deadline, "test child did not exit in time");
            thread::sleep(POLL_INTERVAL);
        }

        let descendant = fs::read_to_string(&pid_file)
            .expect("descendant PID must be recorded")
            .trim()
            .parse::<u32>()
            .expect("descendant PID must be numeric");
        let descendant_path = Path::new("/proc").join(descendant.to_string());
        let reap_deadline = Instant::now() + Duration::from_secs(2);
        while descendant_path.exists() && Instant::now() < reap_deadline {
            thread::sleep(POLL_INTERVAL);
        }
        let survived = descendant_path.exists();
        if survived {
            let descendant = i32::try_from(descendant)
                .ok()
                .and_then(rustix::process::Pid::from_raw)
                .expect("descendant PID must fit the platform range");
            let _ = rustix::process::kill_process(descendant, rustix::process::Signal::KILL);
        }
        drop(process);
        fs::remove_file(pid_file).expect("PID file cleanup must succeed");
        fs::remove_dir(root).expect("test scratch cleanup must succeed");

        assert!(
            !survived,
            "persistent process descendant survived leader exit"
        );
    }
}

#[cfg(test)]
mod ordered_capture_tests {
    use super::{OutputCaptureState, capture_state, read_ordered};
    use automata_ci_execution::ExecutionOutputStream;
    use std::{
        io::{self, Read},
        sync::{Arc, Mutex, atomic::AtomicBool},
    };

    #[test]
    fn capture_state_preserves_one_observation_order_and_both_stream_ends() {
        let mut state = OutputCaptureState::new(32);
        state.observe_data(ExecutionOutputStream::Stdout, b"out-1");
        state.observe_data(ExecutionOutputStream::Stderr, b"err");
        state.observe_data(ExecutionOutputStream::Stdout, b"out-2");
        state.observe_end(ExecutionOutputStream::Stderr);
        state.observe_end(ExecutionOutputStream::Stdout);
        let debug = format!("{state:?}");
        assert!(!debug.contains("out-1"));
        assert!(!debug.contains("out-2"));

        let captured = state.take_output();

        assert!(!captured.incomplete);
        assert_eq!(captured.stdout, b"out-1out-2");
        assert_eq!(captured.stderr, b"err");
        assert_eq!(captured.records.len(), 5);
        assert_eq!(
            captured
                .records
                .iter()
                .map(|record| (record.stream(), record.is_end_of_stream()))
                .collect::<Vec<_>>(),
            [
                (ExecutionOutputStream::Stdout, false),
                (ExecutionOutputStream::Stderr, false),
                (ExecutionOutputStream::Stdout, false),
                (ExecutionOutputStream::Stderr, true),
                (ExecutionOutputStream::Stdout, true),
            ]
        );
    }

    #[test]
    fn capture_state_distinguishes_exact_limit_from_omitted_bytes() {
        let mut exact = OutputCaptureState::new(4);
        exact.observe_data(ExecutionOutputStream::Stdout, b"12");
        exact.observe_data(ExecutionOutputStream::Stdout, b"34");
        exact.observe_end(ExecutionOutputStream::Stdout);
        exact.observe_end(ExecutionOutputStream::Stderr);
        let exact = exact.take_output();
        assert!(!exact.incomplete);
        assert_eq!(exact.records.len(), 3, "adjacent data must coalesce");

        let mut over = OutputCaptureState::new(4);
        over.observe_data(ExecutionOutputStream::Stdout, b"12345");
        over.observe_end(ExecutionOutputStream::Stdout);
        over.observe_end(ExecutionOutputStream::Stderr);
        let over = over.take_output();
        assert!(over.incomplete);
        assert_eq!(over.stdout, b"1234");
    }

    #[test]
    fn hard_reader_error_never_becomes_clean_end_of_stream() {
        struct FailingReader(bool);

        impl Read for FailingReader {
            fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
                if self.0 {
                    return Err(io::Error::other("synthetic read failure"));
                }
                self.0 = true;
                destination[..4].copy_from_slice(b"data");
                Ok(4)
            }
        }

        let state = Arc::new(Mutex::new(OutputCaptureState::new(16)));
        read_ordered(
            FailingReader(false),
            ExecutionOutputStream::Stdout,
            &state,
            &AtomicBool::new(false),
        );
        let captured = capture_state(&state).take_output();

        assert!(captured.incomplete);
        assert_eq!(captured.stdout, b"data");
        assert!(
            captured
                .records
                .iter()
                .all(|record| !record.is_end_of_stream())
        );
    }
}
