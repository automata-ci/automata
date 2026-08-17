//! Windows service host for the restricted broker protocol.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    num::NonZeroU8,
    os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use automata_ci_core::{Sha256Digest, UnixMillis};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use interprocess::os::windows::{
    named_pipe::{PipeListenerOptions, PipeStream, pipe_mode},
    security_descriptor::SecurityDescriptor,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use stellar_agent_windows_identity::{current_user_sid_string, dpapi_protect, dpapi_unprotect};
use thiserror::Error;
use widestring::U16CString;
use windows::Win32::Security::TOKEN_QUERY;
use windows_acl::acl::{ACL, AceType};
use windows_permissions::{
    SecurityDescriptor as WindowsFileSecurityDescriptor,
    constants::{
        AccessRights, AceFlags, AceType as SecurityAceType, SeObjectType, SecurityInformation,
    },
    wrappers::{ConvertSecurityDescriptorToStringSecurityDescriptor, GetSecurityInfo},
};
use windows_token::Token;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    BrokerGrantKeyring, FileBrokerLedger, FileWindowsBrokerAdmissionAuthority,
    FileWindowsBrokerCustody, RestrictedWindowsHyperVBroker,
    UnavailableWindowsBrokerSyntheticProbe, VerifiedWindowsBrokerAdmissionEvaluator,
    WindowsBrokerAdmissionInputSet, WindowsBrokerAdmissionInputSource,
    WindowsBrokerAdmissionSigningKey, WindowsBrokerCustodyError, WindowsBrokerCustodyProtector,
    WindowsBrokerHostInputAttestation, WindowsBrokerHostInputAttestor,
    WindowsBrokerHostInputDescriptor, WindowsBrokerHostInputError,
    WindowsBrokerHostInputObservation, WindowsBrokerHostInputRequest,
    WindowsBrokerPromotionTrustBundle, WindowsBrokerPromotionTrustKey,
    WindowsBrokerPromotionTrustRegistry, WindowsEngineHostComputeAdapter,
    broker_service_protocol::BrokerServiceProtocol,
};

/// Fixed local endpoint for the restricted broker protocol.
pub const WINDOWS_HYPERV_BROKER_PIPE: &str = r"\\.\pipe\automata-windows-hyperv-broker-v1";

const CONFIG_BYTES: u64 = 256 * 1024;
const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const MAX_PIPE_CLIENTS: usize = 8;
const PIPE_CLIENT_DEADLINE: Duration = Duration::from_secs(30);
const PIPE_IO_POLL_INTERVAL: Duration = Duration::from_millis(5);
const SERVICE_SID_PREFIX: &str = "S-1-5-80-";
const ICACLS_PATH: &str = r"C:\Windows\System32\icacls.exe";
const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
const OBJECT_AND_CONTAINER_INHERIT: u8 = 0x03;
const FILE_ATTRIBUTE_REPARSE_POINT: u64 = 0x0000_0400;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const SYSTEM_SID: &str = "S-1-5-18";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
const SECURITY_DESCRIPTOR_DOMAIN: &[u8] = b"automata.windows.host-input-security.v1\0";

type ObservedAdmissionDocument = (
    WindowsBrokerHostInputObservation,
    Option<Zeroizing<Vec<u8>>>,
);

/// Secret-free broker-service startup or local IPC failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsHyperVBrokerServiceError {
    /// Configuration bytes, schema, identifiers, or bounds are invalid.
    #[error("Windows broker service configuration is invalid")]
    InvalidConfiguration,
    /// The process or connecting client does not have the configured service identity.
    #[error("Windows broker service identity verification failed")]
    Identity,
    /// The service-owned state root is missing its exact protected DACL.
    #[error("Windows broker service state-root ACL verification failed")]
    StateRootAcl,
    /// Service-owned durable state could not be opened or reconciled.
    #[error("Windows broker service durable state failed")]
    DurableState,
    /// The fixed Windows container engine boundary could not be opened.
    #[error("Windows broker service host-compute adapter failed")]
    HostCompute,
    /// Host-input path, volume, owner, DACL, or content evidence failed closed.
    #[error("Windows broker host-input attestation failed")]
    HostInput,
    /// The authenticated fixed named-pipe boundary failed.
    #[error("Windows broker service named-pipe boundary failed")]
    Ipc,
    /// The fixed system ACL installer failed or its result did not verify.
    #[error("Windows broker service state-root installation failed")]
    Install,
}

/// Installs the service-owned state root from one strict broker config.
///
/// This invokes only the fixed `C:\Windows\System32\icacls.exe` binary with
/// separately supplied arguments. It refuses to rewrite an existing unsafe
/// root, then verifies the resulting DACL through the safe `windows-acl` API.
///
/// # Errors
///
/// Rejects relative/reparse/nonempty preexisting roots, invalid service SIDs,
/// tool failures, or any DACL other than one full-control service ACE.
pub fn install_windows_hyperv_broker_state_root(
    config_path: &Path,
) -> Result<(), WindowsHyperVBrokerServiceError> {
    let config = BrokerServiceConfig::load(config_path)?;
    if config.state_root.exists() {
        validate_directory(&config.state_root)?;
        if fs::read_dir(&config.state_root)
            .map_err(|_| WindowsHyperVBrokerServiceError::Install)?
            .next()
            .is_some()
        {
            return Err(WindowsHyperVBrokerServiceError::Install);
        }
        if validate_state_root_acl(&config.state_root, &config.broker_service_sid).is_ok() {
            return Ok(());
        }
        return Err(WindowsHyperVBrokerServiceError::Install);
    }
    fs::create_dir(&config.state_root).map_err(|_| WindowsHyperVBrokerServiceError::Install)?;
    validate_directory(&config.state_root)?;
    let path = config
        .state_root
        .to_str()
        .ok_or(WindowsHyperVBrokerServiceError::Install)?;
    run_icacls([path, "/inheritance:r"])?;
    let service_grant = format!("*{}:(OI)(CI)F", config.broker_service_sid);
    run_icacls([path, "/grant:r", service_grant.as_str()])?;
    let service_owner = format!("*{}", config.broker_service_sid);
    run_icacls([path, "/setowner", service_owner.as_str()])?;
    validate_state_root_acl(&config.state_root, &config.broker_service_sid)?;
    let attestor = WindowsServiceHostInputAttestor::open(
        config.host_id,
        &config.broker_service_sid,
        &config.runner_service_sid,
        &config.state_root,
    )?;
    attestor.validate_configuration_source(config_path)
}

/// Opens and serves the restricted broker until `stop` becomes true.
///
/// Startup verifies the current virtual-service account, exact state-root
/// DACL, keyring, DPAPI `CurrentUser` boundary, engine, and a complete lifecycle
/// reconciliation before the pipe is created. An in-process watchdog remains
/// active for the lifetime of this call; it is not evidence of an independent
/// cleanup process surviving broker failure.
///
/// # Errors
///
/// Fails closed on every configuration, identity, durable-state, engine,
/// reconciliation, named-pipe ACL, or listener failure.
pub fn run_windows_hyperv_broker_service(
    config_path: &Path,
    stop: Arc<AtomicBool>,
) -> Result<(), WindowsHyperVBrokerServiceError> {
    run_windows_hyperv_broker_service_with_ready(config_path, stop, || Ok(()))
}

/// Opens and serves the broker, invoking `ready` only after every startup
/// reconciliation step and the fixed named-pipe listener have succeeded.
///
/// Service hosts use this boundary to defer `SERVICE_RUNNING`; console hosts
/// normally use [`run_windows_hyperv_broker_service`].
///
/// # Errors
///
/// Returns any startup, readiness-notification, or serving failure.
pub fn run_windows_hyperv_broker_service_with_ready(
    config_path: &Path,
    stop: Arc<AtomicBool>,
    ready: impl FnOnce() -> Result<(), WindowsHyperVBrokerServiceError>,
) -> Result<(), WindowsHyperVBrokerServiceError> {
    let config = BrokerServiceConfig::load(config_path)?;
    verify_current_service_identity(&config.broker_service_sid)?;
    validate_directory(&config.state_root)?;
    validate_state_root_acl(&config.state_root, &config.broker_service_sid)?;
    let host_input_attestor = Arc::new(WindowsServiceHostInputAttestor::open(
        config.host_id,
        &config.broker_service_sid,
        &config.runner_service_sid,
        &config.state_root,
    )?);
    host_input_attestor.validate_configuration_source(config_path)?;

    let custody_root = config.state_root.join("custody-v1");
    fs::create_dir_all(&custody_root).map_err(|_| WindowsHyperVBrokerServiceError::DurableState)?;
    validate_directory(&custody_root)?;
    let protector: Arc<dyn WindowsBrokerCustodyProtector> = Arc::new(
        WindowsDpapiCustodyProtector::open(config.broker_service_sid.clone())?,
    );
    let custody = Arc::new(
        FileWindowsBrokerCustody::open(&custody_root, protector)
            .map_err(|_| WindowsHyperVBrokerServiceError::DurableState)?,
    );
    let admission_signing_key = Arc::new(config.admission_signing_key()?);
    let promotion_trust = config.promotion_trust_registry()?;
    let evaluator = Arc::new(
        VerifiedWindowsBrokerAdmissionEvaluator::new(
            config.host_id,
            host_input_attestor.clone(),
            promotion_trust,
            Arc::new(UnavailableWindowsBrokerSyntheticProbe),
        )
        .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?,
    );
    let admissions = Arc::new(
        FileWindowsBrokerAdmissionAuthority::open(
            config.state_root.join("admission-state-v1.json"),
            custody.clone(),
            evaluator,
            admission_signing_key,
        )
        .map_err(|_| WindowsHyperVBrokerServiceError::DurableState)?,
    );
    let ledger = Arc::new(
        FileBrokerLedger::open(config.state_root.join("broker-ledger-v1.jsonl"))
            .map_err(|_| WindowsHyperVBrokerServiceError::DurableState)?,
    );
    let adapter = Arc::new(
        WindowsEngineHostComputeAdapter::open()
            .map_err(|_| WindowsHyperVBrokerServiceError::HostCompute)?,
    );
    let broker = Arc::new(
        RestrictedWindowsHyperVBroker::open(
            config.host_id,
            config.keyring()?,
            adapter,
            ledger,
            admissions.clone(),
        )
        .map_err(|_| WindowsHyperVBrokerServiceError::DurableState)?,
    );
    let now = system_unix_millis().ok_or(WindowsHyperVBrokerServiceError::DurableState)?;
    broker
        .reconcile_startup(now)
        .map_err(|_| WindowsHyperVBrokerServiceError::DurableState)?;
    let _watchdog = broker
        .start_watchdog(Duration::from_millis(config.watchdog_interval_millis))
        .map_err(|_| WindowsHyperVBrokerServiceError::DurableState)?;
    let protocol = BrokerServiceProtocol::new(broker, host_input_attestor, admissions);
    serve_pipe(&config, &protocol, stop, ready)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerServiceConfig {
    schema: u16,
    host_id: Sha256Digest,
    broker_service_sid: String,
    runner_service_sid: String,
    state_root: PathBuf,
    grant_verification_keys: Vec<GrantVerificationKey>,
    admission_signing_key: AdmissionSigningKeyConfig,
    promotion_trust_bundles: Vec<PromotionTrustBundleConfig>,
    watchdog_interval_millis: u64,
}

impl BrokerServiceConfig {
    fn load(path: &Path) -> Result<Self, WindowsHyperVBrokerServiceError> {
        validate_config_path(path)?;
        let mut file = open_stable_regular_file(path)
            .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?;
        if file
            .metadata()
            .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?
            .len()
            > CONFIG_BYTES
        {
            return Err(WindowsHyperVBrokerServiceError::InvalidConfiguration);
        }
        let mut encoded = Vec::new();
        Read::by_ref(&mut file)
            .take(CONFIG_BYTES.saturating_add(1))
            .read_to_end(&mut encoded)
            .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?;
        if encoded.is_empty() || encoded.len() as u64 > CONFIG_BYTES {
            return Err(WindowsHyperVBrokerServiceError::InvalidConfiguration);
        }
        let config: Self = serde_json::from_slice(&encoded)
            .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?;
        if config.schema != 2
            || config.host_id.as_bytes().iter().all(|byte| *byte == 0)
            || !valid_service_sid(&config.broker_service_sid)
            || !valid_service_sid(&config.runner_service_sid)
            || config.broker_service_sid == config.runner_service_sid
            || !valid_state_root(&config.state_root)
            || !(1_000..=300_000).contains(&config.watchdog_interval_millis)
            || config.grant_verification_keys.is_empty()
            || config.grant_verification_keys.len() > 32
            || config.admission_signing_key.validate().is_err()
            || config.promotion_trust_registry().is_err()
        {
            return Err(WindowsHyperVBrokerServiceError::InvalidConfiguration);
        }
        validate_security_descriptor(
            &file,
            &config.broker_service_sid,
            &config.runner_service_sid,
        )
        .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?;
        Ok(config)
    }

    fn keyring(&self) -> Result<BrokerGrantKeyring, WindowsHyperVBrokerServiceError> {
        let keys = self
            .grant_verification_keys
            .iter()
            .map(GrantVerificationKey::decode)
            .collect::<Result<Vec<_>, _>>()?;
        BrokerGrantKeyring::new(keys)
            .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)
    }

    fn admission_signing_key(
        &self,
    ) -> Result<WindowsBrokerAdmissionSigningKey, WindowsHyperVBrokerServiceError> {
        let mut protected = Zeroizing::new(
            BASE64
                .decode(&self.admission_signing_key.protected_pkcs8_base64)
                .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?,
        );
        if protected.is_empty() || protected.len() > 64 * 1024 {
            return Err(WindowsHyperVBrokerServiceError::InvalidConfiguration);
        }
        let mut plaintext = Zeroizing::new(
            dpapi_unprotect(&protected)
                .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?,
        );
        protected.zeroize();
        let key = WindowsBrokerAdmissionSigningKey::from_pkcs8(
            &self.admission_signing_key.issuer_key_id,
            &plaintext,
        )
        .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?;
        plaintext.zeroize();
        if Sha256Digest::from_bytes(Sha256::digest(key.public_key()).into())
            != self.admission_signing_key.public_key_sha256
        {
            return Err(WindowsHyperVBrokerServiceError::InvalidConfiguration);
        }
        Ok(key)
    }

    fn promotion_trust_registry(
        &self,
    ) -> Result<WindowsBrokerPromotionTrustRegistry, WindowsHyperVBrokerServiceError> {
        let bundles = self
            .promotion_trust_bundles
            .iter()
            .map(PromotionTrustBundleConfig::decode)
            .collect::<Result<Vec<_>, _>>()?;
        WindowsBrokerPromotionTrustRegistry::new(bundles)
            .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionSigningKeyConfig {
    issuer_key_id: String,
    protected_pkcs8_base64: String,
    public_key_sha256: Sha256Digest,
}

impl AdmissionSigningKeyConfig {
    fn validate(&self) -> Result<(), WindowsHyperVBrokerServiceError> {
        let mut decoded = Zeroizing::new(
            BASE64
                .decode(&self.protected_pkcs8_base64)
                .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?,
        );
        let valid = (3..=128).contains(&self.issuer_key_id.len())
            && self.issuer_key_id.bytes().enumerate().all(|(index, byte)| {
                (index != 0 || byte.is_ascii_lowercase())
                    && (byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-'))
            })
            && !decoded.is_empty()
            && decoded.len() <= 64 * 1024
            && self
                .public_key_sha256
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0);
        decoded.zeroize();
        valid
            .then_some(())
            .ok_or(WindowsHyperVBrokerServiceError::InvalidConfiguration)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromotionTrustBundleConfig {
    trust_bundle_id: String,
    trust_bundle_sha256: Sha256Digest,
    keys: Vec<PromotionVerificationKey>,
}

impl PromotionTrustBundleConfig {
    fn decode(&self) -> Result<WindowsBrokerPromotionTrustBundle, WindowsHyperVBrokerServiceError> {
        let keys = self
            .keys
            .iter()
            .map(PromotionVerificationKey::decode)
            .collect::<Result<Vec<_>, _>>()?;
        WindowsBrokerPromotionTrustBundle::new(
            &self.trust_bundle_id,
            self.trust_bundle_sha256,
            keys,
        )
        .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromotionVerificationKey {
    key_id: String,
    public_key_base64: String,
}

impl PromotionVerificationKey {
    fn decode(&self) -> Result<WindowsBrokerPromotionTrustKey, WindowsHyperVBrokerServiceError> {
        let decoded = BASE64
            .decode(&self.public_key_base64)
            .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?;
        let key = <[u8; 32]>::try_from(decoded.as_slice())
            .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?;
        WindowsBrokerPromotionTrustKey::new(&self.key_id, key)
            .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantVerificationKey {
    key_id: Sha256Digest,
    public_key_base64: String,
}

impl GrantVerificationKey {
    fn decode(&self) -> Result<(Sha256Digest, [u8; 32]), WindowsHyperVBrokerServiceError> {
        let decoded = BASE64
            .decode(&self.public_key_base64)
            .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?;
        let key = <[u8; 32]>::try_from(decoded.as_slice())
            .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?;
        Ok((self.key_id, key))
    }
}

#[derive(Debug)]
struct WindowsServiceHostInputAttestor {
    host_id: Sha256Digest,
    broker_service_sid: String,
    runner_service_sid: String,
    volume_serial_number: u64,
}

impl WindowsServiceHostInputAttestor {
    fn open(
        host_id: Sha256Digest,
        broker_service_sid: &str,
        runner_service_sid: &str,
        state_root: &Path,
    ) -> Result<Self, WindowsHyperVBrokerServiceError> {
        validate_path_components(state_root)
            .map_err(|_| WindowsHyperVBrokerServiceError::HostInput)?;
        validate_local_drive_resolution(state_root)
            .map_err(|_| WindowsHyperVBrokerServiceError::HostInput)?;
        let root = OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(state_root)
            .map_err(|_| WindowsHyperVBrokerServiceError::HostInput)?;
        let information = winapi_util::file::information(&root)
            .map_err(|_| WindowsHyperVBrokerServiceError::HostInput)?;
        if information.volume_serial_number() == 0
            || information.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(WindowsHyperVBrokerServiceError::HostInput);
        }
        Ok(Self {
            host_id,
            broker_service_sid: broker_service_sid.to_owned(),
            runner_service_sid: runner_service_sid.to_owned(),
            volume_serial_number: information.volume_serial_number(),
        })
    }

    fn validate_configuration_source(
        &self,
        path: &Path,
    ) -> Result<(), WindowsHyperVBrokerServiceError> {
        let path = path
            .to_str()
            .ok_or(WindowsHyperVBrokerServiceError::HostInput)?;
        observe_host_input(
            path,
            crate::WindowsBrokerHostInputKind::Configuration,
            None,
            self.volume_serial_number,
            &self.broker_service_sid,
            &self.runner_service_sid,
        )
        .map(|_| ())
        .map_err(|_| WindowsHyperVBrokerServiceError::HostInput)
    }

    fn attest_with_documents(
        &self,
        request: &WindowsBrokerHostInputRequest,
        issued_at: UnixMillis,
        valid_until: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionInputSet, crate::WindowsBrokerAdmissionError> {
        request
            .validate()
            .map_err(|_| crate::WindowsBrokerAdmissionError::EvidenceRejected)?;
        if request.backend_id() != self.host_id.to_string()
            || request.sandbox_provider_id() != crate::WINDOWS_HYPERV_PROVIDER_ID
        {
            return Err(crate::WindowsBrokerAdmissionError::EvidenceRejected);
        }
        let mut observations = Vec::with_capacity(request.inputs().len());
        let mut documents = BTreeMap::new();
        for descriptor in request.inputs() {
            let capture = !matches!(
                descriptor.kind(),
                crate::WindowsBrokerHostInputKind::Configuration
                    | crate::WindowsBrokerHostInputKind::BackendExecutable
            );
            let (observation, document) = observe_host_input_with_document(
                descriptor.absolute_path(),
                descriptor.kind(),
                Some(descriptor),
                self.volume_serial_number,
                &self.broker_service_sid,
                &self.runner_service_sid,
                capture,
            )
            .map_err(|_| crate::WindowsBrokerAdmissionError::EvidenceRejected)?;
            observations.push(observation);
            if let Some(document) = document
                && documents.insert(descriptor.kind(), document).is_some()
            {
                return Err(crate::WindowsBrokerAdmissionError::EvidenceRejected);
            }
        }
        let attestation = WindowsBrokerHostInputAttestation::issue(
            self.host_id,
            request,
            observations,
            issued_at,
            valid_until,
        )
        .map_err(|_| crate::WindowsBrokerAdmissionError::EvidenceRejected)?;
        WindowsBrokerAdmissionInputSet::new(request, attestation, documents)
    }
}

impl WindowsBrokerAdmissionInputSource for WindowsServiceHostInputAttestor {
    fn load(
        &self,
        request: &WindowsBrokerHostInputRequest,
        issued_at: UnixMillis,
        valid_until: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionInputSet, crate::WindowsBrokerAdmissionError> {
        self.attest_with_documents(request, issued_at, valid_until)
    }
}

impl WindowsBrokerHostInputAttestor for WindowsServiceHostInputAttestor {
    fn attest(
        &self,
        request: &WindowsBrokerHostInputRequest,
        issued_at: UnixMillis,
        valid_until: UnixMillis,
    ) -> Result<WindowsBrokerHostInputAttestation, WindowsBrokerHostInputError> {
        request.validate()?;
        if request.backend_id() != self.host_id.to_string()
            || request.sandbox_provider_id() != crate::WINDOWS_HYPERV_PROVIDER_ID
        {
            return Err(WindowsBrokerHostInputError::Policy);
        }
        let observations = request
            .inputs()
            .iter()
            .map(|descriptor| {
                observe_host_input(
                    descriptor.absolute_path(),
                    descriptor.kind(),
                    Some(descriptor),
                    self.volume_serial_number,
                    &self.broker_service_sid,
                    &self.runner_service_sid,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        WindowsBrokerHostInputAttestation::issue(
            self.host_id,
            request,
            observations,
            issued_at,
            valid_until,
        )
    }
}

fn observe_host_input(
    path: &str,
    kind: crate::WindowsBrokerHostInputKind,
    expected: Option<&WindowsBrokerHostInputDescriptor>,
    expected_volume_serial_number: u64,
    broker_service_sid: &str,
    runner_service_sid: &str,
) -> Result<WindowsBrokerHostInputObservation, WindowsBrokerHostInputError> {
    observe_host_input_with_document(
        path,
        kind,
        expected,
        expected_volume_serial_number,
        broker_service_sid,
        runner_service_sid,
        false,
    )
    .map(|(observation, _)| observation)
}

#[allow(clippy::too_many_arguments)]
fn observe_host_input_with_document(
    path: &str,
    kind: crate::WindowsBrokerHostInputKind,
    expected: Option<&WindowsBrokerHostInputDescriptor>,
    expected_volume_serial_number: u64,
    broker_service_sid: &str,
    runner_service_sid: &str,
    capture_document: bool,
) -> Result<ObservedAdmissionDocument, WindowsBrokerHostInputError> {
    let path_object = Path::new(path);
    validate_path_components(path_object)?;
    validate_local_drive_resolution(path_object)?;
    let mut file = open_stable_regular_file(path_object)?;
    let before =
        winapi_util::file::information(&file).map_err(|_| WindowsBrokerHostInputError::File)?;
    if before.volume_serial_number() != expected_volume_serial_number
        || before.volume_serial_number() == 0
        || before.file_index() == 0
        || before.file_size() == 0
        || before.file_size() > kind.byte_limit()
        || before.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !winapi_util::file::typ(&file)
            .map_err(|_| WindowsBrokerHostInputError::File)?
            .is_disk()
    {
        return Err(WindowsBrokerHostInputError::Policy);
    }
    let (owner_sid, security_descriptor, security_descriptor_sha256) =
        validate_security_descriptor(&file, broker_service_sid, runner_service_sid)?;
    let (first_digest, document) = if capture_document {
        let document = read_locked_file(&mut file, kind.byte_limit())?;
        (sha256_bytes(&document), Some(document))
    } else {
        (hash_locked_file(&mut file, kind.byte_limit())?, None)
    };
    if expected.is_some_and(|descriptor| descriptor.expected_sha256() != first_digest) {
        return Err(WindowsBrokerHostInputError::Policy);
    }
    let second_digest = hash_locked_file(&mut file, kind.byte_limit())?;
    let after =
        winapi_util::file::information(&file).map_err(|_| WindowsBrokerHostInputError::File)?;
    let (_, after_security_descriptor, after_security_descriptor_sha256) =
        validate_security_descriptor(&file, broker_service_sid, runner_service_sid)?;
    validate_path_components(path_object)?;
    validate_local_drive_resolution(path_object)?;
    if first_digest != second_digest
        || before.volume_serial_number() != after.volume_serial_number()
        || before.file_index() != after.file_index()
        || before.file_size() != after.file_size()
        || before.number_of_links() != after.number_of_links()
        || before.last_write_time() != after.last_write_time()
        || security_descriptor != after_security_descriptor
        || security_descriptor_sha256 != after_security_descriptor_sha256
    {
        return Err(WindowsBrokerHostInputError::File);
    }
    let descriptor = match expected {
        Some(descriptor) => descriptor.clone(),
        None => WindowsBrokerHostInputDescriptor::new(kind, path, first_digest)?,
    };
    let mut file_id = [0_u8; 16];
    file_id[8..].copy_from_slice(&before.file_index().to_be_bytes());
    let observation = WindowsBrokerHostInputObservation::new(
        &descriptor,
        before.file_size(),
        before.volume_serial_number(),
        file_id,
        owner_sid,
        security_descriptor_sha256,
    )?;
    Ok((observation, document))
}

fn read_locked_file(
    file: &mut File,
    byte_limit: u64,
) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerHostInputError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| WindowsBrokerHostInputError::File)?;
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(file)
        .take(byte_limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| WindowsBrokerHostInputError::File)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).map_or(true, |length| length > byte_limit) {
        return Err(WindowsBrokerHostInputError::Policy);
    }
    Ok(bytes)
}

fn sha256_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn hash_locked_file(
    file: &mut File,
    byte_limit: u64,
) -> Result<Sha256Digest, WindowsBrokerHostInputError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| WindowsBrokerHostInputError::File)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| WindowsBrokerHostInputError::File)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| WindowsBrokerHostInputError::File)?)
            .ok_or(WindowsBrokerHostInputError::File)?;
        if total > byte_limit {
            return Err(WindowsBrokerHostInputError::Policy);
        }
        digest.update(&buffer[..read]);
    }
    if total == 0 {
        return Err(WindowsBrokerHostInputError::Policy);
    }
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

fn validate_security_descriptor(
    file: &File,
    broker_service_sid: &str,
    runner_service_sid: &str,
) -> Result<(String, String, Sha256Digest), WindowsBrokerHostInputError> {
    let requested = SecurityInformation::Owner | SecurityInformation::Dacl;
    let descriptor = GetSecurityInfo(file, SeObjectType::SE_FILE_OBJECT, requested)
        .map_err(|_| WindowsBrokerHostInputError::File)?;
    validate_security_descriptor_value(
        &descriptor,
        requested,
        broker_service_sid,
        runner_service_sid,
    )
}

fn validate_security_descriptor_value(
    descriptor: &WindowsFileSecurityDescriptor,
    requested: SecurityInformation,
    broker_service_sid: &str,
    runner_service_sid: &str,
) -> Result<(String, String, Sha256Digest), WindowsBrokerHostInputError> {
    let owner = descriptor
        .owner()
        .map(ToString::to_string)
        .ok_or(WindowsBrokerHostInputError::Policy)?;
    if !trusted_host_input_sid(&owner, broker_service_sid, runner_service_sid) {
        return Err(WindowsBrokerHostInputError::Policy);
    }
    let dacl = descriptor
        .dacl()
        .ok_or(WindowsBrokerHostInputError::Policy)?;
    if dacl.len() == 0 || dacl.len() > 16 {
        return Err(WindowsBrokerHostInputError::Policy);
    }
    let mut broker_can_read = false;
    let mut runner_can_read = false;
    for index in 0..dacl.len() {
        let ace = dacl
            .get_ace(index)
            .ok_or(WindowsBrokerHostInputError::Policy)?;
        let sid = ace
            .sid()
            .map(ToString::to_string)
            .ok_or(WindowsBrokerHostInputError::Policy)?;
        if ace.ace_type() != SecurityAceType::ACCESS_ALLOWED_ACE_TYPE
            || !ace.flags().is_empty()
            || ace.flags().contains(AceFlags::Inherited)
            || !trusted_host_input_sid(&sid, broker_service_sid, runner_service_sid)
        {
            return Err(WindowsBrokerHostInputError::Policy);
        }
        let mask = ace.mask();
        let readable = mask.contains(AccessRights::GenericAll)
            || mask.contains(AccessRights::GenericRead)
            || mask.contains(AccessRights::FileAllAccess)
            || mask.contains(AccessRights::FileGenericRead);
        broker_can_read |= sid == broker_service_sid && readable;
        runner_can_read |= sid == runner_service_sid && readable;
    }
    if !broker_can_read || !runner_can_read {
        return Err(WindowsBrokerHostInputError::Policy);
    }
    let encoded = ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor, requested)
        .map_err(|_| WindowsBrokerHostInputError::File)?
        .to_str()
        .ok_or(WindowsBrokerHostInputError::Policy)?
        .to_owned();
    let dacl_offset = encoded
        .find("D:")
        .ok_or(WindowsBrokerHostInputError::Policy)?;
    if !encoded[dacl_offset + 2..].starts_with('P')
        || encoded[dacl_offset + 2..].starts_with("PAI")
        || encoded[dacl_offset + 2..].starts_with("PAR")
    {
        return Err(WindowsBrokerHostInputError::Policy);
    }
    let mut hash = Sha256::new();
    hash.update(SECURITY_DESCRIPTOR_DOMAIN);
    hash.update(encoded.as_bytes());
    Ok((
        owner,
        encoded,
        Sha256Digest::from_bytes(hash.finalize().into()),
    ))
}

fn trusted_host_input_sid(value: &str, broker_service_sid: &str, runner_service_sid: &str) -> bool {
    value == broker_service_sid
        || value == runner_service_sid
        || value == SYSTEM_SID
        || value == ADMINISTRATORS_SID
}

#[derive(Debug)]
struct WindowsDpapiCustodyProtector {
    service_sid: String,
}

impl WindowsDpapiCustodyProtector {
    fn open(service_sid: String) -> Result<Self, WindowsHyperVBrokerServiceError> {
        verify_current_service_identity(&service_sid)?;
        Ok(Self { service_sid })
    }
}

impl WindowsBrokerCustodyProtector for WindowsDpapiCustodyProtector {
    fn seal(&self, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError> {
        if current_user_sid_string().ok().as_deref() != Some(self.service_sid.as_str()) {
            return Err(WindowsBrokerCustodyError::Protector);
        }
        dpapi_protect(plaintext)
            .map(Zeroizing::new)
            .map_err(|_| WindowsBrokerCustodyError::Protector)
    }

    fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, WindowsBrokerCustodyError> {
        if current_user_sid_string().ok().as_deref() != Some(self.service_sid.as_str()) {
            return Err(WindowsBrokerCustodyError::Protector);
        }
        dpapi_unprotect(sealed)
            .map(Zeroizing::new)
            .map_err(|_| WindowsBrokerCustodyError::Protector)
    }
}

// The listener owns the stop token so every detached connection receives the
// same service-lifetime fence even after the caller begins shutdown.
#[allow(clippy::needless_pass_by_value)]
fn serve_pipe(
    config: &BrokerServiceConfig,
    protocol: &BrokerServiceProtocol,
    stop: Arc<AtomicBool>,
    ready: impl FnOnce() -> Result<(), WindowsHyperVBrokerServiceError>,
) -> Result<(), WindowsHyperVBrokerServiceError> {
    let descriptor = pipe_security_descriptor(config)?;
    let listener = PipeListenerOptions::new()
        .path(Path::new(WINDOWS_HYPERV_BROKER_PIPE))
        .nonblocking(true)
        .instance_limit(NonZeroU8::new(
            u8::try_from(MAX_PIPE_CLIENTS)
                .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?,
        ))
        .accept_remote(false)
        .input_buffer_size_hint(PIPE_BUFFER_BYTES)
        .output_buffer_size_hint(PIPE_BUFFER_BYTES)
        .security_descriptor(Some(descriptor))
        .inheritable(false)
        .create_duplex::<pipe_mode::Bytes>()
        .map_err(|_| WindowsHyperVBrokerServiceError::Ipc)?;
    ready()?;
    let active_clients = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok(stream) => {
                if active_clients.fetch_add(1, Ordering::AcqRel) >= MAX_PIPE_CLIENTS {
                    active_clients.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }
                let protocol = protocol.clone();
                let expected_sid = config.runner_service_sid.clone();
                let stop = Arc::clone(&stop);
                let active_clients = Arc::clone(&active_clients);
                thread::Builder::new()
                    .name("automata-windows-broker-client".to_owned())
                    .spawn(move || {
                        let _connection = ActivePipeClient(active_clients);
                        let _ = serve_pipe_client(stream, &protocol, &expected_sid, &stop);
                    })
                    .map_err(|_| WindowsHyperVBrokerServiceError::Ipc)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return Err(WindowsHyperVBrokerServiceError::Ipc),
        }
    }
    Ok(())
}

struct ActivePipeClient(Arc<AtomicUsize>);

impl Drop for ActivePipeClient {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve_pipe_client(
    mut stream: PipeStream<pipe_mode::Bytes, pipe_mode::Bytes>,
    protocol: &BrokerServiceProtocol,
    expected_sid: &str,
    stop: &AtomicBool,
) -> Result<(), WindowsHyperVBrokerServiceError> {
    stream
        .set_nonblocking(true)
        .map_err(|_| WindowsHyperVBrokerServiceError::Ipc)?;
    let authenticated_pid = authenticate_client(&stream, expected_sid)?;
    let deadline = Instant::now() + PIPE_CLIENT_DEADLINE;
    let mut encoded = Zeroizing::new(read_frame_until(&mut stream, stop, deadline)?);
    if authenticate_client(&stream, expected_sid)? != authenticated_pid {
        return Err(WindowsHyperVBrokerServiceError::Identity);
    }
    // The impersonation context is established from the exact message just
    // read. Never dispatch while impersonating the less-privileged client.
    let guard = stream
        .impersonate_client()
        .map_err(|_| WindowsHyperVBrokerServiceError::Identity)?;
    if !authenticate_impersonated_client(expected_sid) {
        return Err(WindowsHyperVBrokerServiceError::Identity);
    }
    drop(guard);
    let mut response = Zeroizing::new(protocol.dispatch(&encoded));
    encoded.zeroize();
    write_frame_until(&mut stream, &response, stop, deadline)?;
    response.zeroize();
    Ok(())
}

const fn authenticate_impersonated_client(_expected_sid: &str) -> bool {
    // No reviewed safe dependency currently exposes OpenThreadToken for the
    // active named-pipe impersonation context. A PID/process-token lookup is
    // not an authority boundary because of disconnect and PID-reuse races.
    // Keep production dispatch closed until the single audited Windows
    // security boundary calls OpenThreadToken(TOKEN_QUERY, OpenAsSelf=false),
    // rejects ERROR_NO_TOKEN, requires TokenImpersonationLevel of at least
    // SecurityIdentification, and compares TokenUser from that exact handle
    // while the pipe impersonation guard remains live.
    false
}

fn authenticate_client(
    stream: &PipeStream<pipe_mode::Bytes, pipe_mode::Bytes>,
    expected_sid: &str,
) -> Result<u32, WindowsHyperVBrokerServiceError> {
    let pid = stream
        .client_process_id()
        .map_err(|_| WindowsHyperVBrokerServiceError::Identity)?;
    let _session = stream
        .client_session_id()
        .map_err(|_| WindowsHyperVBrokerServiceError::Identity)?;
    if pid == 0 || pid == std::process::id() {
        return Err(WindowsHyperVBrokerServiceError::Identity);
    }
    let token = Token::open_process(pid, TOKEN_QUERY)
        .map_err(|_| WindowsHyperVBrokerServiceError::Identity)?;
    if token
        .user_sid()
        .map_err(|_| WindowsHyperVBrokerServiceError::Identity)?
        .to_display_string()
        != expected_sid
    {
        return Err(WindowsHyperVBrokerServiceError::Identity);
    }
    Ok(pid)
}

fn pipe_security_descriptor(
    config: &BrokerServiceConfig,
) -> Result<SecurityDescriptor, WindowsHyperVBrokerServiceError> {
    let sddl = format!(
        "O:{owner}D:P(A;;GA;;;{owner})(A;;GRGW;;;{runner})",
        owner = config.broker_service_sid,
        runner = config.runner_service_sid,
    );
    let wide = U16CString::from_str(&sddl)
        .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)?;
    SecurityDescriptor::deserialize(wide.as_ucstr())
        .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)
}

fn read_frame_until(
    stream: &mut impl Read,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<Vec<u8>, WindowsHyperVBrokerServiceError> {
    let mut length = [0_u8; 4];
    read_exact_until(stream, &mut length, stop, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| WindowsHyperVBrokerServiceError::Ipc)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(WindowsHyperVBrokerServiceError::Ipc);
    }
    let mut encoded = vec![0_u8; length];
    read_exact_until(stream, &mut encoded, stop, deadline)?;
    Ok(encoded)
}

fn write_frame_until(
    stream: &mut impl Write,
    response: &[u8],
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<(), WindowsHyperVBrokerServiceError> {
    if response.is_empty() || response.len() > MAX_FRAME_BYTES {
        return Err(WindowsHyperVBrokerServiceError::Ipc);
    }
    let length = u32::try_from(response.len())
        .map_err(|_| WindowsHyperVBrokerServiceError::Ipc)?
        .to_be_bytes();
    write_all_until(stream, &length, stop, deadline)?;
    write_all_until(stream, response, stop, deadline)?;
    flush_until(stream, stop, deadline)
}

fn read_exact_until(
    stream: &mut impl Read,
    buffer: &mut [u8],
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<(), WindowsHyperVBrokerServiceError> {
    let mut offset = 0;
    while offset < buffer.len() {
        ensure_pipe_deadline(stop, deadline)?;
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => return Err(WindowsHyperVBrokerServiceError::Ipc),
            Ok(read) => offset = offset.saturating_add(read),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(PIPE_IO_POLL_INTERVAL);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(WindowsHyperVBrokerServiceError::Ipc),
        }
    }
    Ok(())
}

fn write_all_until(
    stream: &mut impl Write,
    buffer: &[u8],
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<(), WindowsHyperVBrokerServiceError> {
    let mut offset = 0;
    while offset < buffer.len() {
        ensure_pipe_deadline(stop, deadline)?;
        match stream.write(&buffer[offset..]) {
            Ok(0) => return Err(WindowsHyperVBrokerServiceError::Ipc),
            Ok(written) => offset = offset.saturating_add(written),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(PIPE_IO_POLL_INTERVAL);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(WindowsHyperVBrokerServiceError::Ipc),
        }
    }
    Ok(())
}

fn flush_until(
    stream: &mut impl Write,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<(), WindowsHyperVBrokerServiceError> {
    loop {
        ensure_pipe_deadline(stop, deadline)?;
        match stream.flush() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(PIPE_IO_POLL_INTERVAL);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(WindowsHyperVBrokerServiceError::Ipc),
        }
    }
}

fn ensure_pipe_deadline(
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<(), WindowsHyperVBrokerServiceError> {
    if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
        Err(WindowsHyperVBrokerServiceError::Ipc)
    } else {
        Ok(())
    }
}

fn verify_current_service_identity(expected: &str) -> Result<(), WindowsHyperVBrokerServiceError> {
    if current_user_sid_string().ok().as_deref() != Some(expected) {
        return Err(WindowsHyperVBrokerServiceError::Identity);
    }
    Ok(())
}

fn validate_state_root_acl(
    path: &Path,
    service_sid: &str,
) -> Result<(), WindowsHyperVBrokerServiceError> {
    let path = path
        .to_str()
        .ok_or(WindowsHyperVBrokerServiceError::StateRootAcl)?;
    let entries = ACL::from_file_path(path, false)
        .and_then(|acl| acl.all())
        .map_err(|_| WindowsHyperVBrokerServiceError::StateRootAcl)?;
    if entries.len() != 1 {
        return Err(WindowsHyperVBrokerServiceError::StateRootAcl);
    }
    let entry = entries
        .first()
        .ok_or(WindowsHyperVBrokerServiceError::StateRootAcl)?;
    if entry.entry_type != AceType::AccessAllow
        || entry.string_sid != service_sid
        || entry.mask != FILE_ALL_ACCESS
        || entry.flags != OBJECT_AND_CONTAINER_INHERIT
    {
        return Err(WindowsHyperVBrokerServiceError::StateRootAcl);
    }
    Ok(())
}

fn run_icacls<const N: usize>(arguments: [&str; N]) -> Result<(), WindowsHyperVBrokerServiceError> {
    let output = Command::new(ICACLS_PATH)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| WindowsHyperVBrokerServiceError::Install)?;
    if !output.status.success() {
        return Err(WindowsHyperVBrokerServiceError::Install);
    }
    Ok(())
}

fn validate_config_path(path: &Path) -> Result<(), WindowsHyperVBrokerServiceError> {
    validate_path_components(path)
        .and_then(|()| validate_local_drive_resolution(path))
        .and_then(|()| open_stable_regular_file(path).map(|_| ()))
        .map_err(|_| WindowsHyperVBrokerServiceError::InvalidConfiguration)
}

fn validate_directory(path: &Path) -> Result<(), WindowsHyperVBrokerServiceError> {
    validate_path_components(path).map_err(|_| WindowsHyperVBrokerServiceError::StateRootAcl)?;
    validate_local_drive_resolution(path)
        .map_err(|_| WindowsHyperVBrokerServiceError::StateRootAcl)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|_| WindowsHyperVBrokerServiceError::StateRootAcl)?;
    if !metadata.is_dir()
        || u64::from(metadata.file_attributes()) & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(WindowsHyperVBrokerServiceError::StateRootAcl);
    }
    Ok(())
}

fn open_stable_regular_file(path: &Path) -> Result<File, WindowsBrokerHostInputError> {
    if !valid_absolute_windows_path(path) {
        return Err(WindowsBrokerHostInputError::InvalidRequest);
    }
    validate_path_components(path)?;
    validate_local_drive_resolution(path)?;
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| WindowsBrokerHostInputError::File)?;
    let metadata = file
        .metadata()
        .map_err(|_| WindowsBrokerHostInputError::File)?;
    if !metadata.is_file()
        || u64::from(metadata.file_attributes()) & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(WindowsBrokerHostInputError::Policy);
    }
    Ok(file)
}

fn validate_path_components(path: &Path) -> Result<(), WindowsBrokerHostInputError> {
    if !valid_absolute_windows_path(path) {
        return Err(WindowsBrokerHostInputError::InvalidRequest);
    }
    let value = path
        .to_str()
        .ok_or(WindowsBrokerHostInputError::InvalidRequest)?;
    let mut current = PathBuf::from(&value[..3]);
    for component in value[3..].split('\\') {
        current.push(component);
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| WindowsBrokerHostInputError::File)?;
        if u64::from(metadata.file_attributes()) & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(WindowsBrokerHostInputError::Policy);
        }
    }
    Ok(())
}

fn validate_local_drive_resolution(path: &Path) -> Result<(), WindowsBrokerHostInputError> {
    let source = path
        .to_str()
        .ok_or(WindowsBrokerHostInputError::InvalidRequest)?;
    let resolved = fs::canonicalize(path).map_err(|_| WindowsBrokerHostInputError::File)?;
    let resolved = resolved
        .to_str()
        .ok_or(WindowsBrokerHostInputError::Policy)?;
    let resolved = resolved.strip_prefix(r"\\?\").unwrap_or(resolved);
    if resolved.starts_with("UNC\\")
        || resolved.len() < 3
        || !resolved[..2].eq_ignore_ascii_case(&source[..2])
        || resolved.as_bytes()[2] != b'\\'
    {
        return Err(WindowsBrokerHostInputError::Policy);
    }
    Ok(())
}

fn valid_state_root(path: &Path) -> bool {
    valid_absolute_windows_path(path)
        && path
            .to_str()
            .is_some_and(|value| value.len() <= 512 && !value.ends_with([' ', '.']))
}

fn valid_absolute_windows_path(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_uppercase()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !value.contains('/')
        && !value.contains("\\\\")
        && !value.chars().any(char::is_control)
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir | Component::CurDir))
}

fn valid_service_sid(value: &str) -> bool {
    let fields = value.split('-').collect::<Vec<_>>();
    value.len() > SERVICE_SID_PREFIX.len()
        && value.len() <= 184
        && fields.len() == 9
        && fields[..4] == ["S", "1", "5", "80"]
        && fields[4..]
            .iter()
            .all(|field| !field.is_empty() && field.parse::<u32>().is_ok())
}

fn system_unix_millis() -> Option<UnixMillis> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok().map(UnixMillis::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};
    use windows_permissions::LocalBox;

    #[derive(Default)]
    struct PartialThenBlockedReader {
        prefix: Vec<u8>,
        offset: usize,
    }

    impl PartialThenBlockedReader {
        fn new(prefix: impl Into<Vec<u8>>) -> Self {
            Self {
                prefix: prefix.into(),
                offset: 0,
            }
        }
    }

    impl Read for PartialThenBlockedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.offset == self.prefix.len() {
                return Err(Error::from(ErrorKind::WouldBlock));
            }
            let remaining = &self.prefix[self.offset..];
            let copied = remaining.len().min(buffer.len());
            buffer[..copied].copy_from_slice(&remaining[..copied]);
            self.offset = self.offset.saturating_add(copied);
            Ok(copied)
        }
    }

    #[test]
    fn service_sids_are_distinct_narrow_virtual_service_identities() {
        assert!(valid_service_sid("S-1-5-80-1-2-3-4-5"));
        for invalid in [
            "S-1-1-0",
            "S-1-5-11",
            "S-1-5-18",
            "S-1-5-32-545",
            "S-1-5-80-",
            "S-1-5-80-1-x",
        ] {
            assert!(!valid_service_sid(invalid));
        }
    }

    #[test]
    fn state_paths_reject_unc_device_relative_and_traversal_forms() {
        assert!(valid_absolute_windows_path(Path::new(
            r"C:\ProgramData\Automata\WindowsBroker"
        )));
        for invalid in [
            r"relative\state",
            r"\\server\share\state",
            r"\\?\C:\state",
            r"C:\state\..\other",
            r"c:\lowercase-drive",
            r"C:/forward/slash",
        ] {
            assert!(!valid_absolute_windows_path(Path::new(invalid)));
        }
    }

    #[test]
    fn pipe_sddl_contains_only_broker_full_and_runner_read_write() {
        let config = BrokerServiceConfig {
            schema: 2,
            host_id: Sha256Digest::from_bytes([1_u8; 32]),
            broker_service_sid: "S-1-5-80-1-2-3-4-5".to_owned(),
            runner_service_sid: "S-1-5-80-6-7-8-9-10".to_owned(),
            state_root: PathBuf::from(r"C:\ProgramData\Automata\WindowsBroker"),
            grant_verification_keys: Vec::new(),
            admission_signing_key: AdmissionSigningKeyConfig {
                issuer_key_id: "admission-key-v1".to_owned(),
                protected_pkcs8_base64: BASE64.encode([1_u8]),
                public_key_sha256: Sha256Digest::from_bytes([2_u8; 32]),
            },
            promotion_trust_bundles: Vec::new(),
            watchdog_interval_millis: 1_000,
        };
        let sddl = format!(
            "O:{owner}D:P(A;;GA;;;{owner})(A;;GRGW;;;{runner})",
            owner = config.broker_service_sid,
            runner = config.runner_service_sid,
        );
        assert!(!sddl.contains("WD"));
        assert!(!sddl.contains("AN"));
        assert!(!sddl.contains("AU"));
        assert!(pipe_security_descriptor(&config).is_ok());
    }

    #[test]
    fn host_input_acl_requires_protection_exact_trustees_and_direct_read() {
        let broker = "S-1-5-80-1-2-3-4-5";
        let runner = "S-1-5-80-6-7-8-9-10";
        let requested = SecurityInformation::Owner | SecurityInformation::Dacl;
        let valid =
            format!("O:{runner}D:P(A;;GR;;;{broker})(A;;GR;;;{runner})(A;;GA;;;SY)(A;;GA;;;BA)");
        let descriptor: LocalBox<WindowsFileSecurityDescriptor> = valid.parse().unwrap();
        assert!(validate_security_descriptor_value(&descriptor, requested, broker, runner).is_ok());

        for unsafe_sddl in [
            format!("O:{runner}D:(A;;GR;;;{broker})(A;;GR;;;{runner})"),
            format!("O:{runner}D:P(A;ID;GR;;;{broker})(A;;GR;;;{runner})"),
            format!("O:{runner}D:P(A;;GR;;;{broker})(A;;GR;;;{runner})(A;;GR;;;WD)"),
            format!("O:S-1-5-32-545D:P(A;;GR;;;{broker})(A;;GR;;;{runner})"),
            format!("O:{runner}D:P(A;;GR;;;{runner})"),
        ] {
            let descriptor: LocalBox<WindowsFileSecurityDescriptor> = unsafe_sddl.parse().unwrap();
            assert_eq!(
                validate_security_descriptor_value(&descriptor, requested, broker, runner),
                Err(WindowsBrokerHostInputError::Policy)
            );
        }
    }

    #[test]
    fn partial_pipe_frame_is_cancelled_by_service_stop() {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let stopper = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            stop_for_thread.store(true, Ordering::Release);
        });
        let mut reader = PartialThenBlockedReader::new([0_u8, 0]);

        assert_eq!(
            read_frame_until(
                &mut reader,
                stop.as_ref(),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(WindowsHyperVBrokerServiceError::Ipc)
        );
        stopper.join().unwrap();
    }

    #[test]
    fn stalled_pipe_frame_obeys_its_connection_deadline() {
        let stop = AtomicBool::new(false);
        let mut reader = PartialThenBlockedReader::default();

        assert_eq!(
            read_frame_until(&mut reader, &stop, Instant::now()),
            Err(WindowsHyperVBrokerServiceError::Ipc)
        );
    }
}
