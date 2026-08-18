use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write as _},
    os::fd::OwnedFd,
};

use automata_ci_core::Sha256Digest;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use p256::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};
use rustix::{
    fs::{self, AtFlags, Dir, FileType, Mode, OFlags, fstat, mkdirat, openat, renameat_with},
    process::{Gid, Uid},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};
use zeroize::Zeroizing;

use super::{
    LocalInitError, LocalInitErrorCode,
    certificates::CertificateMaterial,
    epoch::{ImmutableEpoch, MaterialDeriver},
};

pub(super) const REQUEST_SCHEMA: &str = "automata.local/materialize-request/v1";
const MANIFEST_SCHEMA: &str = "automata.local/static-material-manifest/v1";
pub(super) const RESPONSE_SCHEMA: &str = "automata.local/materialize-response/v1";
const MANIFEST_FILE: &str = ".automata-static-manifest.json";
pub(super) const MAX_REQUEST_BYTES: usize = 512 * 1024;
const MAX_FILE_BYTES: usize = 128 * 1024;
const MAX_MANIFEST_BYTES: usize = 16 * 1024;
pub(super) const STATIC_FILE_MODE: u32 = 0o400;
const STATIC_DIRECTORY_MODE: u32 = 0o700;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum VolumeRole {
    BootstrapState,
    ControlMaterial,
    Desired,
    EngineRelay,
    ObjectData,
    PostgresConfig,
    PostgresData,
    RelayBinding,
    RunnerConfig,
    RunnerData,
    RunnerSecrets,
    RustfsConfig,
}

impl VolumeRole {
    pub(super) const ALL: [Self; 12] = [
        Self::BootstrapState,
        Self::ControlMaterial,
        Self::Desired,
        Self::EngineRelay,
        Self::ObjectData,
        Self::PostgresConfig,
        Self::PostgresData,
        Self::RelayBinding,
        Self::RunnerConfig,
        Self::RunnerData,
        Self::RunnerSecrets,
        Self::RustfsConfig,
    ];

    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::BootstrapState => "bootstrap-state",
            Self::ControlMaterial => "control-material",
            Self::Desired => "desired",
            Self::EngineRelay => "engine-relay",
            Self::ObjectData => "object-data",
            Self::PostgresConfig => "postgres-config",
            Self::PostgresData => "postgres-data",
            Self::RelayBinding => "relay-binding",
            Self::RunnerConfig => "runner-config",
            Self::RunnerData => "runner-data",
            Self::RunnerSecrets => "runner-secrets",
            Self::RustfsConfig => "rustfs-config",
        }
    }

    pub(super) fn mount_target(self) -> String {
        format!("/automata-local/{}", self.name())
    }

    const fn uid(self) -> u32 {
        match self {
            Self::PostgresConfig | Self::PostgresData => 999,
            Self::ObjectData | Self::RustfsConfig => 10_001,
            Self::Desired | Self::RelayBinding | Self::RunnerConfig => 0,
            _ => 65_532,
        }
    }

    const fn gid(self) -> u32 {
        self.uid()
    }

    const fn directory_mode(self) -> u32 {
        match self {
            Self::Desired | Self::RelayBinding | Self::RunnerConfig => 0o555,
            Self::ObjectData => 0o750,
            _ => STATIC_DIRECTORY_MODE,
        }
    }

    pub(super) const fn is_static(self) -> bool {
        matches!(
            self,
            Self::ControlMaterial | Self::Desired | Self::PostgresConfig | Self::RustfsConfig
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FileId {
    ControlDatabaseCa,
    ControlDatabaseUrl,
    ControlEncryptionKey,
    ControlResultsSigningKey,
    ControlRunnerCa,
    ControlRunnerCaKey,
    ControlRunnerServerCertificate,
    ControlRunnerServerKey,
    ControlS3AccessKey,
    ControlS3Ca,
    ControlS3SecretKey,
    ControlSecretEncryptionKey,
    Desired,
    PostgresCa,
    PostgresPassword,
    PostgresServerCertificate,
    PostgresServerKey,
    RustfsAccessKey,
    RustfsCa,
    RustfsSecretKey,
    RustfsServerCertificate,
    RustfsServerKey,
    RustfsSseMasterKey,
}

impl FileId {
    const ALL: [Self; 23] = [
        Self::ControlDatabaseCa,
        Self::ControlDatabaseUrl,
        Self::ControlEncryptionKey,
        Self::ControlResultsSigningKey,
        Self::ControlRunnerCa,
        Self::ControlRunnerCaKey,
        Self::ControlRunnerServerCertificate,
        Self::ControlRunnerServerKey,
        Self::ControlS3AccessKey,
        Self::ControlS3Ca,
        Self::ControlS3SecretKey,
        Self::ControlSecretEncryptionKey,
        Self::Desired,
        Self::PostgresCa,
        Self::PostgresPassword,
        Self::PostgresServerCertificate,
        Self::PostgresServerKey,
        Self::RustfsAccessKey,
        Self::RustfsCa,
        Self::RustfsSecretKey,
        Self::RustfsServerCertificate,
        Self::RustfsServerKey,
        Self::RustfsSseMasterKey,
    ];

    const fn volume(self) -> VolumeRole {
        match self {
            Self::Desired => VolumeRole::Desired,
            Self::PostgresCa
            | Self::PostgresPassword
            | Self::PostgresServerCertificate
            | Self::PostgresServerKey => VolumeRole::PostgresConfig,
            Self::RustfsAccessKey
            | Self::RustfsCa
            | Self::RustfsSecretKey
            | Self::RustfsServerCertificate
            | Self::RustfsServerKey
            | Self::RustfsSseMasterKey => VolumeRole::RustfsConfig,
            _ => VolumeRole::ControlMaterial,
        }
    }

    const fn path(self) -> &'static str {
        match self {
            Self::Desired => "desired.json",
            Self::ControlDatabaseCa => "postgres-ca.pem",
            Self::ControlDatabaseUrl => "database-url",
            Self::ControlEncryptionKey => "control-plane-encryption-key",
            Self::ControlResultsSigningKey => "results-signing-key",
            Self::ControlRunnerCa => "tls/runner-ca.pem",
            Self::ControlRunnerCaKey => "tls/runner-ca-key.pem",
            Self::ControlRunnerServerCertificate | Self::PostgresServerCertificate => {
                "tls/server.pem"
            }
            Self::ControlRunnerServerKey | Self::PostgresServerKey => "tls/server-key.pem",
            Self::ControlS3AccessKey => "s3-access-key",
            Self::ControlS3Ca => "s3-ca.pem",
            Self::ControlS3SecretKey => "s3-secret-key",
            Self::ControlSecretEncryptionKey => "secret-provider-encryption-key",
            Self::PostgresCa => "tls/ca.pem",
            Self::PostgresPassword => "password",
            Self::RustfsAccessKey => "access-key",
            Self::RustfsCa => "tls/ca.crt",
            Self::RustfsSecretKey => "secret-key",
            Self::RustfsServerCertificate => "tls/rustfs_cert.pem",
            Self::RustfsServerKey => "tls/rustfs_key.pem",
            Self::RustfsSseMasterKey => "sse-s3-master-key",
        }
    }

    const fn mode(self) -> u32 {
        match self {
            Self::Desired => 0o444,
            _ => STATIC_FILE_MODE,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MaterializeRequest {
    schema: String,
    epoch_fingerprint: Sha256Digest,
    initial_desired_sha256: Sha256Digest,
    fresh_dynamic_roots: bool,
    volumes: Vec<VolumePlan>,
    files: Vec<FilePlan>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VolumePlan {
    role: VolumeRole,
    uid: u32,
    gid: u32,
    mode: u32,
    static_material: bool,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FilePlan {
    id: FileId,
    content_base64: String,
    sha256: Sha256Digest,
    size: u32,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticManifest {
    schema: String,
    epoch_fingerprint: Sha256Digest,
    volume: VolumeRole,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    id: FileId,
    path: String,
    sha256: Sha256Digest,
    size: u32,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Serialize)]
struct MaterializeResponse {
    schema: &'static str,
    epoch_fingerprint: Sha256Digest,
    sealed_static_volumes: u8,
}

impl MaterializeRequest {
    pub(super) fn build(
        epoch: &ImmutableEpoch,
        deriver: &MaterialDeriver,
        certificates: &CertificateMaterial,
        desired: &[u8],
        fresh_dynamic_roots: bool,
    ) -> Self {
        let postgres_password = deriver.text(b"postgres/password", 32);
        let s3_access_key = s3_access_key(deriver);
        let s3_secret_key = s3_secret_key(deriver);
        let sse_master_key = sse_master_key(deriver);
        let results_signing = deriver.text(b"control/results-signing-key", 32);
        let database_url = database_url(postgres_password.as_str());
        let files = vec![
            plan(FileId::ControlDatabaseCa, certificates.ca_pem.as_bytes()),
            plan(FileId::ControlDatabaseUrl, database_url.as_bytes()),
            derived_key_plan(
                FileId::ControlEncryptionKey,
                deriver,
                b"control/encryption-key",
            ),
            plan(FileId::ControlResultsSigningKey, results_signing.as_bytes()),
            plan(FileId::ControlRunnerCa, certificates.ca_pem.as_bytes()),
            plan(
                FileId::ControlRunnerCaKey,
                certificates.ca_key_pem.as_bytes(),
            ),
            plan(
                FileId::ControlRunnerServerCertificate,
                certificates.runner_chain_pem.as_bytes(),
            ),
            plan(
                FileId::ControlRunnerServerKey,
                certificates.runner_key_pem.as_bytes(),
            ),
            plan(FileId::ControlS3AccessKey, s3_access_key.as_bytes()),
            plan(FileId::ControlS3Ca, certificates.ca_pem.as_bytes()),
            plan(FileId::ControlS3SecretKey, s3_secret_key.as_bytes()),
            derived_key_plan(
                FileId::ControlSecretEncryptionKey,
                deriver,
                b"control/secret-encryption-key",
            ),
            plan(FileId::Desired, desired),
            plan(FileId::PostgresCa, certificates.ca_pem.as_bytes()),
            plan(FileId::PostgresPassword, postgres_password.as_bytes()),
            plan(
                FileId::PostgresServerCertificate,
                certificates.postgres_chain_pem.as_bytes(),
            ),
            plan(
                FileId::PostgresServerKey,
                certificates.postgres_key_pem.as_bytes(),
            ),
            plan(FileId::RustfsAccessKey, s3_access_key.as_bytes()),
            plan(FileId::RustfsCa, certificates.ca_pem.as_bytes()),
            plan(FileId::RustfsSecretKey, s3_secret_key.as_bytes()),
            plan(
                FileId::RustfsServerCertificate,
                certificates.object_chain_pem.as_bytes(),
            ),
            plan(
                FileId::RustfsServerKey,
                certificates.object_key_pem.as_bytes(),
            ),
            plan(FileId::RustfsSseMasterKey, sse_master_key.as_bytes()),
        ];
        Self {
            schema: REQUEST_SCHEMA.to_owned(),
            epoch_fingerprint: epoch.fingerprint(),
            initial_desired_sha256: epoch.initial_desired_sha256(),
            fresh_dynamic_roots,
            volumes: VolumeRole::ALL
                .into_iter()
                .map(|role| VolumePlan {
                    role,
                    uid: role.uid(),
                    gid: role.gid(),
                    mode: role.directory_mode(),
                    static_material: role.is_static(),
                })
                .collect(),
            files,
        }
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, LocalInitError> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| materialization_failed())?;
        bytes.push(b'\n');
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(materialization_failed());
        }
        Ok(bytes)
    }
}

fn plan(id: FileId, content: &[u8]) -> FilePlan {
    assert!(!content.is_empty() && content.len() <= MAX_FILE_BYTES);
    let volume = id.volume();
    FilePlan {
        id,
        content_base64: STANDARD.encode(content),
        sha256: digest(content),
        size: u32::try_from(content.len()).expect("bounded material file"),
        uid: volume.uid(),
        gid: volume.gid(),
        mode: id.mode(),
    }
}

fn derived_key_plan(id: FileId, deriver: &MaterialDeriver, purpose: &'static [u8]) -> FilePlan {
    let material = deriver.bytes(purpose, 32);
    plan(id, material.as_slice())
}

pub(super) fn s3_access_key(deriver: &MaterialDeriver) -> String {
    const UPPERCASE_HEX: &[u8; 16] = b"0123456789ABCDEF";
    let material = deriver.bytes(b"s3/access-key", 10);
    let mut encoded = String::with_capacity(20);
    for byte in material.iter().copied() {
        encoded.push(char::from(UPPERCASE_HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(UPPERCASE_HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(super) fn s3_secret_key(deriver: &MaterialDeriver) -> Zeroizing<String> {
    deriver.text(b"s3/secret-key", 30)
}

fn sse_master_key(deriver: &MaterialDeriver) -> String {
    STANDARD.encode(deriver.bytes(b"s3/sse-master-key", 32).as_slice())
}

fn database_url(postgres_password: &str) -> String {
    format!("postgresql://automata:{postgres_password}@postgres.automata.invalid:5432/automata\n")
}

pub(crate) fn run_fixed_materializer() -> Result<(), LocalInitError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(materialization_failed());
    }
    let bytes = read_fixed_request()?;
    let request = parse_fixed_request(&bytes)?;
    materialize(&request)?;
    let response = MaterializeResponse {
        schema: RESPONSE_SCHEMA,
        epoch_fingerprint: request.epoch_fingerprint,
        sealed_static_volumes: 4,
    };
    let mut bytes = serde_json::to_vec(&response).map_err(|_| materialization_failed())?;
    bytes.push(b'\n');
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|_| materialization_failed())
}

fn read_fixed_request() -> Result<Zeroizing<Vec<u8>>, LocalInitError> {
    let stdin = std::io::stdin();
    read_fixed_request_from(stdin.lock())
}

fn read_fixed_request_from(mut input: impl Read) -> Result<Zeroizing<Vec<u8>>, LocalInitError> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::Read::by_ref(&mut input)
        .take(u64::try_from(MAX_REQUEST_BYTES + 1).expect("bounded request"))
        .read_to_end(&mut bytes)
        .map_err(|_| materialization_failed())?;
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err(materialization_failed());
    }
    Ok(bytes)
}

fn parse_fixed_request(bytes: &[u8]) -> Result<MaterializeRequest, LocalInitError> {
    let request: MaterializeRequest =
        serde_json::from_slice(bytes).map_err(|_| materialization_failed())?;
    let canonical = Zeroizing::new(request.canonical_bytes()?);
    if canonical.as_slice() != bytes {
        return Err(materialization_failed());
    }
    Ok(request)
}

fn materialize(request: &MaterializeRequest) -> Result<(), LocalInitError> {
    validate_request(request)?;
    let plans = request
        .files
        .iter()
        .map(|plan| (plan.id, plan))
        .collect::<BTreeMap<_, _>>();
    validate_cross_file_material(&plans)?;
    for role in VolumeRole::ALL {
        let directory = open_volume(role)?;
        prepare_volume_root(&directory, role, request.fresh_dynamic_roots)?;
        if role.is_static() {
            seal_static_volume(
                &directory,
                role,
                request.epoch_fingerprint,
                request.initial_desired_sha256,
                &plans,
                request.fresh_dynamic_roots,
            )?;
        } else if !request.fresh_dynamic_roots {
            verify_dynamic_root_shape(&directory, role)?;
        }
        verify_root(&directory, role)?;
    }
    Ok(())
}

fn prepare_volume_root(
    directory: &OwnedFd,
    role: VolumeRole,
    fresh_dynamic_roots: bool,
) -> Result<(), LocalInitError> {
    if fresh_dynamic_roots {
        if !role.is_static() {
            verify_empty_directory(directory)?;
        }
        initialize_root(directory, role)
    } else {
        // Completed materialization is an attestation boundary, never a
        // repair boundary. In particular, do not normalize root ownership or
        // mode after the durable host record says materialization completed.
        verify_root(directory, role)
    }
}

fn verify_dynamic_root_shape(directory: &OwnedFd, role: VolumeRole) -> Result<(), LocalInitError> {
    debug_assert!(!role.is_static());
    for entry in Dir::read_from(directory).map_err(|_| materialization_failed())? {
        let entry = entry.map_err(|_| materialization_failed())?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| materialization_failed())?;
        if matches!(name, "." | "..") {
            continue;
        }
        let allowed = match role {
            VolumeRole::BootstrapState => {
                matches!(
                    name,
                    "request.json"
                        | ".request.json.automata-write"
                        | "runner-enrollment-token"
                        | ".runner-enrollment-token.automata-write"
                        | "receipt.json"
                ) || name
                    .strip_prefix(".automata-bootstrap-receipt-")
                    .and_then(|suffix| suffix.strip_suffix(".tmp"))
                    .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
            }
            VolumeRole::RelayBinding => {
                matches!(name, "binding.json" | ".binding.json.automata-write")
            }
            VolumeRole::RunnerConfig => {
                matches!(name, "runner.json" | ".runner.json.automata-write")
            }
            VolumeRole::RunnerSecrets => matches!(
                name,
                "s3-access-key"
                    | ".s3-access-key.automata-write"
                    | "s3-ca.pem"
                    | ".s3-ca.pem.automata-write"
                    | "s3-secret-key"
                    | ".s3-secret-key.automata-write"
                    | "spool-key-v1.hex"
                    | ".spool-key-v1.hex.automata-write"
            ),
            // These are service-owned data roots. Their internal schemas are
            // attested by the owning production service; this boundary still
            // rejects the static-material namespace and fixed writer staging
            // namespace, which can never be legitimate in these roots.
            VolumeRole::EngineRelay
            | VolumeRole::ObjectData
            | VolumeRole::PostgresData
            | VolumeRole::RunnerData => name != MANIFEST_FILE && !name.ends_with(".automata-write"),
            VolumeRole::ControlMaterial
            | VolumeRole::Desired
            | VolumeRole::PostgresConfig
            | VolumeRole::RustfsConfig => false,
        };
        if !allowed {
            return Err(materialization_failed());
        }
    }
    Ok(())
}

fn verify_empty_directory(directory: &OwnedFd) -> Result<(), LocalInitError> {
    for entry in Dir::read_from(directory).map_err(|_| materialization_failed())? {
        let entry = entry.map_err(|_| materialization_failed())?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| materialization_failed())?;
        if !matches!(name, "." | "..") {
            return Err(materialization_failed());
        }
    }
    Ok(())
}

fn validate_request(request: &MaterializeRequest) -> Result<(), LocalInitError> {
    if request.schema != REQUEST_SCHEMA
        || request.volumes.len() != VolumeRole::ALL.len()
        || request.files.len() != FileId::ALL.len()
    {
        return Err(materialization_failed());
    }
    for (actual, role) in request.volumes.iter().zip(VolumeRole::ALL) {
        if actual.role != role
            || actual.uid != role.uid()
            || actual.gid != role.gid()
            || actual.mode != role.directory_mode()
            || actual.static_material != role.is_static()
        {
            return Err(materialization_failed());
        }
    }
    for (actual, id) in request.files.iter().zip(FileId::ALL) {
        let content = decode_file(actual)?;
        if actual.id != id
            || actual.uid != id.volume().uid()
            || actual.gid != id.volume().gid()
            || actual.mode != id.mode()
            || actual.size != u32::try_from(content.len()).map_err(|_| materialization_failed())?
            || actual.sha256 != digest(&content)
        {
            return Err(materialization_failed());
        }
    }
    Ok(())
}

fn validate_cross_file_material(plans: &BTreeMap<FileId, &FilePlan>) -> Result<(), LocalInitError> {
    exact_equal(plans, FileId::ControlDatabaseCa, FileId::PostgresCa)?;
    exact_equal(plans, FileId::ControlDatabaseCa, FileId::RustfsCa)?;
    exact_equal(plans, FileId::ControlDatabaseCa, FileId::ControlS3Ca)?;
    exact_equal(plans, FileId::ControlDatabaseCa, FileId::ControlRunnerCa)?;
    exact_equal(plans, FileId::ControlS3AccessKey, FileId::RustfsAccessKey)?;
    exact_equal(plans, FileId::ControlS3SecretKey, FileId::RustfsSecretKey)?;
    validate_cert_key(
        plans,
        FileId::PostgresServerCertificate,
        FileId::PostgresServerKey,
        FileId::PostgresCa,
    )?;
    validate_cert_key(
        plans,
        FileId::RustfsServerCertificate,
        FileId::RustfsServerKey,
        FileId::RustfsCa,
    )?;
    validate_cert_key(
        plans,
        FileId::ControlRunnerServerCertificate,
        FileId::ControlRunnerServerKey,
        FileId::ControlRunnerCa,
    )?;
    validate_cert_key(
        plans,
        FileId::ControlRunnerCa,
        FileId::ControlRunnerCaKey,
        FileId::ControlRunnerCa,
    )
}

fn exact_equal(
    plans: &BTreeMap<FileId, &FilePlan>,
    left: FileId,
    right: FileId,
) -> Result<(), LocalInitError> {
    if decode_file(plans.get(&left).ok_or_else(materialization_failed)?)?
        != decode_file(plans.get(&right).ok_or_else(materialization_failed)?)?
    {
        return Err(materialization_failed());
    }
    Ok(())
}

fn validate_cert_key(
    plans: &BTreeMap<FileId, &FilePlan>,
    chain: FileId,
    key: FileId,
    ca: FileId,
) -> Result<(), LocalInitError> {
    let self_signed = chain == ca;
    let chain = decode_file(plans.get(&chain).ok_or_else(materialization_failed)?)?;
    let key = decode_file(plans.get(&key).ok_or_else(materialization_failed)?)?;
    let ca = decode_file(plans.get(&ca).ok_or_else(materialization_failed)?)?;
    let (chain_remainder, leaf_pem) =
        parse_x509_pem(&chain).map_err(|_| materialization_failed())?;
    let (leaf_remainder, certificate) =
        parse_x509_certificate(&leaf_pem.contents).map_err(|_| materialization_failed())?;
    let (ca_remainder, ca_pem) = parse_x509_pem(&ca).map_err(|_| materialization_failed())?;
    let (issuer_remainder, issuer) =
        parse_x509_certificate(&ca_pem.contents).map_err(|_| materialization_failed())?;
    let secret = p256::SecretKey::from_pkcs8_pem(
        std::str::from_utf8(&key).map_err(|_| materialization_failed())?,
    )
    .map_err(|_| materialization_failed())?;
    let public = secret
        .public_key()
        .to_public_key_der()
        .map_err(|_| materialization_failed())?;
    if leaf_pem.label != "CERTIFICATE"
        || ca_pem.label != "CERTIFICATE"
        || !leaf_remainder.is_empty()
        || !ca_remainder.is_empty()
        || !issuer_remainder.is_empty()
        || certificate.public_key().raw != public.as_bytes()
        || if self_signed {
            !chain_remainder.is_empty()
                || chain != ca
                || certificate.subject() != issuer.subject()
                || certificate.issuer() != certificate.subject()
                || certificate.verify_signature(None).is_err()
        } else {
            chain_remainder != ca
                || certificate.subject() == issuer.subject()
                || certificate.issuer() != issuer.subject()
                || certificate
                    .verify_signature(Some(issuer.public_key()))
                    .is_err()
        }
    {
        return Err(materialization_failed());
    }
    Ok(())
}

fn open_volume(role: VolumeRole) -> Result<OwnedFd, LocalInitError> {
    fs::open(
        role.mount_target(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| materialization_failed())
}

fn initialize_root(directory: &OwnedFd, role: VolumeRole) -> Result<(), LocalInitError> {
    let stat = fstat(directory).map_err(|_| materialization_failed())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(materialization_failed());
    }
    if stat.st_uid == role.uid()
        && stat.st_gid == role.gid()
        && stat.st_mode & 0o7777 == role.directory_mode()
    {
        return Ok(());
    }
    if stat.st_uid != 0 || stat.st_gid != 0 {
        return Err(materialization_failed());
    }
    fs::fchmod(directory, Mode::from_raw_mode(role.directory_mode()))
        .and_then(|()| {
            fs::fchown(
                directory,
                Some(Uid::from_raw(role.uid())),
                Some(Gid::from_raw(role.gid())),
            )
        })
        .and_then(|()| fs::fsync(directory))
        .map_err(|_| materialization_failed())
}

fn verify_root(directory: &OwnedFd, role: VolumeRole) -> Result<(), LocalInitError> {
    let stat = fstat(directory).map_err(|_| materialization_failed())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != role.uid()
        || stat.st_gid != role.gid()
        || stat.st_mode & 0o7777 != role.directory_mode()
    {
        return Err(materialization_failed());
    }
    Ok(())
}

fn seal_static_volume(
    directory: &OwnedFd,
    role: VolumeRole,
    epoch_fingerprint: Sha256Digest,
    initial_desired_sha256: Sha256Digest,
    plans: &BTreeMap<FileId, &FilePlan>,
    allow_incomplete: bool,
) -> Result<(), LocalInitError> {
    let role_plans = FileId::ALL
        .into_iter()
        .filter(|id| id.volume() == role)
        .map(|id| plans.get(&id).copied().ok_or_else(materialization_failed))
        .collect::<Result<Vec<_>, _>>()?;
    let expected_paths = expected_paths(&role_plans);
    let manifest = StaticManifest {
        schema: MANIFEST_SCHEMA.to_owned(),
        epoch_fingerprint,
        volume: role,
        files: role_plans
            .iter()
            .map(|plan| ManifestFile {
                id: plan.id,
                path: plan.id.path().to_owned(),
                sha256: plan.sha256,
                size: plan.size,
                uid: plan.uid,
                gid: plan.gid,
                mode: plan.mode,
            })
            .collect(),
    };
    let mut bytes = serde_json::to_vec(&manifest).map_err(|_| materialization_failed())?;
    bytes.push(b'\n');
    if let Some(stored) = try_read_static_manifest(directory, role)? {
        let parsed: StaticManifest =
            serde_json::from_slice(&stored).map_err(|_| materialization_failed())?;
        verify_tls_directory(directory, role, &role_plans)?;
        if role == VolumeRole::Desired {
            validate_stored_desired_manifest(
                directory,
                &stored,
                &parsed,
                epoch_fingerprint,
                initial_desired_sha256,
            )?;
        } else {
            if stored != bytes || parsed != manifest {
                return Err(materialization_failed());
            }
            for plan in &role_plans {
                verify_file(directory, plan)?;
            }
            validate_stored_cross_files(directory, role, &role_plans)?;
        }
        verify_no_extra_entries(directory, &expected_paths, true)?;
        return Ok(());
    }
    if !allow_incomplete {
        return Err(materialization_failed());
    }
    if role == VolumeRole::Desired
        && manifest
            .files
            .iter()
            .find(|file| file.id == FileId::Desired)
            .is_none_or(|file| file.sha256 != initial_desired_sha256)
    {
        return Err(materialization_failed());
    }

    verify_no_extra_entries(directory, &expected_paths, false)?;
    ensure_tls_directory(directory, role, &role_plans)?;
    for plan in &role_plans {
        ensure_file(directory, plan)?;
    }
    validate_stored_cross_files(directory, role, &role_plans)?;
    ensure_exact_file(
        directory,
        MANIFEST_FILE,
        &bytes,
        role.uid(),
        role.gid(),
        manifest_mode(role),
    )?;
    verify_no_extra_entries(directory, &expected_paths, true)?;
    let stored = read_exact_file(
        directory,
        MANIFEST_FILE,
        bytes.len(),
        role.uid(),
        role.gid(),
        manifest_mode(role),
    )?;
    let parsed: StaticManifest =
        serde_json::from_slice(&stored).map_err(|_| materialization_failed())?;
    if stored != bytes || parsed != manifest {
        return Err(materialization_failed());
    }
    Ok(())
}

fn expected_paths(plans: &[&FilePlan]) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for plan in plans {
        let path = plan.id.path();
        paths.insert(path.to_owned());
        if path.starts_with("tls/") {
            paths.insert("tls".to_owned());
        }
    }
    paths
}

const fn manifest_mode(role: VolumeRole) -> u32 {
    if matches!(role, VolumeRole::Desired) {
        0o444
    } else {
        STATIC_FILE_MODE
    }
}

fn ensure_tls_directory(
    directory: &OwnedFd,
    role: VolumeRole,
    plans: &[&FilePlan],
) -> Result<(), LocalInitError> {
    if !plans.iter().any(|plan| plan.id.path().starts_with("tls/")) {
        return Ok(());
    }
    match mkdirat(directory, "tls", Mode::from_raw_mode(STATIC_DIRECTORY_MODE)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(_) => return Err(materialization_failed()),
    }
    let tls = openat(
        directory,
        "tls",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| materialization_failed())?;
    let stat = fstat(&tls).map_err(|_| materialization_failed())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(materialization_failed());
    }
    if stat.st_uid == role.uid()
        && stat.st_gid == role.gid()
        && stat.st_mode & 0o7777 == STATIC_DIRECTORY_MODE
    {
        return Ok(());
    }
    if stat.st_uid != 0 || stat.st_gid != 0 {
        return Err(materialization_failed());
    }
    fs::fchmod(&tls, Mode::from_raw_mode(STATIC_DIRECTORY_MODE))
        .and_then(|()| {
            fs::fchown(
                &tls,
                Some(Uid::from_raw(role.uid())),
                Some(Gid::from_raw(role.gid())),
            )
        })
        .and_then(|()| fs::fsync(&tls))
        .map_err(|_| materialization_failed())
}

fn verify_tls_directory(
    directory: &OwnedFd,
    role: VolumeRole,
    plans: &[&FilePlan],
) -> Result<(), LocalInitError> {
    if !plans.iter().any(|plan| plan.id.path().starts_with("tls/")) {
        return Ok(());
    }
    let tls = openat(
        directory,
        "tls",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| materialization_failed())?;
    let stat = fstat(&tls).map_err(|_| materialization_failed())?;
    if !exact_directory_metadata(&stat, role.uid(), role.gid(), STATIC_DIRECTORY_MODE) {
        return Err(materialization_failed());
    }
    Ok(())
}

fn exact_directory_metadata(stat: &rustix::fs::Stat, uid: u32, gid: u32, mode: u32) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == uid
        && stat.st_gid == gid
        && stat.st_mode & 0o7777 == mode
}

fn ensure_file(directory: &OwnedFd, plan: &FilePlan) -> Result<(), LocalInitError> {
    let content = decode_file(plan)?;
    let (parent, name) = if let Some(name) = plan.id.path().strip_prefix("tls/") {
        let tls = openat(
            directory,
            "tls",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| materialization_failed())?;
        (Some(tls), name)
    } else {
        (None, plan.id.path())
    };
    let parent = parent.as_ref().unwrap_or(directory);
    ensure_exact_file(parent, name, &content, plan.uid, plan.gid, plan.mode)
}

fn verify_file(directory: &OwnedFd, plan: &FilePlan) -> Result<(), LocalInitError> {
    let content = decode_file(plan)?;
    let (parent, name) = if let Some(name) = plan.id.path().strip_prefix("tls/") {
        let tls = openat(
            directory,
            "tls",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| materialization_failed())?;
        (Some(tls), name)
    } else {
        (None, plan.id.path())
    };
    let parent = parent.as_ref().unwrap_or(directory);
    if read_exact_file(parent, name, content.len(), plan.uid, plan.gid, plan.mode)? != content {
        return Err(materialization_failed());
    }
    Ok(())
}

fn try_read_static_manifest(
    directory: &OwnedFd,
    role: VolumeRole,
) -> Result<Option<Vec<u8>>, LocalInitError> {
    let descriptor = match openat(
        directory,
        MANIFEST_FILE,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(materialization_failed()),
    };
    let before = fstat(&descriptor).map_err(|_| materialization_failed())?;
    let size = usize::try_from(before.st_size).map_err(|_| materialization_failed())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_nlink != 1
        || before.st_uid != role.uid()
        || before.st_gid != role.gid()
        || before.st_mode & 0o7777 != manifest_mode(role)
        || size == 0
        || size > MAX_MANIFEST_BYTES
    {
        return Err(materialization_failed());
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(size);
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(MAX_MANIFEST_BYTES + 1).expect("manifest bound fits u64"))
        .read_to_end(&mut bytes)
        .map_err(|_| materialization_failed())?;
    let after = fstat(&file).map_err(|_| materialization_failed())?;
    if bytes.len() != size || !same_file(&before, &after) {
        return Err(materialization_failed());
    }
    Ok(Some(bytes))
}

fn validate_stored_desired_manifest(
    directory: &OwnedFd,
    stored: &[u8],
    manifest: &StaticManifest,
    epoch_fingerprint: Sha256Digest,
    initial_desired_sha256: Sha256Digest,
) -> Result<(), LocalInitError> {
    validate_stored_desired_manifest_descriptor(
        stored,
        manifest,
        epoch_fingerprint,
        initial_desired_sha256,
    )?;
    for file in &manifest.files {
        let expected_size = usize::try_from(file.size).map_err(|_| materialization_failed())?;
        let bytes = read_exact_file(
            directory,
            file.id.path(),
            expected_size,
            file.uid,
            file.gid,
            file.mode,
        )?;
        if digest(&bytes) != file.sha256 {
            return Err(materialization_failed());
        }
    }
    Ok(())
}

fn validate_stored_desired_manifest_descriptor(
    stored: &[u8],
    manifest: &StaticManifest,
    epoch_fingerprint: Sha256Digest,
    initial_desired_sha256: Sha256Digest,
) -> Result<(), LocalInitError> {
    let mut canonical = serde_json::to_vec(manifest).map_err(|_| materialization_failed())?;
    canonical.push(b'\n');
    if stored != canonical
        || manifest.schema != MANIFEST_SCHEMA
        || manifest.epoch_fingerprint != epoch_fingerprint
        || manifest.volume != VolumeRole::Desired
        || manifest.files.len() != 1
    {
        return Err(materialization_failed());
    }
    let file = &manifest.files[0];
    let expected_size = usize::try_from(file.size).map_err(|_| materialization_failed())?;
    if file.id != FileId::Desired
        || file.path != FileId::Desired.path()
        || file.sha256 != initial_desired_sha256
        || expected_size == 0
        || expected_size > MAX_FILE_BYTES
        || file.uid != VolumeRole::Desired.uid()
        || file.gid != VolumeRole::Desired.gid()
        || file.mode != FileId::Desired.mode()
    {
        return Err(materialization_failed());
    }
    Ok(())
}

fn ensure_exact_file(
    directory: &OwnedFd,
    name: &str,
    content: &[u8],
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), LocalInitError> {
    if let Some(existing) = try_read_exact_file(directory, name, content.len(), uid, gid, mode)? {
        if existing == content {
            return Ok(());
        }
        return Err(materialization_failed());
    }
    let temporary = temporary_name(name);
    match try_read_exact_file(directory, &temporary, content.len(), uid, gid, mode) {
        Ok(Some(existing)) if existing == content => {
            publish_temporary(directory, &temporary, name, content, uid, gid, mode)?;
            return Ok(());
        }
        Ok(None) => {}
        Ok(Some(_)) | Err(_) => {
            fs::unlinkat(directory, &temporary, AtFlags::empty())
                .and_then(|()| fs::fsync(directory))
                .map_err(|_| materialization_failed())?;
        }
    }
    let descriptor = openat(
        directory,
        &temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(mode),
    )
    .map_err(|_| materialization_failed())?;
    let result = (|| {
        fs::fchmod(&descriptor, Mode::from_raw_mode(mode))
            .and_then(|()| {
                fs::fchown(
                    &descriptor,
                    Some(Uid::from_raw(uid)),
                    Some(Gid::from_raw(gid)),
                )
            })
            .map_err(|_| materialization_failed())?;
        let mut file = File::from(descriptor);
        file.write_all(content)
            .and_then(|()| file.sync_all())
            .map_err(|_| materialization_failed())?;
        drop(file);
        publish_temporary(directory, &temporary, name, content, uid, gid, mode)
    })();
    if result.is_err() {
        let _ = fs::unlinkat(directory, &temporary, AtFlags::empty());
    }
    result?;
    if read_exact_file(directory, name, content.len(), uid, gid, mode)? != content {
        return Err(materialization_failed());
    }
    Ok(())
}

fn publish_temporary(
    directory: &OwnedFd,
    temporary: &str,
    name: &str,
    content: &[u8],
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), LocalInitError> {
    match renameat_with(
        directory,
        temporary,
        directory,
        name,
        fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            if read_exact_file(directory, name, content.len(), uid, gid, mode)? != content {
                return Err(materialization_failed());
            }
            fs::unlinkat(directory, temporary, AtFlags::empty())
                .map_err(|_| materialization_failed())?;
        }
        Err(_) => return Err(materialization_failed()),
    }
    fs::fsync(directory).map_err(|_| materialization_failed())
}

fn temporary_name(name: &str) -> String {
    format!(".{name}.automata-init.tmp")
}

fn read_exact_file(
    directory: &OwnedFd,
    name: &str,
    expected_size: usize,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<Vec<u8>, LocalInitError> {
    try_read_exact_file(directory, name, expected_size, uid, gid, mode)?
        .ok_or_else(materialization_failed)
}

fn try_read_exact_file(
    directory: &OwnedFd,
    name: &str,
    expected_size: usize,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<Option<Vec<u8>>, LocalInitError> {
    let descriptor = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(materialization_failed()),
    };
    let before = fstat(&descriptor).map_err(|_| materialization_failed())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_nlink != 1
        || before.st_uid != uid
        || before.st_gid != gid
        || before.st_mode & 0o7777 != mode
        || usize::try_from(before.st_size).ok() != Some(expected_size)
    {
        return Err(materialization_failed());
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(expected_size);
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(expected_size + 1).map_err(|_| materialization_failed())?)
        .read_to_end(&mut bytes)
        .map_err(|_| materialization_failed())?;
    let after = fstat(&file).map_err(|_| materialization_failed())?;
    if bytes.len() != expected_size || !same_file(&before, &after) {
        return Err(materialization_failed());
    }
    Ok(Some(bytes))
}

fn verify_no_extra_entries(
    directory: &OwnedFd,
    expected: &BTreeSet<String>,
    require_manifest: bool,
) -> Result<(), LocalInitError> {
    let mut actual = BTreeSet::new();
    for entry in Dir::read_from(directory).map_err(|_| materialization_failed())? {
        let entry = entry.map_err(|_| materialization_failed())?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| materialization_failed())?;
        if matches!(name, "." | "..") {
            continue;
        }
        actual.insert(name.to_owned());
    }
    let expected_top = expected
        .iter()
        .filter_map(|path| path.split('/').next())
        .map(str::to_owned)
        .chain(std::iter::once(MANIFEST_FILE.to_owned()))
        .collect::<BTreeSet<_>>();
    let mut allowed_top = expected_top.clone();
    if !require_manifest {
        for path in expected.iter().filter(|path| !path.contains('/')) {
            allowed_top.insert(temporary_name(path));
        }
        allowed_top.insert(temporary_name(MANIFEST_FILE));
    }
    if !actual.is_subset(&allowed_top) || (require_manifest && actual != expected_top) {
        return Err(materialization_failed());
    }
    if expected.contains("tls") && actual.contains("tls") {
        let tls = openat(
            directory,
            "tls",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| materialization_failed())?;
        let expected_tls = expected
            .iter()
            .filter_map(|path| path.strip_prefix("tls/"))
            .collect::<BTreeSet<_>>();
        let mut actual_tls = BTreeSet::new();
        for entry in Dir::read_from(&tls).map_err(|_| materialization_failed())? {
            let entry = entry.map_err(|_| materialization_failed())?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| materialization_failed())?;
            if !matches!(name, "." | "..") {
                actual_tls.insert(name.to_owned());
            }
        }
        let mut allowed_tls = expected_tls.iter().copied().collect::<BTreeSet<_>>();
        let temporary_tls = expected_tls
            .iter()
            .map(|name| temporary_name(name))
            .collect::<BTreeSet<_>>();
        if !require_manifest {
            allowed_tls.extend(temporary_tls.iter().map(String::as_str));
        }
        if !actual_tls
            .iter()
            .all(|name| allowed_tls.contains(name.as_str()))
            || (require_manifest && actual_tls.len() != expected_tls.len())
        {
            return Err(materialization_failed());
        }
    }
    Ok(())
}

fn validate_stored_cross_files(
    directory: &OwnedFd,
    _role: VolumeRole,
    plans: &[&FilePlan],
) -> Result<(), LocalInitError> {
    for plan in plans {
        let content = decode_file(plan)?;
        let stored = if let Some(name) = plan.id.path().strip_prefix("tls/") {
            let tls = openat(
                directory,
                "tls",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| materialization_failed())?;
            read_exact_file(&tls, name, content.len(), plan.uid, plan.gid, plan.mode)?
        } else {
            read_exact_file(
                directory,
                plan.id.path(),
                content.len(),
                plan.uid,
                plan.gid,
                plan.mode,
            )?
        };
        if digest(&stored) != plan.sha256 || stored != content {
            return Err(materialization_failed());
        }
    }
    Ok(())
}

fn decode_file(plan: &FilePlan) -> Result<Vec<u8>, LocalInitError> {
    let content = STANDARD
        .decode(&plan.content_base64)
        .map_err(|_| materialization_failed())?;
    if content.is_empty() || content.len() > MAX_FILE_BYTES {
        return Err(materialization_failed());
    }
    Ok(content)
}

fn same_file(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn materialization_failed() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::MaterializationFailed)
}

#[cfg(test)]
mod tests;
