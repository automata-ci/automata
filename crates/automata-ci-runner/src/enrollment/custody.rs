//! Crash-safe runner enrollment request and credential custody.

use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::{
    fs::File,
    io::{Read as _, Write as _},
};

use anyhow::{Context as _, Result, bail};
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType, KeyPair,
    PKCS_ECDSA_P256_SHA256, PublicKeyData as _,
};
use reqwest::Url;
use rustls::pki_types::pem::PemObject as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

use super::{RedeemResponse, transport::MAX_RESPONSE_BYTES, validate_token};
use crate::product::{RunnerProductConfig, SecretSource};

const MAX_STAGE_BYTES: usize = 1024 * 1_024;
const STAGE_SCHEMA: u8 = 1;

pub(super) struct CredentialDestinations {
    server_roots: PathBuf,
    certificate_chain: PathBuf,
    private_key: PathBuf,
    request_stage: PathBuf,
    response_stage: PathBuf,
    #[cfg(unix)]
    _lock: rustix::fd::OwnedFd,
}

impl CredentialDestinations {
    pub(super) fn from_config(config: &RunnerProductConfig) -> Result<Self> {
        fn file(source: &SecretSource) -> Result<PathBuf> {
            let SecretSource::File { path } = source else {
                bail!("runner enrollment requires file-backed TLS credential destinations");
            };
            Ok(path.clone())
        }
        let private_key = file(config.tls().private_key())?;
        let request_stage = enrollment_sibling(&private_key, ".automata-enrollment-request")?;
        let response_stage = enrollment_sibling(&private_key, ".automata-enrollment-response")?;
        let lock_path = enrollment_sibling(&private_key, ".automata-enrollment-lock")?;
        let server_roots = file(config.tls().server_roots())?;
        let certificate_chain = file(config.tls().certificate_chain())?;
        let final_paths = [
            server_roots.clone(),
            certificate_chain.clone(),
            private_key.clone(),
            request_stage.clone(),
            response_stage.clone(),
        ];
        let mut paths = final_paths.to_vec();
        paths.push(lock_path.clone());
        for path in &final_paths {
            paths.push(temporary_path(path)?);
        }
        validate_destination_set(&paths)?;
        #[cfg(unix)]
        let lock = acquire_enrollment_lock(&lock_path)?;
        Ok(Self {
            server_roots,
            certificate_chain,
            private_key,
            request_stage,
            response_stage,
            #[cfg(unix)]
            _lock: lock,
        })
    }

    fn require_absent(&self) -> Result<()> {
        if read_bounded_file(&self.server_roots, MAX_STAGE_BYTES, false)?.is_some()
            || read_bounded_file(&self.certificate_chain, MAX_STAGE_BYTES, false)?.is_some()
            || read_bounded_file(&self.private_key, MAX_STAGE_BYTES, true)?.is_some()
        {
            bail!("runner TLS credential destination already exists");
        }
        Ok(())
    }

    pub(super) fn load_stage(
        &self,
        config: &RunnerProductConfig,
        origin: &Url,
        runner_name: &str,
    ) -> Result<Option<EnrollmentStage>> {
        if let Some(bytes) = read_bounded_file(&self.request_stage, MAX_STAGE_BYTES, true)? {
            let stage: EnrollmentStage = serde_json::from_slice(&bytes)
                .context("runner enrollment request stage is invalid")?;
            stage.validate(config, origin, runner_name)?;
            sync_parent(&self.request_stage)?;
            return Ok(Some(stage));
        }
        if let Some(bytes) = read_bounded_temporary(&self.request_stage, MAX_STAGE_BYTES, true)? {
            let Ok(stage) = serde_json::from_slice::<EnrollmentStage>(&bytes) else {
                remove_temporary_durable(&self.request_stage)?;
                return Ok(None);
            };
            stage.validate(config, origin, runner_name)?;
            publish_temporary(&self.request_stage)?;
            return Ok(Some(stage));
        }
        if read_bounded_file(&self.response_stage, MAX_RESPONSE_BYTES, true)?.is_some() {
            bail!("runner enrollment response stage has no matching request stage");
        }
        Ok(None)
    }

    pub(super) fn create_stage(
        &self,
        config: &RunnerProductConfig,
        origin: &Url,
        runner_name: &str,
        token: Zeroizing<String>,
    ) -> Result<EnrollmentStage> {
        self.require_absent()?;
        let stage = EnrollmentStage::new(config, origin, runner_name, token)?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(&stage).context("runner enrollment request could not be staged")?,
        );
        persist_new(&self.request_stage, &bytes, true)?;
        Ok(stage)
    }

    pub(super) fn load_response(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if let Some(response) = read_bounded_file(&self.response_stage, MAX_RESPONSE_BYTES, true)? {
            sync_parent(&self.response_stage)?;
            if serde_json::from_slice::<RedeemResponse>(&response).is_err() {
                remove_durable(&self.response_stage)?;
                return Ok(None);
            }
            return Ok(Some(response));
        }
        let Some(response) =
            read_bounded_temporary(&self.response_stage, MAX_RESPONSE_BYTES, true)?
        else {
            return Ok(None);
        };
        if serde_json::from_slice::<RedeemResponse>(&response).is_err() {
            remove_temporary_durable(&self.response_stage)?;
            return Ok(None);
        }
        publish_temporary(&self.response_stage)?;
        Ok(Some(response))
    }

    pub(super) fn persist_response(&self, response: &[u8]) -> Result<()> {
        persist_exact_file(&self.response_stage, response, true)
            .context("runner enrollment response could not be staged")
    }

    pub(super) fn persist_exact(&self, roots: &[u8], chain: &[u8], key: &[u8]) -> Result<()> {
        persist_exact_file(&self.server_roots, roots, false)?;
        persist_exact_file(&self.certificate_chain, chain, false)?;
        persist_exact_file(&self.private_key, key, true)?;
        Ok(())
    }

    pub(super) fn complete(&self) -> Result<()> {
        remove_durable(&self.response_stage)?;
        remove_durable(&self.request_stage)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnrollmentStage {
    schema: u8,
    pub(super) operation_id: Uuid,
    server_origin: String,
    pub(super) runner_name: String,
    pub(super) capabilities: automata_ci_core::RunnerCapabilities,
    pub(super) csr_pem: String,
    #[serde(
        deserialize_with = "deserialize_zeroizing",
        serialize_with = "serialize_zeroizing"
    )]
    pub(super) token: Zeroizing<String>,
    #[serde(
        deserialize_with = "deserialize_zeroizing",
        serialize_with = "serialize_zeroizing"
    )]
    pub(super) private_key_pem: Zeroizing<String>,
}

impl EnrollmentStage {
    fn validate_schema(&self) -> Result<()> {
        if self.schema != STAGE_SCHEMA {
            bail!("runner enrollment request stage has an unsupported schema");
        }
        Ok(())
    }

    fn new(
        config: &RunnerProductConfig,
        origin: &Url,
        runner_name: &str,
        token: Zeroizing<String>,
    ) -> Result<Self> {
        validate_token(token.as_str())?;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .context("runner enrollment could not generate the local private key")?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, config.runner_id().to_string());
        let mut parameters = CertificateParams::default();
        parameters.distinguished_name = distinguished_name;
        let csr_pem = parameters
            .serialize_request(&key)
            .context("runner enrollment could not create a certificate request")?
            .pem()
            .context("runner enrollment could not encode the certificate request")?;
        Ok(Self {
            schema: STAGE_SCHEMA,
            operation_id: Uuid::new_v4(),
            server_origin: origin.as_str().to_owned(),
            runner_name: runner_name.to_owned(),
            capabilities: config.inventory().clone(),
            csr_pem,
            token,
            private_key_pem: Zeroizing::new(key.serialize_pem()),
        })
    }

    fn validate(
        &self,
        config: &RunnerProductConfig,
        origin: &Url,
        runner_name: &str,
    ) -> Result<()> {
        self.validate_schema()?;
        if self.operation_id.is_nil()
            || self.server_origin != origin.as_str()
            || self.runner_name != runner_name
            || self.capabilities != *config.inventory()
        {
            bail!("runner enrollment request stage does not match this invocation");
        }
        validate_token(self.token.as_str())?;
        let key = KeyPair::from_pem(self.private_key_pem.as_str())
            .context("runner enrollment request stage has an invalid private key")?;
        let csr = CertificateSigningRequestParams::from_pem(&self.csr_pem)
            .context("runner enrollment request stage has an invalid certificate request")?;
        if csr.public_key.algorithm() != &PKCS_ECDSA_P256_SHA256
            || csr.public_key.der_bytes() != key.public_key_raw()
        {
            bail!("runner enrollment request stage key does not match its certificate request");
        }
        Ok(())
    }

    pub(super) fn validate_certificate(
        &self,
        config: &RunnerProductConfig,
        response: &RedeemResponse,
        validation_time_seconds: i64,
    ) -> Result<()> {
        validate_certificate_response(
            config.runner_id().as_uuid(),
            response,
            self.private_key_pem.as_str(),
            validation_time_seconds,
        )
    }
}

fn validate_certificate_response(
    expected_runner_id: Uuid,
    response: &RedeemResponse,
    private_key_pem: &str,
    validation_time_seconds: i64,
) -> Result<()> {
    let key = KeyPair::from_pem(private_key_pem)
        .context("runner enrollment response has an invalid private key")?;
    let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(
        response.certificate_chain_pem.as_bytes(),
    )
    .collect::<std::result::Result<Vec<_>, _>>()
    .context("runner enrollment response has an invalid certificate chain")?;
    let [leaf_der, issuer_der] = certificates.as_slice() else {
        bail!("runner enrollment response has an invalid certificate chain");
    };
    let (leaf_remainder, leaf) = parse_x509_certificate(leaf_der.as_ref())
        .context("runner enrollment response has an invalid leaf certificate")?;
    let (issuer_remainder, issuer) = parse_x509_certificate(issuer_der.as_ref())
        .context("runner enrollment response has an invalid issuing certificate")?;
    let leaf_constraints = leaf
        .basic_constraints()
        .context("runner enrollment response has invalid basic constraints")?;
    let leaf_usage = leaf
        .key_usage()
        .context("runner enrollment response has invalid key usage")?
        .context("runner enrollment response has no key usage")?;
    let leaf_extended_usage = leaf
        .extended_key_usage()
        .context("runner enrollment response has invalid extended key usage")?
        .context("runner enrollment response has no extended key usage")?;
    let issuer_constraints = issuer
        .basic_constraints()
        .context("runner enrollment response has invalid issuer constraints")?
        .context("runner enrollment response issuer has no basic constraints")?;
    let issuer_usage = issuer
        .key_usage()
        .context("runner enrollment response has invalid issuer key usage")?
        .context("runner enrollment response issuer has no key usage")?;
    let expected_common_name = expected_runner_id.hyphenated().to_string();
    let subject_attribute_count = leaf.subject().iter_attributes().count();
    let mut common_names = leaf.subject().iter_common_name();
    let common_name = common_names.next().and_then(|name| name.as_str().ok());
    let has_subject_alternative_name = leaf
        .subject_alternative_name()
        .context("runner enrollment response has an invalid subject alternative name")?
        .is_some();
    if response.runner_id != expected_runner_id
        || !leaf_remainder.is_empty()
        || !issuer_remainder.is_empty()
        || leaf_constraints.is_some_and(|constraints| constraints.value.ca)
        || leaf_usage.value.flags != 1
        || leaf_extended_usage.value.any
        || !leaf_extended_usage.value.client_auth
        || leaf_extended_usage.value.server_auth
        || leaf_extended_usage.value.code_signing
        || leaf_extended_usage.value.email_protection
        || leaf_extended_usage.value.time_stamping
        || leaf_extended_usage.value.ocsp_signing
        || !leaf_extended_usage.value.other.is_empty()
        || leaf.public_key().subject_public_key.data.as_ref() != key.public_key_raw()
        || leaf.issuer() != issuer.subject()
        || leaf.validity().not_before >= leaf.validity().not_after
        || leaf.validity().not_before.timestamp() > validation_time_seconds
        || leaf.validity().not_after.timestamp() <= validation_time_seconds
        || leaf.validity().not_before < issuer.validity().not_before
        || leaf.validity().not_after > issuer.validity().not_after
        || leaf.validity().not_after.timestamp() != response.certificate_expires_at_seconds
        || common_name != Some(expected_common_name.as_str())
        || subject_attribute_count != 1
        || common_names.next().is_some()
        || has_subject_alternative_name
        || !issuer_constraints.value.ca
        || !issuer_usage.value.key_cert_sign()
        || leaf.verify_signature(Some(issuer.public_key())).is_err()
    {
        bail!("runner enrollment response certificate does not match the staged request");
    }
    let mut server_roots = rustls::RootCertStore::empty();
    let mut server_root_count = 0_usize;
    for certificate in
        rustls::pki_types::CertificateDer::pem_slice_iter(response.server_ca_pem.as_bytes())
    {
        let certificate = certificate.context("runner enrollment response has invalid roots")?;
        let (remainder, root) = parse_x509_certificate(certificate.as_ref())
            .context("runner enrollment response has invalid roots")?;
        if !remainder.is_empty()
            || root.validity().not_before >= root.validity().not_after
            || root.validity().not_before.timestamp() > validation_time_seconds
            || root.validity().not_after.timestamp() <= validation_time_seconds
            || !root
                .basic_constraints()
                .context("runner enrollment response has invalid root constraints")?
                .is_some_and(|constraints| constraints.value.ca)
        {
            bail!("runner enrollment response has an unusable server root");
        }
        server_roots
            .add(certificate)
            .context("runner enrollment response has invalid roots")?;
        server_root_count += 1;
    }
    if server_root_count == 0 {
        bail!("runner enrollment response has no server roots");
    }
    Ok(())
}

fn serialize_zeroizing<S>(value: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.as_str())
}

fn deserialize_zeroizing<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

fn enrollment_sibling(path: &Path, suffix: &str) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("runner credential path has no parent")?;
    let mut filename = path
        .file_name()
        .context("runner credential path has no filename")?
        .to_os_string();
    filename.push(suffix);
    Ok(parent.join(filename))
}

fn temporary_name(name: &std::ffi::OsStr) -> std::ffi::OsString {
    let mut temporary = name.to_os_string();
    temporary.push(".automata-write");
    temporary
}

fn temporary_path(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("runner enrollment path has no parent")?;
    let name = path
        .file_name()
        .context("runner enrollment path has no filename")?;
    Ok(parent.join(temporary_name(name)))
}

fn validate_destination_set(paths: &[PathBuf]) -> Result<()> {
    for (index, path) in paths.iter().enumerate() {
        if !path.is_absolute() || paths[..index].contains(path) {
            bail!("runner enrollment credential and staging paths must be distinct absolute paths");
        }
    }

    #[cfg(unix)]
    {
        let mut prepared = Vec::with_capacity(paths.len());
        for path in paths {
            let destination = prepare_destination(path)?;
            for earlier in &prepared {
                if same_destination(earlier, &destination)? {
                    bail!(
                        "runner enrollment credential and staging paths resolve to the same destination"
                    );
                }
            }
            prepared.push(destination);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        bail!("durable runner enrollment is supported only on Unix hosts")
    }
}

#[cfg(unix)]
fn acquire_enrollment_lock(path: &Path) -> Result<rustix::fd::OwnedFd> {
    use rustix::fs::{FlockOperation, Mode, OFlags, flock, openat};

    let destination = prepare_destination(path)?;
    let lock = openat(
        &destination.parent,
        &destination.name,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .context("runner enrollment process lock could not be opened")?;
    let file = File::from(lock);
    validate_file_metadata(&file, true)?;
    let lock: rustix::fd::OwnedFd = file.into();
    flock(&lock, FlockOperation::NonBlockingLockExclusive)
        .context("another runner enrollment process is already using these destinations")?;
    Ok(lock)
}

#[cfg(unix)]
struct PreparedDestination {
    parent: rustix::fd::OwnedFd,
    name: std::ffi::OsString,
}

#[cfg(unix)]
fn same_destination(left: &PreparedDestination, right: &PreparedDestination) -> Result<bool> {
    let left_parent = rustix::fs::fstat(&left.parent)
        .context("runner enrollment directory could not be inspected")?;
    let right_parent = rustix::fs::fstat(&right.parent)
        .context("runner enrollment directory could not be inspected")?;
    Ok(left.name == right.name
        && left_parent.st_dev == right_parent.st_dev
        && left_parent.st_ino == right_parent.st_ino)
}

#[cfg(unix)]
fn prepare_destination(path: &Path) -> Result<PreparedDestination> {
    use std::path::Component;

    use rustix::fs::{Mode, OFlags, mkdirat, openat};

    if !path.is_absolute() {
        bail!("runner enrollment path must be absolute");
    }
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::Normal(value) => Some(Ok(value.to_os_string())),
            _ => Some(Err(())),
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|()| anyhow::anyhow!("runner enrollment path is invalid"))?;
    let (name, parents) = components
        .split_last()
        .context("runner enrollment path has no file name")?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut parent = rustix::fs::open("/", directory_flags, Mode::empty())
        .context("runner enrollment filesystem root could not be opened")?;
    require_trusted_directory(&parent)?;
    for component in parents {
        parent = match openat(&parent, component, directory_flags, Mode::empty()) {
            Ok(directory) => directory,
            Err(rustix::io::Errno::NOENT) => {
                mkdirat(&parent, component, Mode::from_raw_mode(0o700))
                    .context("runner enrollment directory could not be created")?;
                rustix::fs::fsync(&parent)
                    .context("runner enrollment directory could not be synchronized")?;
                openat(&parent, component, directory_flags, Mode::empty())
                    .context("runner enrollment directory could not be opened")?
            }
            Err(error) => {
                return Err(error).context("runner enrollment directory is unavailable");
            }
        };
        require_trusted_directory(&parent)?;
    }
    Ok(PreparedDestination {
        parent,
        name: name.clone(),
    })
}

#[cfg(unix)]
fn require_trusted_directory(directory: &rustix::fd::OwnedFd) -> Result<()> {
    use rustix::fs::{FileType, fstat};

    let metadata =
        fstat(directory).context("runner enrollment directory could not be inspected")?;
    let effective_user = rustix::process::geteuid().as_raw();
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || (!matches!(metadata.st_uid, 0) && metadata.st_uid != effective_user)
        || metadata.st_mode & 0o022 != 0
    {
        bail!("runner enrollment directory is not trusted");
    }
    Ok(())
}

#[cfg(unix)]
fn read_bounded_file(
    path: &Path,
    limit: usize,
    private: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    use rustix::fs::{Mode, OFlags, openat};

    let destination = prepare_destination(path)?;
    let descriptor = match openat(
        &destination.parent,
        &destination.name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(file) => file,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(error).context("runner enrollment state could not be opened");
        }
    };
    let mut file = File::from(descriptor);
    validate_file_metadata(&file, private)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit.min(8 * 1_024)));
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .context("runner enrollment state could not be read")?;
    if bytes.len() > limit {
        bail!("runner enrollment state exceeded its size limit");
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn read_bounded_temporary(
    path: &Path,
    limit: usize,
    private: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    use rustix::fs::{Mode, OFlags, openat};

    let destination = prepare_destination(path)?;
    let temporary = temporary_name(&destination.name);
    let descriptor = match openat(
        &destination.parent,
        &temporary,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(file) => file,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(error).context("runner enrollment staging write could not be opened");
        }
    };
    let mut file = File::from(descriptor);
    validate_file_metadata(&file, private)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit.min(8 * 1_024)));
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .context("runner enrollment staging write could not be read")?;
    file.sync_all()
        .context("runner enrollment staging write could not be synchronized")?;
    if bytes.len() > limit {
        bail!("runner enrollment staging write is oversized");
    }
    Ok(Some(bytes))
}

#[cfg(not(unix))]
fn read_bounded_file(
    _path: &Path,
    _limit: usize,
    _private: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    bail!("durable runner enrollment is supported only on Unix hosts")
}

#[cfg(not(unix))]
fn read_bounded_temporary(
    _path: &Path,
    _limit: usize,
    _private: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    bail!("durable runner enrollment is supported only on Unix hosts")
}

#[cfg(unix)]
fn validate_file_metadata(file: &File, private: bool) -> Result<()> {
    let metadata = file
        .metadata()
        .context("runner enrollment state metadata is unavailable")?;
    if !metadata.is_file() {
        bail!("runner enrollment state is not a regular file");
    }
    use std::os::unix::fs::MetadataExt as _;
    if metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || (private && metadata.mode() & 0o077 != 0)
        || (!private && metadata.mode() & 0o022 != 0)
    {
        bail!("runner enrollment state has unsafe ownership or permissions");
    }
    Ok(())
}

fn existing_file_matches(path: &Path, expected: &[u8], private: bool) -> Result<()> {
    let existing = read_bounded_file(path, expected.len(), private)?
        .context("runner credential destination is missing")?;
    if existing.as_slice() != expected {
        bail!("runner credential destination does not match staged enrollment");
    }
    Ok(())
}

fn persist_exact_file(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    if let Some(existing) = read_bounded_file(path, bytes.len(), private)? {
        if existing.as_slice() == bytes {
            return sync_parent(path);
        }
        bail!("runner credential destination does not match staged enrollment");
    }
    match persist_new(path, bytes, private) {
        Ok(()) => Ok(()),
        Err(error) => match existing_file_matches(path, bytes, private) {
            Ok(()) => sync_parent(path),
            Err(_) => Err(error),
        },
    }
}

#[cfg(unix)]
fn persist_new(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    use rustix::fs::{Mode, OFlags, fchmod, openat};

    if bytes.is_empty() {
        bail!("runner enrollment refused to persist an empty file");
    }
    let destination = prepare_destination(path)?;
    let temporary = temporary_name(&destination.name);
    let mode = Mode::from_raw_mode(if private { 0o600 } else { 0o644 });
    let staging = openat(
        &destination.parent,
        &temporary,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        mode,
    );
    match staging {
        Ok(staging) => {
            fchmod(&staging, mode).context("runner credential permissions could not be set")?;
            let mut file = File::from(staging);
            file.write_all(bytes)
                .context("runner credential could not be written")?;
            file.sync_all()
                .context("runner credential could not be synchronized")?;
        }
        Err(rustix::io::Errno::EXIST) => {
            let staged = read_bounded_temporary(path, bytes.len(), private)?
                .context("runner credential staging write disappeared")?;
            if staged.as_slice() != bytes {
                drop(staged);
                remove_temporary_durable(path)?;
                return persist_new(path, bytes, private);
            }
        }
        Err(error) => {
            return Err(error).context("temporary runner credential could not be created");
        }
    }
    match publish_temporary(path) {
        Ok(()) => Ok(()),
        Err(error) => {
            remove_temporary_durable(path)?;
            Err(error)
        }
    }
}

#[cfg(not(unix))]
fn persist_new(_path: &Path, _bytes: &[u8], _private: bool) -> Result<()> {
    bail!("durable runner enrollment is supported only on Unix hosts")
}

#[cfg(unix)]
fn publish_temporary(path: &Path) -> Result<()> {
    use rustix::fs::{RenameFlags, renameat_with};

    let destination = prepare_destination(path)?;
    let temporary = temporary_name(&destination.name);
    renameat_with(
        &destination.parent,
        &temporary,
        &destination.parent,
        &destination.name,
        RenameFlags::NOREPLACE,
    )
    .context("runner credential destination already exists or is unavailable")?;
    rustix::fs::fsync(&destination.parent)
        .context("runner credential directory could not be synchronized")
}

#[cfg(not(unix))]
fn publish_temporary(_path: &Path) -> Result<()> {
    bail!("durable runner enrollment is supported only on Unix hosts")
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<()> {
    let destination = prepare_destination(path)?;
    rustix::fs::fsync(&destination.parent)
        .context("runner enrollment directory could not be synchronized")
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<()> {
    bail!("durable runner enrollment is supported only on Unix hosts")
}

#[cfg(unix)]
fn remove_temporary_durable(path: &Path) -> Result<()> {
    use rustix::fs::{AtFlags, unlinkat};

    let destination = prepare_destination(path)?;
    let temporary = temporary_name(&destination.name);
    match unlinkat(&destination.parent, &temporary, AtFlags::empty()) {
        Ok(()) => rustix::fs::fsync(&destination.parent)
            .context("runner enrollment directory could not be synchronized"),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(error).context("runner enrollment staging write could not be removed"),
    }
}

#[cfg(not(unix))]
fn remove_temporary_durable(_path: &Path) -> Result<()> {
    bail!("durable runner enrollment is supported only on Unix hosts")
}

#[cfg(unix)]
fn remove_durable(path: &Path) -> Result<()> {
    use rustix::fs::{AtFlags, unlinkat};

    remove_temporary_durable(path)?;
    let destination = prepare_destination(path)?;
    match unlinkat(&destination.parent, &destination.name, AtFlags::empty()) {
        Ok(()) => rustix::fs::fsync(&destination.parent)
            .context("runner enrollment directory could not be synchronized"),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(error).context("runner enrollment state could not be removed"),
    }
}

#[cfg(not(unix))]
fn remove_durable(_path: &Path) -> Result<()> {
    bail!("durable runner enrollment is supported only on Unix hosts")
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[cfg(unix)]
    use std::fs::File;

    use automata_ci_core::{
        Architecture, OperatingSystem, RunnerCapabilities, RunnerId, RunnerPlatform,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
    };
    use uuid::Uuid;

    #[cfg(target_os = "linux")]
    use super::remove_durable;
    use super::{
        CredentialDestinations, EnrollmentStage, STAGE_SCHEMA, persist_exact_file,
        validate_certificate_response,
    };
    #[cfg(unix)]
    use super::{
        acquire_enrollment_lock, persist_new, prepare_destination, same_destination,
        temporary_path, validate_destination_set,
    };
    use crate::enrollment::RedeemResponse;
    #[cfg(target_os = "linux")]
    use crate::product::RunnerProductConfig;

    #[cfg(target_os = "linux")]
    fn product_config(root: &std::path::Path, runner_id: Uuid) -> RunnerProductConfig {
        let mut document: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../config/runner.local-1.example.json"))
                .expect("example runner configuration");
        document["runner_id"] = serde_json::json!(runner_id);
        for (field, filename) in [
            ("server_roots", "server-roots.pem"),
            ("certificate_chain", "runner-chain.pem"),
            ("private_key", "runner-key.pem"),
        ] {
            let path = root.join(filename);
            document["tls"][field]["path"] = serde_json::Value::String(
                path.to_str()
                    .expect("test credential path is UTF-8")
                    .to_owned(),
            );
        }
        RunnerProductConfig::from_json(
            &serde_json::to_vec(&document).expect("runner configuration JSON"),
        )
        .expect("runner product configuration")
    }

    #[test]
    fn partial_credential_publication_is_reconciled_exactly_without_overwrite() {
        let root = std::env::current_dir()
            .expect("current directory")
            .join(format!(".automata-enroll-test-{}", Uuid::new_v4()));
        fs::create_dir(&root).expect("test root");
        let destinations = CredentialDestinations {
            server_roots: root.join("server-roots.pem"),
            certificate_chain: root.join("runner-chain.pem"),
            private_key: root.join("runner-key.pem"),
            request_stage: root.join("runner-key.pem.request"),
            response_stage: root.join("runner-key.pem.response"),
            #[cfg(unix)]
            _lock: acquire_enrollment_lock(&root.join("runner-key.pem.lock"))
                .expect("enrollment lock"),
        };
        persist_exact_file(&destinations.server_roots, b"roots", false)
            .expect("simulated first publication");
        destinations
            .persist_exact(b"roots", b"chain", b"private-key")
            .expect("resume partial publication");
        destinations
            .persist_exact(b"roots", b"chain", b"private-key")
            .expect("exact replay");
        assert_eq!(fs::read(&destinations.server_roots).unwrap(), b"roots");
        assert_eq!(fs::read(&destinations.certificate_chain).unwrap(), b"chain");
        assert_eq!(fs::read(&destinations.private_key).unwrap(), b"private-key");

        let error = destinations
            .persist_exact(b"different", b"chain", b"private-key")
            .expect_err("different retry must not overwrite credentials");
        assert!(error.to_string().contains("does not match"));
        assert_eq!(fs::read(&destinations.server_roots).unwrap(), b"roots");
        fs::remove_dir_all(&root).expect("remove exact test root");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn completion_keeps_replay_authority_until_the_response_receipt_is_gone() {
        let root = std::env::current_dir()
            .expect("current directory")
            .join(format!(
                ".automata-enroll-completion-test-{}",
                Uuid::new_v4()
            ));
        fs::create_dir(&root).expect("test root");
        let config = product_config(&root, Uuid::new_v4());
        let destinations =
            CredentialDestinations::from_config(&config).expect("credential destinations");
        fs::write(&destinations.request_stage, b"request authority").expect("request stage");
        fs::write(&destinations.response_stage, b"response receipt").expect("response stage");

        remove_durable(&destinations.response_stage).expect("remove response first");
        assert!(
            destinations.request_stage.exists(),
            "a crash after response cleanup must retain database replay authority"
        );
        destinations.complete().expect("finish completion cleanup");
        assert!(!destinations.response_stage.exists());
        assert!(!destinations.request_stage.exists());
        fs::remove_dir_all(&root).expect("remove completion test root");
    }

    #[test]
    #[cfg(unix)]
    fn no_replace_publication_cleans_staging_and_preserves_an_existing_destination() {
        let root = std::env::current_dir()
            .expect("current directory")
            .join(format!(".automata-enroll-publish-test-{}", Uuid::new_v4()));
        fs::create_dir(&root).expect("test root");
        let destination = root.join("receipt.json");
        fs::write(&destination, b"existing").expect("existing destination");
        persist_new(&destination, b"replacement", true)
            .expect_err("publication must not replace an existing destination");
        assert_eq!(
            fs::read(&destination).expect("existing contents"),
            b"existing"
        );
        assert_eq!(
            fs::read_dir(&root).expect("test directory").count(),
            1,
            "failed publication must not retain secret-bearing staging files"
        );
        fs::remove_dir_all(&root).expect("remove publication test root");
    }

    #[test]
    #[cfg(unix)]
    fn complete_pre_rename_write_is_recovered_through_its_deterministic_name() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::current_dir()
            .expect("current directory")
            .join(format!(".automata-enroll-recovery-test-{}", Uuid::new_v4()));
        fs::create_dir(&root).expect("test root");
        let destination = root.join("receipt.json");
        let staging = root.join("receipt.json.automata-write");
        fs::write(&staging, b"recovered").expect("staging write");
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o600))
            .expect("staging permissions");
        File::open(&staging)
            .expect("staging file")
            .sync_all()
            .expect("staging sync");
        persist_new(&destination, b"recovered", true).expect("recover publication");
        assert_eq!(fs::read(&destination).expect("destination"), b"recovered");
        assert!(!staging.exists());
        fs::remove_dir_all(&root).expect("remove recovery test root");
    }

    #[test]
    #[cfg(unix)]
    fn prepared_destination_identity_detects_the_same_parent_inode_and_name() {
        let root = std::env::current_dir()
            .expect("current directory")
            .join(format!(".automata-enroll-alias-test-{}", Uuid::new_v4()));
        fs::create_dir(&root).expect("test root");
        let first = prepare_destination(&root.join("credential.pem")).expect("first destination");
        let alias = prepare_destination(&root.join("credential.pem")).expect("aliased destination");
        let distinct = prepare_destination(&root.join("other.pem")).expect("distinct destination");
        assert!(same_destination(&first, &alias).expect("compare aliases"));
        assert!(!same_destination(&first, &distinct).expect("compare destinations"));
        drop((first, alias, distinct));
        fs::remove_dir_all(&root).expect("remove alias test root");
    }

    #[test]
    #[cfg(unix)]
    fn configured_final_cannot_alias_an_internal_staging_destination() {
        let root = std::env::current_dir()
            .expect("current directory")
            .join(format!(
                ".automata-enroll-config-alias-test-{}",
                Uuid::new_v4()
            ));
        fs::create_dir(&root).expect("test root");
        let request = root.join("runner-key.pem.automata-enrollment-request");
        let configured_server_roots = temporary_path(&request).expect("request staging path");
        let final_paths = [
            configured_server_roots,
            root.join("runner-key.pem"),
            request,
        ];
        let mut paths = final_paths.to_vec();
        for path in &final_paths {
            paths.push(temporary_path(path).expect("internal staging path"));
        }
        validate_destination_set(&paths)
            .expect_err("a configured final must not alias internal staging");
        assert_eq!(fs::read_dir(&root).expect("test root entries").count(), 0);
        fs::remove_dir_all(&root).expect("remove config alias test root");
    }

    #[test]
    fn request_stage_round_trip_retains_the_operation_key_and_csr() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("runner key");
        let csr_pem = CertificateParams::default()
            .serialize_request(&key)
            .expect("CSR")
            .pem()
            .expect("CSR PEM");
        let operation_id = Uuid::new_v4();
        let private_key_pem = key.serialize_pem();
        let stage = EnrollmentStage {
            schema: STAGE_SCHEMA,
            operation_id,
            server_origin: "https://ci.example.test/".to_owned(),
            runner_name: "runner-one".to_owned(),
            capabilities: RunnerCapabilities::new(
                RunnerId::new(),
                RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
            ),
            csr_pem: csr_pem.clone(),
            token: zeroize::Zeroizing::new("atm_re_staged-secret".to_owned()),
            private_key_pem: zeroize::Zeroizing::new(private_key_pem.clone()),
        };
        let encoded = serde_json::to_vec(&stage).expect("stage JSON");
        let document: serde_json::Value = serde_json::from_slice(&encoded).expect("stage value");
        assert!(
            document
                .as_object()
                .expect("stage object")
                .contains_key("token")
        );
        let decoded: EnrollmentStage = serde_json::from_slice(&encoded).expect("staged request");
        assert_eq!(decoded.operation_id, operation_id);
        assert_eq!(decoded.csr_pem, csr_pem);
        assert_eq!(decoded.token.as_str(), "atm_re_staged-secret");
        assert_eq!(decoded.private_key_pem.as_str(), private_key_pem);
    }

    #[test]
    fn request_stage_reader_rejects_noncurrent_schema_versions() {
        let mut document = serde_json::json!({
            "schema": STAGE_SCHEMA,
            "operation_id": Uuid::new_v4(),
            "server_origin": "https://ci.example.test/",
            "runner_name": "runner-one",
            "capabilities": RunnerCapabilities::new(
                RunnerId::new(),
                RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
            ),
            "csr_pem": "unused by schema validation",
            "token": "unused by schema validation",
            "private_key_pem": "unused by schema validation",
        });
        document["schema"] = serde_json::json!(STAGE_SCHEMA + 1);
        let stage: EnrollmentStage = serde_json::from_value(document).expect("stage shape");
        stage
            .validate_schema()
            .expect_err("forward stage schema must be rejected");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one profile matrix shares an issuer, key, response, and mutation sequence"
    )]
    fn enrolled_leaf_must_match_the_staged_key_and_fixed_client_profile() {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("CA key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = CertifiedIssuer::self_signed(ca_params, ca_key).expect("CA");
        let runner_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("runner key");
        let expires_at = 1_900_000_000;
        let runner_id = Uuid::new_v4();
        let issue_leaf =
            |extra_subject: bool, subject_alternative_name: bool, extra_key_usage: bool| {
                let mut leaf_params = CertificateParams::default();
                leaf_params
                    .distinguished_name
                    .push(DnType::CommonName, runner_id.to_string());
                if extra_subject {
                    leaf_params
                        .distinguished_name
                        .push(DnType::OrganizationName, "unexpected subject");
                }
                if subject_alternative_name {
                    leaf_params.subject_alt_names.push(SanType::DnsName(
                        "runner.example.test".try_into().expect("DNS name"),
                    ));
                }
                leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
                if extra_key_usage {
                    leaf_params
                        .key_usages
                        .push(KeyUsagePurpose::ContentCommitment);
                }
                leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
                leaf_params.not_after =
                    time::OffsetDateTime::from_unix_timestamp(expires_at).expect("expiry");
                leaf_params
                    .signed_by(&runner_key, &issuer)
                    .expect("runner leaf")
            };
        let mut response = RedeemResponse {
            runner_id,
            runner_group: "default".to_owned(),
            control_endpoint: "https://runner.example.test/".to_owned(),
            certificate_chain_pem: format!(
                "{}{}",
                issue_leaf(false, false, false).pem(),
                issuer.pem()
            ),
            server_ca_pem: issuer.pem(),
            certificate_expires_at_seconds: expires_at,
        };
        validate_certificate_response(
            runner_id,
            &response,
            &runner_key.serialize_pem(),
            expires_at - 1,
        )
        .expect("matching fixed-profile leaf");
        let wrong_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("wrong key");
        validate_certificate_response(
            runner_id,
            &response,
            &wrong_key.serialize_pem(),
            expires_at - 1,
        )
        .expect_err("different key must be rejected");

        validate_certificate_response(
            runner_id,
            &response,
            &runner_key.serialize_pem(),
            expires_at,
        )
        .expect_err("an expired persisted response must not install credentials");

        response.certificate_chain_pem =
            format!("{}{}", issue_leaf(true, false, false).pem(), issuer.pem());
        validate_certificate_response(
            runner_id,
            &response,
            &runner_key.serialize_pem(),
            expires_at - 1,
        )
        .expect_err("an extra subject attribute must be rejected");

        response.certificate_chain_pem =
            format!("{}{}", issue_leaf(false, true, false).pem(), issuer.pem());
        validate_certificate_response(
            runner_id,
            &response,
            &runner_key.serialize_pem(),
            expires_at - 1,
        )
        .expect_err("a subject alternative name must be rejected");

        response.certificate_chain_pem =
            format!("{}{}", issue_leaf(false, false, false).pem(), issuer.pem());
        response.server_ca_pem = "not a PEM certificate".to_owned();
        validate_certificate_response(
            runner_id,
            &response,
            &runner_key.serialize_pem(),
            expires_at - 1,
        )
        .expect_err("malformed server roots must be rejected");

        response.server_ca_pem = issuer.pem();
        response.certificate_chain_pem =
            format!("{}{}", issue_leaf(false, false, true).pem(), issuer.pem());
        validate_certificate_response(
            runner_id,
            &response,
            &runner_key.serialize_pem(),
            expires_at - 1,
        )
        .expect_err("an extra key usage must be rejected");
    }
}
