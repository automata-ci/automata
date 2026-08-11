use std::{
    path::{Component, Path, PathBuf},
    str::FromStr as _,
};

#[cfg(unix)]
use std::io::Read as _;

use automata_ci_core::{
    RunnerCapabilities, RunnerFeature, RunnerGroup, RunnerId, RunnerLabel, Sha256Digest, UnixMillis,
};
use automata_ci_store::{
    MAX_STATIC_RUNNERS, RunnerCapabilityReadiness, RunnerSlotCount, StaticRunnerFleet,
    StaticRunnerRegistration, TenantScope,
};
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use x509_parser::prelude::parse_x509_certificate;

const STATIC_REGISTRATION_SCHEMA_VERSION: u16 = 1;
const MAX_STATIC_REGISTRATION_BYTES: usize = 1024 * 1024;
const MAX_CLIENT_CERTIFICATE_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticRegistrationDocument {
    schema_version: u16,
    tenant: String,
    group: String,
    runners: Vec<StaticRegistrationEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticRegistrationEntry {
    id: String,
    name: String,
    external_identity: String,
    labels: Vec<String>,
    capabilities: Value,
    slots: u16,
    active_client_certificates: Vec<StaticClientCertificateEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticClientCertificateEntry {
    source: String,
    expires_at_seconds: i64,
}

/// Loads and validates a privileged declarative static-runner document.
///
/// Both the document and every referenced certificate must be absolute,
/// root-owned, non-writable, single-linked regular files. Every ancestor must
/// be root-owned and not group- or world-writable, and is traversed relative to
/// an already-open directory with symlinks disabled.
///
/// # Errors
///
/// Returns a sanitized error for insecure files, excessive input, malformed
/// JSON or certificates, expired certificates, or incoherent routing facts.
pub(crate) fn load_static_runner_fleet(
    path: &Path,
    now_seconds: i64,
    readiness: RunnerCapabilityReadiness,
) -> Result<StaticRunnerFleet, StaticRunnerRegistrationError> {
    if !path.is_absolute() {
        return Err(StaticRunnerRegistrationError::RelativePath);
    }
    let document = read_privileged_file(path, MAX_STATIC_REGISTRATION_BYTES)?;
    parse_document_with_readiness(&document, now_seconds, readiness, |certificate_path| {
        read_privileged_file(certificate_path, MAX_CLIENT_CERTIFICATE_BYTES)
    })
}

#[cfg(test)]
fn parse_document<F>(
    bytes: &[u8],
    now_seconds: i64,
    load_certificate: F,
) -> Result<StaticRunnerFleet, StaticRunnerRegistrationError>
where
    F: FnMut(&Path) -> Result<Vec<u8>, StaticRunnerRegistrationError>,
{
    parse_document_with_readiness(
        bytes,
        now_seconds,
        RunnerCapabilityReadiness::unavailable(),
        load_certificate,
    )
}

fn parse_document_with_readiness<F>(
    bytes: &[u8],
    now_seconds: i64,
    readiness: RunnerCapabilityReadiness,
    mut load_certificate: F,
) -> Result<StaticRunnerFleet, StaticRunnerRegistrationError>
where
    F: FnMut(&Path) -> Result<Vec<u8>, StaticRunnerRegistrationError>,
{
    let applied_at = UnixMillis::new(now_millis(now_seconds)?);
    let document: StaticRegistrationDocument = serde_json::from_slice(bytes)
        .map_err(|_| StaticRunnerRegistrationError::InvalidDocument)?;
    if document.schema_version != STATIC_REGISTRATION_SCHEMA_VERSION {
        return Err(StaticRunnerRegistrationError::UnsupportedSchema);
    }
    if document.runners.is_empty() || document.runners.len() > MAX_STATIC_RUNNERS {
        return Err(StaticRunnerRegistrationError::InvalidFleet);
    }
    let tenant = TenantScope::from_authenticated_tenant_id(document.tenant)
        .map_err(|_| StaticRunnerRegistrationError::InvalidFleet)?;
    let group = canonical_group(&document.group)?;
    let mut runners = Vec::with_capacity(document.runners.len());
    for entry in document.runners {
        let runner_id = canonical_runner_id(&entry.id)?;
        let capabilities = canonical_capabilities(&entry.capabilities, readiness)?;
        let labels = entry
            .labels
            .into_iter()
            .map(|value| canonical_label(&value))
            .collect::<Result<Vec<_>, _>>()?;
        let slots = RunnerSlotCount::new(entry.slots)
            .map_err(|_| StaticRunnerRegistrationError::InvalidFleet)?;
        if entry.active_client_certificates.is_empty()
            || entry.active_client_certificates.len()
                > StaticRunnerRegistration::MAX_ACTIVE_CERTIFICATES
        {
            return Err(StaticRunnerRegistrationError::InvalidFleet);
        }
        let mut active_certificates = Vec::with_capacity(entry.active_client_certificates.len());
        for configured_certificate in entry.active_client_certificates {
            let certificate_path = certificate_path(&configured_certificate.source)?;
            let certificate_pem = load_certificate(&certificate_path)?;
            let certificate = parse_leaf_certificate(
                &certificate_pem,
                configured_certificate.expires_at_seconds,
                now_seconds,
            )?;
            let certificate_sha256 =
                Sha256Digest::from_bytes(Sha256::digest(certificate.as_ref()).into());
            active_certificates.push((
                certificate_sha256,
                configured_certificate.expires_at_seconds,
            ));
        }
        runners.push(
            StaticRunnerRegistration::try_new(
                runner_id,
                entry.name,
                entry.external_identity,
                labels,
                capabilities,
                slots,
                active_certificates,
            )
            .map_err(|_| StaticRunnerRegistrationError::InvalidFleet)?,
        );
    }
    StaticRunnerFleet::try_new(tenant, group, runners, applied_at)
        .map_err(|_| StaticRunnerRegistrationError::InvalidFleet)
}

fn canonical_runner_id(value: &str) -> Result<RunnerId, StaticRunnerRegistrationError> {
    let runner_id =
        RunnerId::from_str(value).map_err(|_| StaticRunnerRegistrationError::InvalidFleet)?;
    if runner_id.to_string() != value {
        return Err(StaticRunnerRegistrationError::InvalidFleet);
    }
    Ok(runner_id)
}

fn canonical_group(value: &str) -> Result<RunnerGroup, StaticRunnerRegistrationError> {
    let group = RunnerGroup::new(value).map_err(|_| StaticRunnerRegistrationError::InvalidFleet)?;
    if group.as_str() != value {
        return Err(StaticRunnerRegistrationError::InvalidFleet);
    }
    Ok(group)
}

fn canonical_label(value: &str) -> Result<RunnerLabel, StaticRunnerRegistrationError> {
    let label = RunnerLabel::new(value).map_err(|_| StaticRunnerRegistrationError::InvalidFleet)?;
    if label.as_str() != value {
        return Err(StaticRunnerRegistrationError::InvalidFleet);
    }
    Ok(label)
}

fn canonical_capabilities(
    value: &Value,
    readiness: RunnerCapabilityReadiness,
) -> Result<RunnerCapabilities, StaticRunnerRegistrationError> {
    validate_capability_keys(value)?;
    let capabilities: RunnerCapabilities = serde_json::from_value(value.clone())
        .map_err(|_| StaticRunnerRegistrationError::InvalidCapabilities)?;
    let canonical = serde_json::to_value(&capabilities)
        .map_err(|_| StaticRunnerRegistrationError::InvalidCapabilities)?;
    if &canonical != value {
        return Err(StaticRunnerRegistrationError::InvalidCapabilities);
    }
    if capabilities
        .features()
        .contains(&RunnerFeature::OIDC_TOKENS)
        && !readiness.github_oidc()
    {
        return Err(StaticRunnerRegistrationError::InvalidCapabilities);
    }
    Ok(capabilities)
}

fn validate_capability_keys(value: &Value) -> Result<(), StaticRunnerRegistrationError> {
    const KEYS: &[&str] = &[
        "schema_version",
        "runner_id",
        "platform",
        "labels",
        "groups",
        "max_parallel_jobs",
        "resources_per_job",
        "sandbox",
        "containers",
        "features",
        "environment_profiles",
    ];
    let object = value
        .as_object()
        .ok_or(StaticRunnerRegistrationError::InvalidCapabilities)?;
    if object.keys().any(|key| !KEYS.contains(&key.as_str())) {
        return Err(StaticRunnerRegistrationError::InvalidCapabilities);
    }
    Ok(())
}

fn certificate_path(source: &str) -> Result<PathBuf, StaticRunnerRegistrationError> {
    let path = source
        .strip_prefix("file:")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(StaticRunnerRegistrationError::InvalidCertificateSource)?;
    if !clean_absolute_file_path(&path) {
        return Err(StaticRunnerRegistrationError::InvalidCertificateSource);
    }
    Ok(path)
}

fn clean_absolute_file_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .any(|component| matches!(component, Component::Normal(_)))
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn parse_leaf_certificate(
    pem: &[u8],
    configured_expiry: i64,
    now_seconds: i64,
) -> Result<CertificateDer<'static>, StaticRunnerRegistrationError> {
    if count_pem_sections(pem)? != 1 || !certificate_pem_consumes_file(pem) {
        return Err(StaticRunnerRegistrationError::InvalidCertificate);
    }
    let mut certificates = CertificateDer::pem_slice_iter(pem);
    let certificate = certificates
        .next()
        .ok_or(StaticRunnerRegistrationError::InvalidCertificate)?
        .map_err(|_| StaticRunnerRegistrationError::InvalidCertificate)?;
    if certificates.next().is_some() || certificate.is_empty() {
        return Err(StaticRunnerRegistrationError::InvalidCertificate);
    }
    let (remainder, parsed) = parse_x509_certificate(certificate.as_ref())
        .map_err(|_| StaticRunnerRegistrationError::InvalidCertificate)?;
    if !remainder.is_empty()
        || parsed.tbs_certificate.extensions_map().is_err()
        || parsed
            .basic_constraints()
            .map_err(|_| StaticRunnerRegistrationError::InvalidCertificate)?
            .is_some_and(|constraints| constraints.value.ca)
        || parsed
            .key_usage()
            .map_err(|_| StaticRunnerRegistrationError::InvalidCertificate)?
            .is_some_and(|usage| usage.value.key_cert_sign() || usage.value.crl_sign())
    {
        return Err(StaticRunnerRegistrationError::InvalidCertificate);
    }
    let validity = parsed.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    if configured_expiry != not_after
        || configured_expiry <= now_seconds
        || not_before > now_seconds
    {
        return Err(StaticRunnerRegistrationError::CertificateValidity);
    }
    let usage = parsed
        .extended_key_usage()
        .map_err(|_| StaticRunnerRegistrationError::InvalidCertificate)?
        .ok_or(StaticRunnerRegistrationError::InvalidCertificate)?
        .value;
    if !usage.client_auth
        || usage.any
        || usage.server_auth
        || usage.code_signing
        || usage.email_protection
        || usage.time_stamping
        || usage.ocsp_signing
        || !usage.other.is_empty()
    {
        return Err(StaticRunnerRegistrationError::InvalidCertificate);
    }
    Ok(certificate)
}

fn count_pem_sections(pem: &[u8]) -> Result<usize, StaticRunnerRegistrationError> {
    let mut begin_count = 0_usize;
    let mut end_count = 0_usize;
    for line in pem.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.starts_with(b"-----BEGIN ") {
            begin_count = begin_count.saturating_add(1);
            if line != b"-----BEGIN CERTIFICATE-----" {
                return Err(StaticRunnerRegistrationError::InvalidCertificate);
            }
        }
        if line.starts_with(b"-----END ") {
            end_count = end_count.saturating_add(1);
            if line != b"-----END CERTIFICATE-----" {
                return Err(StaticRunnerRegistrationError::InvalidCertificate);
            }
        }
    }
    if begin_count != end_count {
        return Err(StaticRunnerRegistrationError::InvalidCertificate);
    }
    Ok(begin_count)
}

fn certificate_pem_consumes_file(pem: &[u8]) -> bool {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";

    let Some(begin_at) = pem.windows(BEGIN.len()).position(|window| window == BEGIN) else {
        return false;
    };
    let Some(end_at) = pem.windows(END.len()).position(|window| window == END) else {
        return false;
    };
    begin_at < end_at
        && pem[..begin_at].iter().all(u8::is_ascii_whitespace)
        && pem[end_at.saturating_add(END.len())..]
            .iter()
            .all(u8::is_ascii_whitespace)
}

fn now_millis(now_seconds: i64) -> Result<i64, StaticRunnerRegistrationError> {
    if now_seconds < 0 {
        return Err(StaticRunnerRegistrationError::InvalidClock);
    }
    now_seconds
        .checked_mul(1_000)
        .ok_or(StaticRunnerRegistrationError::InvalidClock)
}

#[cfg(unix)]
fn read_privileged_file(
    path: &Path,
    maximum_bytes: usize,
) -> Result<Vec<u8>, StaticRunnerRegistrationError> {
    read_bounded_nofollow(path, maximum_bytes, 0)
}

#[cfg(unix)]
fn read_bounded_nofollow(
    path: &Path,
    maximum_bytes: usize,
    required_owner: u32,
) -> Result<Vec<u8>, StaticRunnerRegistrationError> {
    use std::{ffi::OsString, fs::File};

    use rustix::{
        fd::OwnedFd,
        fs::{FileType, Mode, OFlags, fstat, openat},
    };

    if !path.is_absolute() {
        return Err(StaticRunnerRegistrationError::RelativePath);
    }
    let mut components = Vec::<OsString>::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => components.push(value.to_os_string()),
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(StaticRunnerRegistrationError::InsecureFile);
            }
        }
    }
    let (file_name, parents) = components
        .split_last()
        .ok_or(StaticRunnerRegistrationError::InsecureFile)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut directory: OwnedFd = rustix::fs::open("/", directory_flags, Mode::empty())
        .map_err(|_| StaticRunnerRegistrationError::UnreadableFile)?;
    validate_privileged_directory(&directory, required_owner)?;
    for component in parents {
        directory = openat(&directory, component, directory_flags, Mode::empty())
            .map_err(map_path_open_error)?;
        validate_privileged_directory(&directory, required_owner)?;
    }
    let file = openat(
        &directory,
        file_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(map_path_open_error)?;
    let metadata = fstat(&file).map_err(|_| StaticRunnerRegistrationError::UnreadableFile)?;
    if !privileged_file_attributes(
        FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile,
        metadata.st_uid,
        metadata.st_mode,
        metadata.st_nlink,
        required_owner,
    ) {
        return Err(StaticRunnerRegistrationError::InsecureFile);
    }
    let received = u64::try_from(metadata.st_size).unwrap_or(u64::MAX);
    if received > u64::try_from(maximum_bytes).unwrap_or(u64::MAX) {
        return Err(StaticRunnerRegistrationError::FileTooLarge);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(received)
            .unwrap_or(maximum_bytes)
            .min(maximum_bytes),
    );
    File::from(file)
        .take(
            u64::try_from(maximum_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|_| StaticRunnerRegistrationError::UnreadableFile)?;
    if bytes.len() > maximum_bytes {
        return Err(StaticRunnerRegistrationError::FileTooLarge);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn validate_privileged_directory(
    directory: &rustix::fd::OwnedFd,
    required_owner: u32,
) -> Result<(), StaticRunnerRegistrationError> {
    use rustix::fs::{FileType, fstat};

    let metadata = fstat(directory).map_err(|_| StaticRunnerRegistrationError::UnreadableFile)?;
    if privileged_directory_attributes(
        FileType::from_raw_mode(metadata.st_mode) == FileType::Directory,
        metadata.st_uid,
        metadata.st_mode,
        required_owner,
    ) {
        Ok(())
    } else {
        Err(StaticRunnerRegistrationError::InsecureFile)
    }
}

#[cfg(unix)]
fn map_path_open_error(error: rustix::io::Errno) -> StaticRunnerRegistrationError {
    if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR {
        StaticRunnerRegistrationError::InsecureFile
    } else {
        StaticRunnerRegistrationError::UnreadableFile
    }
}

#[cfg(unix)]
const fn privileged_file_attributes(
    is_regular_file: bool,
    owner: u32,
    mode: u32,
    link_count: u64,
    required_owner: u32,
) -> bool {
    is_regular_file && owner == required_owner && mode & 0o222 == 0 && link_count == 1
}

#[cfg(unix)]
const fn privileged_directory_attributes(
    is_directory: bool,
    owner: u32,
    mode: u32,
    required_owner: u32,
) -> bool {
    is_directory && (owner == 0 || owner == required_owner) && mode & 0o022 == 0
}

#[cfg(not(unix))]
fn read_privileged_file(
    _path: &Path,
    _maximum_bytes: usize,
) -> Result<Vec<u8>, StaticRunnerRegistrationError> {
    Err(StaticRunnerRegistrationError::UnsupportedPlatform)
}

/// Sanitized declarative static-runner configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum StaticRunnerRegistrationError {
    #[error("static runner registration path must be absolute")]
    RelativePath,
    #[error("static runner registration file could not be read")]
    UnreadableFile,
    #[error(
        "static runner registration paths must have trusted non-writable ancestors and root-owned, non-writable, single-linked regular files reached without symlinks"
    )]
    InsecureFile,
    #[error("static runner registration file exceeds its byte limit")]
    FileTooLarge,
    #[error("static runner registration document is invalid")]
    InvalidDocument,
    #[error("static runner registration schema is unsupported")]
    UnsupportedSchema,
    #[error("static runner registration fleet is invalid")]
    InvalidFleet,
    #[error("static runner capability document is invalid")]
    InvalidCapabilities,
    #[error("static runner client certificate must use an absolute file: reference")]
    InvalidCertificateSource,
    #[error("static runner client certificate is invalid or is not a client-auth-only leaf")]
    InvalidCertificate,
    #[error("static runner certificate expiry is inconsistent or not currently valid")]
    CertificateValidity,
    #[error("system time cannot be represented for static runner registration")]
    InvalidClock,
    #[cfg(not(unix))]
    #[error("secure static runner registration files are not supported on this platform")]
    UnsupportedPlatform,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, date_time_ymd,
    };
    use serde_json::json;
    use x509_parser::prelude::parse_x509_certificate;

    use super::*;
    use automata_ci_core::{Architecture, OperatingSystem, RunnerPlatform};

    const NOW: i64 = 1_800_000_000;

    struct TestCertificate {
        pem: Vec<u8>,
        der: Vec<u8>,
        expiry: i64,
    }

    fn certificate(
        common_name: &str,
        is_ca: IsCa,
        extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
        key_usages: Vec<KeyUsagePurpose>,
    ) -> TestCertificate {
        let issuer_key = KeyPair::generate().expect("CA key");
        let mut issuer_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        issuer_params
            .distinguished_name
            .push(DnType::CommonName, "bootstrap test root");
        issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        issuer_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let issuer = CertifiedIssuer::self_signed(issuer_params, issuer_key).expect("test issuer");
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = is_ca;
        params.extended_key_usages = extended_key_usages;
        params.key_usages = key_usages;
        params.not_before = date_time_ymd(2025, 1, 1);
        params.not_after = date_time_ymd(2030, 1, 1);
        let certificate = params.signed_by(&key, &issuer).expect("leaf certificate");
        let der = certificate.der().as_ref().to_vec();
        let (_, parsed) = parse_x509_certificate(&der).expect("generated X.509");
        let expiry = parsed.validity().not_after.timestamp();
        let encoded = STANDARD.encode(&der);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n")
            .into_bytes();
        TestCertificate { pem, der, expiry }
    }

    fn client_certificate(common_name: &str) -> TestCertificate {
        certificate(
            common_name,
            IsCa::NoCa,
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            vec![KeyUsagePurpose::DigitalSignature],
        )
    }

    fn valid_document(id: RunnerId, expiry: i64) -> Vec<u8> {
        let label = RunnerLabel::new("linux").expect("label");
        let group = RunnerGroup::new("g1").expect("group");
        let capabilities = RunnerCapabilities::new(
            id,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        )
        .with_labels([label])
        .with_groups([group])
        .with_max_parallel_jobs(2)
        .expect("slots");
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "tenant": "automata-ci",
            "group": "g1",
            "runners": [{
                "id": id.to_string(),
                "name": "runner-a",
                "external_identity": "spiffe://automata/runner-a",
                "labels": ["linux"],
                "capabilities": capabilities,
                "slots": 2,
                "active_client_certificates": [{
                    "source": "file:/run/automata/client.pem",
                    "expires_at_seconds": expiry
                }]
            }]
        }))
        .expect("document")
    }

    #[test]
    fn document_derives_der_digest_and_exact_routing_facts() {
        let id = RunnerId::new();
        let certificate = client_certificate("runner-a");
        let expected = Sha256Digest::from_bytes(Sha256::digest(certificate.der.as_slice()).into());
        let fleet = parse_document(&valid_document(id, certificate.expiry), NOW, |_| {
            Ok(certificate.pem.clone())
        })
        .expect("valid static fleet");
        assert_eq!(fleet.tenant().as_str(), "automata-ci");
        assert_eq!(fleet.group().as_str(), "g1");
        assert_eq!(
            fleet.runners()[0].active_certificates(),
            &[(expected, certificate.expiry)]
        );
    }

    #[test]
    fn document_accepts_two_distinct_rotation_leaves_only() {
        let id = RunnerId::new();
        let first = client_certificate("runner-a");
        let second = client_certificate("runner-a-next");
        let mut document: Value =
            serde_json::from_slice(&valid_document(id, first.expiry)).expect("JSON");
        document["runners"][0]["active_client_certificates"] = json!([
            {
                "source": "file:/run/automata/client.pem",
                "expires_at_seconds": first.expiry
            },
            {
                "source": "file:/run/automata/client-next.pem",
                "expires_at_seconds": second.expiry
            }
        ]);
        let fleet =
            parse_document(
                &serde_json::to_vec(&document).expect("JSON"),
                NOW,
                |path| match path.to_str() {
                    Some("/run/automata/client.pem") => Ok(first.pem.clone()),
                    Some("/run/automata/client-next.pem") => Ok(second.pem.clone()),
                    _ => Err(StaticRunnerRegistrationError::UnreadableFile),
                },
            )
            .expect("overlap fleet");
        assert_eq!(fleet.runners()[0].active_certificates().len(), 2);

        document["runners"][0]["active_client_certificates"] = json!([
            { "source": "file:/one.pem", "expires_at_seconds": first.expiry },
            { "source": "file:/two.pem", "expires_at_seconds": first.expiry },
            { "source": "file:/three.pem", "expires_at_seconds": first.expiry }
        ]);
        assert_eq!(
            parse_document(
                &serde_json::to_vec(&document).expect("JSON"),
                NOW,
                |_| panic!("excessive certificate sets must fail before file access"),
            )
            .expect_err("three leaves must fail"),
            StaticRunnerRegistrationError::InvalidFleet
        );
    }

    #[test]
    fn document_enforces_schema_fleet_and_certificate_bounds_before_file_access() {
        let id = RunnerId::new();
        let certificate = client_certificate("runner-a");
        let mut document: Value =
            serde_json::from_slice(&valid_document(id, certificate.expiry)).expect("JSON");
        document["schema_version"] = json!(2);
        assert_eq!(
            parse_document(
                &serde_json::to_vec(&document).expect("JSON"),
                NOW,
                |_| panic!("unsupported schema fails before file access"),
            )
            .expect_err("unsupported schema"),
            StaticRunnerRegistrationError::UnsupportedSchema
        );

        document["schema_version"] = json!(1);
        let runner = document["runners"][0].clone();
        document["runners"] = json!([]);
        assert_eq!(
            parse_document(
                &serde_json::to_vec(&document).expect("JSON"),
                NOW,
                |_| panic!("empty fleet fails before file access"),
            )
            .expect_err("empty fleet"),
            StaticRunnerRegistrationError::InvalidFleet
        );

        document["runners"] = Value::Array(vec![runner.clone(); MAX_STATIC_RUNNERS + 1]);
        assert_eq!(
            parse_document(
                &serde_json::to_vec(&document).expect("JSON"),
                NOW,
                |_| panic!("oversized fleet fails before file access"),
            )
            .expect_err("oversized fleet"),
            StaticRunnerRegistrationError::InvalidFleet
        );

        document["runners"] = Value::Array(vec![runner]);
        document["runners"][0]["active_client_certificates"] = json!([]);
        assert_eq!(
            parse_document(
                &serde_json::to_vec(&document).expect("JSON"),
                NOW,
                |_| panic!("empty certificate set fails before file access"),
            )
            .expect_err("empty certificate set"),
            StaticRunnerRegistrationError::InvalidFleet
        );
    }

    #[test]
    fn document_rejects_unknown_fields_and_noncanonical_domain_values() {
        let id = RunnerId::new();
        let certificate = client_certificate("runner-a");
        let mut document: Value =
            serde_json::from_slice(&valid_document(id, certificate.expiry)).expect("JSON");
        document["unreviewed_authority"] = json!(true);
        assert_eq!(
            parse_document(
                &serde_json::to_vec(&document).expect("JSON"),
                NOW,
                |_| panic!("unknown fields fail before file access"),
            )
            .expect_err("unknown field"),
            StaticRunnerRegistrationError::InvalidDocument
        );

        document
            .as_object_mut()
            .expect("document object")
            .remove("unreviewed_authority");
        document["runners"][0]["active_client_certificates"][0]["unreviewed_authority"] =
            json!(true);
        assert_eq!(
            parse_document(
                &serde_json::to_vec(&document).expect("JSON"),
                NOW,
                |_| panic!("unknown certificate fields fail before file access"),
            )
            .expect_err("unknown certificate field"),
            StaticRunnerRegistrationError::InvalidDocument
        );

        document["runners"][0]["active_client_certificates"][0]
            .as_object_mut()
            .expect("certificate object")
            .remove("unreviewed_authority");
        document["group"] = json!("G1");
        assert_eq!(
            parse_document(
                &serde_json::to_vec(&document).expect("JSON"),
                NOW,
                |_| panic!("noncanonical group fails before file access"),
            )
            .expect_err("uppercase group"),
            StaticRunnerRegistrationError::InvalidFleet
        );

        document["group"] = json!("g1");
        document["runners"][0]["id"] = json!(id.to_string().to_uppercase());
        assert_eq!(
            parse_document(
                &serde_json::to_vec(&document).expect("JSON"),
                NOW,
                |_| panic!("noncanonical ID fails before file access"),
            )
            .expect_err("uppercase ID"),
            StaticRunnerRegistrationError::InvalidFleet
        );
    }

    #[test]
    fn document_rejects_noncanonical_or_unknown_capability_authority() {
        let id = RunnerId::new();
        let certificate = client_certificate("runner-a");
        let mut document: Value =
            serde_json::from_slice(&valid_document(id, certificate.expiry)).expect("JSON");
        document["runners"][0]["capabilities"]["platform"]["unreviewed_route"] = json!(true);
        assert_eq!(
            parse_document(&serde_json::to_vec(&document).expect("JSON"), NOW, |_| Ok(
                certificate.pem.clone()
            ),)
            .expect_err("nested authority"),
            StaticRunnerRegistrationError::InvalidCapabilities
        );

        let mut document: Value =
            serde_json::from_slice(&valid_document(id, certificate.expiry)).expect("JSON");
        document["runners"][0]["capabilities"]["labels"] = json!(["LINUX"]);
        assert_eq!(
            parse_document(&serde_json::to_vec(&document).expect("JSON"), NOW, |_| Ok(
                certificate.pem.clone()
            ),)
            .expect_err("noncanonical capability selector"),
            StaticRunnerRegistrationError::InvalidCapabilities
        );
    }

    #[test]
    fn document_gates_oidc_capability_on_server_operational_readiness() {
        let id = RunnerId::new();
        let certificate = client_certificate("runner-a");
        let mut document: Value =
            serde_json::from_slice(&valid_document(id, certificate.expiry)).expect("JSON");
        let capabilities: RunnerCapabilities =
            serde_json::from_value(document["runners"][0]["capabilities"].clone())
                .expect("canonical fixture capabilities");
        document["runners"][0]["capabilities"] = serde_json::to_value(
            capabilities
                .clone()
                .with_features([RunnerFeature::SHELL_STEPS]),
        )
        .expect("canonical non-OIDC inventory");
        let admitted = parse_document(&serde_json::to_vec(&document).expect("JSON"), NOW, |_| {
            Ok(certificate.pem.clone())
        })
        .expect("an unrelated canonical feature must remain admitted");
        assert!(
            admitted.runners()[0]
                .capabilities()
                .features()
                .contains(&RunnerFeature::SHELL_STEPS)
        );

        document["runners"][0]["capabilities"] = serde_json::to_value(
            capabilities.with_features([RunnerFeature::SHELL_STEPS, RunnerFeature::OIDC_TOKENS]),
        )
        .expect("canonical OIDC-capable inventory");

        assert_eq!(
            parse_document(
                &serde_json::to_vec(&document).expect("JSON"),
                NOW,
                |_| panic!("OIDC capability admission must fail before certificate access"),
            )
            .expect_err("OIDC-capable static fleet must stay dark"),
            StaticRunnerRegistrationError::InvalidCapabilities
        );

        let admitted = parse_document_with_readiness(
            &serde_json::to_vec(&document).expect("JSON"),
            NOW,
            RunnerCapabilityReadiness::unavailable().with_github_oidc(),
            |_| Ok(certificate.pem.clone()),
        )
        .expect("a ready OIDC product admits the exact advertised capability");
        assert!(
            admitted.runners()[0]
                .capabilities()
                .features()
                .contains(&RunnerFeature::OIDC_TOKENS)
        );
    }

    #[test]
    fn document_rejects_invalid_certificate_sources_before_loading() {
        let id = RunnerId::new();
        let certificate = client_certificate("runner-a");
        for source in [
            "/run/automata/client.pem",
            "file:relative.pem",
            "file:/run/../client.pem",
            "file:/",
            "vault:key",
        ] {
            let mut document: Value =
                serde_json::from_slice(&valid_document(id, certificate.expiry)).expect("JSON");
            document["runners"][0]["active_client_certificates"][0]["source"] = json!(source);
            assert_eq!(
                parse_document(
                    &serde_json::to_vec(&document).expect("JSON"),
                    NOW,
                    |_| panic!("invalid sources fail before file access"),
                )
                .expect_err("invalid source"),
                StaticRunnerRegistrationError::InvalidCertificateSource
            );
        }
    }

    #[test]
    fn leaf_must_have_only_explicit_client_auth_authority() {
        let cases = [
            vec![],
            vec![ExtendedKeyUsagePurpose::Any],
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            vec![
                ExtendedKeyUsagePurpose::ClientAuth,
                ExtendedKeyUsagePurpose::ServerAuth,
            ],
        ];
        for usages in cases {
            let certificate = certificate(
                "invalid-purpose",
                IsCa::NoCa,
                usages,
                vec![KeyUsagePurpose::DigitalSignature],
            );
            assert_eq!(
                parse_leaf_certificate(&certificate.pem, certificate.expiry, NOW)
                    .expect_err("non-exclusive client auth must fail"),
                StaticRunnerRegistrationError::InvalidCertificate
            );
        }

        let certificate = certificate(
            "ca-purpose",
            IsCa::Ca(BasicConstraints::Unconstrained),
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            vec![KeyUsagePurpose::KeyCertSign],
        );
        assert_eq!(
            parse_leaf_certificate(&certificate.pem, certificate.expiry, NOW)
                .expect_err("CA must fail"),
            StaticRunnerRegistrationError::InvalidCertificate
        );
    }

    #[test]
    fn leaf_must_be_one_complete_pem_certificate() {
        let certificate = client_certificate("runner-a");
        let mut bundle = certificate.pem.clone();
        bundle.extend_from_slice(&certificate.pem);
        assert_eq!(
            parse_leaf_certificate(&bundle, certificate.expiry, NOW).expect_err("bundle must fail"),
            StaticRunnerRegistrationError::InvalidCertificate
        );

        let mut wrong_section = certificate.pem.clone();
        wrong_section
            .extend_from_slice(b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n");
        assert_eq!(
            parse_leaf_certificate(&wrong_section, certificate.expiry, NOW)
                .expect_err("extra PEM section must fail"),
            StaticRunnerRegistrationError::InvalidCertificate
        );

        let malformed = b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
        assert_eq!(
            parse_leaf_certificate(malformed, certificate.expiry, NOW)
                .expect_err("malformed DER must fail"),
            StaticRunnerRegistrationError::InvalidCertificate
        );

        for garbage_wrapped in [
            [b"untrusted-prefix\n".as_slice(), certificate.pem.as_slice()].concat(),
            [certificate.pem.as_slice(), b"untrusted-suffix\n".as_slice()].concat(),
        ] {
            assert_eq!(
                parse_leaf_certificate(&garbage_wrapped, certificate.expiry, NOW)
                    .expect_err("unconsumed bytes must fail"),
                StaticRunnerRegistrationError::InvalidCertificate
            );
        }

        let whitespace_wrapped = [
            b" \t\r\n".as_slice(),
            certificate.pem.as_slice(),
            b"\r\n \t".as_slice(),
        ]
        .concat();
        parse_leaf_certificate(&whitespace_wrapped, certificate.expiry, NOW)
            .expect("surrounding ASCII whitespace is not authority data");
    }

    #[test]
    fn leaf_expiry_and_current_window_are_exact() {
        let certificate = client_certificate("runner-a");
        let (_, parsed) = parse_x509_certificate(&certificate.der).expect("certificate");
        let not_before = parsed.validity().not_before.timestamp();
        assert_eq!(
            parse_leaf_certificate(&certificate.pem, certificate.expiry + 1, NOW)
                .expect_err("expiry drift"),
            StaticRunnerRegistrationError::CertificateValidity
        );
        assert_eq!(
            parse_leaf_certificate(&certificate.pem, certificate.expiry, not_before - 1)
                .expect_err("not yet valid"),
            StaticRunnerRegistrationError::CertificateValidity
        );
        assert_eq!(
            parse_leaf_certificate(&certificate.pem, certificate.expiry, certificate.expiry)
                .expect_err("expired"),
            StaticRunnerRegistrationError::CertificateValidity
        );
        parse_leaf_certificate(&certificate.pem, certificate.expiry, not_before)
            .expect("notBefore is inclusive");
    }

    #[cfg(unix)]
    fn test_file_root() -> PathBuf {
        let manifest = fs::canonicalize(env!("CARGO_MANIFEST_DIR")).expect("manifest directory");
        let workspace = manifest
            .parent()
            .and_then(Path::parent)
            .expect("workspace test directory");
        let root = workspace
            .join("target/static-registration-loader-tests")
            .join("automata-static-registration-loader-tests")
            .join(RunnerId::new().to_string());
        fs::create_dir_all(&root).expect("test root");
        root
    }

    #[cfg(unix)]
    fn write_read_only(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;

        fs::write(path, bytes).expect("write test file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).expect("chmod test file");
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_relative_reader_accepts_exact_limit_through_trusted_ancestors() {
        let root = test_file_root();
        let path = root.join("document.json");
        write_read_only(&path, b"1234");
        let owner = rustix::process::geteuid().as_raw();
        assert_eq!(
            read_bounded_nofollow(&path, 4, owner).expect("exact bound"),
            b"1234"
        );
        assert_eq!(
            read_bounded_nofollow(&path, 3, owner).expect_err("over bound"),
            StaticRunnerRegistrationError::FileTooLarge
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_relative_reader_rejects_symlinks_hardlinks_and_writable_files() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = test_file_root();
        let target = root.join("target");
        write_read_only(&target, b"trusted");
        let owner = rustix::process::geteuid().as_raw();

        let final_link = root.join("final-link");
        symlink(&target, &final_link).expect("final symlink");
        assert_eq!(
            read_bounded_nofollow(&final_link, 16, owner).expect_err("final symlink"),
            StaticRunnerRegistrationError::InsecureFile
        );

        let real_directory = root.join("real");
        fs::create_dir(&real_directory).expect("real directory");
        let nested = real_directory.join("nested");
        write_read_only(&nested, b"trusted");
        let directory_link = root.join("directory-link");
        symlink(&real_directory, &directory_link).expect("directory symlink");
        assert_eq!(
            read_bounded_nofollow(&directory_link.join("nested"), 16, owner)
                .expect_err("intermediate symlink"),
            StaticRunnerRegistrationError::InsecureFile
        );

        let hard_link = root.join("hard-link");
        fs::hard_link(&target, &hard_link).expect("hard link");
        assert_eq!(
            read_bounded_nofollow(&target, 16, owner).expect_err("multiple links"),
            StaticRunnerRegistrationError::InsecureFile
        );

        let writable = root.join("writable");
        fs::write(&writable, b"mutable").expect("writable file");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o600)).expect("writable mode");
        assert_eq!(
            read_bounded_nofollow(&writable, 16, owner).expect_err("writable file"),
            StaticRunnerRegistrationError::InsecureFile
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_relative_reader_rejects_unprivileged_writable_ancestors() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = test_file_root();
        let writable_directory = root.join("writable-directory");
        fs::create_dir(&writable_directory).expect("writable directory");
        fs::set_permissions(&writable_directory, fs::Permissions::from_mode(0o777))
            .expect("writable directory mode");
        let file = writable_directory.join("document.json");
        write_read_only(&file, b"trusted");
        let owner = rustix::process::geteuid().as_raw();
        assert_eq!(
            read_bounded_nofollow(&file, 16, owner).expect_err("writable ancestor"),
            StaticRunnerRegistrationError::InsecureFile
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn privileged_metadata_requires_root_regular_nonwritable_single_link() {
        assert!(privileged_file_attributes(true, 0, 0o100_440, 1, 0));
        assert!(!privileged_file_attributes(true, 1_000, 0o100_440, 1, 0));
        assert!(!privileged_file_attributes(true, 0, 0o100_640, 1, 0));
        assert!(!privileged_file_attributes(false, 0, 0o120_440, 1, 0));
        assert!(!privileged_file_attributes(true, 0, 0o100_440, 2, 0));

        assert!(privileged_directory_attributes(true, 0, 0o040_755, 0));
        assert!(!privileged_directory_attributes(true, 0, 0o040_775, 0));
        assert!(!privileged_directory_attributes(true, 1_000, 0o040_755, 0));
        assert!(!privileged_directory_attributes(false, 0, 0o100_444, 0));
    }

    #[test]
    fn errors_never_retain_paths() {
        let marker = format!("static-registration-sensitive-{}", RunnerId::new());
        let error = load_static_runner_fleet(
            Path::new(&marker),
            NOW,
            RunnerCapabilityReadiness::unavailable(),
        )
        .expect_err("relative path must fail");
        assert_eq!(error, StaticRunnerRegistrationError::RelativePath);
        assert!(!error.to_string().contains(&marker));
        assert!(!format!("{error:?}").contains(&marker));
    }

    #[test]
    fn clock_must_fit_nonnegative_unix_milliseconds() {
        assert_eq!(
            now_millis(-1).expect_err("negative clock"),
            StaticRunnerRegistrationError::InvalidClock
        );
        assert_eq!(
            now_millis(i64::MAX).expect_err("overflow clock"),
            StaticRunnerRegistrationError::InvalidClock
        );
    }
}
