use std::{collections::BTreeMap, fmt::Write as _};

use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SerialNumber,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime};
use x509_parser::{extensions::GeneralName, parse_x509_certificate, pem::parse_x509_pem};
use zeroize::Zeroizing;

use automata_ci_core::Sha256Digest;

use super::{
    LocalInitError, LocalInitErrorCode,
    epoch::{ImmutableEpoch, MaterialDeriver},
    state::StateRoot,
};

const CERTIFICATE_SCHEMA: &str = "automata.local/certificate-custody/v1";
const CERTIFICATE_ALGORITHM: &str = "ecdsa-p256-sha256";
const CA_ROLE: &str = "installation-ca";
const POSTGRES_ROLE: &str = "postgres-server";
const OBJECT_ROLE: &str = "object-store-server";
const RUNNER_ROLE: &str = "runner-server";
const CA_COMMON_NAME: &str = "Automata local installation CA";
const POSTGRES_HOST: &str = "postgres.automata.invalid";
const OBJECT_HOST: &str = "objects.automata.invalid";
const RUNNER_HOST: &str = "runner.automata.invalid";
const VALIDITY_SECONDS: i64 = 10 * 365 * 24 * 60 * 60;
const CLOCK_SKEW_SECONDS: i64 = 5 * 60;
const MAX_RECORD_BYTES: usize = 128 * 1024;

#[allow(clippy::struct_field_names)]
pub(super) struct CertificateMaterial {
    pub(super) ca_pem: String,
    pub(super) ca_key_pem: Zeroizing<String>,
    pub(super) postgres_chain_pem: String,
    pub(super) postgres_key_pem: Zeroizing<String>,
    pub(super) object_chain_pem: String,
    pub(super) object_key_pem: Zeroizing<String>,
    pub(super) runner_chain_pem: String,
    pub(super) runner_key_pem: Zeroizing<String>,
}

pub(super) fn load_or_issue(
    state: &StateRoot,
    deriver: &MaterialDeriver,
    epoch: &ImmutableEpoch,
    material_volumes_exist: bool,
) -> Result<CertificateMaterial, LocalInitError> {
    let keys = DerivedKeys::new(deriver)?;
    if let Some(bytes) = state.load_certificates()? {
        return validate_record(&bytes, &keys, epoch);
    }
    if material_volumes_exist {
        return Err(reset_required());
    }
    let record = issue_record(&keys, epoch)?;
    let bytes = canonical_bytes(&record)?;
    state.store_certificates(&bytes)?;
    let stored = state.load_certificates()?.ok_or_else(reset_required)?;
    validate_record(&stored, &keys, epoch)
}

pub(super) fn validate_existing(
    bytes: &[u8],
    deriver: &MaterialDeriver,
    epoch: &ImmutableEpoch,
) -> Result<CertificateMaterial, LocalInitError> {
    let keys = DerivedKeys::new(deriver)?;
    validate_record(bytes, &keys, epoch)
}

struct DerivedKeys {
    ca: KeyPair,
    ca_pem: Zeroizing<String>,
    postgres: KeyPair,
    postgres_pem: Zeroizing<String>,
    object: KeyPair,
    object_pem: Zeroizing<String>,
    runner: KeyPair,
    runner_pem: Zeroizing<String>,
}

impl DerivedKeys {
    fn new(deriver: &MaterialDeriver) -> Result<Self, LocalInitError> {
        let (ca, ca_pem) = derived_key(deriver, b"tls/installation-ca/private-key")?;
        let (postgres, postgres_pem) = derived_key(deriver, b"tls/postgres-server/private-key")?;
        let (object, object_pem) = derived_key(deriver, b"tls/object-store-server/private-key")?;
        let (runner, runner_pem) = derived_key(deriver, b"tls/runner-server/private-key")?;
        Ok(Self {
            ca,
            ca_pem,
            postgres,
            postgres_pem,
            object,
            object_pem,
            runner,
            runner_pem,
        })
    }
}

fn derived_key(
    deriver: &MaterialDeriver,
    purpose: &'static [u8],
) -> Result<(KeyPair, Zeroizing<String>), LocalInitError> {
    let candidates = deriver.bytes(purpose, 64);
    let secret = candidates
        .as_chunks::<32>()
        .0
        .iter()
        .find_map(|candidate| p256::SecretKey::from_slice(candidate).ok())
        .ok_or_else(reset_required)?;
    let pem = secret
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| reset_required())?;
    let pem = Zeroizing::new(pem.to_string());
    let key = KeyPair::from_pem_and_sign_algo(&pem, &PKCS_ECDSA_P256_SHA256)
        .map_err(|_| reset_required())?;
    Ok((key, pem))
}

fn issue_record(
    keys: &DerivedKeys,
    epoch: &ImmutableEpoch,
) -> Result<CertificateRecord, LocalInitError> {
    let not_before = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|_| reset_required())?
        - Duration::seconds(CLOCK_SKEW_SECONDS);
    let not_after = not_before + Duration::seconds(VALIDITY_SECONDS);

    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| reset_required())?;
    ca_params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let ca_serial = serial(epoch, CA_ROLE);
    let ca_serial_hex = hex(ca_serial.as_ref());
    ca_params.serial_number = Some(ca_serial);
    let issuer = CertifiedIssuer::self_signed(ca_params, clone_key(&keys.ca)?)
        .map_err(|_| reset_required())?;
    let ca_pem = issuer.pem();
    let ca = certificate_entry(
        CA_ROLE,
        CA_COMMON_NAME,
        None,
        not_before,
        not_after,
        &ca_pem,
        &ca_pem,
        &keys.ca,
        &ca_serial_hex,
    );

    let postgres = issue_leaf(
        epoch,
        POSTGRES_ROLE,
        POSTGRES_HOST,
        not_before,
        not_after,
        &keys.postgres,
        &issuer,
        &ca_pem,
    )?;
    let object = issue_leaf(
        epoch,
        OBJECT_ROLE,
        OBJECT_HOST,
        not_before,
        not_after,
        &keys.object,
        &issuer,
        &ca_pem,
    )?;
    let runner = issue_leaf(
        epoch,
        RUNNER_ROLE,
        RUNNER_HOST,
        not_before,
        not_after,
        &keys.runner,
        &issuer,
        &ca_pem,
    )?;
    Ok(CertificateRecord {
        schema: CERTIFICATE_SCHEMA.to_owned(),
        algorithm: CERTIFICATE_ALGORITHM.to_owned(),
        epoch_fingerprint: epoch.fingerprint(),
        certificates: BTreeMap::from([
            (CA_ROLE.to_owned(), ca),
            (OBJECT_ROLE.to_owned(), object),
            (POSTGRES_ROLE.to_owned(), postgres),
            (RUNNER_ROLE.to_owned(), runner),
        ]),
    })
}

fn clone_key(key: &KeyPair) -> Result<KeyPair, LocalInitError> {
    KeyPair::from_pem_and_sign_algo(&key.serialize_pem(), &PKCS_ECDSA_P256_SHA256)
        .map_err(|_| reset_required())
}

#[allow(clippy::too_many_arguments)]
fn issue_leaf(
    epoch: &ImmutableEpoch,
    role: &'static str,
    hostname: &'static str,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    key: &KeyPair,
    issuer: &CertifiedIssuer<'_, KeyPair>,
    ca_pem: &str,
) -> Result<CertificateEntry, LocalInitError> {
    let mut params =
        CertificateParams::new(vec![hostname.to_owned()]).map_err(|_| reset_required())?;
    params.distinguished_name.push(DnType::CommonName, hostname);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = not_before;
    params.not_after = not_after;
    let leaf_serial = serial(epoch, role);
    let leaf_serial_hex = hex(leaf_serial.as_ref());
    params.serial_number = Some(leaf_serial);
    let certificate = params
        .signed_by(key, issuer)
        .map_err(|_| reset_required())?;
    let leaf_pem = certificate.pem();
    let chain_pem = format!("{leaf_pem}{ca_pem}");
    Ok(certificate_entry(
        role,
        hostname,
        Some(hostname),
        not_before,
        not_after,
        &leaf_pem,
        &chain_pem,
        key,
        &leaf_serial_hex,
    ))
}

#[allow(clippy::too_many_arguments)]
fn certificate_entry(
    role: &'static str,
    common_name: &'static str,
    dns_name: Option<&'static str>,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    leaf_pem: &str,
    chain_pem: &str,
    key: &KeyPair,
    serial_hex: &str,
) -> CertificateEntry {
    CertificateEntry {
        role: role.to_owned(),
        common_name: common_name.to_owned(),
        dns_name: dns_name.map(str::to_owned),
        serial_hex: serial_hex.to_owned(),
        not_before_seconds: not_before.unix_timestamp(),
        not_after_seconds: not_after.unix_timestamp(),
        leaf_pem: leaf_pem.to_owned(),
        leaf_sha256: digest(leaf_pem.as_bytes()),
        chain_pem: chain_pem.to_owned(),
        chain_sha256: digest(chain_pem.as_bytes()),
        public_key_sha256: digest(key.public_key_raw()),
    }
}

fn serial(epoch: &ImmutableEpoch, role: &str) -> SerialNumber {
    let mut hasher = Sha256::new();
    hasher.update(b"automata/local/certificate-serial/v1\0");
    hasher.update(epoch.fingerprint().as_bytes());
    hasher.update(
        u16::try_from(role.len())
            .expect("closed certificate role fits u16")
            .to_be_bytes(),
    );
    hasher.update(role.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let bytes = canonical_serial_bytes(digest[..20].try_into().expect("fixed serial length"));
    SerialNumber::from_slice(&bytes)
}

fn canonical_serial_bytes(mut bytes: [u8; 20]) -> [u8; 20] {
    // DER INTEGER removes redundant leading zero magnitude octets. Keeping the
    // first byte nonzero makes the recorded bytes exactly the parsed bytes,
    // while clearing its sign bit keeps the serial positive without a DER pad.
    bytes[0] = (bytes[0] & 0x7f) | 0x01;
    bytes
}

fn validate_record(
    bytes: &[u8],
    keys: &DerivedKeys,
    epoch: &ImmutableEpoch,
) -> Result<CertificateMaterial, LocalInitError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(reset_required());
    }
    let record: CertificateRecord = serde_json::from_slice(bytes).map_err(|_| reset_required())?;
    if canonical_bytes(&record)? != bytes
        || record.schema != CERTIFICATE_SCHEMA
        || record.algorithm != CERTIFICATE_ALGORITHM
        || record.epoch_fingerprint != epoch.fingerprint()
        || record
            .certificates
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != [CA_ROLE, OBJECT_ROLE, POSTGRES_ROLE, RUNNER_ROLE]
    {
        return Err(reset_required());
    }
    let ca = record
        .certificates
        .get(CA_ROLE)
        .ok_or_else(reset_required)?;
    validate_certificate(
        ca,
        CA_ROLE,
        CA_COMMON_NAME,
        None,
        &keys.ca,
        None,
        &ca.leaf_pem,
        epoch,
    )?;
    let postgres = record
        .certificates
        .get(POSTGRES_ROLE)
        .ok_or_else(reset_required)?;
    validate_certificate(
        postgres,
        POSTGRES_ROLE,
        POSTGRES_HOST,
        Some(POSTGRES_HOST),
        &keys.postgres,
        Some(&ca.leaf_pem),
        &ca.leaf_pem,
        epoch,
    )?;
    let object = record
        .certificates
        .get(OBJECT_ROLE)
        .ok_or_else(reset_required)?;
    validate_certificate(
        object,
        OBJECT_ROLE,
        OBJECT_HOST,
        Some(OBJECT_HOST),
        &keys.object,
        Some(&ca.leaf_pem),
        &ca.leaf_pem,
        epoch,
    )?;
    let runner = record
        .certificates
        .get(RUNNER_ROLE)
        .ok_or_else(reset_required)?;
    validate_certificate(
        runner,
        RUNNER_ROLE,
        RUNNER_HOST,
        Some(RUNNER_HOST),
        &keys.runner,
        Some(&ca.leaf_pem),
        &ca.leaf_pem,
        epoch,
    )?;
    if [postgres, object, runner].into_iter().any(|entry| {
        entry.not_before_seconds != ca.not_before_seconds
            || entry.not_after_seconds != ca.not_after_seconds
    }) {
        return Err(reset_required());
    }
    Ok(CertificateMaterial {
        ca_pem: ca.leaf_pem.clone(),
        ca_key_pem: keys.ca_pem.clone(),
        postgres_chain_pem: postgres.chain_pem.clone(),
        postgres_key_pem: keys.postgres_pem.clone(),
        object_chain_pem: object.chain_pem.clone(),
        object_key_pem: keys.object_pem.clone(),
        runner_chain_pem: runner.chain_pem.clone(),
        runner_key_pem: keys.runner_pem.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn validate_certificate(
    entry: &CertificateEntry,
    role: &str,
    common_name: &str,
    dns_name: Option<&str>,
    key: &KeyPair,
    issuer_pem: Option<&str>,
    ca_pem: &str,
    epoch: &ImmutableEpoch,
) -> Result<(), LocalInitError> {
    let expected_serial = hex(serial(epoch, role).as_ref());
    if entry.role != role
        || entry.common_name != common_name
        || entry.dns_name.as_deref() != dns_name
        || digest(entry.leaf_pem.as_bytes()) != entry.leaf_sha256
        || digest(entry.chain_pem.as_bytes()) != entry.chain_sha256
        || digest(key.public_key_raw()) != entry.public_key_sha256
        || entry.serial_hex != expected_serial
        || entry
            .not_after_seconds
            .checked_sub(entry.not_before_seconds)
            != Some(VALIDITY_SECONDS)
        || entry.chain_pem
            != if issuer_pem.is_some() {
                format!("{}{}", entry.leaf_pem, ca_pem)
            } else {
                entry.leaf_pem.clone()
            }
    {
        return Err(reset_required());
    }
    let (remainder, pem) =
        parse_x509_pem(entry.leaf_pem.as_bytes()).map_err(|_| reset_required())?;
    if !remainder.is_empty() || pem.label != "CERTIFICATE" {
        return Err(reset_required());
    }
    let (remainder, certificate) =
        parse_x509_certificate(&pem.contents).map_err(|_| reset_required())?;
    let subject_count = certificate.subject().iter_attributes().count();
    let mut common_names = certificate.subject().iter_common_name();
    let actual_common_name = common_names.next().and_then(|name| name.as_str().ok());
    let actual_dns = certificate
        .subject_alternative_name()
        .map_err(|_| reset_required())?
        .and_then(|extension| {
            let names = &extension.value.general_names;
            (names.len() == 1).then(|| match &names[0] {
                GeneralName::DNSName(name) => Some(*name),
                _ => None,
            })?
        });
    let basic_constraints = certificate
        .basic_constraints()
        .map_err(|_| reset_required())?;
    let key_usage = certificate
        .key_usage()
        .map_err(|_| reset_required())?
        .ok_or_else(reset_required)?;
    let extended_key_usage = certificate
        .extended_key_usage()
        .map_err(|_| reset_required())?;
    let validation_time = OffsetDateTime::now_utc().unix_timestamp();
    let is_ca = issuer_pem.is_none();
    let extensions_match = if is_ca {
        basic_constraints.is_some_and(|constraints| {
            constraints.critical
                && constraints.value.ca
                && constraints.value.path_len_constraint.is_none()
        }) && key_usage.critical
            && key_usage.value.flags == 0b0_0110_0001
            && extended_key_usage.is_none()
    } else {
        basic_constraints.is_none()
            && key_usage.critical
            && key_usage.value.flags == 1
            && extended_key_usage.is_some_and(|usage| {
                !usage.value.any
                    && usage.value.server_auth
                    && !usage.value.client_auth
                    && !usage.value.code_signing
                    && !usage.value.email_protection
                    && !usage.value.time_stamping
                    && !usage.value.ocsp_signing
                    && usage.value.other.is_empty()
            })
    };
    if !remainder.is_empty()
        || certificate.public_key().subject_public_key.data.as_ref() != key.public_key_raw()
        || certificate.validity().not_before.timestamp() != entry.not_before_seconds
        || certificate.validity().not_after.timestamp() != entry.not_after_seconds
        || certificate.validity().not_before >= certificate.validity().not_after
        || certificate.validity().not_before.timestamp() > validation_time
        || certificate.validity().not_after.timestamp() <= validation_time
        || actual_common_name != Some(common_name)
        || subject_count != 1
        || common_names.next().is_some()
        || actual_dns != dns_name
        || !extensions_match
        || certificate.signature_algorithm.algorithm.to_id_string() != "1.2.840.10045.4.3.2"
    {
        return Err(reset_required());
    }
    let actual_serial = certificate.raw_serial();
    let actual_serial_hex = hex(actual_serial);
    if entry.serial_hex != actual_serial_hex {
        return Err(reset_required());
    }
    if let Some(issuer_pem) = issuer_pem {
        let (issuer_pem_remainder, issuer_pem) =
            parse_x509_pem(issuer_pem.as_bytes()).map_err(|_| reset_required())?;
        let (issuer_remainder, issuer) =
            parse_x509_certificate(&issuer_pem.contents).map_err(|_| reset_required())?;
        if !issuer_pem_remainder.is_empty()
            || !issuer_remainder.is_empty()
            || certificate.issuer() != issuer.subject()
            || certificate
                .verify_signature(Some(issuer.public_key()))
                .is_err()
        {
            return Err(reset_required());
        }
    } else if certificate.issuer() != certificate.subject()
        || certificate.verify_signature(None).is_err()
    {
        return Err(reset_required());
    }
    Ok(())
}

fn canonical_bytes(value: &CertificateRecord) -> Result<Vec<u8>, LocalInitError> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| reset_required())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String is infallible");
    }
    output
}

fn reset_required() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::ResetRequired)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CertificateRecord {
    schema: String,
    algorithm: String,
    epoch_fingerprint: Sha256Digest,
    certificates: BTreeMap<String, CertificateEntry>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CertificateEntry {
    role: String,
    common_name: String,
    dns_name: Option<String>,
    serial_hex: String,
    not_before_seconds: i64,
    not_after_seconds: i64,
    leaf_pem: String,
    leaf_sha256: Sha256Digest,
    chain_pem: String,
    chain_sha256: Sha256Digest,
    public_key_sha256: Sha256Digest,
}

#[cfg(test)]
mod tests;
