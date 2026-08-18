//! Crash-safe runner enrollment request and credential custody.

use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::{
    fs::File,
    io::{Read as _, Write as _},
    os::unix::fs::MetadataExt as _,
};

use anyhow::{Context as _, Result, bail};
use automata_ci_auth::secret::RunnerEnrollmentToken;
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType, KeyPair,
    PKCS_ECDSA_P256_SHA256, PublicKeyData as _,
};
use reqwest::Url;
use rustls::pki_types::pem::PemObject as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

use super::{RedeemResponse, transport::MAX_RESPONSE_BYTES};
use crate::product::{RunnerProductConfig, SecretSource};

const MAX_STAGE_BYTES: usize = 1024 * 1_024;
const STAGE_SCHEMA: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompletedEnrollmentState {
    Current,
    Expired,
}

struct CompletedEnrollmentSnapshot {
    receipt: Zeroizing<Vec<u8>>,
    server_roots: Zeroizing<Vec<u8>>,
    certificate_chain: Zeroizing<Vec<u8>>,
    private_key: Zeroizing<Vec<u8>>,
}

impl CompletedEnrollmentSnapshot {
    fn exact_match(&self, other: &Self) -> bool {
        self.receipt == other.receipt
            && self.server_roots == other.server_roots
            && self.certificate_chain == other.certificate_chain
            && self.private_key == other.private_key
    }
}

struct CredentialPaths {
    server_roots: PathBuf,
    certificate_chain: PathBuf,
    private_key: PathBuf,
    request_stage: PathBuf,
    response_stage: PathBuf,
    recovery_response_stage: PathBuf,
    lock: PathBuf,
}

impl CredentialPaths {
    fn from_config(config: &RunnerProductConfig) -> Result<Self> {
        fn file(source: &SecretSource) -> Result<PathBuf> {
            let SecretSource::File { path } = source else {
                bail!("runner enrollment requires file-backed TLS credential destinations");
            };
            Ok(path.clone())
        }
        let private_key = file(config.tls().private_key())?;
        Ok(Self {
            server_roots: file(config.tls().server_roots())?,
            certificate_chain: file(config.tls().certificate_chain())?,
            request_stage: enrollment_sibling(&private_key, ".automata-enrollment-request")?,
            response_stage: enrollment_sibling(&private_key, ".automata-enrollment-response")?,
            recovery_response_stage: enrollment_sibling(
                &private_key,
                ".automata-enrollment-recovery-response",
            )?,
            lock: enrollment_sibling(&private_key, ".automata-tls-lock")?,
            private_key,
        })
    }

    fn final_paths(&self) -> [&Path; 6] {
        [
            &self.server_roots,
            &self.certificate_chain,
            &self.private_key,
            &self.request_stage,
            &self.response_stage,
            &self.recovery_response_stage,
        ]
    }

    fn all_paths(&self) -> Result<Vec<PathBuf>> {
        let final_paths = self.final_paths();
        let mut paths = final_paths
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<Vec<_>>();
        paths.push(self.lock.clone());
        for path in final_paths {
            paths.push(temporary_path(path)?);
        }
        Ok(paths)
    }
}

pub(super) struct CredentialDestinations {
    server_roots: PathBuf,
    certificate_chain: PathBuf,
    private_key: PathBuf,
    request_stage: PathBuf,
    response_stage: PathBuf,
    recovery_response_stage: PathBuf,
    #[cfg(unix)]
    _lock: rustix::fd::OwnedFd,
}

impl CredentialDestinations {
    /// Observes one exact completed identity without opening or creating the
    /// writer flock, synchronizing directories, reading a token, or repairing
    /// custody. Two identical no-follow snapshots close the multi-file read
    /// against an atomic renewal/recovery rotation in progress.
    pub(crate) fn observe_completed(
        config: &RunnerProductConfig,
        validation_time_seconds: i64,
    ) -> Result<Option<CompletedEnrollmentState>> {
        let paths = CredentialPaths::from_config(config)?;
        validate_lexical_destination_set(&paths.all_paths()?)?;
        let first = match read_completed_snapshot(&paths)? {
            Some(snapshot) => snapshot,
            None => return Ok(None),
        };
        validate_existing_destination_set(&paths.all_paths()?)?;
        let second = read_completed_snapshot(&paths)?
            .context("runner enrollment custody changed during observation")?;
        if !first.exact_match(&second) {
            bail!("runner enrollment custody changed during observation");
        }
        let response: RedeemResponse = serde_json::from_slice(&second.receipt)
            .context("runner enrollment completion receipt is invalid")?;
        let expires_at_seconds = certificate_expiration(&second.certificate_chain)?;
        let (state, profile_validation_time) = if expires_at_seconds > validation_time_seconds {
            (CompletedEnrollmentState::Current, validation_time_seconds)
        } else {
            (
                CompletedEnrollmentState::Expired,
                expires_at_seconds
                    .checked_sub(1)
                    .context("runner enrollment certificate expiry is invalid")?,
            )
        };
        validate_completed_material(
            config,
            &response,
            &second.receipt,
            &second.server_roots,
            &second.certificate_chain,
            &second.private_key,
            profile_validation_time,
        )?;
        Ok(Some(state))
    }

    pub(super) fn from_config(config: &RunnerProductConfig) -> Result<Self> {
        let paths = CredentialPaths::from_config(config)?;
        validate_destination_set(&paths.all_paths()?)?;
        #[cfg(unix)]
        let lock = acquire_enrollment_lock(&paths.lock)?;
        Ok(Self {
            server_roots: paths.server_roots,
            certificate_chain: paths.certificate_chain,
            private_key: paths.private_key,
            request_stage: paths.request_stage,
            response_stage: paths.response_stage,
            recovery_response_stage: paths.recovery_response_stage,
            #[cfg(unix)]
            _lock: lock,
        })
    }

    fn require_absent(&self) -> Result<()> {
        if read_bounded_file(&self.server_roots, MAX_STAGE_BYTES, false)?.is_some()
            || read_bounded_file(&self.certificate_chain, MAX_STAGE_BYTES, false)?.is_some()
            || read_bounded_file(&self.private_key, MAX_STAGE_BYTES, true)?.is_some()
            || read_bounded_temporary(&self.server_roots, MAX_STAGE_BYTES, false)?.is_some()
            || read_bounded_temporary(&self.certificate_chain, MAX_STAGE_BYTES, false)?.is_some()
            || read_bounded_temporary(&self.private_key, MAX_STAGE_BYTES, true)?.is_some()
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
        Ok(None)
    }

    /// Recognizes only a fully published, currently usable enrollment identity.
    ///
    /// This path deliberately does not repair, replace, or remove anything. It
    /// is used after the secret-bearing request stage has been durably retired
    /// and the exact non-secret server response retained as the completion
    /// receipt. Partial credentials, dangling writes, receipt drift, malformed
    /// roots, an expired leaf, or a key/profile mismatch all fail closed.
    pub(super) fn attest_completed(
        &self,
        config: &RunnerProductConfig,
        response: &RedeemResponse,
        receipt: &[u8],
        validation_time_seconds: i64,
    ) -> Result<()> {
        let server_roots = read_bounded_file(&self.server_roots, MAX_STAGE_BYTES, false)?;
        let certificate_chain = read_bounded_file(&self.certificate_chain, MAX_STAGE_BYTES, false)?;
        let private_key = read_bounded_file(&self.private_key, MAX_STAGE_BYTES, true)?;
        for (path, private) in [
            (&self.server_roots, false),
            (&self.certificate_chain, false),
            (&self.private_key, true),
        ] {
            if read_bounded_temporary(path, MAX_STAGE_BYTES, private)?.is_some() {
                bail!("runner TLS credential custody has a dangling staging write");
            }
        }
        match (&server_roots, &certificate_chain, &private_key) {
            (Some(_), Some(_), Some(_)) => {}
            _ => bail!("runner TLS credential custody is not completely published"),
        }
        let (Some(server_roots), Some(certificate_chain), Some(private_key)) =
            (server_roots, certificate_chain, private_key)
        else {
            unreachable!("complete credential tuple was established above");
        };
        let stored_receipt = read_bounded_file(&self.response_stage, MAX_RESPONSE_BYTES, true)?
            .context("runner enrollment completion receipt is missing")?;
        if read_bounded_temporary(&self.response_stage, MAX_RESPONSE_BYTES, true)?.is_some()
            || stored_receipt.as_slice() != receipt
        {
            bail!("runner TLS credential custody does not match its completion receipt");
        }
        validate_completed_material(
            config,
            response,
            receipt,
            &server_roots,
            &certificate_chain,
            &private_key,
            validation_time_seconds,
        )
    }

    pub(super) fn attest_expired_completed(
        &self,
        config: &RunnerProductConfig,
        response: &RedeemResponse,
        receipt: &[u8],
        validation_time_seconds: i64,
    ) -> Result<RecoveryPredecessor> {
        let chain = read_bounded_file(&self.certificate_chain, MAX_STAGE_BYTES, false)?
            .context("runner enrollment certificate chain is missing")?;
        let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(chain.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("runner enrollment predecessor chain is invalid")?;
        let [leaf, issuer] = certificates.as_slice() else {
            bail!("runner enrollment predecessor chain is invalid");
        };
        let (remainder, parsed_leaf) = parse_x509_certificate(leaf.as_ref())
            .context("runner enrollment predecessor chain is invalid")?;
        let predecessor_expires_at_seconds = parsed_leaf.validity().not_after.timestamp();
        if !remainder.is_empty()
            || predecessor_expires_at_seconds <= 0
            || predecessor_expires_at_seconds > validation_time_seconds
        {
            bail!("runner enrollment identity is not an exact expired predecessor");
        }
        let historical_validation_time = predecessor_expires_at_seconds
            .checked_sub(1)
            .context("runner enrollment predecessor expiry is invalid")?;
        self.attest_completed(config, response, receipt, historical_validation_time)?;
        let verified_chain = read_bounded_file(&self.certificate_chain, MAX_STAGE_BYTES, false)?
            .context("runner enrollment certificate chain is missing")?;
        if verified_chain.as_slice() != chain.as_slice() {
            bail!("runner enrollment predecessor changed during attestation");
        }
        let roots = read_bounded_file(&self.server_roots, MAX_STAGE_BYTES, false)?
            .context("runner enrollment server roots are missing")?;
        let key = read_bounded_file(&self.private_key, MAX_STAGE_BYTES, true)?
            .context("runner enrollment private key is missing")?;
        Ok(RecoveryPredecessor {
            presented_leaf_sha256: Sha256::digest(leaf.as_ref()).into(),
            issuer_sha256: Sha256::digest(issuer.as_ref()).into(),
            presented_expires_at_seconds: predecessor_expires_at_seconds,
            server_roots_sha256: Sha256::digest(roots.as_slice()).into(),
            certificate_chain_sha256: Sha256::digest(chain.as_slice()).into(),
            private_key_sha256: Sha256::digest(key.as_slice()).into(),
            completion_receipt_sha256: Sha256::digest(receipt).into(),
        })
    }

    pub(super) fn create_stage(
        &self,
        config: &RunnerProductConfig,
        origin: &Url,
        runner_name: &str,
        token: RunnerEnrollmentToken,
    ) -> Result<EnrollmentStage> {
        self.require_absent()?;
        let stage = EnrollmentStage::new(config, origin, runner_name, token)?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(&stage).context("runner enrollment request could not be staged")?,
        );
        persist_new(&self.request_stage, &bytes, true)?;
        Ok(stage)
    }

    pub(super) fn create_recovery_stage(
        &self,
        config: &RunnerProductConfig,
        origin: &Url,
        runner_name: &str,
        token: RunnerEnrollmentToken,
        predecessor: RecoveryPredecessor,
    ) -> Result<EnrollmentStage> {
        if self.load_recovery_response()?.is_some() {
            bail!("runner enrollment recovery response lacks its request stage");
        }
        let stage = EnrollmentStage::new_recovery(config, origin, runner_name, token, predecessor)?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(&stage)
                .context("runner enrollment recovery request could not be staged")?,
        );
        persist_new(&self.request_stage, &bytes, true)?;
        Ok(stage)
    }

    /// Re-proves the exact expired tuple before a recovery token is sent. A
    /// staged server response is sufficient authority for crash replay, but
    /// until one exists no drift in the predecessor custody is tolerated.
    pub(super) fn attest_recovery_request(
        &self,
        config: &RunnerProductConfig,
        stage: &EnrollmentStage,
        validation_time_seconds: i64,
    ) -> Result<()> {
        let predecessor = stage
            .recovery
            .as_ref()
            .context("runner enrollment request is not a recovery")?;
        predecessor.validate()?;
        let receipt = read_bounded_file(&self.response_stage, MAX_RESPONSE_BYTES, true)?
            .context("runner enrollment recovery predecessor is missing")?;
        let response: RedeemResponse = serde_json::from_slice(&receipt)
            .context("runner enrollment recovery predecessor receipt is invalid")?;
        let observed =
            self.attest_expired_completed(config, &response, &receipt, validation_time_seconds)?;
        if &observed != predecessor {
            bail!("runner enrollment recovery predecessor does not match its request");
        }
        Ok(())
    }

    pub(super) fn load_response(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if let Some(response) = read_bounded_file(&self.response_stage, MAX_RESPONSE_BYTES, true)? {
            sync_parent(&self.response_stage)?;
            if serde_json::from_slice::<RedeemResponse>(&response).is_err() {
                bail!("runner enrollment completion receipt is invalid");
            }
            return Ok(Some(response));
        }
        let Some(response) =
            read_bounded_temporary(&self.response_stage, MAX_RESPONSE_BYTES, true)?
        else {
            return Ok(None);
        };
        if serde_json::from_slice::<RedeemResponse>(&response).is_err() {
            bail!("runner enrollment completion receipt is invalid");
        }
        publish_temporary(&self.response_stage)?;
        Ok(Some(response))
    }

    pub(super) fn persist_response(&self, response: &[u8]) -> Result<()> {
        persist_exact_file(&self.response_stage, response, true)
            .context("runner enrollment response could not be staged")
    }

    pub(super) fn load_recovery_response(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if let Some(response) =
            read_bounded_file(&self.recovery_response_stage, MAX_RESPONSE_BYTES, true)?
        {
            sync_parent(&self.recovery_response_stage)?;
            if serde_json::from_slice::<RedeemResponse>(&response).is_err() {
                bail!("runner enrollment recovery response is invalid");
            }
            return Ok(Some(response));
        }
        let Some(response) =
            read_bounded_temporary(&self.recovery_response_stage, MAX_RESPONSE_BYTES, true)?
        else {
            return Ok(None);
        };
        if serde_json::from_slice::<RedeemResponse>(&response).is_err() {
            bail!("runner enrollment recovery response is invalid");
        }
        publish_temporary(&self.recovery_response_stage)?;
        Ok(Some(response))
    }

    pub(super) fn persist_recovery_response(&self, response: &[u8]) -> Result<()> {
        persist_exact_file(&self.recovery_response_stage, response, true)
            .context("runner enrollment recovery response could not be staged")
    }

    pub(super) fn finish_recovery(
        &self,
        config: &RunnerProductConfig,
        stage: &EnrollmentStage,
        response_bytes: &[u8],
        validation_time_seconds: i64,
    ) -> Result<()> {
        let predecessor = stage
            .recovery
            .as_ref()
            .context("runner enrollment request is not a recovery")?;
        let response: RedeemResponse = serde_json::from_slice(response_bytes)
            .context("runner enrollment recovery response is invalid")?;
        super::validate_response(config, &response, validation_time_seconds)?;
        let validated = validate_issued_runner_certificate(
            config.runner_id().as_uuid(),
            &response.certificate_chain_pem,
            response.certificate_expires_at_seconds,
            stage.private_key_pem.as_str(),
            validation_time_seconds,
            Some(predecessor.issuer_sha256),
        )?;
        if validated.leaf == predecessor.presented_leaf_sha256
            || response.certificate_expires_at_seconds <= predecessor.presented_expires_at_seconds
            || Sha256::digest(response.server_ca_pem.as_bytes()).as_slice()
                != predecessor.server_roots_sha256
        {
            bail!("runner enrollment recovery response does not replace its predecessor");
        }
        replace_exact_file(
            &self.server_roots,
            &predecessor.server_roots_sha256,
            response.server_ca_pem.as_bytes(),
            false,
        )?;
        replace_exact_file(
            &self.certificate_chain,
            &predecessor.certificate_chain_sha256,
            response.certificate_chain_pem.as_bytes(),
            false,
        )?;
        replace_exact_file(
            &self.private_key,
            &predecessor.private_key_sha256,
            stage.private_key_pem.as_bytes(),
            true,
        )?;
        replace_exact_file(
            &self.response_stage,
            &predecessor.completion_receipt_sha256,
            response_bytes,
            true,
        )?;
        Ok(())
    }

    pub(super) fn persist_exact(&self, roots: &[u8], chain: &[u8], key: &[u8]) -> Result<()> {
        persist_exact_file(&self.server_roots, roots, false)?;
        persist_exact_file(&self.certificate_chain, chain, false)?;
        persist_exact_file(&self.private_key, key, true)?;
        Ok(())
    }

    pub(super) fn complete(&self) -> Result<()> {
        remove_durable(&self.request_stage)
    }

    pub(super) fn complete_recovery(&self) -> Result<()> {
        // All final files are durable before cleanup begins. Retire the
        // secret-bearing request first; if cleanup is interrupted, the
        // response is an exact duplicate of the canonical completion receipt
        // and the next invocation can reconcile it without token or network.
        remove_durable(&self.request_stage)?;
        self.remove_recovery_response()
    }

    pub(super) fn remove_recovery_response(&self) -> Result<()> {
        remove_durable(&self.recovery_response_stage)
    }
}

fn read_completed_snapshot(paths: &CredentialPaths) -> Result<Option<CompletedEnrollmentSnapshot>> {
    for path in [&paths.request_stage, &paths.recovery_response_stage] {
        if read_bounded_observed_file(path, MAX_STAGE_BYTES, true)?.is_some()
            || read_bounded_observed_temporary(path, MAX_STAGE_BYTES, true)?.is_some()
        {
            return Ok(None);
        }
    }
    let Some(receipt) =
        read_bounded_observed_file(&paths.response_stage, MAX_RESPONSE_BYTES, true)?
    else {
        return Ok(None);
    };
    if read_bounded_observed_temporary(&paths.response_stage, MAX_RESPONSE_BYTES, true)?.is_some() {
        bail!("runner enrollment completion receipt has a dangling staging write");
    }
    let load = |path: &Path, private| -> Result<Zeroizing<Vec<u8>>> {
        if read_bounded_observed_temporary(path, MAX_STAGE_BYTES, private)?.is_some() {
            bail!("runner TLS credential custody has a dangling staging write");
        }
        read_bounded_observed_file(path, MAX_STAGE_BYTES, private)?
            .context("runner TLS credential custody is not completely published")
    };
    Ok(Some(CompletedEnrollmentSnapshot {
        receipt,
        server_roots: load(&paths.server_roots, false)?,
        certificate_chain: load(&paths.certificate_chain, false)?,
        private_key: load(&paths.private_key, true)?,
    }))
}

fn certificate_expiration(certificate_chain: &[u8]) -> Result<i64> {
    let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(certificate_chain)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("runner enrollment certificate chain is invalid")?;
    let [leaf, _issuer] = certificates.as_slice() else {
        bail!("runner enrollment certificate chain is invalid");
    };
    let (remainder, leaf) = parse_x509_certificate(leaf.as_ref())
        .context("runner enrollment certificate chain is invalid")?;
    if !remainder.is_empty() || leaf.validity().not_after.timestamp() <= 0 {
        bail!("runner enrollment certificate chain is invalid");
    }
    Ok(leaf.validity().not_after.timestamp())
}

fn validate_completed_material(
    config: &RunnerProductConfig,
    response: &RedeemResponse,
    receipt: &[u8],
    server_roots: &[u8],
    certificate_chain: &[u8],
    private_key: &[u8],
    validation_time_seconds: i64,
) -> Result<()> {
    let expected_group = automata_ci_core::RunnerGroup::new(&response.runner_group)
        .context("runner enrollment completion receipt has an invalid group")?;
    if response.runner_id != config.runner_id().as_uuid()
        || response.control_endpoint != config.control_endpoint().to_string()
        || config.inventory().groups() != &std::collections::BTreeSet::from([expected_group])
        || response.certificate_chain_pem.is_empty()
        || response.server_ca_pem.is_empty()
        || response.certificate_expires_at_seconds <= 0
    {
        bail!("runner enrollment completion receipt does not match the local configuration");
    }
    let roots_text =
        std::str::from_utf8(server_roots).context("runner enrollment server roots are invalid")?;
    let chain_text = std::str::from_utf8(certificate_chain)
        .context("runner enrollment certificate chain is invalid")?;
    let key_text =
        std::str::from_utf8(private_key).context("runner enrollment private key is invalid")?;
    let canonical_receipt =
        serde_json::to_vec(response).context("runner enrollment completion receipt is invalid")?;
    if receipt != canonical_receipt || server_roots != response.server_ca_pem.as_bytes() {
        bail!("runner TLS credential custody does not match its completion receipt");
    }
    let receipt_certificates = rustls::pki_types::CertificateDer::pem_slice_iter(
        response.certificate_chain_pem.as_bytes(),
    )
    .collect::<std::result::Result<Vec<_>, _>>()
    .context("runner enrollment completion receipt is invalid")?;
    let [receipt_leaf, receipt_issuer] = receipt_certificates.as_slice() else {
        bail!("runner enrollment completion receipt is invalid");
    };
    let (receipt_remainder, receipt_leaf) = parse_x509_certificate(receipt_leaf.as_ref())
        .context("runner enrollment completion receipt is invalid")?;
    if !receipt_remainder.is_empty()
        || receipt_leaf.validity().not_after.timestamp() != response.certificate_expires_at_seconds
    {
        bail!("runner enrollment completion receipt is invalid");
    }
    let receipt_issuer_sha256: [u8; 32] = Sha256::digest(receipt_issuer.as_ref()).into();
    let expires_at_seconds = certificate_expiration(certificate_chain)?;
    validate_issued_runner_certificate(
        config.runner_id().as_uuid(),
        chain_text,
        expires_at_seconds,
        key_text,
        validation_time_seconds,
        Some(receipt_issuer_sha256),
    )?;
    validate_server_roots(roots_text, validation_time_seconds)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryPredecessor {
    presented_leaf_sha256: [u8; 32],
    issuer_sha256: [u8; 32],
    presented_expires_at_seconds: i64,
    server_roots_sha256: [u8; 32],
    certificate_chain_sha256: [u8; 32],
    private_key_sha256: [u8; 32],
    completion_receipt_sha256: [u8; 32],
}

impl RecoveryPredecessor {
    fn validate(&self) -> Result<()> {
        if self.presented_expires_at_seconds <= 0
            || [
                self.presented_leaf_sha256,
                self.issuer_sha256,
                self.server_roots_sha256,
                self.certificate_chain_sha256,
                self.private_key_sha256,
                self.completion_receipt_sha256,
            ]
            .iter()
            .any(|digest| digest.iter().all(|byte| *byte == 0))
        {
            bail!("runner enrollment recovery predecessor is invalid");
        }
        Ok(())
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
    #[serde(serialize_with = "serialize_runner_enrollment_token")]
    pub(super) token: RunnerEnrollmentToken,
    #[serde(
        deserialize_with = "deserialize_zeroizing",
        serialize_with = "serialize_zeroizing"
    )]
    pub(super) private_key_pem: Zeroizing<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery: Option<RecoveryPredecessor>,
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
        token: RunnerEnrollmentToken,
    ) -> Result<Self> {
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
            recovery: None,
        })
    }

    fn new_recovery(
        config: &RunnerProductConfig,
        origin: &Url,
        runner_name: &str,
        token: RunnerEnrollmentToken,
        predecessor: RecoveryPredecessor,
    ) -> Result<Self> {
        predecessor.validate()?;
        let mut stage = Self::new(config, origin, runner_name, token)?;
        stage.recovery = Some(predecessor);
        Ok(stage)
    }

    pub(super) fn is_recovery(&self) -> bool {
        self.recovery.is_some()
    }

    pub(super) fn recovery_predecessor(&self) -> Option<([u8; 32], i64)> {
        self.recovery.as_ref().map(|predecessor| {
            (
                predecessor.presented_leaf_sha256,
                predecessor.presented_expires_at_seconds,
            )
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
        if let Some(recovery) = &self.recovery {
            recovery.validate()?;
        }
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
    if response.runner_id != expected_runner_id {
        bail!("runner enrollment response certificate does not match the staged request");
    }
    validate_issued_runner_certificate(
        expected_runner_id,
        &response.certificate_chain_pem,
        response.certificate_expires_at_seconds,
        private_key_pem,
        validation_time_seconds,
        None,
    )?;
    validate_server_roots(&response.server_ca_pem, validation_time_seconds)
}

/// Exact identities derived while validating one issued runner certificate.
pub(crate) struct ValidatedRunnerCertificate {
    pub(crate) leaf: [u8; 32],
    pub(crate) issuer: [u8; 32],
    pub(crate) public_key: [u8; 32],
}

/// Validates the shared runner leaf profile, key binding, issuer signature, and
/// local validity window used by both enrollment and certificate renewal.
pub(crate) fn validate_issued_runner_certificate(
    expected_runner_id: Uuid,
    certificate_chain_pem: &str,
    certificate_expires_at_seconds: i64,
    private_key_pem: &str,
    validation_time_seconds: i64,
    expected_issuer_sha256: Option<[u8; 32]>,
) -> Result<ValidatedRunnerCertificate> {
    let key = KeyPair::from_pem(private_key_pem)
        .context("runner certificate response has an invalid private key")?;
    let certificates =
        rustls::pki_types::CertificateDer::pem_slice_iter(certificate_chain_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("runner certificate response has an invalid certificate chain")?;
    let [leaf_der, issuer_der] = certificates.as_slice() else {
        bail!("runner certificate response has an invalid certificate chain");
    };
    let (leaf_remainder, leaf) = parse_x509_certificate(leaf_der.as_ref())
        .context("runner certificate response has an invalid leaf certificate")?;
    let (issuer_remainder, issuer) = parse_x509_certificate(issuer_der.as_ref())
        .context("runner certificate response has an invalid issuing certificate")?;
    let leaf_constraints = leaf
        .basic_constraints()
        .context("runner certificate response has invalid basic constraints")?;
    let leaf_usage = leaf
        .key_usage()
        .context("runner certificate response has invalid key usage")?
        .context("runner certificate response has no key usage")?;
    let leaf_extended_usage = leaf
        .extended_key_usage()
        .context("runner certificate response has invalid extended key usage")?
        .context("runner certificate response has no extended key usage")?;
    let issuer_constraints = issuer
        .basic_constraints()
        .context("runner certificate response has invalid issuer constraints")?
        .context("runner certificate response issuer has no basic constraints")?;
    let issuer_usage = issuer
        .key_usage()
        .context("runner certificate response has invalid issuer key usage")?
        .context("runner certificate response issuer has no key usage")?;
    let expected_common_name = expected_runner_id.hyphenated().to_string();
    let subject_attribute_count = leaf.subject().iter_attributes().count();
    let mut common_names = leaf.subject().iter_common_name();
    let common_name = common_names.next().and_then(|name| name.as_str().ok());
    let has_subject_alternative_name = leaf
        .subject_alternative_name()
        .context("runner certificate response has an invalid subject alternative name")?
        .is_some();
    let leaf_sha256: [u8; 32] = Sha256::digest(leaf_der.as_ref()).into();
    let issuer_sha256: [u8; 32] = Sha256::digest(issuer_der.as_ref()).into();
    if !leaf_remainder.is_empty()
        || !issuer_remainder.is_empty()
        || key.algorithm() != &PKCS_ECDSA_P256_SHA256
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
        || leaf.validity().not_after.timestamp() != certificate_expires_at_seconds
        || common_name != Some(expected_common_name.as_str())
        || subject_attribute_count != 1
        || common_names.next().is_some()
        || has_subject_alternative_name
        || !issuer_constraints.value.ca
        || !issuer_usage.value.key_cert_sign()
        || expected_issuer_sha256.is_some_and(|expected| expected != issuer_sha256)
        || leaf.verify_signature(Some(issuer.public_key())).is_err()
    {
        bail!("runner certificate response does not match the staged request");
    }
    Ok(ValidatedRunnerCertificate {
        leaf: leaf_sha256,
        issuer: issuer_sha256,
        public_key: Sha256::digest(key.public_key_raw()).into(),
    })
}

fn validate_server_roots(server_ca_pem: &str, validation_time_seconds: i64) -> Result<()> {
    let mut server_roots = rustls::RootCertStore::empty();
    let mut server_root_count = 0_usize;
    for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(server_ca_pem.as_bytes()) {
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

fn serialize_runner_enrollment_token<S>(
    value: &RunnerEnrollmentToken,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.expose_secret())
}

fn deserialize_zeroizing<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

pub(crate) fn enrollment_sibling(path: &Path, suffix: &str) -> Result<PathBuf> {
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

pub(crate) fn temporary_path(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("runner enrollment path has no parent")?;
    let name = path
        .file_name()
        .context("runner enrollment path has no filename")?;
    Ok(parent.join(temporary_name(name)))
}

pub(crate) fn validate_destination_set(paths: &[PathBuf]) -> Result<()> {
    validate_lexical_destination_set(paths)?;

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

fn validate_lexical_destination_set(paths: &[PathBuf]) -> Result<()> {
    for (index, path) in paths.iter().enumerate() {
        if !path.is_absolute() || paths[..index].contains(path) {
            bail!("runner enrollment credential and staging paths must be distinct absolute paths");
        }
    }
    Ok(())
}

fn validate_existing_destination_set(paths: &[PathBuf]) -> Result<()> {
    #[cfg(unix)]
    {
        let mut prepared = Vec::with_capacity(paths.len());
        for path in paths {
            let destination = prepare_existing_destination(path)?
                .context("runner enrollment custody parent is missing")?;
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
pub(crate) fn acquire_enrollment_lock(path: &Path) -> Result<rustix::fd::OwnedFd> {
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
fn prepare_existing_destination(path: &Path) -> Result<Option<PreparedDestination>> {
    use std::path::Component;

    use rustix::fs::{Mode, OFlags, openat};

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
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => {
                return Err(error).context("runner enrollment directory is unavailable");
            }
        };
        require_trusted_directory(&parent)?;
    }
    Ok(Some(PreparedDestination {
        parent,
        name: name.clone(),
    }))
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
pub(crate) fn read_bounded_file(
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
fn read_bounded_observed_file(
    path: &Path,
    limit: usize,
    private: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    use rustix::fs::{Mode, OFlags, openat};

    let Some(destination) = prepare_existing_destination(path)? else {
        return Ok(None);
    };
    let descriptor = match openat(
        &destination.parent,
        &destination.name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(file) => file,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(error).context("runner enrollment state could not be observed");
        }
    };
    let mut file = File::from(descriptor);
    validate_file_metadata(&file, private)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit.min(8 * 1_024)));
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .context("runner enrollment state could not be observed")?;
    if bytes.len() > limit {
        bail!("runner enrollment state exceeded its size limit");
    }
    Ok(Some(bytes))
}

fn read_bounded_observed_temporary(
    path: &Path,
    limit: usize,
    private: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    read_bounded_observed_file(&temporary_path(path)?, limit, private)
}

#[cfg(unix)]
pub(crate) fn read_bounded_temporary(
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
pub(crate) fn read_bounded_file(
    _path: &Path,
    _limit: usize,
    _private: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    bail!("durable runner enrollment is supported only on Unix hosts")
}

#[cfg(not(unix))]
fn read_bounded_observed_file(
    _path: &Path,
    _limit: usize,
    _private: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    bail!("durable runner enrollment observation is supported only on Unix hosts")
}

#[cfg(not(unix))]
pub(crate) fn read_bounded_temporary(
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

pub(crate) fn persist_exact_file(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
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

/// Replaces one existing credential by atomic rename after proving its exact
/// staged predecessor digest. A crash before rename leaves the old file; a
/// crash after rename leaves the exact replacement, so replay is idempotent.
pub(crate) fn replace_exact_file(
    path: &Path,
    predecessor_sha256: &[u8; 32],
    replacement: &[u8],
    private: bool,
) -> Result<()> {
    if replacement.is_empty() {
        bail!("runner credential replacement is empty");
    }
    let current = read_bounded_file(path, replacement.len().max(MAX_STAGE_BYTES), private)?
        .context("runner credential replacement target is missing")?;
    if current.as_slice() == replacement {
        return sync_parent(path);
    }
    let current_sha256: [u8; 32] = Sha256::digest(current.as_slice()).into();
    if &current_sha256 != predecessor_sha256 {
        bail!("runner credential replacement predecessor does not match");
    }
    replace_file_from_temporary(path, replacement, private)
}

#[cfg(unix)]
fn replace_file_from_temporary(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    use rustix::fs::{Mode, OFlags, fchmod, openat, renameat};

    let destination = prepare_destination(path)?;
    let temporary = temporary_name(&destination.name);
    let mode = Mode::from_raw_mode(if private { 0o600 } else { 0o644 });
    match openat(
        &destination.parent,
        &temporary,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        mode,
    ) {
        Ok(staging) => {
            fchmod(&staging, mode).context("runner credential permissions could not be set")?;
            let mut file = File::from(staging);
            file.write_all(bytes)
                .context("runner credential replacement could not be written")?;
            file.sync_all()
                .context("runner credential replacement could not be synchronized")?;
        }
        Err(rustix::io::Errno::EXIST) => {
            let staged = read_bounded_temporary(path, bytes.len(), private)?
                .context("runner credential replacement staging write disappeared")?;
            if staged.as_slice() != bytes {
                drop(staged);
                remove_temporary_durable(path)?;
                return replace_file_from_temporary(path, bytes, private);
            }
        }
        Err(error) => {
            return Err(error).context("runner credential replacement could not be staged");
        }
    }
    renameat(
        &destination.parent,
        &temporary,
        &destination.parent,
        &destination.name,
    )
    .context("runner credential replacement could not be published")?;
    rustix::fs::fsync(&destination.parent)
        .context("runner credential directory could not be synchronized")
}

#[cfg(not(unix))]
fn replace_file_from_temporary(_path: &Path, _bytes: &[u8], _private: bool) -> Result<()> {
    bail!("durable runner credential replacement is supported only on Unix hosts")
}

#[cfg(unix)]
pub(crate) fn persist_new(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
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
pub(crate) fn persist_new(_path: &Path, _bytes: &[u8], _private: bool) -> Result<()> {
    bail!("durable runner enrollment is supported only on Unix hosts")
}

#[cfg(unix)]
pub(crate) fn publish_temporary(path: &Path) -> Result<()> {
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
pub(crate) fn publish_temporary(_path: &Path) -> Result<()> {
    bail!("durable runner enrollment is supported only on Unix hosts")
}

#[cfg(unix)]
pub(crate) fn sync_parent(path: &Path) -> Result<()> {
    let destination = prepare_destination(path)?;
    rustix::fs::fsync(&destination.parent)
        .context("runner enrollment directory could not be synchronized")
}

#[cfg(not(unix))]
pub(crate) fn sync_parent(_path: &Path) -> Result<()> {
    bail!("durable runner enrollment is supported only on Unix hosts")
}

#[cfg(unix)]
pub(crate) fn remove_temporary_durable(path: &Path) -> Result<()> {
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
pub(crate) fn remove_temporary_durable(_path: &Path) -> Result<()> {
    bail!("durable runner enrollment is supported only on Unix hosts")
}

#[cfg(unix)]
pub(crate) fn remove_durable(path: &Path) -> Result<()> {
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
pub(crate) fn remove_durable(_path: &Path) -> Result<()> {
    bail!("durable runner enrollment is supported only on Unix hosts")
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::fs::{self, File};

    use automata_ci_auth::secret::{RandomnessError, RunnerEnrollmentToken, SecureRandom};
    use automata_ci_core::{
        Architecture, OperatingSystem, RunnerCapabilities, RunnerId, RunnerPlatform,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
    };
    use reqwest::Url;
    use rustls::pki_types::pem::PemObject as _;
    use sha2::{Digest as _, Sha256};
    use uuid::Uuid;

    #[cfg(windows)]
    use super::validate_destination_set;
    use super::{
        CompletedEnrollmentState, EnrollmentStage, STAGE_SCHEMA, validate_certificate_response,
    };
    #[cfg(unix)]
    use super::{CredentialDestinations, persist_exact_file};
    #[cfg(unix)]
    use super::{
        acquire_enrollment_lock, persist_new, prepare_destination, same_destination,
        temporary_path, validate_destination_set,
    };
    use crate::enrollment::RedeemResponse;
    #[cfg(target_os = "linux")]
    use crate::product::RunnerProductConfig;

    struct FixedRandom;

    impl SecureRandom for FixedRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), RandomnessError> {
            destination.fill(7);
            Ok(())
        }
    }

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

    #[cfg(windows)]
    #[test]
    fn durable_windows_enrollment_custody_remains_unavailable() {
        let destination = std::env::temp_dir().join(format!(
            "automata-windows-enrollment-must-not-write-{}",
            Uuid::new_v4()
        ));
        let error = validate_destination_set(std::slice::from_ref(&destination))
            .expect_err("Windows enrollment must remain broker-owned and unavailable here");
        assert_eq!(
            error.to_string(),
            "durable runner enrollment is supported only on Unix hosts"
        );
        assert!(!destination.exists());
    }

    #[test]
    #[cfg(unix)]
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
            recovery_response_stage: root.join("runner-key.pem.recovery-response"),
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
    fn completion_retires_the_secret_request_and_preserves_the_response_receipt() {
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

        destinations.complete().expect("finish completion cleanup");
        assert!(!destinations.request_stage.exists());
        assert_eq!(
            fs::read(&destinations.response_stage).expect("preserved completion receipt"),
            b"response receipt"
        );
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
            token: RunnerEnrollmentToken::generate(&FixedRandom).expect("runner token"),
            private_key_pem: zeroize::Zeroizing::new(private_key_pem.clone()),
            recovery: None,
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
        assert_eq!(
            decoded.token.expose_secret(),
            RunnerEnrollmentToken::generate(&FixedRandom)
                .expect("runner token")
                .expose_secret()
        );
        assert_eq!(decoded.private_key_pem.as_str(), private_key_pem);
    }

    #[test]
    fn request_stage_reader_rejects_noncurrent_schema_versions() {
        let token = RunnerEnrollmentToken::generate(&FixedRandom).expect("runner token");
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
            "token": token.expose_secret(),
            "private_key_pem": "unused by schema validation",
        });
        document["schema"] = serde_json::json!(STAGE_SCHEMA + 1);
        let stage: EnrollmentStage = serde_json::from_value(document).expect("stage shape");
        stage
            .validate_schema()
            .expect_err("forward stage schema must be rejected");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn completed_identity_is_accepted_only_when_the_full_tls_custody_is_exact() {
        let root = std::env::current_dir()
            .expect("current directory")
            .join(format!(
                ".automata-enroll-completed-test-{}",
                Uuid::new_v4()
            ));
        fs::create_dir(&root).expect("test root");
        let runner_id = Uuid::new_v4();
        let config = product_config(&root, runner_id);
        let destinations =
            CredentialDestinations::from_config(&config).expect("credential destinations");

        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("CA key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = CertifiedIssuer::self_signed(ca_params, ca_key).expect("CA");
        let runner_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("runner key");
        let expires_at = 1_900_000_000;
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, runner_id.to_string());
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        leaf_params.not_after =
            time::OffsetDateTime::from_unix_timestamp(expires_at).expect("expiry");
        let leaf = leaf_params
            .signed_by(&runner_key, &issuer)
            .expect("runner leaf");
        let roots = issuer.pem();
        let chain = format!("{}{roots}", leaf.pem());
        let key = runner_key.serialize_pem();
        let response = RedeemResponse {
            runner_id,
            runner_group: "default".to_owned(),
            control_endpoint: config.control_endpoint().to_string(),
            certificate_chain_pem: chain.clone(),
            server_ca_pem: roots.clone(),
            certificate_expires_at_seconds: expires_at,
        };
        let receipt = serde_json::to_vec(&response).expect("canonical completion receipt");
        destinations
            .persist_response(&receipt)
            .expect("persist completion receipt");
        destinations
            .persist_exact(roots.as_bytes(), chain.as_bytes(), key.as_bytes())
            .expect("complete credentials");

        use std::os::unix::fs::MetadataExt as _;
        let observed_paths = [
            &destinations.server_roots,
            &destinations.certificate_chain,
            &destinations.private_key,
            &destinations.response_stage,
        ];
        let before = observed_paths
            .iter()
            .map(|path| {
                let metadata = fs::metadata(path).expect("observed metadata");
                (
                    fs::read(path).expect("observed bytes"),
                    metadata.mode(),
                    metadata.uid(),
                    metadata.gid(),
                    metadata.nlink(),
                    metadata.size(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            CredentialDestinations::observe_completed(&config, expires_at - 1)
                .expect("read-only completed observation"),
            Some(CompletedEnrollmentState::Current),
            "the observer must not contend with the exclusive writer flock held here"
        );
        let after = observed_paths
            .iter()
            .map(|path| {
                let metadata = fs::metadata(path).expect("observed metadata");
                (
                    fs::read(path).expect("observed bytes"),
                    metadata.mode(),
                    metadata.uid(),
                    metadata.gid(),
                    metadata.nlink(),
                    metadata.size(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(after, before, "observation must not mutate custody");

        destinations
            .persist_recovery_response(&receipt)
            .expect("simulate response left after request retirement");
        assert_eq!(
            CredentialDestinations::observe_completed(&config, expires_at - 1)
                .expect("orphaned response observation"),
            None,
            "an unreconciled recovery response must keep lock-free readiness closed"
        );
        let orphaned_response = destinations
            .load_recovery_response()
            .expect("load orphaned recovery response")
            .expect("orphaned recovery response");
        assert_eq!(orphaned_response.as_slice(), receipt.as_slice());
        destinations
            .remove_recovery_response()
            .expect("reconcile orphaned recovery response");
        assert_eq!(
            CredentialDestinations::observe_completed(&config, expires_at - 1)
                .expect("reconciled completed observation"),
            Some(CompletedEnrollmentState::Current)
        );

        destinations
            .attest_completed(&config, &response, &receipt, expires_at - 1)
            .expect("exact completed identity");

        let renewed_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("renewed key");
        let renewed_expires_at = expires_at + 10_000;
        let mut renewed_params = CertificateParams::default();
        renewed_params
            .distinguished_name
            .push(DnType::CommonName, runner_id.to_string());
        renewed_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        renewed_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        renewed_params.not_after =
            time::OffsetDateTime::from_unix_timestamp(renewed_expires_at).expect("renewed expiry");
        let renewed_leaf = renewed_params
            .signed_by(&renewed_key, &issuer)
            .expect("renewed runner leaf");
        let renewed_chain = format!("{}{roots}", renewed_leaf.pem());
        let renewed_key = renewed_key.serialize_pem();
        fs::write(&destinations.certificate_chain, renewed_chain.as_bytes())
            .expect("publish simulated renewal chain");
        fs::write(&destinations.private_key, renewed_key.as_bytes())
            .expect("publish simulated renewal key");
        destinations
            .attest_completed(&config, &response, &receipt, expires_at - 1)
            .expect("current same-issuer renewal remains enrolled");
        destinations
            .attest_completed(&config, &response, &receipt, renewed_expires_at)
            .expect_err("an expired renewed leaf must not remain enrolled");
        assert_eq!(
            CredentialDestinations::observe_completed(&config, renewed_expires_at)
                .expect("expired completed observation"),
            Some(CompletedEnrollmentState::Expired)
        );
        let predecessor = destinations
            .attest_expired_completed(&config, &response, &receipt, renewed_expires_at)
            .expect("the exact expired renewed leaf is recovery authority");
        assert_eq!(
            predecessor.presented_expires_at_seconds, renewed_expires_at,
            "recovery must bind the current renewed leaf, not the original receipt leaf"
        );
        let renewed_certificates =
            rustls::pki_types::CertificateDer::pem_slice_iter(renewed_chain.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("renewed chain");
        let renewed_leaf_sha256: [u8; 32] = Sha256::digest(renewed_certificates[0].as_ref()).into();
        assert_eq!(predecessor.presented_leaf_sha256, renewed_leaf_sha256);
        let origin = Url::parse("https://ci.example.test/").expect("origin");
        let mut recovery_stage = EnrollmentStage::new_recovery(
            &config,
            &origin,
            "local-runner",
            RunnerEnrollmentToken::generate(&FixedRandom).expect("recovery token"),
            predecessor,
        )
        .expect("recovery stage");
        assert!(recovery_stage.is_recovery());
        recovery_stage
            .validate(&config, &origin, "local-runner")
            .expect("recovery stage validation");
        destinations
            .attest_recovery_request(&config, &recovery_stage, renewed_expires_at)
            .expect("recovery request must re-prove its exact expired predecessor");
        let recovery = recovery_stage
            .recovery
            .as_mut()
            .expect("recovery predecessor");
        recovery.presented_leaf_sha256[0] ^= 1;
        destinations
            .attest_recovery_request(&config, &recovery_stage, renewed_expires_at)
            .expect_err("a drifted predecessor leaf digest must fail closed");
        recovery_stage
            .recovery
            .as_mut()
            .expect("recovery predecessor")
            .presented_leaf_sha256[0] ^= 1;
        let recovery_json = serde_json::to_value(&recovery_stage).expect("recovery stage JSON");
        assert!(recovery_json.get("recovery").is_some());

        let original_chain = fs::read(&destinations.certificate_chain).expect("chain");
        fs::write(&destinations.private_key, b"not a private key")
            .expect("simulate private-key drift");
        destinations
            .attest_completed(&config, &response, &receipt, expires_at - 1)
            .expect_err("a drifted private key must fail closed");
        assert_eq!(
            fs::read(&destinations.certificate_chain).expect("preserved chain"),
            original_chain
        );

        fs::write(&destinations.private_key, renewed_key.as_bytes()).expect("restore test key");
        fs::remove_file(&destinations.certificate_chain).expect("simulate partial custody");
        destinations
            .attest_completed(&config, &response, &receipt, expires_at - 1)
            .expect_err("partial TLS custody must fail closed");
        drop(destinations);
        fs::remove_dir_all(&root).expect("remove completed identity test root");
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
