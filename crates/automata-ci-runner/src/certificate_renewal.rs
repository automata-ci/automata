//! Crash-durable runner certificate renewal and identity rotation.

use std::{
    fmt,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use automata_ci_runner_transport::{
    PreparedCertificateRenewalRequest, RetryClass, RunnerCertificateRenewalClient,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType, KeyPair,
    PKCS_ECDSA_P256_SHA256, PublicKeyData as _,
};
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

use crate::{
    enrollment::custody::{
        enrollment_sibling, persist_new, read_bounded_file, read_bounded_temporary, remove_durable,
        remove_temporary_durable, replace_exact_file, sync_parent, temporary_path,
        validate_destination_set, validate_issued_runner_certificate,
    },
    product::{ClientTlsSources, RunnerProductConfig, SecretSource},
};

const STAGE_SCHEMA: u8 = 1;
const MAX_STAGE_BYTES: usize = 1024 * 1024;
const MAX_CERTIFICATE_CHAIN_BYTES: usize = 4 * 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 1024 * 1024;
const CLIENT_RENEWAL_REMAINING_SECONDS: i64 = 6 * 24 * 60 * 60;
const CLOCK_RECHECK_SECONDS: u64 = 5 * 60;
const RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Sanitized runner certificate-renewal failure.
#[derive(Debug, Error)]
pub(crate) enum CertificateRenewalError {
    #[error("runner certificate renewal custody failed")]
    Custody,
    #[error("runner certificate renewal identity validation failed")]
    Identity,
    #[error("runner certificate renewal was rejected")]
    Rejected,
    #[error("runner certificate expired before renewal completed")]
    Expired,
}

/// Terminal outcome of the runner-owned renewal supervisor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CertificateRenewalOutcome {
    Renewed,
    Cancelled,
}

/// One locked, reconciled renewal lifecycle bound to the current identity.
pub(crate) struct CertificateRenewal {
    destinations: RenewalDestinations,
    current: CurrentIdentity,
    staged: Option<RenewalStage>,
}

impl CertificateRenewal {
    /// Opens custody and completes any response-backed partial rotation before
    /// callers load TLS material into a transport client.
    pub(crate) fn open(config: &RunnerProductConfig) -> Result<Self, CertificateRenewalError> {
        let now = current_unix_time_seconds().map_err(|_| CertificateRenewalError::Identity)?;
        let destinations = RenewalDestinations::from_sources(config.tls())
            .map_err(|_| CertificateRenewalError::Custody)?;
        let staged = destinations
            .load_request(config)
            .map_err(|_| CertificateRenewalError::Custody)?;
        let response = destinations
            .load_response()
            .map_err(|_| CertificateRenewalError::Custody)?;
        match (staged, response) {
            (Some(stage), Some(response)) => {
                destinations
                    .finish_rotation(config, &stage, &response, now)
                    .map_err(|_| CertificateRenewalError::Identity)?;
                destinations
                    .complete()
                    .map_err(|_| CertificateRenewalError::Custody)?;
            }
            (Some(stage), None) => {
                let current = CurrentIdentity::load(config, &destinations, now)
                    .map_err(|_| CertificateRenewalError::Identity)?;
                stage
                    .validate_pending(config, &current)
                    .map_err(|_| CertificateRenewalError::Identity)?;
                return Ok(Self {
                    destinations,
                    current,
                    staged: Some(stage),
                });
            }
            (None, Some(response)) => {
                destinations
                    .finish_orphaned_response(config, &response, now)
                    .map_err(|_| CertificateRenewalError::Identity)?;
                destinations
                    .remove_response()
                    .map_err(|_| CertificateRenewalError::Custody)?;
            }
            (None, None) => {}
        }
        let current = CurrentIdentity::load(config, &destinations, now)
            .map_err(|_| CertificateRenewalError::Identity)?;
        Ok(Self {
            destinations,
            current,
            staged: None,
        })
    }

    /// Waits for the fixed renewal point, exact-retries one staged request, and
    /// publishes the validated replacement identity durably.
    pub(crate) async fn run(
        mut self,
        config: &RunnerProductConfig,
        client: Arc<dyn RunnerCertificateRenewalClient>,
        cancellation: CancellationToken,
    ) -> Result<CertificateRenewalOutcome, CertificateRenewalError> {
        if self.staged.is_none() {
            let due_at = self
                .current
                .expires_at_seconds
                .saturating_sub(CLIENT_RENEWAL_REMAINING_SECONDS);
            wait_until(due_at, &cancellation).await?;
            if cancellation.is_cancelled() {
                return Ok(CertificateRenewalOutcome::Cancelled);
            }
            self.staged = Some(
                self.destinations
                    .create_request(config, &self.current)
                    .map_err(|_| CertificateRenewalError::Custody)?,
            );
        }
        let stage = self.staged.as_ref().expect("renewal stage is present");
        let request_bytes = stage.request_bytes();
        let prepared = PreparedCertificateRenewalRequest::new(request_bytes)
            .map_err(|_| CertificateRenewalError::Identity)?;
        loop {
            let now = current_unix_time_seconds().map_err(|_| CertificateRenewalError::Identity)?;
            if now >= self.current.expires_at_seconds {
                return Err(CertificateRenewalError::Expired);
            }
            let response = match client.exchange(&prepared, cancellation.clone()).await {
                Ok(response) => response.into_body(),
                Err(_error) if cancellation.is_cancelled() => {
                    return Ok(CertificateRenewalOutcome::Cancelled);
                }
                Err(error) if error.retry_class() == RetryClass::RetrySameRequest => {
                    tokio::select! {
                        biased;
                        () = cancellation.cancelled() => {
                            return Ok(CertificateRenewalOutcome::Cancelled);
                        }
                        () = tokio::time::sleep(RETRY_INTERVAL) => {}
                    }
                    continue;
                }
                Err(_) => return Err(CertificateRenewalError::Rejected),
            };
            let response_stage = RenewalResponseStage::new(stage, response)
                .map_err(|_| CertificateRenewalError::Identity)?;
            self.destinations
                .persist_response(&response_stage)
                .map_err(|_| CertificateRenewalError::Custody)?;
            let now = current_unix_time_seconds().map_err(|_| CertificateRenewalError::Identity)?;
            self.destinations
                .finish_rotation(config, stage, &response_stage, now)
                .map_err(|_| CertificateRenewalError::Identity)?;
            self.destinations
                .complete()
                .map_err(|_| CertificateRenewalError::Custody)?;
            return Ok(CertificateRenewalOutcome::Renewed);
        }
    }
}

impl fmt::Debug for CertificateRenewal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateRenewal")
            .field("expires_at_seconds", &self.current.expires_at_seconds)
            .field("staged", &self.staged.is_some())
            .finish_non_exhaustive()
    }
}

struct RenewalDestinations {
    certificate_chain: PathBuf,
    private_key: PathBuf,
    request_stage: PathBuf,
    response_stage: PathBuf,
    #[cfg(unix)]
    _lock: rustix::fd::OwnedFd,
}

impl RenewalDestinations {
    fn from_sources(sources: &ClientTlsSources) -> Result<Self> {
        fn file(source: &SecretSource) -> Result<PathBuf> {
            let SecretSource::File { path } = source else {
                bail!("runner certificate renewal requires file-backed TLS custody");
            };
            Ok(path.clone())
        }
        let server_roots = file(sources.server_roots())?;
        let certificate_chain = file(sources.certificate_chain())?;
        let private_key = file(sources.private_key())?;
        let request_stage = enrollment_sibling(&private_key, ".automata-renewal-request")?;
        let response_stage = enrollment_sibling(&private_key, ".automata-renewal-response")?;
        let lock_path = enrollment_sibling(&private_key, ".automata-tls-lock")?;
        let final_paths = [
            server_roots,
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
        let lock = crate::enrollment::custody::acquire_enrollment_lock(&lock_path)?;
        Ok(Self {
            certificate_chain,
            private_key,
            request_stage,
            response_stage,
            #[cfg(unix)]
            _lock: lock,
        })
    }

    fn load_request(&self, config: &RunnerProductConfig) -> Result<Option<RenewalStage>> {
        if let Some(bytes) = read_bounded_file(&self.request_stage, MAX_STAGE_BYTES, true)? {
            let stage: RenewalStage = serde_json::from_slice(&bytes)
                .context("runner certificate renewal request stage is invalid")?;
            stage.validate_static(config)?;
            sync_parent(&self.request_stage)?;
            return Ok(Some(stage));
        }
        let Some(bytes) = read_bounded_temporary(&self.request_stage, MAX_STAGE_BYTES, true)?
        else {
            return Ok(None);
        };
        let Ok(stage) = serde_json::from_slice::<RenewalStage>(&bytes) else {
            remove_temporary_durable(&self.request_stage)?;
            return Ok(None);
        };
        stage.validate_static(config)?;
        crate::enrollment::custody::publish_temporary(&self.request_stage)?;
        Ok(Some(stage))
    }

    fn load_response(&self) -> Result<Option<RenewalResponseStage>> {
        if let Some(bytes) = read_bounded_file(&self.response_stage, MAX_STAGE_BYTES, true)? {
            let response: RenewalResponseStage = serde_json::from_slice(&bytes)
                .context("runner certificate renewal response stage is invalid")?;
            response.validate_envelope()?;
            sync_parent(&self.response_stage)?;
            return Ok(Some(response));
        }
        let Some(bytes) = read_bounded_temporary(&self.response_stage, MAX_STAGE_BYTES, true)?
        else {
            return Ok(None);
        };
        let Ok(response) = serde_json::from_slice::<RenewalResponseStage>(&bytes) else {
            remove_temporary_durable(&self.response_stage)?;
            return Ok(None);
        };
        response.validate_envelope()?;
        crate::enrollment::custody::publish_temporary(&self.response_stage)?;
        Ok(Some(response))
    }

    fn create_request(
        &self,
        config: &RunnerProductConfig,
        current: &CurrentIdentity,
    ) -> Result<RenewalStage> {
        let stage = RenewalStage::new(config, current)?;
        let bytes = Zeroizing::new(serde_json::to_vec(&stage)?);
        if bytes.len() > MAX_STAGE_BYTES {
            bail!("runner certificate renewal request stage exceeds its bound");
        }
        persist_new(&self.request_stage, &bytes, true)?;
        Ok(stage)
    }

    fn persist_response(&self, response: &RenewalResponseStage) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(response)?);
        if bytes.len() > MAX_STAGE_BYTES {
            bail!("runner certificate renewal response stage exceeds its bound");
        }
        persist_new(&self.response_stage, &bytes, true)
    }

    fn finish_rotation(
        &self,
        config: &RunnerProductConfig,
        stage: &RenewalStage,
        response_stage: &RenewalResponseStage,
        now: i64,
    ) -> Result<()> {
        response_stage.validate_for(stage)?;
        let response = response_stage.response()?;
        let validated = validate_renewal_response(config, stage, &response, now)?;
        if validated.leaf == stage.presented_leaf_sha256
            || validated.public_key != stage.new_public_key_sha256
        {
            bail!("runner certificate renewal did not replace the presented leaf");
        }
        replace_exact_file(
            &self.certificate_chain,
            &stage.predecessor_chain_sha256,
            response.certificate_chain_pem.as_bytes(),
            false,
        )?;
        replace_exact_file(
            &self.private_key,
            &stage.predecessor_key_sha256,
            stage.private_key_pem.as_bytes(),
            true,
        )?;
        Ok(())
    }

    fn finish_orphaned_response(
        &self,
        config: &RunnerProductConfig,
        response_stage: &RenewalResponseStage,
        now: i64,
    ) -> Result<()> {
        response_stage.validate_envelope()?;
        let response = response_stage.response()?;
        if response.operation_id != response_stage.operation_id
            || response.runner_id != response_stage.runner_id
            || response.runner_id != config.runner_id().as_uuid()
            || response.control_endpoint != response_stage.server_origin
            || response.control_endpoint != config.control_endpoint().to_string()
            || response.certificate_expires_at_seconds
                <= response_stage.presented_expires_at_seconds
            || response_stage.presented_leaf_sha256 == response_stage.renewed_leaf_sha256
        {
            bail!("orphaned runner certificate renewal response is not current");
        }
        let chain = read_bounded_file(&self.certificate_chain, MAX_CERTIFICATE_CHAIN_BYTES, false)?
            .context("runner certificate chain is missing")?;
        if chain.as_slice() != response.certificate_chain_pem.as_bytes() {
            bail!("orphaned runner certificate renewal response was not fully published");
        }
        let current = CurrentIdentity::load(config, self, now)?;
        if current.leaf_sha256 != response_stage.renewed_leaf_sha256
            || current.issuer_sha256 != response_stage.issuer_sha256
            || current.public_key_sha256 != response_stage.new_public_key_sha256
            || current.expires_at_seconds != response.certificate_expires_at_seconds
        {
            bail!("orphaned runner certificate renewal response does not match current identity");
        }
        Ok(())
    }

    fn complete(&self) -> Result<()> {
        remove_durable(&self.request_stage)?;
        self.remove_response()
    }

    fn remove_response(&self) -> Result<()> {
        remove_durable(&self.response_stage)
    }
}

struct CurrentIdentity {
    leaf_sha256: [u8; 32],
    issuer_sha256: [u8; 32],
    public_key_sha256: [u8; 32],
    chain_sha256: [u8; 32],
    key_sha256: [u8; 32],
    expires_at_seconds: i64,
}

impl CurrentIdentity {
    fn load(
        config: &RunnerProductConfig,
        destinations: &RenewalDestinations,
        now: i64,
    ) -> Result<Self> {
        let chain = read_bounded_file(
            &destinations.certificate_chain,
            MAX_CERTIFICATE_CHAIN_BYTES,
            false,
        )?
        .context("runner certificate chain is missing")?;
        let key = read_bounded_file(&destinations.private_key, MAX_PRIVATE_KEY_BYTES, true)?
            .context("runner certificate private key is missing")?;
        let chain_text =
            std::str::from_utf8(&chain).context("runner certificate chain is invalid")?;
        let key_text = std::str::from_utf8(&key).context("runner certificate key is invalid")?;
        let certificates = CertificateDer::pem_slice_iter(chain_text.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let [leaf, _issuer] = certificates.as_slice() else {
            bail!("runner certificate chain does not contain exactly one leaf and issuer");
        };
        let (remainder, parsed) = parse_x509_certificate(leaf.as_ref())?;
        if !remainder.is_empty() {
            bail!("runner certificate leaf has trailing bytes");
        }
        let expires_at_seconds = parsed.validity().not_after.timestamp();
        let validated = validate_issued_runner_certificate(
            config.runner_id().as_uuid(),
            chain_text,
            expires_at_seconds,
            key_text,
            now,
            None,
        )?;
        Ok(Self {
            leaf_sha256: validated.leaf,
            issuer_sha256: validated.issuer,
            public_key_sha256: validated.public_key,
            chain_sha256: Sha256::digest(chain.as_slice()).into(),
            key_sha256: Sha256::digest(key.as_slice()).into(),
            expires_at_seconds,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RenewalStage {
    schema: u8,
    operation_id: Uuid,
    runner_id: Uuid,
    server_origin: String,
    presented_leaf_sha256: [u8; 32],
    presented_expires_at_seconds: i64,
    issuer_sha256: [u8; 32],
    predecessor_chain_sha256: [u8; 32],
    predecessor_key_sha256: [u8; 32],
    new_public_key_sha256: [u8; 32],
    request_sha256: [u8; 32],
    #[serde(
        deserialize_with = "deserialize_zeroizing_bytes",
        serialize_with = "serialize_zeroizing_bytes"
    )]
    request: Zeroizing<Vec<u8>>,
    #[serde(
        deserialize_with = "deserialize_zeroizing_string",
        serialize_with = "serialize_zeroizing_string"
    )]
    private_key_pem: Zeroizing<String>,
}

impl RenewalStage {
    fn new(config: &RunnerProductConfig, current: &CurrentIdentity) -> Result<Self> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, config.runner_id().to_string());
        let mut parameters = CertificateParams::default();
        parameters.distinguished_name = distinguished_name;
        let csr_pem = parameters.serialize_request(&key)?.pem()?;
        let operation_id = Uuid::new_v4();
        let request = RenewalRequestDocument {
            operation_id,
            csr_pem,
        };
        let request_bytes = serde_json::to_vec(&request)?;
        Ok(Self {
            schema: STAGE_SCHEMA,
            operation_id,
            runner_id: config.runner_id().as_uuid(),
            server_origin: config.control_endpoint().to_string(),
            presented_leaf_sha256: current.leaf_sha256,
            presented_expires_at_seconds: current.expires_at_seconds,
            issuer_sha256: current.issuer_sha256,
            predecessor_chain_sha256: current.chain_sha256,
            predecessor_key_sha256: current.key_sha256,
            new_public_key_sha256: Sha256::digest(key.public_key_raw()).into(),
            request_sha256: Sha256::digest(&request_bytes).into(),
            request: Zeroizing::new(request_bytes),
            private_key_pem: Zeroizing::new(key.serialize_pem()),
        })
    }

    fn validate_static(&self, config: &RunnerProductConfig) -> Result<()> {
        if self.schema != STAGE_SCHEMA
            || self.operation_id.is_nil()
            || self.runner_id != config.runner_id().as_uuid()
            || self.server_origin != config.control_endpoint().to_string()
            || self.presented_leaf_sha256 == [0; 32]
            || self.presented_expires_at_seconds <= 0
            || self.issuer_sha256 == [0; 32]
            || self.predecessor_chain_sha256 == [0; 32]
            || self.predecessor_key_sha256 == [0; 32]
            || self.new_public_key_sha256 == [0; 32]
            || self.request_sha256 == [0; 32]
        {
            bail!("runner certificate renewal request stage is invalid");
        }
        let key = KeyPair::from_pem(self.private_key_pem.as_str())?;
        let request: RenewalRequestDocument = serde_json::from_slice(&self.request)?;
        let csr = CertificateSigningRequestParams::from_pem(&request.csr_pem)?;
        if key.algorithm() != &PKCS_ECDSA_P256_SHA256
            || request.operation_id != self.operation_id
            || csr.public_key.algorithm() != &PKCS_ECDSA_P256_SHA256
            || csr.public_key.der_bytes() != key.public_key_raw()
            || Sha256::digest(key.public_key_raw()).as_slice() != self.new_public_key_sha256
            || self.request.is_empty()
            || self.request.len()
                > automata_ci_runner_transport::MAX_CERTIFICATE_RENEWAL_REQUEST_BYTES
            || Sha256::digest(self.request.as_slice()).as_slice() != self.request_sha256
        {
            bail!("runner certificate renewal key and request binding is invalid");
        }
        Ok(())
    }

    fn validate_pending(
        &self,
        config: &RunnerProductConfig,
        current: &CurrentIdentity,
    ) -> Result<()> {
        self.validate_static(config)?;
        if self.presented_leaf_sha256 != current.leaf_sha256
            || self.presented_expires_at_seconds != current.expires_at_seconds
            || self.issuer_sha256 != current.issuer_sha256
            || self.predecessor_chain_sha256 != current.chain_sha256
            || self.predecessor_key_sha256 != current.key_sha256
        {
            bail!("runner certificate renewal stage does not match the current identity");
        }
        Ok(())
    }

    fn request_bytes(&self) -> Vec<u8> {
        self.request.to_vec()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RenewalRequestDocument {
    operation_id: Uuid,
    csr_pem: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RenewalResponseStage {
    schema: u8,
    operation_id: Uuid,
    runner_id: Uuid,
    server_origin: String,
    presented_leaf_sha256: [u8; 32],
    presented_expires_at_seconds: i64,
    issuer_sha256: [u8; 32],
    new_public_key_sha256: [u8; 32],
    request_sha256: [u8; 32],
    response_sha256: [u8; 32],
    renewed_leaf_sha256: [u8; 32],
    #[serde(
        deserialize_with = "deserialize_zeroizing_bytes",
        serialize_with = "serialize_zeroizing_bytes"
    )]
    response: Zeroizing<Vec<u8>>,
}

impl RenewalResponseStage {
    fn new(stage: &RenewalStage, response: Zeroizing<Vec<u8>>) -> Result<Self> {
        let document: RenewalResponseDocument = serde_json::from_slice(&response)?;
        if document.operation_id != stage.operation_id
            || document.runner_id != stage.runner_id
            || document.control_endpoint != stage.server_origin
            || document.certificate_expires_at_seconds <= stage.presented_expires_at_seconds
        {
            bail!("runner certificate renewal response authority is invalid");
        }
        let validated = validate_issued_runner_certificate(
            stage.runner_id,
            &document.certificate_chain_pem,
            document.certificate_expires_at_seconds,
            stage.private_key_pem.as_str(),
            current_unix_time_seconds()?,
            Some(stage.issuer_sha256),
        )?;
        if validated.leaf == stage.presented_leaf_sha256
            || validated.public_key != stage.new_public_key_sha256
        {
            bail!("runner certificate renewal did not replace the presented leaf");
        }
        let response_sha256 = Sha256::digest(response.as_slice()).into();
        let value = Self {
            schema: STAGE_SCHEMA,
            operation_id: stage.operation_id,
            runner_id: stage.runner_id,
            server_origin: stage.server_origin.clone(),
            presented_leaf_sha256: stage.presented_leaf_sha256,
            presented_expires_at_seconds: stage.presented_expires_at_seconds,
            issuer_sha256: stage.issuer_sha256,
            new_public_key_sha256: stage.new_public_key_sha256,
            request_sha256: stage.request_sha256,
            response_sha256,
            renewed_leaf_sha256: validated.leaf,
            response,
        };
        value.validate_for(stage)?;
        Ok(value)
    }

    fn validate_envelope(&self) -> Result<()> {
        if self.schema != STAGE_SCHEMA
            || self.operation_id.is_nil()
            || self.runner_id.is_nil()
            || self.server_origin.is_empty()
            || self.presented_leaf_sha256 == [0; 32]
            || self.presented_expires_at_seconds <= 0
            || self.issuer_sha256 == [0; 32]
            || self.new_public_key_sha256 == [0; 32]
            || self.request_sha256 == [0; 32]
            || self.response_sha256 == [0; 32]
            || self.renewed_leaf_sha256 == [0; 32]
            || self.renewed_leaf_sha256 == self.presented_leaf_sha256
            || self.response.is_empty()
            || self.response.len()
                > automata_ci_runner_transport::MAX_CERTIFICATE_RENEWAL_RESPONSE_BYTES
            || Sha256::digest(self.response.as_slice()).as_slice() != self.response_sha256
        {
            bail!("runner certificate renewal response stage is invalid");
        }
        Ok(())
    }

    fn validate_for(&self, stage: &RenewalStage) -> Result<()> {
        self.validate_envelope()?;
        if self.operation_id != stage.operation_id
            || self.runner_id != stage.runner_id
            || self.server_origin != stage.server_origin
            || self.presented_leaf_sha256 != stage.presented_leaf_sha256
            || self.presented_expires_at_seconds != stage.presented_expires_at_seconds
            || self.issuer_sha256 != stage.issuer_sha256
            || self.new_public_key_sha256 != stage.new_public_key_sha256
            || self.request_sha256 != stage.request_sha256
        {
            bail!("runner certificate renewal response stage does not match its request");
        }
        Ok(())
    }

    fn response(&self) -> Result<RenewalResponseDocument> {
        Ok(serde_json::from_slice(&self.response)?)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewalResponseDocument {
    operation_id: Uuid,
    runner_id: Uuid,
    control_endpoint: String,
    certificate_chain_pem: String,
    certificate_expires_at_seconds: i64,
}

fn validate_renewal_response(
    config: &RunnerProductConfig,
    stage: &RenewalStage,
    response: &RenewalResponseDocument,
    now: i64,
) -> Result<crate::enrollment::custody::ValidatedRunnerCertificate> {
    if response.operation_id != stage.operation_id
        || response.runner_id != stage.runner_id
        || response.runner_id != config.runner_id().as_uuid()
        || response.control_endpoint != stage.server_origin
        || response.control_endpoint != config.control_endpoint().to_string()
        || response.certificate_expires_at_seconds <= stage.presented_expires_at_seconds
    {
        bail!("runner certificate renewal response authority does not match");
    }
    validate_issued_runner_certificate(
        stage.runner_id,
        &response.certificate_chain_pem,
        response.certificate_expires_at_seconds,
        stage.private_key_pem.as_str(),
        now,
        Some(stage.issuer_sha256),
    )
}

async fn wait_until(
    deadline_seconds: i64,
    cancellation: &CancellationToken,
) -> Result<(), CertificateRenewalError> {
    loop {
        let now = current_unix_time_seconds().map_err(|_| CertificateRenewalError::Identity)?;
        if now >= deadline_seconds {
            return Ok(());
        }
        let seconds =
            u64::try_from(deadline_seconds - now).map_err(|_| CertificateRenewalError::Identity)?;
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            () = tokio::time::sleep(Duration::from_secs(seconds.min(CLOCK_RECHECK_SECONDS))) => {}
        }
    }
}

fn current_unix_time_seconds() -> Result<i64> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    i64::try_from(seconds).context("runner certificate renewal clock is out of range")
}

fn serialize_zeroizing_string<S>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.as_str())
}

fn deserialize_zeroizing_string<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

fn serialize_zeroizing_bytes<S>(
    value: &Zeroizing<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded = Zeroizing::new(STANDARD.encode(value.as_slice()));
    serializer.serialize_str(encoded.as_str())
}

fn deserialize_zeroizing_bytes<'de, D>(deserializer: D) -> Result<Zeroizing<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = Zeroizing::new(String::deserialize(deserializer)?);
    STANDARD
        .decode(encoded.as_bytes())
        .map(Zeroizing::new)
        .map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::fs;

    #[cfg(target_os = "linux")]
    use rcgen::{
        BasicConstraints, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
    };

    #[cfg(target_os = "linux")]
    use super::*;

    #[cfg(target_os = "linux")]
    fn product_config(root: &std::path::Path, runner_id: Uuid) -> RunnerProductConfig {
        let mut document: serde_json::Value =
            serde_json::from_slice(include_bytes!("../config/runner.local-1.example.json"))
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

    #[cfg(target_os = "linux")]
    fn issuer() -> CertifiedIssuer<'static, KeyPair> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        CertifiedIssuer::self_signed(parameters, key).expect("runner issuer")
    }

    #[cfg(target_os = "linux")]
    fn runner_chain(
        issuer: &CertifiedIssuer<'_, KeyPair>,
        runner_id: Uuid,
        key: &KeyPair,
        expires_at_seconds: i64,
    ) -> String {
        let mut parameters = CertificateParams::default();
        parameters
            .distinguished_name
            .push(DnType::CommonName, runner_id.to_string());
        parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        parameters.not_after = time::OffsetDateTime::from_unix_timestamp(expires_at_seconds)
            .expect("certificate expiry");
        let leaf = parameters.signed_by(key, issuer).expect("runner leaf");
        format!("{}{}", leaf.pem(), issuer.pem())
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[allow(
        clippy::too_many_lines,
        reason = "one crash fixture retains the staged key, exact response, partial file rotation, and recovery proof"
    )]
    fn partial_rotation_recovers_only_from_a_key_bound_exact_response() {
        let root = std::env::current_dir()
            .expect("current directory")
            .join(format!(".automata-renewal-test-{}", Uuid::new_v4()));
        fs::create_dir(&root).expect("test root");
        let runner_id = Uuid::new_v4();
        let config = product_config(&root, runner_id);
        let now = current_unix_time_seconds().expect("current time");
        let presented_expiry = now + 8 * 24 * 60 * 60;
        let renewed_expiry = now + 30 * 24 * 60 * 60;
        let issuer = issuer();
        let presented_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("presented key");
        let presented_chain = runner_chain(&issuer, runner_id, &presented_key, presented_expiry);
        let certificate_path = root.join("runner-chain.pem");
        let key_path = root.join("runner-key.pem");
        persist_new(&certificate_path, presented_chain.as_bytes(), false)
            .expect("presented certificate");
        persist_new(&key_path, presented_key.serialize_pem().as_bytes(), true)
            .expect("presented key custody");

        let renewal = CertificateRenewal::open(&config).expect("open current identity");
        let stage = renewal
            .destinations
            .create_request(&config, &renewal.current)
            .expect("durable renewal request");
        let staged_request_bytes =
            fs::read(&renewal.destinations.request_stage).expect("persisted renewal request stage");
        assert!(staged_request_bytes.len() <= MAX_STAGE_BYTES);
        let staged_request_document: serde_json::Value =
            serde_json::from_slice(&staged_request_bytes).expect("request stage document");
        let exact_request = STANDARD
            .decode(
                staged_request_document["request"]
                    .as_str()
                    .expect("base64 exact request"),
            )
            .expect("exact request encoding");
        assert_eq!(exact_request.as_slice(), stage.request.as_slice());
        let renewed_key = KeyPair::from_pem(stage.private_key_pem.as_str()).expect("staged key");
        let renewed_key_pem = renewed_key.serialize_pem();
        let renewed_chain = runner_chain(&issuer, runner_id, &renewed_key, renewed_expiry);
        let response = serde_json::to_vec(&serde_json::json!({
            "operation_id": stage.operation_id,
            "runner_id": runner_id,
            "control_endpoint": stage.server_origin,
            "certificate_chain_pem": renewed_chain,
            "certificate_expires_at_seconds": renewed_expiry,
        }))
        .expect("renewal response");
        let response_stage = RenewalResponseStage::new(&stage, Zeroizing::new(response.clone()))
            .expect("validated response stage");
        let renewed_leaf_sha256 = response_stage.renewed_leaf_sha256;
        renewal
            .destinations
            .persist_response(&response_stage)
            .expect("durable response stage");
        let staged_response_bytes = fs::read(&renewal.destinations.response_stage)
            .expect("persisted renewal response stage");
        assert!(staged_response_bytes.len() <= MAX_STAGE_BYTES);
        let staged_response_document: serde_json::Value =
            serde_json::from_slice(&staged_response_bytes).expect("response stage document");
        assert!(staged_response_document["response"].is_string());

        let mut wrong_authority: serde_json::Value =
            serde_json::from_slice(&response).expect("response value");
        wrong_authority["control_endpoint"] =
            serde_json::Value::String("https://different.example.test/".to_owned());
        assert!(
            RenewalResponseStage::new(
                &stage,
                Zeroizing::new(serde_json::to_vec(&wrong_authority).expect("wrong response")),
            )
            .is_err(),
            "response authority must be bound before persistence"
        );

        let wrong_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("wrong key");
        let wrong_chain = runner_chain(&issuer, runner_id, &wrong_key, renewed_expiry);
        let wrong_key_response = serde_json::to_vec(&serde_json::json!({
            "operation_id": stage.operation_id,
            "runner_id": runner_id,
            "control_endpoint": stage.server_origin,
            "certificate_chain_pem": wrong_chain,
            "certificate_expires_at_seconds": renewed_expiry,
        }))
        .expect("wrong-key response");
        assert!(
            RenewalResponseStage::new(&stage, Zeroizing::new(wrong_key_response)).is_err(),
            "returned leaf must match the staged private key"
        );

        replace_exact_file(
            &certificate_path,
            &stage.predecessor_chain_sha256,
            renewed_chain.as_bytes(),
            false,
        )
        .expect("simulate crash after certificate publication");
        drop((response_stage, stage, renewal));

        let recovered = CertificateRenewal::open(&config)
            .expect("response-backed partial rotation must recover");
        assert_eq!(recovered.current.leaf_sha256, renewed_leaf_sha256);
        assert_eq!(
            fs::read_to_string(&certificate_path).expect("recovered chain"),
            renewed_chain
        );
        assert_eq!(
            fs::read_to_string(&key_path).expect("recovered key"),
            renewed_key_pem
        );
        assert!(!recovered.destinations.request_stage.exists());
        assert!(!recovered.destinations.response_stage.exists());

        let orphan_expiry = now + 60 * 24 * 60 * 60;
        let orphan_stage = recovered
            .destinations
            .create_request(&config, &recovered.current)
            .expect("second durable request");
        let orphan_key =
            KeyPair::from_pem(orphan_stage.private_key_pem.as_str()).expect("second staged key");
        let orphan_chain = runner_chain(&issuer, runner_id, &orphan_key, orphan_expiry);
        let orphan_response = serde_json::to_vec(&serde_json::json!({
            "operation_id": orphan_stage.operation_id,
            "runner_id": runner_id,
            "control_endpoint": orphan_stage.server_origin,
            "certificate_chain_pem": orphan_chain,
            "certificate_expires_at_seconds": orphan_expiry,
        }))
        .expect("second response");
        let orphan_response_stage =
            RenewalResponseStage::new(&orphan_stage, Zeroizing::new(orphan_response))
                .expect("second response stage");
        let orphan_leaf_sha256 = orphan_response_stage.renewed_leaf_sha256;
        recovered
            .destinations
            .persist_response(&orphan_response_stage)
            .expect("second durable response");
        replace_exact_file(
            &certificate_path,
            &orphan_stage.predecessor_chain_sha256,
            orphan_chain.as_bytes(),
            false,
        )
        .expect("second certificate publication");
        replace_exact_file(
            &key_path,
            &orphan_stage.predecessor_key_sha256,
            orphan_stage.private_key_pem.as_bytes(),
            true,
        )
        .expect("second key publication");
        remove_durable(&recovered.destinations.request_stage)
            .expect("simulate crash after request-stage cleanup");
        drop((orphan_response_stage, orphan_stage, recovered));

        let orphan_recovered =
            CertificateRenewal::open(&config).expect("fully published orphan response");
        assert_eq!(orphan_recovered.current.leaf_sha256, orphan_leaf_sha256);
        assert!(!orphan_recovered.destinations.response_stage.exists());

        let incomplete_expiry = now + 90 * 24 * 60 * 60;
        let incomplete_stage = orphan_recovered
            .destinations
            .create_request(&config, &orphan_recovered.current)
            .expect("third durable request");
        let incomplete_key =
            KeyPair::from_pem(incomplete_stage.private_key_pem.as_str()).expect("third staged key");
        let incomplete_chain = runner_chain(&issuer, runner_id, &incomplete_key, incomplete_expiry);
        let incomplete_response = serde_json::to_vec(&serde_json::json!({
            "operation_id": incomplete_stage.operation_id,
            "runner_id": runner_id,
            "control_endpoint": incomplete_stage.server_origin,
            "certificate_chain_pem": incomplete_chain,
            "certificate_expires_at_seconds": incomplete_expiry,
        }))
        .expect("third response");
        let incomplete_response_stage =
            RenewalResponseStage::new(&incomplete_stage, Zeroizing::new(incomplete_response))
                .expect("third response stage");
        orphan_recovered
            .destinations
            .persist_response(&incomplete_response_stage)
            .expect("third durable response");
        replace_exact_file(
            &key_path,
            &incomplete_stage.predecessor_key_sha256,
            incomplete_stage.private_key_pem.as_bytes(),
            true,
        )
        .expect("simulate incomplete orphan key publication");
        remove_durable(&orphan_recovered.destinations.request_stage)
            .expect("simulate invalid premature request cleanup");
        let response_path = orphan_recovered.destinations.response_stage.clone();
        drop((
            incomplete_response_stage,
            incomplete_stage,
            orphan_recovered,
        ));
        assert!(matches!(
            CertificateRenewal::open(&config),
            Err(CertificateRenewalError::Identity)
        ));
        assert!(
            response_path.exists(),
            "failed orphan reconciliation must retain its exact response authority"
        );
        fs::remove_dir_all(&root).expect("remove renewal test root");
    }
}
