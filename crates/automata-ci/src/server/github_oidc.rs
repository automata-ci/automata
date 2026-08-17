//! Product composition for the optional GitHub-compatible workload OIDC surface.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr as _,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use automata_ci_control::github_oidc::{
    GithubOidcAuthorityProvisioner, GithubOidcRuntimeAuthorityIssuer,
    RandomGithubOidcAuthorityIdGenerator, ReserveGithubOidcRuntimeAuthority,
    ReservedGithubOidcRuntimeAuthority, UnavailableGithubOidcRuntimeAuthorityIssuer,
};
use automata_ci_control::runner_control::{
    CompositeRuntimeAuthorityIssuer, ControlPortError, OptionalRuntimeAuthorityIssuer,
    RuntimeAuthorityIssuer,
};
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_oidc_github::{
    GithubOidcApi, MAXIMUM_OIDC_KEYS_PER_KEYRING, MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS,
    OidcClock, OidcClockError, OidcIssuanceRepository, OidcIssuer, OidcKeyId, OidcService,
    OidcSupportedClaims, OidcTokenLifetime, RequestBearerConfig, RequestBearerKey,
    RequestBearerKeyring, Rs256Keyring, Rs256SigningKey, RsaPublicJwk,
};
use automata_ci_results_github::ResultsPublicEndpoint;
use automata_ci_store::{
    GITHUB_OIDC_REQUEST_BEARER_KEY_FINGERPRINT_DOMAIN, GithubOidcAuthorityProposal,
    GithubOidcAuthorityRepository, GithubOidcCurrentPolicy, GithubOidcCurrentnessClock,
    GithubOidcCurrentnessClockError, GithubOidcExecutionIdentity, GithubOidcKeyUse,
    GithubOidcLoadedKey, GithubOidcStoreError, GithubOidcSubjectPolicyMode,
    GithubOidcSubjectPolicyRevision, ReserveGithubOidcAuthority,
    github_oidc_rs256_public_key_fingerprint,
};
use automata_ci_store_postgres::{
    PostgresGithubOidcAuthorityRepository, PostgresGithubOidcIssuanceRepository, PostgresStore,
};
use axum::{
    Router,
    error_handling::HandleErrorLayer,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tower::{ServiceBuilder, timeout::TimeoutLayer};

use super::{SecretLoadError, SecretSource};

const MANIFEST_SCHEMA: u16 = 1;
const MAXIMUM_MANIFEST_BYTES: usize = 256 * 1_024;
const MAXIMUM_HMAC_KEY_BYTES: usize = 16 * 1_024;
const MAXIMUM_RSA_PRIVATE_KEY_BYTES: usize = 64 * 1_024;
const OIDC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_BEARER_AUDIENCE: &str = "automata-ci:github-oidc-mint";
const SUBJECT_POLICY_FINGERPRINT_DOMAIN: &[u8] =
    b"automata/github-oidc/stable-owner-subject-policy:v1\0";
const CONFIGURATION_FINGERPRINT_DOMAIN: &[u8] = b"automata/github-oidc/product-configuration:v1\0";

const PRODUCT_SUPPORTED_CLAIMS: [&str; 11] = [
    "event_name",
    "ref",
    "repository",
    "repository_owner",
    "run_attempt",
    "run_number",
    "runner_environment",
    "sha",
    "workflow",
    "workflow_ref",
    "workflow_sha",
];

/// Sanitized OIDC product configuration or key-loading failure.
#[derive(Debug, Error)]
pub enum GithubOidcProductError {
    /// The optional manifest was malformed, incomplete, excessive, or incoherent.
    #[error("GitHub-compatible OIDC configuration is invalid")]
    InvalidConfiguration,
    /// A referenced private key could not be loaded through the privileged source boundary.
    #[error(transparent)]
    Secret(#[from] SecretLoadError),
    /// Durable key-retention state does not match this replica's complete loaded key set.
    #[error("GitHub-compatible OIDC durable key readiness failed")]
    KeyReadiness,
}

/// Validated optional product configuration with no loaded key material.
#[derive(Clone)]
pub struct GithubOidcConfig {
    issuer: OidcIssuer,
    subject_policy_revision: GithubOidcSubjectPolicyRevision,
    subject_policy_sha256: Sha256Digest,
    configuration_sha256: Sha256Digest,
    supported_claims: OidcSupportedClaims,
    supported_additional_claims: BTreeSet<String>,
    request_bearer: RequestBearerManifest,
    id_token: IdTokenManifest,
}

impl GithubOidcConfig {
    /// Loads and validates one strict current manifest from a redacted source.
    ///
    /// The issuer is always derived from the dedicated Results public endpoint;
    /// the manifest cannot override it. Enabling OIDC therefore additionally
    /// requires that endpoint to be an exact HTTPS root origin.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration error when the source cannot be read
    /// within its bound or any manifest field violates the current contract.
    pub fn load(
        source: &SecretSource,
        results_endpoint: &ResultsPublicEndpoint,
    ) -> Result<Self, GithubOidcProductError> {
        let bytes = source
            .load_bytes(MAXIMUM_MANIFEST_BYTES)
            .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
        let raw: RawManifest = serde_json::from_slice(&bytes)
            .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
        Self::from_raw(raw, results_endpoint)
    }

    fn from_raw(
        raw: RawManifest,
        results_endpoint: &ResultsPublicEndpoint,
    ) -> Result<Self, GithubOidcProductError> {
        if raw.schema != MANIFEST_SCHEMA || raw.subject_policy.mode != "stable_owner_evidence" {
            return Err(GithubOidcProductError::InvalidConfiguration);
        }
        let issuer = OidcIssuer::https(results_endpoint.url().clone())
            .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
        let subject_policy_revision =
            GithubOidcSubjectPolicyRevision::new(raw.subject_policy.revision)
                .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
        let supported_additional_claims = validate_supported_claims(&raw.supported_claims)?;
        let supported_claims = OidcSupportedClaims::new(raw.supported_claims)
            .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
        let request_bearer = RequestBearerManifest::validate(raw.request_bearer, &issuer)?;
        let id_token = IdTokenManifest::validate(raw.id_token)?;
        let subject_policy_sha256 = subject_policy_fingerprint();
        let configuration_sha256 = configuration_fingerprint(
            &issuer,
            &supported_additional_claims,
            &request_bearer,
            &id_token,
        );
        Ok(Self {
            issuer,
            subject_policy_revision,
            subject_policy_sha256,
            configuration_sha256,
            supported_claims,
            supported_additional_claims,
            request_bearer,
            id_token,
        })
    }

    /// Returns the exact HTTPS root shared by discovery, tokens, and runner authority.
    #[must_use]
    pub const fn issuer(&self) -> &OidcIssuer {
        &self.issuer
    }

    fn current_policy(&self) -> Result<GithubOidcCurrentPolicy, GithubOidcProductError> {
        GithubOidcCurrentPolicy::new(
            GithubOidcSubjectPolicyMode::StableOwnerEvidence,
            self.subject_policy_revision,
            self.subject_policy_sha256,
            self.configuration_sha256,
            self.request_bearer.allowed_clock_skew_seconds,
            self.id_token.verifier_skew_seconds,
        )
        .map_err(|_| GithubOidcProductError::InvalidConfiguration)
    }

    fn load_keyrings(&self) -> Result<LoadedKeyrings, GithubOidcProductError> {
        let request_config = RequestBearerConfig::new(
            self.issuer.as_str(),
            REQUEST_BEARER_AUDIENCE,
            self.request_bearer.maximum_lifetime_seconds,
            self.request_bearer.allowed_clock_skew_seconds,
        )
        .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
        let mut request_keys = Vec::with_capacity(self.request_bearer.keys.len());
        let mut request_key_evidence = Vec::with_capacity(self.request_bearer.keys.len());
        let mut request_key_fingerprints = BTreeMap::new();
        let mut unique_request_key_fingerprints = BTreeSet::new();
        for spec in &self.request_bearer.keys {
            let secret = spec.source.load_bytes(MAXIMUM_HMAC_KEY_BYTES)?;
            let fingerprint = request_bearer_key_fingerprint(&secret);
            if !unique_request_key_fingerprints.insert(fingerprint) {
                return Err(GithubOidcProductError::InvalidConfiguration);
            }
            let key = RequestBearerKey::new(spec.key_id.clone(), &secret)
                .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
            request_key_evidence.push(GithubOidcLoadedKey::new(
                GithubOidcKeyUse::RequestBearer,
                spec.key_id.clone(),
                fingerprint,
            ));
            request_key_fingerprints.insert(spec.key_id.clone(), fingerprint);
            request_keys.push(key);
        }
        let request_bearers = Arc::new(
            RequestBearerKeyring::new(
                request_config,
                self.request_bearer.active_key_id.clone(),
                request_keys,
            )
            .map_err(|_| GithubOidcProductError::InvalidConfiguration)?,
        );

        let mut signing_keys = Vec::with_capacity(self.id_token.keys.len());
        let mut signing_key_evidence = Vec::with_capacity(self.id_token.keys.len());
        let mut unique_signing_key_fingerprints = BTreeSet::new();
        for spec in &self.id_token.keys {
            let fingerprint = github_oidc_rs256_public_key_fingerprint(&spec.public_jwk);
            if !unique_signing_key_fingerprints.insert(fingerprint) {
                return Err(GithubOidcProductError::InvalidConfiguration);
            }
            let private_key = spec.source.load_bytes(MAXIMUM_RSA_PRIVATE_KEY_BYTES)?;
            let private_key = std::str::from_utf8(&private_key)
                .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
            signing_key_evidence.push(GithubOidcLoadedKey::new(
                GithubOidcKeyUse::IdTokenSigning,
                spec.public_jwk.key_id().clone(),
                fingerprint,
            ));
            signing_keys.push(
                Rs256SigningKey::from_pem(private_key, spec.public_jwk.clone())
                    .map_err(|_| GithubOidcProductError::InvalidConfiguration)?,
            );
        }
        let signing_keys = Arc::new(
            Rs256Keyring::new(self.id_token.active_key_id.clone(), signing_keys)
                .map_err(|_| GithubOidcProductError::InvalidConfiguration)?,
        );
        Ok(LoadedKeyrings {
            request_bearers,
            signing_keys,
            request_key_evidence,
            signing_key_evidence,
            request_key_fingerprints,
        })
    }
}

impl fmt::Debug for GithubOidcConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubOidcConfig")
            .field("issuer", &self.issuer)
            .field("subject_policy_revision", &self.subject_policy_revision)
            .field("subject_policy_sha256", &self.subject_policy_sha256)
            .field("configuration_sha256", &self.configuration_sha256)
            .field("supported_claims", &self.supported_claims.as_slice())
            .field(
                "supported_additional_claims",
                &self.supported_additional_claims,
            )
            .field("request_bearer_key_count", &self.request_bearer.keys.len())
            .field("id_token_key_count", &self.id_token.keys.len())
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    schema: u16,
    subject_policy: RawSubjectPolicy,
    supported_claims: Vec<String>,
    request_bearer: RawRequestBearerManifest,
    id_token: RawIdTokenManifest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawSubjectPolicy {
    mode: String,
    revision: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawRequestBearerManifest {
    maximum_lifetime_seconds: u64,
    allowed_clock_skew_seconds: u64,
    keys: Vec<RawRequestBearerKey>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawRequestBearerKey {
    key_id: String,
    lifecycle: RawKeyLifecycle,
    source: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawIdTokenManifest {
    lifetime_seconds: u64,
    verifier_skew_seconds: u64,
    keys: Vec<RawRs256Key>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawRs256Key {
    key_id: String,
    lifecycle: RawKeyLifecycle,
    private_key_source: String,
    modulus: String,
    exponent: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RawKeyLifecycle {
    Active,
    Prepublished,
    Retained,
}

#[derive(Clone)]
struct RequestBearerManifest {
    maximum_lifetime_seconds: u64,
    allowed_clock_skew_seconds: u64,
    active_key_id: OidcKeyId,
    keys: Vec<RequestBearerKeySpec>,
}

impl RequestBearerManifest {
    fn validate(
        raw: RawRequestBearerManifest,
        issuer: &OidcIssuer,
    ) -> Result<Self, GithubOidcProductError> {
        RequestBearerConfig::new(
            issuer.as_str(),
            REQUEST_BEARER_AUDIENCE,
            raw.maximum_lifetime_seconds,
            raw.allowed_clock_skew_seconds,
        )
        .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
        if raw.keys.is_empty() || raw.keys.len() > MAXIMUM_OIDC_KEYS_PER_KEYRING {
            return Err(GithubOidcProductError::InvalidConfiguration);
        }
        let mut seen = BTreeSet::new();
        let mut active_key_id = None;
        let mut keys = Vec::with_capacity(raw.keys.len());
        for raw_key in raw.keys {
            if raw_key.lifecycle == RawKeyLifecycle::Prepublished {
                return Err(GithubOidcProductError::InvalidConfiguration);
            }
            let key_id = OidcKeyId::new(raw_key.key_id)
                .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
            if !seen.insert(key_id.clone()) {
                return Err(GithubOidcProductError::InvalidConfiguration);
            }
            if raw_key.lifecycle == RawKeyLifecycle::Active
                && active_key_id.replace(key_id.clone()).is_some()
            {
                return Err(GithubOidcProductError::InvalidConfiguration);
            }
            keys.push(RequestBearerKeySpec {
                key_id,
                source: parse_secret_source(&raw_key.source)?,
            });
        }
        let active_key_id = active_key_id.ok_or(GithubOidcProductError::InvalidConfiguration)?;
        Ok(Self {
            maximum_lifetime_seconds: raw.maximum_lifetime_seconds,
            allowed_clock_skew_seconds: raw.allowed_clock_skew_seconds,
            active_key_id,
            keys,
        })
    }
}

#[derive(Clone)]
struct RequestBearerKeySpec {
    key_id: OidcKeyId,
    source: SecretSource,
}

#[derive(Clone)]
struct IdTokenManifest {
    lifetime_seconds: u64,
    verifier_skew_seconds: u64,
    active_key_id: OidcKeyId,
    keys: Vec<Rs256KeySpec>,
}

impl IdTokenManifest {
    fn validate(raw: RawIdTokenManifest) -> Result<Self, GithubOidcProductError> {
        OidcTokenLifetime::from_seconds(raw.lifetime_seconds)
            .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
        if raw.verifier_skew_seconds > MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS
            || raw.keys.is_empty()
            || raw.keys.len() > MAXIMUM_OIDC_KEYS_PER_KEYRING
        {
            return Err(GithubOidcProductError::InvalidConfiguration);
        }
        let mut seen = BTreeSet::new();
        let mut active_key_id = None;
        let mut keys = Vec::with_capacity(raw.keys.len());
        for raw_key in raw.keys {
            let key_id = OidcKeyId::new(raw_key.key_id)
                .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
            if !seen.insert(key_id.clone()) {
                return Err(GithubOidcProductError::InvalidConfiguration);
            }
            if raw_key.lifecycle == RawKeyLifecycle::Active
                && active_key_id.replace(key_id.clone()).is_some()
            {
                return Err(GithubOidcProductError::InvalidConfiguration);
            }
            let public_jwk = RsaPublicJwk::new(key_id, raw_key.modulus, raw_key.exponent)
                .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
            keys.push(Rs256KeySpec {
                public_jwk,
                source: parse_secret_source(&raw_key.private_key_source)?,
            });
        }
        let active_key_id = active_key_id.ok_or(GithubOidcProductError::InvalidConfiguration)?;
        Ok(Self {
            lifetime_seconds: raw.lifetime_seconds,
            verifier_skew_seconds: raw.verifier_skew_seconds,
            active_key_id,
            keys,
        })
    }
}

#[derive(Clone)]
struct Rs256KeySpec {
    public_jwk: RsaPublicJwk,
    source: SecretSource,
}

fn parse_secret_source(value: &str) -> Result<SecretSource, GithubOidcProductError> {
    let source = SecretSource::from_str(value).unwrap_or(SecretSource::Invalid);
    if matches!(source, SecretSource::Invalid) {
        return Err(GithubOidcProductError::InvalidConfiguration);
    }
    Ok(source)
}

fn validate_supported_claims(
    claims: &[String],
) -> Result<BTreeSet<String>, GithubOidcProductError> {
    let configured = claims.iter().cloned().collect::<BTreeSet<_>>();
    let expected = PRODUCT_SUPPORTED_CLAIMS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if configured.len() != claims.len() || configured != expected {
        return Err(GithubOidcProductError::InvalidConfiguration);
    }
    Ok(configured)
}

fn subject_policy_fingerprint() -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(SUBJECT_POLICY_FINGERPRINT_DOMAIN);
    hasher.update(b"stable_owner_evidence\0signed-positive-owner-id\0ref-or-pull-request\0");
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn configuration_fingerprint(
    issuer: &OidcIssuer,
    supported_claims: &BTreeSet<String>,
    request_bearer: &RequestBearerManifest,
    id_token: &IdTokenManifest,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(CONFIGURATION_FINGERPRINT_DOMAIN);
    hash_length_prefixed(&mut hasher, issuer.as_str().as_bytes());
    hash_length_prefixed(&mut hasher, REQUEST_BEARER_AUDIENCE.as_bytes());
    hasher.update(request_bearer.maximum_lifetime_seconds.to_be_bytes());
    hasher.update(request_bearer.allowed_clock_skew_seconds.to_be_bytes());
    hasher.update(id_token.lifetime_seconds.to_be_bytes());
    hasher.update(id_token.verifier_skew_seconds.to_be_bytes());
    hasher.update(
        u64::try_from(supported_claims.len())
            .expect("the claim universe is statically bounded")
            .to_be_bytes(),
    );
    for claim in supported_claims {
        hash_length_prefixed(&mut hasher, claim.as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn request_bearer_key_fingerprint(secret: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(GITHUB_OIDC_REQUEST_BEARER_KEY_FINGERPRINT_DOMAIN);
    hasher.update(
        u64::try_from(secret.len())
            .expect("loaded HMAC keys are bounded")
            .to_be_bytes(),
    );
    hasher.update(secret);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(
        u64::try_from(value.len())
            .expect("OIDC product configuration is bounded")
            .to_be_bytes(),
    );
    hasher.update(value);
}

struct LoadedKeyrings {
    request_bearers: Arc<RequestBearerKeyring>,
    signing_keys: Arc<Rs256Keyring>,
    request_key_evidence: Vec<GithubOidcLoadedKey>,
    signing_key_evidence: Vec<GithubOidcLoadedKey>,
    request_key_fingerprints: BTreeMap<OidcKeyId, Sha256Digest>,
}

trait GithubOidcProvisionerClock: fmt::Debug + Send + Sync {
    fn now_millis(&self) -> Result<UnixMillis, ()>;
}

#[derive(Clone, Copy, Debug, Default)]
struct SystemGithubOidcClock;

impl GithubOidcProvisionerClock for SystemGithubOidcClock {
    fn now_millis(&self) -> Result<UnixMillis, ()> {
        let millis = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| ())?
            .as_millis();
        let millis = i64::try_from(millis).map_err(|_| ())?;
        Ok(UnixMillis::new(millis))
    }
}

impl OidcClock for SystemGithubOidcClock {
    fn now_seconds(&self) -> Result<u64, OidcClockError> {
        let millis = GithubOidcProvisionerClock::now_millis(self).map_err(|()| OidcClockError)?;
        u64::try_from(millis.get() / 1_000).map_err(|_| OidcClockError)
    }
}

impl GithubOidcCurrentnessClock for SystemGithubOidcClock {
    fn now_millis(&self) -> Result<UnixMillis, GithubOidcCurrentnessClockError> {
        GithubOidcProvisionerClock::now_millis(self).map_err(|()| GithubOidcCurrentnessClockError)
    }
}

struct ProductGithubOidcProvisioner {
    repository: Arc<dyn GithubOidcAuthorityRepository>,
    clock: Arc<dyn GithubOidcProvisionerClock>,
    current_policy: GithubOidcCurrentPolicy,
    request_key_fingerprints: BTreeMap<OidcKeyId, Sha256Digest>,
}

impl ProductGithubOidcProvisioner {
    fn new(
        repository: Arc<dyn GithubOidcAuthorityRepository>,
        clock: Arc<dyn GithubOidcProvisionerClock>,
        current_policy: GithubOidcCurrentPolicy,
        request_key_fingerprints: BTreeMap<OidcKeyId, Sha256Digest>,
    ) -> Self {
        Self {
            repository,
            clock,
            current_policy,
            request_key_fingerprints,
        }
    }
}

impl fmt::Debug for ProductGithubOidcProvisioner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductGithubOidcProvisioner")
            .field("repository", &"[configured]")
            .field("clock", &"[injected]")
            .field("current_policy", &self.current_policy)
            .field("request_key_count", &self.request_key_fingerprints.len())
            .finish()
    }
}

#[async_trait]
impl GithubOidcAuthorityProvisioner for ProductGithubOidcProvisioner {
    async fn reserve_github_oidc_runtime_authority(
        &self,
        request: ReserveGithubOidcRuntimeAuthority<'_>,
    ) -> Result<ReservedGithubOidcRuntimeAuthority, ControlPortError> {
        let runtime = request.runtime_authority_request();
        let job = runtime.job();
        let repository_name =
            automata_ci_store::GithubRepositoryName::new(job.source().repository().to_owned())
                .map_err(|_| ControlPortError::Corrupt)?;
        let execution = GithubOidcExecutionIdentity::new(
            job.workflow_id(),
            repository_name,
            job.job().run_id(),
            job.job().job_id(),
            runtime.lease().clone(),
            runtime.session(),
            runtime.slot(),
            runtime.job_ir_metadata().clone(),
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        let request_key_sha256 = self
            .request_key_fingerprints
            .get(request.proposed_request_bearer_key_id())
            .copied()
            .ok_or(ControlPortError::Corrupt)?;
        let proposal = GithubOidcAuthorityProposal::new(
            request.proposed_authority_id(),
            request.proposed_request_bearer_key_id().clone(),
            request_key_sha256,
            self.current_policy
                .request_bearer_verification_skew_seconds(),
            request.proposed_issued_at_seconds(),
            request.proposed_expires_at_seconds(),
            request.proposed_request_bearer_sha256(),
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        let observed_at = self
            .clock
            .now_millis()
            .map_err(|()| ControlPortError::Unavailable)?;
        let reserve =
            ReserveGithubOidcAuthority::new(execution, self.current_policy, proposal, observed_at)
                .map_err(|_| ControlPortError::Conflict)?;
        let reserved = self
            .repository
            .reserve_github_oidc_authority(reserve)
            .await
            .map_err(map_store_error)?;
        Ok(ReservedGithubOidcRuntimeAuthority::new(
            reserved.authority_id(),
            reserved.request_bearer_key_id().clone(),
            reserved.issued_at_seconds(),
            reserved.expires_at_seconds(),
            reserved.request_bearer_sha256(),
        ))
    }
}

const fn map_store_error(error: GithubOidcStoreError) -> ControlPortError {
    match error {
        GithubOidcStoreError::Unavailable => ControlPortError::Unavailable,
        GithubOidcStoreError::CorruptData => ControlPortError::Corrupt,
        GithubOidcStoreError::Unauthorized
        | GithubOidcStoreError::Conflict
        | GithubOidcStoreError::ResourceExhausted => ControlPortError::Conflict,
    }
}

/// OIDC routes and optional authority contribution admitted for one replica.
pub(crate) struct GithubOidcProduct {
    pub(crate) router: Router,
    pub(crate) authority_issuer: Arc<dyn OptionalRuntimeAuthorityIssuer>,
    operationally_ready: bool,
}

impl GithubOidcProduct {
    pub(crate) fn unavailable() -> Self {
        Self {
            router: Router::new(),
            authority_issuer: Arc::new(UnavailableGithubOidcRuntimeAuthorityIssuer),
            operationally_ready: false,
        }
    }

    /// Returns whether this replica proved the complete OIDC product ready.
    pub(crate) const fn operationally_ready(&self) -> bool {
        self.operationally_ready
    }
}

/// Composes mandatory Results with ordered OIDC and repository-authority contributions.
pub(crate) fn compose_runtime_authority_issuer(
    required_results: Arc<dyn RuntimeAuthorityIssuer>,
    github_oidc: Arc<dyn OptionalRuntimeAuthorityIssuer>,
    github_repository: Arc<dyn OptionalRuntimeAuthorityIssuer>,
) -> Result<Arc<dyn RuntimeAuthorityIssuer>, ControlPortError> {
    let composite = CompositeRuntimeAuthorityIssuer::new(vec![required_results])?
        .with_optional_issuers(vec![github_oidc, github_repository])?;
    Ok(Arc::new(composite))
}

/// Builds the complete OIDC product or the zero-credential entitlement guard.
pub(crate) async fn build_github_oidc_product(
    config: Option<&GithubOidcConfig>,
    store: &PostgresStore,
) -> Result<GithubOidcProduct, GithubOidcProductError> {
    // Absence is a deliberate disabled state, so retain the fail-closed guard
    // for stale runner capability advertisements. Once an operator supplies a
    // manifest, every configuration and durable-readiness failure below aborts
    // startup rather than silently degrading back to the disabled product.
    let Some(config) = config else {
        return Ok(GithubOidcProduct::unavailable());
    };
    let loaded = config.load_keyrings()?;
    let current_policy = config.current_policy()?;
    let clock = Arc::new(SystemGithubOidcClock);
    let issuance_repository = Arc::new(
        PostgresGithubOidcIssuanceRepository::new(
            store.clone(),
            current_policy,
            loaded.signing_key_evidence.clone(),
            clock.clone(),
        )
        .map_err(|_| GithubOidcProductError::InvalidConfiguration)?,
    );
    let now_seconds =
        OidcClock::now_seconds(clock.as_ref()).map_err(|_| GithubOidcProductError::KeyReadiness)?;
    admit_key_readiness(
        issuance_repository
            .verify_github_oidc_key_readiness(now_seconds, &loaded.request_key_evidence)
            .await,
    )?;
    let repository: Arc<dyn OidcIssuanceRepository> = issuance_repository;
    let service = Arc::new(OidcService::new(
        config.issuer.clone(),
        config.supported_claims.clone(),
        OidcTokenLifetime::from_seconds(config.id_token.lifetime_seconds)
            .map_err(|_| GithubOidcProductError::InvalidConfiguration)?,
        Arc::clone(&loaded.request_bearers),
        Arc::clone(&loaded.signing_keys),
        repository,
    ));
    let http_clock: Arc<dyn OidcClock> = clock.clone();
    let router = oidc_router_with_deadline(service, http_clock, OIDC_REQUEST_TIMEOUT);

    let authority_repository: Arc<dyn GithubOidcAuthorityRepository> = Arc::new(
        PostgresGithubOidcAuthorityRepository::new(store.clone(), clock.clone()),
    );
    let provisioner_clock: Arc<dyn GithubOidcProvisionerClock> = clock;
    let provisioner: Arc<dyn GithubOidcAuthorityProvisioner> =
        Arc::new(ProductGithubOidcProvisioner::new(
            authority_repository,
            provisioner_clock,
            current_policy,
            loaded.request_key_fingerprints,
        ));
    let authority_ids = Arc::new(RandomGithubOidcAuthorityIdGenerator);
    let authority_issuer = GithubOidcRuntimeAuthorityIssuer::new(
        config.issuer.clone(),
        loaded.request_bearers,
        authority_ids,
        provisioner,
    )
    .map_err(|_| GithubOidcProductError::InvalidConfiguration)?;
    Ok(GithubOidcProduct {
        router,
        authority_issuer: Arc::new(authority_issuer),
        operationally_ready: true,
    })
}

fn admit_key_readiness(
    result: Result<(), GithubOidcStoreError>,
) -> Result<(), GithubOidcProductError> {
    result.map_err(|_| GithubOidcProductError::KeyReadiness)
}

fn oidc_router_with_deadline(
    service: Arc<OidcService>,
    clock: Arc<dyn OidcClock>,
    timeout: Duration,
) -> Router {
    GithubOidcApi::new(service, clock).router().layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(handle_oidc_middleware_error))
            .layer(TimeoutLayer::new(timeout)),
    )
}

async fn handle_oidc_middleware_error(_error: tower::BoxError) -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(TimeoutResponse {
            error: "temporarily_unavailable",
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[derive(Serialize)]
struct TimeoutResponse {
    error: &'static str,
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Mutex};

    use automata_ci_control::runner_control::RuntimeAuthorityIssueRequest;
    use automata_ci_core::{
        AttemptId, FencingToken, JobAuthorityProfile, JobContentReference, JobExecutionContext,
        JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobPermissionRequest, JobSource, Lease,
        LeaseId, PermissionLevel, RunId, RunValueTemplates, RunnerId, RunnerRequirements,
        RunnerSessionId, RuntimeBoolean, SemanticStep, ShellTemplate, StepId, StepIr,
        TrustActorEvidence, TrustActorKind, TrustAutomationKind, TrustEventKind, TrustEvidence,
        TrustOriginKind, TrustPolicy, TrustRepositoryEvidence, TrustSnapshot, TrustTokenRecursion,
        ValueTemplate, WorkflowId,
    };
    use automata_ci_oidc_github::{
        AuthorizedOidcIssuance, OidcAuthorityId, OidcRepositoryError, ReserveOidcIssuance,
    };
    use automata_ci_protocol::{
        JobRuntimeAuthorities, JobRuntimeAuthority, ProtocolLimits, RuntimeAuthorityCredential,
        RuntimeAuthorityEndpoint, RuntimeAuthorityName,
    };
    use automata_ci_protocol_protobuf::encode_job_ir;
    use automata_ci_store::{
        GithubOidcStoreError, JobIrMetadata, ObjectKey, ReservedGithubOidcAuthority,
        RunnerGeneration, RunnerSessionFence, SessionEpoch, StableRunnerSlot,
    };
    use axum::{body::Body, http::Request};
    use tower::ServiceExt as _;

    use super::super::github_job_runtime_authority::unavailable_github_job_runtime_authority_issuer;
    use super::*;

    const NOW_MILLIS: i64 = 1_800_000_001_000;
    const ISSUED_AT_MILLIS: i64 = 1_800_000_000_999;
    const TEST_RSA_MODULUS: &str = "3EB2d40ghnbyGr9du8XI5MMt_dHBRJlGaIQzk_fgMxwAxiToz5Ck540SPVcosHkRC-YjGIXjhwDSOlSJ9kxsoQRM5venRhsZeQWeuo_82S95k6CFguafVLvOSmFKltf5obDHo6DBxum_C_1jc4ZTJGEi1K7AV33qhJ_qZfAMI8K8a6xIpkXtcpTDU-yxTrdFQF5yzW7cVqyoXjHbcxIIS2UMVZTMJ3Hv5pgDxe9eYhVlxkBO0oZn89jVVMSfKnThlsj02cd9N5doFuJEKB5NTYGG9E7uWnOEq_jddN-NNa8hU1PTSqpzwIdDs1ZBet2wmNl5Wr1KI981Rkp2FTvPkw";
    const TEST_REPLACEMENT_RSA_MODULUS: &str = "o1A6wARhTiKLU_SKTdxcBDZK2gGqMoFS-fLEh_4fL-14V0JW5xRjwbzAO8m3oqzjCT9sDU1AZh-czgZ7QQQ8njEYrVykYLkapZOffcQvFt7rzsc2C9pbrkOnmbBq0b3_U53NPM1Fy1B3s1C_CRuOP7urc0VELeFaaEy3JFMTUpZDC-sti-JzY768ZfgwrcWkp703jEl2N7kkUoBQPZjpyymfm4ABPQJ6gObx95gAmV3p4XBIYxaxhoh7oSLUyF4solYC7N3mDCHmdf2CIbb8INdMfiqhLqOafdm9qCHT4wDNya94v7U7pHiggHyIkSa3RfMWomjDIEY39LSDgaFYSw";
    const TEST_RSA_EXPONENT: &str = "AQAB";
    const TEST_PRIVATE_KEY_BODY: &str = r"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDcQHZ3jSCGdvIa
v127xcjkwy390cFEmUZohDOT9+AzHADGJOjPkKTnjRI9VyiweREL5iMYheOHANI6
VIn2TGyhBEzm96dGGxl5BZ66j/zZL3mToIWC5p9Uu85KYUqW1/mhsMejoMHG6b8L
/WNzhlMkYSLUrsBXfeqEn+pl8AwjwrxrrEimRe1ylMNT7LFOt0VAXnLNbtxWrKhe
MdtzEghLZQxVlMwnce/mmAPF715iFWXGQE7Shmfz2NVUxJ8qdOGWyPTZx303l2gW
4kQoHk1NgYb0Tu5ac4Sr+N103401ryFTU9NKqnPAh0OzVkF63bCY2XlavUoj3zVG
SnYVO8+TAgMBAAECggEAWtLWR0xR+kD4ayE4tOLFidgWkhE6AmC2UQka/8x6jnjg
tNSpkFZUOgvJVrQnWkZCSkbXeBhWD+i9yEHuNjujm+5bC+9Z8iXgpjA0GTihCqpy
FvddtvIFB/r+AVwHVxauoQd1+7qhzbW8C2Ss6wmcJWdM5qk9NZb96zzKesi3KNMz
t0zGmdm8frIppxnP2U/S5+Tu/3uHdG7TqJdFWX1qx6FKSi3oQdSrhKhCzCxEZO/A
slb9OJZPvPBAO9/BIJQiMPgLq1cIAj8q1uK8DAYIbYFNkzpVNYyVBk1E2KSJxUCg
zC3QgJ1XzHcEpDTAmv1o+yYAX58+DgAM0jvJYnp3cQKBgQD4hWRMC4c2L7lkP+fy
VHl6jNXKLSzonlOlVqJnz+D4EJI94hTHlkFLHKZKZLcKekokjtuohZuS7x9hZcIP
EVs5w+NPOIfhEk+s5UmRRxeojl86f1TrLhvkUqvkwPSuWR0zmNyEzh1OYNdoEM/G
CzxOzhczp6mOuH7A2CFnS8dhSwKBgQDi4UjP0i+BEE3nE02+QaPqP4N6Z5sXQKq0
IJtcBjZMm79g8TN5ZYWBpFlhNCOHn+AxYvh5tPq+QM9XuQQDHzxum5CRCFVWSCDu
IMR7dNs3Y3gXnPY4G5siCAWj/TuLs+GG/6iMezoE3+4j19zHxQRrYfGJQMOYlgMw
LT9jeG+l2QKBgCinoaWzCRZ7LifRMH97BDhhC6Q8SalwJRzaFE1JO3M5OsM21dFk
qh/Aew+WdD8ZjEF4wURLPw0FYyvKurk+TJ8hhXDzPX87QJ93DtbeO2eOitOF+v1S
GKv8PjR4wE45M8a6DfEHytGElBhpD6RFOENoAXGoztsTIWEouiYsxlwLAoGBAKpj
rS4+2WRhnVAUpEdlvrfXOWP9WXGuJEWhU2xaUf9Y3PLuUs0yHIEPr/ybjq91t4b/
oEKvU7z8qXtlPQknNViQRpNVodlp1ClivI1HZreDYZbCT/w1Z124jpvpPAYgcxjS
+n9+sEUm9A9BN9NkOHx5E1AULpFy4DQXV0raEWeJAoGBAJN+ZF4n+c+pzlUObvtC
H3N4m86U0TUSWCXJe4Kv/5eNdkdjztyUJ8diHOK530A0wWAc7zK9L2NJh/qHC+cY
XTlo/WPBMPJ3JOYlcxCXVn4sCBlRlPIccmoS6vGKQiWadCgwxLaBZNWctfKOQAdm
tPlzul2Px6cR3krgeRjgAs0j";
    const TEST_REPLACEMENT_PRIVATE_KEY_BODY: &str = r"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCjUDrABGFOIotT
9IpN3FwENkraAaoygVL58sSH/h8v7XhXQlbnFGPBvMA7ybeirOMJP2wNTUBmH5zO
BntBBDyeMRitXKRguRqlk599xC8W3uvOxzYL2luuQ6eZsGrRvf9Tnc08zUXLUHez
UL8JG44/u6tzRUQt4VpoTLckUxNSlkML6y2L4nNjvrxl+DCtxaSnvTeMSXY3uSRS
gFA9mOnLKZ+bgAE9AnqA5vH3mACZXenhcEhjFrGGiHuhItTIXiyiVgLs3eYMIeZ1
/YIhtvwg10x+KqEuo5p92b2oIdPjAM3Jr3i/tTukeKCAfIiRJrdF8xaiaMMgRjf0
tIOBoVhLAgMBAAECggEARw+faLLfNjTwxCi5T1TNkyWen0qvKIe+N7UrT/NC1cNy
JCHhF253U7MSQFGu/nFU3s7CcO1G0sj5nWoTkoBJ8hlx3+laOx4AGsDn2r0VMlHw
cEqdWT37u5GDqWuqpzYRlewphEXbkzKhyxwc69UaKeA6o48lsgMHKDANVphxZXL7
nliHUI/ysmHQWsgBcxBS8xUYJr0ZzYI/7ytqa9jn36lQBbwQ+U91MOXvkBtiVzlY
OWwZ4UNKUb1XkcGgWvu1aVBhsL3FXFc0Yt9nEVX0zTKKzsb2b8DnbWot0vKWsbHK
dS9oUUnlKrc8NAfiFpsg6YZWZL7AAc0sUMkFqaGKwQKBgQDRcRz48iGkmB+dHzx/
clbwRa+hFK1KXINVjG5p0g6wuY5tEtF2C8LtPhl0ybHALr78RZFBYCC/oc/L8t1a
zhCeUXdAR8OTwT6JFLgWdqd9P9wFHnV7V/fP9rtaCweCMGVo+82Q/tHXufvIgpgm
YgRYosEUa/Tqk2ETKTrCpDyxCwKBgQDHnguCfbAZSkuKsV3GT2U5eejlRo0yZlSO
KkQ2Weolvp+PBrQqhZlkRs0JNe8+KYePkdc25ue/IsC6I2xAs6x9ywVl/njGVy6R
2MvZ4BkT3lf5M5YhJDoelDqiSGTo711/qhY6rdvpor8tar6+zFCsmV86UwaeCUA+
cFFGf7j9wQKBgB/YkCw2PPFXBC+S6VMDor6EChF3IGZXLM0cPkmu2/b5L/Pb0aee
YDRMpfhBFtr/AKFBPrXvFOuugfcj5Y6CGLrJ7lUC1HUqBAU59kfMIOmFhUHuALUR
iie//3rQhILCMxlEeFxcsrGXoPY7DUGA0+JaVPty8tmcMT2Fnl6sNGJDAoGAQGI3
cCU98UpHRzqh9l6RVZJ+jcTNsd3Tk+8KBUXHAdmT+Tu+TKC+stsrMrdUrQYUFTiC
49BiGwIIi4D1X4EUN5aN7THAnqhr+tqkFWf0brYeReBfodzfahGBP+p9savSymR/
uvlsntTBONLfJwcbVjA5yMQStFJjiEAN1uFHN4ECgYAPJdJvC9DZiPYzW8XLq/yJ
DZ9/Oee47TlmWCu6u19WYhCptY0H684HBeOnFo7/idKicNUqnHicN9XTcq5E8j5f
glu2nlK2QMPKwi98A22Yj/CtYjB8ldL/jg5rG1N/lmj9fGC7P7or9Ucsc4w0j27M
norlX3KEHNe7cTke5cP4OA==";

    fn raw_manifest() -> RawManifest {
        RawManifest {
            schema: MANIFEST_SCHEMA,
            subject_policy: RawSubjectPolicy {
                mode: "stable_owner_evidence".to_owned(),
                revision: 1,
            },
            supported_claims: PRODUCT_SUPPORTED_CLAIMS
                .into_iter()
                .rev()
                .map(str::to_owned)
                .collect(),
            request_bearer: RawRequestBearerManifest {
                maximum_lifetime_seconds: 600,
                allowed_clock_skew_seconds: 30,
                keys: vec![
                    RawRequestBearerKey {
                        key_id: "hmac-current".to_owned(),
                        lifecycle: RawKeyLifecycle::Active,
                        source: "env:OIDC_HMAC_CURRENT".to_owned(),
                    },
                    RawRequestBearerKey {
                        key_id: "hmac-old".to_owned(),
                        lifecycle: RawKeyLifecycle::Retained,
                        source: "file:/run/keys/oidc-hmac-old".to_owned(),
                    },
                ],
            },
            id_token: RawIdTokenManifest {
                lifetime_seconds: 300,
                verifier_skew_seconds: 30,
                keys: vec![
                    raw_rs256("rsa-current", RawKeyLifecycle::Active),
                    RawRs256Key {
                        modulus: TEST_REPLACEMENT_RSA_MODULUS.to_owned(),
                        ..raw_rs256("rsa-next", RawKeyLifecycle::Prepublished)
                    },
                ],
            },
        }
    }

    fn raw_rs256(key_id: &str, lifecycle: RawKeyLifecycle) -> RawRs256Key {
        RawRs256Key {
            key_id: key_id.to_owned(),
            lifecycle,
            private_key_source: format!("env:OIDC_RSA_{}", key_id.replace('-', "_")),
            modulus: TEST_RSA_MODULUS.to_owned(),
            exponent: TEST_RSA_EXPONENT.to_owned(),
        }
    }

    fn https_results() -> ResultsPublicEndpoint {
        ResultsPublicEndpoint::https(
            "https://results.example.test/"
                .parse()
                .expect("Results URL"),
        )
        .expect("HTTPS Results endpoint")
    }

    fn write_private_test_file(name: &str, bytes: &[u8]) -> PathBuf {
        let test_root =
            std::env::var_os("CARGO_TARGET_TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let directory = test_root.join(format!(
            "automata-ci-github-oidc-product-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("test key directory");
        let path = directory.join(name);
        fs::write(&path, bytes).expect("test key file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("owner-only test key");
        }
        #[cfg(windows)]
        automata_ci_windows_file_security::restrict_file_to_current_user_for_test(&path)
            .expect("owner-only test key DACL");
        path
    }

    #[test]
    fn manifest_is_atomic_bounded_and_stable_owner_policy_only() {
        let config = GithubOidcConfig::from_raw(raw_manifest(), &https_results())
            .expect("complete current manifest");
        assert_eq!(config.issuer().as_str(), "https://results.example.test/");
        assert_eq!(config.request_bearer.keys.len(), 2);
        assert_eq!(config.id_token.keys.len(), 2);
        assert!(!format!("{config:?}").contains("OIDC_HMAC_CURRENT"));

        let mut repository_name_fallback = raw_manifest();
        repository_name_fallback.subject_policy.mode = "repository_evidence".to_owned();
        assert!(matches!(
            GithubOidcConfig::from_raw(repository_name_fallback, &https_results()),
            Err(GithubOidcProductError::InvalidConfiguration)
        ));

        let mut partial_claims = raw_manifest();
        partial_claims.supported_claims.pop();
        assert!(GithubOidcConfig::from_raw(partial_claims, &https_results()).is_err());

        let mut hmac_prepublished = raw_manifest();
        hmac_prepublished.request_bearer.keys[1].lifecycle = RawKeyLifecycle::Prepublished;
        assert!(GithubOidcConfig::from_raw(hmac_prepublished, &https_results()).is_err());

        let development = ResultsPublicEndpoint::loopback_development(
            "http://127.0.0.1:8081/".parse().expect("URL"),
            "127.0.0.1:8081".parse().expect("listener"),
        )
        .expect("explicit Results development endpoint");
        assert!(GithubOidcConfig::from_raw(raw_manifest(), &development).is_err());

        let mut encoded = serde_json::to_value(raw_manifest()).expect("encoded manifest");
        encoded
            .as_object_mut()
            .expect("manifest object")
            .insert("unsupported".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<RawManifest>(encoded).is_err());

        let mut exact_bytes = serde_json::to_vec(&raw_manifest()).expect("manifest JSON");
        exact_bytes.resize(MAXIMUM_MANIFEST_BYTES, b' ');
        let exact_path = write_private_test_file("manifest-size.json", &exact_bytes);
        let source = SecretSource::File(exact_path.clone());
        assert!(GithubOidcConfig::load(&source, &https_results()).is_ok());
        exact_bytes.push(b' ');
        write_private_test_file("manifest-size.json", &exact_bytes);
        assert!(matches!(
            GithubOidcConfig::load(&source, &https_results()),
            Err(GithubOidcProductError::InvalidConfiguration)
        ));
    }

    #[test]
    fn manifest_loader_rejects_noncurrent_schemas() {
        for schema in [0, MANIFEST_SCHEMA.checked_add(1).expect("test schema")] {
            let mut manifest = raw_manifest();
            manifest.schema = schema;
            let bytes = serde_json::to_vec(&manifest).expect("noncurrent manifest");
            let path = write_private_test_file(
                &format!("manifest-noncurrent-schema-{schema}.json"),
                &bytes,
            );
            let source = SecretSource::File(path);
            assert!(matches!(
                GithubOidcConfig::load(&source, &https_results()),
                Err(GithubOidcProductError::InvalidConfiguration)
            ));
        }
    }

    #[test]
    fn manifest_enforces_exact_shared_key_and_time_limits() {
        let mut exact = raw_manifest();
        exact.request_bearer.maximum_lifetime_seconds =
            automata_ci_oidc_github::MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS;
        exact.request_bearer.allowed_clock_skew_seconds = MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS;
        exact.id_token.lifetime_seconds =
            automata_ci_oidc_github::MAXIMUM_ID_TOKEN_LIFETIME_SECONDS;
        exact.id_token.verifier_skew_seconds = MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS;
        exact.request_bearer.keys = (0..MAXIMUM_OIDC_KEYS_PER_KEYRING)
            .map(|index| RawRequestBearerKey {
                key_id: format!("hmac-{index}"),
                lifecycle: if index == 0 {
                    RawKeyLifecycle::Active
                } else {
                    RawKeyLifecycle::Retained
                },
                source: format!("env:OIDC_HMAC_{index}"),
            })
            .collect();
        exact.id_token.keys = (0..MAXIMUM_OIDC_KEYS_PER_KEYRING)
            .map(|index| {
                raw_rs256(
                    &format!("rsa-{index}"),
                    if index == 0 {
                        RawKeyLifecycle::Active
                    } else if index == 1 {
                        RawKeyLifecycle::Prepublished
                    } else {
                        RawKeyLifecycle::Retained
                    },
                )
            })
            .collect();
        assert!(GithubOidcConfig::from_raw(exact, &https_results()).is_ok());

        let mut excessive_hmac = raw_manifest();
        excessive_hmac.request_bearer.keys = (0..=MAXIMUM_OIDC_KEYS_PER_KEYRING)
            .map(|index| RawRequestBearerKey {
                key_id: format!("hmac-{index}"),
                lifecycle: if index == 0 {
                    RawKeyLifecycle::Active
                } else {
                    RawKeyLifecycle::Retained
                },
                source: format!("env:OIDC_HMAC_{index}"),
            })
            .collect();
        assert!(GithubOidcConfig::from_raw(excessive_hmac, &https_results()).is_err());

        let mut excessive_rsa = raw_manifest();
        excessive_rsa.id_token.keys = (0..=MAXIMUM_OIDC_KEYS_PER_KEYRING)
            .map(|index| {
                raw_rs256(
                    &format!("rsa-{index}"),
                    if index == 0 {
                        RawKeyLifecycle::Active
                    } else {
                        RawKeyLifecycle::Retained
                    },
                )
            })
            .collect();
        assert!(GithubOidcConfig::from_raw(excessive_rsa, &https_results()).is_err());

        let mut excessive_lifetime = raw_manifest();
        excessive_lifetime.request_bearer.maximum_lifetime_seconds =
            automata_ci_oidc_github::MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS + 1;
        assert!(GithubOidcConfig::from_raw(excessive_lifetime, &https_results()).is_err());

        let mut excessive_skew = raw_manifest();
        excessive_skew.id_token.verifier_skew_seconds =
            MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS + 1;
        assert!(GithubOidcConfig::from_raw(excessive_skew, &https_results()).is_err());
    }

    #[test]
    fn complete_keyrings_load_with_exact_non_secret_fingerprints() {
        let active_hmac = b"test-only-active-request-key-material-at-least-32-bytes";
        let retained_hmac = b"test-only-retained-request-key-material-at-least-32-bytes";
        let active_hmac_path = write_private_test_file("request-hmac-active", active_hmac);
        let retained_hmac_path = write_private_test_file("request-hmac-retained", retained_hmac);
        let active_private_key_path =
            write_private_test_file("id-token-rsa-active.pem", private_key_pem().as_bytes());
        let replacement_private_key_path = write_private_test_file(
            "id-token-rsa-replacement.pem",
            replacement_private_key_pem().as_bytes(),
        );
        let configured_manifest = |replacement_lifecycle| {
            let mut raw = raw_manifest();
            raw.request_bearer.keys[0].source = format!("file:{}", active_hmac_path.display());
            raw.request_bearer.keys[1].source = format!("file:{}", retained_hmac_path.display());
            raw.id_token.keys[0].private_key_source =
                format!("file:{}", active_private_key_path.display());
            raw.id_token.keys[1].private_key_source =
                format!("file:{}", replacement_private_key_path.display());
            raw.id_token.keys[1].lifecycle = replacement_lifecycle;
            raw
        };
        let config = GithubOidcConfig::from_raw(
            configured_manifest(RawKeyLifecycle::Prepublished),
            &https_results(),
        )
        .expect("configuration");
        let loaded = config.load_keyrings().expect("complete keyrings");
        assert_eq!(loaded.request_key_evidence.len(), 2);
        assert_eq!(loaded.signing_key_evidence.len(), 2);
        assert_eq!(
            loaded.request_key_evidence[0].key_sha256(),
            request_bearer_key_fingerprint(active_hmac)
        );
        assert_eq!(
            loaded.request_key_evidence[1].key_sha256(),
            request_bearer_key_fingerprint(retained_hmac)
        );
        let expected_signing_fingerprints = [TEST_RSA_MODULUS, TEST_REPLACEMENT_RSA_MODULUS]
            .into_iter()
            .map(|modulus| {
                github_oidc_rs256_public_key_fingerprint(
                    &RsaPublicJwk::new(
                        OidcKeyId::new("fingerprint-only").expect("key ID"),
                        modulus,
                        TEST_RSA_EXPONENT,
                    )
                    .expect("JWK"),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            loaded
                .signing_key_evidence
                .iter()
                .map(GithubOidcLoadedKey::key_sha256)
                .collect::<BTreeSet<_>>(),
            expected_signing_fingerprints
        );
        assert_eq!(loaded.signing_keys.jwks().keys().len(), 2);

        let retained = GithubOidcConfig::from_raw(
            configured_manifest(RawKeyLifecycle::Retained),
            &https_results(),
        )
        .expect("retained-key configuration")
        .load_keyrings()
        .expect("distinct retained signing key remains loadable");
        assert_eq!(retained.signing_key_evidence.len(), 2);
    }

    #[test]
    fn different_request_kids_cannot_share_hmac_material() {
        let shared_hmac = b"test-only-shared-request-key-material-at-least-32-bytes";
        let shared_hmac_path = write_private_test_file("request-hmac-shared", shared_hmac);
        let active_private_key_path = write_private_test_file(
            "duplicate-hmac-rsa-active.pem",
            private_key_pem().as_bytes(),
        );
        let replacement_private_key_path = write_private_test_file(
            "duplicate-hmac-rsa-replacement.pem",
            replacement_private_key_pem().as_bytes(),
        );
        let mut raw = raw_manifest();
        for key in &mut raw.request_bearer.keys {
            key.source = format!("file:{}", shared_hmac_path.display());
        }
        raw.id_token.keys[0].private_key_source =
            format!("file:{}", active_private_key_path.display());
        raw.id_token.keys[1].private_key_source =
            format!("file:{}", replacement_private_key_path.display());
        let config = GithubOidcConfig::from_raw(raw, &https_results()).expect("configuration");
        let Err(error) = config.load_keyrings() else {
            panic!("different request kids must have different fingerprints");
        };
        assert!(matches!(
            &error,
            GithubOidcProductError::InvalidConfiguration
        ));
        assert_eq!(format!("{error:?}"), "InvalidConfiguration");
    }

    #[test]
    fn different_signing_kids_cannot_share_public_key_material() {
        let active_hmac = b"test-only-unique-request-key-material-at-least-32-bytes";
        let active_hmac_path = write_private_test_file("duplicate-rsa-hmac", active_hmac);
        let shared_private_key_path =
            write_private_test_file("id-token-rsa-shared.pem", private_key_pem().as_bytes());
        let mut raw = raw_manifest();
        raw.request_bearer.keys.truncate(1);
        raw.request_bearer.keys[0].source = format!("file:{}", active_hmac_path.display());
        raw.id_token.keys = vec![
            RawRs256Key {
                key_id: "rsa-current".to_owned(),
                lifecycle: RawKeyLifecycle::Active,
                private_key_source: format!("file:{}", shared_private_key_path.display()),
                modulus: TEST_RSA_MODULUS.to_owned(),
                exponent: TEST_RSA_EXPONENT.to_owned(),
            },
            RawRs256Key {
                key_id: "rsa-retained".to_owned(),
                lifecycle: RawKeyLifecycle::Retained,
                private_key_source: format!("file:{}", shared_private_key_path.display()),
                modulus: TEST_RSA_MODULUS.to_owned(),
                exponent: TEST_RSA_EXPONENT.to_owned(),
            },
        ];
        let config = GithubOidcConfig::from_raw(raw, &https_results()).expect("configuration");
        let Err(error) = config.load_keyrings() else {
            panic!("different signing kids must have different fingerprints");
        };
        assert!(matches!(
            &error,
            GithubOidcProductError::InvalidConfiguration
        ));
        assert_eq!(format!("{error:?}"), "InvalidConfiguration");
    }

    #[derive(Debug)]
    struct FixedClock(UnixMillis);

    impl GithubOidcProvisionerClock for FixedClock {
        fn now_millis(&self) -> Result<UnixMillis, ()> {
            Ok(self.0)
        }
    }

    #[derive(Debug, Default)]
    struct CaptureAuthorityRepository {
        requests: Mutex<Vec<ReserveGithubOidcAuthority>>,
    }

    #[async_trait]
    impl GithubOidcAuthorityRepository for CaptureAuthorityRepository {
        async fn reserve_github_oidc_authority(
            &self,
            request: ReserveGithubOidcAuthority,
        ) -> Result<ReservedGithubOidcAuthority, GithubOidcStoreError> {
            self.requests.lock().expect("capture lock").push(request);
            Err(GithubOidcStoreError::Unavailable)
        }
    }

    struct RuntimeFixture {
        job: JobIrEnvelope,
        metadata: JobIrMetadata,
        lease: Lease,
        session: RunnerSessionFence,
        slot: StableRunnerSlot,
    }

    fn authenticated_snapshot(event_name: &str, git_ref: &str) -> TrustSnapshot {
        let event = match event_name {
            "pull_request" => TrustEventKind::PullRequest,
            _ => TrustEventKind::Push,
        };
        let repository =
            TrustRepositoryEvidence::new("42", "7").expect("stable repository evidence");
        let actor = || {
            TrustActorEvidence::new("actor-1", TrustActorKind::User, TrustAutomationKind::None)
                .expect("stable actor evidence")
        };
        let evidence = TrustEvidence::new(TrustOriginKind::ProviderWebhook, event)
            .with_original_actor(actor())
            .with_repositories(repository.clone(), repository)
            .with_refs(git_ref, git_ref, git_ref)
            .with_revisions(
                "0123456789abcdef0123456789abcdef01234567",
                "0123456789abcdef0123456789abcdef01234567",
                "0123456789abcdef0123456789abcdef01234567",
            )
            .with_fork(false)
            .with_token_recursion(TrustTokenRecursion::Suppressed);
        let evidence = if event == TrustEventKind::PullRequest {
            evidence.with_source_actor(actor())
        } else {
            evidence
        };
        TrustPolicy::current()
            .evaluate(evidence)
            .expect("authenticated test trust snapshot")
    }

    impl RuntimeFixture {
        fn new(provider: &str, permission: JobPermissionRequest, event_name: &str) -> Self {
            Self::new_with_git_ref(provider, permission, event_name, "refs/heads/main")
        }

        fn new_with_git_ref(
            provider: &str,
            permission: JobPermissionRequest,
            event_name: &str,
            git_ref: &str,
        ) -> Self {
            let runner_id = RunnerId::new();
            let job = JobIr::new(
                JobId::new(),
                RunId::new(),
                "verify",
                RunnerRequirements::default(),
                JobInstanceIdentity::new("verify", 0, 1, Sha256Digest::from_bytes([9; 32]))
                    .expect("instance"),
                false,
                vec![StepIr::new(
                    StepId::new("verify").expect("step ID"),
                    ValueTemplate::literal("Verify").expect("step name"),
                    RuntimeBoolean::literal(false),
                    SemanticStep::run(RunValueTemplates::new(
                        ValueTemplate::literal("cargo test").expect("command"),
                        ShellTemplate::default_shell(),
                    )),
                )],
            )
            .with_permission_request(permission)
            .with_trust_snapshot(authenticated_snapshot(event_name, git_ref))
            .with_authority_profile(JobAuthorityProfile::Standard)
            .with_timeout_seconds(120);
            let execution = JobExecutionContext::new(
                "CI",
                git_ref,
                "/__w/example/example",
                JobContentReference::new(
                    "events/event.json",
                    Sha256Digest::from_bytes([7; 32]),
                    2,
                    "application/json",
                ),
                JobContentReference::new(
                    "contexts/verify.pb",
                    Sha256Digest::from_bytes([8; 32]),
                    2,
                    "application/vnd.automata.job-runtime-context.protobuf",
                ),
            )
            .with_actor("octocat")
            .with_run_number(42)
            .with_run_attempt(2);
            let job = JobIrEnvelope::new(
                WorkflowId::new(),
                JobSource::new(
                    provider,
                    "octo-org/example",
                    automata_ci_core::GitObjectId::from_provider_hex(
                        "0123456789abcdef0123456789abcdef01234567",
                    )
                    .expect("revision"),
                    ".ci/workflows/ci.yml",
                    event_name,
                ),
                execution,
                job,
            );
            job.validate().expect("current JobIR");
            let encoded = encode_job_ir(&job, &ProtocolLimits::default()).expect("encoded JobIR");
            let metadata = JobIrMetadata::new(
                job.job().job_id(),
                job.job().run_id(),
                job.version(),
                u64::try_from(encoded.len()).expect("bounded"),
                Sha256Digest::from_bytes(Sha256::digest(encoded).into()),
                ObjectKey::new("job-ir/oidc-product.pb").expect("object key"),
            )
            .expect("metadata");
            let lease = Lease::new(
                LeaseId::new(),
                AttemptId::new(),
                runner_id,
                FencingToken::new(7).expect("fence"),
                UnixMillis::new(ISSUED_AT_MILLIS),
                UnixMillis::new(ISSUED_AT_MILLIS + 600_000),
            )
            .expect("lease");
            let session = RunnerSessionFence::new(
                RunnerSessionId::new(),
                runner_id,
                RunnerGeneration::new(2).expect("generation"),
                SessionEpoch::new(3).expect("epoch"),
            );
            Self {
                job,
                metadata,
                lease,
                session,
                slot: StableRunnerSlot::new(1).expect("slot"),
            }
        }

        fn request(&self) -> RuntimeAuthorityIssueRequest<'_> {
            RuntimeAuthorityIssueRequest::new(
                &self.job,
                &self.metadata,
                &self.lease,
                self.lease.issued_at(),
                self.session,
                self.slot,
            )
            .expect("runtime authority request")
        }
    }

    fn current_policy() -> GithubOidcCurrentPolicy {
        GithubOidcCurrentPolicy::new(
            GithubOidcSubjectPolicyMode::StableOwnerEvidence,
            GithubOidcSubjectPolicyRevision::new(1).expect("revision"),
            subject_policy_fingerprint(),
            Sha256Digest::from_bytes([5; 32]),
            30,
            30,
        )
        .expect("current policy")
    }

    fn test_request_keyring() -> Arc<RequestBearerKeyring> {
        let key_id = OidcKeyId::new("hmac-current").expect("key ID");
        Arc::new(
            RequestBearerKeyring::new(
                RequestBearerConfig::new(
                    "https://results.example.test/",
                    REQUEST_BEARER_AUDIENCE,
                    600,
                    30,
                )
                .expect("bearer config"),
                key_id.clone(),
                [RequestBearerKey::new(
                    key_id,
                    b"test-only-request-key-material-with-at-least-32-bytes",
                )
                .expect("request key")],
            )
            .expect("request keyring"),
        )
    }

    #[tokio::test]
    async fn provisioner_maps_only_execution_current_policy_and_trusted_time() {
        let repository = Arc::new(CaptureAuthorityRepository::default());
        let secret = b"test-only-request-key-material-with-at-least-32-bytes";
        let fingerprint = request_bearer_key_fingerprint(secret);
        let provisioner: Arc<dyn GithubOidcAuthorityProvisioner> =
            Arc::new(ProductGithubOidcProvisioner::new(
                repository.clone(),
                Arc::new(FixedClock(UnixMillis::new(NOW_MILLIS))),
                current_policy(),
                BTreeMap::from([(OidcKeyId::new("hmac-current").expect("key ID"), fingerprint)]),
            ));
        let issuer = GithubOidcRuntimeAuthorityIssuer::new(
            OidcIssuer::https("https://results.example.test/".parse().expect("issuer URL"))
                .expect("issuer"),
            test_request_keyring(),
            Arc::new(RandomGithubOidcAuthorityIdGenerator),
            provisioner,
        )
        .expect("runtime issuer");
        let fixture = RuntimeFixture::new("github", JobPermissionRequest::WriteAll, "push");
        assert_eq!(
            issuer.issue_optional(fixture.request()).await,
            Err(ControlPortError::Unavailable)
        );
        let pull_request = RuntimeFixture::new_with_git_ref(
            "github",
            JobPermissionRequest::WriteAll,
            "pull_request",
            "refs/pull/17/merge",
        );
        assert_eq!(
            issuer.issue_optional(pull_request.request()).await,
            Err(ControlPortError::Unavailable)
        );
        let requests = repository.requests.lock().expect("capture lock");
        assert_eq!(requests.len(), 2);
        let request = &requests[0];
        assert_eq!(request.observed_at(), UnixMillis::new(NOW_MILLIS));
        assert_eq!(request.execution().workflow_id(), fixture.job.workflow_id());
        assert_eq!(request.execution().run_id(), fixture.job.job().run_id());
        assert_eq!(request.execution().job_id(), fixture.job.job().job_id());
        assert_eq!(request.execution().lease(), &fixture.lease);
        assert_eq!(request.execution().session(), fixture.session);
        assert_eq!(request.execution().slot(), fixture.slot);
        assert_eq!(request.execution().job_ir(), &fixture.metadata);
        assert_eq!(
            request.execution().github_repository_name().as_str(),
            "octo-org/example"
        );
        assert_eq!(request.current_policy(), current_policy());
        assert_eq!(
            request.current_policy().subject_policy_mode(),
            GithubOidcSubjectPolicyMode::StableOwnerEvidence
        );
        assert_eq!(request.proposal().request_bearer_key_sha256(), fingerprint);
        assert_eq!(
            request.proposal().issued_at_seconds(),
            u64::try_from(ISSUED_AT_MILLIS).expect("positive") / 1_000
        );
        assert_eq!(
            request.proposal().expires_at_seconds(),
            u64::try_from(ISSUED_AT_MILLIS).expect("positive") / 1_000 + 120
        );
        let expected_bearer = test_request_keyring()
            .issue_with_key_id(
                request.proposal().request_bearer_key_id(),
                request.proposal().authority_id(),
                request.proposal().issued_at_seconds(),
                request.proposal().expires_at_seconds(),
            )
            .expect("same deterministic proposal bearer");
        assert_eq!(
            request.proposal().request_bearer_sha256(),
            Sha256Digest::from_bytes(Sha256::digest(expected_bearer.expose_secret()).into())
        );
        assert_eq!(requests[1].current_policy(), current_policy());
        assert_eq!(requests[1].execution().job_ir(), &pull_request.metadata);
    }

    #[tokio::test]
    async fn disabled_product_guard_blocks_only_entitled_github_jobs() {
        let unavailable = GithubOidcProduct::unavailable();
        assert!(!unavailable.operationally_ready());
        let entitled = RuntimeFixture::new("github", JobPermissionRequest::WriteAll, "push");
        assert_eq!(
            unavailable
                .authority_issuer
                .issue_optional(entitled.request())
                .await,
            Err(ControlPortError::Unavailable)
        );
        let unrelated = RuntimeFixture::new(
            "github",
            JobPermissionRequest::mapping([automata_ci_core::JobPermissionGrant::new(
                "id-token",
                PermissionLevel::None,
            )]),
            "push",
        );
        assert!(
            unavailable
                .authority_issuer
                .issue_optional(unrelated.request())
                .await
                .expect("unentitled jobs decline")
                .is_none()
        );
    }

    #[test]
    fn enabled_product_never_degrades_a_key_readiness_failure_to_disabled() {
        for error in [
            GithubOidcStoreError::Unauthorized,
            GithubOidcStoreError::Conflict,
            GithubOidcStoreError::ResourceExhausted,
            GithubOidcStoreError::CorruptData,
            GithubOidcStoreError::Unavailable,
        ] {
            assert!(matches!(
                admit_key_readiness(Err(error)),
                Err(GithubOidcProductError::KeyReadiness)
            ));
        }
        assert!(admit_key_readiness(Ok(())).is_ok());
    }

    #[derive(Debug)]
    struct RequiredResultsIssuer;

    #[async_trait]
    impl RuntimeAuthorityIssuer for RequiredResultsIssuer {
        async fn issue(
            &self,
            request: RuntimeAuthorityIssueRequest<'_>,
        ) -> Result<JobRuntimeAuthorities, ControlPortError> {
            let authority = JobRuntimeAuthority::new(
                RuntimeAuthorityName::new("github-results")
                    .map_err(|_| ControlPortError::Corrupt)?,
                request.job().job().run_id(),
                request.job().job().job_id(),
                request.lease().attempt_id(),
                request.lease().fencing_token(),
                RuntimeAuthorityEndpoint::new("https://results.example.test/")
                    .map_err(|_| ControlPortError::Corrupt)?,
                RuntimeAuthorityCredential::new("test-only-results-credential".to_owned())
                    .map_err(|_| ControlPortError::Corrupt)?,
                request.lease().issued_at(),
                request.lease().expires_at(),
            )
            .map_err(|_| ControlPortError::Corrupt)?;
            JobRuntimeAuthorities::new(vec![authority], request.job(), request.lease())
                .map_err(|_| ControlPortError::Corrupt)
        }
    }

    #[derive(Debug)]
    struct RecordingOptionalIssuer {
        label: &'static str,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
    impl OptionalRuntimeAuthorityIssuer for RecordingOptionalIssuer {
        async fn issue_optional(
            &self,
            _request: RuntimeAuthorityIssueRequest<'_>,
        ) -> Result<Option<JobRuntimeAuthorities>, ControlPortError> {
            self.calls
                .lock()
                .expect("optional call log")
                .push(self.label);
            Ok(None)
        }
    }

    #[tokio::test]
    async fn composite_keeps_results_required_and_optional_order_stable() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let optional = |label| {
            let issuer: Arc<dyn OptionalRuntimeAuthorityIssuer> =
                Arc::new(RecordingOptionalIssuer {
                    label,
                    calls: Arc::clone(&calls),
                });
            issuer
        };
        let composite = compose_runtime_authority_issuer(
            Arc::new(RequiredResultsIssuer),
            optional("oidc"),
            optional("provider"),
        )
        .expect("one required plus two ordered optional issuers");
        let fixture = RuntimeFixture::new("gitlab", JobPermissionRequest::mapping([]), "push");
        let authorities = composite
            .issue(fixture.request())
            .await
            .expect("declining optional issuers retain Results");
        assert_eq!(authorities.as_slice().len(), 1);
        assert_eq!(authorities.as_slice()[0].name().as_str(), "github-results");
        assert_eq!(
            calls.lock().expect("optional call log").as_slice(),
            ["oidc", "provider"]
        );
    }

    #[tokio::test]
    async fn disabled_optional_products_decline_only_unentitled_jobs() {
        let composite = compose_runtime_authority_issuer(
            Arc::new(RequiredResultsIssuer),
            GithubOidcProduct::unavailable().authority_issuer,
            unavailable_github_job_runtime_authority_issuer(),
        )
        .expect("one required plus two fail-closed optional issuers");
        let unentitled = RuntimeFixture::new("gitlab", JobPermissionRequest::mapping([]), "push");
        let authorities = composite
            .issue(unentitled.request())
            .await
            .expect("unentitled job keeps Results");
        assert_eq!(authorities.as_slice().len(), 1);
        assert_eq!(authorities.as_slice()[0].name().as_str(), "github-results");

        let provider_without_authority =
            RuntimeFixture::new("github", JobPermissionRequest::mapping([]), "push");
        let authorities = composite
            .issue(provider_without_authority.request())
            .await
            .expect("an explicit empty permission mapping keeps only Results");
        assert_eq!(authorities.as_slice().len(), 1);

        let provider_entitled = RuntimeFixture::new(
            "github",
            JobPermissionRequest::mapping([automata_ci_core::JobPermissionGrant::new(
                "contents",
                PermissionLevel::Read,
            )]),
            "push",
        );
        assert_eq!(
            composite.issue(provider_entitled.request()).await,
            Err(ControlPortError::Unavailable)
        );

        let oidc_entitled = RuntimeFixture::new("github", JobPermissionRequest::WriteAll, "push");
        assert_eq!(
            composite.issue(oidc_entitled.request()).await,
            Err(ControlPortError::Unavailable)
        );
    }

    #[derive(Debug)]
    struct FixedOidcClock(u64);

    impl OidcClock for FixedOidcClock {
        fn now_seconds(&self) -> Result<u64, OidcClockError> {
            Ok(self.0)
        }
    }

    #[derive(Debug)]
    struct BlockingIssuanceRepository;

    #[async_trait]
    impl OidcIssuanceRepository for BlockingIssuanceRepository {
        async fn reserve(
            &self,
            _request: ReserveOidcIssuance,
        ) -> Result<AuthorizedOidcIssuance, OidcRepositoryError> {
            std::future::pending().await
        }
    }

    fn private_key_pem() -> String {
        format!("-----BEGIN PRIVATE KEY-----\n{TEST_PRIVATE_KEY_BODY}\n-----END PRIVATE KEY-----\n")
    }

    fn replacement_private_key_pem() -> String {
        format!(
            "-----BEGIN PRIVATE KEY-----\n{TEST_REPLACEMENT_PRIVATE_KEY_BODY}\n-----END PRIVATE KEY-----\n"
        )
    }

    #[tokio::test]
    async fn oidc_routes_are_isolated_and_timeout_failures_are_no_store() {
        let now = 1_800_000_000;
        let request_bearers = test_request_keyring();
        let public_jwk = RsaPublicJwk::new(
            OidcKeyId::new("rsa-current").expect("key ID"),
            TEST_RSA_MODULUS,
            TEST_RSA_EXPONENT,
        )
        .expect("JWK");
        let signing_key =
            Rs256SigningKey::from_pem(&private_key_pem(), public_jwk).expect("signing key");
        let signing_keys = Arc::new(
            Rs256Keyring::new(
                OidcKeyId::new("rsa-current").expect("key ID"),
                [signing_key],
            )
            .expect("signing keyring"),
        );
        let service = Arc::new(OidcService::new(
            OidcIssuer::https("https://results.example.test/".parse().expect("issuer URL"))
                .expect("issuer"),
            OidcSupportedClaims::new(PRODUCT_SUPPORTED_CLAIMS.into_iter().map(str::to_owned))
                .expect("supported claims"),
            OidcTokenLifetime::from_seconds(300).expect("lifetime"),
            request_bearers.clone(),
            signing_keys,
            Arc::new(BlockingIssuanceRepository),
        ));
        let oidc_router = oidc_router_with_deadline(
            service,
            Arc::new(FixedOidcClock(now)),
            Duration::from_millis(1),
        );
        let router = Router::new()
            .route(
                "/results/slow",
                axum::routing::get(|| async {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    StatusCode::OK
                }),
            )
            .merge(oidc_router);
        let results = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/results/slow")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("Results response");
        assert_eq!(results.status(), StatusCode::OK);
        let discovery = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("discovery response");
        assert_eq!(discovery.status(), StatusCode::OK);
        assert_eq!(
            discovery.headers()[header::CACHE_CONTROL],
            "public, max-age=300"
        );

        let authority_id =
            OidcAuthorityId::from_uuid(RunId::new().as_uuid()).expect("authority ID");
        let bearer = request_bearers
            .issue(authority_id, now - 1, now + 60)
            .expect("request bearer");
        let timed_out = router
            .oneshot(
                Request::builder()
                    .uri("/oidc/token?api-version=2.0")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", bearer.expose_secret()),
                    )
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("timeout response");
        assert_eq!(timed_out.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(timed_out.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(timed_out.headers()[header::PRAGMA], "no-cache");
        assert_eq!(
            timed_out.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
    }
}
