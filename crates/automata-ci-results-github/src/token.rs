use std::{fmt, net::SocketAddr, str::FromStr as _, sync::Arc};

use automata_ci_core::{AttemptId, FencingToken, JobId, RunId, Sha256Digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    ArtifactId, CacheAccessScope, CacheAuthority, CacheEntryId, ExecutionAuthority, ResultsClock,
    RuntimeTokenClaims, RuntimeTokenIssuer, RuntimeTokenVerifier, SignedCacheCapability,
    SignedDownloadCapability, SignedUploadCapability, TokenError, UploadId,
};
use automata_ci_protocol::RuntimeAuthorityEndpoint;

const MINIMUM_SIGNING_SECRET_BYTES: usize = 32;
const MAXIMUM_SIGNING_SECRET_BYTES: usize = 16 * 1024;
const MAXIMUM_COMPACT_JWT_BYTES: usize = 16 * 1024;
const MAXIMUM_JWT_HEADER_BYTES: usize = 1024;
const MAXIMUM_JWT_PAYLOAD_BYTES: usize = 8 * 1024;
const MAXIMUM_SCOPE_BYTES: usize = 4 * 1024;
const MAXIMUM_SCOPE_COUNT: usize = 32;
const MAXIMUM_SCOPE_PART_BYTES: usize = 255;
// foundation-governance: derived-contract owner=github-runtime kind=cryptographic-context
const JWT_DERIVATION_LABEL: &[u8] = b"automata/results/runtime-jwt/hs256/v1";
// foundation-governance: derived-contract owner=github-runtime kind=cryptographic-context
const UPLOAD_DERIVATION_LABEL: &[u8] = b"automata/results/upload-capability/hs256/v1";
// foundation-governance: derived-contract owner=github-runtime kind=cryptographic-context
const DOWNLOAD_DERIVATION_LABEL: &[u8] = b"automata/results/download-capability/hs256/v1";
// foundation-governance: derived-contract owner=github-runtime kind=cryptographic-context
const CACHE_UPLOAD_DERIVATION_LABEL: &[u8] = b"automata/results/cache-upload-capability/hs256/v1";
// foundation-governance: derived-contract owner=github-runtime kind=cryptographic-context
const CACHE_DOWNLOAD_DERIVATION_LABEL: &[u8] =
    b"automata/results/cache-download-capability/hs256/v1";
// foundation-governance: derived-contract owner=github-runtime kind=digest-domain
const UPLOAD_SIGNATURE_DOMAIN: &str = "automata-results-upload-v1";
// foundation-governance: derived-contract owner=github-runtime kind=digest-domain
const DOWNLOAD_SIGNATURE_DOMAIN: &str = "automata-results-download-v1";
// foundation-governance: derived-contract owner=github-runtime kind=digest-domain
const CACHE_UPLOAD_SIGNATURE_DOMAIN: &str = "automata-results-cache-upload-v1";
// foundation-governance: derived-contract owner=github-runtime kind=digest-domain
const CACHE_DOWNLOAD_SIGNATURE_DOMAIN: &str = "automata-results-cache-download-v1";

/// Validated public Results origin and its explicit transport policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultsPublicEndpoint {
    url: Url,
    runtime_endpoint: RuntimeAuthorityEndpoint,
    development_listener_bind: Option<SocketAddr>,
}

impl ResultsPublicEndpoint {
    /// Creates a production endpoint protected by TLS.
    ///
    /// # Errors
    ///
    /// Rejects plaintext, credentials, query/fragment data, and non-root URLs.
    pub fn https(url: Url) -> Result<Self, TokenError> {
        validate_public_url(&url)?;
        let runtime_endpoint =
            RuntimeAuthorityEndpoint::new(url.as_str()).map_err(|_| TokenError::Policy)?;
        Ok(Self {
            url,
            runtime_endpoint,
            development_listener_bind: None,
        })
    }

    /// Creates an explicit plaintext loopback-only development endpoint.
    ///
    /// # Errors
    ///
    /// Rejects a non-loopback or wildcard bind, a non-loopback public host,
    /// and a public URL port different from the exact listener port.
    pub fn loopback_development(url: Url, listener_bind: SocketAddr) -> Result<Self, TokenError> {
        validate_development_listener(&url, listener_bind, true)?;
        let runtime_endpoint = RuntimeAuthorityEndpoint::loopback_development(url.as_str())
            .map_err(|_| TokenError::Policy)?;
        Ok(Self {
            url,
            runtime_endpoint,
            development_listener_bind: Some(listener_bind),
        })
    }

    /// Creates an explicit plaintext private-link development endpoint.
    ///
    /// `trusted_public_host` is the exact DNS name or private IP that the
    /// operator maps to `listener_bind` (for example `host.containers.internal`
    /// and the Podman bridge gateway). This assertion is deliberately required
    /// because DNS resolution is outside deterministic configuration parsing.
    ///
    /// # Errors
    ///
    /// Rejects wildcard, loopback, or public-interface binds, a host assertion
    /// that differs from the URL, and a mismatched listener port.
    pub fn trusted_private_development(
        url: Url,
        listener_bind: SocketAddr,
        trusted_public_host: &str,
    ) -> Result<Self, TokenError> {
        validate_development_listener(&url, listener_bind, false)?;
        let actual_host = url.host_str().ok_or(TokenError::Policy)?;
        if trusted_public_host.is_empty()
            || trusted_public_host.len() > 255
            || !trusted_public_host.is_ascii()
            || trusted_public_host
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || trusted_public_host.contains('*')
            || !actual_host.eq_ignore_ascii_case(trusted_public_host)
        {
            return Err(TokenError::Policy);
        }
        let runtime_endpoint = RuntimeAuthorityEndpoint::trusted_private_development(url.as_str())
            .map_err(|_| TokenError::Policy)?;
        Ok(Self {
            url,
            runtime_endpoint,
            development_listener_bind: Some(listener_bind),
        })
    }

    /// Returns the normalized public origin injected into the job.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the authenticated wire endpoint, including development policy.
    #[must_use]
    pub const fn runtime_endpoint(&self) -> &RuntimeAuthorityEndpoint {
        &self.runtime_endpoint
    }

    /// Returns the exact required listener bind for a development endpoint.
    #[must_use]
    pub const fn development_listener_bind(&self) -> Option<SocketAddr> {
        self.development_listener_bind
    }
}

fn validate_public_url(url: &Url) -> Result<(), TokenError> {
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(TokenError::Policy);
    }
    Ok(())
}

fn validate_development_listener(
    url: &Url,
    listener_bind: SocketAddr,
    require_loopback: bool,
) -> Result<(), TokenError> {
    validate_public_url(url)?;
    let private_bind = match listener_bind.ip() {
        std::net::IpAddr::V4(address) => address.is_private() || address.is_link_local(),
        std::net::IpAddr::V6(address) => {
            address.is_unique_local() || address.is_unicast_link_local()
        }
    };
    let accepted_bind = if require_loopback {
        listener_bind.ip().is_loopback()
    } else {
        private_bind
    };
    if url.scheme() != "http"
        || listener_bind.port() == 0
        || !accepted_bind
        || url.port_or_known_default() != Some(listener_bind.port())
    {
        return Err(TokenError::Policy);
    }
    Ok(())
}

/// Deployment policy for one HMAC Results authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HmacResultsAuthorityConfig {
    issuer: String,
    audience: String,
    key_id: String,
    public_endpoint: ResultsPublicEndpoint,
    maximum_token_lifetime_seconds: u64,
    maximum_signed_url_lifetime_seconds: u64,
    allowed_clock_skew_seconds: u64,
}

impl HmacResultsAuthorityConfig {
    /// Creates a bounded issuer, audience, key identity, and public URL policy.
    ///
    /// # Errors
    ///
    /// Rejects empty or unsafe identities, a URL containing credentials/query/
    /// fragment, non-HTTP schemes, and zero validity ceilings.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        key_id: impl Into<String>,
        public_endpoint: ResultsPublicEndpoint,
        maximum_token_lifetime_seconds: u64,
        maximum_signed_url_lifetime_seconds: u64,
        allowed_clock_skew_seconds: u64,
    ) -> Result<Self, TokenError> {
        let issuer = issuer.into();
        let audience = audience.into();
        let key_id = key_id.into();
        for value in [&issuer, &audience, &key_id] {
            if value.is_empty()
                || value.len() > 255
                || !value.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(TokenError::Policy);
            }
        }
        if maximum_token_lifetime_seconds == 0 || maximum_signed_url_lifetime_seconds == 0 {
            return Err(TokenError::Policy);
        }
        Ok(Self {
            issuer,
            audience,
            key_id,
            public_endpoint,
            maximum_token_lifetime_seconds,
            maximum_signed_url_lifetime_seconds,
            allowed_clock_skew_seconds,
        })
    }
}

/// Redacted short-lived runtime credential.
pub struct RuntimeToken(Zeroizing<String>);

impl RuntimeToken {
    /// Exposes the token only at the explicit secret-injection boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RuntimeToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeToken([redacted])")
    }
}

/// HMAC-SHA256 authority implementing both runtime JWTs and signed upload URLs.
///
/// Distinct derived keys and protocol-domain strings prevent a signature from
/// one surface being replayed on the other. Only derived keys are retained.
pub struct HmacResultsAuthority {
    runtime_key: hmac::Key,
    upload_key: hmac::Key,
    download_key: hmac::Key,
    cache_upload_key: hmac::Key,
    cache_download_key: hmac::Key,
    config: HmacResultsAuthorityConfig,
    clock: Arc<dyn ResultsClock>,
}

impl HmacResultsAuthority {
    /// Derives protocol-specific keys from one deployment secret.
    ///
    /// # Errors
    ///
    /// Rejects secrets outside the 32..=16384-byte policy.
    pub fn new(
        signing_secret: &[u8],
        config: HmacResultsAuthorityConfig,
        clock: Arc<dyn ResultsClock>,
    ) -> Result<Self, TokenError> {
        if !(MINIMUM_SIGNING_SECRET_BYTES..=MAXIMUM_SIGNING_SECRET_BYTES)
            .contains(&signing_secret.len())
        {
            return Err(TokenError::Policy);
        }
        let root = hmac::Key::new(hmac::HMAC_SHA256, signing_secret);
        let runtime = hmac::sign(&root, JWT_DERIVATION_LABEL);
        let upload = hmac::sign(&root, UPLOAD_DERIVATION_LABEL);
        let download = hmac::sign(&root, DOWNLOAD_DERIVATION_LABEL);
        let cache_upload = hmac::sign(&root, CACHE_UPLOAD_DERIVATION_LABEL);
        let cache_download = hmac::sign(&root, CACHE_DOWNLOAD_DERIVATION_LABEL);
        Ok(Self {
            runtime_key: hmac::Key::new(hmac::HMAC_SHA256, runtime.as_ref()),
            upload_key: hmac::Key::new(hmac::HMAC_SHA256, upload.as_ref()),
            download_key: hmac::Key::new(hmac::HMAC_SHA256, download.as_ref()),
            cache_upload_key: hmac::Key::new(hmac::HMAC_SHA256, cache_upload.as_ref()),
            cache_download_key: hmac::Key::new(hmac::HMAC_SHA256, cache_download.as_ref()),
            config,
            clock,
        })
    }

    fn upload_message(upload_id: UploadId, expires_at_seconds: u64) -> String {
        format!("{UPLOAD_SIGNATURE_DOMAIN}\n{upload_id}\n{expires_at_seconds}")
    }

    fn download_message(
        artifact_id: ArtifactId,
        content_digest: Sha256Digest,
        expires_at_seconds: u64,
    ) -> String {
        format!(
            "{DOWNLOAD_SIGNATURE_DOMAIN}\n{artifact_id}\n{content_digest}\n{expires_at_seconds}"
        )
    }

    fn cache_upload_message(entry_id: CacheEntryId, expires_at_seconds: u64) -> String {
        format!("{CACHE_UPLOAD_SIGNATURE_DOMAIN}\n{entry_id}\n{expires_at_seconds}")
    }

    fn cache_download_message(
        entry_id: CacheEntryId,
        content_digest: Sha256Digest,
        expires_at_seconds: u64,
    ) -> String {
        format!(
            "{CACHE_DOWNLOAD_SIGNATURE_DOMAIN}\n{entry_id}\n{content_digest}\n{expires_at_seconds}"
        )
    }

    fn verify_expiry(
        &self,
        expires_at_seconds: u64,
        maximum_lifetime: u64,
    ) -> Result<(), TokenError> {
        let now = self.clock.now_seconds();
        if expires_at_seconds <= now {
            return Err(TokenError::Expired);
        }
        if expires_at_seconds.saturating_sub(now) > maximum_lifetime {
            return Err(TokenError::Policy);
        }
        Ok(())
    }

    /// Returns the validated public Results origin used in job environments.
    #[must_use]
    pub const fn public_results_url(&self) -> &Url {
        self.config.public_endpoint.url()
    }

    /// Returns the endpoint and transport policy carried to the runner.
    #[must_use]
    pub const fn runtime_authority_endpoint(&self) -> &RuntimeAuthorityEndpoint {
        self.config.public_endpoint.runtime_endpoint()
    }

    /// Returns the exact required development listener bind, when configured.
    #[must_use]
    pub const fn development_listener_bind(&self) -> Option<SocketAddr> {
        self.config.public_endpoint.development_listener_bind()
    }

    /// Deterministically issues a token at an explicit durable time anchor.
    ///
    /// Repeating this call with identical inputs returns byte-identical JWT
    /// bytes, which lets durable lease-offer replay remain exact.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive validity and timestamp overflow.
    pub fn issue_at(
        &self,
        authority: ExecutionAuthority,
        cache: &CacheAuthority,
        issued_at_seconds: u64,
        valid_for_seconds: u64,
    ) -> Result<RuntimeToken, TokenError> {
        if valid_for_seconds == 0 || valid_for_seconds > self.config.maximum_token_lifetime_seconds
        {
            return Err(TokenError::Policy);
        }
        let expires_at = issued_at_seconds
            .checked_add(valid_for_seconds)
            .ok_or(TokenError::Policy)?;
        let header = JwtHeader {
            alg: "HS256".to_owned(),
            typ: "JWT".to_owned(),
            kid: self.config.key_id.clone(),
        };
        let access_controls =
            serde_json::to_string(cache.scopes()).map_err(|_| TokenError::Policy)?;
        if access_controls.len() > MAXIMUM_SCOPE_BYTES {
            return Err(TokenError::Policy);
        }
        let payload = JwtPayload {
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            sub: authority.attempt_id().to_string(),
            iat: issued_at_seconds,
            nbf: issued_at_seconds,
            exp: expires_at,
            scp: format!(
                "Actions.Results:{}:{}",
                authority.run_id(),
                authority.job_id()
            ),
            attempt_id: authority.attempt_id().to_string(),
            fencing_token: authority.fencing_token().get(),
            repository: cache.repository().to_owned(),
            ac: access_controls,
        };
        let encoded_header = encode_json(&header)?;
        let encoded_payload = encode_json(&payload)?;
        let signing_input = format!("{encoded_header}.{encoded_payload}");
        let signature =
            URL_SAFE_NO_PAD.encode(hmac::sign(&self.runtime_key, signing_input.as_bytes()));
        Ok(RuntimeToken(Zeroizing::new(format!(
            "{signing_input}.{signature}"
        ))))
    }
}

impl fmt::Debug for HmacResultsAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HmacResultsAuthority")
            .field("issuer", &self.config.issuer)
            .field("audience", &self.config.audience)
            .field("key_id", &self.config.key_id)
            .field("public_results_url", &self.config.public_endpoint.url())
            .field(
                "development_listener_bind",
                &self.config.public_endpoint.development_listener_bind(),
            )
            .field("signing_keys", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JwtPayload {
    iss: String,
    aud: String,
    sub: String,
    iat: u64,
    nbf: u64,
    exp: u64,
    scp: String,
    attempt_id: String,
    fencing_token: u64,
    repository: String,
    ac: String,
}

impl RuntimeTokenIssuer for HmacResultsAuthority {
    fn issue(
        &self,
        authority: ExecutionAuthority,
        cache: CacheAuthority,
        valid_for_seconds: u64,
    ) -> Result<RuntimeToken, TokenError> {
        let issued_at = self.clock.now_seconds();
        self.issue_at(authority, &cache, issued_at, valid_for_seconds)
    }
}

impl RuntimeTokenVerifier for HmacResultsAuthority {
    fn verify(&self, token: &str) -> Result<RuntimeTokenClaims, TokenError> {
        if token.is_empty() || token.len() > MAXIMUM_COMPACT_JWT_BYTES {
            return Err(TokenError::Malformed);
        }
        let mut components = token.split('.');
        let encoded_header = components.next().ok_or(TokenError::Malformed)?;
        let encoded_payload = components.next().ok_or(TokenError::Malformed)?;
        let encoded_signature = components.next().ok_or(TokenError::Malformed)?;
        if components.next().is_some()
            || encoded_header.is_empty()
            || encoded_payload.is_empty()
            || encoded_signature.is_empty()
        {
            return Err(TokenError::Malformed);
        }

        let header_bytes = decode_canonical(encoded_header, MAXIMUM_JWT_HEADER_BYTES)?;
        let payload_bytes = decode_canonical(encoded_payload, MAXIMUM_JWT_PAYLOAD_BYTES)?;
        let signature = decode_canonical(
            encoded_signature,
            hmac::HMAC_SHA256.digest_algorithm().output_len(),
        )?;
        if signature.len() != hmac::HMAC_SHA256.digest_algorithm().output_len() {
            return Err(TokenError::Malformed);
        }
        let signing_input_length = encoded_header
            .len()
            .checked_add(encoded_payload.len())
            .and_then(|length| length.checked_add(1))
            .ok_or(TokenError::Malformed)?;
        let signing_input = token
            .get(..signing_input_length)
            .ok_or(TokenError::Malformed)?;
        hmac::verify(&self.runtime_key, signing_input.as_bytes(), &signature)
            .map_err(|_| TokenError::Invalid)?;

        let header: JwtHeader =
            serde_json::from_slice(&header_bytes).map_err(|_| TokenError::Malformed)?;
        if header.alg != "HS256" || header.typ != "JWT" || header.kid != self.config.key_id {
            return Err(TokenError::Invalid);
        }
        let payload: JwtPayload =
            serde_json::from_slice(&payload_bytes).map_err(|_| TokenError::Malformed)?;
        if payload.iss != self.config.issuer || payload.aud != self.config.audience {
            return Err(TokenError::Invalid);
        }
        let now = self.clock.now_seconds();
        let latest_accepted = now.saturating_add(self.config.allowed_clock_skew_seconds);
        if payload.exp <= now {
            return Err(TokenError::Expired);
        }
        if payload.nbf > latest_accepted || payload.iat > latest_accepted {
            return Err(TokenError::Expired);
        }
        if payload.exp <= payload.iat
            || payload.nbf > payload.exp
            || payload.exp.saturating_sub(payload.iat) > self.config.maximum_token_lifetime_seconds
        {
            return Err(TokenError::Policy);
        }

        let (run_id, job_id) = parse_results_scope(&payload.scp)?;
        let attempt_id =
            AttemptId::from_str(&payload.attempt_id).map_err(|_| TokenError::Malformed)?;
        if payload.sub != payload.attempt_id {
            return Err(TokenError::Invalid);
        }
        let fencing_token =
            FencingToken::new(payload.fencing_token).map_err(|_| TokenError::Malformed)?;
        if payload.ac.is_empty() || payload.ac.len() > MAXIMUM_SCOPE_BYTES {
            return Err(TokenError::Scope);
        }
        let scopes: Vec<CacheAccessScope> =
            serde_json::from_str(&payload.ac).map_err(|_| TokenError::Scope)?;
        let cache =
            CacheAuthority::new(payload.repository, scopes).map_err(|_| TokenError::Scope)?;
        Ok(RuntimeTokenClaims::new(
            ExecutionAuthority::new(run_id, job_id, attempt_id, fencing_token),
            cache,
            payload.iat,
            payload.exp,
        ))
    }
}

impl SignedCacheCapability for HmacResultsAuthority {
    fn issue_cache_upload_url(
        &self,
        entry_id: CacheEntryId,
        expires_at_seconds: u64,
    ) -> Result<Url, TokenError> {
        let now = self.clock.now_seconds();
        if expires_at_seconds <= now {
            return Err(TokenError::Expired);
        }
        let expires_at_seconds = expires_at_seconds
            .min(now.saturating_add(self.config.maximum_signed_url_lifetime_seconds));
        let message = Self::cache_upload_message(entry_id, expires_at_seconds);
        let signature =
            URL_SAFE_NO_PAD.encode(hmac::sign(&self.cache_upload_key, message.as_bytes()));
        let mut url = self
            .config
            .public_endpoint
            .url()
            .join(&format!("_apis/results/caches/{entry_id}/blob"))
            .map_err(|_| TokenError::Policy)?;
        url.query_pairs_mut()
            .append_pair("se", &expires_at_seconds.to_string())
            .append_pair("sig", &signature);
        Ok(url)
    }

    fn verify_cache_upload(
        &self,
        entry_id: CacheEntryId,
        expires_at_seconds: u64,
        signature: &str,
    ) -> Result<(), TokenError> {
        self.verify_expiry(
            expires_at_seconds,
            self.config.maximum_signed_url_lifetime_seconds,
        )?;
        let signature =
            decode_canonical(signature, hmac::HMAC_SHA256.digest_algorithm().output_len())?;
        if signature.len() != hmac::HMAC_SHA256.digest_algorithm().output_len() {
            return Err(TokenError::Malformed);
        }
        hmac::verify(
            &self.cache_upload_key,
            Self::cache_upload_message(entry_id, expires_at_seconds).as_bytes(),
            &signature,
        )
        .map_err(|_| TokenError::Invalid)
    }

    fn issue_cache_download_url(
        &self,
        entry_id: CacheEntryId,
        digest: Sha256Digest,
        expires_at_seconds: u64,
    ) -> Result<Url, TokenError> {
        let now = self.clock.now_seconds();
        if expires_at_seconds <= now {
            return Err(TokenError::Expired);
        }
        let expires_at_seconds = expires_at_seconds
            .min(now.saturating_add(self.config.maximum_signed_url_lifetime_seconds));
        let message = Self::cache_download_message(entry_id, digest, expires_at_seconds);
        let signature =
            URL_SAFE_NO_PAD.encode(hmac::sign(&self.cache_download_key, message.as_bytes()));
        let mut url = self
            .config
            .public_endpoint
            .url()
            .join(&format!(
                "_apis/results/caches/{entry_id}/{digest}/download"
            ))
            .map_err(|_| TokenError::Policy)?;
        url.query_pairs_mut()
            .append_pair("se", &expires_at_seconds.to_string())
            .append_pair("sig", &signature);
        Ok(url)
    }

    fn verify_cache_download(
        &self,
        entry_id: CacheEntryId,
        digest: Sha256Digest,
        expires_at_seconds: u64,
        signature: &str,
    ) -> Result<(), TokenError> {
        self.verify_expiry(
            expires_at_seconds,
            self.config.maximum_signed_url_lifetime_seconds,
        )?;
        let signature =
            decode_canonical(signature, hmac::HMAC_SHA256.digest_algorithm().output_len())?;
        if signature.len() != hmac::HMAC_SHA256.digest_algorithm().output_len() {
            return Err(TokenError::Malformed);
        }
        hmac::verify(
            &self.cache_download_key,
            Self::cache_download_message(entry_id, digest, expires_at_seconds).as_bytes(),
            &signature,
        )
        .map_err(|_| TokenError::Invalid)
    }
}

impl SignedUploadCapability for HmacResultsAuthority {
    fn issue_url(&self, upload_id: UploadId, expires_at_seconds: u64) -> Result<Url, TokenError> {
        let now = self.clock.now_seconds();
        if expires_at_seconds <= now {
            return Err(TokenError::Expired);
        }
        let expires_at_seconds = expires_at_seconds
            .min(now.saturating_add(self.config.maximum_signed_url_lifetime_seconds));
        let message = Self::upload_message(upload_id, expires_at_seconds);
        let signature = URL_SAFE_NO_PAD.encode(hmac::sign(&self.upload_key, message.as_bytes()));
        let mut url = self
            .config
            .public_endpoint
            .url()
            .join(&format!("_apis/results/artifacts/{upload_id}/blob"))
            .map_err(|_| TokenError::Policy)?;
        url.query_pairs_mut()
            .append_pair("se", &expires_at_seconds.to_string())
            .append_pair("sig", &signature);
        Ok(url)
    }

    fn verify(
        &self,
        upload_id: UploadId,
        expires_at_seconds: u64,
        signature: &str,
    ) -> Result<(), TokenError> {
        self.verify_expiry(
            expires_at_seconds,
            self.config.maximum_signed_url_lifetime_seconds,
        )?;
        let signature =
            decode_canonical(signature, hmac::HMAC_SHA256.digest_algorithm().output_len())?;
        if signature.len() != hmac::HMAC_SHA256.digest_algorithm().output_len() {
            return Err(TokenError::Malformed);
        }
        hmac::verify(
            &self.upload_key,
            Self::upload_message(upload_id, expires_at_seconds).as_bytes(),
            &signature,
        )
        .map_err(|_| TokenError::Invalid)
    }
}

impl SignedDownloadCapability for HmacResultsAuthority {
    fn issue_download_url(
        &self,
        artifact_id: ArtifactId,
        content_digest: Sha256Digest,
        expires_at_seconds: u64,
    ) -> Result<Url, TokenError> {
        let now = self.clock.now_seconds();
        if expires_at_seconds <= now {
            return Err(TokenError::Expired);
        }
        let expires_at_seconds = expires_at_seconds
            .min(now.saturating_add(self.config.maximum_signed_url_lifetime_seconds));
        let message = Self::download_message(artifact_id, content_digest, expires_at_seconds);
        let signature = URL_SAFE_NO_PAD.encode(hmac::sign(&self.download_key, message.as_bytes()));
        let mut url = self
            .config
            .public_endpoint
            .url()
            .join(&format!(
                "_apis/results/artifacts/{artifact_id}/{content_digest}/download.zip"
            ))
            .map_err(|_| TokenError::Policy)?;
        url.query_pairs_mut()
            .append_pair("se", &expires_at_seconds.to_string())
            .append_pair("sig", &signature);
        Ok(url)
    }

    fn verify_download(
        &self,
        artifact_id: ArtifactId,
        content_digest: Sha256Digest,
        expires_at_seconds: u64,
        signature: &str,
    ) -> Result<(), TokenError> {
        self.verify_expiry(
            expires_at_seconds,
            self.config.maximum_signed_url_lifetime_seconds,
        )?;
        let signature =
            decode_canonical(signature, hmac::HMAC_SHA256.digest_algorithm().output_len())?;
        if signature.len() != hmac::HMAC_SHA256.digest_algorithm().output_len() {
            return Err(TokenError::Malformed);
        }
        hmac::verify(
            &self.download_key,
            Self::download_message(artifact_id, content_digest, expires_at_seconds).as_bytes(),
            &signature,
        )
        .map_err(|_| TokenError::Invalid)
    }
}

fn encode_json(value: &impl Serialize) -> Result<String, TokenError> {
    serde_json::to_vec(value)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| TokenError::Policy)
}

fn decode_canonical(value: &str, maximum_bytes: usize) -> Result<Vec<u8>, TokenError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| TokenError::Malformed)?;
    if bytes.len() > maximum_bytes || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(TokenError::Malformed);
    }
    Ok(bytes)
}

fn parse_results_scope(scope: &str) -> Result<(RunId, JobId), TokenError> {
    if scope.is_empty()
        || scope.len() > MAXIMUM_SCOPE_BYTES
        || scope.starts_with(' ')
        || scope.ends_with(' ')
        || scope.contains("  ")
    {
        return Err(TokenError::Scope);
    }
    let mut result = None;
    let mut count = 0_usize;
    for item in scope.split(' ') {
        count = count.checked_add(1).ok_or(TokenError::Scope)?;
        if count > MAXIMUM_SCOPE_COUNT
            || item.is_empty()
            || item.len() > MAXIMUM_SCOPE_PART_BYTES
            || !item.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(TokenError::Scope);
        }
        let Some(remainder) = item.strip_prefix("Actions.Results:") else {
            continue;
        };
        if result.is_some() {
            return Err(TokenError::Scope);
        }
        let mut ids = remainder.split(':');
        let run = ids.next().ok_or(TokenError::Scope)?;
        let job = ids.next().ok_or(TokenError::Scope)?;
        if ids.next().is_some() || run.is_empty() || job.is_empty() {
            return Err(TokenError::Scope);
        }
        result = Some((
            RunId::from_str(run).map_err(|_| TokenError::Scope)?,
            JobId::from_str(job).map_err(|_| TokenError::Scope)?,
        ));
    }
    result.ok_or(TokenError::Scope)
}
