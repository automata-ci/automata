use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{MAXIMUM_OIDC_KEYS_PER_KEYRING, OidcAuthorityId, OidcKeyId};

const MINIMUM_HMAC_SECRET_BYTES: usize = 32;
const MAXIMUM_HMAC_SECRET_BYTES: usize = 16 * 1_024;
const MAXIMUM_REQUEST_BEARER_BYTES: usize = 8 * 1_024;
const MAXIMUM_HEADER_BYTES: usize = 1_024;
const MAXIMUM_PAYLOAD_BYTES: usize = 2 * 1_024;
const HMAC_SHA256_OUTPUT_BYTES: usize = 32;
const MAXIMUM_IDENTITY_BYTES: usize = 255;

/// Maximum clock skew accepted while verifying a private mint-request bearer.
pub const MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS: u64 = 300;

/// Maximum lifetime for the private runner-to-mint request bearer.
///
/// ID tokens minted through that bearer retain their independent one-hour
/// ceiling. A request bearer may cover a bounded long-running job while every
/// mint still revalidates current durable execution authority.
pub const MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS: u64 = 24 * 60 * 60;

/// Sanitized request-bearer issuance or verification failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RequestBearerError {
    /// Compact JWT syntax, JSON shape, or a bounded field is malformed.
    #[error("OIDC request bearer is malformed")]
    Malformed,
    /// Signature, issuer, audience, algorithm, type, or key identity is invalid.
    #[error("OIDC request bearer is invalid")]
    Invalid,
    /// The bearer is not yet active or is expired.
    #[error("OIDC request bearer is outside its validity interval")]
    Expired,
    /// Issuance or key configuration violates a current policy bound.
    #[error("OIDC request bearer policy rejected the operation")]
    Policy,
    /// An exact retry names a request-bearer key that is no longer retained.
    #[error("OIDC request bearer issuance key is unavailable")]
    MissingIssuanceKey,
}

/// Explicit issuer, audience, lifetime, and skew policy for private mint bearers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestBearerConfig {
    issuer: String,
    audience: String,
    maximum_lifetime_seconds: u64,
    allowed_clock_skew_seconds: u64,
}

impl RequestBearerConfig {
    /// Creates a bounded current-only request-bearer policy.
    ///
    /// # Errors
    ///
    /// Rejects non-visible ASCII identities, zero/excessive lifetime, or skew
    /// beyond five minutes.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        maximum_lifetime_seconds: u64,
        allowed_clock_skew_seconds: u64,
    ) -> Result<Self, RequestBearerError> {
        let issuer = issuer.into();
        let audience = audience.into();
        if !valid_identity(&issuer)
            || !valid_identity(&audience)
            || maximum_lifetime_seconds == 0
            || maximum_lifetime_seconds > MAXIMUM_REQUEST_BEARER_LIFETIME_SECONDS
            || allowed_clock_skew_seconds > MAXIMUM_REQUEST_BEARER_CLOCK_SKEW_SECONDS
        {
            return Err(RequestBearerError::Policy);
        }
        Ok(Self {
            issuer,
            audience,
            maximum_lifetime_seconds,
            allowed_clock_skew_seconds,
        })
    }
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_IDENTITY_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// One redacted HMAC key used for private request-bearer authentication.
pub struct RequestBearerKey {
    key_id: OidcKeyId,
    key: hmac::Key,
}

impl RequestBearerKey {
    /// Loads a key from 32..=16384 bytes of deployment secret material.
    ///
    /// # Errors
    ///
    /// Rejects secrets outside the supported byte bound.
    pub fn new(key_id: OidcKeyId, secret: &[u8]) -> Result<Self, RequestBearerError> {
        if !(MINIMUM_HMAC_SECRET_BYTES..=MAXIMUM_HMAC_SECRET_BYTES).contains(&secret.len()) {
            return Err(RequestBearerError::Policy);
        }
        Ok(Self {
            key_id,
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
        })
    }
}

impl fmt::Debug for RequestBearerKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBearerKey")
            .field("key_id", &self.key_id)
            .field("key", &"[redacted]")
            .finish()
    }
}

/// Redacted private credential injected into `ACTIONS_ID_TOKEN_REQUEST_TOKEN`.
pub struct OidcRequestBearer(Zeroizing<String>);

impl OidcRequestBearer {
    /// Exposes the bearer only at an explicit runner or HTTP boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OidcRequestBearer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OidcRequestBearer([redacted])")
    }
}

/// Authenticated request-bearer claims safe to pass to the repository port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRequestBearer {
    authority_id: OidcAuthorityId,
    issued_at_seconds: u64,
    expires_at_seconds: u64,
}

impl VerifiedRequestBearer {
    /// Returns the opaque durable authority identity.
    #[must_use]
    pub const fn authority_id(self) -> OidcAuthorityId {
        self.authority_id
    }

    /// Returns the signed issuance second.
    #[must_use]
    pub const fn issued_at_seconds(self) -> u64 {
        self.issued_at_seconds
    }

    /// Returns the exclusive signed bearer deadline.
    #[must_use]
    pub const fn expires_at_seconds(self) -> u64 {
        self.expires_at_seconds
    }
}

/// Rotatable HMAC issuer and verifier for private OIDC mint-request bearers.
pub struct RequestBearerKeyring {
    config: RequestBearerConfig,
    active_key_id: OidcKeyId,
    keys: BTreeMap<OidcKeyId, hmac::Key>,
}

impl RequestBearerKeyring {
    /// Creates a bounded keyring whose active key must be present exactly once.
    ///
    /// # Errors
    ///
    /// Rejects an empty/oversized key set, duplicate IDs, or a missing active key.
    pub fn new(
        config: RequestBearerConfig,
        active_key_id: OidcKeyId,
        keys: impl IntoIterator<Item = RequestBearerKey>,
    ) -> Result<Self, RequestBearerError> {
        let mut key_map = BTreeMap::new();
        for entry in keys {
            if key_map.len() >= MAXIMUM_OIDC_KEYS_PER_KEYRING
                || key_map.insert(entry.key_id, entry.key).is_some()
            {
                return Err(RequestBearerError::Policy);
            }
        }
        if key_map.is_empty() || !key_map.contains_key(&active_key_id) {
            return Err(RequestBearerError::Policy);
        }
        Ok(Self {
            config,
            active_key_id,
            keys: key_map,
        })
    }

    /// Returns the key proposed for a newly reserved request bearer.
    #[must_use]
    pub const fn active_key_id(&self) -> &OidcKeyId {
        &self.active_key_id
    }

    /// Returns whether a durably pinned issuance key remains available.
    #[must_use]
    pub fn contains_key(&self, key_id: &OidcKeyId) -> bool {
        self.keys.contains_key(key_id)
    }

    /// Returns the configured upper bound for one request-bearer interval.
    #[must_use]
    pub const fn maximum_lifetime_seconds(&self) -> u64 {
        self.config.maximum_lifetime_seconds
    }

    /// Issues a deterministic private bearer with the active key.
    ///
    /// # Errors
    ///
    /// Rejects an empty, inverted, or excessive validity interval.
    pub fn issue(
        &self,
        authority_id: OidcAuthorityId,
        issued_at_seconds: u64,
        expires_at_seconds: u64,
    ) -> Result<OidcRequestBearer, RequestBearerError> {
        self.issue_with_key_id(
            &self.active_key_id,
            authority_id,
            issued_at_seconds,
            expires_at_seconds,
        )
    }

    /// Issues deterministic retry bytes with one durably pinned retained key.
    ///
    /// New reservations should persist [`Self::active_key_id`] before calling
    /// this method. Exact retries must call it with that persisted `kid`, so a
    /// concurrent active-key rotation cannot change protected authority bytes.
    ///
    /// # Errors
    ///
    /// Rejects an empty, inverted, or excessive validity interval, or a pinned
    /// key that is no longer retained by this keyring.
    pub fn issue_with_key_id(
        &self,
        key_id: &OidcKeyId,
        authority_id: OidcAuthorityId,
        issued_at_seconds: u64,
        expires_at_seconds: u64,
    ) -> Result<OidcRequestBearer, RequestBearerError> {
        if expires_at_seconds <= issued_at_seconds
            || expires_at_seconds.saturating_sub(issued_at_seconds)
                > self.config.maximum_lifetime_seconds
        {
            return Err(RequestBearerError::Policy);
        }
        let header = RequestHeader {
            alg: "HS256",
            typ: "JWT",
            kid: key_id.as_str(),
        };
        let payload = RequestClaims {
            iss: &self.config.issuer,
            aud: &self.config.audience,
            sub: authority_id.to_string(),
            iat: issued_at_seconds,
            nbf: issued_at_seconds,
            exp: expires_at_seconds,
        };
        let header = serde_json::to_vec(&header).map_err(|_| RequestBearerError::Policy)?;
        let payload = serde_json::to_vec(&payload).map_err(|_| RequestBearerError::Policy)?;
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let key = self
            .keys
            .get(key_id)
            .ok_or(RequestBearerError::MissingIssuanceKey)?;
        let signature = hmac::sign(key, signing_input.as_bytes());
        Ok(OidcRequestBearer(Zeroizing::new(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))))
    }

    /// Authenticates one bounded bearer at an explicit time anchor.
    ///
    /// # Errors
    ///
    /// Returns only sanitized syntax, signature, identity, or time failures.
    pub fn verify(
        &self,
        token: &str,
        now_seconds: u64,
    ) -> Result<VerifiedRequestBearer, RequestBearerError> {
        if token.is_empty() || token.len() > MAXIMUM_REQUEST_BEARER_BYTES {
            return Err(RequestBearerError::Malformed);
        }
        let mut segments = token.split('.');
        let encoded_header = segments.next().ok_or(RequestBearerError::Malformed)?;
        let encoded_payload = segments.next().ok_or(RequestBearerError::Malformed)?;
        let encoded_signature = segments.next().ok_or(RequestBearerError::Malformed)?;
        if segments.next().is_some()
            || encoded_header.is_empty()
            || encoded_payload.is_empty()
            || encoded_signature.is_empty()
        {
            return Err(RequestBearerError::Malformed);
        }
        let header_bytes = decode_segment(encoded_header, MAXIMUM_HEADER_BYTES)?;
        let payload_bytes = decode_segment(encoded_payload, MAXIMUM_PAYLOAD_BYTES)?;
        let signature = decode_segment(encoded_signature, HMAC_SHA256_OUTPUT_BYTES)?;
        if signature.len() != HMAC_SHA256_OUTPUT_BYTES {
            return Err(RequestBearerError::Malformed);
        }
        let header: OwnedRequestHeader =
            serde_json::from_slice(&header_bytes).map_err(|_| RequestBearerError::Malformed)?;
        if header.alg != "HS256" || header.typ != "JWT" {
            return Err(RequestBearerError::Invalid);
        }
        let key_id = OidcKeyId::new(header.kid).map_err(|_| RequestBearerError::Malformed)?;
        let key = self.keys.get(&key_id).ok_or(RequestBearerError::Invalid)?;
        let signing_input = format!("{encoded_header}.{encoded_payload}");
        hmac::verify(key, signing_input.as_bytes(), &signature)
            .map_err(|_| RequestBearerError::Invalid)?;

        let claims: OwnedRequestClaims =
            serde_json::from_slice(&payload_bytes).map_err(|_| RequestBearerError::Malformed)?;
        if claims.iss != self.config.issuer || claims.aud != self.config.audience {
            return Err(RequestBearerError::Invalid);
        }
        if claims.nbf != claims.iat
            || claims.exp <= claims.iat
            || claims.exp.saturating_sub(claims.iat) > self.config.maximum_lifetime_seconds
        {
            return Err(RequestBearerError::Invalid);
        }
        let latest_accepted = now_seconds.saturating_add(self.config.allowed_clock_skew_seconds);
        let earliest_accepted = now_seconds.saturating_sub(self.config.allowed_clock_skew_seconds);
        if claims.iat > latest_accepted
            || claims.nbf > latest_accepted
            || claims.exp <= earliest_accepted
        {
            return Err(RequestBearerError::Expired);
        }
        let parsed = Uuid::parse_str(&claims.sub).map_err(|_| RequestBearerError::Malformed)?;
        if parsed.hyphenated().to_string() != claims.sub {
            return Err(RequestBearerError::Malformed);
        }
        let authority_id =
            OidcAuthorityId::from_uuid(parsed).map_err(|_| RequestBearerError::Malformed)?;
        Ok(VerifiedRequestBearer {
            authority_id,
            issued_at_seconds: claims.iat,
            expires_at_seconds: claims.exp,
        })
    }
}

impl fmt::Debug for RequestBearerKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBearerKeyring")
            .field("config", &self.config)
            .field("active_key_id", &self.active_key_id)
            .field("verification_key_count", &self.keys.len())
            .finish()
    }
}

fn decode_segment(
    encoded: &str,
    maximum_decoded_bytes: usize,
) -> Result<Vec<u8>, RequestBearerError> {
    if encoded.contains('=') || encoded.len() > maximum_decoded_bytes.saturating_mul(2) {
        return Err(RequestBearerError::Malformed);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| RequestBearerError::Malformed)?;
    if decoded.len() > maximum_decoded_bytes || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(RequestBearerError::Malformed);
    }
    Ok(decoded)
}

#[derive(Serialize)]
struct RequestHeader<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedRequestHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Serialize)]
struct RequestClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: String,
    iat: u64,
    nbf: u64,
    exp: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedRequestClaims {
    iss: String,
    aud: String,
    sub: String,
    iat: u64,
    nbf: u64,
    exp: u64,
}
