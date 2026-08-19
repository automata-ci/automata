use std::fmt;

use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderName};
use ring::{digest, hmac};
use thiserror::Error;

/// Maximum raw Forgejo webhook body accepted by the provider boundary.
pub const FORGEJO_WEBHOOK_BODY_LIMIT: usize = 26_214_400;
/// Maximum configured Forgejo webhook secret size.
pub const FORGEJO_WEBHOOK_SECRET_LIMIT: usize = 16_384;
/// Media type used when authenticated Forgejo bytes are durably archived.
pub const FORGEJO_AUTHENTICATED_EVENT_MEDIA_TYPE: &str =
    "application/vnd.automata.forgejo-authenticated-event+json";

/// Forgejo event-name header.
pub const X_FORGEJO_EVENT: &str = "x-forgejo-event";
/// Forgejo native HMAC-SHA256 signature header.
pub const X_FORGEJO_SIGNATURE: &str = "x-forgejo-signature";
/// Gitea/Forgejo delivery UUID header.
pub const X_GITEA_DELIVERY: &str = "x-gitea-delivery";

const MAX_HEADER_BYTES: usize = 128;
const FINGERPRINT_DOMAIN: &[u8] = b"automata.store.forgejo-webhook-verifier-fingerprint.v1\0";

/// Authenticated Forgejo webhook evidence before event-specific decoding.
pub struct ForgejoAuthenticatedWebhook {
    raw_body: Bytes,
    body_digest: ForgejoWebhookBodyDigest,
    event_name: Box<str>,
    delivery_id: Box<str>,
}

impl ForgejoAuthenticatedWebhook {
    /// Returns the exact authenticated raw body.
    #[must_use]
    pub fn raw_body(&self) -> &Bytes {
        &self.raw_body
    }
    /// Returns the body digest bound to these bytes.
    #[must_use]
    pub const fn body_digest(&self) -> ForgejoWebhookBodyDigest {
        self.body_digest
    }
    /// Returns the provider event name.
    #[must_use]
    pub fn event_name(&self) -> &str {
        &self.event_name
    }
    /// Returns the unique delivery UUID.
    #[must_use]
    pub fn delivery_id(&self) -> &str {
        &self.delivery_id
    }
}

impl fmt::Debug for ForgejoAuthenticatedWebhook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForgejoAuthenticatedWebhook")
            .field("raw_body", &"[redacted]")
            .field("body_digest", &"[redacted]")
            .field("event_name", &self.event_name)
            .field("delivery_id", &"[redacted]")
            .finish()
    }
}

/// Domain-separated SHA-256 digest of an authenticated Forgejo body.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ForgejoWebhookBodyDigest([u8; 32]);

impl ForgejoWebhookBodyDigest {
    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Public fingerprint of a configured Forgejo webhook secret.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ForgejoWebhookVerifierFingerprint([u8; 32]);

impl ForgejoWebhookVerifierFingerprint {
    /// Returns the public fingerprint bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ForgejoWebhookVerifierFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ForgejoWebhookVerifierFingerprint([public sha256])")
    }
}

/// Authenticates Forgejo's native raw-body webhook signature.
pub struct ForgejoWebhookVerifier {
    key: hmac::Key,
    fingerprint: ForgejoWebhookVerifierFingerprint,
}

impl ForgejoWebhookVerifier {
    /// Constructs a verifier for one nonempty bounded secret.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized webhook secret.
    pub fn new(secret: &[u8]) -> Result<Self, ForgejoWebhookError> {
        if secret.is_empty() || secret.len() > FORGEJO_WEBHOOK_SECRET_LIMIT {
            return Err(ForgejoWebhookError::InvalidSecret);
        }
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(FINGERPRINT_DOMAIN);
        context.update(secret);
        let digest = context.finish();
        let mut fingerprint = [0_u8; 32];
        fingerprint.copy_from_slice(digest.as_ref());
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
            fingerprint: ForgejoWebhookVerifierFingerprint(fingerprint),
        })
    }

    /// Returns the public secret fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> ForgejoWebhookVerifierFingerprint {
        self.fingerprint
    }

    /// Authenticates a bounded raw Forgejo webhook without decoding JSON.
    ///
    /// # Errors
    ///
    /// Rejects oversized bodies, missing or malformed headers, and failed HMAC
    /// authentication.
    pub fn authenticate(
        &self,
        headers: &HeaderMap,
        raw_body: Bytes,
    ) -> Result<ForgejoAuthenticatedWebhook, ForgejoWebhookError> {
        if raw_body.len() > FORGEJO_WEBHOOK_BODY_LIMIT {
            return Err(ForgejoWebhookError::BodyTooLarge);
        }
        let event = header(headers, X_FORGEJO_EVENT)?;
        let delivery = header(headers, X_GITEA_DELIVERY)?;
        let signature = header(headers, X_FORGEJO_SIGNATURE)?;
        let signature = decode_hex_signature(&signature)?;
        hmac::verify(&self.key, &raw_body, &signature)
            .map_err(|_| ForgejoWebhookError::InvalidSignature)?;
        let mut digest = digest::Context::new(&digest::SHA256);
        digest.update(&raw_body);
        let mut body_digest = [0_u8; 32];
        body_digest.copy_from_slice(digest.finish().as_ref());
        Ok(ForgejoAuthenticatedWebhook {
            raw_body,
            body_digest: ForgejoWebhookBodyDigest(body_digest),
            event_name: event.into_boxed_str(),
            delivery_id: delivery.into_boxed_str(),
        })
    }
}

impl fmt::Debug for ForgejoWebhookVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ForgejoWebhookVerifier([redacted])")
    }
}

fn header(headers: &HeaderMap, name: &str) -> Result<String, ForgejoWebhookError> {
    let name =
        HeaderName::from_bytes(name.as_bytes()).map_err(|_| ForgejoWebhookError::InvalidHeader)?;
    if headers.get_all(&name).iter().count() != 1 {
        return Err(ForgejoWebhookError::MissingHeader);
    }
    let value = headers
        .get(name)
        .ok_or(ForgejoWebhookError::MissingHeader)?
        .to_str()
        .map_err(|_| ForgejoWebhookError::InvalidHeader)?;
    if value.is_empty() || value.len() > MAX_HEADER_BYTES || !value.is_ascii() {
        return Err(ForgejoWebhookError::InvalidHeader);
    }
    Ok(value.to_owned())
}

fn decode_hex_signature(value: &str) -> Result<Vec<u8>, ForgejoWebhookError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ForgejoWebhookError::InvalidSignature);
    }
    (0..64)
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| ForgejoWebhookError::InvalidSignature)
        })
        .collect()
}

/// Sanitized Forgejo webhook boundary failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ForgejoWebhookError {
    /// The configured secret is empty or too large.
    #[error("Forgejo webhook secret is invalid")]
    InvalidSecret,
    /// The raw body exceeds the configured admission bound.
    #[error("Forgejo webhook body is too large")]
    BodyTooLarge,
    /// A required Forgejo header is absent.
    #[error("Forgejo webhook header is missing")]
    MissingHeader,
    /// A required Forgejo header is malformed.
    #[error("Forgejo webhook header is invalid")]
    InvalidHeader,
    /// The signature is malformed or does not authenticate the exact body.
    #[error("Forgejo webhook signature is invalid")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;
    use std::fmt::Write as _;

    const SECRET: &[u8] = b"forgejo-test-secret";
    const BODY: &[u8] = br#"{"ref":"refs/heads/main"}"#;

    fn headers(signature: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORGEJO_EVENT, HeaderValue::from_static("push"));
        headers.insert(
            X_GITEA_DELIVERY,
            HeaderValue::from_static("d9d2f7d4-9f31-4c5c-8b5f-2f2b6f7f7d21"),
        );
        headers.insert(
            X_FORGEJO_SIGNATURE,
            HeaderValue::from_str(signature).unwrap(),
        );
        headers
    }

    fn signature() -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, SECRET);
        hmac::sign(&key, BODY).as_ref().iter().fold(
            String::with_capacity(64),
            |mut output, byte| {
                write!(output, "{byte:02x}").unwrap();
                output
            },
        )
    }

    #[test]
    fn authenticates_exact_native_signature_and_redacts_debug() {
        let verifier = ForgejoWebhookVerifier::new(SECRET).unwrap();
        let authenticated = verifier
            .authenticate(&headers(&signature()), Bytes::from_static(BODY))
            .unwrap();
        assert_eq!(authenticated.event_name(), "push");
        assert_eq!(
            authenticated.delivery_id(),
            "d9d2f7d4-9f31-4c5c-8b5f-2f2b6f7f7d21"
        );
        assert!(!format!("{verifier:?}").contains("forgejo-test-secret"));
        assert!(!format!("{authenticated:?}").contains("refs/heads/main"));
    }

    #[test]
    fn rejects_wrong_encoding_body_and_duplicate_headers() {
        let verifier = ForgejoWebhookVerifier::new(SECRET).unwrap();
        assert!(matches!(
            verifier.authenticate(&headers("sha256="), Bytes::from_static(BODY)),
            Err(ForgejoWebhookError::InvalidSignature)
        ));
        assert!(matches!(
            verifier.authenticate(&headers(&signature()), Bytes::from_static(br"{}")),
            Err(ForgejoWebhookError::InvalidSignature)
        ));
        let mut duplicate = headers(&signature());
        duplicate.append(X_GITEA_DELIVERY, HeaderValue::from_static("second"));
        assert!(matches!(
            verifier.authenticate(&duplicate, Bytes::from_static(BODY)),
            Err(ForgejoWebhookError::MissingHeader)
        ));
    }
}
