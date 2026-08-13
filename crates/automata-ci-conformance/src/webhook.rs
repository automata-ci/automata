use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::catalog::hex_digest;

/// Exact webhook bytes and headers injected into product ingress.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawWebhookFixture {
    event: String,
    delivery_id: String,
    signature_sha256: String,
    body: Vec<u8>,
    body_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawWebhookFixtureWire {
    event: String,
    delivery_id: String,
    signature_sha256: String,
    body: Vec<u8>,
    body_sha256: String,
}

impl RawWebhookFixture {
    /// Locks one exact raw body and matching GitHub signature header.
    ///
    /// # Errors
    ///
    /// Rejects unsafe headers, malformed signatures, and empty or oversized bodies.
    pub fn new(
        event: impl Into<String>,
        delivery_id: impl Into<String>,
        signature_sha256: impl Into<String>,
        body: Vec<u8>,
    ) -> Result<Self, RawWebhookFixtureError> {
        let event = event.into();
        let delivery_id = delivery_id.into();
        let signature_sha256 = signature_sha256.into();
        if !header_token(&event) || !header_token(&delivery_id) {
            return Err(RawWebhookFixtureError::InvalidHeader);
        }
        let Some(digest) = signature_sha256.strip_prefix("sha256=") else {
            return Err(RawWebhookFixtureError::InvalidSignature);
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(RawWebhookFixtureError::InvalidSignature);
        }
        if body.is_empty() || body.len() > 25 * 1_048_576 {
            return Err(RawWebhookFixtureError::InvalidBody);
        }
        let body_sha256 = hex_digest(&Sha256::digest(&body));
        Ok(Self {
            event,
            delivery_id,
            signature_sha256,
            body,
            body_sha256,
        })
    }

    /// Parses only the exact canonical encoding and recomputes the body digest.
    ///
    /// # Errors
    ///
    /// Rejects malformed JSON, unknown fields, invalid headers/signatures/body,
    /// a forged body digest, or a non-canonical representation.
    pub fn from_json(bytes: &[u8]) -> Result<Self, RawWebhookFixtureError> {
        let wire: RawWebhookFixtureWire =
            serde_json::from_slice(bytes).map_err(|_| RawWebhookFixtureError::InvalidJson)?;
        let expected_body_sha256 = wire.body_sha256;
        let fixture = Self::new(
            wire.event,
            wire.delivery_id,
            wire.signature_sha256,
            wire.body,
        )?;
        if fixture.body_sha256 != expected_body_sha256 {
            return Err(RawWebhookFixtureError::BodyDigestMismatch);
        }
        if fixture.canonical_json()?.as_slice() != bytes {
            return Err(RawWebhookFixtureError::NonCanonicalEncoding);
        }
        Ok(fixture)
    }

    /// Serializes this fixture as compact canonical JSON with one trailing newline.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization unexpectedly fails.
    pub fn canonical_json(&self) -> Result<Vec<u8>, RawWebhookFixtureError> {
        let mut bytes =
            serde_json::to_vec(self).map_err(|_| RawWebhookFixtureError::InvalidJson)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    #[must_use]
    pub fn event(&self) -> &str {
        &self.event
    }
    #[must_use]
    pub fn delivery_id(&self) -> &str {
        &self.delivery_id
    }
    #[must_use]
    pub fn signature_sha256(&self) -> &str {
        &self.signature_sha256
    }
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    #[must_use]
    pub fn body_sha256(&self) -> &str {
        &self.body_sha256
    }
}

fn header_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.trim() == value
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RawWebhookFixtureError {
    #[error("webhook fixture JSON is invalid")]
    InvalidJson,
    #[error("webhook fixture JSON is not its exact canonical encoding")]
    NonCanonicalEncoding,
    #[error("webhook fixture header is invalid")]
    InvalidHeader,
    #[error("webhook fixture signature is not an exact SHA-256 header")]
    InvalidSignature,
    #[error("webhook fixture body is empty or oversized")]
    InvalidBody,
    #[error("webhook fixture body digest does not match its exact bytes")]
    BodyDigestMismatch,
}
