use std::fmt;

use automata_ci_auth::{secret::SecretString, time::UnixTimestamp};
use automata_ci_scm::credential::ProviderResourceId;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair},
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use automata_ci_store::Sha256Digest;

const MAX_PRIVATE_KEY_PEM_BYTES: usize = 32 * 1_024;
const IAT_BACKDATE_SECONDS: u64 = 60;
const JWT_LIFETIME_SECONDS: u64 = 600;
const JWT_HEADER: &str = r#"{"alg":"RS256","typ":"JWT"}"#;
const RSA_ENCRYPTION_ALGORITHM_IDENTIFIER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

pub(crate) struct GithubAppJwtSigner {
    key_der: Zeroizing<Vec<u8>>,
    key_format: KeyFormat,
    issuer: ProviderResourceId,
    app_key_spki_sha256: Sha256Digest,
}

impl GithubAppJwtSigner {
    pub(crate) fn from_pem(
        private_key_pem: &SecretString,
        issuer: ProviderResourceId,
    ) -> Result<Self, GithubAppKeyError> {
        let pem = private_key_pem.expose_secret();
        if pem.len() > MAX_PRIVATE_KEY_PEM_BYTES || !pem.as_bytes().starts_with(b"-----BEGIN ") {
            return Err(GithubAppKeyError::InvalidPrivateKey);
        }
        let (label, decoded) = pem_rfc7468::decode_vec(pem.as_bytes())
            .map_err(|_| GithubAppKeyError::InvalidPrivateKey)?;
        // Wrap decoded secret material before examining any metadata so every
        // successful decode path, including a rejected label, is zeroized.
        let key_der = Zeroizing::new(decoded);
        let key_format = match label {
            "PRIVATE KEY" => KeyFormat::Pkcs8,
            "RSA PRIVATE KEY" => KeyFormat::Pkcs1,
            _ => return Err(GithubAppKeyError::InvalidPrivateKey),
        };
        let key = parse_key(key_format, &key_der)?;
        let app_key_spki_sha256 = rsa_spki_sha256(key.public_key().as_ref());
        Ok(Self {
            key_der,
            key_format,
            issuer,
            app_key_spki_sha256,
        })
    }

    pub(crate) const fn app_key_spki_sha256(&self) -> Sha256Digest {
        self.app_key_spki_sha256
    }

    pub(crate) fn sign(&self, now: UnixTimestamp) -> Result<GithubAppJwt, GithubAppKeyError> {
        let issued_at = now
            .as_seconds()
            .checked_sub(IAT_BACKDATE_SECONDS)
            .ok_or(GithubAppKeyError::ClockOutOfRange)?;
        let expires_at = issued_at
            .checked_add(JWT_LIFETIME_SECONDS)
            .ok_or(GithubAppKeyError::ClockOutOfRange)?;
        let claims = JwtClaims {
            iat: issued_at,
            exp: expires_at,
            iss: self.issuer.as_str(),
        };
        let payload = serde_json::to_vec(&claims).map_err(|_| GithubAppKeyError::SigningFailed)?;
        let encoded_header = URL_SAFE_NO_PAD.encode(JWT_HEADER.as_bytes());
        let encoded_payload = URL_SAFE_NO_PAD.encode(payload);
        let signing_input = format!("{encoded_header}.{encoded_payload}");
        let key = parse_key(self.key_format, &self.key_der)?;
        let mut signature_bytes = Zeroizing::new(vec![0_u8; key.public().modulus_len()]);
        // RSASSA-PKCS1-v1_5 output is deterministic. `ring` consumes the system
        // RNG to blind the private-key operation against timing observations.
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signing_input.as_bytes(),
            &mut signature_bytes,
        )
        .map_err(|_| GithubAppKeyError::SigningFailed)?;
        let encoded_signature = Zeroizing::new(URL_SAFE_NO_PAD.encode(&*signature_bytes));
        Ok(GithubAppJwt(Zeroizing::new(format!(
            "{signing_input}.{}",
            encoded_signature.as_str()
        ))))
    }
}

impl fmt::Debug for GithubAppJwtSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubAppJwtSigner")
            .field("key_der", &"[redacted]")
            .field("key_format", &self.key_format)
            .field("issuer", &self.issuer)
            .field("app_key_spki_sha256", &self.app_key_spki_sha256)
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
enum KeyFormat {
    Pkcs1,
    Pkcs8,
}

fn parse_key(key_format: KeyFormat, key_der: &[u8]) -> Result<RsaKeyPair, GithubAppKeyError> {
    match key_format {
        KeyFormat::Pkcs1 => RsaKeyPair::from_der(key_der),
        KeyFormat::Pkcs8 => RsaKeyPair::from_pkcs8(key_der),
    }
    .map_err(|_| GithubAppKeyError::InvalidPrivateKey)
}

fn rsa_spki_sha256(pkcs1_public_key_der: &[u8]) -> Sha256Digest {
    // `ring::rsa::PublicKey::as_ref` is the canonical DER PKCS#1
    // `RSAPublicKey`. SubjectPublicKeyInfo wraps that exact value in the
    // rsaEncryption AlgorithmIdentifier and a zero-unused-bits BIT STRING.
    let mut subject_public_key = Vec::with_capacity(pkcs1_public_key_der.len() + 8);
    subject_public_key.push(0);
    subject_public_key.extend_from_slice(pkcs1_public_key_der);
    let subject_public_key = der_tlv(0x03, &subject_public_key);
    let mut spki_value =
        Vec::with_capacity(RSA_ENCRYPTION_ALGORITHM_IDENTIFIER.len() + subject_public_key.len());
    spki_value.extend_from_slice(RSA_ENCRYPTION_ALGORITHM_IDENTIFIER);
    spki_value.extend_from_slice(&subject_public_key);
    let spki = der_tlv(0x30, &spki_value);
    Sha256Digest::from_bytes(Sha256::digest(spki).into())
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(value.len() + 6);
    encoded.push(tag);
    der_length(value.len(), &mut encoded);
    encoded.extend_from_slice(value);
    encoded
}

fn der_length(length: usize, encoded: &mut Vec<u8>) {
    if length < 0x80 {
        encoded.push(u8::try_from(length).expect("short DER length fits u8"));
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-short DER length is nonzero");
    let significant = &bytes[first..];
    encoded.push(0x80 | u8::try_from(significant.len()).expect("usize DER length fits one octet"));
    encoded.extend_from_slice(significant);
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    iat: u64,
    exp: u64,
    iss: &'a str,
}

pub(crate) struct GithubAppJwt(Zeroizing<String>);

impl GithubAppJwt {
    pub(crate) fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GithubAppJwt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubAppJwt([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
/// Sanitized failure while loading a GitHub App key or signing an assertion.
///
/// No variant contains private-key bytes, assertion contents, or a provider
/// identity. Successfully decoded key and signature buffers are zeroized.
pub enum GithubAppKeyError {
    /// The bounded PEM was not a supported, valid RSA PKCS#1 or PKCS#8 key.
    #[error("GitHub App private key is invalid")]
    InvalidPrivateKey,
    /// The current time could not represent the bounded assertion interval.
    #[error("system clock cannot produce a valid GitHub App assertion")]
    ClockOutOfRange,
    /// RS256 signing failed without exposing the underlying key-library error.
    #[error("GitHub App assertion signing failed")]
    SigningFailed,
}
