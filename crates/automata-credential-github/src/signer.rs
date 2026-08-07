use std::fmt;

use automata_auth::{secret::SecretString, time::UnixTimestamp};
use automata_credential::ProviderResourceId;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_PRIVATE_KEY_PEM_BYTES: usize = 32 * 1_024;
const IAT_BACKDATE_SECONDS: u64 = 60;
const JWT_LIFETIME_SECONDS: u64 = 600;
const JWT_HEADER: &str = r#"{"alg":"RS256","typ":"JWT"}"#;

pub(crate) struct GithubAppJwtSigner {
    key_der: Zeroizing<Vec<u8>>,
    key_format: KeyFormat,
    issuer: ProviderResourceId,
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
        parse_key(key_format, &key_der)?;
        Ok(Self {
            key_der,
            key_format,
            issuer,
        })
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
pub enum GithubAppKeyError {
    #[error("GitHub App private key is invalid")]
    InvalidPrivateKey,
    #[error("system clock cannot produce a valid GitHub App assertion")]
    ClockOutOfRange,
    #[error("GitHub App assertion signing failed")]
    SigningFailed,
}
