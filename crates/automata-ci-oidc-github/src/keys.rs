use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RsaKeyPair, UnparsedPublicKey},
};
use serde::{Serialize, ser::SerializeStruct as _};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{MAXIMUM_OIDC_KEYS_PER_KEYRING, OidcIssuance, OidcIssuer, OidcKeyId};

const MAXIMUM_PRIVATE_KEY_PEM_BYTES: usize = 64 * 1_024;
const MAXIMUM_RSA_MODULUS_BYTES: usize = 1_024;
const MINIMUM_RSA_MODULUS_BITS: usize = 2_048;
const MAXIMUM_RSA_MODULUS_BITS: usize = 8_192;
const PAIR_VALIDATION_MESSAGE: &[u8] = b"automata-ci-oidc-github/rs256-key-pair/v1";

/// Sanitized RS256 key loading, rotation, or signing failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum Rs256KeyError {
    /// The bounded PEM is not an unencrypted RSA PKCS#1 or PKCS#8 private key.
    #[error("OIDC RS256 private key is invalid")]
    InvalidPrivateKey,
    /// JWK modulus or exponent syntax and strength are invalid.
    #[error("OIDC RS256 public key is invalid")]
    InvalidPublicKey,
    /// The configured public JWK does not match the private key.
    #[error("OIDC RS256 private and public keys do not match")]
    KeyPairMismatch,
    /// The key set is empty, excessive, duplicated, or lacks its active key.
    #[error("OIDC RS256 keyring is invalid")]
    InvalidKeyring,
    /// An exact replay names a signing key that is no longer loaded.
    #[error("OIDC RS256 replay signing key is unavailable")]
    MissingSigningKey,
    /// Serialization or the blinded RSA operation failed.
    #[error("OIDC RS256 signing failed")]
    SigningFailed,
}

/// Validated RSA signing public key serialized in RFC 7517 JWK form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RsaPublicJwk {
    key_id: OidcKeyId,
    modulus: String,
    exponent: String,
    public_key_der: Vec<u8>,
}

impl RsaPublicJwk {
    /// Creates an RS256 signing JWK from canonical base64url `n` and `e` values.
    ///
    /// # Errors
    ///
    /// Rejects padded/noncanonical encoding, RSA moduli outside 2048..=8192
    /// bits, and invalid public exponents.
    pub fn new(
        key_id: OidcKeyId,
        modulus: impl Into<String>,
        exponent: impl Into<String>,
    ) -> Result<Self, Rs256KeyError> {
        let modulus = modulus.into();
        let exponent = exponent.into();
        let modulus_bytes = decode_public_integer(&modulus, MAXIMUM_RSA_MODULUS_BYTES)?;
        let exponent_bytes = decode_public_integer(&exponent, size_of::<u64>())?;
        let modulus_bits =
            (modulus_bytes.len() - 1) * 8 + (u8::BITS - modulus_bytes[0].leading_zeros()) as usize;
        if !(MINIMUM_RSA_MODULUS_BITS..=MAXIMUM_RSA_MODULUS_BITS).contains(&modulus_bits) {
            return Err(Rs256KeyError::InvalidPublicKey);
        }
        let exponent_value = exponent_bytes
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
        if exponent_value < 3 || exponent_value.is_multiple_of(2) {
            return Err(Rs256KeyError::InvalidPublicKey);
        }
        let public_key_der = rsa_public_key_der(&modulus_bytes, &exponent_bytes)?;
        Ok(Self {
            key_id,
            modulus,
            exponent,
            public_key_der,
        })
    }

    /// Returns the JWK `kid`.
    #[must_use]
    pub const fn key_id(&self) -> &OidcKeyId {
        &self.key_id
    }

    /// Returns the canonical base64url RSA modulus.
    #[must_use]
    pub fn modulus(&self) -> &str {
        &self.modulus
    }

    /// Returns the canonical base64url RSA public exponent.
    #[must_use]
    pub fn exponent(&self) -> &str {
        &self.exponent
    }
}

impl Serialize for RsaPublicJwk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("RsaPublicJwk", 6)?;
        state.serialize_field("kty", "RSA")?;
        state.serialize_field("use", "sig")?;
        state.serialize_field("alg", "RS256")?;
        state.serialize_field("kid", self.key_id.as_str())?;
        state.serialize_field("n", &self.modulus)?;
        state.serialize_field("e", &self.exponent)?;
        state.end()
    }
}

fn decode_public_integer(encoded: &str, maximum_bytes: usize) -> Result<Vec<u8>, Rs256KeyError> {
    if encoded.is_empty() || encoded.contains('=') || encoded.len() > maximum_bytes * 2 {
        return Err(Rs256KeyError::InvalidPublicKey);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Rs256KeyError::InvalidPublicKey)?;
    if decoded.is_empty()
        || decoded.len() > maximum_bytes
        || decoded[0] == 0
        || URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err(Rs256KeyError::InvalidPublicKey);
    }
    Ok(decoded)
}

fn rsa_public_key_der(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>, Rs256KeyError> {
    let mut body = Vec::with_capacity(modulus.len() + exponent.len() + 16);
    append_der_integer(&mut body, modulus)?;
    append_der_integer(&mut body, exponent)?;
    let mut encoded = Vec::with_capacity(body.len() + 8);
    encoded.push(0x30);
    append_der_length(&mut encoded, body.len())?;
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

fn append_der_integer(output: &mut Vec<u8>, integer: &[u8]) -> Result<(), Rs256KeyError> {
    output.push(0x02);
    let needs_positive_prefix = integer[0] & 0x80 != 0;
    append_der_length(output, integer.len() + usize::from(needs_positive_prefix))?;
    if needs_positive_prefix {
        output.push(0);
    }
    output.extend_from_slice(integer);
    Ok(())
}

fn append_der_length(output: &mut Vec<u8>, length: usize) -> Result<(), Rs256KeyError> {
    if length < 128 {
        output.push(u8::try_from(length).map_err(|_| Rs256KeyError::InvalidPublicKey)?);
        return Ok(());
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(Rs256KeyError::InvalidPublicKey)?;
    let significant = &bytes[first..];
    let count = u8::try_from(significant.len()).map_err(|_| Rs256KeyError::InvalidPublicKey)?;
    output.push(0x80 | count);
    output.extend_from_slice(significant);
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum PrivateKeyFormat {
    Pkcs1,
    Pkcs8,
}

/// One validated RS256 private/public key pair.
pub struct Rs256SigningKey {
    public_jwk: RsaPublicJwk,
    private_key_der: Zeroizing<Vec<u8>>,
    private_key_format: PrivateKeyFormat,
}

impl Rs256SigningKey {
    /// Loads an unencrypted PKCS#1 or PKCS#8 PEM and verifies its explicit JWK.
    ///
    /// The public JWK is explicit so JWKS publication never relies on an
    /// implementation-specific private-key parser. A blinded probe signature
    /// proves the pair before either is admitted.
    ///
    /// # Errors
    ///
    /// Rejects oversized/unsupported PEM, malformed RSA keys, or a mismatched JWK.
    pub fn from_pem(
        private_key_pem: &str,
        public_jwk: RsaPublicJwk,
    ) -> Result<Self, Rs256KeyError> {
        if private_key_pem.is_empty()
            || private_key_pem.len() > MAXIMUM_PRIVATE_KEY_PEM_BYTES
            || !private_key_pem.as_bytes().starts_with(b"-----BEGIN ")
        {
            return Err(Rs256KeyError::InvalidPrivateKey);
        }
        let (label, decoded) = pem_rfc7468::decode_vec(private_key_pem.as_bytes())
            .map_err(|_| Rs256KeyError::InvalidPrivateKey)?;
        let private_key_der = Zeroizing::new(decoded);
        let private_key_format = match label {
            "RSA PRIVATE KEY" => PrivateKeyFormat::Pkcs1,
            "PRIVATE KEY" => PrivateKeyFormat::Pkcs8,
            _ => return Err(Rs256KeyError::InvalidPrivateKey),
        };
        let key = parse_private_key(private_key_format, &private_key_der)?;
        let mut signature = Zeroizing::new(vec![0_u8; key.public().modulus_len()]);
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            PAIR_VALIDATION_MESSAGE,
            &mut signature,
        )
        .map_err(|_| Rs256KeyError::InvalidPrivateKey)?;
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public_jwk.public_key_der)
            .verify(PAIR_VALIDATION_MESSAGE, &signature)
            .map_err(|_| Rs256KeyError::KeyPairMismatch)?;
        Ok(Self {
            public_jwk,
            private_key_der,
            private_key_format,
        })
    }

    fn sign(&self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>, Rs256KeyError> {
        let key = parse_private_key(self.private_key_format, &self.private_key_der)?;
        let mut signature = Zeroizing::new(vec![0_u8; key.public().modulus_len()]);
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            message,
            &mut signature,
        )
        .map_err(|_| Rs256KeyError::SigningFailed)?;
        Ok(signature)
    }
}

impl fmt::Debug for Rs256SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Rs256SigningKey")
            .field("public_jwk", &self.public_jwk)
            .field("private_key_der", &"[redacted]")
            .field("private_key_format", &self.private_key_format)
            .finish()
    }
}

fn parse_private_key(
    format: PrivateKeyFormat,
    key_der: &[u8],
) -> Result<RsaKeyPair, Rs256KeyError> {
    match format {
        PrivateKeyFormat::Pkcs1 => RsaKeyPair::from_der(key_der),
        PrivateKeyFormat::Pkcs8 => RsaKeyPair::from_pkcs8(key_der),
    }
    .map_err(|_| Rs256KeyError::InvalidPrivateKey)
}

/// Public JSON Web Key Set response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JsonWebKeySet {
    keys: Vec<RsaPublicJwk>,
}

impl JsonWebKeySet {
    /// Returns every accepted verification key sorted by `kid`.
    #[must_use]
    pub fn keys(&self) -> &[RsaPublicJwk] {
        &self.keys
    }
}

/// Redacted RS256 ID token returned only at the HTTP response boundary.
pub struct OidcIdToken(Zeroizing<String>);

impl OidcIdToken {
    /// Exposes the compact JWT only at an explicit response boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OidcIdToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OidcIdToken([redacted])")
    }
}

/// Rotatable RS256 signing keyring that retains keys needed for exact replay.
pub struct Rs256Keyring {
    active_key_id: OidcKeyId,
    keys: BTreeMap<OidcKeyId, Rs256SigningKey>,
}

impl Rs256Keyring {
    /// Creates a bounded keyring whose active key must be present exactly once.
    ///
    /// # Errors
    ///
    /// Rejects an empty/oversized key set, duplicate IDs, or a missing active key.
    pub fn new(
        active_key_id: OidcKeyId,
        keys: impl IntoIterator<Item = Rs256SigningKey>,
    ) -> Result<Self, Rs256KeyError> {
        let mut key_map = BTreeMap::new();
        for key in keys {
            if key_map.len() >= MAXIMUM_OIDC_KEYS_PER_KEYRING
                || key_map.insert(key.public_jwk.key_id.clone(), key).is_some()
            {
                return Err(Rs256KeyError::InvalidKeyring);
            }
        }
        if key_map.is_empty() || !key_map.contains_key(&active_key_id) {
            return Err(Rs256KeyError::InvalidKeyring);
        }
        Ok(Self {
            active_key_id,
            keys: key_map,
        })
    }

    /// Returns the key used for a newly reserved issuance.
    #[must_use]
    pub const fn active_key_id(&self) -> &OidcKeyId {
        &self.active_key_id
    }

    /// Returns whether a replay-bound signing key remains available.
    #[must_use]
    pub fn contains_key(&self, key_id: &OidcKeyId) -> bool {
        self.keys.contains_key(key_id)
    }

    /// Returns every public verification key sorted by `kid`.
    #[must_use]
    pub fn jwks(&self) -> JsonWebKeySet {
        JsonWebKeySet {
            keys: self
                .keys
                .values()
                .map(|key| key.public_jwk.clone())
                .collect(),
        }
    }

    /// Signs one exact repository-reserved issuance with its bound key.
    ///
    /// # Errors
    ///
    /// Fails closed if replay names a removed key or serialization/signing fails.
    pub fn sign(
        &self,
        issuer: &OidcIssuer,
        issuance: &OidcIssuance,
    ) -> Result<OidcIdToken, Rs256KeyError> {
        let key = self
            .keys
            .get(issuance.signing_key_id())
            .ok_or(Rs256KeyError::MissingSigningKey)?;
        let header = IdTokenHeader {
            alg: "RS256",
            typ: "JWT",
            kid: issuance.signing_key_id().as_str(),
        };
        let claims = IdTokenClaims {
            iss: issuer.as_str(),
            sub: issuance.subject().as_str(),
            aud: issuance.audience().as_str(),
            exp: issuance.expires_at_seconds(),
            nbf: issuance.not_before_seconds(),
            iat: issuance.issued_at_seconds(),
            jti: issuance.token_id().to_string(),
            additional: issuance.additional_claims().as_map(),
        };
        let header = serde_json::to_vec(&header).map_err(|_| Rs256KeyError::SigningFailed)?;
        let claims = serde_json::to_vec(&claims).map_err(|_| Rs256KeyError::SigningFailed)?;
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signature = key.sign(signing_input.as_bytes())?;
        Ok(OidcIdToken(Zeroizing::new(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(&*signature)
        ))))
    }
}

impl fmt::Debug for Rs256Keyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Rs256Keyring")
            .field("active_key_id", &self.active_key_id)
            .field("signing_key_count", &self.keys.len())
            .finish()
    }
}

#[derive(Serialize)]
struct IdTokenHeader<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

#[derive(Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: u64,
    nbf: u64,
    iat: u64,
    jti: String,
    #[serde(flatten)]
    additional: &'a BTreeMap<String, String>,
}
