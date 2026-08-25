//! Private binary envelope for one managed-secret delivery operation.
//!
//! This is deliberately separate from runner-control protobuf.  The envelope
//! is accepted only on the dedicated mTLS ephemeral route, is never written to
//! a runner command, journal, or spool, and carries a one-shot bearer only in
//! zeroizing memory.  The server still has to authenticate the machine from
//! TLS and recheck every coordinate against shared durable state.

use std::fmt;

use automata_ci_core::{
    AttemptId, FencingToken, Lease, LeaseId, RunnerId, SecretBinding, UnixMillis,
};
use automata_ci_protocol::ManagedSecretBindingOverlay;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

const REQUEST_MAGIC: &[u8; 4] = b"AMSD";
const RESPONSE_MAGIC: &[u8; 4] = b"AMSR";
const WIRE_VERSION: u8 = 1;
const FETCH: u8 = 1;
const ACKNOWLEDGE: u8 = 2;
const MAX_BINDINGS: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 1_024;
const MAX_KEY_ID_BYTES: usize = 128;
const MIN_BEARER_BYTES: usize = 32;
const MAX_BEARER_BYTES: usize = 64;
const MAX_SECRET_BYTES: usize = 65_536;
const MAX_TOTAL_SECRET_BYTES: usize = 1_024 * 1_024;

/// Exact value-free identity carried by a private secret-delivery request.
///
/// Every UUID is represented as its RFC-4122 network-order bytes.  The wire
/// model intentionally does not interpret any identity; the application layer
/// converts it to its strongly typed store value before authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedSecretDeliveryCoordinates {
    /// Claimed durable runner identity.
    pub runner_id: [u8; 16],
    /// Claimed current runner-session identity.
    pub session_id: [u8; 16],
    /// One-based runner slot that accepted the lease.
    pub slot: u16,
    /// Exact workflow run.
    pub run_id: [u8; 16],
    /// Exact concrete job.
    pub job_id: [u8; 16],
    /// Exact leased attempt.
    pub attempt_id: [u8; 16],
    /// Exact lease identity.
    pub lease_id: [u8; 16],
    /// Lease issuance wall-clock bound.
    pub lease_issued_at_ms: i64,
    /// Lease exclusive expiry wall-clock bound.
    pub lease_expires_at_ms: i64,
    /// Exact fencing token.
    pub fencing_token: u64,
    /// Digest of the verified immutable runtime context.
    pub runtime_context_digest: [u8; 32],
    /// Digest of the lease-scoped, value-free binding overlay.
    pub binding_overlay_digest: [u8; 32],
}

/// One exact runtime-context secret locator, without a plaintext value.
#[derive(Clone, Eq, PartialEq)]
pub struct ManagedSecretDeliveryBinding {
    canonical_name: String,
    binding_id: String,
    version_id: String,
}

impl ManagedSecretDeliveryBinding {
    /// Creates a bounded exact binding/version pair.
    ///
    /// # Errors
    ///
    /// Rejects empty, control-bearing, or overlong opaque identifiers.
    pub fn new(
        canonical_name: impl Into<String>,
        binding_id: impl Into<String>,
        version_id: impl Into<String>,
    ) -> Result<Self, ManagedSecretDeliveryWireError> {
        let canonical_name = canonical_name.into();
        let binding_id = binding_id.into();
        let version_id = version_id.into();
        if !valid_canonical_name(&canonical_name)
            || !valid_canonical_uuid(&binding_id)
            || !valid_canonical_uuid(&version_id)
        {
            return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
        }
        Ok(Self {
            canonical_name,
            binding_id,
            version_id,
        })
    }

    /// Returns the canonical environment name committed by the lease overlay.
    #[must_use]
    pub fn canonical_name(&self) -> &str {
        &self.canonical_name
    }

    /// Returns the opaque runtime-context binding identity.
    #[must_use]
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    /// Returns the immutable selected secret-version identity.
    #[must_use]
    pub fn version_id(&self) -> &str {
        &self.version_id
    }
}

impl fmt::Debug for ManagedSecretDeliveryBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSecretDeliveryBinding")
            .field("canonical_name", &"[REDACTED]")
            .field("binding_id", &"[REDACTED]")
            .field("version_id", &"[REDACTED]")
            .finish()
    }
}

/// Private request operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedSecretDeliveryOperation {
    /// Atomically reserve or replay the exact delivery, then return values.
    Fetch,
    /// Acknowledge full local decoding and custody of a previous fetch reply.
    Acknowledge,
}

/// Decoded private delivery request.
///
/// The bearer is intentionally not `Clone`, `Serialize`, or printable.  It
/// is carried only by this request and the transport's zeroizing aggregate.
pub struct ManagedSecretDeliveryRequest {
    operation: ManagedSecretDeliveryOperation,
    credential_key_id: String,
    bearer: Zeroizing<Vec<u8>>,
    coordinates: ManagedSecretDeliveryCoordinates,
    bindings: Vec<ManagedSecretDeliveryBinding>,
}

impl ManagedSecretDeliveryRequest {
    /// Builds a one-shot private delivery request.
    ///
    /// # Errors
    ///
    /// Rejects malformed coordinates, empty/oversized binding sets, and an
    /// invalid bearer.  Rejected bearer bytes are zeroized before return.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: ManagedSecretDeliveryOperation,
        credential_key_id: impl Into<String>,
        mut bearer: Vec<u8>,
        coordinates: ManagedSecretDeliveryCoordinates,
        bindings: Vec<ManagedSecretDeliveryBinding>,
    ) -> Result<Self, ManagedSecretDeliveryWireError> {
        let credential_key_id = credential_key_id.into();
        if !valid_key_id(&credential_key_id)
            || bearer.len() < MIN_BEARER_BYTES
            || bearer.len() > MAX_BEARER_BYTES
            || bearer.iter().all(|byte| *byte == 0)
            || !valid_coordinates(coordinates)
            || bindings.is_empty()
            || bindings.len() > MAX_BINDINGS
            || !bindings_are_unique(&bindings)
            || !bindings_match_overlay(coordinates, &bindings)
        {
            bearer.zeroize();
            return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
        }
        Ok(Self {
            operation,
            credential_key_id,
            bearer: Zeroizing::new(bearer),
            coordinates,
            bindings,
        })
    }

    /// Returns the private operation kind.
    #[must_use]
    pub const fn operation(&self) -> ManagedSecretDeliveryOperation {
        self.operation
    }

    /// Returns the non-secret verifier-key identity.
    #[must_use]
    pub fn credential_key_id(&self) -> &str {
        &self.credential_key_id
    }

    /// Exposes the bearer only to the immediate authorization adapter.
    #[must_use]
    pub fn expose_bearer(&self) -> &[u8] {
        &self.bearer
    }

    /// Returns exact claimed execution coordinates.
    #[must_use]
    pub const fn coordinates(&self) -> ManagedSecretDeliveryCoordinates {
        self.coordinates
    }

    /// Returns the exact runtime-context binding set.
    #[must_use]
    pub fn bindings(&self) -> &[ManagedSecretDeliveryBinding] {
        &self.bindings
    }

    /// Encodes the request for one exact retry-stable private exchange.
    ///
    /// # Errors
    ///
    /// Returns an error only if a previously valid in-memory envelope cannot
    /// fit within the fixed ephemeral transport request bound.
    pub fn encode(&self) -> Result<Vec<u8>, ManagedSecretDeliveryWireError> {
        let mut output = Vec::with_capacity(256 + self.bindings.len() * 64);
        output.extend_from_slice(REQUEST_MAGIC);
        output.push(WIRE_VERSION);
        output.push(match self.operation {
            ManagedSecretDeliveryOperation::Fetch => FETCH,
            ManagedSecretDeliveryOperation::Acknowledge => ACKNOWLEDGE,
        });
        put_short(&mut output, self.credential_key_id.as_bytes())?;
        put_short(&mut output, &self.bearer)?;
        encode_coordinates(&mut output, self.coordinates);
        let count = u16::try_from(self.bindings.len())
            .map_err(|_| ManagedSecretDeliveryWireError::InvalidEnvelope)?;
        output.extend_from_slice(&count.to_be_bytes());
        for binding in &self.bindings {
            put_short(&mut output, binding.canonical_name.as_bytes())?;
            put_short(&mut output, binding.binding_id.as_bytes())?;
            put_short(&mut output, binding.version_id.as_bytes())?;
        }
        if output.len() > crate::MAX_EPHEMERAL_REQUEST_BYTES {
            output.zeroize();
            return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
        }
        Ok(output)
    }

    /// Decodes one bounded private-route request.
    ///
    /// The incoming body is copied into the resulting request's zeroizing
    /// bearer custody.  The transport retains and zeroizes its own aggregate.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, noncanonical, or cross-bound request
    /// evidence without exposing any portion of the bearer in diagnostics.
    pub fn decode(body: &[u8]) -> Result<Self, ManagedSecretDeliveryWireError> {
        if body.len() > crate::MAX_EPHEMERAL_REQUEST_BYTES {
            return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
        }
        let mut input = Decoder::new(body);
        if input.take_exact(4)? != REQUEST_MAGIC || input.byte()? != WIRE_VERSION {
            return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
        }
        let operation = match input.byte()? {
            FETCH => ManagedSecretDeliveryOperation::Fetch,
            ACKNOWLEDGE => ManagedSecretDeliveryOperation::Acknowledge,
            _ => return Err(ManagedSecretDeliveryWireError::InvalidEnvelope),
        };
        let credential_key_id = input.utf8_short()?;
        // Parsing continues after the bearer. Keep the copy zeroizing so a
        // malformed coordinate or binding cannot leave plaintext credential
        // bytes in an ordinary allocation on the error path.
        let mut bearer = Zeroizing::new(input.short()?.to_vec());
        let coordinates = decode_coordinates(&mut input)?;
        let count = usize::from(input.u16()?);
        if count == 0 || count > MAX_BINDINGS {
            return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
        }
        let mut bindings = Vec::with_capacity(count);
        for _ in 0..count {
            bindings.push(ManagedSecretDeliveryBinding::new(
                input.utf8_short()?,
                input.utf8_short()?,
                input.utf8_short()?,
            )?);
        }
        if !input.is_empty() {
            return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
        }
        Self::new(
            operation,
            credential_key_id,
            std::mem::take(&mut *bearer),
            coordinates,
            bindings,
        )
    }
}

impl fmt::Debug for ManagedSecretDeliveryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSecretDeliveryRequest")
            .field("operation", &self.operation)
            .field("binding_count", &self.bindings.len())
            .field("coordinates", &"[REDACTED]")
            .field("credential_key_id", &"[REDACTED]")
            .field("bearer", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// One decoded plaintext value from the private response.
///
/// It is non-cloneable and its bytes zeroize when dropped unless transferred
/// into the executor's final `SecretString` custody.
pub struct ManagedSecretDeliveryValue {
    binding_id: String,
    version_id: String,
    value: Zeroizing<Vec<u8>>,
}

impl ManagedSecretDeliveryValue {
    /// Constructs one bounded value bound to an exact runtime locator.
    ///
    /// # Errors
    ///
    /// Rejects invalid identifiers or empty/oversized plaintext bytes.
    pub fn new(
        binding_id: impl Into<String>,
        version_id: impl Into<String>,
        mut value: Vec<u8>,
    ) -> Result<Self, ManagedSecretDeliveryWireError> {
        let binding_id = binding_id.into();
        let version_id = version_id.into();
        if !valid_identifier(&binding_id)
            || !valid_identifier(&version_id)
            || value.is_empty()
            || value.len() > MAX_SECRET_BYTES
        {
            value.zeroize();
            return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
        }
        Ok(Self {
            binding_id,
            version_id,
            value: Zeroizing::new(value),
        })
    }

    /// Returns the exact runtime-context binding identity.
    #[must_use]
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    /// Returns the exact immutable version identity.
    #[must_use]
    pub fn version_id(&self) -> &str {
        &self.version_id
    }

    /// Transfers plaintext into the final local custody decoder.
    #[must_use]
    pub fn into_value(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.value))
    }
}

impl fmt::Debug for ManagedSecretDeliveryValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSecretDeliveryValue")
            .field("binding_id", &"[REDACTED]")
            .field("version_id", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Private response for one fetch or acknowledgement exchange.
pub enum ManagedSecretDeliveryResponse {
    /// Exact values returned only after an atomic authority reservation.
    Values(Vec<ManagedSecretDeliveryValue>),
    /// Value-free acknowledgement of one exact successful custody operation.
    Acknowledged,
}

impl ManagedSecretDeliveryResponse {
    /// Encodes a private reply.
    ///
    /// # Errors
    ///
    /// Rejects duplicate or unbounded values before any response is sent.
    pub fn encode(self) -> Result<Vec<u8>, ManagedSecretDeliveryWireError> {
        let mut output = Vec::with_capacity(64);
        output.extend_from_slice(RESPONSE_MAGIC);
        output.push(WIRE_VERSION);
        match self {
            Self::Values(values) => {
                if values.is_empty()
                    || values.len() > MAX_BINDINGS
                    || !values_are_unique(&values)
                    || values
                        .iter()
                        .try_fold(0_usize, |total, value| total.checked_add(value.value.len()))
                        .is_none_or(|total| total > MAX_TOTAL_SECRET_BYTES)
                {
                    output.zeroize();
                    return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
                }
                output.push(FETCH);
                let count = u16::try_from(values.len())
                    .map_err(|_| ManagedSecretDeliveryWireError::InvalidEnvelope)?;
                output.extend_from_slice(&count.to_be_bytes());
                for value in values {
                    put_short(&mut output, value.binding_id.as_bytes())?;
                    put_short(&mut output, value.version_id.as_bytes())?;
                    let length = u32::try_from(value.value.len())
                        .map_err(|_| ManagedSecretDeliveryWireError::InvalidEnvelope)?;
                    output.extend_from_slice(&length.to_be_bytes());
                    output.extend_from_slice(&value.value);
                }
            }
            Self::Acknowledged => {
                output.push(ACKNOWLEDGE);
                output.extend_from_slice(&0_u16.to_be_bytes());
            }
        }
        if output.len() > crate::MAX_EPHEMERAL_RESPONSE_BYTES {
            output.zeroize();
            return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
        }
        Ok(output)
    }

    /// Decodes a private reply into zeroizing value custody.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, duplicate, or noncanonical exact values.
    pub fn decode(body: &[u8]) -> Result<Self, ManagedSecretDeliveryWireError> {
        if body.len() > crate::MAX_EPHEMERAL_RESPONSE_BYTES {
            return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
        }
        let mut input = Decoder::new(body);
        if input.take_exact(4)? != RESPONSE_MAGIC || input.byte()? != WIRE_VERSION {
            return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
        }
        let kind = input.byte()?;
        let count = usize::from(input.u16()?);
        match kind {
            FETCH => {
                if count == 0 || count > MAX_BINDINGS {
                    return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
                }
                let mut values = Vec::with_capacity(count);
                let mut total = 0_usize;
                for _ in 0..count {
                    let binding_id = input.utf8_short()?;
                    let version_id = input.utf8_short()?;
                    let length = usize::try_from(input.u32()?)
                        .map_err(|_| ManagedSecretDeliveryWireError::InvalidEnvelope)?;
                    if length == 0 || length > MAX_SECRET_BYTES {
                        return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
                    }
                    total = total
                        .checked_add(length)
                        .filter(|total| *total <= MAX_TOTAL_SECRET_BYTES)
                        .ok_or(ManagedSecretDeliveryWireError::InvalidEnvelope)?;
                    values.push(ManagedSecretDeliveryValue::new(
                        binding_id,
                        version_id,
                        input.take_exact(length)?.to_vec(),
                    )?);
                }
                if !input.is_empty() || !values_are_unique(&values) {
                    return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
                }
                Ok(Self::Values(values))
            }
            ACKNOWLEDGE if count == 0 && input.is_empty() => Ok(Self::Acknowledged),
            _ => Err(ManagedSecretDeliveryWireError::InvalidEnvelope),
        }
    }
}

impl fmt::Debug for ManagedSecretDeliveryResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Values(values) => formatter
                .debug_struct("ManagedSecretDeliveryResponse")
                .field("kind", &"values")
                .field("binding_count", &values.len())
                .field("values", &"[REDACTED]")
                .finish(),
            Self::Acknowledged => formatter
                .debug_struct("ManagedSecretDeliveryResponse")
                .field("kind", &"acknowledged")
                .finish(),
        }
    }
}

/// Closed private-envelope validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("managed secret delivery envelope is invalid")]
pub struct ManagedSecretDeliveryWireError;

impl ManagedSecretDeliveryWireError {
    #[allow(non_upper_case_globals)]
    const InvalidEnvelope: Self = Self;
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES && !value.chars().any(char::is_control)
}

fn valid_canonical_name(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_uppercase())
        && value.len() <= 255
        && characters.all(|character| {
            character == '_' || character.is_ascii_uppercase() || character.is_ascii_digit()
        })
        && !["GITHUB_", "ACTIONS_", "RUNNER_", "AUTOMATA_"]
            .iter()
            .any(|prefix| value.starts_with(prefix))
}

fn valid_canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value)
        .is_ok_and(|parsed| !parsed.is_nil() && parsed.hyphenated().to_string().as_str() == value)
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KEY_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_coordinates(value: ManagedSecretDeliveryCoordinates) -> bool {
    value.runner_id != [0; 16]
        && value.session_id != [0; 16]
        && value.run_id != [0; 16]
        && value.job_id != [0; 16]
        && value.attempt_id != [0; 16]
        && value.lease_id != [0; 16]
        && value.slot > 0
        && value.fencing_token > 0
        && value.lease_issued_at_ms >= 0
        && value.lease_expires_at_ms > value.lease_issued_at_ms
}

fn bindings_are_unique(bindings: &[ManagedSecretDeliveryBinding]) -> bool {
    bindings
        .windows(2)
        .all(|window| window[0].binding_id < window[1].binding_id)
}

fn bindings_match_overlay(
    coordinates: ManagedSecretDeliveryCoordinates,
    bindings: &[ManagedSecretDeliveryBinding],
) -> bool {
    let Ok(fencing_token) = FencingToken::new(coordinates.fencing_token) else {
        return false;
    };
    let Ok(lease) = Lease::new(
        LeaseId::from_uuid(Uuid::from_bytes(coordinates.lease_id)),
        AttemptId::from_uuid(Uuid::from_bytes(coordinates.attempt_id)),
        RunnerId::from_uuid(Uuid::from_bytes(coordinates.runner_id)),
        fencing_token,
        UnixMillis::new(coordinates.lease_issued_at_ms),
        UnixMillis::new(coordinates.lease_expires_at_ms),
    ) else {
        return false;
    };
    let entries = bindings.iter().map(|binding| {
        let binding_value = SecretBinding::new(binding.binding_id.clone())
            .and_then(|value| value.with_version_id(binding.version_id.clone()));
        binding_value.map(|value| (binding.canonical_name.clone(), value))
    });
    let Ok(entries) = entries.collect::<Result<Vec<_>, _>>() else {
        return false;
    };
    ManagedSecretBindingOverlay::new(&lease, entries)
        .is_ok_and(|overlay| overlay.digest().as_bytes() == &coordinates.binding_overlay_digest)
}

fn values_are_unique(values: &[ManagedSecretDeliveryValue]) -> bool {
    values
        .windows(2)
        .all(|window| window[0].binding_id < window[1].binding_id)
}

fn encode_coordinates(output: &mut Vec<u8>, coordinates: ManagedSecretDeliveryCoordinates) {
    output.extend_from_slice(&coordinates.runner_id);
    output.extend_from_slice(&coordinates.session_id);
    output.extend_from_slice(&coordinates.slot.to_be_bytes());
    output.extend_from_slice(&coordinates.run_id);
    output.extend_from_slice(&coordinates.job_id);
    output.extend_from_slice(&coordinates.attempt_id);
    output.extend_from_slice(&coordinates.lease_id);
    output.extend_from_slice(&coordinates.lease_issued_at_ms.to_be_bytes());
    output.extend_from_slice(&coordinates.lease_expires_at_ms.to_be_bytes());
    output.extend_from_slice(&coordinates.fencing_token.to_be_bytes());
    output.extend_from_slice(&coordinates.runtime_context_digest);
    output.extend_from_slice(&coordinates.binding_overlay_digest);
}

fn decode_coordinates(
    input: &mut Decoder<'_>,
) -> Result<ManagedSecretDeliveryCoordinates, ManagedSecretDeliveryWireError> {
    let coordinates = ManagedSecretDeliveryCoordinates {
        runner_id: input.array_16()?,
        session_id: input.array_16()?,
        slot: input.u16()?,
        run_id: input.array_16()?,
        job_id: input.array_16()?,
        attempt_id: input.array_16()?,
        lease_id: input.array_16()?,
        lease_issued_at_ms: input.i64()?,
        lease_expires_at_ms: input.i64()?,
        fencing_token: input.u64()?,
        runtime_context_digest: input.array_32()?,
        binding_overlay_digest: input.array_32()?,
    };
    valid_coordinates(coordinates)
        .then_some(coordinates)
        .ok_or(ManagedSecretDeliveryWireError::InvalidEnvelope)
}

fn put_short(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ManagedSecretDeliveryWireError> {
    let length =
        u16::try_from(value.len()).map_err(|_| ManagedSecretDeliveryWireError::InvalidEnvelope)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn take_exact(&mut self, length: usize) -> Result<&'a [u8], ManagedSecretDeliveryWireError> {
        if length > self.remaining.len() {
            return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
        }
        let (taken, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(taken)
    }

    fn byte(&mut self) -> Result<u8, ManagedSecretDeliveryWireError> {
        Ok(self.take_exact(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ManagedSecretDeliveryWireError> {
        Ok(u16::from_be_bytes(self.take_exact(2)?.try_into().map_err(
            |_| ManagedSecretDeliveryWireError::InvalidEnvelope,
        )?))
    }

    fn u32(&mut self) -> Result<u32, ManagedSecretDeliveryWireError> {
        Ok(u32::from_be_bytes(self.take_exact(4)?.try_into().map_err(
            |_| ManagedSecretDeliveryWireError::InvalidEnvelope,
        )?))
    }

    fn u64(&mut self) -> Result<u64, ManagedSecretDeliveryWireError> {
        Ok(u64::from_be_bytes(self.take_exact(8)?.try_into().map_err(
            |_| ManagedSecretDeliveryWireError::InvalidEnvelope,
        )?))
    }

    fn i64(&mut self) -> Result<i64, ManagedSecretDeliveryWireError> {
        Ok(i64::from_be_bytes(self.take_exact(8)?.try_into().map_err(
            |_| ManagedSecretDeliveryWireError::InvalidEnvelope,
        )?))
    }

    fn array_16(&mut self) -> Result<[u8; 16], ManagedSecretDeliveryWireError> {
        self.take_exact(16)?
            .try_into()
            .map_err(|_| ManagedSecretDeliveryWireError::InvalidEnvelope)
    }

    fn array_32(&mut self) -> Result<[u8; 32], ManagedSecretDeliveryWireError> {
        self.take_exact(32)?
            .try_into()
            .map_err(|_| ManagedSecretDeliveryWireError::InvalidEnvelope)
    }

    fn short(&mut self) -> Result<&'a [u8], ManagedSecretDeliveryWireError> {
        let length = usize::from(self.u16()?);
        self.take_exact(length)
    }

    fn utf8_short(&mut self) -> Result<String, ManagedSecretDeliveryWireError> {
        let bytes = self.short()?;
        let value = std::str::from_utf8(bytes)
            .map_err(|_| ManagedSecretDeliveryWireError::InvalidEnvelope)?;
        if !valid_identifier(value) {
            return Err(ManagedSecretDeliveryWireError::InvalidEnvelope);
        }
        Ok(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coordinates(bindings: &[ManagedSecretDeliveryBinding]) -> ManagedSecretDeliveryCoordinates {
        let mut coordinates = ManagedSecretDeliveryCoordinates {
            runner_id: [1; 16],
            session_id: [2; 16],
            slot: 1,
            run_id: [5; 16],
            job_id: [6; 16],
            attempt_id: [7; 16],
            lease_id: [8; 16],
            lease_issued_at_ms: 100,
            lease_expires_at_ms: 200,
            fencing_token: 9,
            runtime_context_digest: [10; 32],
            binding_overlay_digest: [0; 32],
        };
        let lease = Lease::new(
            LeaseId::from_uuid(Uuid::from_bytes(coordinates.lease_id)),
            AttemptId::from_uuid(Uuid::from_bytes(coordinates.attempt_id)),
            RunnerId::from_uuid(Uuid::from_bytes(coordinates.runner_id)),
            FencingToken::new(coordinates.fencing_token).expect("fence"),
            UnixMillis::new(coordinates.lease_issued_at_ms),
            UnixMillis::new(coordinates.lease_expires_at_ms),
        )
        .expect("lease");
        let overlay = ManagedSecretBindingOverlay::new(
            &lease,
            bindings.iter().map(|binding| {
                (
                    binding.canonical_name.clone(),
                    SecretBinding::new(binding.binding_id.clone())
                        .and_then(|value| value.with_version_id(binding.version_id.clone()))
                        .expect("binding"),
                )
            }),
        )
        .expect("overlay");
        coordinates.binding_overlay_digest = overlay.digest().into_bytes();
        coordinates
    }

    fn bindings() -> Vec<ManagedSecretDeliveryBinding> {
        vec![
            ManagedSecretDeliveryBinding::new(
                "TOKEN_A",
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-000000000101",
            )
            .expect("first exact binding"),
            ManagedSecretDeliveryBinding::new(
                "TOKEN_B",
                "00000000-0000-4000-8000-000000000002",
                "00000000-0000-4000-8000-000000000102",
            )
            .expect("second exact binding"),
        ]
    }

    #[test]
    fn fetch_request_round_trips_without_exposing_bearer() {
        let bindings = bindings();
        let coordinates = coordinates(&bindings);
        let request = ManagedSecretDeliveryRequest::new(
            ManagedSecretDeliveryOperation::Fetch,
            "managed-secret-delivery-v1",
            vec![12; 32],
            coordinates,
            bindings.clone(),
        )
        .expect("valid request");
        let encoded = request.encode().expect("bounded encoding");
        let decoded = ManagedSecretDeliveryRequest::decode(&encoded).expect("valid decoding");
        assert_eq!(decoded.operation(), ManagedSecretDeliveryOperation::Fetch);
        assert_eq!(decoded.expose_bearer(), &[12; 32]);
        assert_eq!(decoded.coordinates(), coordinates);
        assert_eq!(decoded.bindings(), bindings);
        let diagnostic = format!("{decoded:?}");
        assert!(!diagnostic.contains("managed-secret-delivery-v1"));
        assert!(!diagnostic.contains("12"));
    }

    #[test]
    fn response_round_trips_and_rejects_duplicate_bindings() {
        let response = ManagedSecretDeliveryResponse::Values(vec![
            ManagedSecretDeliveryValue::new("binding-a", "version-a", b"fixture-value".to_vec())
                .expect("first value"),
            ManagedSecretDeliveryValue::new("binding-b", "version-b", b"fixture-value".to_vec())
                .expect("second value"),
        ]);
        let encoded = response.encode().expect("bounded response");
        let decoded = ManagedSecretDeliveryResponse::decode(&encoded).expect("valid response");
        let ManagedSecretDeliveryResponse::Values(values) = decoded else {
            panic!("fetch response must retain values");
        };
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].binding_id(), "binding-a");
        assert_eq!(values[0].version_id(), "version-a");

        let duplicate = ManagedSecretDeliveryResponse::Values(vec![
            ManagedSecretDeliveryValue::new("binding-a", "version-a", b"fixture-value".to_vec())
                .expect("first duplicate"),
            ManagedSecretDeliveryValue::new("binding-a", "version-b", b"fixture-value".to_vec())
                .expect("second duplicate"),
        ]);
        assert_eq!(
            duplicate.encode(),
            Err(ManagedSecretDeliveryWireError),
            "the private response never allows ambiguous custody"
        );
    }

    #[test]
    fn acknowledgement_has_no_value_slots() {
        let encoded = ManagedSecretDeliveryResponse::Acknowledged
            .encode()
            .expect("ack encoding");
        assert!(matches!(
            ManagedSecretDeliveryResponse::decode(&encoded),
            Ok(ManagedSecretDeliveryResponse::Acknowledged)
        ));
    }

    #[test]
    fn request_and_response_reject_forward_wire_version() {
        let bindings = bindings();
        let request = ManagedSecretDeliveryRequest::new(
            ManagedSecretDeliveryOperation::Fetch,
            "managed-secret-delivery-v1",
            vec![12; 32],
            coordinates(&bindings),
            bindings,
        )
        .expect("valid request");
        let mut request_bytes = request.encode().expect("request encoding");
        let forward_version = WIRE_VERSION.checked_add(1).expect("test version");
        request_bytes[REQUEST_MAGIC.len()] = forward_version;
        assert!(ManagedSecretDeliveryRequest::decode(&request_bytes).is_err());

        let mut response_bytes = ManagedSecretDeliveryResponse::Acknowledged
            .encode()
            .expect("response encoding");
        response_bytes[RESPONSE_MAGIC.len()] = forward_version;
        assert!(ManagedSecretDeliveryResponse::decode(&response_bytes).is_err());
    }
}
