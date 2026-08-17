//! Broker-authoritative evidence for Windows enrollment host inputs.

use std::{collections::HashSet, fmt};

use automata_ci_core::{Sha256Digest, UnixMillis};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::WINDOWS_HYPERV_PROVIDER_ID;

const HOST_INPUT_SCHEMA: u16 = 1;
const HOST_INPUT_COUNT: usize = 9;
const MAX_BACKEND_ID_BYTES: usize = 64;
const MAX_PATH_BYTES: usize = 1_024;
const MAX_OWNER_SID_BYTES: usize = 184;
const MAX_ATTESTATION_LIFETIME_MILLIS: i64 = 5 * 60 * 1_000;
const DIGEST_DOMAIN: &[u8] = b"automata.windows.host-input-attestation.v1\0";

/// One security-sensitive file role required by Windows runner admission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsBrokerHostInputKind {
    /// The exact runner product configuration loaded from disk.
    Configuration,
    /// The pinned runner-side broker client executable.
    BackendExecutable,
    /// The verified Windows image manifest.
    ImageManifest,
    /// The verified Windows image lock.
    ImageLock,
    /// Image provenance evidence.
    Provenance,
    /// Image software-bill-of-materials evidence.
    Sbom,
    /// Image patch-status evidence.
    PatchReport,
    /// Image revocation evidence.
    Revocations,
    /// The signed image-promotion envelope.
    PromotionEnvelope,
}

impl WindowsBrokerHostInputKind {
    const ORDERED: [Self; HOST_INPUT_COUNT] = [
        Self::Configuration,
        Self::BackendExecutable,
        Self::ImageManifest,
        Self::ImageLock,
        Self::Provenance,
        Self::Sbom,
        Self::PatchReport,
        Self::Revocations,
        Self::PromotionEnvelope,
    ];

    const fn code(self) -> u8 {
        match self {
            Self::Configuration => 1,
            Self::BackendExecutable => 2,
            Self::ImageManifest => 3,
            Self::ImageLock => 4,
            Self::Provenance => 5,
            Self::Sbom => 6,
            Self::PatchReport => 7,
            Self::Revocations => 8,
            Self::PromotionEnvelope => 9,
        }
    }

    pub(crate) const fn byte_limit(self) -> u64 {
        match self {
            Self::Configuration => 1024 * 1024,
            Self::BackendExecutable => 512 * 1024 * 1024,
            Self::ImageManifest
            | Self::ImageLock
            | Self::Provenance
            | Self::Sbom
            | Self::PatchReport
            | Self::Revocations
            | Self::PromotionEnvelope => 16 * 1024 * 1024,
        }
    }
}

/// One exact path and content digest the broker must independently attest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsBrokerHostInputDescriptor {
    kind: WindowsBrokerHostInputKind,
    absolute_path: String,
    expected_sha256: Sha256Digest,
}

impl WindowsBrokerHostInputDescriptor {
    /// Creates one bounded, absolute Windows input descriptor.
    ///
    /// # Errors
    ///
    /// Rejects non-canonical paths or a zero content digest.
    pub fn new(
        kind: WindowsBrokerHostInputKind,
        absolute_path: impl Into<String>,
        expected_sha256: Sha256Digest,
    ) -> Result<Self, WindowsBrokerHostInputError> {
        let value = Self {
            kind,
            absolute_path: absolute_path.into(),
            expected_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the fixed semantic role of this input.
    #[must_use]
    pub const fn kind(&self) -> WindowsBrokerHostInputKind {
        self.kind
    }

    /// Returns the exact canonical absolute Windows path.
    #[must_use]
    pub fn absolute_path(&self) -> &str {
        &self.absolute_path
    }

    /// Returns the content digest the broker must observe.
    #[must_use]
    pub const fn expected_sha256(&self) -> Sha256Digest {
        self.expected_sha256
    }

    fn validate(&self) -> Result<(), WindowsBrokerHostInputError> {
        if !valid_absolute_windows_path(&self.absolute_path) || zero_digest(self.expected_sha256) {
            return Err(WindowsBrokerHostInputError::InvalidRequest);
        }
        Ok(())
    }
}

/// Closed batch of every host file that one Windows enrollment depends on.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsBrokerHostInputRequest {
    schema: u16,
    backend_id: String,
    sandbox_provider_id: String,
    inputs: Vec<WindowsBrokerHostInputDescriptor>,
}

impl WindowsBrokerHostInputRequest {
    /// Creates an exact nine-input request in the admission contract's fixed order.
    ///
    /// # Errors
    ///
    /// Rejects an invalid backend identity, provider substitution, a missing or
    /// reordered role, duplicate Windows paths, malformed paths, or zero digests.
    pub fn new(
        backend_id: impl Into<String>,
        sandbox_provider_id: impl Into<String>,
        inputs: Vec<WindowsBrokerHostInputDescriptor>,
    ) -> Result<Self, WindowsBrokerHostInputError> {
        let value = Self {
            schema: HOST_INPUT_SCHEMA,
            backend_id: backend_id.into(),
            sandbox_provider_id: sandbox_provider_id.into(),
            inputs,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the exact broker host/service authority identity.
    #[must_use]
    pub fn backend_id(&self) -> &str {
        &self.backend_id
    }

    /// Returns the exact sandbox-provider identity used for active probing.
    #[must_use]
    pub fn sandbox_provider_id(&self) -> &str {
        &self.sandbox_provider_id
    }

    /// Returns all inputs in their fixed semantic order.
    #[must_use]
    pub fn inputs(&self) -> &[WindowsBrokerHostInputDescriptor] {
        &self.inputs
    }

    pub(crate) fn validate(&self) -> Result<(), WindowsBrokerHostInputError> {
        if self.schema != HOST_INPUT_SCHEMA
            || !valid_backend_id(&self.backend_id)
            || self.sandbox_provider_id != WINDOWS_HYPERV_PROVIDER_ID
            || self.inputs.len() != HOST_INPUT_COUNT
        {
            return Err(WindowsBrokerHostInputError::InvalidRequest);
        }
        let mut paths = HashSet::with_capacity(HOST_INPUT_COUNT);
        for (descriptor, expected_kind) in
            self.inputs.iter().zip(WindowsBrokerHostInputKind::ORDERED)
        {
            descriptor.validate()?;
            if descriptor.kind != expected_kind
                || !paths.insert(descriptor.absolute_path.to_ascii_lowercase())
            {
                return Err(WindowsBrokerHostInputError::InvalidRequest);
            }
        }
        Ok(())
    }
}

/// One broker-observed, value-free Windows file identity and security policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsBrokerHostInputObservation {
    kind: WindowsBrokerHostInputKind,
    absolute_path: String,
    content_sha256: Sha256Digest,
    byte_len: u64,
    volume_serial_number: u64,
    file_id: [u8; 16],
    owner_sid: String,
    security_descriptor_sha256: Sha256Digest,
}

impl WindowsBrokerHostInputObservation {
    #[cfg(any(windows, test))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        descriptor: &WindowsBrokerHostInputDescriptor,
        byte_len: u64,
        volume_serial_number: u64,
        file_id: [u8; 16],
        owner_sid: String,
        security_descriptor_sha256: Sha256Digest,
    ) -> Result<Self, WindowsBrokerHostInputError> {
        let value = Self {
            kind: descriptor.kind,
            absolute_path: descriptor.absolute_path.clone(),
            content_sha256: descriptor.expected_sha256,
            byte_len,
            volume_serial_number,
            file_id,
            owner_sid,
            security_descriptor_sha256,
        };
        value.validate(descriptor)?;
        Ok(value)
    }

    /// Returns the semantic role independently observed by the broker.
    #[must_use]
    pub const fn kind(&self) -> WindowsBrokerHostInputKind {
        self.kind
    }

    /// Returns the exact path independently opened by the broker.
    #[must_use]
    pub fn absolute_path(&self) -> &str {
        &self.absolute_path
    }

    /// Returns the digest computed from the broker-held file handle.
    #[must_use]
    pub const fn content_sha256(&self) -> Sha256Digest {
        self.content_sha256
    }

    /// Returns the exact byte length observed by the broker.
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    /// Returns the pinned local-volume serial number.
    #[must_use]
    pub const fn volume_serial_number(&self) -> u64 {
        self.volume_serial_number
    }

    /// Returns the exact 128-bit filesystem file identifier.
    #[must_use]
    pub const fn file_id(&self) -> &[u8; 16] {
        &self.file_id
    }

    /// Returns the exact trusted owner SID.
    #[must_use]
    pub fn owner_sid(&self) -> &str {
        &self.owner_sid
    }

    /// Returns the digest of the canonical protected owner/DACL descriptor.
    #[must_use]
    pub const fn security_descriptor_sha256(&self) -> Sha256Digest {
        self.security_descriptor_sha256
    }

    fn validate(
        &self,
        descriptor: &WindowsBrokerHostInputDescriptor,
    ) -> Result<(), WindowsBrokerHostInputError> {
        if self.kind != descriptor.kind
            || self.absolute_path != descriptor.absolute_path
            || self.content_sha256 != descriptor.expected_sha256
            || self.byte_len == 0
            || self.byte_len > self.kind.byte_limit()
            || self.volume_serial_number == 0
            || self.file_id.iter().all(|byte| *byte == 0)
            || !valid_sid(&self.owner_sid)
            || zero_digest(self.security_descriptor_sha256)
        {
            return Err(WindowsBrokerHostInputError::InvalidEvidence);
        }
        Ok(())
    }
}

/// Fresh aggregate broker evidence for all Windows enrollment host inputs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsBrokerHostInputAttestation {
    schema: u16,
    host_id: Sha256Digest,
    backend_id: String,
    sandbox_provider_id: String,
    inputs: Vec<WindowsBrokerHostInputObservation>,
    issued_at: UnixMillis,
    valid_until: UnixMillis,
    digest: Sha256Digest,
}

impl WindowsBrokerHostInputAttestation {
    #[cfg(any(windows, test))]
    pub(crate) fn issue(
        host_id: Sha256Digest,
        request: &WindowsBrokerHostInputRequest,
        inputs: Vec<WindowsBrokerHostInputObservation>,
        issued_at: UnixMillis,
        valid_until: UnixMillis,
    ) -> Result<Self, WindowsBrokerHostInputError> {
        let digest = attestation_digest(host_id, request, &inputs, issued_at, valid_until)?;
        let value = Self {
            schema: HOST_INPUT_SCHEMA,
            host_id,
            backend_id: request.backend_id.clone(),
            sandbox_provider_id: request.sandbox_provider_id.clone(),
            inputs,
            issued_at,
            valid_until,
            digest,
        };
        value.validate_for(request, host_id)?;
        Ok(value)
    }

    /// Returns the exact host identity that produced this evidence.
    #[must_use]
    pub const fn host_id(&self) -> Sha256Digest {
        self.host_id
    }

    /// Returns the exact broker authority identity bound by the request.
    #[must_use]
    pub fn backend_id(&self) -> &str {
        &self.backend_id
    }

    /// Returns the exact active-probe provider identity.
    #[must_use]
    pub fn sandbox_provider_id(&self) -> &str {
        &self.sandbox_provider_id
    }

    /// Returns all independently observed inputs in fixed semantic order.
    #[must_use]
    pub fn inputs(&self) -> &[WindowsBrokerHostInputObservation] {
        &self.inputs
    }

    /// Returns the service-clock issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }

    /// Returns the exclusive freshness deadline.
    #[must_use]
    pub const fn valid_until(&self) -> UnixMillis {
        self.valid_until
    }

    /// Returns the canonical aggregate attestation digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    pub(crate) fn validate_for(
        &self,
        request: &WindowsBrokerHostInputRequest,
        expected_host_id: Sha256Digest,
    ) -> Result<(), WindowsBrokerHostInputError> {
        request.validate()?;
        if self.schema != HOST_INPUT_SCHEMA
            || self.host_id != expected_host_id
            || self.backend_id != request.backend_id
            || self.sandbox_provider_id != request.sandbox_provider_id
            || self.inputs.len() != request.inputs.len()
            || self.issued_at.get() < 0
            || self.valid_until.get() <= self.issued_at.get()
            || self.valid_until.get().saturating_sub(self.issued_at.get())
                > MAX_ATTESTATION_LIFETIME_MILLIS
        {
            return Err(WindowsBrokerHostInputError::InvalidEvidence);
        }
        for (observation, descriptor) in self.inputs.iter().zip(&request.inputs) {
            observation.validate(descriptor)?;
        }
        let expected = attestation_digest(
            self.host_id,
            request,
            &self.inputs,
            self.issued_at,
            self.valid_until,
        )?;
        if self.digest != expected || zero_digest(self.digest) {
            return Err(WindowsBrokerHostInputError::InvalidEvidence);
        }
        Ok(())
    }
}

/// Closed production/test seam for broker-side Windows file attestation.
pub trait WindowsBrokerHostInputAttestor: fmt::Debug + Send + Sync {
    /// Independently opens, verifies, and attests every exact request input.
    ///
    /// # Errors
    ///
    /// Fails closed on malformed requests, path races, content changes, unsafe
    /// ownership/DACLs, the wrong volume, or unavailable platform evidence.
    fn attest(
        &self,
        request: &WindowsBrokerHostInputRequest,
        issued_at: UnixMillis,
        valid_until: UnixMillis,
    ) -> Result<WindowsBrokerHostInputAttestation, WindowsBrokerHostInputError>;
}

/// Secret-free host-input request or evidence failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WindowsBrokerHostInputError {
    /// The versioned request or one of its descriptors is malformed.
    #[error("Windows broker host-input request is invalid")]
    InvalidRequest,
    /// Broker-observed evidence is inconsistent or malformed.
    #[error("Windows broker host-input evidence is invalid")]
    InvalidEvidence,
    /// The path, volume, owner, or protected DACL violates broker policy.
    #[error("Windows broker host-input policy rejected the file")]
    Policy,
    /// The file could not be opened and stabilized for attestation.
    #[error("Windows broker host-input file could not be stabilized")]
    File,
}

fn attestation_digest(
    host_id: Sha256Digest,
    request: &WindowsBrokerHostInputRequest,
    inputs: &[WindowsBrokerHostInputObservation],
    issued_at: UnixMillis,
    valid_until: UnixMillis,
) -> Result<Sha256Digest, WindowsBrokerHostInputError> {
    if inputs.len() != request.inputs.len() {
        return Err(WindowsBrokerHostInputError::InvalidEvidence);
    }
    let mut hash = Sha256::new();
    hash.update(DIGEST_DOMAIN);
    hash.update(host_id.as_bytes());
    put_bytes(&mut hash, request.backend_id.as_bytes())?;
    put_bytes(&mut hash, request.sandbox_provider_id.as_bytes())?;
    hash.update(issued_at.get().to_be_bytes());
    hash.update(valid_until.get().to_be_bytes());
    hash.update(
        u16::try_from(inputs.len())
            .map_err(|_| WindowsBrokerHostInputError::InvalidEvidence)?
            .to_be_bytes(),
    );
    for input in inputs {
        hash.update([input.kind.code()]);
        put_bytes(&mut hash, input.absolute_path.as_bytes())?;
        hash.update(input.content_sha256.as_bytes());
        hash.update(input.byte_len.to_be_bytes());
        hash.update(input.volume_serial_number.to_be_bytes());
        hash.update(input.file_id);
        put_bytes(&mut hash, input.owner_sid.as_bytes())?;
        hash.update(input.security_descriptor_sha256.as_bytes());
    }
    Ok(Sha256Digest::from_bytes(hash.finalize().into()))
}

fn put_bytes(hash: &mut Sha256, value: &[u8]) -> Result<(), WindowsBrokerHostInputError> {
    let len =
        u32::try_from(value.len()).map_err(|_| WindowsBrokerHostInputError::InvalidEvidence)?;
    hash.update(len.to_be_bytes());
    hash.update(value);
    Ok(())
}

fn valid_backend_id(value: &str) -> bool {
    value.len() == MAX_BACKEND_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_absolute_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 4
        || bytes.len() > MAX_PATH_BYTES
        || !bytes.is_ascii()
        || !bytes[0].is_ascii_uppercase()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || value.contains('/')
        || value.contains("\\\\")
        || value.chars().any(char::is_control)
    {
        return false;
    }
    value[3..].split('\\').all(|component| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && !component.ends_with([' ', '.'])
            && !component.contains(':')
    })
}

fn valid_sid(value: &str) -> bool {
    value.len() >= 7
        && value.len() <= MAX_OWNER_SID_BYTES
        && value.starts_with("S-1-")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
        && value
            .split('-')
            .skip(2)
            .all(|part| !part.is_empty() && part.len() <= 10 && part.parse::<u32>().is_ok())
}

const fn zero_digest(value: Sha256Digest) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> WindowsBrokerHostInputRequest {
        let inputs = WindowsBrokerHostInputKind::ORDERED
            .into_iter()
            .enumerate()
            .map(|(index, kind)| {
                WindowsBrokerHostInputDescriptor::new(
                    kind,
                    format!(r"C:\Automata\input-{index}.bin"),
                    Sha256Digest::from_bytes([u8::try_from(index + 1).unwrap(); 32]),
                )
                .unwrap()
            })
            .collect();
        WindowsBrokerHostInputRequest::new("a".repeat(64), WINDOWS_HYPERV_PROVIDER_ID, inputs)
            .unwrap()
    }

    fn observations(
        request: &WindowsBrokerHostInputRequest,
    ) -> Vec<WindowsBrokerHostInputObservation> {
        request
            .inputs()
            .iter()
            .enumerate()
            .map(|(index, descriptor)| {
                WindowsBrokerHostInputObservation::new(
                    descriptor,
                    100,
                    42,
                    [u8::try_from(index + 1).unwrap(); 16],
                    "S-1-5-80-1-2-3-4-5".to_owned(),
                    Sha256Digest::from_bytes([99; 32]),
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn request_requires_exact_roles_order_provider_and_unique_paths() {
        let valid = request();
        assert_eq!(valid.inputs().len(), HOST_INPUT_COUNT);

        let mut reordered = valid.inputs.clone();
        reordered.swap(0, 1);
        assert_eq!(
            WindowsBrokerHostInputRequest::new(
                valid.backend_id.clone(),
                WINDOWS_HYPERV_PROVIDER_ID,
                reordered,
            ),
            Err(WindowsBrokerHostInputError::InvalidRequest)
        );
        assert_eq!(
            WindowsBrokerHostInputRequest::new(valid.backend_id, "windows-process", valid.inputs,),
            Err(WindowsBrokerHostInputError::InvalidRequest)
        );
    }

    #[test]
    fn attestation_digest_binds_file_identity_security_and_freshness() {
        let request = request();
        let host_id = Sha256Digest::from_bytes([7; 32]);
        let issued = UnixMillis::new(1_000);
        let valid_until = UnixMillis::new(301_000);
        let attestation = WindowsBrokerHostInputAttestation::issue(
            host_id,
            &request,
            observations(&request),
            issued,
            valid_until,
        )
        .unwrap();
        attestation.validate_for(&request, host_id).unwrap();

        let mut tampered = attestation.clone();
        tampered.inputs[0].file_id[0] ^= 1;
        assert_eq!(
            tampered.validate_for(&request, host_id),
            Err(WindowsBrokerHostInputError::InvalidEvidence)
        );
        let mut expired_shape = attestation;
        expired_shape.valid_until = UnixMillis::new(301_001);
        assert_eq!(
            expired_shape.validate_for(&request, host_id),
            Err(WindowsBrokerHostInputError::InvalidEvidence)
        );
    }

    #[test]
    fn attestation_rejects_host_substitution_and_invalid_validity_horizons() {
        let request = request();
        let host_id = Sha256Digest::from_bytes([7; 32]);
        let attestation = WindowsBrokerHostInputAttestation::issue(
            host_id,
            &request,
            observations(&request),
            UnixMillis::new(1_000),
            UnixMillis::new(301_000),
        )
        .unwrap();

        assert_eq!(
            attestation.validate_for(&request, Sha256Digest::from_bytes([8; 32])),
            Err(WindowsBrokerHostInputError::InvalidEvidence)
        );

        let mut serialized = serde_json::to_value(&attestation).expect("serialize attestation");
        serialized["host_id"] = serde_json::json!(Sha256Digest::from_bytes([8; 32]));
        let substituted: WindowsBrokerHostInputAttestation =
            serde_json::from_value(serialized).expect("decode substituted attestation");
        assert_eq!(
            substituted.validate_for(&request, Sha256Digest::from_bytes([8; 32])),
            Err(WindowsBrokerHostInputError::InvalidEvidence)
        );

        let mut inverted = attestation;
        inverted.valid_until = inverted.issued_at;
        assert_eq!(
            inverted.validate_for(&request, host_id),
            Err(WindowsBrokerHostInputError::InvalidEvidence)
        );
    }

    #[test]
    fn paths_reject_unc_device_traversal_and_case_ambiguous_duplicates() {
        for path in [
            r"relative\file",
            r"\\server\share\file",
            r"\\?\C:\file",
            r"C:\dir\..\file",
            r"c:\file",
            r"C:/file",
        ] {
            assert!(!valid_absolute_windows_path(path));
        }
        let mut duplicate = request();
        duplicate.inputs[1].absolute_path = duplicate.inputs[0].absolute_path.to_ascii_lowercase();
        assert_eq!(
            duplicate.validate(),
            Err(WindowsBrokerHostInputError::InvalidRequest)
        );
    }
}
