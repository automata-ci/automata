//! Admission service contract and value-free receipts.

use std::fmt;

use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_protocol::{WindowsRunnerAdmissionEnvelope, WindowsRunnerPlacementRenewalEnvelope};
use automata_ci_windows_broker_core::{
    admission::WindowsBrokerAdmissionError, request::WindowsBrokerAdmissionRequest,
};
use sha2::{Digest as _, Sha256};

use crate::custody::WindowsBrokerCustodyHandle;

const HANDLE_COMMITMENT_DOMAIN: &[u8] = b"automata.windows-runner-admission-custody-handle.v1\0";

/// Exact result of one broker-owned admission issue or resume operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsBrokerAdmissionReceipt {
    handle: WindowsBrokerCustodyHandle,
    envelope: WindowsRunnerAdmissionEnvelope,
    envelope_sha256: Sha256Digest,
}

/// Durable, expiry-independent proof needed to complete one admission.
///
/// The signed enrollment receipt is deliberately short-lived, but control may
/// have durably committed the exact enrollment before the runner receives its
/// response. Keeping this value with the staged request allows an exact server
/// replay to finish broker tombstoning without reopening or extending the
/// expired admission authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsBrokerAdmissionCompletion {
    handle: WindowsBrokerCustodyHandle,
    envelope_sha256: Sha256Digest,
}

impl WindowsBrokerAdmissionCompletion {
    /// Constructs an exact completion proof from durable public metadata.
    ///
    /// # Errors
    ///
    /// Rejects a zero envelope commitment.
    pub fn new(
        handle: WindowsBrokerCustodyHandle,
        envelope_sha256: Sha256Digest,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        if envelope_sha256.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(WindowsBrokerAdmissionError::InvalidReceipt);
        }
        Ok(Self {
            handle,
            envelope_sha256,
        })
    }

    /// Returns the opaque broker custody handle.
    #[must_use]
    pub const fn handle(&self) -> &WindowsBrokerCustodyHandle {
        &self.handle
    }

    /// Returns the exact signed-envelope commitment.
    #[must_use]
    pub const fn envelope_sha256(&self) -> Sha256Digest {
        self.envelope_sha256
    }
}

/// Exact result of a broker-owned placement-renewal operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsBrokerPlacementRenewalReceipt {
    envelope: WindowsRunnerPlacementRenewalEnvelope,
    envelope_sha256: Sha256Digest,
}

impl WindowsBrokerPlacementRenewalReceipt {
    pub(crate) fn from_wire(
        envelope: WindowsRunnerPlacementRenewalEnvelope,
        expected_enrollment_envelope_sha256: Sha256Digest,
        observed_at: UnixMillis,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        let claims = envelope
            .claims()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        let observed_at = u64::try_from(observed_at.get())
            .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        if claims.enrollment_envelope_sha256() != expected_enrollment_envelope_sha256
            || claims.validity().issued_at_unix_millis() > observed_at
            || claims.validity().expires_at_unix_millis() <= observed_at
        {
            return Err(WindowsBrokerAdmissionError::InvalidReceipt);
        }
        let envelope_sha256 = envelope.envelope_sha256();
        Ok(Self {
            envelope,
            envelope_sha256,
        })
    }

    /// Returns the complete broker-signed renewal sent on a lease request.
    #[must_use]
    pub const fn envelope(&self) -> &WindowsRunnerPlacementRenewalEnvelope {
        &self.envelope
    }

    /// Returns the byte-exact renewal-envelope commitment.
    #[must_use]
    pub const fn envelope_sha256(&self) -> Sha256Digest {
        self.envelope_sha256
    }
}

impl WindowsBrokerAdmissionReceipt {
    pub(crate) fn from_wire(
        handle: WindowsBrokerCustodyHandle,
        envelope: WindowsRunnerAdmissionEnvelope,
        expected_request_sha256: Sha256Digest,
        observed_at: UnixMillis,
    ) -> Result<Self, WindowsBrokerAdmissionError> {
        let claims = envelope
            .claims()
            .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        let observed_at = u64::try_from(observed_at.get())
            .map_err(|_| WindowsBrokerAdmissionError::InvalidReceipt)?;
        if claims.binding().broker_profile().request_binding_sha256() != expected_request_sha256
            || claims.custody_handle_sha256() != custody_handle_commitment(&handle)
            || claims.validity().issued_at_unix_millis() > observed_at
            || claims.validity().expires_at_unix_millis() <= observed_at
        {
            return Err(WindowsBrokerAdmissionError::InvalidReceipt);
        }
        let envelope_sha256 = envelope.envelope_sha256();
        Ok(Self {
            handle,
            envelope,
            envelope_sha256,
        })
    }

    /// Returns the path-free broker custody capability.
    #[must_use]
    pub const fn handle(&self) -> &WindowsBrokerCustodyHandle {
        &self.handle
    }

    /// Returns the complete broker-signed envelope sent to control.
    #[must_use]
    pub const fn envelope(&self) -> &WindowsRunnerAdmissionEnvelope {
        &self.envelope
    }

    /// Returns the exact digest required for idempotent completion.
    #[must_use]
    pub const fn envelope_sha256(&self) -> Sha256Digest {
        self.envelope_sha256
    }

    /// Returns expiry-independent metadata for exact post-enrollment cleanup.
    #[must_use]
    pub fn completion(&self) -> WindowsBrokerAdmissionCompletion {
        WindowsBrokerAdmissionCompletion {
            handle: self.handle.clone(),
            envelope_sha256: self.envelope_sha256,
        }
    }
}

/// Privileged implementation behind the authenticated broker service.
///
/// Implementations must independently re-read and verify all host inputs and
/// promotion evidence, execute and clean the fixed synthetic probe, advance
/// durable serial floors, mint the Ed25519 envelope, and persist the admitted
/// launch contract before returning success.
pub trait WindowsBrokerAdmissionAuthority: fmt::Debug + Send + Sync {
    /// Mints or exactly replays one request-indexed admission record.
    ///
    /// # Errors
    ///
    /// Returns a value-free request, evidence, state, or availability error.
    fn issue(
        &self,
        request: &WindowsBrokerAdmissionRequest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError>;

    /// Resumes one exact live receipt without exposing generic custody bytes.
    ///
    /// # Errors
    ///
    /// Returns a value-free binding, state, receipt, or availability error.
    fn resume(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        request_sha256: Sha256Digest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError>;

    /// Atomically tombstones one exact receipt after durable enrollment.
    /// Repeating the same completion is required to succeed.
    ///
    /// # Errors
    ///
    /// Returns a value-free digest, state, or availability error.
    fn complete(
        &self,
        handle: &WindowsBrokerCustodyHandle,
        envelope_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerAdmissionError>;

    /// Returns a retained current renewal or durably mints exactly the next
    /// serial for a completed admission handle. The implementation keeps the
    /// handle tombstoned against enrollment reuse while retaining only the
    /// minimal admitted contract needed for renewal.
    ///
    /// # Errors
    ///
    /// Returns a value-free receipt, state, evidence, or availability error.
    fn renew(
        &self,
        completed_handle: &WindowsBrokerCustodyHandle,
        enrollment_envelope_sha256: Sha256Digest,
        now: UnixMillis,
    ) -> Result<WindowsBrokerPlacementRenewalReceipt, WindowsBrokerAdmissionError>;

    /// Acknowledges that control durably accepted one exact renewal.
    ///
    /// Until this exact ACK is retained, the broker replays the same serial
    /// and never advances across an expired lost response. Repeating an exact
    /// ACK is idempotent; substituting a handle or envelope is rejected.
    ///
    /// # Errors
    ///
    /// Returns a value-free receipt, state, or availability error.
    fn acknowledge_renewal(
        &self,
        completed_handle: &WindowsBrokerCustodyHandle,
        renewal_envelope_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerAdmissionError>;
}

/// Fail-closed authority used until every production trust/input/probe
/// dependency has been initialized and reconciled.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableWindowsBrokerAdmissionAuthority;

impl WindowsBrokerAdmissionAuthority for UnavailableWindowsBrokerAdmissionAuthority {
    fn issue(
        &self,
        _request: &WindowsBrokerAdmissionRequest,
        _now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError> {
        Err(WindowsBrokerAdmissionError::Unavailable)
    }

    fn resume(
        &self,
        _handle: &WindowsBrokerCustodyHandle,
        _request_sha256: Sha256Digest,
        _now: UnixMillis,
    ) -> Result<WindowsBrokerAdmissionReceipt, WindowsBrokerAdmissionError> {
        Err(WindowsBrokerAdmissionError::Unavailable)
    }

    fn complete(
        &self,
        _handle: &WindowsBrokerCustodyHandle,
        _envelope_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerAdmissionError> {
        Err(WindowsBrokerAdmissionError::Unavailable)
    }

    fn renew(
        &self,
        _completed_handle: &WindowsBrokerCustodyHandle,
        _enrollment_envelope_sha256: Sha256Digest,
        _now: UnixMillis,
    ) -> Result<WindowsBrokerPlacementRenewalReceipt, WindowsBrokerAdmissionError> {
        Err(WindowsBrokerAdmissionError::Unavailable)
    }

    fn acknowledge_renewal(
        &self,
        _completed_handle: &WindowsBrokerCustodyHandle,
        _renewal_envelope_sha256: Sha256Digest,
    ) -> Result<(), WindowsBrokerAdmissionError> {
        Err(WindowsBrokerAdmissionError::Unavailable)
    }
}

pub(crate) fn custody_handle_commitment(handle: &WindowsBrokerCustodyHandle) -> Sha256Digest {
    domain_digest(HANDLE_COMMITMENT_DOMAIN, &[handle.opaque().as_bytes()])
}

fn domain_digest(domain: &[u8], fields: &[&[u8]]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}
