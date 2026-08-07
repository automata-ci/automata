use std::fmt;

use automata_core::{LeaseGuard, OperationId, RunnerId, RunnerSessionId, Sha256Digest};
use automata_protocol::RunnerSlotOrdinal;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::JournalInvariantError;

const MAX_ORPHAN_AUTHORITY_PROOF_BYTES: usize = 65_536;

/// Exact old-session lease claim presented to an external authority verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrphanClaim {
    runner_id: RunnerId,
    session_id: RunnerSessionId,
    slot: RunnerSlotOrdinal,
    guard: LeaseGuard,
}

impl OrphanClaim {
    pub(crate) const fn new(
        runner_id: RunnerId,
        session_id: RunnerSessionId,
        slot: RunnerSlotOrdinal,
        guard: LeaseGuard,
    ) -> Self {
        Self {
            runner_id,
            session_id,
            slot,
            guard,
        }
    }

    #[must_use]
    pub const fn runner_id(self) -> RunnerId {
        self.runner_id
    }

    #[must_use]
    pub const fn session_id(self) -> RunnerSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn slot(self) -> RunnerSlotOrdinal {
        self.slot
    }

    #[must_use]
    pub const fn guard(self) -> LeaseGuard {
        self.guard
    }
}

/// Secret-bearing control-plane proof passed only to the configured verifier.
///
/// It is non-serializable, non-cloneable, redacted in debug output, and erased
/// when dropped. The journal persists only the verifier's non-secret digest.
pub struct OrphanAuthorityProof(Vec<u8>);

impl OrphanAuthorityProof {
    /// Creates a bounded, non-empty authority proof.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized proof material.
    pub fn new(value: Vec<u8>) -> Result<Self, OrphanAuthorityError> {
        if value.is_empty() || value.len() > MAX_ORPHAN_AUTHORITY_PROOF_BYTES {
            Err(OrphanAuthorityError::InvalidProof)
        } else {
            Ok(Self(value))
        }
    }

    /// Explicitly exposes proof bytes at the verifier boundary.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for OrphanAuthorityProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OrphanAuthorityProof([REDACTED])")
    }
}

impl Drop for OrphanAuthorityProof {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Which old-session deliveries the server explicitly permits abandoning.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrphanAbandonmentPermissions {
    terminal_result: bool,
    log_delivery: bool,
    lease_rejection: bool,
}

impl OrphanAbandonmentPermissions {
    #[must_use]
    pub const fn new(terminal_result: bool, log_delivery: bool, lease_rejection: bool) -> Self {
        Self {
            terminal_result,
            log_delivery,
            lease_rejection,
        }
    }

    #[must_use]
    pub const fn terminal_result(self) -> bool {
        self.terminal_result
    }

    #[must_use]
    pub const fn log_delivery(self) -> bool {
        self.log_delivery
    }

    #[must_use]
    pub const fn lease_rejection(self) -> bool {
        self.lease_rejection
    }

    const fn allows(self, delivery: OrphanDelivery) -> bool {
        match delivery {
            OrphanDelivery::TerminalResult => self.terminal_result,
            OrphanDelivery::LogStream => self.log_delivery,
            OrphanDelivery::LeaseRejection => self.lease_rejection,
        }
    }
}

/// Non-secret grant returned only by an authenticated authority adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrphanAuthorityGrant {
    claim: OrphanClaim,
    authority_operation_id: OperationId,
    evidence_digest: Sha256Digest,
    permissions: OrphanAbandonmentPermissions,
}

impl OrphanAuthorityGrant {
    /// Constructs the grant returned after an adapter verifies server authority.
    #[must_use]
    pub const fn new(
        claim: OrphanClaim,
        authority_operation_id: OperationId,
        evidence_digest: Sha256Digest,
        permissions: OrphanAbandonmentPermissions,
    ) -> Self {
        Self {
            claim,
            authority_operation_id,
            evidence_digest,
            permissions,
        }
    }

    #[must_use]
    pub const fn claim(self) -> OrphanClaim {
        self.claim
    }

    #[must_use]
    pub const fn authority_operation_id(self) -> OperationId {
        self.authority_operation_id
    }

    #[must_use]
    pub const fn evidence_digest(self) -> Sha256Digest {
        self.evidence_digest
    }

    #[must_use]
    pub const fn permissions(self) -> OrphanAbandonmentPermissions {
        self.permissions
    }
}

/// External authenticated server-authority boundary.
pub trait OrphanAuthorityVerifier: Send + Sync {
    /// Verifies that the server invalidated the exact old-session fence.
    ///
    /// # Errors
    ///
    /// Returns a typed denial or availability failure. Implementations must not
    /// include proof material in diagnostics.
    fn verify(
        &self,
        claim: OrphanClaim,
        proof: &OrphanAuthorityProof,
    ) -> Result<OrphanAuthorityGrant, OrphanAuthorityError>;
}

/// Secret-free authority-verification failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OrphanAuthorityError {
    #[error("orphan authority proof is invalid")]
    InvalidProof,
    #[error("control plane denied orphan reconciliation")]
    Denied,
    #[error("orphan authority verifier is unavailable")]
    Unavailable,
}

/// Old-session delivery that can be abandoned only when explicitly granted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrphanDelivery {
    TerminalResult,
    LogStream,
    LeaseRejection,
}

/// Bounded reason retained for an authorized undeliverable item.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrphanAbandonmentReason {
    SessionInvalidated,
    ControlPlaneRejected,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OrphanAbandonments {
    terminal_result: Option<OrphanAbandonmentReason>,
    log_delivery: Option<OrphanAbandonmentReason>,
    lease_rejection: Option<OrphanAbandonmentReason>,
}

impl OrphanAbandonments {
    const fn get(self, delivery: OrphanDelivery) -> Option<OrphanAbandonmentReason> {
        match delivery {
            OrphanDelivery::TerminalResult => self.terminal_result,
            OrphanDelivery::LogStream => self.log_delivery,
            OrphanDelivery::LeaseRejection => self.lease_rejection,
        }
    }

    fn set(&mut self, delivery: OrphanDelivery, reason: OrphanAbandonmentReason) {
        match delivery {
            OrphanDelivery::TerminalResult => self.terminal_result = Some(reason),
            OrphanDelivery::LogStream => self.log_delivery = Some(reason),
            OrphanDelivery::LeaseRejection => self.lease_rejection = Some(reason),
        }
    }
}

/// Durable proof metadata and authorized abandonment decisions for an orphan.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrphanRecord {
    session_id: RunnerSessionId,
    guard: LeaseGuard,
    authority_operation_id: OperationId,
    evidence_digest: Sha256Digest,
    permissions: OrphanAbandonmentPermissions,
    abandonments: OrphanAbandonments,
}

impl OrphanRecord {
    pub(crate) fn from_grant(grant: OrphanAuthorityGrant) -> Self {
        Self {
            session_id: grant.claim().session_id(),
            guard: grant.claim().guard(),
            authority_operation_id: grant.authority_operation_id(),
            evidence_digest: grant.evidence_digest(),
            permissions: grant.permissions(),
            abandonments: OrphanAbandonments::default(),
        }
    }

    #[must_use]
    pub const fn session_id(self) -> RunnerSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn guard(self) -> LeaseGuard {
        self.guard
    }

    #[must_use]
    pub const fn authority_operation_id(self) -> OperationId {
        self.authority_operation_id
    }

    #[must_use]
    pub const fn evidence_digest(self) -> Sha256Digest {
        self.evidence_digest
    }

    #[must_use]
    pub const fn permissions(self) -> OrphanAbandonmentPermissions {
        self.permissions
    }

    #[must_use]
    pub const fn abandonment(self, delivery: OrphanDelivery) -> Option<OrphanAbandonmentReason> {
        self.abandonments.get(delivery)
    }

    pub(crate) fn abandon(
        &mut self,
        authority_operation_id: OperationId,
        delivery: OrphanDelivery,
        reason: OrphanAbandonmentReason,
    ) -> Result<bool, JournalInvariantError> {
        if self.authority_operation_id != authority_operation_id
            || !self.permissions.allows(delivery)
        {
            return Err(JournalInvariantError::OrphanAuthorityMismatch);
        }
        match self.abandonments.get(delivery) {
            Some(existing) if existing == reason => Ok(false),
            Some(_) => Err(JournalInvariantError::OrphanAbandonmentConflict),
            None => {
                self.abandonments.set(delivery, reason);
                Ok(true)
            }
        }
    }

    pub(crate) fn matches_grant(self, grant: OrphanAuthorityGrant) -> bool {
        self.session_id == grant.claim().session_id()
            && self.guard == grant.claim().guard()
            && self.authority_operation_id == grant.authority_operation_id()
            && self.evidence_digest == grant.evidence_digest()
            && self.permissions == grant.permissions()
    }

    pub(crate) const fn is_abandoned(self, delivery: OrphanDelivery) -> bool {
        self.abandonments.get(delivery).is_some()
    }
}
