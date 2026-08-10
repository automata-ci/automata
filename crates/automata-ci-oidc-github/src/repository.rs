use std::{
    collections::BTreeMap,
    fmt,
    sync::{Mutex, MutexGuard},
};

use async_trait::async_trait;
use thiserror::Error;

use crate::{
    AuthorizedOidcAuthority, AuthorizedOidcIssuance, OidcAudience, OidcAuthorityId, OidcIssuance,
    ReserveOidcIssuance,
};

const MAXIMUM_IN_MEMORY_AUTHORITIES: usize = 65_536;
const MAXIMUM_IN_MEMORY_ISSUANCES: usize = 262_144;

/// Stable class for a sanitized durable OIDC repository failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcRepositoryErrorKind {
    /// No current execution authority permits this operation.
    Unauthorized,
    /// Immutable replay evidence conflicts with the request.
    Conflict,
    /// A configured durable count or byte ceiling was reached.
    ResourceExhausted,
    /// Persisted state violates the repository contract.
    CorruptData,
    /// The durable provider is temporarily unavailable.
    Unavailable,
}

/// Provider-sanitized durable OIDC repository failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("OIDC issuance repository operation failed: {kind:?}")]
pub struct OidcRepositoryError {
    kind: OidcRepositoryErrorKind,
}

impl OidcRepositoryError {
    /// Creates an error without provider text or credential data.
    #[must_use]
    pub const fn new(kind: OidcRepositoryErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> OidcRepositoryErrorKind {
        self.kind
    }
}

/// Durable authorization and exact-replay boundary for workload ID tokens.
///
/// An implementation must atomically revalidate current execution authority
/// and reserve a new issuance, or return the byte-equivalent immutable replay
/// for the same authenticated request-bearer interval and requested audience.
/// Caller-provided HTTP fields never determine the subject or additional
/// claims. A replay must still be unexpired and within every current authority
/// and request-bearer deadline in [`ReserveOidcIssuance`]. Every successful
/// call must also return the trusted time of that call's authorization; replay
/// may reuse immutable token fields but cannot reuse an earlier authorization
/// decision.
#[async_trait]
pub trait OidcIssuanceRepository: fmt::Debug + Send + Sync {
    /// Revalidates authority and reserves or replays one exact issuance.
    ///
    /// The returned authorization time is a current trusted sample for this
    /// call and cannot predate [`ReserveOidcIssuance::observed_at_seconds`].
    async fn reserve(
        &self,
        request: ReserveOidcIssuance,
    ) -> Result<AuthorizedOidcIssuance, OidcRepositoryError>;
}

/// Bounded capacities for the reference in-memory repository.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InMemoryOidcRepositoryLimits {
    maximum_authorities: usize,
    maximum_issuances: usize,
}

impl InMemoryOidcRepositoryLimits {
    /// Creates nonzero capacities within the reference adapter ceilings.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive capacities.
    pub const fn new(
        maximum_authorities: usize,
        maximum_issuances: usize,
    ) -> Result<Self, InMemoryOidcRepositoryLimitsError> {
        if maximum_authorities == 0
            || maximum_authorities > MAXIMUM_IN_MEMORY_AUTHORITIES
            || maximum_issuances == 0
            || maximum_issuances > MAXIMUM_IN_MEMORY_ISSUANCES
        {
            return Err(InMemoryOidcRepositoryLimitsError);
        }
        Ok(Self {
            maximum_authorities,
            maximum_issuances,
        })
    }
}

impl Default for InMemoryOidcRepositoryLimits {
    fn default() -> Self {
        Self {
            maximum_authorities: 1_024,
            maximum_issuances: 16_384,
        }
    }
}

/// Invalid in-memory OIDC repository capacities.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("in-memory OIDC repository capacities are invalid")]
pub struct InMemoryOidcRepositoryLimitsError;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReplayKey {
    authority_id: OidcAuthorityId,
    request_issued_at_seconds: u64,
    request_expires_at_seconds: u64,
    requested_audience: Option<OidcAudience>,
}

#[derive(Debug, Default)]
struct InMemoryState {
    authorities: BTreeMap<OidcAuthorityId, AuthorizedOidcAuthority>,
    issuances: BTreeMap<ReplayKey, OidcIssuance>,
}

/// Reference bounded repository for tests and local, non-durable composition.
///
/// This adapter models the atomic authorization/replay contract but loses all
/// state on process exit. It is not a production durability boundary.
#[derive(Debug)]
pub struct InMemoryOidcRepository {
    limits: InMemoryOidcRepositoryLimits,
    state: Mutex<InMemoryState>,
}

impl InMemoryOidcRepository {
    /// Creates an empty reference repository with explicit capacities.
    #[must_use]
    pub fn new(limits: InMemoryOidcRepositoryLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(InMemoryState::default()),
        }
    }

    /// Inserts or replaces current authenticated authority data.
    ///
    /// Changing an authority invalidates its in-memory replay records so stale
    /// claims cannot survive an authorization revision.
    ///
    /// # Errors
    ///
    /// Returns a sanitized capacity or poisoned-state failure.
    pub fn upsert_authority(
        &self,
        authority: AuthorizedOidcAuthority,
    ) -> Result<(), OidcRepositoryError> {
        let mut state = self.lock_state()?;
        let authority_id = authority.authority_id();
        let is_new = !state.authorities.contains_key(&authority_id);
        if is_new && state.authorities.len() >= self.limits.maximum_authorities {
            return Err(OidcRepositoryError::new(
                OidcRepositoryErrorKind::ResourceExhausted,
            ));
        }
        let changed = state.authorities.get(&authority_id) != Some(&authority);
        state.authorities.insert(authority_id, authority);
        if changed {
            state
                .issuances
                .retain(|key, _| key.authority_id != authority_id);
        }
        Ok(())
    }

    /// Revokes one authority and every in-memory replay bound to it.
    ///
    /// # Errors
    ///
    /// Returns a sanitized poisoned-state failure.
    pub fn revoke_authority(
        &self,
        authority_id: OidcAuthorityId,
    ) -> Result<bool, OidcRepositoryError> {
        let mut state = self.lock_state()?;
        let removed = state.authorities.remove(&authority_id).is_some();
        state
            .issuances
            .retain(|key, _| key.authority_id != authority_id);
        Ok(removed)
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, InMemoryState>, OidcRepositoryError> {
        self.state
            .lock()
            .map_err(|_| OidcRepositoryError::new(OidcRepositoryErrorKind::CorruptData))
    }
}

impl Default for InMemoryOidcRepository {
    fn default() -> Self {
        Self::new(InMemoryOidcRepositoryLimits::default())
    }
}

#[async_trait]
impl OidcIssuanceRepository for InMemoryOidcRepository {
    async fn reserve(
        &self,
        request: ReserveOidcIssuance,
    ) -> Result<AuthorizedOidcIssuance, OidcRepositoryError> {
        if request.request_issued_at_seconds() > request.observed_at_seconds()
            || request.request_expires_at_seconds() <= request.observed_at_seconds()
            || request.maximum_expires_at_seconds() > request.request_expires_at_seconds()
            || request.maximum_expires_at_seconds() <= request.observed_at_seconds()
        {
            return Err(OidcRepositoryError::new(
                OidcRepositoryErrorKind::Unauthorized,
            ));
        }

        let mut state = self.lock_state()?;
        let authority = state
            .authorities
            .get(&request.authority_id())
            .ok_or_else(|| OidcRepositoryError::new(OidcRepositoryErrorKind::Unauthorized))?
            .clone();
        if authority.not_before_seconds() > request.observed_at_seconds()
            || authority.expires_at_seconds() <= request.observed_at_seconds()
        {
            return Err(OidcRepositoryError::new(
                OidcRepositoryErrorKind::Unauthorized,
            ));
        }

        state
            .issuances
            .retain(|_, issuance| issuance.expires_at_seconds() > request.observed_at_seconds());
        let replay_key = ReplayKey {
            authority_id: request.authority_id(),
            request_issued_at_seconds: request.request_issued_at_seconds(),
            request_expires_at_seconds: request.request_expires_at_seconds(),
            requested_audience: request.requested_audience().cloned(),
        };
        let audience = request
            .requested_audience()
            .unwrap_or_else(|| authority.default_audience())
            .clone();
        if let Some(replay) = state.issuances.get(&replay_key) {
            let valid_replay = replay.authority_id() == authority.authority_id()
                && replay.subject() == authority.subject()
                && replay.audience() == &audience
                && replay.additional_claims() == authority.additional_claims()
                && replay.issued_at_seconds() >= request.request_issued_at_seconds()
                && replay.issued_at_seconds() <= request.observed_at_seconds()
                && replay.not_before_seconds() <= request.observed_at_seconds()
                && replay.expires_at_seconds() > request.observed_at_seconds()
                && replay.expires_at_seconds() <= request.maximum_expires_at_seconds()
                && replay.expires_at_seconds() <= authority.expires_at_seconds();
            if !valid_replay {
                return Err(OidcRepositoryError::new(
                    OidcRepositoryErrorKind::CorruptData,
                ));
            }
            return Ok(AuthorizedOidcIssuance::new(
                replay.clone(),
                request.observed_at_seconds(),
            ));
        }

        if state.issuances.len() >= self.limits.maximum_issuances {
            return Err(OidcRepositoryError::new(
                OidcRepositoryErrorKind::ResourceExhausted,
            ));
        }
        if state
            .issuances
            .values()
            .any(|issuance| issuance.token_id() == request.proposed_token_id())
        {
            return Err(OidcRepositoryError::new(OidcRepositoryErrorKind::Conflict));
        }

        let expires_at_seconds = request
            .maximum_expires_at_seconds()
            .min(authority.expires_at_seconds());
        if expires_at_seconds <= request.observed_at_seconds() {
            return Err(OidcRepositoryError::new(
                OidcRepositoryErrorKind::Unauthorized,
            ));
        }
        let issuance = OidcIssuance::new(
            authority.authority_id(),
            request.proposed_token_id(),
            request.proposed_signing_key_id().clone(),
            authority.subject().clone(),
            audience,
            authority.additional_claims().clone(),
            request.observed_at_seconds(),
            request.observed_at_seconds(),
            expires_at_seconds,
        )
        .map_err(|_| OidcRepositoryError::new(OidcRepositoryErrorKind::CorruptData))?;
        state.issuances.insert(replay_key, issuance.clone());
        Ok(AuthorizedOidcIssuance::new(
            issuance,
            request.observed_at_seconds(),
        ))
    }
}
