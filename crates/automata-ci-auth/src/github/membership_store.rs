//! Durable GitHub membership-snapshot persistence.
//!
//! Membership display names are retained only as observations. Stable GitHub
//! numeric organization and team IDs are the sole authorization authority.

use std::{fmt, future::Future, pin::Pin};

use thiserror::Error;
use uuid::Uuid;

use crate::{
    human::{PrincipalId, ProviderSubject, TenantId},
    time::UnixTimestamp,
    vault::TokenVersion,
};

use super::GithubMembershipSnapshot;

/// Maximum total organization and team observations in one durable snapshot.
pub const MAX_GITHUB_MEMBERSHIP_OBSERVATIONS: usize = 100_000;

/// Immutable identifier for one durable GitHub membership observation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubMembershipSnapshotId(Uuid);

impl GithubMembershipSnapshotId {
    /// Parses one canonical, non-nil, lowercase hyphenated UUID.
    ///
    /// # Errors
    ///
    /// Rejects nil, non-canonical, or malformed UUID text.
    pub fn new(value: impl AsRef<str>) -> Result<Self, GithubMembershipRequestError> {
        let value = value.as_ref();
        let parsed =
            Uuid::parse_str(value).map_err(|_| GithubMembershipRequestError::InvalidSnapshotId)?;
        if parsed.is_nil() || parsed.hyphenated().to_string() != value {
            return Err(GithubMembershipRequestError::InvalidSnapshotId);
        }
        Ok(Self(parsed))
    }

    /// Constructs an identifier from a parsed UUID.
    ///
    /// # Errors
    ///
    /// Rejects the nil UUID.
    pub const fn from_uuid(value: Uuid) -> Result<Self, GithubMembershipRequestError> {
        if value.is_nil() {
            return Err(GithubMembershipRequestError::InvalidSnapshotId);
        }
        Ok(Self(value))
    }

    /// Returns the parsed durable snapshot UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for GithubMembershipSnapshotId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// One complete, bounded GitHub membership observation made with fresh credentials.
///
/// This value intentionally carries no tenant, principal, or provider-token key.
/// Those durable bindings are added only inside the atomic persistence boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubMembershipObservation {
    snapshot_id: GithubMembershipSnapshotId,
    memberships: GithubMembershipSnapshot,
    observed_at: UnixTimestamp,
    valid_until: UnixTimestamp,
}

impl GithubMembershipObservation {
    /// Creates one complete membership observation.
    ///
    /// # Errors
    ///
    /// Rejects a non-positive validity interval or more observations than the
    /// durable adapter can safely persist.
    pub fn new(
        snapshot_id: GithubMembershipSnapshotId,
        memberships: GithubMembershipSnapshot,
        observed_at: UnixTimestamp,
        valid_until: UnixTimestamp,
    ) -> Result<Self, GithubMembershipRequestError> {
        if valid_until <= observed_at {
            return Err(GithubMembershipRequestError::InvalidValidity);
        }
        let membership_count = memberships
            .organizations()
            .len()
            .checked_add(memberships.teams().len())
            .ok_or(GithubMembershipRequestError::TooManyMemberships)?;
        if membership_count > MAX_GITHUB_MEMBERSHIP_OBSERVATIONS {
            return Err(GithubMembershipRequestError::TooManyMemberships);
        }
        Ok(Self {
            snapshot_id,
            memberships,
            observed_at,
            valid_until,
        })
    }

    /// Returns the immutable snapshot identity.
    #[must_use]
    pub const fn snapshot_id(&self) -> GithubMembershipSnapshotId {
        self.snapshot_id
    }

    /// Returns the complete numeric-ID membership observation.
    #[must_use]
    pub const fn memberships(&self) -> &GithubMembershipSnapshot {
        &self.memberships
    }

    /// Returns when the provider observation was made.
    #[must_use]
    pub const fn observed_at(&self) -> UnixTimestamp {
        self.observed_at
    }

    /// Returns the exclusive authorization-validity ceiling.
    #[must_use]
    pub const fn valid_until(&self) -> UnixTimestamp {
        self.valid_until
    }
}

impl fmt::Debug for GithubMembershipObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubMembershipObservation")
            .field("snapshot_id", &self.snapshot_id)
            .field(
                "organization_count",
                &self.memberships.organizations().len(),
            )
            .field("team_count", &self.memberships.teams().len())
            .field("observed_at", &self.observed_at)
            .field("valid_until", &self.valid_until)
            .finish()
    }
}

/// Validated request to persist one complete GitHub membership observation.
#[derive(Clone, Eq, PartialEq)]
pub struct PersistGithubMembershipSnapshot {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    principal_uuid: Uuid,
    provider_subject: ProviderSubject,
    provider_token_version: TokenVersion,
    observation: GithubMembershipObservation,
}

impl PersistGithubMembershipSnapshot {
    /// Binds one exact observation to its durable principal and credential.
    ///
    /// # Errors
    ///
    /// Rejects a non-canonical Automata principal UUID, a non-canonical positive
    /// GitHub numeric subject, or a non-positive snapshot validity interval.
    pub fn new(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        provider_subject: ProviderSubject,
        provider_token_version: TokenVersion,
        observation: GithubMembershipObservation,
    ) -> Result<Self, GithubMembershipRequestError> {
        let principal_uuid = Uuid::parse_str(principal_id.as_str())
            .map_err(|_| GithubMembershipRequestError::InvalidPrincipalId)?;
        if principal_uuid.is_nil()
            || principal_uuid.hyphenated().to_string() != principal_id.as_str()
        {
            return Err(GithubMembershipRequestError::InvalidPrincipalId);
        }
        let github_subject = provider_subject
            .as_str()
            .parse::<u64>()
            .ok()
            .filter(|subject| *subject > 0)
            .ok_or(GithubMembershipRequestError::InvalidProviderSubject)?;
        if github_subject.to_string() != provider_subject.as_str() {
            return Err(GithubMembershipRequestError::InvalidProviderSubject);
        }
        Ok(Self {
            tenant_id,
            principal_id,
            principal_uuid,
            provider_subject,
            provider_token_version,
            observation,
        })
    }

    /// Returns the tenant whose authorization snapshot is being updated.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the Automata principal bound to the provider identity.
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    /// Returns the validated UUID representation of the principal.
    #[must_use]
    pub const fn principal_uuid(&self) -> Uuid {
        self.principal_uuid
    }

    /// Returns the stable positive numeric GitHub user identity.
    #[must_use]
    pub const fn provider_subject(&self) -> &ProviderSubject {
        &self.provider_subject
    }

    /// Returns the exact credential version used for this observation.
    #[must_use]
    pub const fn provider_token_version(&self) -> TokenVersion {
        self.provider_token_version
    }

    /// Returns the immutable snapshot identity.
    #[must_use]
    pub const fn snapshot_id(&self) -> GithubMembershipSnapshotId {
        self.observation.snapshot_id()
    }

    /// Returns the complete numeric-ID membership observation.
    #[must_use]
    pub const fn memberships(&self) -> &GithubMembershipSnapshot {
        self.observation.memberships()
    }

    /// Returns when the provider observation was made.
    #[must_use]
    pub const fn observed_at(&self) -> UnixTimestamp {
        self.observation.observed_at()
    }

    /// Returns the exclusive authorization-validity ceiling.
    #[must_use]
    pub const fn valid_until(&self) -> UnixTimestamp {
        self.observation.valid_until()
    }
}

impl fmt::Debug for PersistGithubMembershipSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistGithubMembershipSnapshot")
            .field("tenant_id", &self.tenant_id)
            .field("principal_id", &self.principal_id)
            .field("provider_subject", &self.provider_subject)
            .field("provider_token_version", &self.provider_token_version)
            .field("snapshot_id", &self.observation.snapshot_id())
            .field(
                "organization_count",
                &self.observation.memberships().organizations().len(),
            )
            .field("team_count", &self.observation.memberships().teams().len())
            .field("observed_at", &self.observation.observed_at())
            .field("valid_until", &self.observation.valid_until())
            .finish_non_exhaustive()
    }
}

/// Closed validation failure for a membership-persistence request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubMembershipRequestError {
    /// The snapshot identifier is malformed, non-canonical, or nil.
    #[error("GitHub membership snapshot ID must be a canonical non-nil UUID")]
    InvalidSnapshotId,
    /// The Automata principal is not a canonical non-nil UUID.
    #[error("GitHub membership principal ID must be a canonical non-nil UUID")]
    InvalidPrincipalId,
    /// The provider subject is not a canonical positive GitHub numeric ID.
    #[error("GitHub provider subject must be a canonical positive numeric ID")]
    InvalidProviderSubject,
    /// The authorization-validity ceiling is not after observation.
    #[error("GitHub membership snapshot validity must end after observation")]
    InvalidValidity,
    /// The complete organization/team observation exceeds its durable bound.
    #[error("GitHub membership snapshot contains too many observations")]
    TooManyMemberships,
}

/// Result of one membership-snapshot persistence attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistGithubMembershipSnapshotOutcome {
    /// A new immutable snapshot was stored.
    Stored {
        /// Current positive authorization revision after persistence.
        authorization_revision: u64,
        /// Whether stable numeric authority changed from the previous snapshot.
        authorization_changed: bool,
    },
    /// The same immutable snapshot and observations were already stored.
    AlreadyStored {
        /// Existing positive authorization revision for this exact snapshot.
        authorization_revision: u64,
    },
    /// The bound Automata principal does not exist.
    PrincipalNotFound,
    /// The bound principal cannot currently authenticate.
    PrincipalDisabled,
    /// The principal has no matching provider identity.
    IdentityNotFound,
    /// No durable membership record exists for the identity.
    MembershipNotFound,
    /// The durable provider membership is suspended.
    MembershipSuspended,
    /// The exact provider credential record does not exist.
    ProviderTokenNotFound,
    /// The exact provider credential has been revoked.
    ProviderTokenRevoked,
    /// The provider credential is not valid yet.
    ProviderTokenNotYetValid,
    /// The provider credential is expired.
    ProviderTokenExpired,
    /// Durable credential rotation raced this observation.
    ProviderTokenVersionChanged {
        /// Current durable provider-token version.
        current_version: TokenVersion,
    },
    /// The UUID already names different immutable content.
    SnapshotConflict,
    /// A new snapshot was observed no later than an already persisted snapshot.
    ObservationOutOfOrder,
}

/// Boxed future returned by [`GithubMembershipRepository`].
pub type GithubMembershipPersistenceFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    PersistGithubMembershipSnapshotOutcome,
                    GithubMembershipRepositoryError,
                >,
            > + Send
            + 'a,
    >,
>;

/// Object-safe durable GitHub membership authority boundary.
pub trait GithubMembershipRepository: fmt::Debug + Send + Sync {
    /// Atomically validates authority and persists one complete observation.
    fn persist<'a>(
        &'a self,
        request: &'a PersistGithubMembershipSnapshot,
    ) -> GithubMembershipPersistenceFuture<'a>;
}

/// Sanitized persistence or durable-data failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubMembershipRepositoryError {
    /// The request violates the repository's closed input contract.
    #[error("GitHub membership persistence request is invalid")]
    InvalidRequest,
    /// Durable storage is temporarily unavailable.
    #[error("GitHub membership storage is unavailable")]
    Unavailable,
    /// Persisted identity, membership, or snapshot state is inconsistent.
    #[error("durable GitHub membership data violates an invariant")]
    CorruptData,
}
