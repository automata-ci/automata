//! One-time, replica-independent credentials for authorized human log tails.

use std::time::Duration;

use async_trait::async_trait;
use automata_ci_core::{AttemptId, JobId, LogStreamId, RunId, UnixMillis};
use thiserror::Error;
use url::{Host, Url};

use crate::{RepositoryId, StoreError, TenantScope};

/// Wire version shared by ticket issuance and live-log transports.
pub const HUMAN_LIVE_LOG_PROTOCOL_VERSION: u16 = 1;
/// Maximum time in which an issued live-log ticket may be redeemed.
pub const MAX_HUMAN_LIVE_LOG_TICKET_LIFETIME: Duration = Duration::from_mins(1);

const MAX_BROWSER_ORIGIN_BYTES: usize = 2_048;

/// Exact durable resource authorized for one live-log connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanLiveLogScope {
    tenant: TenantScope,
    repository_id: RepositoryId,
    run_id: RunId,
    job_id: JobId,
    attempt_id: AttemptId,
    stream_id: LogStreamId,
}

impl HumanLiveLogScope {
    /// Creates a completely nested, non-nil live-log resource scope.
    ///
    /// # Errors
    ///
    /// Rejects a nil durable identity.
    pub fn new(
        tenant: TenantScope,
        repository_id: RepositoryId,
        run_id: RunId,
        job_id: JobId,
        attempt_id: AttemptId,
        stream_id: LogStreamId,
    ) -> Result<Self, HumanLiveLogTicketValueError> {
        if repository_id.as_uuid().is_nil()
            || run_id.as_uuid().is_nil()
            || job_id.as_uuid().is_nil()
            || attempt_id.as_uuid().is_nil()
            || stream_id.as_uuid().is_nil()
        {
            return Err(HumanLiveLogTicketValueError);
        }
        Ok(Self {
            tenant,
            repository_id,
            run_id,
            job_id,
            attempt_id,
            stream_id,
        })
    }

    /// Returns the workspace that owns the stream.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the exact parent repository.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the exact parent workflow run.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the exact parent job.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns the exact execution attempt.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the exact durable log stream.
    #[must_use]
    pub const fn stream_id(&self) -> LogStreamId {
        self.stream_id
    }
}

/// Canonical browser origin to which a live-log ticket is bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanLiveLogBrowserOrigin(String);

impl HumanLiveLogBrowserOrigin {
    /// Validates a canonical HTTPS origin or literal-loopback HTTP origin.
    ///
    /// # Errors
    ///
    /// Rejects credentials, paths, queries, fragments, noncanonical text, and
    /// cleartext non-loopback origins.
    pub fn new(value: impl Into<String>) -> Result<Self, HumanLiveLogTicketValueError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_BROWSER_ORIGIN_BYTES {
            return Err(HumanLiveLogTicketValueError);
        }
        let parsed = Url::parse(&value).map_err(|_| HumanLiveLogTicketValueError)?;
        let secure = parsed.scheme() == "https";
        let loopback = parsed.scheme() == "http"
            && matches!(
                parsed.host(),
                Some(Host::Ipv4(address)) if address.is_loopback()
            )
            || parsed.scheme() == "http"
                && matches!(
                    parsed.host(),
                    Some(Host::Ipv6(address)) if address.is_loopback()
                );
        if (!secure && !loopback)
            || parsed.host().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.origin().ascii_serialization() != value
        {
            return Err(HumanLiveLogTicketValueError);
        }
        Ok(Self(value))
    }

    /// Returns the canonical serialized origin without a trailing slash.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Sanitized invalid live-log ticket value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("live-log ticket value is invalid")]
pub struct HumanLiveLogTicketValueError;

/// Durable issue request containing only a one-way credential digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueHumanLiveLogTicket {
    token_sha256: [u8; 32],
    scope: HumanLiveLogScope,
    browser_origin: HumanLiveLogBrowserOrigin,
    protocol_version: u16,
    lifetime: Duration,
}

impl IssueHumanLiveLogTicket {
    /// Creates a bounded current-protocol ticket issue request.
    ///
    /// # Errors
    ///
    /// Rejects a zero, subsecond, or over-limit lifetime.
    pub fn new(
        token_sha256: [u8; 32],
        scope: HumanLiveLogScope,
        browser_origin: HumanLiveLogBrowserOrigin,
        lifetime: Duration,
    ) -> Result<Self, HumanLiveLogTicketValueError> {
        if lifetime.is_zero()
            || lifetime > MAX_HUMAN_LIVE_LOG_TICKET_LIFETIME
            || lifetime.subsec_nanos() != 0
        {
            return Err(HumanLiveLogTicketValueError);
        }
        Ok(Self {
            token_sha256,
            scope,
            browser_origin,
            protocol_version: HUMAN_LIVE_LOG_PROTOCOL_VERSION,
            lifetime,
        })
    }

    /// Returns the one-way lookup digest.
    #[must_use]
    pub const fn token_sha256(&self) -> &[u8; 32] {
        &self.token_sha256
    }

    /// Returns the authorized durable resource.
    #[must_use]
    pub const fn scope(&self) -> &HumanLiveLogScope {
        &self.scope
    }

    /// Returns the browser origin allowed to redeem the ticket.
    #[must_use]
    pub const fn browser_origin(&self) -> &HumanLiveLogBrowserOrigin {
        &self.browser_origin
    }

    /// Returns the exact live-log protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    /// Returns the bounded redemption window.
    #[must_use]
    pub const fn lifetime(&self) -> Duration {
        self.lifetime
    }
}

/// Successful ticket issue metadata. The raw credential remains app-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssuedHumanLiveLogTicket {
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

impl IssuedHumanLiveLogTicket {
    /// Creates exact database-clock issue metadata.
    #[must_use]
    pub const fn new(issued_at: UnixMillis, expires_at: UnixMillis) -> Self {
        Self {
            issued_at,
            expires_at,
        }
    }

    /// Returns the database-clock issue time.
    #[must_use]
    pub const fn issued_at(self) -> UnixMillis {
        self.issued_at
    }

    /// Returns the exclusive database-clock redemption deadline.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

/// Outcome of inserting a random ticket digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueHumanLiveLogTicketOutcome {
    /// The digest was inserted and can be returned to the caller.
    Issued(IssuedHumanLiveLogTicket),
    /// The random digest already existed; the caller should generate a new credential.
    DigestCollision,
}

/// Atomic one-time ticket redemption request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedeemHumanLiveLogTicket {
    token_sha256: [u8; 32],
    browser_origin: HumanLiveLogBrowserOrigin,
    protocol_version: u16,
}

impl RedeemHumanLiveLogTicket {
    /// Creates an exact current-protocol redemption request.
    #[must_use]
    pub const fn new(token_sha256: [u8; 32], browser_origin: HumanLiveLogBrowserOrigin) -> Self {
        Self {
            token_sha256,
            browser_origin,
            protocol_version: HUMAN_LIVE_LOG_PROTOCOL_VERSION,
        }
    }

    /// Returns the one-way lookup digest.
    #[must_use]
    pub const fn token_sha256(&self) -> &[u8; 32] {
        &self.token_sha256
    }

    /// Returns the exact requesting browser origin.
    #[must_use]
    pub const fn browser_origin(&self) -> &HumanLiveLogBrowserOrigin {
        &self.browser_origin
    }

    /// Returns the exact requested protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }
}

/// Scope recovered by one successful atomic redemption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedeemedHumanLiveLogTicket {
    scope: HumanLiveLogScope,
    consumed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl RedeemedHumanLiveLogTicket {
    /// Creates exact database-decoded redemption evidence.
    #[must_use]
    pub const fn new(
        scope: HumanLiveLogScope,
        consumed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Self {
        Self {
            scope,
            consumed_at,
            expires_at,
        }
    }

    /// Returns the exact durable stream authority.
    #[must_use]
    pub const fn scope(&self) -> &HumanLiveLogScope {
        &self.scope
    }

    /// Returns when the database atomically consumed the ticket.
    #[must_use]
    pub const fn consumed_at(&self) -> UnixMillis {
        self.consumed_at
    }

    /// Returns the original exclusive redemption deadline.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Shared durable repository for one-time live-log tickets.
#[async_trait]
pub trait HumanLiveLogTicketRepository: std::fmt::Debug + Send + Sync {
    /// Inserts one digest or reports the vanishingly unlikely random collision.
    async fn issue(
        &self,
        request: &IssueHumanLiveLogTicket,
    ) -> Result<IssueHumanLiveLogTicketOutcome, StoreError>;

    /// Atomically consumes one unexpired, origin-bound ticket.
    async fn redeem(
        &self,
        request: &RedeemHumanLiveLogTicket,
    ) -> Result<Option<RedeemedHumanLiveLogTicket>, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn browser_origins_are_canonical_and_never_downgrade_remote_http() {
        for valid in [
            "https://ci.example",
            "http://127.0.0.1:8080",
            "http://[::1]",
        ] {
            assert_eq!(
                HumanLiveLogBrowserOrigin::new(valid)
                    .expect("valid origin")
                    .as_str(),
                valid
            );
        }
        for invalid in [
            "http://ci.example",
            "https://ci.example/",
            "https://ci.example/path",
            "https://user@ci.example",
            "https://ci.example?query",
        ] {
            assert!(
                HumanLiveLogBrowserOrigin::new(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn scope_and_lifetime_reject_ambiguous_authority() {
        let tenant =
            TenantScope::from_authenticated_tenant_id("workspace".to_owned()).expect("tenant");
        let scope = HumanLiveLogScope::new(
            tenant.clone(),
            RepositoryId::from_uuid(Uuid::from_u128(1)),
            RunId::from_uuid(Uuid::from_u128(2)),
            JobId::from_uuid(Uuid::from_u128(3)),
            AttemptId::from_uuid(Uuid::from_u128(4)),
            LogStreamId::from_uuid(Uuid::from_u128(5)),
        )
        .expect("scope");
        let origin = HumanLiveLogBrowserOrigin::new("https://ci.example").expect("origin");
        assert!(
            IssueHumanLiveLogTicket::new(
                [1; 32],
                scope.clone(),
                origin.clone(),
                Duration::from_mins(1)
            )
            .is_ok()
        );
        assert!(
            IssueHumanLiveLogTicket::new([1; 32], scope, origin, Duration::from_secs(61)).is_err()
        );
        assert!(
            HumanLiveLogScope::new(
                tenant,
                RepositoryId::from_uuid(Uuid::nil()),
                RunId::from_uuid(Uuid::from_u128(2)),
                JobId::from_uuid(Uuid::from_u128(3)),
                AttemptId::from_uuid(Uuid::from_u128(4)),
                LogStreamId::from_uuid(Uuid::from_u128(5)),
            )
            .is_err()
        );
    }
}
