use std::{fmt, sync::Arc};

use crate::runner_control::{
    ControlPortError, OptionalRuntimeAuthorityIssuer, RuntimeAuthorityIssueRequest,
};
use async_trait::async_trait;
use automata_ci_core::{PermissionLevel, Sha256Digest, UnixMillis};
use automata_ci_protocol::{
    JobRuntimeAuthorities, JobRuntimeAuthority, RuntimeAuthorityCredential,
    RuntimeAuthorityEndpoint, RuntimeAuthorityName,
};
use automata_ci_workload_oidc::{
    OidcAuthorityId, OidcIssuer, OidcKeyId, RequestBearerKeyring,
    WORKLOAD_OIDC_RUNTIME_AUTHORITY_NAMESPACE,
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use uuid::Uuid;

const GITHUB_PROVIDER: &str = "github";
const ID_TOKEN_PERMISSION: &str = "id-token";

/// Exact entitled lease-offer evidence proposed for durable OIDC reservation.
///
/// The provisioner must transactionally authenticate every coordinate in
/// [`Self::runtime_authority_request`] and idempotently reserve one fixed result.
/// A new record must persist the exact proposed tuple and digest. A replay may
/// instead return its previously pinned identity, retained key, interval, and
/// digest. The provisioner never receives request-bearer signing material.
#[derive(Clone, Eq, PartialEq)]
pub struct ReserveWorkloadOidcRuntimeAuthority<'a> {
    runtime_authority_request: RuntimeAuthorityIssueRequest<'a>,
    proposed_authority_id: OidcAuthorityId,
    proposed_request_bearer_key_id: OidcKeyId,
    proposed_issued_at_seconds: u64,
    proposed_expires_at_seconds: u64,
    proposed_request_bearer_sha256: Sha256Digest,
}

impl<'a> ReserveWorkloadOidcRuntimeAuthority<'a> {
    fn new(
        runtime_authority_request: RuntimeAuthorityIssueRequest<'a>,
        proposed_authority_id: OidcAuthorityId,
        proposed_request_bearer_key_id: OidcKeyId,
        proposed_issued_at_seconds: u64,
        proposed_expires_at_seconds: u64,
        proposed_request_bearer_sha256: Sha256Digest,
    ) -> Self {
        Self {
            runtime_authority_request,
            proposed_authority_id,
            proposed_request_bearer_key_id,
            proposed_issued_at_seconds,
            proposed_expires_at_seconds,
            proposed_request_bearer_sha256,
        }
    }

    /// Returns the current `JobIR`, immutable object metadata, lease, session,
    /// slot, and deterministic issuance anchor that durable state must bind.
    #[must_use]
    pub const fn runtime_authority_request(&self) -> RuntimeAuthorityIssueRequest<'a> {
        self.runtime_authority_request
    }

    /// Returns the fresh opaque authority identity proposed for a new record.
    #[must_use]
    pub const fn proposed_authority_id(&self) -> OidcAuthorityId {
        self.proposed_authority_id
    }

    /// Returns the active request-bearer key proposed for a new reservation.
    #[must_use]
    pub const fn proposed_request_bearer_key_id(&self) -> &OidcKeyId {
        &self.proposed_request_bearer_key_id
    }

    /// Returns the fixed inclusive issuance second derived from the lease.
    #[must_use]
    pub const fn proposed_issued_at_seconds(&self) -> u64 {
        self.proposed_issued_at_seconds
    }

    /// Returns the exact exclusive expiration proposed for a new record.
    #[must_use]
    pub const fn proposed_expires_at_seconds(&self) -> u64 {
        self.proposed_expires_at_seconds
    }

    /// Returns the SHA-256 digest of the exact proposed private bearer bytes.
    #[must_use]
    pub const fn proposed_request_bearer_sha256(&self) -> Sha256Digest {
        self.proposed_request_bearer_sha256
    }
}

impl fmt::Debug for ReserveWorkloadOidcRuntimeAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let request = self.runtime_authority_request;
        formatter
            .debug_struct("ReserveWorkloadOidcRuntimeAuthority")
            .field("run_id", &request.job().job().run_id())
            .field("job_id", &request.job().job().job_id())
            .field("attempt_id", &request.lease().attempt_id())
            .field("fencing_token", &request.lease().fencing_token())
            .field("proposed_authority_id", &self.proposed_authority_id)
            .field(
                "proposed_request_bearer_key_id",
                &self.proposed_request_bearer_key_id,
            )
            .field(
                "proposed_issued_at_seconds",
                &self.proposed_issued_at_seconds,
            )
            .field(
                "proposed_expires_at_seconds",
                &self.proposed_expires_at_seconds,
            )
            .field(
                "proposed_request_bearer_sha256",
                &self.proposed_request_bearer_sha256,
            )
            .finish()
    }
}

/// Durably reserved OIDC runtime authority returned by the provisioner.
///
/// This value carries no subject, audience, repository policy, or credential.
/// The issuer independently checks its interval and retained key against the
/// exact reservation request before producing protected runner bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedWorkloadOidcRuntimeAuthority {
    authority_id: OidcAuthorityId,
    request_bearer_key_id: OidcKeyId,
    issued_at_seconds: u64,
    expires_at_seconds: u64,
    request_bearer_sha256: Sha256Digest,
}

impl ReservedWorkloadOidcRuntimeAuthority {
    /// Rehydrates the narrow result of one atomic durable reservation.
    ///
    /// Cross-request interval and key consistency are intentionally validated
    /// again by [`WorkloadOidcRuntimeAuthorityIssuer`].
    #[must_use]
    pub const fn new(
        authority_id: OidcAuthorityId,
        request_bearer_key_id: OidcKeyId,
        issued_at_seconds: u64,
        expires_at_seconds: u64,
        request_bearer_sha256: Sha256Digest,
    ) -> Self {
        Self {
            authority_id,
            request_bearer_key_id,
            issued_at_seconds,
            expires_at_seconds,
            request_bearer_sha256,
        }
    }

    /// Returns the opaque durable authority identity signed into the bearer.
    #[must_use]
    pub const fn authority_id(&self) -> OidcAuthorityId {
        self.authority_id
    }

    /// Returns the exact retained request-bearer key pinned by durable state.
    #[must_use]
    pub const fn request_bearer_key_id(&self) -> &OidcKeyId {
        &self.request_bearer_key_id
    }

    /// Returns the fixed inclusive request-bearer issuance second.
    #[must_use]
    pub const fn issued_at_seconds(&self) -> u64 {
        self.issued_at_seconds
    }

    /// Returns the fixed exclusive request-bearer expiration second.
    #[must_use]
    pub const fn expires_at_seconds(&self) -> u64 {
        self.expires_at_seconds
    }

    /// Returns the durable digest of the exact private bearer bytes.
    #[must_use]
    pub const fn request_bearer_sha256(&self) -> Sha256Digest {
        self.request_bearer_sha256
    }
}

/// Fresh opaque identity source kept outside durable reservation for replay.
pub trait WorkloadOidcAuthorityIdGenerator: fmt::Debug + Send + Sync {
    /// Generates one fresh, unguessable authority identity for a new proposal.
    fn next_workload_oidc_authority_id(&self) -> OidcAuthorityId;
}

/// Random RFC 9562 version-4 OIDC authority identity generator.
#[derive(Clone, Copy, Debug, Default)]
pub struct RandomWorkloadOidcAuthorityIdGenerator;

impl WorkloadOidcAuthorityIdGenerator for RandomWorkloadOidcAuthorityIdGenerator {
    fn next_workload_oidc_authority_id(&self) -> OidcAuthorityId {
        OidcAuthorityId::from_uuid(Uuid::new_v4()).expect("a version-4 UUID is non-nil")
    }
}

/// Least-authority durable boundary for one entitled workload OIDC execution.
///
/// Implementations must authenticate the request's exact current job, object,
/// lease, session, and slot; recheck the durable permission and execution
/// lifecycle; and atomically reserve or replay one byte-stable result. Missing
/// or inconsistent execution evidence is an error, not a permission decline.
/// For a new execution it must persist the proposal exactly; it must not
/// shorten the horizon. An existing execution returns its original tuple and
/// digest without rewriting it from the new proposal.
#[async_trait]
pub trait WorkloadOidcAuthorityProvisioner: fmt::Debug + Send + Sync {
    /// Authenticates and reserves the sole OIDC authority for this request.
    async fn reserve_workload_oidc_runtime_authority(
        &self,
        request: ReserveWorkloadOidcRuntimeAuthority<'_>,
    ) -> Result<ReservedWorkloadOidcRuntimeAuthority, ControlPortError>;
}

/// Fail-closed optional issuer used while Automata workload OIDC is unavailable.
///
/// A product should install this guard whenever an old durable runner
/// registration could still advertise OIDC consumption but the complete OIDC
/// route, key, policy, or repository composition has not been admitted. Jobs
/// that do not request workload OIDC remain unaffected. An entitled job returns a
/// sanitized transient failure before a lease offer can publish, never an empty
/// authority bundle that would let the job execute without OIDC variables.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableWorkloadOidcRuntimeAuthorityIssuer;

#[async_trait]
impl OptionalRuntimeAuthorityIssuer for UnavailableWorkloadOidcRuntimeAuthorityIssuer {
    async fn issue_optional(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<Option<JobRuntimeAuthorities>, ControlPortError> {
        if workload_oidc_is_permitted(request) {
            Err(ControlPortError::Unavailable)
        } else {
            Ok(None)
        }
    }
}

/// Sanitized invalid configuration for the OIDC runtime-authority bridge.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkloadOidcRuntimeAuthorityIssuerConfigurationError {
    /// The OIDC issuer cannot be represented as the exact TLS runtime origin.
    #[error("the workload OIDC runtime-authority issuer is invalid")]
    InvalidIssuer,
}

/// Permission-gated issuer for one deterministic Automata workload OIDC bearer.
pub struct WorkloadOidcRuntimeAuthorityIssuer {
    provisioner: Arc<dyn WorkloadOidcAuthorityProvisioner>,
    authority_ids: Arc<dyn WorkloadOidcAuthorityIdGenerator>,
    request_bearers: Arc<RequestBearerKeyring>,
    issuer: OidcIssuer,
    endpoint: RuntimeAuthorityEndpoint,
    name: RuntimeAuthorityName,
}

impl WorkloadOidcRuntimeAuthorityIssuer {
    /// Binds one OIDC issuer and request-bearer keyring to durable provisioning.
    ///
    /// # Errors
    ///
    /// Rejects an issuer that cannot be represented as the same bounded HTTPS
    /// root runtime-authority endpoint.
    pub fn new(
        issuer: OidcIssuer,
        request_bearers: Arc<RequestBearerKeyring>,
        authority_ids: Arc<dyn WorkloadOidcAuthorityIdGenerator>,
        provisioner: Arc<dyn WorkloadOidcAuthorityProvisioner>,
    ) -> Result<Self, WorkloadOidcRuntimeAuthorityIssuerConfigurationError> {
        let endpoint = RuntimeAuthorityEndpoint::new(issuer.as_str())
            .map_err(|_| WorkloadOidcRuntimeAuthorityIssuerConfigurationError::InvalidIssuer)?;
        let name = RuntimeAuthorityName::new(WORKLOAD_OIDC_RUNTIME_AUTHORITY_NAMESPACE)
            .map_err(|_| WorkloadOidcRuntimeAuthorityIssuerConfigurationError::InvalidIssuer)?;
        Ok(Self {
            provisioner,
            authority_ids,
            request_bearers,
            issuer,
            endpoint,
            name,
        })
    }

    fn maximum_interval(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<(u64, u64), ControlPortError> {
        let issued_at_millis =
            u64::try_from(request.issued_at().get()).map_err(|_| ControlPortError::Corrupt)?;
        let issued_at_seconds = issued_at_millis / 1_000;
        let maximum_lifetime_seconds = request.job().job().timeout_seconds().map_or_else(
            || self.request_bearers.maximum_lifetime_seconds(),
            |timeout| {
                self.request_bearers
                    .maximum_lifetime_seconds()
                    .min(u64::from(timeout))
            },
        );
        if maximum_lifetime_seconds == 0 {
            return Err(ControlPortError::Corrupt);
        }
        let maximum_expires_at_seconds = issued_at_seconds
            .checked_add(maximum_lifetime_seconds)
            .ok_or(ControlPortError::Corrupt)?;
        Ok((issued_at_seconds, maximum_expires_at_seconds))
    }
}

impl fmt::Debug for WorkloadOidcRuntimeAuthorityIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkloadOidcRuntimeAuthorityIssuer")
            .field("provisioner", &"[GITHUB OIDC AUTHORITY PROVISIONER]")
            .field("authority_ids", &"[GITHUB OIDC AUTHORITY ID GENERATOR]")
            .field("request_bearers", &self.request_bearers)
            .field("issuer", &self.issuer)
            .field("endpoint", &self.endpoint)
            .field("name", &self.name)
            .finish()
    }
}

#[async_trait]
impl OptionalRuntimeAuthorityIssuer for WorkloadOidcRuntimeAuthorityIssuer {
    async fn issue_optional(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<Option<JobRuntimeAuthorities>, ControlPortError> {
        if !workload_oidc_is_permitted(request) {
            return Ok(None);
        }

        let (issued_at_seconds, maximum_expires_at_seconds) = self.maximum_interval(request)?;
        let issued_at = seconds_to_unix_millis(issued_at_seconds)?;
        seconds_to_unix_millis(maximum_expires_at_seconds)?;
        let proposed_authority_id = self.authority_ids.next_workload_oidc_authority_id();
        let proposed_request_bearer_key_id = self.request_bearers.active_key_id().clone();
        let proposed_request_bearer_sha256 = {
            let proposed_bearer = self
                .request_bearers
                .issue_with_key_id(
                    &proposed_request_bearer_key_id,
                    proposed_authority_id,
                    issued_at_seconds,
                    maximum_expires_at_seconds,
                )
                .map_err(|_| ControlPortError::Corrupt)?;
            bearer_digest(&proposed_bearer)
        };
        let reserve = ReserveWorkloadOidcRuntimeAuthority::new(
            request,
            proposed_authority_id,
            proposed_request_bearer_key_id,
            issued_at_seconds,
            maximum_expires_at_seconds,
            proposed_request_bearer_sha256,
        );
        let reserved = self
            .provisioner
            .reserve_workload_oidc_runtime_authority(reserve)
            .await?;
        if reserved.issued_at_seconds() != issued_at_seconds
            || reserved.expires_at_seconds() <= issued_at_seconds
            || reserved.expires_at_seconds() > maximum_expires_at_seconds
            || !self
                .request_bearers
                .contains_key(reserved.request_bearer_key_id())
        {
            return Err(ControlPortError::Corrupt);
        }

        let bearer = self
            .request_bearers
            .issue_with_key_id(
                reserved.request_bearer_key_id(),
                reserved.authority_id(),
                reserved.issued_at_seconds(),
                reserved.expires_at_seconds(),
            )
            .map_err(|_| ControlPortError::Corrupt)?;
        let generated_digest = bearer_digest(&bearer);
        if !bool::from(
            generated_digest
                .as_bytes()
                .ct_eq(reserved.request_bearer_sha256().as_bytes()),
        ) {
            return Err(ControlPortError::Corrupt);
        }
        let expires_at = seconds_to_unix_millis(reserved.expires_at_seconds())?;
        let job = request.job();
        let lease = request.lease();
        let authority = JobRuntimeAuthority::new(
            self.name.clone(),
            job.job().run_id(),
            job.job().job_id(),
            lease.attempt_id(),
            lease.fencing_token(),
            self.endpoint.clone(),
            RuntimeAuthorityCredential::new(bearer.expose_secret().to_owned())
                .map_err(|_| ControlPortError::Corrupt)?,
            issued_at,
            expires_at,
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        JobRuntimeAuthorities::new(
            vec![authority],
            automata_ci_core::SandboxAuthorizations::empty(),
            job,
            lease,
        )
        .map(Some)
        .map_err(|_| ControlPortError::Corrupt)
    }
}

fn workload_oidc_is_permitted(request: RuntimeAuthorityIssueRequest<'_>) -> bool {
    let job = request.job();
    if job.source().provider() != GITHUB_PROVIDER {
        return false;
    }
    if job.job().trust_snapshot().authority().oidc()
        != automata_ci_core::TrustOidcAuthority::Eligible
    {
        return false;
    }
    job.job()
        .permission_request()
        .requested_level(ID_TOKEN_PERMISSION)
        == Some(PermissionLevel::Write)
}

fn seconds_to_unix_millis(seconds: u64) -> Result<UnixMillis, ControlPortError> {
    let milliseconds = seconds
        .checked_mul(1_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(ControlPortError::Corrupt)?;
    Ok(UnixMillis::new(milliseconds))
}

fn bearer_digest(bearer: &automata_ci_workload_oidc::OidcRequestBearer) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bearer.expose_secret().as_bytes()).into())
}
