//! Short-lived, job-bound authorities delivered with an exact lease offer.

use std::{fmt, sync::Arc};

use automata_ci_auth::secret::SecretString;
use automata_ci_core::{
    AttemptId, FencingToken, JobAuthorityProfile, JobId, JobIrEnvelope, Lease, RunId,
    TrustPermissionAuthority, UnixMillis,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use url::{Host, Url};

/// Schema of the protected runtime-authority bundle.
pub const RUNTIME_AUTHORITY_SCHEMA_VERSION: u16 = 1;
/// Maximum number of independent authorities carried by one job.
pub const MAX_RUNTIME_AUTHORITIES: usize = 16;
/// Maximum UTF-8 bytes in one authority name.
pub const MAX_RUNTIME_AUTHORITY_NAME_BYTES: usize = 64;
/// Maximum UTF-8 bytes in one authority endpoint.
pub const MAX_RUNTIME_AUTHORITY_ENDPOINT_BYTES: usize = 2_048;
/// Maximum bytes in one opaque bearer credential.
pub const MAX_RUNTIME_AUTHORITY_CREDENTIAL_BYTES: usize = 16 * 1_024;

/// Stable adapter-selected runtime-authority namespace.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct RuntimeAuthorityName(String);

impl RuntimeAuthorityName {
    /// Validates a lower-case, portable adapter namespace.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, path-like, or non-canonical names.
    pub fn new(value: impl Into<String>) -> Result<Self, RuntimeAuthorityError> {
        let value = value.into();
        let mut bytes = value.bytes();
        let valid_first = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
        let valid_rest = bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        });
        if value.len() <= MAX_RUNTIME_AUTHORITY_NAME_BYTES && valid_first && valid_rest {
            Ok(Self(value))
        } else {
            Err(RuntimeAuthorityError::InvalidName)
        }
    }

    /// Returns the canonical authority namespace.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<RuntimeAuthorityName> for String {
    fn from(value: RuntimeAuthorityName) -> Self {
        value.0
    }
}

impl TryFrom<String> for RuntimeAuthorityName {
    type Error = RuntimeAuthorityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Transport policy explicitly selected for a runtime-authority endpoint.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAuthorityEndpointSecurity {
    /// Production endpoint protected by TLS.
    Tls,
    /// Plaintext endpoint confined to a host loopback interface.
    LoopbackDevelopment,
    /// Plaintext endpoint on an explicitly trusted private development link.
    TrustedPrivateDevelopment,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeAuthorityEndpointDocument {
    url: String,
    security: RuntimeAuthorityEndpointSecurity,
}

/// Validated public endpoint exposed to a sandboxed job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAuthorityEndpoint {
    url: Url,
    security: RuntimeAuthorityEndpointSecurity,
}

impl RuntimeAuthorityEndpoint {
    /// Validates a production HTTPS origin.
    ///
    /// # Errors
    ///
    /// Rejects credentials, queries, fragments, non-root paths, unsafe
    /// schemes, and oversized endpoints.
    pub fn new(value: impl AsRef<str>) -> Result<Self, RuntimeAuthorityError> {
        Self::parse(value.as_ref(), RuntimeAuthorityEndpointSecurity::Tls)
    }

    /// Validates an HTTP origin confined to literal loopback, `localhost`, or
    /// a `.localhost` name for explicit local development.
    ///
    /// # Errors
    ///
    /// Rejects non-loopback hosts and every malformed endpoint.
    pub fn loopback_development(value: impl AsRef<str>) -> Result<Self, RuntimeAuthorityError> {
        Self::parse(
            value.as_ref(),
            RuntimeAuthorityEndpointSecurity::LoopbackDevelopment,
        )
    }

    /// Validates an HTTP origin whose private host/bind relationship was
    /// explicitly approved by the server's development configuration.
    ///
    /// This constructor is a wire-level trust marker. The Results adapter must
    /// validate the exact non-wildcard private listener and public host before
    /// selecting it.
    ///
    /// # Errors
    ///
    /// Rejects loopback aliases, IP-literal public hosts, and malformed URLs.
    pub fn trusted_private_development(
        value: impl AsRef<str>,
    ) -> Result<Self, RuntimeAuthorityError> {
        Self::parse(
            value.as_ref(),
            RuntimeAuthorityEndpointSecurity::TrustedPrivateDevelopment,
        )
    }

    fn parse(
        value: &str,
        security: RuntimeAuthorityEndpointSecurity,
    ) -> Result<Self, RuntimeAuthorityError> {
        if value.is_empty()
            || value.len() > MAX_RUNTIME_AUTHORITY_ENDPOINT_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(RuntimeAuthorityError::InvalidEndpoint);
        }
        let endpoint = Url::parse(value).map_err(|_| RuntimeAuthorityError::InvalidEndpoint)?;
        if endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            return Err(RuntimeAuthorityError::InvalidEndpoint);
        }
        let host = endpoint
            .host()
            .ok_or(RuntimeAuthorityError::InvalidEndpoint)?;
        let loopback_host = match &host {
            Host::Domain(host) => *host == "localhost" || host.ends_with(".localhost"),
            Host::Ipv4(address) => address.is_loopback(),
            Host::Ipv6(address) => address.is_loopback(),
        };
        let trusted_private_host = match &host {
            // The Results server configuration explicitly binds a canonical
            // domain to its private listener before selecting this wire mode.
            Host::Domain(_) => !loopback_host,
            Host::Ipv4(address) => address.is_private() || address.is_link_local(),
            Host::Ipv6(address) => address.is_unique_local() || address.is_unicast_link_local(),
        };
        match security {
            RuntimeAuthorityEndpointSecurity::Tls if endpoint.scheme() != "https" => {
                return Err(RuntimeAuthorityError::InvalidEndpoint);
            }
            RuntimeAuthorityEndpointSecurity::LoopbackDevelopment
                if endpoint.scheme() != "http" || !loopback_host =>
            {
                return Err(RuntimeAuthorityError::InvalidEndpoint);
            }
            RuntimeAuthorityEndpointSecurity::TrustedPrivateDevelopment
                if endpoint.scheme() != "http" || !trusted_private_host =>
            {
                return Err(RuntimeAuthorityError::InvalidEndpoint);
            }
            _ => {}
        }
        Ok(Self {
            url: endpoint,
            security,
        })
    }

    /// Returns the normalized endpoint URL.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.url
    }

    /// Returns the normalized endpoint text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// Returns the explicit transport-security policy carried on the wire.
    #[must_use]
    pub const fn security(&self) -> RuntimeAuthorityEndpointSecurity {
        self.security
    }
}

impl Serialize for RuntimeAuthorityEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        RuntimeAuthorityEndpointDocument {
            url: self.as_str().to_owned(),
            security: self.security,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RuntimeAuthorityEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let document = RuntimeAuthorityEndpointDocument::deserialize(deserializer)?;
        Self::parse(&document.url, document.security).map_err(serde::de::Error::custom)
    }
}

/// Redacted, cloneable bearer credential with one zeroized backing allocation.
///
/// Serialization is intentional: this credential must cross the authenticated
/// runner transport and protected local spool. Debug and display surfaces
/// never expose it.
#[derive(Clone)]
pub struct RuntimeAuthorityCredential(Arc<SecretString>);

impl RuntimeAuthorityCredential {
    /// Creates a bounded, non-whitespace opaque credential.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or whitespace-containing material.
    pub fn new(value: impl Into<String>) -> Result<Self, RuntimeAuthorityError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_RUNTIME_AUTHORITY_CREDENTIAL_BYTES
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(RuntimeAuthorityError::InvalidCredential);
        }
        let secret =
            SecretString::new(value).map_err(|_| RuntimeAuthorityError::InvalidCredential)?;
        Ok(Self(Arc::new(secret)))
    }

    /// Explicitly exposes the credential at a transport or process boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }

    /// Shares the same zeroized allocation with a process-environment value.
    #[must_use]
    pub fn shared_secret(&self) -> Arc<SecretString> {
        Arc::clone(&self.0)
    }
}

impl fmt::Debug for RuntimeAuthorityCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeAuthorityCredential([REDACTED])")
    }
}

impl PartialEq for RuntimeAuthorityCredential {
    fn eq(&self, other: &Self) -> bool {
        self.0.constant_time_eq(other.expose_secret())
    }
}

impl Eq for RuntimeAuthorityCredential {}

impl Serialize for RuntimeAuthorityCredential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.expose_secret())
    }
}

impl<'de> Deserialize<'de> for RuntimeAuthorityCredential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// One adapter-owned authority bound to an exact workflow execution fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobRuntimeAuthority {
    name: RuntimeAuthorityName,
    run_id: RunId,
    job_id: JobId,
    attempt_id: AttemptId,
    fencing_token: FencingToken,
    endpoint: RuntimeAuthorityEndpoint,
    credential: RuntimeAuthorityCredential,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

impl JobRuntimeAuthority {
    /// Creates one validated, execution-bound runtime authority.
    ///
    /// # Errors
    ///
    /// Rejects negative timestamps and empty or inverted validity intervals.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: RuntimeAuthorityName,
        run_id: RunId,
        job_id: JobId,
        attempt_id: AttemptId,
        fencing_token: FencingToken,
        endpoint: RuntimeAuthorityEndpoint,
        credential: RuntimeAuthorityCredential,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, RuntimeAuthorityError> {
        if issued_at.get() < 0 || expires_at <= issued_at {
            return Err(RuntimeAuthorityError::InvalidInterval);
        }
        Ok(Self {
            name,
            run_id,
            job_id,
            attempt_id,
            fencing_token,
            endpoint,
            credential,
            issued_at,
            expires_at,
        })
    }

    /// Returns the stable adapter namespace.
    #[must_use]
    pub const fn name(&self) -> &RuntimeAuthorityName {
        &self.name
    }

    /// Returns the workflow-run backend identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the workflow-job backend identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns the exact execution attempt.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the lease fence captured during issuance.
    #[must_use]
    pub const fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }

    /// Returns the public service endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &RuntimeAuthorityEndpoint {
        &self.endpoint
    }

    /// Returns the redacted bearer credential.
    #[must_use]
    pub const fn credential(&self) -> &RuntimeAuthorityCredential {
        &self.credential
    }

    /// Returns the inclusive issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }

    /// Returns the exclusive expiry boundary.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }

    /// Validates the authority against the exact `JobIR` and lease envelope.
    ///
    /// # Errors
    ///
    /// Rejects cross-run, cross-job, cross-attempt, or stale-fence delivery.
    pub fn validate_for(
        &self,
        job: &JobIrEnvelope,
        lease: &Lease,
    ) -> Result<(), RuntimeAuthorityError> {
        if self.run_id != job.job().run_id()
            || self.job_id != job.job().job_id()
            || self.attempt_id != lease.attempt_id()
            || self.fencing_token != lease.fencing_token()
        {
            return Err(RuntimeAuthorityError::ExecutionBindingMismatch);
        }
        if self.issued_at.get() < 0 || self.expires_at <= self.issued_at {
            return Err(RuntimeAuthorityError::InvalidInterval);
        }
        Ok(())
    }
}

/// Canonically ordered authorities stored as one protected runner object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobRuntimeAuthorities {
    schema_version: u16,
    authorities: Vec<JobRuntimeAuthority>,
}

impl JobRuntimeAuthorities {
    /// Creates a canonical authority bundle matching the job's immutable profile.
    ///
    /// # Errors
    ///
    /// Standard jobs require at least one authority unless their sealed trust
    /// snapshot denies every provider permission. Credential-free and such
    /// fail-closed jobs require an empty bundle. Oversized, duplicate, unsorted,
    /// or execution-mismatched material is rejected in every case.
    pub fn new(
        authorities: Vec<JobRuntimeAuthority>,
        job: &JobIrEnvelope,
        lease: &Lease,
    ) -> Result<Self, RuntimeAuthorityError> {
        let bundle = Self {
            schema_version: RUNTIME_AUTHORITY_SCHEMA_VERSION,
            authorities,
        };
        bundle.validate_for(job, lease)?;
        Ok(bundle)
    }

    /// Returns the protected-content schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns authorities in canonical name order.
    #[must_use]
    pub fn as_slice(&self) -> &[JobRuntimeAuthority] {
        &self.authorities
    }

    /// Finds one exact adapter namespace.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&JobRuntimeAuthority> {
        self.authorities
            .binary_search_by(|authority| authority.name().as_str().cmp(name))
            .ok()
            .map(|index| &self.authorities[index])
    }

    /// Validates schema, canonical order, bounds, and execution binding.
    ///
    /// # Errors
    ///
    /// Returns a typed invariant failure before acceptance or execution.
    pub fn validate_for(
        &self,
        job: &JobIrEnvelope,
        lease: &Lease,
    ) -> Result<(), RuntimeAuthorityError> {
        if self.schema_version != RUNTIME_AUTHORITY_SCHEMA_VERSION {
            return Err(RuntimeAuthorityError::UnsupportedSchema);
        }
        if self.authorities.len() > MAX_RUNTIME_AUTHORITIES {
            return Err(RuntimeAuthorityError::InvalidCount);
        }
        let trust_denies_all = !job.job().trust_snapshot().is_construction_placeholder()
            && job.job().trust_snapshot().authority().permissions()
                == TrustPermissionAuthority::DenyAll;
        match job.job().authority_profile() {
            JobAuthorityProfile::Standard if self.authorities.is_empty() && !trust_denies_all => {
                return Err(RuntimeAuthorityError::AuthorityProfileMismatch);
            }
            JobAuthorityProfile::Standard if !self.authorities.is_empty() && trust_denies_all => {
                return Err(RuntimeAuthorityError::AuthorityProfileMismatch);
            }
            JobAuthorityProfile::CredentialFree if !self.authorities.is_empty() => {
                return Err(RuntimeAuthorityError::AuthorityProfileMismatch);
            }
            JobAuthorityProfile::Standard | JobAuthorityProfile::CredentialFree => {}
        }
        let mut previous: Option<&RuntimeAuthorityName> = None;
        for authority in &self.authorities {
            if previous.is_some_and(|name| name >= authority.name()) {
                return Err(RuntimeAuthorityError::NonCanonicalOrder);
            }
            authority.validate_for(job, lease)?;
            previous = Some(authority.name());
        }
        Ok(())
    }
}

/// Invalid runtime-authority material or delivery binding.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RuntimeAuthorityError {
    /// Adapter namespace is not canonical or exceeds its bound.
    #[error("runtime authority name is invalid")]
    InvalidName,
    /// Endpoint is unsafe, malformed, or exceeds its bound.
    #[error("runtime authority endpoint is invalid")]
    InvalidEndpoint,
    /// Credential is empty, oversized, or contains whitespace.
    #[error("runtime authority credential is invalid")]
    InvalidCredential,
    /// Issuance and expiry timestamps are incoherent.
    #[error("runtime authority validity interval is invalid")]
    InvalidInterval,
    /// Protected authority schema is unsupported.
    #[error("runtime authority schema is unsupported")]
    UnsupportedSchema,
    /// Bundle is empty or exceeds the hard authority-count limit.
    #[error("runtime authority count is invalid")]
    InvalidCount,
    /// The bundle's emptiness disagreed with the immutable `JobIR` authority profile.
    #[error("runtime authority bundle disagrees with the job authority profile")]
    AuthorityProfileMismatch,
    /// Authorities are not strictly ordered by unique name.
    #[error("runtime authorities are not in canonical order")]
    NonCanonicalOrder,
    /// Cleartext delivery binding contradicts `JobIR` or lease identity.
    #[error("runtime authority execution binding does not match the lease offer")]
    ExecutionBindingMismatch,
}
