//! Purpose-separated control and lease-bound workload credential contracts.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    num::NonZeroU64,
    pin::Pin,
};

use automata_ci_core::{JobId, Lease, PermissionLevel, Sha256Digest, TrustSourceClass, UnixMillis};
use automata_ci_secret::SecretValue;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ExternalCredentialId, ExternalRepositoryIdentity, ProviderConnectionId,
    ProviderConnectionManifest, ProviderConnectionRevision, ProviderControlCredentialId,
    ProviderControlCredentialWorkerId, ProviderLifecycleState, ProviderWorkloadCredentialId,
    WorkloadCredentialProfile, WorkloadCredentialRevocation,
};

/// Maximum operations in one least-privilege control credential.
pub const MAX_PROVIDER_CONTROL_OPERATIONS: usize = 32;
/// Maximum requested validity for a control credential.
pub const MAX_CONTROL_CREDENTIAL_VALIDITY_MILLIS: u64 = 24 * 60 * 60 * 1_000;
/// Maximum permission grants in one workload credential.
pub const MAX_WORKLOAD_PERMISSIONS: usize = 64;
/// Maximum bytes in one canonical workload permission name.
pub const MAX_WORKLOAD_PERMISSION_NAME_BYTES: usize = 64;
/// Maximum custody lifetime of one workload credential.
pub const MAX_WORKLOAD_CREDENTIAL_VALIDITY_MILLIS: u64 = 60 * 60 * 1_000;
/// Maximum provider guidance accepted for a workload credential retry.
pub const MAX_WORKLOAD_CREDENTIAL_RETRY_MILLIS: u64 = 24 * 60 * 60 * 1_000;

const CONTROL_REQUEST_DOMAIN: &[u8] = b"automata.provider.control-credential-request.v1\0";
const WORKLOAD_CREDENTIAL_ID_DOMAIN: &[u8] = b"automata.provider.workload-credential-id.v1\0";
const WORKLOAD_REQUEST_DOMAIN: &[u8] = b"automata.provider.workload-credential-request.v1\0";

/// Provider API operation requested by an application service.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProviderControlOperation {
    /// Resolve exact repository and commit metadata.
    RepositoryRead,
    /// Read changed-file evidence for one commit range.
    CommitChangedFilesRead,
    /// Read changed-file evidence for one merge request.
    MergeRequestChangedFilesRead,
    /// Publish provider result state.
    ResultWrite,
    /// Read provider result state for reconciliation.
    ResultRead,
    /// Resolve provider-native result container state.
    ResultResolve,
    /// Create one deterministically identified provider result.
    ResultCreate,
    /// Reconcile a result creation whose outcome is uncertain.
    ResultReconcile,
    /// Install, rotate, or remove provider webhooks.
    WebhookManage,
    /// Read provider-native schedule state.
    ScheduleRead,
    /// Emit an authenticated provider-native dispatch.
    DispatchWrite,
    /// Read effective repository workflow-token permission defaults.
    WorkflowPermissionRead,
    /// Read human organization or team membership evidence.
    MembershipRead,
    /// Create, reconcile, or revoke workload credentials.
    WorkloadCredentialManage,
}

/// Nonempty canonical operation set for one control credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderControlOperationSet(BTreeSet<ProviderControlOperation>);

impl ProviderControlOperationSet {
    /// Creates a nonempty bounded operation set.
    ///
    /// # Errors
    ///
    /// Rejects empty or excessive sets.
    pub fn new(
        operations: impl IntoIterator<Item = ProviderControlOperation>,
    ) -> Result<Self, ProviderCredentialModelError> {
        let operations = operations.into_iter().collect::<BTreeSet<_>>();
        if operations.is_empty() || operations.len() > MAX_PROVIDER_CONTROL_OPERATIONS {
            return Err(ProviderCredentialModelError::InvalidControlOperations);
        }
        Ok(Self(operations))
    }

    /// Returns whether the credential permits one exact operation.
    #[must_use]
    pub fn contains(&self, operation: ProviderControlOperation) -> bool {
        self.0.contains(&operation)
    }

    /// Iterates in canonical operation order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = ProviderControlOperation> + '_ {
        self.0.iter().copied()
    }
}

/// Provider-side origin of a control credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlCredentialStrategy {
    /// The adapter mints or refreshes a short-lived credential.
    Minted,
    /// The adapter resolves an encrypted operator-provisioned credential.
    Stored,
}

/// Provider-side invalidation behavior of a control credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlCredentialRevocation {
    /// The provider enforces the reported expiry.
    ProviderExpiry,
    /// The provider supports explicit credential revocation.
    Explicit,
    /// Replacing the configured secret generation invalidates this credential.
    ConfigurationRotation,
}

/// Positive durable credential generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderCredentialGeneration(NonZeroU64);

impl ProviderCredentialGeneration {
    /// Creates a positive generation representable by durable signed storage.
    ///
    /// # Errors
    ///
    /// Rejects zero and values beyond `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, ProviderCredentialModelError> {
        NonZeroU64::new(value)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .map(Self)
            .ok_or(ProviderCredentialModelError::InvalidGeneration)
    }

    /// Returns the positive generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Exact least-privilege control credential acquisition request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlCredentialRequest {
    claim: ControlCredentialClaim,
    connection: ProviderConnectionManifest,
    operations: ProviderControlOperationSet,
    requested_at: UnixMillis,
    minimum_validity_millis: u64,
    digest: Sha256Digest,
}

/// Exact durable claim authorizing one control-credential acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlCredentialClaim {
    credential_id: ProviderControlCredentialId,
    worker_id: ProviderControlCredentialWorkerId,
    fence: u64,
    revision: u64,
    expires_at: UnixMillis,
}

impl ControlCredentialClaim {
    /// Creates a live positive-fence acquisition claim.
    ///
    /// # Errors
    ///
    /// Rejects zero fences or revisions and non-positive expiry timestamps.
    pub fn new(
        credential_id: ProviderControlCredentialId,
        worker_id: ProviderControlCredentialWorkerId,
        fence: u64,
        revision: u64,
        expires_at: UnixMillis,
    ) -> Result<Self, ProviderCredentialModelError> {
        if fence == 0
            || revision == 0
            || fence > i64::MAX.cast_unsigned()
            || revision > i64::MAX.cast_unsigned()
            || expires_at.get() <= 0
        {
            return Err(ProviderCredentialModelError::InvalidControlClaim);
        }
        Ok(Self {
            credential_id,
            worker_id,
            fence,
            revision,
            expires_at,
        })
    }

    /// Returns the durable acquisition identity.
    #[must_use]
    pub const fn credential_id(self) -> ProviderControlCredentialId {
        self.credential_id
    }

    /// Returns the exact claiming worker.
    #[must_use]
    pub const fn worker_id(self) -> ProviderControlCredentialWorkerId {
        self.worker_id
    }

    /// Returns the current claim fence.
    #[must_use]
    pub const fn fence(self) -> u64 {
        self.fence
    }

    /// Returns the purpose-specific durable revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Returns the exclusive claim expiry.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

impl ControlCredentialRequest {
    /// Creates one request under an active exact connection revision.
    ///
    /// # Errors
    ///
    /// Rejects inactive connections, invalid timestamps, or invalid validity bounds.
    pub fn new(
        claim: ControlCredentialClaim,
        connection: &ProviderConnectionManifest,
        operations: ProviderControlOperationSet,
        requested_at: UnixMillis,
        minimum_validity_millis: u64,
    ) -> Result<Self, ProviderCredentialModelError> {
        if connection.state() != ProviderLifecycleState::Active {
            return Err(ProviderCredentialModelError::InactiveConnection);
        }
        let required_until = requested_at
            .get()
            .checked_add(minimum_validity_millis.cast_signed());
        if requested_at.get() < 0
            || minimum_validity_millis == 0
            || minimum_validity_millis > MAX_CONTROL_CREDENTIAL_VALIDITY_MILLIS
            || required_until.is_none()
            || requested_at >= claim.expires_at()
            || required_until
                .is_some_and(|required_until| required_until < claim.expires_at().get())
        {
            return Err(ProviderCredentialModelError::InvalidValidity);
        }
        let mut value = Self {
            claim,
            connection: connection.clone(),
            operations,
            requested_at,
            minimum_validity_millis,
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        value.digest = value.calculate_digest();
        Ok(value)
    }

    fn calculate_digest(&self) -> Sha256Digest {
        let mut hash = Sha256::new();
        hash.update(CONTROL_REQUEST_DOMAIN);
        hash.update(self.claim.credential_id.as_uuid().as_bytes());
        hash.update(self.claim.worker_id.as_uuid().as_bytes());
        hash.update(self.claim.fence.to_be_bytes());
        hash.update(self.claim.revision.to_be_bytes());
        hash.update(self.claim.expires_at.get().to_be_bytes());
        hash.update(self.connection.connection_id().as_uuid().as_bytes());
        hash.update(self.connection.revision().get().to_be_bytes());
        hash.update(self.connection.digest().as_bytes());
        hash.update(
            self.connection
                .configuration()
                .repository()
                .instance_id()
                .as_uuid()
                .as_bytes(),
        );
        part(
            &mut hash,
            self.connection
                .configuration()
                .repository()
                .external_id()
                .as_str()
                .as_bytes(),
        );
        for operation in self.operations.iter() {
            hash.update([control_operation_code(operation)]);
        }
        hash.update(self.requested_at.get().to_be_bytes());
        hash.update(self.minimum_validity_millis.to_be_bytes());
        Sha256Digest::from_bytes(hash.finalize().into())
    }

    /// Returns the acquisition identity.
    #[must_use]
    pub const fn credential_id(&self) -> ProviderControlCredentialId {
        self.claim.credential_id()
    }
    /// Returns the exact durable acquisition claim.
    #[must_use]
    pub const fn claim(&self) -> ControlCredentialClaim {
        self.claim
    }
    /// Returns the complete secret-free connection manifest for provider validation.
    #[must_use]
    pub const fn connection(&self) -> &ProviderConnectionManifest {
        &self.connection
    }
    /// Returns the exact connection.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection.connection_id()
    }
    /// Returns the exact connection revision.
    #[must_use]
    pub const fn connection_revision(&self) -> ProviderConnectionRevision {
        self.connection.revision()
    }
    /// Returns the connection digest.
    #[must_use]
    pub const fn connection_digest(&self) -> Sha256Digest {
        self.connection.digest()
    }
    /// Returns the exact repository audience.
    #[must_use]
    pub const fn repository(&self) -> &ExternalRepositoryIdentity {
        self.connection.configuration().repository()
    }
    /// Returns the requested operation set.
    #[must_use]
    pub const fn operations(&self) -> &ProviderControlOperationSet {
        &self.operations
    }
    /// Returns the trusted request time.
    #[must_use]
    pub const fn requested_at(&self) -> UnixMillis {
        self.requested_at
    }
    /// Returns the required remaining validity.
    #[must_use]
    pub const fn minimum_validity_millis(&self) -> u64 {
        self.minimum_validity_millis
    }
    /// Returns the canonical request digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Secret-bearing control credential bound to one exact request.
pub struct ControlCredential {
    request_digest: Sha256Digest,
    operations: ProviderControlOperationSet,
    strategy: ControlCredentialStrategy,
    generation: ProviderCredentialGeneration,
    value: SecretValue,
    issued_at: UnixMillis,
    expires_at: Option<UnixMillis>,
    revocation: ControlCredentialRevocation,
    release: Box<dyn ControlCredentialRelease>,
}

impl ControlCredential {
    /// Binds secret material and provider lifecycle evidence to a request.
    ///
    /// # Errors
    ///
    /// Rejects mismatched operations or insufficient remaining validity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &ControlCredentialRequest,
        operations: ProviderControlOperationSet,
        strategy: ControlCredentialStrategy,
        generation: ProviderCredentialGeneration,
        value: SecretValue,
        issued_at: UnixMillis,
        expires_at: Option<UnixMillis>,
        revocation: ControlCredentialRevocation,
        release: Box<dyn ControlCredentialRelease>,
    ) -> Result<Self, ProviderCredentialModelError> {
        if operations != request.operations || issued_at.get() < 0 {
            drop(value);
            drop(release);
            return Err(ProviderCredentialModelError::InvalidCredentialBinding);
        }
        let required_until =
            request.requested_at.get() + request.minimum_validity_millis.cast_signed();
        if expires_at.is_some_and(|expires_at| {
            expires_at.get() <= issued_at.get() || expires_at.get() < required_until
        }) || (strategy == ControlCredentialStrategy::Minted
            && revocation == ControlCredentialRevocation::ConfigurationRotation)
            || (strategy == ControlCredentialStrategy::Stored
                && revocation == ControlCredentialRevocation::ProviderExpiry)
        {
            drop(value);
            drop(release);
            return Err(ProviderCredentialModelError::InvalidValidity);
        }
        Ok(Self {
            request_digest: request.digest,
            operations,
            strategy,
            generation,
            value,
            issued_at,
            expires_at,
            revocation,
            release,
        })
    }

    /// Returns the request digest this credential satisfies.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }
    /// Returns whether one exact operation is logically permitted.
    #[must_use]
    pub fn permits(&self, operation: ProviderControlOperation) -> bool {
        self.operations.contains(operation)
    }
    /// Returns the acquisition strategy.
    #[must_use]
    pub const fn strategy(&self) -> ControlCredentialStrategy {
        self.strategy
    }
    /// Returns the source credential generation.
    #[must_use]
    pub const fn generation(&self) -> ProviderCredentialGeneration {
        self.generation
    }
    /// Exposes secret bytes only at the provider HTTP boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.value.expose_secret()
    }
    /// Destroys secret custody and relinquishes the exact acquisition.
    ///
    /// Provider implementations supervise cleanup that cannot finish before
    /// the returned future resolves, so callers never retain provider-specific
    /// release identities or retry policy.
    #[must_use = "the credential release future must be awaited"]
    pub fn release(self) -> ControlCredentialReleaseFuture {
        let Self { value, release, .. } = self;
        drop(value);
        release.release()
    }
    /// Returns provider issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }
    /// Returns provider expiry when available.
    #[must_use]
    pub const fn expires_at(&self) -> Option<UnixMillis> {
        self.expires_at
    }
    /// Returns the invalidation behavior.
    #[must_use]
    pub const fn revocation(&self) -> ControlCredentialRevocation {
        self.revocation
    }
}

impl fmt::Debug for ControlCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlCredential")
            .field("request_digest", &self.request_digest)
            .field("operations", &self.operations)
            .field("strategy", &self.strategy)
            .field("generation", &self.generation)
            .field("value", &"[REDACTED]")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("revocation", &self.revocation)
            .field("release", &"[PROVIDER CUSTODY RELEASE]")
            .finish()
    }
}

/// Future returned by control credential acquisition.
pub type ControlCredentialFuture<'a> = Pin<
    Box<dyn Future<Output = Result<ControlCredential, ControlCredentialProviderError>> + Send + 'a>,
>;

/// Future returned after relinquishing one control credential's local custody.
pub type ControlCredentialReleaseFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Provider-owned cleanup boundary retained by an acquired control credential.
///
/// Implementations must make release idempotent, arrange equivalent supervised
/// cleanup from `Drop` when a caller abandons the credential, and supervise any
/// cleanup that cannot finish before the returned future resolves. Secret
/// material is destroyed before this boundary is invoked.
pub trait ControlCredentialRelease: fmt::Debug + Send {
    /// Relinquishes the exact provider credential acquisition.
    fn release(self: Box<Self>) -> ControlCredentialReleaseFuture;
}

/// Narrow adapter port for operation-scoped provider API credentials.
pub trait ControlCredentialProvider: fmt::Debug + Send + Sync {
    /// Acquires a credential satisfying exactly one immutable request.
    fn acquire<'a>(&'a self, request: &'a ControlCredentialRequest) -> ControlCredentialFuture<'a>;
}

/// Sanitized control credential acquisition failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ControlCredentialProviderError {
    /// The adapter cannot grant every requested operation.
    #[error("control credential operations are unsupported")]
    Unsupported,
    /// Credential configuration is missing or rejected.
    #[error("control credential authentication failed")]
    Unauthorized,
    /// Credential authority is insufficient.
    #[error("control credential authorization failed")]
    Forbidden,
    /// Provider quota is temporarily exhausted.
    #[error("control credential provider is rate limited")]
    RateLimited,
    /// Provider or secret custody is temporarily unavailable.
    #[error("control credential provider is unavailable")]
    Unavailable,
    /// Minting may have committed and must be reconciled before another mutation.
    #[error("control credential provider outcome is indeterminate")]
    Indeterminate,
    /// Provider response violates the common contract.
    #[error("control credential provider response is invalid")]
    InvalidResponse,
}

/// Canonical provider permission and effective level for a workload credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPermission {
    name: String,
    level: PermissionLevel,
}

impl ProviderPermission {
    /// Creates one canonical non-denied provider permission.
    ///
    /// # Errors
    ///
    /// Rejects invalid names and explicit denied entries.
    pub fn new(
        name: impl Into<String>,
        level: PermissionLevel,
    ) -> Result<Self, ProviderCredentialModelError> {
        let name = name.into();
        if !valid_permission_name(&name) || level == PermissionLevel::None {
            return Err(ProviderCredentialModelError::InvalidWorkloadPermission);
        }
        Ok(Self { name, level })
    }
    /// Returns the canonical provider permission name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Returns the effective level.
    #[must_use]
    pub const fn level(&self) -> PermissionLevel {
        self.level
    }
}

/// Complete canonical effective permission set for one workload credential.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProviderPermissionSet(BTreeMap<String, PermissionLevel>);

impl ProviderPermissionSet {
    /// Creates a bounded duplicate-free permission set.
    ///
    /// # Errors
    ///
    /// Rejects duplicates or excessive grants. Empty is valid for checkout-only credentials.
    pub fn new(
        permissions: impl IntoIterator<Item = ProviderPermission>,
    ) -> Result<Self, ProviderCredentialModelError> {
        let mut values = BTreeMap::new();
        for permission in permissions {
            if values.len() >= MAX_WORKLOAD_PERMISSIONS
                || values.insert(permission.name, permission.level).is_some()
            {
                return Err(ProviderCredentialModelError::InvalidWorkloadPermission);
            }
        }
        Ok(Self(values))
    }
    /// Returns whether no provider permission is requested.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Returns the number of exact grants.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Iterates in canonical permission-name order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, PermissionLevel)> {
        self.0.iter().map(|(name, level)| (name.as_str(), *level))
    }
}

impl ProviderWorkloadCredentialId {
    /// Derives one stable RFC 9562 version-8 identity from exact issuance evidence.
    ///
    /// # Panics
    ///
    /// Panics only if a UUID carrying mandatory version and variant bits is
    /// classified as nil, which would indicate a UUID library invariant break.
    #[must_use]
    pub fn derive(connection: &ProviderConnectionManifest, job_id: JobId, lease: &Lease) -> Self {
        let mut hash = Sha256::new();
        hash.update(WORKLOAD_CREDENTIAL_ID_DOMAIN);
        hash.update(connection.connection_id().as_uuid().as_bytes());
        hash.update(connection.revision().get().to_be_bytes());
        hash.update(connection.digest().as_bytes());
        hash.update(job_id.as_uuid().as_bytes());
        hash.update(lease.attempt_id().as_uuid().as_bytes());
        hash.update(lease.lease_id().as_uuid().as_bytes());
        hash.update(lease.fencing_token().get().to_be_bytes());
        let digest = hash.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self::from_uuid(uuid::Uuid::from_bytes(bytes))
            .expect("a domain-separated version-8 workload credential ID is non-nil")
    }
}

/// Exact job, attempt, lease, trust, repository, and permission issuance request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadCredentialRequest {
    credential_id: ProviderWorkloadCredentialId,
    connection_id: ProviderConnectionId,
    connection_revision: ProviderConnectionRevision,
    connection_digest: Sha256Digest,
    repository: ExternalRepositoryIdentity,
    job_id: JobId,
    lease: Lease,
    trust_class: TrustSourceClass,
    profile: WorkloadCredentialProfile,
    permissions: ProviderPermissionSet,
    requested_at: UnixMillis,
    expires_at: UnixMillis,
    digest: Sha256Digest,
}

impl WorkloadCredentialRequest {
    /// Creates one exact bounded workload issuance request.
    ///
    /// # Errors
    ///
    /// Rejects inactive connections, malformed lease binding, excessive lifetime,
    /// or permissions inconsistent with the selected profile.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connection: &ProviderConnectionManifest,
        job_id: JobId,
        lease: Lease,
        trust_class: TrustSourceClass,
        profile: WorkloadCredentialProfile,
        permissions: ProviderPermissionSet,
        requested_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, ProviderCredentialModelError> {
        if connection.state() != ProviderLifecycleState::Active {
            return Err(ProviderCredentialModelError::InactiveConnection);
        }
        lease
            .validate()
            .map_err(|_| ProviderCredentialModelError::InvalidLease)?;
        let lifetime = expires_at
            .get()
            .checked_sub(requested_at.get())
            .filter(|value| *value > 0)
            .and_then(|value| u64::try_from(value).ok());
        if requested_at < lease.issued_at()
            || expires_at > lease.expires_at()
            || lifetime.is_none_or(|value| value > MAX_WORKLOAD_CREDENTIAL_VALIDITY_MILLIS)
        {
            return Err(ProviderCredentialModelError::InvalidValidity);
        }
        let has_write = permissions
            .iter()
            .any(|(_, level)| level == PermissionLevel::Write);
        match profile {
            WorkloadCredentialProfile::CheckoutRead if !permissions.is_empty() => {
                return Err(ProviderCredentialModelError::InvalidWorkloadPermission);
            }
            WorkloadCredentialProfile::RepositoryAccess
                if permissions.is_empty()
                    || (has_write && trust_class != TrustSourceClass::SameRepository) =>
            {
                return Err(ProviderCredentialModelError::InvalidWorkloadPermission);
            }
            WorkloadCredentialProfile::CheckoutRead
            | WorkloadCredentialProfile::RepositoryAccess => {}
        }
        let credential_id = ProviderWorkloadCredentialId::derive(connection, job_id, &lease);
        let mut value = Self {
            credential_id,
            connection_id: connection.connection_id(),
            connection_revision: connection.revision(),
            connection_digest: connection.digest(),
            repository: connection.configuration().repository().clone(),
            job_id,
            lease,
            trust_class,
            profile,
            permissions,
            requested_at,
            expires_at,
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        value.digest = value.calculate_digest();
        Ok(value)
    }

    fn calculate_digest(&self) -> Sha256Digest {
        let mut hash = Sha256::new();
        hash.update(WORKLOAD_REQUEST_DOMAIN);
        hash.update(self.credential_id.as_uuid().as_bytes());
        hash.update(self.connection_id.as_uuid().as_bytes());
        hash.update(self.connection_revision.get().to_be_bytes());
        hash.update(self.connection_digest.as_bytes());
        hash.update(self.repository.instance_id().as_uuid().as_bytes());
        part(&mut hash, self.repository.external_id().as_str().as_bytes());
        hash.update(self.job_id.as_uuid().as_bytes());
        hash.update(self.lease.attempt_id().as_uuid().as_bytes());
        hash.update(self.lease.lease_id().as_uuid().as_bytes());
        hash.update(self.lease.runner_id().as_uuid().as_bytes());
        hash.update(self.lease.fencing_token().get().to_be_bytes());
        hash.update(self.lease.issued_at().get().to_be_bytes());
        hash.update(self.lease.expires_at().get().to_be_bytes());
        hash.update([
            trust_class_code(self.trust_class),
            profile_code(self.profile),
        ]);
        for (name, level) in self.permissions.iter() {
            part(&mut hash, name.as_bytes());
            hash.update([permission_level_code(level)]);
        }
        hash.update(self.requested_at.get().to_be_bytes());
        hash.update(self.expires_at.get().to_be_bytes());
        Sha256Digest::from_bytes(hash.finalize().into())
    }

    /// Returns the workload credential identity.
    #[must_use]
    pub const fn credential_id(&self) -> ProviderWorkloadCredentialId {
        self.credential_id
    }
    /// Returns the exact provider connection.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }
    /// Returns the exact connection revision.
    #[must_use]
    pub const fn connection_revision(&self) -> ProviderConnectionRevision {
        self.connection_revision
    }
    /// Returns the exact connection digest.
    #[must_use]
    pub const fn connection_digest(&self) -> Sha256Digest {
        self.connection_digest
    }
    /// Returns the exact repository.
    #[must_use]
    pub const fn repository(&self) -> &ExternalRepositoryIdentity {
        &self.repository
    }
    /// Returns the exact job.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }
    /// Returns the exclusive runner lease.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }
    /// Returns the admission trust class.
    #[must_use]
    pub const fn trust_class(&self) -> TrustSourceClass {
        self.trust_class
    }
    /// Returns the requested common credential profile.
    #[must_use]
    pub const fn profile(&self) -> WorkloadCredentialProfile {
        self.profile
    }
    /// Returns the complete effective permission set.
    #[must_use]
    pub const fn permissions(&self) -> &ProviderPermissionSet {
        &self.permissions
    }
    /// Returns the issuance request time.
    #[must_use]
    pub const fn requested_at(&self) -> UnixMillis {
        self.requested_at
    }
    /// Returns the local custody deadline.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
    /// Returns the canonical request digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Validated non-secret evidence for one provider issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadCredentialIssuance {
    request_digest: Sha256Digest,
    external_id: Option<ExternalCredentialId>,
    issued_at: UnixMillis,
    provider_expires_at: Option<UnixMillis>,
    revocation: WorkloadCredentialRevocation,
}

impl WorkloadCredentialIssuance {
    /// Validates provider evidence against the exact immutable request.
    ///
    /// # Errors
    ///
    /// Rejects incoherent evidence before any recovered secret changes ownership.
    pub fn new(
        request: &WorkloadCredentialRequest,
        external_id: Option<ExternalCredentialId>,
        issued_at: UnixMillis,
        provider_expires_at: Option<UnixMillis>,
        revocation: WorkloadCredentialRevocation,
    ) -> Result<Self, ProviderCredentialModelError> {
        if issued_at < request.requested_at
            || issued_at >= request.expires_at
            || provider_expires_at.is_some_and(|expires_at| {
                expires_at <= issued_at || expires_at < request.expires_at
            })
            || (revocation == WorkloadCredentialRevocation::ProviderExpiry
                && provider_expires_at.is_none())
        {
            return Err(ProviderCredentialModelError::InvalidValidity);
        }
        Ok(Self {
            request_digest: request.digest,
            external_id,
            issued_at,
            provider_expires_at,
            revocation,
        })
    }
    /// Moves a recovered secret under already-validated issuance evidence.
    #[must_use]
    pub fn bind_secret(self, value: SecretValue) -> IssuedWorkloadCredential {
        IssuedWorkloadCredential {
            evidence: self,
            value,
        }
    }
    /// Returns the exact issuance request digest.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }
    /// Returns the provider-native credential identity when available.
    #[must_use]
    pub const fn external_id(&self) -> Option<&ExternalCredentialId> {
        self.external_id.as_ref()
    }
    /// Returns the provider issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }
    /// Returns the provider-enforced expiry when available.
    #[must_use]
    pub const fn provider_expires_at(&self) -> Option<UnixMillis> {
        self.provider_expires_at
    }
    /// Returns the provider invalidation mechanism.
    #[must_use]
    pub const fn revocation(&self) -> WorkloadCredentialRevocation {
        self.revocation
    }
}

/// Secret-bearing workload credential bound to validated issuance evidence.
pub struct IssuedWorkloadCredential {
    evidence: WorkloadCredentialIssuance,
    value: SecretValue,
}

impl IssuedWorkloadCredential {
    /// Returns the exact issuance request digest.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.evidence.request_digest()
    }
    /// Returns the provider-native credential identity when available.
    #[must_use]
    pub const fn external_id(&self) -> Option<&ExternalCredentialId> {
        self.evidence.external_id()
    }
    /// Exposes secret bytes only to encrypted custody or workload injection.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.value.expose_secret()
    }
    /// Consumes the issued workload credential into encrypted secret custody.
    #[must_use]
    pub fn into_secret(self) -> SecretValue {
        self.value
    }
    /// Returns the provider issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixMillis {
        self.evidence.issued_at()
    }
    /// Returns the provider-enforced expiry when available.
    #[must_use]
    pub const fn provider_expires_at(&self) -> Option<UnixMillis> {
        self.evidence.provider_expires_at()
    }
    /// Returns the provider invalidation mechanism.
    #[must_use]
    pub const fn revocation(&self) -> WorkloadCredentialRevocation {
        self.evidence.revocation()
    }

    /// Ends local use and returns the provider cleanup obligation, if any.
    pub fn retire(self) -> WorkloadCredentialRetirement {
        match self.evidence.revocation {
            WorkloadCredentialRevocation::ProviderExpiry => {
                WorkloadCredentialRetirement::ProviderExpiry
            }
            WorkloadCredentialRevocation::Explicit => {
                WorkloadCredentialRetirement::Revoke(WorkloadCredentialRevocationCandidate {
                    request_digest: self.evidence.request_digest,
                    external_id: self.evidence.external_id,
                    value: self.value,
                    provider_expires_at: self.evidence.provider_expires_at,
                })
            }
        }
    }
}

impl fmt::Debug for IssuedWorkloadCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedWorkloadCredential")
            .field("evidence", &self.evidence)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Provider cleanup required after local custody of an issued credential ends.
#[must_use]
#[derive(Debug)]
pub enum WorkloadCredentialRetirement {
    /// Provider-enforced expiry is the only cleanup mechanism.
    ProviderExpiry,
    /// The exact secret-bearing credential must be explicitly revoked.
    Revoke(WorkloadCredentialRevocationCandidate),
}

/// A uniquely recovered workload credential retained until revocation or expiry.
///
/// This value is move-only, redacted, and zeroized on drop. A durable lifecycle
/// coordinator must protect it before relinquishing memory ownership and must
/// retain it whenever a revocation attempt is not confirmed.
pub struct WorkloadCredentialRevocationCandidate {
    request_digest: Sha256Digest,
    external_id: Option<ExternalCredentialId>,
    value: SecretValue,
    provider_expires_at: Option<UnixMillis>,
}

impl WorkloadCredentialRevocationCandidate {
    /// Restores one exact cleanup obligation from protected durable custody.
    #[must_use]
    pub fn new(
        request_digest: Sha256Digest,
        external_id: Option<ExternalCredentialId>,
        value: SecretValue,
        provider_expires_at: Option<UnixMillis>,
    ) -> Self {
        Self {
            request_digest,
            external_id,
            value,
            provider_expires_at,
        }
    }
    /// Returns the exact issuance request digest.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }
    /// Returns provider identity learned from issuance, when available.
    #[must_use]
    pub const fn external_id(&self) -> Option<&ExternalCredentialId> {
        self.external_id.as_ref()
    }
    /// Explicitly exposes the bearer value to protected custody or revocation.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.value.expose_secret()
    }
    /// Consumes the candidate into protected durable secret custody.
    #[must_use]
    pub fn into_secret(self) -> SecretValue {
        self.value
    }
    /// Returns the provider-enforced expiration when it was recoverable.
    #[must_use]
    pub const fn provider_expires_at(&self) -> Option<UnixMillis> {
        self.provider_expires_at
    }
}

impl fmt::Debug for WorkloadCredentialRevocationCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkloadCredentialRevocationCandidate")
            .field("request_digest", &self.request_digest)
            .field("external_id", &self.external_id)
            .field("value", &"[REDACTED]")
            .field("provider_expires_at", &self.provider_expires_at)
            .finish()
    }
}

/// A recovered credential that failed validation and requires cleanup.
pub struct PendingWorkloadCredentialRevocation {
    candidate: WorkloadCredentialRevocationCandidate,
    reason: WorkloadCredentialProviderError,
}

impl PendingWorkloadCredentialRevocation {
    /// Creates a cleanup obligation for a recovered but unusable credential.
    #[must_use]
    pub const fn new(
        candidate: WorkloadCredentialRevocationCandidate,
        reason: WorkloadCredentialProviderError,
    ) -> Self {
        Self { candidate, reason }
    }
    /// Borrows the candidate that must be retained until cleanup is confirmed.
    #[must_use]
    pub const fn candidate(&self) -> &WorkloadCredentialRevocationCandidate {
        &self.candidate
    }
    /// Returns the sanitized reason the credential could not be issued.
    #[must_use]
    pub const fn reason(&self) -> WorkloadCredentialProviderError {
        self.reason
    }
    /// Consumes this state into its cleanup obligation.
    #[must_use]
    pub fn into_candidate(self) -> WorkloadCredentialRevocationCandidate {
        self.candidate
    }
}

impl fmt::Debug for PendingWorkloadCredentialRevocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingWorkloadCredentialRevocation")
            .field("candidate", &self.candidate)
            .field("reason", &self.reason)
            .finish()
    }
}

/// Why a provider mutation may have committed without a recoverable credential.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkloadCredentialIndeterminateReason {
    /// Transport failed after the request may have reached the provider.
    #[error("workload credential transport outcome is indeterminate")]
    Transport,
    /// The provider failed after accepting a side-effectful request.
    #[error("workload credential provider outcome is indeterminate")]
    ProviderUnavailable,
    /// A successful response exceeded the configured byte ceiling.
    #[error("workload credential response exceeded its byte limit")]
    ResponseTooLarge,
    /// A successful response ended before its body completed.
    #[error("workload credential response was truncated")]
    TruncatedResponse,
    /// A successful response could not be decoded safely.
    #[error("workload credential response was malformed")]
    MalformedResponse,
    /// A successful response contained no recoverable credential.
    #[error("workload credential response contained no credential")]
    MissingCredential,
    /// A successful response contained more than one possible credential.
    #[error("workload credential response contained ambiguous credentials")]
    AmbiguousCredential,
    /// The provider returned a status that proves neither creation nor rejection.
    #[error("workload credential response status was indeterminate")]
    UnexpectedStatus,
}

/// Provider-side issue outcome requiring durable operator reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndeterminateWorkloadCredential {
    reason: WorkloadCredentialIndeterminateReason,
}

impl IndeterminateWorkloadCredential {
    /// Creates an indeterminate issue result from a sanitized reason.
    #[must_use]
    pub const fn new(reason: WorkloadCredentialIndeterminateReason) -> Self {
        Self { reason }
    }
    /// Returns why this exact issuance must never be retried automatically.
    #[must_use]
    pub const fn reason(self) -> WorkloadCredentialIndeterminateReason {
        self.reason
    }
}

/// Complete outcome of exactly one provider-side workload credential issue attempt.
///
/// This enum is move-only and non-serializable. Every variant requires a
/// distinct durable lifecycle transition; in particular, callers must never
/// retry issuance after [`Self::Indeterminate`].
#[must_use]
#[derive(Debug)]
pub enum WorkloadCredentialIssueOutcome {
    /// One credential exactly satisfies the immutable request.
    Ready(IssuedWorkloadCredential),
    /// One credential was recovered but is unusable and must be revoked.
    RevokePending(PendingWorkloadCredentialRevocation),
    /// A credential may exist, but no unique secret could be recovered.
    Indeterminate(IndeterminateWorkloadCredential),
    /// The provider definitively rejected the request before creating a credential.
    Rejected(WorkloadCredentialProviderError),
}

/// Sanitized classification of an unconfirmed revocation attempt.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkloadCredentialRevocationFailureKind {
    /// Provider authentication failed without proving the credential absent.
    #[error("workload credential revocation authentication failed")]
    Unauthorized,
    /// Provider quota prevented revocation confirmation.
    #[error("workload credential revocation was rate limited")]
    RateLimited,
    /// Transport or provider availability prevented confirmation.
    #[error("workload credential revocation is unavailable")]
    Unavailable,
    /// Provider response did not confirm revocation.
    #[error("workload credential revocation response is invalid")]
    InvalidResponse,
}

/// An unconfirmed revocation failure with bounded provider retry guidance.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("workload credential revocation was not confirmed: {kind}")]
pub struct WorkloadCredentialRevocationFailure {
    kind: WorkloadCredentialRevocationFailureKind,
    retry_after: Option<WorkloadCredentialRetryAfter>,
}

impl WorkloadCredentialRevocationFailure {
    /// Creates a sanitized failure without provider retry guidance.
    #[must_use]
    pub const fn new(kind: WorkloadCredentialRevocationFailureKind) -> Self {
        Self {
            kind,
            retry_after: None,
        }
    }
    /// Creates a rate-limit failure with validated retry guidance.
    #[must_use]
    pub const fn rate_limited(retry_after: Option<WorkloadCredentialRetryAfter>) -> Self {
        Self {
            kind: WorkloadCredentialRevocationFailureKind::RateLimited,
            retry_after,
        }
    }
    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> WorkloadCredentialRevocationFailureKind {
        self.kind
    }
    /// Returns bounded provider retry guidance when available.
    #[must_use]
    pub const fn retry_after(self) -> Option<WorkloadCredentialRetryAfter> {
        self.retry_after
    }
}

/// Result of one revocation attempt. Only `Confirmed` permits secret erasure.
#[must_use]
#[derive(Debug)]
pub enum WorkloadCredentialRevocationOutcome {
    /// The provider confirmed that the exact credential is no longer usable.
    Confirmed,
    /// Revocation was not proven; the candidate remains owned by the caller.
    Unconfirmed {
        /// The exact secret-bearing cleanup obligation.
        candidate: WorkloadCredentialRevocationCandidate,
        /// Sanitized reason confirmation failed.
        failure: WorkloadCredentialRevocationFailure,
    },
}

/// Future returned by one workload credential issue attempt.
pub type WorkloadCredentialIssueFuture<'a> =
    Pin<Box<dyn Future<Output = WorkloadCredentialIssueOutcome> + Send + 'a>>;

/// Future returned by one workload credential revocation attempt.
pub type WorkloadCredentialRevocationFuture<'a> =
    Pin<Box<dyn Future<Output = WorkloadCredentialRevocationOutcome> + Send + 'a>>;

/// Adapter port for one-attempt issue and secret-bearing revocation.
pub trait WorkloadCredentialProvider: fmt::Debug + Send + Sync {
    /// Performs exactly one provider-side issue mutation.
    fn issue_once<'a>(
        &'a self,
        request: &'a WorkloadCredentialRequest,
    ) -> WorkloadCredentialIssueFuture<'a>;
    /// Attempts to revoke the exact recovered credential.
    ///
    /// The implementation must return ownership of `candidate` unless the
    /// provider confirms that the credential is no longer usable.
    fn revoke(
        &self,
        candidate: WorkloadCredentialRevocationCandidate,
    ) -> WorkloadCredentialRevocationFuture<'_>;
}

/// Bounded provider guidance for retrying a credential operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkloadCredentialRetryAfter(NonZeroU64);

impl WorkloadCredentialRetryAfter {
    /// Creates retry guidance within the common credential retry bound.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive delays.
    pub fn new(millis: u64) -> Result<Self, ProviderCredentialModelError> {
        NonZeroU64::new(millis)
            .filter(|value| value.get() <= MAX_WORKLOAD_CREDENTIAL_RETRY_MILLIS)
            .map(Self)
            .ok_or(ProviderCredentialModelError::InvalidRetry)
    }
    /// Returns the suggested retry delay in milliseconds.
    #[must_use]
    pub const fn millis(self) -> u64 {
        self.0.get()
    }
}

/// Stable classification of a definitive provider rejection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkloadCredentialProviderErrorKind {
    /// The profile or permission mapping is unsupported.
    #[error("workload credential profile is unsupported")]
    Unsupported,
    /// Provider authentication failed.
    #[error("workload credential authentication failed")]
    Unauthorized,
    /// Provider authorization denied the request.
    #[error("workload credential authorization failed")]
    Forbidden,
    /// The exact provider resource does not exist or was deliberately hidden.
    #[error("workload credential provider resource was not found")]
    NotFound,
    /// Provider quota is temporarily exhausted.
    #[error("workload credential provider is rate limited")]
    RateLimited,
    /// Provider service is temporarily unavailable.
    #[error("workload credential provider is unavailable")]
    Unavailable,
    /// Provider state conflicts with the exact request.
    #[error("workload credential provider state conflicts with the request")]
    Conflict,
    /// Provider response violates the common contract.
    #[error("workload credential provider response is invalid")]
    InvalidResponse,
}

/// Sanitized definitive provider rejection with bounded retry guidance.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("workload credential operation was rejected: {kind}")]
pub struct WorkloadCredentialProviderError {
    kind: WorkloadCredentialProviderErrorKind,
    retry_after: Option<WorkloadCredentialRetryAfter>,
}

impl WorkloadCredentialProviderError {
    /// Creates a sanitized rejection without provider retry guidance.
    #[must_use]
    pub const fn new(kind: WorkloadCredentialProviderErrorKind) -> Self {
        Self {
            kind,
            retry_after: None,
        }
    }
    /// Creates a rate-limit rejection with validated retry guidance.
    #[must_use]
    pub const fn rate_limited(retry_after: Option<WorkloadCredentialRetryAfter>) -> Self {
        Self {
            kind: WorkloadCredentialProviderErrorKind::RateLimited,
            retry_after,
        }
    }
    /// Returns the stable provider rejection classification.
    #[must_use]
    pub const fn kind(self) -> WorkloadCredentialProviderErrorKind {
        self.kind
    }
    /// Returns bounded provider retry guidance when available.
    #[must_use]
    pub const fn retry_after(self) -> Option<WorkloadCredentialRetryAfter> {
        self.retry_after
    }
}

/// Invalid common provider credential model.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderCredentialModelError {
    /// New credential work requires an active connection.
    #[error("provider credential connection is not active")]
    InactiveConnection,
    /// A durable timestamp is invalid.
    #[error("provider credential timestamp is invalid")]
    InvalidTimestamp,
    /// Requested or observed validity is invalid.
    #[error("provider credential validity is invalid")]
    InvalidValidity,
    /// Durable control acquisition claim evidence is invalid.
    #[error("provider control credential claim is invalid")]
    InvalidControlClaim,
    /// Control operations are empty or excessive.
    #[error("provider control credential operations are invalid")]
    InvalidControlOperations,
    /// Credential evidence does not bind to the exact request.
    #[error("provider credential binding is invalid")]
    InvalidCredentialBinding,
    /// Durable generation is invalid.
    #[error("provider credential generation is invalid")]
    InvalidGeneration,
    /// Workload permission mapping is invalid.
    #[error("provider workload credential permission is invalid")]
    InvalidWorkloadPermission,
    /// Workload lease evidence is invalid.
    #[error("provider workload credential lease is invalid")]
    InvalidLease,
    /// Provider retry guidance is zero or excessive.
    #[error("provider workload credential retry guidance is invalid")]
    InvalidRetry,
}

fn valid_permission_name(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_WORKLOAD_PERMISSION_NAME_BYTES {
        return false;
    }
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase()) {
        return false;
    }
    let mut previous_separator = false;
    for byte in bytes {
        if matches!(byte, b'-' | b'_') {
            if previous_separator {
                return false;
            }
            previous_separator = true;
        } else if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            previous_separator = false;
        } else {
            return false;
        }
    }
    !previous_separator
}

fn part(hash: &mut Sha256, value: &[u8]) {
    hash.update(
        u64::try_from(value.len())
            .expect("bounded provider credential value fits u64")
            .to_be_bytes(),
    );
    hash.update(value);
}
const fn control_operation_code(value: ProviderControlOperation) -> u8 {
    match value {
        ProviderControlOperation::RepositoryRead => 1,
        ProviderControlOperation::CommitChangedFilesRead => 2,
        ProviderControlOperation::MergeRequestChangedFilesRead => 3,
        ProviderControlOperation::ResultWrite => 4,
        ProviderControlOperation::ResultRead => 5,
        ProviderControlOperation::ResultResolve => 6,
        ProviderControlOperation::ResultCreate => 7,
        ProviderControlOperation::ResultReconcile => 8,
        ProviderControlOperation::WebhookManage => 9,
        ProviderControlOperation::ScheduleRead => 10,
        ProviderControlOperation::DispatchWrite => 11,
        ProviderControlOperation::WorkflowPermissionRead => 12,
        ProviderControlOperation::MembershipRead => 13,
        ProviderControlOperation::WorkloadCredentialManage => 14,
    }
}
const fn trust_class_code(value: TrustSourceClass) -> u8 {
    match value {
        TrustSourceClass::SameRepository => 1,
        TrustSourceClass::Fork => 2,
        TrustSourceClass::Dependabot => 3,
        TrustSourceClass::Automation => 4,
        TrustSourceClass::Incomplete => 5,
        TrustSourceClass::MergeQueue => 6,
    }
}
const fn profile_code(value: WorkloadCredentialProfile) -> u8 {
    match value {
        WorkloadCredentialProfile::CheckoutRead => 1,
        WorkloadCredentialProfile::RepositoryAccess => 2,
    }
}
const fn permission_level_code(value: PermissionLevel) -> u8 {
    match value {
        PermissionLevel::None => 0,
        PermissionLevel::Read => 1,
        PermissionLevel::Write => 2,
    }
}
