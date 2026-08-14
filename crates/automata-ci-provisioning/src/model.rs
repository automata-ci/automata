use std::fmt;

use thiserror::Error;
use url::Url;
use uuid::Uuid;

const MAX_SHARD_ID_BYTES: usize = 63;
const MAX_DISPLAY_NAME_SCALARS: usize = 255;
const MAX_AUTHORITY_ID_BYTES: usize = 255;
const MAX_REQUEST_ID_BYTES: usize = 255;
const PROTOBUF_TIMESTAMP_MIN_SECONDS: i64 = -62_135_596_800;
const PROTOBUF_TIMESTAMP_MAX_SECONDS: i64 = 253_402_300_799;
const NANOS_PER_SECOND: u32 = 1_000_000_000;

macro_rules! uuid_identifier {
    ($name:ident, $error:ident, $label:literal) => {
        #[doc = concat!("A validated, non-nil canonical UUID identifying ", $label, ".")]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            #[doc = concat!("Parses the canonical UUID for ", $label, ".")]
            ///
            /// # Errors
            ///
            /// Rejects nil, non-hyphenated, upper-case, or otherwise
            /// non-canonical UUID text.
            pub fn parse(value: &str) -> Result<Self, ProvisioningValueError> {
                let parsed = Uuid::parse_str(value).map_err(|_| ProvisioningValueError::$error)?;
                if parsed.is_nil() || parsed.hyphenated().to_string() != value {
                    return Err(ProvisioningValueError::$error);
                }
                Ok(Self(parsed))
            }

            #[doc = concat!("Creates ", $label, " from a trusted non-nil UUID.")]
            ///
            /// # Errors
            ///
            /// Rejects the nil UUID.
            pub const fn from_uuid(value: Uuid) -> Result<Self, ProvisioningValueError> {
                if value.is_nil() {
                    return Err(ProvisioningValueError::$error);
                }
                Ok(Self(value))
            }

            #[doc = concat!("Returns the UUID for ", $label, ".")]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}", self.0.hyphenated())
            }
        }
    };
}

uuid_identifier!(OperationId, InvalidOperationId, "a provisioning operation");
uuid_identifier!(WorkspaceId, InvalidWorkspaceId, "a workspace");
uuid_identifier!(
    ExternalAccountSubject,
    InvalidExternalAccountSubject,
    "an external account subject"
);
uuid_identifier!(
    InitialOwnerPrincipalId,
    InvalidInitialOwnerPrincipalId,
    "a Core principal"
);

/// Immutable operational identity of one load-balanced Core shard.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ShardId(String);

impl ShardId {
    /// Creates a lower-case DNS-label-like shard identity.
    ///
    /// # Errors
    ///
    /// Rejects values outside the contract's 1–63 byte lower-case slug profile.
    pub fn new(value: impl Into<String>) -> Result<Self, ProvisioningValueError> {
        let value = value.into();
        let bytes = value.as_bytes();
        let valid_edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        if bytes.is_empty()
            || bytes.len() > MAX_SHARD_ID_BYTES
            || !valid_edge(bytes[0])
            || !valid_edge(bytes[bytes.len() - 1])
            || !bytes.iter().all(|byte| valid_edge(*byte) || *byte == b'-')
        {
            return Err(ProvisioningValueError::InvalidShardId);
        }
        Ok(Self(value))
    }

    /// Returns the validated shard slug.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded, trimmed, non-authoritative display label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayName(String);

impl DisplayName {
    /// Validates one workspace or human display label.
    ///
    /// # Errors
    ///
    /// Rejects blank, untrimmed, control-bearing, or oversized text.
    pub fn new(value: impl Into<String>) -> Result<Self, ProvisioningValueError> {
        let value = value.into();
        if value.is_empty()
            || value.trim() != value
            || value.chars().any(char::is_control)
            || value.chars().count() > MAX_DISPLAY_NAME_SCALARS
        {
            return Err(ProvisioningValueError::InvalidDisplayName);
        }
        Ok(Self(value))
    }

    /// Returns the validated label.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact configured HTTPS origin that may issue delegated actor assertions.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DelegatedActorIssuer(String);

impl DelegatedActorIssuer {
    /// Creates a canonical HTTPS origin without credentials or URL components.
    ///
    /// # Errors
    ///
    /// Rejects non-HTTPS, non-origin, credential-bearing, and non-canonical URLs.
    pub fn new(value: impl Into<String>) -> Result<Self, ProvisioningValueError> {
        let value = value.into();
        let parsed =
            Url::parse(&value).map_err(|_| ProvisioningValueError::InvalidDelegatedActorIssuer)?;
        if parsed.scheme() != "https"
            || parsed.host().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.origin().ascii_serialization() != value
        {
            return Err(ProvisioningValueError::InvalidDelegatedActorIssuer);
        }
        Ok(Self(value))
    }

    /// Returns the exact configured origin.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable server-configured identity used as the idempotency namespace.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProvisioningAuthorityId(String);

impl ProvisioningAuthorityId {
    /// Creates a bounded, portable workload authority identity.
    ///
    /// # Errors
    ///
    /// Rejects empty, whitespace-bearing, control-bearing, or oversized values.
    pub fn new(value: impl Into<String>) -> Result<Self, ProvisioningValueError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_AUTHORITY_ID_BYTES
            || value.chars().any(char::is_whitespace)
        {
            return Err(ProvisioningValueError::InvalidProvisioningAuthorityId);
        }
        Ok(Self(value))
    }

    /// Returns the stable authority identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Server-derived authority and its exact provisioning scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisioningAuthority {
    id: ProvisioningAuthorityId,
    shard_id: ShardId,
    delegated_actor_issuer: DelegatedActorIssuer,
}

impl ProvisioningAuthority {
    /// Binds a stable workload identity to one shard and delegated issuer.
    pub const fn new(
        id: ProvisioningAuthorityId,
        shard_id: ShardId,
        delegated_actor_issuer: DelegatedActorIssuer,
    ) -> Self {
        Self {
            id,
            shard_id,
            delegated_actor_issuer,
        }
    }

    /// Returns the durable idempotency namespace.
    pub const fn id(&self) -> &ProvisioningAuthorityId {
        &self.id
    }

    /// Returns the only shard this authority may provision.
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    /// Returns the only delegated actor issuer this authority may install.
    pub const fn delegated_actor_issuer(&self) -> &DelegatedActorIssuer {
        &self.delegated_actor_issuer
    }
}

/// Complete validated semantic input for workspace provisioning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisionWorkspaceCommand {
    operation_id: OperationId,
    shard_id: ShardId,
    workspace_id: WorkspaceId,
    workspace_display_name: DisplayName,
    initial_owner_issuer: DelegatedActorIssuer,
    initial_owner_subject: ExternalAccountSubject,
    initial_owner_display_name: DisplayName,
}

impl ProvisionWorkspaceCommand {
    /// Creates one fully validated provisioning command.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        operation_id: OperationId,
        shard_id: ShardId,
        workspace_id: WorkspaceId,
        workspace_display_name: DisplayName,
        initial_owner_issuer: DelegatedActorIssuer,
        initial_owner_subject: ExternalAccountSubject,
        initial_owner_display_name: DisplayName,
    ) -> Self {
        Self {
            operation_id,
            shard_id,
            workspace_id,
            workspace_display_name,
            initial_owner_issuer,
            initial_owner_subject,
            initial_owner_display_name,
        }
    }

    /// Returns the durable caller-generated operation identity.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the caller's expected shard.
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    /// Returns the exact workspace/Core tenant identity.
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Returns the initial workspace label.
    pub const fn workspace_display_name(&self) -> &DisplayName {
        &self.workspace_display_name
    }

    /// Returns the exact external identity issuer.
    pub const fn initial_owner_issuer(&self) -> &DelegatedActorIssuer {
        &self.initial_owner_issuer
    }

    /// Returns the stable external account subject.
    pub const fn initial_owner_subject(&self) -> ExternalAccountSubject {
        self.initial_owner_subject
    }

    /// Returns the initial owner's non-authoritative label.
    pub const fn initial_owner_display_name(&self) -> &DisplayName {
        &self.initial_owner_display_name
    }
}

/// Provisioning command proven to be within a workload authority's scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedProvisionWorkspace {
    authority: ProvisioningAuthority,
    command: ProvisionWorkspaceCommand,
}

impl AuthorizedProvisionWorkspace {
    /// Authorizes a command against the server-derived shard and issuer bindings.
    ///
    /// # Errors
    ///
    /// Rejects a command for any other shard or delegated actor issuer.
    pub fn authorize(
        authority: ProvisioningAuthority,
        command: ProvisionWorkspaceCommand,
    ) -> Result<Self, ProvisioningAuthorizationError> {
        if authority.shard_id != command.shard_id
            || authority.delegated_actor_issuer != command.initial_owner_issuer
        {
            return Err(ProvisioningAuthorizationError::Forbidden);
        }
        Ok(Self { authority, command })
    }

    /// Returns the stable server-derived authority.
    pub const fn authority(&self) -> &ProvisioningAuthority {
        &self.authority
    }

    /// Returns the validated semantic command.
    pub const fn command(&self) -> &ProvisionWorkspaceCommand {
        &self.command
    }

    /// Consumes the request into its authority and command.
    pub fn into_parts(self) -> (ProvisioningAuthority, ProvisionWorkspaceCommand) {
        (self.authority, self.command)
    }
}

/// A Protobuf-compatible UTC instant returned by the durable transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvisionedAt {
    seconds: i64,
    nanoseconds: u32,
}

impl ProvisionedAt {
    /// Creates an instant within the Protobuf Timestamp range.
    ///
    /// # Errors
    ///
    /// Rejects out-of-range seconds or one billion or more nanoseconds.
    pub const fn new(seconds: i64, nanoseconds: u32) -> Result<Self, ProvisioningValueError> {
        if seconds < PROTOBUF_TIMESTAMP_MIN_SECONDS
            || seconds > PROTOBUF_TIMESTAMP_MAX_SECONDS
            || nanoseconds >= NANOS_PER_SECOND
        {
            return Err(ProvisioningValueError::InvalidProvisionedAt);
        }
        Ok(Self {
            seconds,
            nanoseconds,
        })
    }

    /// Returns whole Unix seconds.
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Returns the fractional nanoseconds within the second.
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }
}

/// Stable result committed atomically with the provisioning operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisionWorkspaceResult {
    operation_id: OperationId,
    shard_id: ShardId,
    workspace_id: WorkspaceId,
    initial_owner_principal_id: InitialOwnerPrincipalId,
    provisioned_at: ProvisionedAt,
}

impl ProvisionWorkspaceResult {
    /// Creates a durable first-attempt or replay result.
    pub const fn new(
        operation_id: OperationId,
        shard_id: ShardId,
        workspace_id: WorkspaceId,
        initial_owner_principal_id: InitialOwnerPrincipalId,
        provisioned_at: ProvisionedAt,
    ) -> Self {
        Self {
            operation_id,
            shard_id,
            workspace_id,
            initial_owner_principal_id,
            provisioned_at,
        }
    }

    /// Returns the request operation identity.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the shard that committed the transaction.
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    /// Returns the resulting workspace/Core tenant identity.
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Returns the Core-owned initial owner principal.
    pub const fn initial_owner_principal_id(&self) -> InitialOwnerPrincipalId {
        self.initial_owner_principal_id
    }

    /// Returns the stable database commit time.
    pub const fn provisioned_at(&self) -> ProvisionedAt {
        self.provisioned_at
    }
}

/// Opaque bounded correlation identity safe to return to the control plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisioningRequestId(String);

impl ProvisioningRequestId {
    /// Creates a portable request correlation identity.
    ///
    /// # Errors
    ///
    /// Rejects empty, whitespace-bearing, or oversized text.
    pub fn new(value: impl Into<String>) -> Result<Self, ProvisioningValueError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_REQUEST_ID_BYTES
            || value.chars().any(char::is_whitespace)
        {
            return Err(ProvisioningValueError::InvalidRequestId);
        }
        Ok(Self(value))
    }

    /// Returns the sanitized correlation identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Closed failure kinds returned by the durable provisioning boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisioningFailureKind {
    /// The operation ID is already bound to different semantic input.
    OperationConflict,
    /// Another operation already owns the workspace identity.
    WorkspaceConflict,
    /// The exact external identity cannot be used as an active principal.
    PrincipalUnavailable,
    /// The authority exceeded a bounded provisioning rate.
    RateLimited,
    /// Core failed without a safer specific result.
    Internal,
    /// A required durable dependency is temporarily unavailable.
    TemporarilyUnavailable,
}

/// Sanitized application failure with optional safe correlation identity.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("workspace provisioning failed: {kind:?}")]
pub struct ProvisioningFailure {
    kind: ProvisioningFailureKind,
    request_id: Option<ProvisioningRequestId>,
}

impl ProvisioningFailure {
    /// Creates one closed provisioning failure.
    pub const fn new(
        kind: ProvisioningFailureKind,
        request_id: Option<ProvisioningRequestId>,
    ) -> Self {
        Self { kind, request_id }
    }

    /// Returns the stable failure kind.
    pub const fn kind(&self) -> ProvisioningFailureKind {
        self.kind
    }

    /// Returns an optional safe correlation identity.
    pub const fn request_id(&self) -> Option<&ProvisioningRequestId> {
        self.request_id.as_ref()
    }
}

/// Server-derived scope rejection for a valid provisioning command.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProvisioningAuthorizationError {
    /// The authority is not bound to the requested shard and issuer pair.
    #[error("the provisioning authority is outside the requested scope")]
    Forbidden,
}

/// Validation failure for a provisioning domain value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProvisioningValueError {
    /// The operation UUID is invalid.
    #[error("operation ID is invalid")]
    InvalidOperationId,
    /// The shard slug is invalid.
    #[error("shard ID is invalid")]
    InvalidShardId,
    /// The workspace UUID is invalid.
    #[error("workspace ID is invalid")]
    InvalidWorkspaceId,
    /// A display label is invalid.
    #[error("display name is invalid")]
    InvalidDisplayName,
    /// The delegated actor origin is invalid.
    #[error("delegated actor issuer is invalid")]
    InvalidDelegatedActorIssuer,
    /// The external account UUID is invalid.
    #[error("external account subject is invalid")]
    InvalidExternalAccountSubject,
    /// The workload authority identity is invalid.
    #[error("provisioning authority ID is invalid")]
    InvalidProvisioningAuthorityId,
    /// The Core principal UUID is invalid.
    #[error("initial owner principal ID is invalid")]
    InvalidInitialOwnerPrincipalId,
    /// The database commit timestamp is invalid.
    #[error("provisioned timestamp is invalid")]
    InvalidProvisionedAt,
    /// The safe request correlation identity is invalid.
    #[error("provisioning request ID is invalid")]
    InvalidRequestId,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> ProvisioningAuthority {
        ProvisioningAuthority::new(
            ProvisioningAuthorityId::new("automata-cloud-production").unwrap(),
            ShardId::new("prod-us-east-1-001").unwrap(),
            DelegatedActorIssuer::new("https://cloud.automata.example").unwrap(),
        )
    }

    fn command() -> ProvisionWorkspaceCommand {
        ProvisionWorkspaceCommand::new(
            OperationId::parse("55555555-5555-4555-8555-555555555555").unwrap(),
            ShardId::new("prod-us-east-1-001").unwrap(),
            WorkspaceId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            DisplayName::new("Acme Engineering").unwrap(),
            DelegatedActorIssuer::new("https://cloud.automata.example").unwrap(),
            ExternalAccountSubject::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            DisplayName::new("The Octocat").unwrap(),
        )
    }

    #[test]
    fn canonical_contract_values_authorize() {
        let authorized = AuthorizedProvisionWorkspace::authorize(authority(), command()).unwrap();
        assert_eq!(
            authorized.authority().id().as_str(),
            "automata-cloud-production"
        );
        assert_eq!(
            authorized.command().workspace_id().to_string(),
            "22222222-2222-4222-8222-222222222222"
        );
    }

    #[test]
    fn authority_scope_checks_both_shard_and_issuer() {
        let mut wrong_shard = command();
        wrong_shard.shard_id = ShardId::new("prod-eu-west-1-001").unwrap();
        assert_eq!(
            AuthorizedProvisionWorkspace::authorize(authority(), wrong_shard),
            Err(ProvisioningAuthorizationError::Forbidden)
        );

        let mut wrong_issuer = command();
        wrong_issuer.initial_owner_issuer =
            DelegatedActorIssuer::new("https://other.automata.example").unwrap();
        assert_eq!(
            AuthorizedProvisionWorkspace::authorize(authority(), wrong_issuer),
            Err(ProvisioningAuthorizationError::Forbidden)
        );
    }

    #[test]
    fn uuid_text_is_canonical_and_non_nil() {
        assert_eq!(
            WorkspaceId::parse("00000000-0000-0000-0000-000000000000"),
            Err(ProvisioningValueError::InvalidWorkspaceId)
        );
        assert_eq!(
            WorkspaceId::parse("22222222222242228222222222222222"),
            Err(ProvisioningValueError::InvalidWorkspaceId)
        );
        assert_eq!(
            WorkspaceId::parse("22222222-2222-4222-8222-22222222222A"),
            Err(ProvisioningValueError::InvalidWorkspaceId)
        );
    }

    #[test]
    fn issuer_is_an_exact_canonical_https_origin() {
        for invalid in [
            "http://cloud.automata.example",
            "https://cloud.automata.example/",
            "https://user@cloud.automata.example",
            "https://cloud.automata.example/path",
            "https://cloud.automata.example?query",
        ] {
            assert_eq!(
                DelegatedActorIssuer::new(invalid),
                Err(ProvisioningValueError::InvalidDelegatedActorIssuer),
                "{invalid}"
            );
        }
    }

    #[test]
    fn labels_are_trimmed_control_free_and_scalar_bounded() {
        for invalid in ["", " leading", "trailing ", "line\nbreak"] {
            assert_eq!(
                DisplayName::new(invalid),
                Err(ProvisioningValueError::InvalidDisplayName)
            );
        }
        assert!(DisplayName::new("🦀".repeat(255)).is_ok());
        assert_eq!(
            DisplayName::new("🦀".repeat(256)),
            Err(ProvisioningValueError::InvalidDisplayName)
        );
    }
}
