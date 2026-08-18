//! Canonical non-secret provider configuration and named secret bindings.

use std::{
    collections::BTreeMap,
    fmt,
    num::{NonZeroU16, NonZeroU64},
};

use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_key_management::SecretBytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::{Host, Url};

use crate::{ProviderCapabilities, ProviderInstanceId, ProviderTypeId};

/// Maximum canonical adapter-configuration document size.
pub const MAX_PROVIDER_CONFIGURATION_BYTES: usize = 256 * 1_024;
/// Largest adapter schema version representable by the durable `SMALLINT` contract.
pub const MAX_PROVIDER_SCHEMA_VERSION: u16 = i16::MAX as u16;
/// Maximum secrets bound to one provider instance revision.
pub const MAX_PROVIDER_SECRET_BINDINGS: usize = 32;
/// Maximum bytes in one canonical provider secret name.
pub const MAX_PROVIDER_SECRET_NAME_BYTES: usize = 64;
/// Maximum bytes in one canonical provider origin.
pub const MAX_PROVIDER_ORIGIN_BYTES: usize = 2_048;

const CONFIGURATION_DIGEST_DOMAIN: &[u8] = b"automata.provider.configuration.v1\0";
const CAPABILITY_DIGEST_DOMAIN: &[u8] = b"automata.provider.capabilities.v1\0";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"automata.provider.instance-manifest.v1\0";

macro_rules! positive_value {
    ($(#[$meta:meta])* $name:ident, $error:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "u64", into = "u64")]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Creates a positive value representable by a `PostgreSQL BIGINT`.
            ///
            /// # Errors
            ///
            /// Rejects zero and values larger than `i64::MAX`.
            pub const fn new(value: u64) -> Result<Self, ProviderConfigurationError> {
                match NonZeroU64::new(value) {
                    Some(value) if value.get() <= i64::MAX as u64 => Ok(Self(value)),
                    _ => Err(ProviderConfigurationError::$error),
                }
            }

            /// Returns the positive durable value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }

        impl TryFrom<u64> for $name {
            type Error = ProviderConfigurationError;

            fn try_from(value: u64) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for u64 {
            fn from(value: $name) -> Self {
                value.get()
            }
        }
    };
}

positive_value!(
    /// Monotonic revision of one configured provider instance.
    ProviderConfigurationRevision,
    InvalidConfigurationRevision
);
positive_value!(
    /// Monotonic generation of one named provider secret.
    ProviderSecretGeneration,
    InvalidSecretGeneration
);

/// Positive, bounded adapter-owned configuration schema version.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct ProviderSchemaVersion(NonZeroU16);

impl ProviderSchemaVersion {
    /// Creates a schema version representable by the durable `SMALLINT` contract.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than [`MAX_PROVIDER_SCHEMA_VERSION`].
    pub const fn new(value: u16) -> Result<Self, ProviderConfigurationError> {
        match NonZeroU16::new(value) {
            Some(value) if value.get() <= MAX_PROVIDER_SCHEMA_VERSION => Ok(Self(value)),
            _ => Err(ProviderConfigurationError::InvalidSchemaVersion),
        }
    }

    /// Returns the positive durable schema version.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl TryFrom<u16> for ProviderSchemaVersion {
    type Error = ProviderConfigurationError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProviderSchemaVersion> for u16 {
    fn from(value: ProviderSchemaVersion) -> Self {
        value.get()
    }
}

/// Canonical name of one adapter-required provider secret.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProviderSecretName(String);

impl ProviderSecretName {
    /// Creates a lower-case hyphen-separated secret name.
    ///
    /// # Errors
    ///
    /// Rejects values outside `[a-z][a-z0-9]*(?:-[a-z0-9]+)*` or the byte bound.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderConfigurationError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_PROVIDER_SECRET_NAME_BYTES {
            return Err(ProviderConfigurationError::InvalidSecretName);
        }
        let mut parts = value.split('-');
        let Some(first) = parts.next() else {
            return Err(ProviderConfigurationError::InvalidSecretName);
        };
        if !valid_name_part(first, false) || !parts.all(|part| valid_name_part(part, true)) {
            return Err(ProviderConfigurationError::InvalidSecretName);
        }
        Ok(Self(value))
    }

    /// Returns the canonical secret name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProviderSecretName {
    type Error = ProviderConfigurationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProviderSecretName> for String {
    fn from(value: ProviderSecretName) -> Self {
        value.0
    }
}

fn valid_name_part(value: &str, digit_first: bool) -> bool {
    let Some(first) = value.as_bytes().first() else {
        return false;
    };
    (first.is_ascii_lowercase() || (digit_first && first.is_ascii_digit()))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

/// Closed transport class admitted for provider web and API origins.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProviderOriginTransport {
    /// Public or private provider endpoints protected by HTTPS.
    Https,
    /// Explicit development endpoints confined to the local host.
    LoopbackHttp,
    /// Explicit container-mapped endpoints beneath the reserved `.invalid` TLD.
    MappedHttp,
}

/// Canonical provider web and API origins.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedProviderOrigins")]
pub struct ProviderOrigins {
    web: String,
    api: String,
    #[serde(skip)]
    transport: ProviderOriginTransport,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedProviderOrigins {
    web: String,
    api: String,
}

impl ProviderOrigins {
    /// Validates canonical web and API base URLs under one transport class.
    ///
    /// The web URL must be an origin with `/`; the API URL may have a path
    /// prefix but must end in `/`. User info, query, and fragment are rejected.
    /// HTTP is accepted only for loopback hosts or reserved `.invalid` names;
    /// ordinary provider endpoints must use HTTPS.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical or untrusted URL shapes.
    pub fn new(
        web: impl Into<String>,
        api: impl Into<String>,
    ) -> Result<Self, ProviderConfigurationError> {
        let web = web.into();
        let api = api.into();
        let web_transport = validate_origin(&web, true)?;
        let api_transport = validate_origin(&api, false)?;
        if web_transport != api_transport {
            return Err(ProviderConfigurationError::InvalidOrigin);
        }
        Ok(Self {
            web,
            api,
            transport: web_transport,
        })
    }

    /// Returns the canonical browser origin.
    #[must_use]
    pub fn web(&self) -> &str {
        &self.web
    }

    /// Returns the canonical API base.
    #[must_use]
    pub fn api(&self) -> &str {
        &self.api
    }

    /// Returns the closed transport class shared by both canonical origins.
    #[must_use]
    pub const fn transport(&self) -> ProviderOriginTransport {
        self.transport
    }
}

impl TryFrom<UncheckedProviderOrigins> for ProviderOrigins {
    type Error = ProviderConfigurationError;

    fn try_from(value: UncheckedProviderOrigins) -> Result<Self, Self::Error> {
        Self::new(value.web, value.api)
    }
}

fn validate_origin(
    value: &str,
    web: bool,
) -> Result<ProviderOriginTransport, ProviderConfigurationError> {
    if value.is_empty() || value.len() > MAX_PROVIDER_ORIGIN_BYTES {
        return Err(ProviderConfigurationError::InvalidOrigin);
    }
    let parsed = Url::parse(value).map_err(|_| ProviderConfigurationError::InvalidOrigin)?;
    if parsed.as_str() != value
        || origin_transport(&parsed).is_none()
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (web && parsed.path() != "/")
        || (!web && !parsed.path().ends_with('/'))
    {
        return Err(ProviderConfigurationError::InvalidOrigin);
    }
    origin_transport(&parsed).ok_or(ProviderConfigurationError::InvalidOrigin)
}

fn origin_transport(origin: &Url) -> Option<ProviderOriginTransport> {
    match origin.scheme() {
        "https" => Some(ProviderOriginTransport::Https),
        "http" => match origin.host()? {
            Host::Domain(domain) if is_loopback_domain(domain) => {
                Some(ProviderOriginTransport::LoopbackHttp)
            }
            Host::Ipv4(address) if address.is_loopback() => {
                Some(ProviderOriginTransport::LoopbackHttp)
            }
            Host::Ipv6(address) if address.is_loopback() => {
                Some(ProviderOriginTransport::LoopbackHttp)
            }
            Host::Domain(domain) if is_mapped_domain(domain) => {
                Some(ProviderOriginTransport::MappedHttp)
            }
            Host::Domain(_) | Host::Ipv4(_) | Host::Ipv6(_) => None,
        },
        _ => None,
    }
}

fn is_loopback_domain(domain: &str) -> bool {
    domain.eq_ignore_ascii_case("localhost")
        || domain
            .to_ascii_lowercase()
            .strip_suffix(".localhost")
            .is_some_and(|prefix| !prefix.is_empty())
}

fn is_mapped_domain(domain: &str) -> bool {
    domain
        .to_ascii_lowercase()
        .strip_suffix(".invalid")
        .is_some_and(|prefix| !prefix.is_empty())
}

/// One named secret generation pinned by a configuration revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedProviderSecretBinding")]
pub struct ProviderSecretBinding {
    name: ProviderSecretName,
    generation: ProviderSecretGeneration,
    digest: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedProviderSecretBinding {
    name: ProviderSecretName,
    generation: ProviderSecretGeneration,
    digest: Sha256Digest,
}

impl ProviderSecretBinding {
    /// Binds one name and generation to its plaintext digest.
    #[must_use]
    pub const fn new(
        name: ProviderSecretName,
        generation: ProviderSecretGeneration,
        digest: Sha256Digest,
    ) -> Self {
        Self {
            name,
            generation,
            digest,
        }
    }

    /// Returns the canonical binding name.
    #[must_use]
    pub const fn name(&self) -> &ProviderSecretName {
        &self.name
    }

    /// Returns the exact secret generation.
    #[must_use]
    pub const fn generation(&self) -> ProviderSecretGeneration {
        self.generation
    }

    /// Returns the exact plaintext digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

impl TryFrom<UncheckedProviderSecretBinding> for ProviderSecretBinding {
    type Error = ProviderConfigurationError;

    fn try_from(value: UncheckedProviderSecretBinding) -> Result<Self, Self::Error> {
        Ok(Self::new(value.name, value.generation, value.digest))
    }
}

/// Sorted, duplicate-free named secret bindings for one instance revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    try_from = "Vec<ProviderSecretBinding>",
    into = "Vec<ProviderSecretBinding>"
)]
pub struct ProviderSecretBindings(BTreeMap<ProviderSecretName, ProviderSecretBinding>);

impl ProviderSecretBindings {
    /// Creates a bounded binding set.
    ///
    /// # Errors
    ///
    /// Rejects duplicate names or more than 32 bindings.
    pub fn new(
        bindings: impl IntoIterator<Item = ProviderSecretBinding>,
    ) -> Result<Self, ProviderConfigurationError> {
        let mut indexed = BTreeMap::new();
        for binding in bindings {
            if indexed.len() == MAX_PROVIDER_SECRET_BINDINGS {
                return Err(ProviderConfigurationError::TooManySecrets);
            }
            if indexed.insert(binding.name.clone(), binding).is_some() {
                return Err(ProviderConfigurationError::DuplicateSecret);
            }
        }
        Ok(Self(indexed))
    }

    /// Returns an empty binding set for a credential-free adapter.
    #[must_use]
    pub const fn empty() -> Self {
        Self(BTreeMap::new())
    }

    /// Looks up one exact named binding.
    #[must_use]
    pub fn get(&self, name: &ProviderSecretName) -> Option<&ProviderSecretBinding> {
        self.0.get(name)
    }

    /// Iterates bindings in canonical name order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &ProviderSecretBinding> {
        self.0.values()
    }

    /// Returns the number of named bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether no secrets are bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn valid_successor_of(&self, prior: &Self) -> bool {
        self.iter().all(|binding| match prior.get(binding.name()) {
            // The durable repository checks a newly present name against all
            // historical revisions; the adjacent manifest has no such view.
            None => true,
            Some(previous) if previous.digest() == binding.digest() => {
                previous.generation() == binding.generation()
            }
            Some(previous) => previous
                .generation()
                .get()
                .checked_add(1)
                .is_some_and(|next| next == binding.generation().get()),
        })
    }
}

impl TryFrom<Vec<ProviderSecretBinding>> for ProviderSecretBindings {
    type Error = ProviderConfigurationError;

    fn try_from(value: Vec<ProviderSecretBinding>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProviderSecretBindings> for Vec<ProviderSecretBinding> {
    fn from(value: ProviderSecretBindings) -> Self {
        value.0.into_values().collect()
    }
}

/// Bounded canonical adapter-owned configuration bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderConfigurationDocument {
    schema_version: ProviderSchemaVersion,
    bytes: Vec<u8>,
    digest: Sha256Digest,
}

impl fmt::Debug for ProviderConfigurationDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderConfigurationDocument")
            .field("schema_version", &self.schema_version)
            .field("bytes", &"[CANONICAL]")
            .field("byte_length", &self.bytes.len())
            .field("digest", &self.digest)
            .finish()
    }
}

impl ProviderConfigurationDocument {
    /// Creates one nonempty bounded configuration document.
    ///
    /// Canonical syntax is adapter-owned; the adapter factory must decode and
    /// byte-for-byte re-encode this document before accepting it.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized bytes.
    pub fn new(
        schema_version: ProviderSchemaVersion,
        bytes: Vec<u8>,
    ) -> Result<Self, ProviderConfigurationError> {
        if bytes.is_empty() || bytes.len() > MAX_PROVIDER_CONFIGURATION_BYTES {
            return Err(ProviderConfigurationError::InvalidConfigurationDocument);
        }
        let mut hash = Sha256::new();
        hash.update(CONFIGURATION_DIGEST_DOMAIN);
        hash.update(schema_version.get().to_be_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(&bytes);
        Ok(Self {
            schema_version,
            bytes,
            digest: Sha256Digest::from_bytes(hash.finalize().into()),
        })
    }

    /// Returns the adapter schema version.
    #[must_use]
    pub const fn schema_version(&self) -> ProviderSchemaVersion {
        self.schema_version
    }

    /// Returns the exact canonical bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the domain-separated document digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Enabled-state lifecycle of one provider installation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLifecycleState {
    /// Configuration is retained but provider side effects are disabled.
    Disabled,
    /// The provider instance may serve declared capabilities.
    Active,
    /// The instance is terminal and can never be reactivated.
    Retired,
}

/// Immutable validated provider-instance configuration revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderInstanceManifest {
    instance_id: ProviderInstanceId,
    provider_type: ProviderTypeId,
    revision: ProviderConfigurationRevision,
    state: ProviderLifecycleState,
    origins: ProviderOrigins,
    configuration: ProviderConfigurationDocument,
    secrets: ProviderSecretBindings,
    capability_digest: Sha256Digest,
    created_at: UnixMillis,
    activated_at: Option<UnixMillis>,
    retired_at: Option<UnixMillis>,
    digest: Sha256Digest,
}

/// Complete provider-instance revision awaiting adapter capability validation.
pub struct ProviderInstanceDraft {
    instance_id: ProviderInstanceId,
    provider_type: ProviderTypeId,
    revision: ProviderConfigurationRevision,
    state: ProviderLifecycleState,
    origins: ProviderOrigins,
    configuration: ProviderConfigurationDocument,
    secret_bindings: ProviderSecretBindings,
    secrets: ProviderSecretSet,
    created_at: UnixMillis,
    activated_at: Option<UnixMillis>,
    retired_at: Option<UnixMillis>,
}

impl ProviderInstanceDraft {
    /// Creates one complete revision without accepting a caller-supplied capability digest.
    ///
    /// Secret bindings are derived from the exact supplied plaintext values. The
    /// registered adapter validates this draft and supplies the capability set
    /// before a durable manifest can exist.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent lifecycle evidence or invalid secret cardinality.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: ProviderInstanceId,
        provider_type: ProviderTypeId,
        revision: ProviderConfigurationRevision,
        state: ProviderLifecycleState,
        origins: ProviderOrigins,
        configuration: ProviderConfigurationDocument,
        secrets: impl IntoIterator<Item = ProviderSecret>,
        created_at: UnixMillis,
        activated_at: Option<UnixMillis>,
        retired_at: Option<UnixMillis>,
    ) -> Result<Self, ProviderConfigurationError> {
        validate_lifecycle(state, created_at, activated_at, retired_at)?;
        let (secret_bindings, secrets) = ProviderSecretSet::bind(secrets)?;
        Ok(Self {
            instance_id,
            provider_type,
            revision,
            state,
            origins,
            configuration,
            secret_bindings,
            secrets,
            created_at,
            activated_at,
            retired_at,
        })
    }

    /// Returns the provider type selecting one registered adapter.
    #[must_use]
    pub const fn provider_type(&self) -> &ProviderTypeId {
        &self.provider_type
    }

    /// Returns the canonical provider origins.
    #[must_use]
    pub const fn origins(&self) -> &ProviderOrigins {
        &self.origins
    }

    /// Returns the canonical adapter-owned configuration document.
    #[must_use]
    pub const fn configuration(&self) -> &ProviderConfigurationDocument {
        &self.configuration
    }

    /// Returns bindings derived from the exact plaintext values.
    #[must_use]
    pub const fn secret_bindings(&self) -> &ProviderSecretBindings {
        &self.secret_bindings
    }

    /// Returns the exact plaintext secret set at the adapter validation boundary.
    #[must_use]
    pub const fn secrets(&self) -> &ProviderSecretSet {
        &self.secrets
    }

    pub(crate) fn into_manifest(
        self,
        capability_digest: Sha256Digest,
    ) -> Result<(ProviderInstanceManifest, ProviderSecretSet), ProviderConfigurationError> {
        let manifest = ProviderInstanceManifest::new(
            self.instance_id,
            self.provider_type,
            self.revision,
            self.state,
            self.origins,
            self.configuration,
            self.secret_bindings,
            capability_digest,
            self.created_at,
            self.activated_at,
            self.retired_at,
        )?;
        Ok((manifest, self.secrets))
    }
}

impl fmt::Debug for ProviderInstanceDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderInstanceDraft")
            .field("instance_id", &self.instance_id)
            .field("provider_type", &self.provider_type)
            .field("revision", &self.revision)
            .field("state", &self.state)
            .field("origins", &self.origins)
            .field("configuration", &self.configuration)
            .field("secret_bindings", &self.secret_bindings)
            .field("secrets", &self.secrets)
            .field("created_at", &self.created_at)
            .field("activated_at", &self.activated_at)
            .field("retired_at", &self.retired_at)
            .finish()
    }
}

impl ProviderInstanceManifest {
    /// Constructs one complete immutable manifest revision.
    ///
    /// # Errors
    ///
    /// Rejects negative or inconsistent lifecycle evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: ProviderInstanceId,
        provider_type: ProviderTypeId,
        revision: ProviderConfigurationRevision,
        state: ProviderLifecycleState,
        origins: ProviderOrigins,
        configuration: ProviderConfigurationDocument,
        secrets: ProviderSecretBindings,
        capability_digest: Sha256Digest,
        created_at: UnixMillis,
        activated_at: Option<UnixMillis>,
        retired_at: Option<UnixMillis>,
    ) -> Result<Self, ProviderConfigurationError> {
        validate_lifecycle(state, created_at, activated_at, retired_at)?;
        let mut manifest = Self {
            instance_id,
            provider_type,
            revision,
            state,
            origins,
            configuration,
            secrets,
            capability_digest,
            created_at,
            activated_at,
            retired_at,
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        manifest.digest = manifest.compute_digest();
        Ok(manifest)
    }

    /// Returns the configured instance identity.
    #[must_use]
    pub const fn instance_id(&self) -> ProviderInstanceId {
        self.instance_id
    }

    /// Returns the statically registered adapter type.
    #[must_use]
    pub const fn provider_type(&self) -> &ProviderTypeId {
        &self.provider_type
    }

    /// Returns the monotonic configuration revision.
    #[must_use]
    pub const fn revision(&self) -> ProviderConfigurationRevision {
        self.revision
    }

    /// Returns the lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ProviderLifecycleState {
        self.state
    }

    /// Returns canonical network origins.
    #[must_use]
    pub const fn origins(&self) -> &ProviderOrigins {
        &self.origins
    }

    /// Returns the canonical adapter document.
    #[must_use]
    pub const fn configuration(&self) -> &ProviderConfigurationDocument {
        &self.configuration
    }

    /// Returns exact named secret bindings.
    #[must_use]
    pub const fn secrets(&self) -> &ProviderSecretBindings {
        &self.secrets
    }

    /// Returns the adapter-validated capability digest.
    #[must_use]
    pub const fn capability_digest(&self) -> Sha256Digest {
        self.capability_digest
    }

    /// Returns instance creation time.
    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }

    /// Returns first activation evidence when activation has occurred.
    #[must_use]
    pub const fn activated_at(&self) -> Option<UnixMillis> {
        self.activated_at
    }

    /// Returns terminal retirement evidence.
    #[must_use]
    pub const fn retired_at(&self) -> Option<UnixMillis> {
        self.retired_at
    }

    /// Returns the complete domain-separated manifest digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Validates a strictly contiguous, changed successor revision.
    ///
    /// # Errors
    ///
    /// Rejects identity changes, reactivation after retirement, continuing
    /// secret generation drift, noncontiguous revisions, or no-op revisions.
    pub fn validate_successor(&self, prior: &Self) -> Result<(), ProviderConfigurationError> {
        let next = prior
            .revision
            .get()
            .checked_add(1)
            .ok_or(ProviderConfigurationError::InvalidSuccessor)?;
        if self.instance_id != prior.instance_id
            || self.provider_type != prior.provider_type
            || self.revision.get() != next
            || self.created_at != prior.created_at
            || prior.state == ProviderLifecycleState::Retired
            || (prior.activated_at.is_some() && self.activated_at != prior.activated_at)
            || (prior.activated_at.is_none()
                && self.state != ProviderLifecycleState::Active
                && self.activated_at.is_some())
            || !self.secrets.valid_successor_of(&prior.secrets)
            || !self.has_substantive_change_from(prior)
        {
            return Err(ProviderConfigurationError::InvalidSuccessor);
        }
        Ok(())
    }

    fn has_substantive_change_from(&self, prior: &Self) -> bool {
        self.state != prior.state
            || self.origins != prior.origins
            || self.configuration != prior.configuration
            || self.secrets != prior.secrets
            || self.capability_digest != prior.capability_digest
            || self.activated_at != prior.activated_at
            || self.retired_at != prior.retired_at
    }

    fn compute_digest(&self) -> Sha256Digest {
        let mut hash = Sha256::new();
        hash.update(MANIFEST_DIGEST_DOMAIN);
        update_part(&mut hash, self.instance_id.as_uuid().as_bytes());
        update_part(&mut hash, self.provider_type.as_str().as_bytes());
        update_part(&mut hash, &self.revision.get().to_be_bytes());
        update_part(
            &mut hash,
            match self.state {
                ProviderLifecycleState::Disabled => b"disabled",
                ProviderLifecycleState::Active => b"active",
                ProviderLifecycleState::Retired => b"retired",
            },
        );
        update_part(&mut hash, self.origins.web().as_bytes());
        update_part(&mut hash, self.origins.api().as_bytes());
        update_part(&mut hash, self.configuration.digest().as_bytes());
        for secret in self.secrets.iter() {
            update_part(&mut hash, secret.name().as_str().as_bytes());
            update_part(&mut hash, &secret.generation().get().to_be_bytes());
            update_part(&mut hash, secret.digest().as_bytes());
        }
        update_part(&mut hash, self.capability_digest.as_bytes());
        update_part(&mut hash, &self.created_at.get().to_be_bytes());
        update_optional_time(&mut hash, self.activated_at);
        update_optional_time(&mut hash, self.retired_at);
        Sha256Digest::from_bytes(hash.finalize().into())
    }
}

pub(crate) fn validate_lifecycle(
    state: ProviderLifecycleState,
    created_at: UnixMillis,
    activated_at: Option<UnixMillis>,
    retired_at: Option<UnixMillis>,
) -> Result<(), ProviderConfigurationError> {
    if created_at.get() < 0
        || activated_at.is_some_and(|value| value.get() < created_at.get())
        || retired_at.is_some_and(|value| value.get() < activated_at.unwrap_or(created_at).get())
        || (state == ProviderLifecycleState::Active
            && (activated_at.is_none() || retired_at.is_some()))
        || (state == ProviderLifecycleState::Retired && retired_at.is_none())
        || (state != ProviderLifecycleState::Retired && retired_at.is_some())
    {
        return Err(ProviderConfigurationError::InvalidLifecycle);
    }
    Ok(())
}

/// Plaintext named secret accepted only at the registry/factory boundary.
pub struct ProviderSecret {
    name: ProviderSecretName,
    generation: ProviderSecretGeneration,
    value: SecretBytes,
}

impl ProviderSecret {
    /// Creates one move-only named secret value.
    #[must_use]
    pub const fn new(
        name: ProviderSecretName,
        generation: ProviderSecretGeneration,
        value: SecretBytes,
    ) -> Self {
        Self {
            name,
            generation,
            value,
        }
    }

    /// Consumes the secret into its exact name, generation, and plaintext.
    #[must_use]
    pub fn into_parts(self) -> (ProviderSecretName, ProviderSecretGeneration, SecretBytes) {
        (self.name, self.generation, self.value)
    }
}

impl fmt::Debug for ProviderSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSecret")
            .field("name", &self.name)
            .field("generation", &self.generation)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Exact plaintext values matching one manifest's named bindings.
pub struct ProviderSecretSet(BTreeMap<ProviderSecretName, ProviderSecret>);

impl ProviderSecretSet {
    /// Derives exact bindings from plaintext values and takes custody of them.
    ///
    /// # Errors
    ///
    /// Rejects duplicate names or more than the common secret bound.
    pub fn bind(
        secrets: impl IntoIterator<Item = ProviderSecret>,
    ) -> Result<(ProviderSecretBindings, Self), ProviderConfigurationError> {
        let mut indexed = BTreeMap::new();
        for secret in secrets {
            if indexed.len() == MAX_PROVIDER_SECRET_BINDINGS {
                return Err(ProviderConfigurationError::TooManySecrets);
            }
            if indexed.insert(secret.name.clone(), secret).is_some() {
                return Err(ProviderConfigurationError::DuplicateSecret);
            }
        }
        let bindings = ProviderSecretBindings::new(indexed.values().map(|secret| {
            ProviderSecretBinding::new(
                secret.name.clone(),
                secret.generation,
                Sha256Digest::from_bytes(Sha256::digest(secret.value.expose_secret()).into()),
            )
        }))?;
        Ok((bindings, Self(indexed)))
    }

    /// Validates exact names, generations, and plaintext digests.
    ///
    /// # Errors
    ///
    /// Rejects missing, unexpected, duplicate, or mismatched values.
    pub fn new(
        bindings: &ProviderSecretBindings,
        secrets: impl IntoIterator<Item = ProviderSecret>,
    ) -> Result<Self, ProviderConfigurationError> {
        let mut indexed = BTreeMap::new();
        for secret in secrets {
            let Some(binding) = bindings.get(&secret.name) else {
                return Err(ProviderConfigurationError::UnexpectedSecret);
            };
            let digest =
                Sha256Digest::from_bytes(Sha256::digest(secret.value.expose_secret()).into());
            if binding.generation() != secret.generation || binding.digest() != digest {
                return Err(ProviderConfigurationError::SecretMismatch);
            }
            if indexed.insert(secret.name.clone(), secret).is_some() {
                return Err(ProviderConfigurationError::DuplicateSecret);
            }
        }
        if indexed.len() != bindings.len() {
            return Err(ProviderConfigurationError::MissingSecret);
        }
        Ok(Self(indexed))
    }

    /// Borrows one exact secret value.
    #[must_use]
    pub fn get(&self, name: &ProviderSecretName) -> Option<&SecretBytes> {
        self.0.get(name).map(|secret| &secret.value)
    }

    /// Iterates canonical secret names without exposing values.
    pub fn names(&self) -> impl ExactSizeIterator<Item = &ProviderSecretName> {
        self.0.keys()
    }

    /// Consumes the set into secrets in canonical name order.
    pub fn into_secrets(self) -> impl ExactSizeIterator<Item = ProviderSecret> {
        self.0.into_values()
    }

    pub(crate) fn matches(&self, bindings: &ProviderSecretBindings) -> bool {
        self.0.len() == bindings.len()
            && self.0.iter().all(|(name, secret)| {
                bindings.get(name).is_some_and(|binding| {
                    binding.generation() == secret.generation
                        && binding.digest()
                            == Sha256Digest::from_bytes(
                                Sha256::digest(secret.value.expose_secret()).into(),
                            )
                })
            })
    }
}

impl fmt::Debug for ProviderSecretSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSecretSet")
            .field("names", &self.0.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Computes the canonical digest of one validated capability declaration.
///
/// # Errors
///
/// Returns an error only if the closed capability model cannot serialize.
pub fn provider_capability_digest(
    capabilities: &ProviderCapabilities,
) -> Result<Sha256Digest, ProviderConfigurationError> {
    let bytes = serde_json::to_vec(capabilities)
        .map_err(|_| ProviderConfigurationError::CapabilityEncoding)?;
    let mut hash = Sha256::new();
    hash.update(CAPABILITY_DIGEST_DOMAIN);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    Ok(Sha256Digest::from_bytes(hash.finalize().into()))
}

fn update_part(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn update_optional_time(hash: &mut Sha256, value: Option<UnixMillis>) {
    match value {
        Some(value) => {
            hash.update([1]);
            hash.update(value.get().to_be_bytes());
        }
        None => hash.update([0]),
    }
}

/// Invalid common provider configuration or secret evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderConfigurationError {
    /// Configuration revisions must be positive signed 64-bit values.
    #[error("provider configuration revision is invalid")]
    InvalidConfigurationRevision,
    /// Adapter schema versions must fit the positive durable `SMALLINT` range.
    #[error("provider configuration schema version is invalid")]
    InvalidSchemaVersion,
    /// Secret generations must be positive signed 64-bit values.
    #[error("provider secret generation is invalid")]
    InvalidSecretGeneration,
    /// A secret name was noncanonical or oversized.
    #[error("provider secret name is invalid")]
    InvalidSecretName,
    /// A provider origin was noncanonical or did not use HTTPS.
    #[error("provider origin is invalid")]
    InvalidOrigin,
    /// The adapter document was empty or oversized.
    #[error("provider configuration document is invalid")]
    InvalidConfigurationDocument,
    /// More than the closed secret-binding bound was supplied.
    #[error("too many provider secrets were configured")]
    TooManySecrets,
    /// One secret name appeared more than once.
    #[error("a provider secret name was duplicated")]
    DuplicateSecret,
    /// Plaintext was supplied for a name absent from the manifest.
    #[error("an unexpected provider secret was supplied")]
    UnexpectedSecret,
    /// One manifest binding had no plaintext value.
    #[error("a required provider secret is missing")]
    MissingSecret,
    /// Secret generation or digest evidence did not match plaintext.
    #[error("provider secret evidence does not match")]
    SecretMismatch,
    /// Lifecycle state and timestamps were inconsistent.
    #[error("provider instance lifecycle is invalid")]
    InvalidLifecycle,
    /// A revision did not strictly succeed its predecessor.
    #[error("provider configuration successor is invalid")]
    InvalidSuccessor,
    /// Closed capability serialization failed.
    #[error("provider capability encoding failed")]
    CapabilityEncoding,
}
