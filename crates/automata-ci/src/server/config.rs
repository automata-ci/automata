use std::{
    collections::BTreeSet,
    convert::Infallible,
    env, fmt, io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

#[cfg(unix)]
use std::{fs::File, io::Read as _, path::Component};

use http::{Uri, uri::Authority};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use automata_ci_auth::{github::GithubClientId, installation::InstallationTenant};
use automata_ci_blob_s3::S3AtRestEncryption;
use automata_ci_control::maintenance::{
    LeaseFailureLimit, MaintenanceBatchSize, StaleSessionTimeoutMillis,
};
use automata_ci_key_management::{
    KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes as KeySecretBytes,
};
use automata_ci_provisioning::{
    DelegatedActorIssuer, ProvisioningAuthority, ProvisioningAuthorityId, ShardId,
};
use automata_ci_results_github::ResultsPublicEndpoint;
use automata_ci_store_postgres::PostgresTransportSecurity;

use crate::cli::{DatabaseTransport, ServerArgs};

use super::{github_oidc::GithubOidcConfig, github_provider_config::GithubProviderConfig};

const MAX_SOURCE_REFERENCE_BYTES: usize = 4_096;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 255;
const MAX_DATABASE_URL_BYTES: usize = 16 * 1_024;
const MAX_S3_CREDENTIAL_BYTES: usize = 16 * 1_024;
const MAX_CA_PEM_BYTES: usize = 4 * 1_024 * 1_024;
const MAX_CERTIFICATE_PEM_BYTES: usize = 4 * 1_024 * 1_024;
const MAX_PRIVATE_KEY_PEM_BYTES: usize = 1024 * 1024;
const MAX_RESULTS_SIGNING_KEY_BYTES: usize = 16 * 1024;
const MAX_RESULTS_KEY_ID_BYTES: usize = 255;
const MAX_GITHUB_CLIENT_SECRET_BYTES: usize = 16 * 1024;
const MAX_BOOTSTRAP_TOKEN_BYTES: usize = 4 * 1024;
const MAX_CONFORMANCE_EXPORT_TOKEN_BYTES: usize = 4 * 1024;
const MAX_MANAGEMENT_CLIENT_CERTIFICATES: usize = 8;
const MAX_DELEGATED_ACTOR_JWKS_URL_BYTES: usize = 2_048;
const SECRET_ENCRYPTION_KEY_BYTES: usize = 32;
const SESSION_HASH_KEY_BYTES: usize = 32;
const MIN_BOOTSTRAP_TOKEN_BYTES: usize = 32;
const MIN_CONFORMANCE_EXPORT_TOKEN_BYTES: usize = 32;
const MIN_BROWSER_SESSION_TTL_SECONDS: u64 = 5 * 60;
const MAX_BROWSER_SESSION_TTL_SECONDS: u64 = 24 * 60 * 60;
const MIN_CLI_SESSION_TTL_SECONDS: u64 = 5 * 60;
const MAX_CLI_SESSION_TTL_SECONDS: u64 = 90 * 24 * 60 * 60;

/// A credential or PEM reference that keeps its value out of process arguments.
///
/// `env:NAME` reads bytes from an environment variable and `file:PATH` reads a
/// bounded file. Debug output deliberately reveals neither the variable name nor
/// the path because either can contain deployment metadata.
#[derive(Clone, Eq, PartialEq)]
pub enum SecretSource {
    /// Read from a process environment variable.
    Environment(String),
    /// Read from a mounted or local file.
    File(PathBuf),
    /// Invalid syntax retained only as a redacted configuration sentinel.
    ///
    /// Retaining no original bytes prevents command-line parse diagnostics from
    /// echoing a credential that was accidentally supplied instead of a source.
    Invalid,
}

impl SecretSource {
    /// Loads at most `maximum_bytes` bytes from this reference.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when the source is absent, unreadable,
    /// non-Unicode when text is required, or exceeds its bound.
    pub fn load_bytes(&self, maximum_bytes: usize) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
        if maximum_bytes == 0 {
            return Err(SecretLoadError::InvalidLimit);
        }
        let bytes = match self {
            Self::Environment(name) => Zeroizing::new(
                env::var_os(name)
                    .ok_or(SecretLoadError::MissingEnvironment)?
                    .into_string()
                    .map_err(|_| SecretLoadError::InvalidText)?
                    .into_bytes(),
            ),
            Self::File(path) => read_bounded_file(path, maximum_bytes)?,
            Self::Invalid => return Err(SecretLoadError::InvalidReference),
        };
        if bytes.len() > maximum_bytes {
            return Err(SecretLoadError::TooLarge {
                maximum: maximum_bytes,
            });
        }
        Ok(bytes)
    }

    /// Loads bounded UTF-8 scalar text, removing one conventional file newline.
    ///
    /// This normalization is suitable for database URLs and S3 credentials, but
    /// not PEM documents. It never trims other leading or trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error for any load failure, invalid UTF-8, embedded
    /// line ending, empty value, or value beyond the post-normalization bound.
    pub fn load_scalar(&self, maximum_bytes: usize) -> Result<Zeroizing<String>, SecretLoadError> {
        if maximum_bytes == 0 {
            return Err(SecretLoadError::InvalidLimit);
        }
        let source_limit = match self {
            Self::File(_) => maximum_bytes
                .checked_add(2)
                .ok_or(SecretLoadError::InvalidLimit)?,
            Self::Environment(_) | Self::Invalid => maximum_bytes,
        };
        let mut bytes = self.load_bytes(source_limit)?;
        if matches!(self, Self::File(_)) {
            if bytes.ends_with(b"\r\n") {
                let normalized_length = bytes.len() - 2;
                bytes.truncate(normalized_length);
            } else if bytes.ends_with(b"\n") {
                let normalized_length = bytes.len() - 1;
                bytes.truncate(normalized_length);
            }
        }
        if bytes.is_empty() {
            return Err(SecretLoadError::Empty);
        }
        if bytes.len() > maximum_bytes {
            return Err(SecretLoadError::TooLarge {
                maximum: maximum_bytes,
            });
        }
        if bytes.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err(SecretLoadError::InvalidScalar);
        }
        let text = String::from_utf8(std::mem::take(&mut *bytes))
            .map_err(|_| SecretLoadError::InvalidText)?;
        Ok(Zeroizing::new(text))
    }

    const fn is_valid_reference(&self) -> bool {
        matches!(self, Self::Environment(_) | Self::File(_))
    }
}

impl fmt::Debug for SecretSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Environment(_) => "environment",
            Self::File(_) => "file",
            Self::Invalid => "invalid",
        };
        formatter
            .debug_struct("SecretSource")
            .field("kind", &kind)
            .field("reference", &"[redacted]")
            .finish()
    }
}

impl FromStr for SecretSource {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() || value.len() > MAX_SOURCE_REFERENCE_BYTES {
            return Ok(Self::Invalid);
        }
        if let Some(name) = value.strip_prefix("env:") {
            if name.is_empty()
                || name.len() > MAX_ENVIRONMENT_NAME_BYTES
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return Ok(Self::Invalid);
            }
            return Ok(Self::Environment(name.to_owned()));
        }
        if let Some(path) = value.strip_prefix("file:") {
            if path.is_empty() || path.contains('\0') {
                return Ok(Self::Invalid);
            }
            return Ok(Self::File(PathBuf::from(path)));
        }
        Ok(Self::Invalid)
    }
}

/// One non-secret key identity paired with a redacted deployment secret source.
///
/// This is used for decrypt-only keys during online built-in-provider rotation.
#[derive(Clone, Eq, PartialEq)]
pub struct VersionedSecretSource {
    key_id: KeyId,
    source: SecretSource,
}

impl VersionedSecretSource {
    /// Returns the non-secret identity of this decrypt-only key.
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Returns the redacted deployment source for this key's material.
    pub const fn source(&self) -> &SecretSource {
        &self.source
    }
}

impl fmt::Debug for VersionedSecretSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VersionedSecretSource")
            .field("key_id", &self.key_id)
            .field("source", &"[redacted]")
            .finish()
    }
}

impl FromStr for VersionedSecretSource {
    type Err = VersionedSecretSourceParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (key_id, source) = value
            .split_once('=')
            .ok_or(VersionedSecretSourceParseError)?;
        let key_id = KeyId::new(key_id).map_err(|_| VersionedSecretSourceParseError)?;
        let source = SecretSource::from_str(source).unwrap_or(SecretSource::Invalid);
        if !source.is_valid_reference() {
            return Err(VersionedSecretSourceParseError);
        }
        Ok(Self { key_id, source })
    }
}

/// Sanitized parser failure for a versioned deployment secret source.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("versioned secret source must use KEY_ID=env:NAME or KEY_ID=file:PATH")]
pub struct VersionedSecretSourceParseError;

/// Sanitized bounded-source loading failure.
#[derive(Debug, Error)]
pub enum SecretLoadError {
    /// Configuration did not contain an environment or file reference.
    #[error("secret configuration must use an environment or file reference")]
    InvalidReference,
    /// A zero allocation limit was requested by application code.
    #[error("secret source byte limit is invalid")]
    InvalidLimit,
    /// An environment reference was not present.
    #[error("referenced environment variable is not set")]
    MissingEnvironment,
    /// A referenced file could not be opened, inspected, or read.
    #[error("referenced secret file could not be read")]
    File(#[source] io::Error),
    /// A file reference did not meet the platform's privileged-input policy.
    #[error("referenced secret file does not satisfy the privileged-input policy")]
    FileSecurity,
    /// The source exceeded its context-specific byte ceiling.
    #[error("referenced secret exceeds the {maximum}-byte limit")]
    TooLarge {
        /// Inclusive context-specific byte ceiling.
        maximum: usize,
    },
    /// A textual source was not valid UTF-8.
    #[error("referenced secret is not valid UTF-8 text")]
    InvalidText,
    /// A scalar source contained an embedded or repeated line ending.
    #[error("referenced secret is not a single scalar value")]
    InvalidScalar,
    /// A scalar source contained no bytes after newline normalization.
    #[error("referenced secret is empty")]
    Empty,
    /// A credential source did not meet its minimum security length.
    #[error("referenced secret is shorter than the {minimum}-byte minimum")]
    TooShort {
        /// Inclusive context-specific byte floor.
        minimum: usize,
    },
    /// A cryptographic key source was not the required exact size.
    #[error("referenced secret must contain exactly {expected} bytes")]
    InvalidLength {
        /// Required byte length.
        expected: usize,
    },
}

/// Validated product configuration for one control-plane replica.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub(crate) http_listen: SocketAddr,
    pub(crate) metrics_listen: Option<SocketAddr>,
    pub(crate) human_auth: Option<HumanAuthConfig>,
    pub(crate) conformance_export_token: Option<SecretSource>,
    pub(crate) secret_encryption: Option<SecretEncryptionConfig>,
    pub(crate) control_plane_encryption: ControlPlaneEncryptionConfig,
    pub(crate) runner_listen: SocketAddr,
    pub(crate) runner_public_authority: Option<Authority>,
    pub(crate) results_listen: SocketAddr,
    pub(crate) results_public_endpoint: ResultsPublicEndpoint,
    pub(crate) results_signing_key: SecretSource,
    pub(crate) results_key_id: String,
    pub(crate) github_provider: Option<GithubProviderConfig>,
    pub(crate) github_oidc: Option<GithubOidcConfig>,
    pub(crate) database_url: SecretSource,
    pub(crate) database_max_connections: u32,
    pub(crate) database_transport_security: PostgresTransportSecurity,
    pub(crate) s3_endpoint: Url,
    pub(crate) s3_region: String,
    pub(crate) s3_bucket: String,
    pub(crate) s3_prefix: Option<String>,
    pub(crate) s3_force_path_style: bool,
    pub(crate) s3_at_rest_encryption: S3AtRestEncryption,
    pub(crate) s3_allow_loopback_http: bool,
    pub(crate) s3_operation_timeout: Duration,
    pub(crate) s3_access_key: SecretSource,
    pub(crate) s3_secret_key: SecretSource,
    pub(crate) s3_session_token: Option<SecretSource>,
    pub(crate) runner_client_ca_certificate: SecretSource,
    pub(crate) runner_client_ca_private_key: SecretSource,
    pub(crate) runner_server_ca: SecretSource,
    pub(crate) runner_server_certificate: SecretSource,
    pub(crate) runner_server_private_key: SecretSource,
    pub(crate) management: Option<ManagementConfig>,
    pub(crate) readiness_probe_interval: Duration,
    pub(crate) maintenance_interval: Duration,
    pub(crate) maintenance_batch_size: MaintenanceBatchSize,
    pub(crate) maximum_lease_failures: LeaseFailureLimit,
    pub(crate) stale_runner_session_timeout: StaleSessionTimeoutMillis,
    pub(crate) fallback_tenant_id: String,
}

/// Complete opt-in configuration for the private shard-management listener.
#[derive(Clone, Debug)]
pub struct ManagementConfig {
    pub(crate) listen: SocketAddr,
    authority: ProvisioningAuthority,
    delegated_actor_jwks_url: Url,
    client_certificate_sha256: Vec<[u8; 32]>,
    client_ca_certificate: SecretSource,
    server_certificate: SecretSource,
    server_private_key: SecretSource,
}

impl ManagementConfig {
    /// Returns the stable authority and its exact shard and delegated-issuer scope.
    pub const fn authority(&self) -> &ProvisioningAuthority {
        &self.authority
    }

    /// Returns the exact, deployment-configured delegated actor key endpoint.
    pub const fn delegated_actor_jwks_url(&self) -> &Url {
        &self.delegated_actor_jwks_url
    }

    pub(crate) fn client_certificate_sha256(&self) -> &[[u8; 32]] {
        &self.client_certificate_sha256
    }

    pub(crate) fn load_client_ca_certificate_pem(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
        self.client_ca_certificate.load_bytes(MAX_CA_PEM_BYTES)
    }

    pub(crate) fn load_server_certificate_pem(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
        self.server_certificate
            .load_bytes(MAX_CERTIFICATE_PEM_BYTES)
    }

    pub(crate) fn load_server_private_key_pem(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
        self.server_private_key
            .load_bytes(MAX_PRIVATE_KEY_PEM_BYTES)
    }
}

/// Mandatory rotation-aware wrapping keys for durable control-plane payloads.
#[derive(Clone, Debug)]
pub struct ControlPlaneEncryptionConfig {
    active_key_id: KeyId,
    active_key_source: SecretSource,
    decrypt_only_keys: Vec<VersionedSecretSource>,
}

impl ControlPlaneEncryptionConfig {
    /// Returns the identity used for newly encrypted control-plane payloads.
    pub const fn active_key_id(&self) -> &KeyId {
        &self.active_key_id
    }

    /// Iterates the distinct identities accepted only for decryption.
    pub fn decrypt_only_key_ids(&self) -> impl Iterator<Item = &KeyId> {
        self.decrypt_only_keys
            .iter()
            .map(VersionedSecretSource::key_id)
    }

    /// Loads exact-length local key material and constructs the rotation-aware keyring.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when a source is unavailable, a key is not
    /// exactly 32 bytes, or the keyring rejects the configuration.
    pub fn load_local_keyring(&self) -> Result<LocalAes256GcmKeyring, SecretEncryptionLoadError> {
        let active = load_local_key_material(&self.active_key_id, &self.active_key_source)?;
        let decrypt_only = self
            .decrypt_only_keys
            .iter()
            .map(|key| load_local_key_material(key.key_id(), key.source()))
            .collect::<Result<Vec<_>, _>>()?;
        LocalAes256GcmKeyring::new(active, decrypt_only, [])
            .map_err(|_| SecretEncryptionLoadError::InvalidKeyConfiguration)
    }
}

/// Local wrapping-key configuration for the encrypted built-in secret provider.
#[derive(Clone, Debug)]
pub struct SecretEncryptionConfig {
    active_key_id: KeyId,
    active_key_source: SecretSource,
    decrypt_only_keys: Vec<VersionedSecretSource>,
}

impl SecretEncryptionConfig {
    /// Returns the identity used for newly encrypted built-in secret versions.
    pub const fn active_key_id(&self) -> &KeyId {
        &self.active_key_id
    }

    /// Iterates the distinct identities accepted only for decryption.
    pub fn decrypt_only_key_ids(&self) -> impl Iterator<Item = &KeyId> {
        self.decrypt_only_keys
            .iter()
            .map(VersionedSecretSource::key_id)
    }

    /// Loads exact-length local key material and constructs the rotation-aware keyring.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when a source is unavailable, a key is not
    /// exactly 32 bytes, or the keyring rejects the configuration.
    pub fn load_local_keyring(&self) -> Result<LocalAes256GcmKeyring, SecretEncryptionLoadError> {
        let active = load_local_key_material(&self.active_key_id, &self.active_key_source)?;
        let decrypt_only = self
            .decrypt_only_keys
            .iter()
            .map(|key| load_local_key_material(key.key_id(), key.source()))
            .collect::<Result<Vec<_>, _>>()?;
        LocalAes256GcmKeyring::new(active, decrypt_only, [])
            .map_err(|_| SecretEncryptionLoadError::InvalidKeyConfiguration)
    }
}

/// Complete, validated GitHub human-authentication configuration.
///
/// Authentication is opt-in at the deployment boundary. Partial configuration
/// is rejected so a replica cannot accidentally serve a broken or weaker login
/// path than its peers.
#[derive(Clone, Debug)]
pub struct HumanAuthConfig {
    external_url: Url,
    callback_url: Url,
    github_client_id: GithubClientId,
    github_client_secret: SecretSource,
    session_hash_key: SecretSource,
    encryption: AuthEncryptionConfig,
    browser_session_ttl: Duration,
    cli_session_ttl: Duration,
    bootstrap: Option<BootstrapConfig>,
}

/// Rotation-aware local wrapping-key configuration for human authentication state.
#[derive(Clone, Debug)]
pub struct AuthEncryptionConfig {
    active_key_id: KeyId,
    active_key_source: SecretSource,
    decrypt_only_keys: Vec<VersionedSecretSource>,
}

impl AuthEncryptionConfig {
    /// Returns the identity used for newly encrypted authentication state.
    pub const fn active_key_id(&self) -> &KeyId {
        &self.active_key_id
    }

    /// Iterates the distinct identities accepted only for decryption.
    pub fn decrypt_only_key_ids(&self) -> impl Iterator<Item = &KeyId> {
        self.decrypt_only_keys
            .iter()
            .map(VersionedSecretSource::key_id)
    }

    /// Loads the exact-length active and decrypt-only key material.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error for unavailable, malformed, or conflicting keys.
    pub fn load_local_keyring(&self) -> Result<LocalAes256GcmKeyring, SecretEncryptionLoadError> {
        let active = load_local_key_material(&self.active_key_id, &self.active_key_source)?;
        let decrypt_only = self
            .decrypt_only_keys
            .iter()
            .map(|key| load_local_key_material(key.key_id(), key.source()))
            .collect::<Result<Vec<_>, _>>()?;
        LocalAes256GcmKeyring::new(active, decrypt_only, [])
            .map_err(|_| SecretEncryptionLoadError::InvalidKeyConfiguration)
    }
}

impl HumanAuthConfig {
    /// Returns the canonical public browser origin.
    pub fn external_url(&self) -> &Url {
        &self.external_url
    }

    /// Returns the exact GitHub OAuth callback derived from the public origin.
    pub fn callback_url(&self) -> &Url {
        &self.callback_url
    }

    /// Returns the validated public GitHub OAuth client identifier.
    pub const fn github_client_id(&self) -> &GithubClientId {
        &self.github_client_id
    }

    /// Returns the active non-secret authentication wrapping-key identity.
    pub fn encryption_key_id(&self) -> &str {
        self.encryption.active_key_id().as_str()
    }

    /// Returns the rotation-aware authentication encryption configuration.
    pub const fn encryption(&self) -> &AuthEncryptionConfig {
        &self.encryption
    }

    /// Returns the validated absolute lifetime for browser sessions.
    pub const fn browser_session_ttl(&self) -> Duration {
        self.browser_session_ttl
    }

    /// Returns the validated absolute lifetime for CLI sessions.
    pub const fn cli_session_ttl(&self) -> Duration {
        self.cli_session_ttl
    }

    /// Returns one-use installation bootstrap configuration when explicitly enabled.
    pub const fn bootstrap(&self) -> Option<&BootstrapConfig> {
        self.bootstrap.as_ref()
    }

    /// Loads the bounded GitHub OAuth client secret.
    ///
    /// # Errors
    ///
    /// Returns a sanitized source error when the reference is unavailable,
    /// insecure, malformed, or exceeds its scalar byte limit.
    pub fn load_github_client_secret(&self) -> Result<Zeroizing<String>, SecretLoadError> {
        self.github_client_secret
            .load_scalar(MAX_GITHUB_CLIENT_SECRET_BYTES)
    }

    /// Loads the exact-length key used to hash opaque session credentials.
    ///
    /// # Errors
    ///
    /// Returns a sanitized source error when the reference cannot be read
    /// securely or does not contain exactly the required number of bytes.
    pub fn load_session_hash_key(&self) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
        load_exact_bytes(&self.session_hash_key, SESSION_HASH_KEY_BYTES)
    }
}

/// Optional one-use proof and exact provider identity for secure installation setup.
#[derive(Clone, Debug)]
pub struct BootstrapConfig {
    token: SecretSource,
    github_user_id: u64,
    tenant: InstallationTenant,
}

impl BootstrapConfig {
    /// Returns the exact nonzero GitHub user identity allowed to bootstrap installation.
    pub const fn github_user_id(&self) -> u64 {
        self.github_user_id
    }

    /// Returns the validated tenant identity and display name to create.
    pub const fn tenant(&self) -> &InstallationTenant {
        &self.tenant
    }

    /// Loads the bounded one-use installation proof token.
    ///
    /// # Errors
    ///
    /// Returns a sanitized source error when the reference cannot be read as a
    /// scalar or when its value is shorter than the minimum entropy boundary.
    pub fn load_token(&self) -> Result<Zeroizing<String>, SecretLoadError> {
        let token = self.token.load_scalar(MAX_BOOTSTRAP_TOKEN_BYTES)?;
        if token.len() < MIN_BOOTSTRAP_TOKEN_BYTES {
            return Err(SecretLoadError::TooShort {
                minimum: MIN_BOOTSTRAP_TOKEN_BYTES,
            });
        }
        Ok(token)
    }
}

impl ServerConfig {
    /// Converts parsed CLI values into bounded deployment configuration.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid endpoint or duration configuration.
    pub fn from_args(args: &ServerArgs) -> Result<Self, ServerConfigError> {
        validate_server_secret_sources(args)?;
        validate_local_listeners(args)?;
        validate_fallback_tenant(&args.fallback_tenant_id)?;
        let s3_endpoint =
            Url::parse(&args.s3_endpoint).map_err(|_| ServerConfigError::InvalidS3Endpoint)?;
        let s3_at_rest_encryption = s3_at_rest_encryption(args.s3_kms_key_id.as_deref())?;
        if args.database_max_connections == 0 {
            return Err(ServerConfigError::InvalidDatabaseConnections);
        }
        let s3_operation_timeout = positive_seconds(args.s3_operation_timeout_seconds)?;
        let readiness_probe_interval = positive_seconds(args.readiness_probe_interval_seconds)?;
        let maintenance_interval = positive_seconds(args.maintenance_interval_seconds)?;
        let maintenance_batch_size = MaintenanceBatchSize::new(args.maintenance_batch_size)
            .map_err(|_| ServerConfigError::InvalidMaintenancePolicy)?;
        let maximum_lease_failures = LeaseFailureLimit::new(args.maximum_lease_failures)
            .map_err(|_| ServerConfigError::InvalidMaintenancePolicy)?;
        let stale_timeout_millis = args
            .stale_runner_session_timeout_seconds
            .checked_mul(1_000)
            .ok_or(ServerConfigError::InvalidMaintenancePolicy)?;
        let stale_runner_session_timeout = StaleSessionTimeoutMillis::new(stale_timeout_millis)
            .map_err(|_| ServerConfigError::InvalidMaintenancePolicy)?;
        if u128::from(stale_timeout_millis) <= maintenance_interval.as_millis() {
            return Err(ServerConfigError::InvalidMaintenancePolicy);
        }
        let (results_public_endpoint, results_key_id) = results_configuration(args)?;
        let github_provider = args
            .github_provider_config_source
            .as_ref()
            .map(GithubProviderConfig::load)
            .transpose()
            .map_err(|_| ServerConfigError::InvalidGithubProviderConfiguration)?;
        let github_oidc = args
            .github_oidc_config_source
            .as_ref()
            .map(|source| GithubOidcConfig::load(source, &results_public_endpoint))
            .transpose()
            .map_err(|_| ServerConfigError::InvalidGithubOidcConfiguration)?;
        let human_auth = human_auth_configuration(args)?;
        let conformance_export_token = conformance_export_configuration(args, human_auth.as_ref())?;
        let secret_encryption = secret_encryption_configuration(args)?;
        let runner_public_authority = runner_public_authority_configuration(args)?;
        if (secret_encryption.is_some() || human_auth.is_some())
            && runner_public_authority.is_none()
        {
            return Err(ServerConfigError::MissingRunnerPublicEndpoint);
        }
        let control_plane_encryption = control_plane_encryption_configuration(args)?;
        let management = management_configuration(args)?;
        Ok(Self {
            http_listen: args.listen,
            metrics_listen: args.metrics_listen,
            human_auth,
            conformance_export_token,
            secret_encryption,
            control_plane_encryption,
            runner_listen: args.runner_listen,
            runner_public_authority,
            results_listen: args.results_listen,
            results_public_endpoint,
            results_signing_key: args.results_signing_key_source.clone(),
            results_key_id,
            github_provider,
            github_oidc,
            database_url: args.database_url_source.clone(),
            database_max_connections: args.database_max_connections,
            database_transport_security: match args.database_transport {
                DatabaseTransport::VerifyFull => PostgresTransportSecurity::VerifyFull,
                DatabaseTransport::LoopbackPlaintext => {
                    PostgresTransportSecurity::LoopbackPlaintext
                }
            },
            s3_endpoint,
            s3_region: args.s3_region.clone(),
            s3_bucket: args.s3_bucket.clone(),
            s3_prefix: args.s3_prefix.clone(),
            s3_force_path_style: args.s3_force_path_style,
            s3_at_rest_encryption,
            s3_allow_loopback_http: args.s3_allow_loopback_http,
            s3_operation_timeout,
            s3_access_key: args.s3_access_key_source.clone(),
            s3_secret_key: args.s3_secret_key_source.clone(),
            s3_session_token: args.s3_session_token_source.clone(),
            runner_client_ca_certificate: args.runner_client_ca_certificate_source.clone(),
            runner_client_ca_private_key: args.runner_client_ca_key_source.clone(),
            runner_server_ca: args.runner_server_ca_source.clone(),
            runner_server_certificate: args.runner_server_certificate_source.clone(),
            runner_server_private_key: args.runner_server_key_source.clone(),
            management,
            readiness_probe_interval,
            maintenance_interval,
            maintenance_batch_size,
            maximum_lease_failures,
            stale_runner_session_timeout,
            fallback_tenant_id: args.fallback_tenant_id.clone(),
        })
    }

    /// Returns complete human-authentication configuration when explicitly enabled.
    pub const fn human_auth(&self) -> Option<&HumanAuthConfig> {
        self.human_auth.as_ref()
    }

    /// Loads the optional loopback-only conformance export bearer.
    ///
    /// # Errors
    ///
    /// Returns a sanitized source error when the credential is unavailable,
    /// malformed, or below the minimum entropy boundary.
    pub fn load_conformance_export_token(
        &self,
    ) -> Result<Option<Zeroizing<String>>, SecretLoadError> {
        self.conformance_export_token
            .as_ref()
            .map(|source| {
                let token = source.load_scalar(MAX_CONFORMANCE_EXPORT_TOKEN_BYTES)?;
                if token.len() < MIN_CONFORMANCE_EXPORT_TOKEN_BYTES {
                    return Err(SecretLoadError::TooShort {
                        minimum: MIN_CONFORMANCE_EXPORT_TOKEN_BYTES,
                    });
                }
                Ok(token)
            })
            .transpose()
    }

    /// Returns built-in secret encryption configuration when explicitly enabled.
    pub const fn secret_encryption(&self) -> Option<&SecretEncryptionConfig> {
        self.secret_encryption.as_ref()
    }

    /// Returns the mandatory encryption configuration for durable control-plane payloads.
    pub const fn control_plane_encryption(&self) -> &ControlPlaneEncryptionConfig {
        &self.control_plane_encryption
    }

    /// Returns the private shard-management configuration when explicitly enabled.
    pub const fn management(&self) -> Option<&ManagementConfig> {
        self.management.as_ref()
    }

    /// Returns the strict GitHub provider registry only when explicitly enabled.
    pub const fn github_provider(&self) -> Option<&GithubProviderConfig> {
        self.github_provider.as_ref()
    }

    /// Returns the complete OIDC configuration only when its strict manifest is enabled.
    pub const fn github_oidc(&self) -> Option<&GithubOidcConfig> {
        self.github_oidc.as_ref()
    }

    pub(crate) fn load_database_url(&self) -> Result<Zeroizing<String>, SecretLoadError> {
        self.database_url.load_scalar(MAX_DATABASE_URL_BYTES)
    }

    pub(crate) fn load_s3_access_key(&self) -> Result<Zeroizing<String>, SecretLoadError> {
        self.s3_access_key.load_scalar(MAX_S3_CREDENTIAL_BYTES)
    }

    pub(crate) fn load_s3_secret_key(&self) -> Result<Zeroizing<String>, SecretLoadError> {
        self.s3_secret_key.load_scalar(MAX_S3_CREDENTIAL_BYTES)
    }

    pub(crate) fn load_s3_session_token(
        &self,
    ) -> Result<Option<Zeroizing<String>>, SecretLoadError> {
        self.s3_session_token
            .as_ref()
            .map(|source| source.load_scalar(MAX_S3_CREDENTIAL_BYTES))
            .transpose()
    }

    pub(crate) fn load_client_ca_pem(&self) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
        self.runner_client_ca_certificate
            .load_bytes(MAX_CA_PEM_BYTES)
    }

    pub(crate) fn load_client_ca_private_key_pem(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
        self.runner_client_ca_private_key
            .load_bytes(MAX_PRIVATE_KEY_PEM_BYTES)
    }

    pub(crate) fn load_runner_server_ca_pem(&self) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
        self.runner_server_ca.load_bytes(MAX_CA_PEM_BYTES)
    }

    pub(crate) fn load_server_certificate_pem(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
        self.runner_server_certificate
            .load_bytes(MAX_CERTIFICATE_PEM_BYTES)
    }

    pub(crate) fn load_server_private_key_pem(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
        self.runner_server_private_key
            .load_bytes(MAX_PRIVATE_KEY_PEM_BYTES)
    }

    pub(crate) fn load_results_signing_key(&self) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
        self.results_signing_key
            .load_bytes(MAX_RESULTS_SIGNING_KEY_BYTES)
    }
}

fn validate_fallback_tenant(value: &str) -> Result<(), ServerConfigError> {
    if value.is_empty()
        || value.len() > 255
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ServerConfigError::InvalidFallbackTenant);
    }
    Ok(())
}

fn validate_local_listeners(args: &ServerArgs) -> Result<(), ServerConfigError> {
    if args.listen.port() == 0 || args.runner_listen.port() == 0 || args.results_listen.port() == 0
    {
        return Err(ServerConfigError::InvalidServiceListener);
    }
    if args.human_trusted_reverse_proxy == args.auth_allow_loopback_http
        && (args.human_trusted_reverse_proxy || !args.listen.ip().is_loopback())
    {
        return Err(ServerConfigError::InvalidHumanListenerPolicy);
    }
    if args
        .metrics_listen
        .is_some_and(|listen| !listen.ip().is_loopback() || listen.port() == 0)
    {
        return Err(ServerConfigError::MetricsRequiresLoopback);
    }
    Ok(())
}

fn management_configuration(
    args: &ServerArgs,
) -> Result<Option<ManagementConfig>, ServerConfigError> {
    let configured = args.management_listen.is_some()
        || args.management_shard_id.is_some()
        || args.management_authority_id.is_some()
        || args.management_delegated_actor_issuer.is_some()
        || args.management_delegated_actor_jwks_url.is_some()
        || args.management_delegated_actor_jwks_allow_loopback_http
        || !args.management_client_certificate_sha256.is_empty()
        || args.management_client_ca_certificate_source.is_some()
        || args.management_server_certificate_source.is_some()
        || args.management_server_key_source.is_some();
    if !configured {
        return Ok(None);
    }

    let listen = args
        .management_listen
        .filter(|listen| listen.port() != 0)
        .ok_or(ServerConfigError::InvalidManagementConfiguration)?;
    let shard_id = args
        .management_shard_id
        .as_deref()
        .ok_or(ServerConfigError::InvalidManagementConfiguration)
        .and_then(|value| {
            ShardId::new(value.to_owned())
                .map_err(|_| ServerConfigError::InvalidManagementConfiguration)
        })?;
    let authority_id = args
        .management_authority_id
        .as_deref()
        .ok_or(ServerConfigError::InvalidManagementConfiguration)
        .and_then(|value| {
            ProvisioningAuthorityId::new(value.to_owned())
                .map_err(|_| ServerConfigError::InvalidManagementConfiguration)
        })?;
    let delegated_actor_issuer = args
        .management_delegated_actor_issuer
        .as_deref()
        .ok_or(ServerConfigError::InvalidManagementConfiguration)
        .and_then(|value| {
            DelegatedActorIssuer::new(value.to_owned())
                .map_err(|_| ServerConfigError::InvalidManagementConfiguration)
        })?;
    let delegated_actor_jwks_url = args
        .management_delegated_actor_jwks_url
        .as_deref()
        .filter(|value| value.len() <= MAX_DELEGATED_ACTOR_JWKS_URL_BYTES)
        .ok_or(ServerConfigError::InvalidManagementConfiguration)
        .and_then(|value| {
            Url::parse(value).map_err(|_| ServerConfigError::InvalidManagementConfiguration)
        })?;
    validate_delegated_actor_jwks_url(
        &delegated_actor_jwks_url,
        args.management_delegated_actor_jwks_allow_loopback_http,
    )?;
    if args.management_client_certificate_sha256.is_empty()
        || args.management_client_certificate_sha256.len() > MAX_MANAGEMENT_CLIENT_CERTIFICATES
    {
        return Err(ServerConfigError::InvalidManagementConfiguration);
    }
    let mut unique_fingerprints = BTreeSet::new();
    for encoded in &args.management_client_certificate_sha256 {
        let fingerprint = decode_sha256_fingerprint(encoded)
            .ok_or(ServerConfigError::InvalidManagementConfiguration)?;
        if !unique_fingerprints.insert(fingerprint) {
            return Err(ServerConfigError::InvalidManagementConfiguration);
        }
    }
    let client_ca_certificate = args
        .management_client_ca_certificate_source
        .clone()
        .ok_or(ServerConfigError::InvalidManagementConfiguration)?;
    let server_certificate = args
        .management_server_certificate_source
        .clone()
        .ok_or(ServerConfigError::InvalidManagementConfiguration)?;
    let server_private_key = args
        .management_server_key_source
        .clone()
        .ok_or(ServerConfigError::InvalidManagementConfiguration)?;

    Ok(Some(ManagementConfig {
        listen,
        authority: ProvisioningAuthority::new(authority_id, shard_id, delegated_actor_issuer),
        delegated_actor_jwks_url,
        client_certificate_sha256: unique_fingerprints.into_iter().collect(),
        client_ca_certificate,
        server_certificate,
        server_private_key,
    }))
}

fn validate_delegated_actor_jwks_url(
    url: &Url,
    allow_loopback_http: bool,
) -> Result<(), ServerConfigError> {
    let has_safe_shape = url.host().is_some()
        && url.port_or_known_default().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none();
    let transport_allowed = match url.scheme() {
        "https" => true,
        "http" if allow_loopback_http => match url.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            Some(url::Host::Domain(_)) | None => false,
        },
        _ => false,
    };
    if !has_safe_shape || !transport_allowed {
        return Err(ServerConfigError::InvalidManagementConfiguration);
    }
    Ok(())
}

fn decode_sha256_fingerprint(encoded: &str) -> Option<[u8; 32]> {
    if encoded.len() != 64 || !encoded.is_ascii() {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    Some(decoded)
}

const fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn runner_public_authority_configuration(
    args: &ServerArgs,
) -> Result<Option<Authority>, ServerConfigError> {
    let Some(value) = args.runner_public_url.as_deref() else {
        return Ok(None);
    };
    let uri = value
        .parse::<Uri>()
        .map_err(|_| ServerConfigError::InvalidRunnerPublicEndpoint)?;
    let path = uri.path_and_query().map_or("", |value| value.as_str());
    if uri.scheme_str() != Some("https")
        || !matches!(path, "" | "/")
        || uri
            .authority()
            .is_none_or(|authority| authority.as_str().contains('@'))
    {
        return Err(ServerConfigError::InvalidRunnerPublicEndpoint);
    }
    Ok(uri.authority().cloned())
}

fn control_plane_encryption_configuration(
    args: &ServerArgs,
) -> Result<ControlPlaneEncryptionConfig, ServerConfigError> {
    let active_key_source = &args.control_plane_encryption_key_source;
    if !active_key_source.is_valid_reference() {
        return Err(ServerConfigError::InvalidSecretSource);
    }
    let active_key_id = KeyId::new(args.control_plane_encryption_key_id.clone())
        .map_err(|_| ServerConfigError::InvalidControlPlaneEncryptionConfiguration)?;
    let mut key_ids = BTreeSet::from([active_key_id.clone()]);
    if args
        .control_plane_decryption_keys
        .iter()
        .any(|key| !key.source().is_valid_reference() || !key_ids.insert(key.key_id().clone()))
    {
        return Err(ServerConfigError::InvalidControlPlaneEncryptionConfiguration);
    }
    Ok(ControlPlaneEncryptionConfig {
        active_key_id,
        active_key_source: active_key_source.clone(),
        decrypt_only_keys: args.control_plane_decryption_keys.clone(),
    })
}

fn secret_encryption_configuration(
    args: &ServerArgs,
) -> Result<Option<SecretEncryptionConfig>, ServerConfigError> {
    let Some(active_key_source) = args.secret_encryption_key_source.as_ref() else {
        if args.secret_decryption_keys.is_empty() {
            return Ok(None);
        }
        return Err(ServerConfigError::InvalidSecretEncryptionConfiguration);
    };
    if !active_key_source.is_valid_reference() {
        return Err(ServerConfigError::InvalidSecretSource);
    }
    let active_key_id = KeyId::new(args.secret_encryption_key_id.clone())
        .map_err(|_| ServerConfigError::InvalidSecretEncryptionConfiguration)?;
    let mut key_ids = BTreeSet::from([active_key_id.clone()]);
    if args
        .secret_decryption_keys
        .iter()
        .any(|key| !key.source().is_valid_reference() || !key_ids.insert(key.key_id().clone()))
    {
        return Err(ServerConfigError::InvalidSecretEncryptionConfiguration);
    }
    Ok(Some(SecretEncryptionConfig {
        active_key_id,
        active_key_source: active_key_source.clone(),
        decrypt_only_keys: args.secret_decryption_keys.clone(),
    }))
}

fn load_local_key_material(
    key_id: &KeyId,
    source: &SecretSource,
) -> Result<LocalKeyMaterial, SecretEncryptionLoadError> {
    let mut loaded = source.load_bytes(SECRET_ENCRYPTION_KEY_BYTES)?;
    if loaded.len() != SECRET_ENCRYPTION_KEY_BYTES {
        return Err(SecretEncryptionLoadError::InvalidKeyConfiguration);
    }
    let bytes = std::mem::take(&mut *loaded);
    let secret = KeySecretBytes::new(bytes)
        .map_err(|_| SecretEncryptionLoadError::InvalidKeyConfiguration)?;
    LocalKeyMaterial::new(key_id.clone(), secret)
        .map_err(|_| SecretEncryptionLoadError::InvalidKeyConfiguration)
}

fn load_exact_bytes(
    source: &SecretSource,
    expected: usize,
) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
    let bytes = source.load_bytes(expected)?;
    if bytes.len() != expected {
        return Err(SecretLoadError::InvalidLength { expected });
    }
    Ok(bytes)
}

fn s3_at_rest_encryption(
    kms_key_id: Option<&str>,
) -> Result<S3AtRestEncryption, ServerConfigError> {
    kms_key_id
        .map(S3AtRestEncryption::aws_kms)
        .transpose()
        .map_err(|_| ServerConfigError::InvalidS3Encryption)
        .map(|encryption| encryption.unwrap_or_else(S3AtRestEncryption::aes256))
}

fn human_auth_configuration(
    args: &ServerArgs,
) -> Result<Option<HumanAuthConfig>, ServerConfigError> {
    let requested = args.external_url.is_some()
        || args.auth_allow_loopback_http
        || args.github_client_id.is_some()
        || args.github_client_secret_source.is_some()
        || args.auth_session_hash_key_source.is_some()
        || args.auth_encryption_key_source.is_some()
        || !args.auth_decryption_keys.is_empty()
        || args.bootstrap_token_source.is_some()
        || args.bootstrap_github_user_id.is_some()
        || args.bootstrap_tenant_id.is_some()
        || args.bootstrap_tenant_display_name.is_some();
    if !requested {
        return Ok(None);
    }

    let external_url = args
        .external_url
        .as_deref()
        .ok_or(ServerConfigError::IncompleteHumanAuth)
        .and_then(|value| Url::parse(value).map_err(|_| ServerConfigError::InvalidExternalUrl))?;
    validate_external_url(args, &external_url)?;

    let github_client_id = args
        .github_client_id
        .as_ref()
        .ok_or(ServerConfigError::IncompleteHumanAuth)
        .and_then(|value| {
            GithubClientId::new(value.clone()).map_err(|_| ServerConfigError::InvalidGithubClientId)
        })?;
    let github_client_secret = required_auth_source(args.github_client_secret_source.as_ref())?;
    let session_hash_key = required_auth_source(args.auth_session_hash_key_source.as_ref())?;
    let encryption_key = required_auth_source(args.auth_encryption_key_source.as_ref())?;
    let encryption_key_id =
        KeyId::new(args.auth_key_id.clone()).map_err(|_| ServerConfigError::InvalidAuthKeyId)?;
    let mut encryption_key_ids = BTreeSet::from([encryption_key_id.clone()]);
    if args.auth_decryption_keys.iter().any(|key| {
        !key.source().is_valid_reference() || !encryption_key_ids.insert(key.key_id().clone())
    }) {
        return Err(ServerConfigError::InvalidAuthKeyId);
    }
    if !(MIN_BROWSER_SESSION_TTL_SECONDS..=MAX_BROWSER_SESSION_TTL_SECONDS)
        .contains(&args.auth_browser_session_ttl_seconds)
        || !(MIN_CLI_SESSION_TTL_SECONDS..=MAX_CLI_SESSION_TTL_SECONDS)
            .contains(&args.auth_cli_session_ttl_seconds)
    {
        return Err(ServerConfigError::InvalidAuthSessionLifetime);
    }

    let bootstrap = match (
        args.bootstrap_token_source.as_ref(),
        args.bootstrap_github_user_id,
        args.bootstrap_tenant_id.as_ref(),
        args.bootstrap_tenant_display_name.as_ref(),
    ) {
        (None, None, None, None) => None,
        (Some(token), Some(github_user_id), Some(tenant_id), Some(display_name))
            if token.is_valid_reference() && github_user_id > 0 =>
        {
            let tenant = InstallationTenant::new(
                automata_ci_auth::human::TenantId::new(tenant_id.clone())
                    .map_err(|_| ServerConfigError::InvalidBootstrapConfiguration)?,
                display_name.clone(),
            )
            .map_err(|_| ServerConfigError::InvalidBootstrapConfiguration)?;
            Some(BootstrapConfig {
                token: token.clone(),
                github_user_id,
                tenant,
            })
        }
        _ => return Err(ServerConfigError::InvalidBootstrapConfiguration),
    };
    let callback_url = external_url
        .join("auth/github/callback")
        .map_err(|_| ServerConfigError::InvalidExternalUrl)?;

    Ok(Some(HumanAuthConfig {
        external_url,
        callback_url,
        github_client_id,
        github_client_secret,
        session_hash_key,
        encryption: AuthEncryptionConfig {
            active_key_id: encryption_key_id,
            active_key_source: encryption_key,
            decrypt_only_keys: args.auth_decryption_keys.clone(),
        },
        browser_session_ttl: Duration::from_secs(args.auth_browser_session_ttl_seconds),
        cli_session_ttl: Duration::from_secs(args.auth_cli_session_ttl_seconds),
        bootstrap,
    }))
}

fn required_auth_source(source: Option<&SecretSource>) -> Result<SecretSource, ServerConfigError> {
    match source {
        Some(source) if source.is_valid_reference() => Ok(source.clone()),
        Some(_) => Err(ServerConfigError::InvalidSecretSource),
        None => Err(ServerConfigError::IncompleteHumanAuth),
    }
}

fn conformance_export_configuration(
    args: &ServerArgs,
    human_auth: Option<&HumanAuthConfig>,
) -> Result<Option<SecretSource>, ServerConfigError> {
    let Some(source) = args.conformance_export_token_source.as_ref() else {
        return Ok(None);
    };
    if !source.is_valid_reference() || !args.listen.ip().is_loopback() || human_auth.is_some() {
        return Err(ServerConfigError::InvalidConformanceExportConfiguration);
    }
    Ok(Some(source.clone()))
}

fn validate_server_secret_sources(args: &ServerArgs) -> Result<(), ServerConfigError> {
    let required = [
        &args.database_url_source,
        &args.results_signing_key_source,
        &args.control_plane_encryption_key_source,
        &args.s3_access_key_source,
        &args.s3_secret_key_source,
        &args.runner_client_ca_certificate_source,
        &args.runner_client_ca_key_source,
        &args.runner_server_ca_source,
        &args.runner_server_certificate_source,
        &args.runner_server_key_source,
    ];
    let optional = [
        args.s3_session_token_source.as_ref(),
        args.github_provider_config_source.as_ref(),
        args.github_oidc_config_source.as_ref(),
        args.conformance_export_token_source.as_ref(),
        args.management_client_ca_certificate_source.as_ref(),
        args.management_server_certificate_source.as_ref(),
        args.management_server_key_source.as_ref(),
    ];
    if required
        .into_iter()
        .any(|source| !source.is_valid_reference())
        || optional
            .into_iter()
            .flatten()
            .any(|source| !source.is_valid_reference())
    {
        return Err(ServerConfigError::InvalidSecretSource);
    }
    Ok(())
}

fn validate_external_url(args: &ServerArgs, external_url: &Url) -> Result<(), ServerConfigError> {
    if external_url.cannot_be_a_base()
        || external_url.host_str().is_none()
        || !external_url.username().is_empty()
        || external_url.password().is_some()
        || external_url.query().is_some()
        || external_url.fragment().is_some()
        || external_url.path() != "/"
    {
        return Err(ServerConfigError::InvalidExternalUrl);
    }
    match external_url.scheme() {
        "https" if !args.auth_allow_loopback_http => Ok(()),
        "http" if args.auth_allow_loopback_http && args.listen.ip().is_loopback() => {
            let host = external_url
                .host_str()
                .and_then(|host| host.parse::<IpAddr>().ok())
                .filter(IpAddr::is_loopback)
                .ok_or(ServerConfigError::InvalidExternalUrl)?;
            if host.is_loopback() {
                Ok(())
            } else {
                Err(ServerConfigError::InvalidExternalUrl)
            }
        }
        _ => Err(ServerConfigError::InvalidExternalUrl),
    }
}

fn results_configuration(
    args: &ServerArgs,
) -> Result<(ResultsPublicEndpoint, String), ServerConfigError> {
    let results_url = args
        .results_public_url
        .as_deref()
        .ok_or(ServerConfigError::MissingResultsEndpoint)
        .and_then(|value| {
            Url::parse(value).map_err(|_| ServerConfigError::InvalidResultsEndpoint)
        })?;
    let endpoint = match results_url.scheme() {
        "https"
            if !args.results_allow_development_http
                && args.results_trusted_private_host.is_none()
                && (args.results_listen.ip().is_loopback()
                    || args.results_trusted_reverse_proxy) =>
        {
            ResultsPublicEndpoint::https(results_url)
        }
        "http" if args.results_allow_development_http => {
            development_results_endpoint(args, results_url)
        }
        _ => return Err(ServerConfigError::InvalidResultsEndpoint),
    }
    .map_err(|_| ServerConfigError::InvalidResultsEndpoint)?;
    let key_id = args.results_key_id.clone();
    if key_id.is_empty()
        || key_id.len() > MAX_RESULTS_KEY_ID_BYTES
        || !key_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ServerConfigError::InvalidResultsKeyId);
    }
    Ok((endpoint, key_id))
}

fn development_results_endpoint(
    args: &ServerArgs,
    results_url: Url,
) -> Result<ResultsPublicEndpoint, automata_ci_results_github::TokenError> {
    if args.results_listen.ip().is_loopback() {
        if args.results_trusted_private_host.is_some() {
            return Err(automata_ci_results_github::TokenError::Policy);
        }
        return ResultsPublicEndpoint::loopback_development(results_url, args.results_listen);
    }
    let trusted_host = args
        .results_trusted_private_host
        .as_deref()
        .ok_or(automata_ci_results_github::TokenError::Policy)?;
    ResultsPublicEndpoint::trusted_private_development(
        results_url,
        args.results_listen,
        trusted_host,
    )
}

/// Invalid server deployment configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ServerConfigError {
    /// A credential option did not contain an environment or file reference.
    #[error("secret configuration must use env:NAME or file:PATH references")]
    InvalidSecretSource,
    /// Human authentication was requested without every required field.
    #[error("human authentication configuration is incomplete")]
    IncompleteHumanAuth,
    /// The canonical browser origin is not an exact secure origin.
    #[error("external authentication URL policy is invalid")]
    InvalidExternalUrl,
    /// The public GitHub OAuth client identifier is malformed.
    #[error("GitHub client identity is invalid")]
    InvalidGithubClientId,
    /// The non-secret authentication encryption-key identity is malformed.
    #[error("authentication key identity is invalid")]
    InvalidAuthKeyId,
    /// Browser or CLI session lifetime is outside the bounded policy.
    #[error("authentication session lifetime is invalid")]
    InvalidAuthSessionLifetime,
    /// Setup requires both a one-use proof source and a nonzero stable GitHub user ID.
    #[error("installation bootstrap configuration is invalid")]
    InvalidBootstrapConfiguration,
    /// Built-in secret-provider key sources or identities are incomplete or inconsistent.
    #[error("built-in secret encryption configuration is invalid")]
    InvalidSecretEncryptionConfiguration,
    /// Durable control-plane key sources or identities are invalid or inconsistent.
    #[error("control-plane encryption configuration is invalid")]
    InvalidControlPlaneEncryptionConfiguration,
    /// The S3 endpoint is not an absolute URL.
    #[error("S3 endpoint is not a valid URL")]
    InvalidS3Endpoint,
    /// The configured server-side encryption key identity is malformed.
    #[error("S3 server-side encryption configuration is invalid")]
    InvalidS3Encryption,
    /// The `PostgreSQL` pool size is zero.
    #[error("database maximum connections must be greater than zero")]
    InvalidDatabaseConnections,
    /// A configured duration is zero.
    #[error("server durations must be greater than zero")]
    InvalidDuration,
    /// Bounded maintenance policy fields are inconsistent or out of range.
    #[error("control-plane maintenance policy is invalid")]
    InvalidMaintenancePolicy,
    /// The unauthenticated operations endpoint requires a nonzero loopback socket.
    #[error("metrics listener requires a nonzero literal loopback address")]
    MetricsRequiresLoopback,
    /// Human/webhook listener exposure lacks one coherent isolation policy.
    #[error("human and webhook listener isolation policy is invalid")]
    InvalidHumanListenerPolicy,
    /// Machine conformance authority requires an exact source, loopback bind,
    /// and disabled human authentication.
    #[error("conformance export authentication configuration is invalid")]
    InvalidConformanceExportConfiguration,
    /// A mandatory service listener requested an ephemeral port.
    #[error("human, Results, and runner listeners require nonzero ports")]
    InvalidServiceListener,
    /// No public Results endpoint was supplied for per-attempt credentials.
    #[error("a public Results endpoint is required")]
    MissingResultsEndpoint,
    /// Secret delivery requires the exact public direct-mTLS runner origin.
    #[error("a public runner-control endpoint is required for managed secrets")]
    MissingRunnerPublicEndpoint,
    /// The public runner-control endpoint is not an exact HTTPS origin.
    #[error("runner-control endpoint policy is invalid")]
    InvalidRunnerPublicEndpoint,
    /// Results endpoint/listener transport policy is invalid or inconsistent.
    #[error("Results endpoint policy is invalid")]
    InvalidResultsEndpoint,
    /// The non-secret Results signing-key identity is malformed.
    #[error("Results key identity is invalid")]
    InvalidResultsKeyId,
    /// The optional OIDC manifest is incomplete, malformed, excessive, or requires plaintext.
    #[error("GitHub-compatible OIDC configuration is invalid")]
    InvalidGithubOidcConfiguration,
    /// The optional GitHub provider registry is malformed, excessive, or incoherent.
    #[error("GitHub provider configuration is invalid")]
    InvalidGithubProviderConfiguration,
    /// The opt-in mTLS management listener is partial, malformed, or unbounded.
    #[error("management listener configuration is invalid")]
    InvalidManagementConfiguration,
    /// The unauthenticated fallback tenant identity is malformed.
    #[error("fallback tenant identity is invalid")]
    InvalidFallbackTenant,
}

/// Sanitized failure while loading the built-in provider's local keyring.
#[derive(Debug, Error)]
pub enum SecretEncryptionLoadError {
    /// A bounded deployment secret source could not be loaded.
    #[error(transparent)]
    Source(#[from] SecretLoadError),
    /// Key material was not exact-length or key identities conflicted.
    #[error("built-in secret encryption key configuration is invalid")]
    InvalidKeyConfiguration,
}

fn positive_seconds(seconds: u64) -> Result<Duration, ServerConfigError> {
    if seconds == 0 {
        return Err(ServerConfigError::InvalidDuration);
    }
    Ok(Duration::from_secs(seconds))
}

#[cfg(unix)]
fn read_bounded_file(
    path: &Path,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
    use std::ffi::OsString;

    use rustix::{
        fd::OwnedFd,
        fs::{FileType, Mode, OFlags, fstat, openat},
    };

    if !path.is_absolute() || maximum_bytes == 0 {
        return Err(SecretLoadError::FileSecurity);
    }
    let mut components = Vec::<OsString>::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {}
            Component::Normal(value) => components.push(value.to_os_string()),
            Component::CurDir | Component::ParentDir => {
                return Err(SecretLoadError::FileSecurity);
            }
        }
    }
    let (file_name, parents) = components
        .split_last()
        .ok_or(SecretLoadError::FileSecurity)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut directory: OwnedFd = rustix::fs::open("/", directory_flags, Mode::empty())
        .map_err(|_| SecretLoadError::FileSecurity)?;
    for component in parents {
        directory = openat(&directory, component, directory_flags, Mode::empty())
            .map_err(|_| SecretLoadError::FileSecurity)?;
        let metadata = fstat(&directory).map_err(|_| SecretLoadError::FileSecurity)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
            return Err(SecretLoadError::FileSecurity);
        }
    }
    let file = openat(
        &directory,
        file_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| SecretLoadError::FileSecurity)?;
    let metadata = fstat(&file).map_err(|_| SecretLoadError::FileSecurity)?;
    let permission_bits = metadata.st_mode & 0o777;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || permission_bits & 0o400 == 0
        || permission_bits & 0o077 != 0
    {
        return Err(SecretLoadError::FileSecurity);
    }
    let received = u64::try_from(metadata.st_size).unwrap_or(u64::MAX);
    if received > u64::try_from(maximum_bytes).unwrap_or(u64::MAX) {
        return Err(SecretLoadError::TooLarge {
            maximum: maximum_bytes,
        });
    }
    let capacity = usize::try_from(received).unwrap_or(maximum_bytes);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity.min(maximum_bytes)));
    let take_limit = u64::try_from(maximum_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    File::from(file)
        .take(take_limit)
        .read_to_end(&mut bytes)
        .map_err(SecretLoadError::File)?;
    if bytes.len() > maximum_bytes {
        return Err(SecretLoadError::TooLarge {
            maximum: maximum_bytes,
        });
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_bounded_file(
    _path: &Path,
    _maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
    Err(SecretLoadError::FileSecurity)
}
