use std::{
    convert::Infallible,
    env, fmt,
    fs::File,
    io::{self, Read as _},
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use automata_results_github::ResultsPublicEndpoint;
use automata_store::{LeaseFailureLimit, MaintenanceBatchSize, StaleSessionTimeoutMillis};

use crate::cli::ServerArgs;

const MAX_SOURCE_REFERENCE_BYTES: usize = 4_096;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 255;
const MAX_DATABASE_URL_BYTES: usize = 16 * 1_024;
const MAX_S3_CREDENTIAL_BYTES: usize = 16 * 1_024;
const MAX_CA_PEM_BYTES: usize = 4 * 1_024 * 1_024;
const MAX_CERTIFICATE_PEM_BYTES: usize = 4 * 1_024 * 1_024;
const MAX_PRIVATE_KEY_PEM_BYTES: usize = 1024 * 1024;
const MAX_LOCAL_ADMISSION_TOKEN_BYTES: usize = 4 * 1024;
const MAX_RESULTS_SIGNING_KEY_BYTES: usize = 16 * 1024;
const MAX_RESULTS_KEY_ID_BYTES: usize = 255;

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
            Self::Environment(name) => env::var_os(name)
                .ok_or(SecretLoadError::MissingEnvironment)?
                .into_string()
                .map_err(|_| SecretLoadError::InvalidText)?
                .into_bytes(),
            Self::File(path) => read_bounded_file(path, maximum_bytes)?,
            Self::Invalid => return Err(SecretLoadError::InvalidReference),
        };
        if bytes.len() > maximum_bytes {
            return Err(SecretLoadError::TooLarge {
                maximum: maximum_bytes,
            });
        }
        Ok(Zeroizing::new(bytes))
    }

    /// Loads bounded UTF-8 scalar text, removing one conventional file newline.
    ///
    /// This normalization is suitable for database URLs and S3 credentials, but
    /// not PEM documents. It never trims other leading or trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error for any load failure or invalid UTF-8.
    pub fn load_scalar(&self, maximum_bytes: usize) -> Result<Zeroizing<String>, SecretLoadError> {
        let mut bytes = self.load_bytes(maximum_bytes)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        let text = String::from_utf8(std::mem::take(&mut *bytes))
            .map_err(|_| SecretLoadError::InvalidText)?;
        if text.is_empty() {
            return Err(SecretLoadError::Empty);
        }
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
    /// The source exceeded its context-specific byte ceiling.
    #[error("referenced secret exceeds the {maximum}-byte limit")]
    TooLarge {
        /// Inclusive context-specific byte ceiling.
        maximum: usize,
    },
    /// A textual source was not valid UTF-8.
    #[error("referenced secret is not valid UTF-8 text")]
    InvalidText,
    /// A scalar source contained no bytes after newline normalization.
    #[error("referenced secret is empty")]
    Empty,
}

/// Validated product configuration for one control-plane replica.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub(crate) http_listen: SocketAddr,
    pub(crate) runner_listen: SocketAddr,
    pub(crate) results_listen: SocketAddr,
    pub(crate) results_public_endpoint: ResultsPublicEndpoint,
    pub(crate) results_signing_key: SecretSource,
    pub(crate) results_key_id: String,
    pub(crate) database_url: SecretSource,
    pub(crate) database_max_connections: u32,
    pub(crate) s3_endpoint: Url,
    pub(crate) s3_region: String,
    pub(crate) s3_bucket: String,
    pub(crate) s3_prefix: Option<String>,
    pub(crate) s3_force_path_style: bool,
    pub(crate) s3_allow_loopback_http: bool,
    pub(crate) s3_operation_timeout: Duration,
    pub(crate) s3_access_key: SecretSource,
    pub(crate) s3_secret_key: SecretSource,
    pub(crate) s3_session_token: Option<SecretSource>,
    pub(crate) runner_client_ca: SecretSource,
    pub(crate) runner_server_certificate: SecretSource,
    pub(crate) runner_server_private_key: SecretSource,
    pub(crate) readiness_probe_interval: Duration,
    pub(crate) maintenance_interval: Duration,
    pub(crate) maintenance_batch_size: MaintenanceBatchSize,
    pub(crate) maximum_lease_failures: LeaseFailureLimit,
    pub(crate) stale_runner_session_timeout: StaleSessionTimeoutMillis,
    pub(crate) local_admission_token: Option<SecretSource>,
    pub(crate) local_admission_tenant: String,
}

impl ServerConfig {
    /// Converts parsed CLI values into bounded deployment configuration.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid endpoint or duration configuration.
    pub fn from_args(args: &ServerArgs) -> Result<Self, ServerConfigError> {
        let required_sources = [
            &args.database_url_source,
            &args.results_signing_key_source,
            &args.s3_access_key_source,
            &args.s3_secret_key_source,
            &args.runner_client_ca_source,
            &args.runner_server_certificate_source,
            &args.runner_server_key_source,
        ];
        if required_sources
            .iter()
            .any(|source| !source.is_valid_reference())
            || args
                .s3_session_token_source
                .as_ref()
                .is_some_and(|source| !source.is_valid_reference())
            || args
                .local_admission_token_source
                .as_ref()
                .is_some_and(|source| !source.is_valid_reference())
        {
            return Err(ServerConfigError::InvalidSecretSource);
        }
        if args.local_admission_token_source.is_some() && !args.listen.ip().is_loopback() {
            return Err(ServerConfigError::LocalAdmissionRequiresLoopback);
        }
        if args.local_admission_tenant.is_empty()
            || args.local_admission_tenant.len() > 255
            || args
                .local_admission_tenant
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(ServerConfigError::InvalidLocalAdmissionTenant);
        }
        let s3_endpoint =
            Url::parse(&args.s3_endpoint).map_err(|_| ServerConfigError::InvalidS3Endpoint)?;
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
        Ok(Self {
            http_listen: args.listen,
            runner_listen: args.runner_listen,
            results_listen: args.results_listen,
            results_public_endpoint,
            results_signing_key: args.results_signing_key_source.clone(),
            results_key_id,
            database_url: args.database_url_source.clone(),
            database_max_connections: args.database_max_connections,
            s3_endpoint,
            s3_region: args.s3_region.clone(),
            s3_bucket: args.s3_bucket.clone(),
            s3_prefix: args.s3_prefix.clone(),
            s3_force_path_style: args.s3_force_path_style,
            s3_allow_loopback_http: args.s3_allow_loopback_http,
            s3_operation_timeout,
            s3_access_key: args.s3_access_key_source.clone(),
            s3_secret_key: args.s3_secret_key_source.clone(),
            s3_session_token: args.s3_session_token_source.clone(),
            runner_client_ca: args.runner_client_ca_source.clone(),
            runner_server_certificate: args.runner_server_certificate_source.clone(),
            runner_server_private_key: args.runner_server_key_source.clone(),
            readiness_probe_interval,
            maintenance_interval,
            maintenance_batch_size,
            maximum_lease_failures,
            stale_runner_session_timeout,
            local_admission_token: args.local_admission_token_source.clone(),
            local_admission_tenant: args.local_admission_tenant.clone(),
        })
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
        self.runner_client_ca.load_bytes(MAX_CA_PEM_BYTES)
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

    pub(crate) fn load_local_admission_token(
        &self,
    ) -> Result<Option<Zeroizing<String>>, SecretLoadError> {
        self.local_admission_token
            .as_ref()
            .map(|source| source.load_scalar(MAX_LOCAL_ADMISSION_TOKEN_BYTES))
            .transpose()
    }

    pub(crate) fn load_results_signing_key(&self) -> Result<Zeroizing<Vec<u8>>, SecretLoadError> {
        self.results_signing_key
            .load_bytes(MAX_RESULTS_SIGNING_KEY_BYTES)
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
                && args.results_trusted_private_host.is_none() =>
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
) -> Result<ResultsPublicEndpoint, automata_results_github::TokenError> {
    if args.results_listen.ip().is_loopback() {
        if args.results_trusted_private_host.is_some() {
            return Err(automata_results_github::TokenError::Policy);
        }
        return ResultsPublicEndpoint::loopback_development(results_url, args.results_listen);
    }
    let trusted_host = args
        .results_trusted_private_host
        .as_deref()
        .ok_or(automata_results_github::TokenError::Policy)?;
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
    /// The S3 endpoint is not an absolute URL.
    #[error("S3 endpoint is not a valid URL")]
    InvalidS3Endpoint,
    /// The `PostgreSQL` pool size is zero.
    #[error("database maximum connections must be greater than zero")]
    InvalidDatabaseConnections,
    /// A configured duration is zero.
    #[error("server durations must be greater than zero")]
    InvalidDuration,
    /// Bounded maintenance policy fields are inconsistent or out of range.
    #[error("control-plane maintenance policy is invalid")]
    InvalidMaintenancePolicy,
    /// No public Results endpoint was supplied for per-attempt credentials.
    #[error("a public Results endpoint is required")]
    MissingResultsEndpoint,
    /// Results endpoint/listener transport policy is invalid or inconsistent.
    #[error("Results endpoint policy is invalid")]
    InvalidResultsEndpoint,
    /// The non-secret Results signing-key identity is malformed.
    #[error("Results key identity is invalid")]
    InvalidResultsKeyId,
    /// Local admission is deliberately unavailable on a non-loopback listener.
    #[error("local workflow admission requires a loopback human HTTP listener")]
    LocalAdmissionRequiresLoopback,
    /// The tenant bound to local admission is malformed.
    #[error("local workflow admission tenant is invalid")]
    InvalidLocalAdmissionTenant,
}

fn positive_seconds(seconds: u64) -> Result<Duration, ServerConfigError> {
    if seconds == 0 {
        return Err(ServerConfigError::InvalidDuration);
    }
    Ok(Duration::from_secs(seconds))
}

fn read_bounded_file(path: &PathBuf, maximum_bytes: usize) -> Result<Vec<u8>, SecretLoadError> {
    let file = File::open(path).map_err(SecretLoadError::File)?;
    let metadata = file.metadata().map_err(SecretLoadError::File)?;
    if metadata.len() > u64::try_from(maximum_bytes).unwrap_or(u64::MAX) {
        return Err(SecretLoadError::TooLarge {
            maximum: maximum_bytes,
        });
    }
    let capacity = usize::try_from(metadata.len()).unwrap_or(maximum_bytes);
    let mut bytes = Vec::with_capacity(capacity.min(maximum_bytes));
    let take_limit = u64::try_from(maximum_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    file.take(take_limit)
        .read_to_end(&mut bytes)
        .map_err(SecretLoadError::File)?;
    if bytes.len() > maximum_bytes {
        return Err(SecretLoadError::TooLarge {
            maximum: maximum_bytes,
        });
    }
    Ok(bytes)
}
