use std::{fmt, net::IpAddr, time::Duration};

use aws_sdk_s3::{Client, config::Region};
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

const MAX_BUCKET_BYTES: usize = 63;
const MAX_PREFIX_BYTES: usize = 1_024;
const MAX_REGION_BYTES: usize = 64;
const MAX_KMS_KEY_ID_BYTES: usize = 2_048;
const MAX_OPERATION_TIMEOUT: Duration = Duration::from_mins(5);

/// Required server-side encryption policy for every immutable object.
///
/// KMS identifiers must be the exact stable value returned by the S3 service
/// on reads (normally a full key ARN), so verification cannot silently accept
/// an object encrypted under a different key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3AtRestEncryption {
    mode: S3AtRestEncryptionMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum S3AtRestEncryptionMode {
    Aes256,
    AwsKms { key_id: String },
    AwsKmsDsse { key_id: String },
}

impl S3AtRestEncryption {
    /// Selects provider-managed AES-256 server-side encryption (`SSE-S3`).
    #[must_use]
    pub const fn aes256() -> Self {
        Self {
            mode: S3AtRestEncryptionMode::Aes256,
        }
    }

    /// Creates an exact KMS-key policy.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or control-containing key identities.
    pub fn aws_kms(key_id: impl Into<String>) -> Result<Self, S3BlobStoreConfigError> {
        let key_id = validate_kms_key_id(key_id.into())?;
        Ok(Self {
            mode: S3AtRestEncryptionMode::AwsKms { key_id },
        })
    }

    /// Creates an exact dual-layer KMS-key policy.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or control-containing key identities.
    pub fn aws_kms_dsse(key_id: impl Into<String>) -> Result<Self, S3BlobStoreConfigError> {
        let key_id = validate_kms_key_id(key_id.into())?;
        Ok(Self {
            mode: S3AtRestEncryptionMode::AwsKmsDsse { key_id },
        })
    }

    pub(crate) const fn algorithm(&self) -> aws_sdk_s3::types::ServerSideEncryption {
        match &self.mode {
            S3AtRestEncryptionMode::Aes256 => aws_sdk_s3::types::ServerSideEncryption::Aes256,
            S3AtRestEncryptionMode::AwsKms { .. } => {
                aws_sdk_s3::types::ServerSideEncryption::AwsKms
            }
            S3AtRestEncryptionMode::AwsKmsDsse { .. } => {
                aws_sdk_s3::types::ServerSideEncryption::AwsKmsDsse
            }
        }
    }

    pub(crate) fn kms_key_id(&self) -> Option<&str> {
        match &self.mode {
            S3AtRestEncryptionMode::Aes256 => None,
            S3AtRestEncryptionMode::AwsKms { key_id }
            | S3AtRestEncryptionMode::AwsKmsDsse { key_id } => Some(key_id),
        }
    }

    pub(crate) fn verifies(
        &self,
        algorithm: Option<&aws_sdk_s3::types::ServerSideEncryption>,
        kms_key_id: Option<&str>,
    ) -> bool {
        algorithm == Some(&self.algorithm()) && kms_key_id == self.kms_key_id()
    }
}

impl Default for S3AtRestEncryption {
    fn default() -> Self {
        Self::aes256()
    }
}

/// Static S3 credential material consumed when constructing an SDK client.
pub struct StaticS3Credentials {
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

impl StaticS3Credentials {
    /// Creates non-empty static credentials.
    ///
    /// # Errors
    ///
    /// Rejects empty fields and a present-but-empty session token.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
    ) -> Result<Self, S3BlobStoreConfigError> {
        let access_key_id = Zeroizing::new(access_key_id.into());
        let secret_access_key = Zeroizing::new(secret_access_key.into());
        let session_token = session_token.map(Zeroizing::new);
        if access_key_id.is_empty()
            || secret_access_key.is_empty()
            || session_token.as_ref().is_some_and(|value| value.is_empty())
        {
            return Err(S3BlobStoreConfigError::InvalidCredentials);
        }
        Ok(Self {
            access_key_id,
            secret_access_key,
            session_token,
        })
    }

    pub(crate) fn into_sdk(self) -> aws_sdk_s3::config::Credentials {
        aws_sdk_s3::config::Credentials::new(
            self.access_key_id.as_str(),
            self.secret_access_key.as_str(),
            self.session_token
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            None,
            "automata-static-s3",
        )
    }
}

impl fmt::Debug for StaticS3Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticS3Credentials")
            .field("access_key_id", &"[redacted]")
            .field("secret_access_key", &"[redacted]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// Validated S3 endpoint and immutable-object namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3BlobStoreConfig {
    endpoint: Url,
    region: String,
    bucket: String,
    prefix: Option<String>,
    force_path_style: bool,
    operation_timeout: Duration,
    at_rest_encryption: S3AtRestEncryption,
}

struct UnvalidatedS3BlobStoreConfig {
    endpoint: Url,
    region: String,
    bucket: String,
    prefix: Option<String>,
    force_path_style: bool,
    operation_timeout: Duration,
    at_rest_encryption: S3AtRestEncryption,
}

#[derive(Clone, Copy)]
enum EndpointPolicy {
    HttpsOnly,
    LoopbackDevelopment,
}

impl S3BlobStoreConfig {
    /// Creates a production configuration requiring HTTPS.
    ///
    /// # Errors
    ///
    /// Rejects unsafe endpoints, invalid bucket/prefix/region values, and
    /// zero or excessive operation deadlines.
    pub fn new(
        endpoint: Url,
        region: impl Into<String>,
        bucket: impl Into<String>,
        prefix: Option<String>,
        force_path_style: bool,
        operation_timeout: Duration,
    ) -> Result<Self, S3BlobStoreConfigError> {
        Self::validate(
            UnvalidatedS3BlobStoreConfig {
                endpoint,
                region: region.into(),
                bucket: bucket.into(),
                prefix,
                force_path_style,
                operation_timeout,
                at_rest_encryption: S3AtRestEncryption::default(),
            },
            EndpointPolicy::HttpsOnly,
        )
    }

    /// Creates a development configuration that permits HTTP only for a
    /// literal loopback IP address.
    ///
    /// # Errors
    ///
    /// Applies every production validation and rejects non-loopback HTTP.
    pub fn loopback_development(
        endpoint: Url,
        region: impl Into<String>,
        bucket: impl Into<String>,
        prefix: Option<String>,
        operation_timeout: Duration,
    ) -> Result<Self, S3BlobStoreConfigError> {
        Self::validate(
            UnvalidatedS3BlobStoreConfig {
                endpoint,
                region: region.into(),
                bucket: bucket.into(),
                prefix,
                force_path_style: true,
                operation_timeout,
                at_rest_encryption: S3AtRestEncryption::default(),
            },
            EndpointPolicy::LoopbackDevelopment,
        )
    }

    fn validate(
        candidate: UnvalidatedS3BlobStoreConfig,
        endpoint_policy: EndpointPolicy,
    ) -> Result<Self, S3BlobStoreConfigError> {
        let UnvalidatedS3BlobStoreConfig {
            endpoint,
            region,
            bucket,
            prefix,
            force_path_style,
            operation_timeout,
            at_rest_encryption,
        } = candidate;
        let allow_loopback_http = matches!(endpoint_policy, EndpointPolicy::LoopbackDevelopment);
        validate_endpoint(&endpoint, allow_loopback_http)?;
        validate_region(&region)?;
        validate_bucket(&bucket)?;
        let prefix = validate_prefix(prefix)?;
        if operation_timeout.is_zero() || operation_timeout > MAX_OPERATION_TIMEOUT {
            return Err(S3BlobStoreConfigError::InvalidOperationTimeout);
        }
        Ok(Self {
            endpoint,
            region,
            bucket,
            prefix,
            force_path_style,
            operation_timeout,
            at_rest_encryption,
        })
    }

    /// Constructs a statically authenticated S3 SDK client.
    ///
    /// The adapter also accepts an externally constructed [`Client`] so a
    /// deployment may use any SDK credential provider without changing this
    /// domain configuration.
    #[must_use]
    pub fn client(&self, credentials: StaticS3Credentials) -> Client {
        let http_client = aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https();
        let config = aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .http_client(http_client)
            .endpoint_url(self.endpoint.as_str())
            .region(Region::new(self.region.clone()))
            .credentials_provider(credentials.into_sdk())
            .force_path_style(self.force_path_style)
            .build();
        Client::from_conf(config)
    }

    /// Returns the bucket name without credentials.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Returns the optional namespace prefix.
    #[must_use]
    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    /// Returns the all-attempt wall-clock deadline.
    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    /// Selects a mandatory server-side encryption policy.
    #[must_use]
    pub fn with_at_rest_encryption(mut self, encryption: S3AtRestEncryption) -> Self {
        self.at_rest_encryption = encryption;
        self
    }

    /// Returns the encryption policy verified on every object read.
    #[must_use]
    pub const fn at_rest_encryption(&self) -> &S3AtRestEncryption {
        &self.at_rest_encryption
    }
}

/// Invalid S3 adapter configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum S3BlobStoreConfigError {
    /// The endpoint is not a credential-free HTTPS origin without extra URL components.
    #[error("S3 endpoint must be credential-free HTTPS with no query, fragment, or base path")]
    InvalidEndpoint,
    /// Development HTTP was requested for a host that is not a literal loopback address.
    #[error("development HTTP S3 endpoint must use a literal loopback IP address")]
    InsecureNonLoopbackEndpoint,
    /// The region is empty, oversized, or contains a non-visible ASCII byte.
    #[error("S3 region must be 1..=64 visible ASCII bytes")]
    InvalidRegion,
    /// The bucket is not a canonical DNS-compatible S3 bucket name.
    #[error("S3 bucket must be a canonical DNS-compatible name")]
    InvalidBucket,
    /// The object namespace prefix is absolute, aliased, or otherwise noncanonical.
    #[error("S3 object prefix is invalid")]
    InvalidPrefix,
    /// The all-attempt wall-clock deadline is zero or exceeds five minutes.
    #[error("S3 operation timeout must be greater than zero and at most five minutes")]
    InvalidOperationTimeout,
    /// A required access-key or secret-key field is empty.
    #[error("static S3 credentials contain an empty field")]
    InvalidCredentials,
    /// The KMS key identifier is empty, oversized, padded, or contains control characters.
    #[error("S3 KMS key identity is invalid")]
    InvalidKmsKeyId,
}

fn validate_kms_key_id(value: String) -> Result<String, S3BlobStoreConfigError> {
    if value.is_empty()
        || value.len() > MAX_KMS_KEY_ID_BYTES
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        return Err(S3BlobStoreConfigError::InvalidKmsKeyId);
    }
    Ok(value)
}

fn validate_endpoint(
    endpoint: &Url,
    allow_loopback_http: bool,
) -> Result<(), S3BlobStoreConfigError> {
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
        || endpoint.host_str().is_none()
    {
        return Err(S3BlobStoreConfigError::InvalidEndpoint);
    }
    match endpoint.scheme() {
        "https" => Ok(()),
        "http" if allow_loopback_http && endpoint_is_loopback(endpoint) => Ok(()),
        "http" => Err(S3BlobStoreConfigError::InsecureNonLoopbackEndpoint),
        _ => Err(S3BlobStoreConfigError::InvalidEndpoint),
    }
}

fn endpoint_is_loopback(endpoint: &Url) -> bool {
    endpoint.host().is_some_and(|host| match host {
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
        Host::Domain(_) => false,
    })
}

fn validate_region(region: &str) -> Result<(), S3BlobStoreConfigError> {
    if region.is_empty()
        || region.len() > MAX_REGION_BYTES
        || !region.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(S3BlobStoreConfigError::InvalidRegion);
    }
    Ok(())
}

fn validate_bucket(bucket: &str) -> Result<(), S3BlobStoreConfigError> {
    let labels_are_canonical = bucket.split('.').all(|label| {
        !label.is_empty()
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    });
    if bucket.len() < 3
        || bucket.len() > MAX_BUCKET_BYTES
        || bucket.starts_with('-')
        || bucket.ends_with('-')
        || bucket.starts_with('.')
        || bucket.ends_with('.')
        || bucket.contains("..")
        || !labels_are_canonical
        || bucket.starts_with("xn--")
        || bucket.starts_with("sthree-")
        || bucket.starts_with("amzn_s3_demo_")
        || bucket.ends_with("-s3alias")
        || bucket.ends_with("--ol-s3")
        || bucket.as_bytes().ends_with(b".mrap")
        || bucket.ends_with("--x-s3")
        || bucket.ends_with("--table-s3")
        || !bucket.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        || bucket.parse::<IpAddr>().is_ok()
    {
        return Err(S3BlobStoreConfigError::InvalidBucket);
    }
    Ok(())
}

fn validate_prefix(prefix: Option<String>) -> Result<Option<String>, S3BlobStoreConfigError> {
    let Some(prefix) = prefix else {
        return Ok(None);
    };
    if prefix.is_empty()
        || prefix.len() > MAX_PREFIX_BYTES
        || prefix.starts_with('/')
        || prefix.ends_with('/')
        || prefix.chars().any(char::is_control)
        || prefix.contains('\\')
        || prefix
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(S3BlobStoreConfigError::InvalidPrefix);
    }
    Ok(Some(prefix))
}
