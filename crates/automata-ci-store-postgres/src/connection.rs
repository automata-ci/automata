use std::{env, ffi::OsStr, fmt, net::IpAddr, ops::Deref};

use automata_ci_tls::{MAX_CA_CERTIFICATE_PEM_BYTES, ValidatedCaCertificate};
use percent_encoding::percent_decode_str;
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const MAX_DATABASE_URL_BYTES: usize = 16 * 1024;
const APPLICATION_NAME: &str = "automata-ci";
const SEARCH_PATH: &str = "public";

/// Maximum accepted size of the additive private `PostgreSQL` CA certificate.
pub const MAX_POSTGRES_PRIVATE_CA_PEM_BYTES: usize = MAX_CA_CERTIFICATE_PEM_BYTES;

/// Closed transport and server-authentication policy for `PostgreSQL`.
pub struct PostgresTransportSecurity {
    policy: PostgresTransportPolicy,
}

enum PostgresTransportPolicy {
    WebPkiVerifyFull,
    WebPkiPlusPrivateCaVerifyFull(ValidatedCaCertificate),
    LoopbackPlaintext,
}

impl PostgresTransportSecurity {
    /// Requires TLS, hostname verification, and the pinned Web PKI root set.
    #[must_use]
    pub const fn web_pki_verify_full() -> Self {
        Self {
            policy: PostgresTransportPolicy::WebPkiVerifyFull,
        }
    }

    /// Requires TLS and hostname verification against the pinned Web PKI root
    /// set plus one explicit deployment-provided CA.
    ///
    /// This mode deliberately names the union: `SQLx` adds the supplied CA to its
    /// compiled Web PKI roots rather than replacing them.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error unless `certificate_pem` is exactly one
    /// canonical, bounded X.509 CA certificate.
    pub fn web_pki_plus_private_ca_verify_full(
        certificate_pem: impl Into<Vec<u8>>,
    ) -> Result<Self, PostgresConnectionConfigError> {
        let certificate = ValidatedCaCertificate::new(certificate_pem)
            .map_err(|_| PostgresConnectionConfigError::InvalidPrivateCa)?;
        Ok(Self {
            policy: PostgresTransportPolicy::WebPkiPlusPrivateCaVerifyFull(certificate),
        })
    }

    /// Disables TLS for an exact literal-loopback TCP endpoint.
    ///
    /// [`PostgresConnectionConfig::parse`] rejects domain names, remote
    /// addresses, and Unix-domain sockets when this policy is selected.
    #[must_use]
    pub const fn loopback_plaintext() -> Self {
        Self {
            policy: PostgresTransportPolicy::LoopbackPlaintext,
        }
    }
}

impl fmt::Debug for PostgresTransportSecurity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match &self.policy {
            PostgresTransportPolicy::WebPkiVerifyFull => {
                "PostgresTransportSecurity::WebPkiVerifyFull"
            }
            PostgresTransportPolicy::WebPkiPlusPrivateCaVerifyFull(_) => {
                "PostgresTransportSecurity::WebPkiPlusPrivateCaVerifyFull([certificate redacted])"
            }
            PostgresTransportPolicy::LoopbackPlaintext => {
                "PostgresTransportSecurity::LoopbackPlaintext"
            }
        })
    }
}

/// Validated exact `PostgreSQL` TCP connection configuration.
pub struct PostgresConnectionConfig {
    options: PgConnectOptions,
    transport: RetainedTransportKind,
}

struct SensitiveUrl(Option<Url>);

impl SensitiveUrl {
    fn parse(value: &str) -> Result<Self, PostgresConnectionConfigError> {
        Url::parse(value)
            .map(|url| Self(Some(url)))
            .map_err(|_| PostgresConnectionConfigError::InvalidUrl)
    }
}

impl Deref for SensitiveUrl {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("sensitive URL retained until drop")
    }
}

impl fmt::Debug for SensitiveUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveUrl([redacted])")
    }
}

impl Drop for SensitiveUrl {
    fn drop(&mut self) {
        if let Some(url) = self.0.take() {
            let _serialized = Zeroizing::new(String::from(url));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetainedTransportKind {
    WebPkiVerifyFull,
    WebPkiPlusPrivateCaVerifyFull,
    LoopbackPlaintext,
}

impl PostgresConnectionConfig {
    /// Parses the current exact `postgresql://` connection contract.
    ///
    /// The URL must explicitly contain one TCP host, port, user, non-empty
    /// password, and database. Query parameters, fragments, socket paths,
    /// implicit fields, and the legacy `postgres://` alias are rejected. The
    /// process environment must contain no key beginning with `PG`, preventing
    /// `SQLx`/libpq environment and passfile semantics from becoming a second
    /// configuration authority.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error for an ambient `PostgreSQL` environment, an
    /// invalid URL, or plaintext transport targeting anything except a literal
    /// loopback IP address.
    pub fn parse(
        database_url: &str,
        transport_security: PostgresTransportSecurity,
    ) -> Result<Self, PostgresConnectionConfigError> {
        Self::parse_with_environment(
            database_url,
            transport_security,
            env::vars_os().map(|(key, _)| key),
        )
    }

    fn parse_with_environment(
        database_url: &str,
        transport_security: PostgresTransportSecurity,
        environment_keys: impl IntoIterator<Item = impl AsRef<OsStr>>,
    ) -> Result<Self, PostgresConnectionConfigError> {
        reject_ambient_postgres_environment(environment_keys)?;
        if database_url.is_empty()
            || database_url.len() > MAX_DATABASE_URL_BYTES
            || database_url.chars().any(char::is_control)
            || !database_url.starts_with("postgresql://")
        {
            return Err(PostgresConnectionConfigError::InvalidUrl);
        }
        let url = SensitiveUrl::parse(database_url)?;
        if url.scheme() != "postgresql"
            || url.cannot_be_a_base()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(PostgresConnectionConfigError::InvalidUrl);
        }

        let host = canonical_tcp_host(&url)?;
        let port = url
            .port()
            .filter(|port| *port != 0)
            .ok_or(PostgresConnectionConfigError::InvalidUrl)?;
        let username = decode_required_component(url.username())?;
        let password = decode_required_component(
            url.password()
                .ok_or(PostgresConnectionConfigError::InvalidUrl)?,
        )?;
        let mut path_segments = url
            .path_segments()
            .ok_or(PostgresConnectionConfigError::InvalidUrl)?;
        let database = decode_required_component(
            path_segments
                .next()
                .ok_or(PostgresConnectionConfigError::InvalidUrl)?,
        )?;
        if path_segments.next().is_some() {
            return Err(PostgresConnectionConfigError::InvalidUrl);
        }

        if matches!(
            &transport_security.policy,
            PostgresTransportPolicy::LoopbackPlaintext
        ) && !literal_loopback(&url)
        {
            return Err(PostgresConnectionConfigError::InsecureTransport);
        }

        // `new_without_pgpass` still reads PG* variables in SQLx 0.9. Parsing
        // rejected every such key immediately before this constructor. Every
        // imported field is then set explicitly, and `apply_pgpass` is never
        // called.
        let options = PgConnectOptions::new_without_pgpass()
            .host(&host)
            .port(port)
            .username(&username)
            .password(&password)
            .database(&database)
            .application_name(APPLICATION_NAME)
            .options([("search_path", SEARCH_PATH)]);
        let (options, transport) = match transport_security.policy {
            PostgresTransportPolicy::WebPkiVerifyFull => (
                options.ssl_mode(PgSslMode::VerifyFull),
                RetainedTransportKind::WebPkiVerifyFull,
            ),
            PostgresTransportPolicy::WebPkiPlusPrivateCaVerifyFull(certificate) => {
                let options = options
                    .ssl_mode(PgSslMode::VerifyFull)
                    .ssl_root_cert_from_pem(certificate.as_pem().to_vec());
                (
                    options,
                    RetainedTransportKind::WebPkiPlusPrivateCaVerifyFull,
                )
            }
            PostgresTransportPolicy::LoopbackPlaintext => (
                options.ssl_mode(PgSslMode::Disable),
                RetainedTransportKind::LoopbackPlaintext,
            ),
        };
        Ok(Self { options, transport })
    }

    pub(crate) fn into_connect_options(self) -> PgConnectOptions {
        self.options
    }
}

impl fmt::Debug for PostgresConnectionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresConnectionConfig")
            .field("endpoint", &"[redacted]")
            .field("credentials", &"[redacted]")
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

/// Rejection from the exact `PostgreSQL` connection boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PostgresConnectionConfigError {
    /// A process environment key beginning with `PG` was present.
    #[error("ambient PostgreSQL environment configuration is not permitted")]
    AmbientEnvironment,
    /// The URL was not the exact current TCP connection grammar.
    #[error("PostgreSQL URL must contain exact explicit TCP connection fields")]
    InvalidUrl,
    /// Plaintext transport did not target a literal loopback IP address.
    #[error("plaintext PostgreSQL requires a literal loopback TCP endpoint")]
    InsecureTransport,
    /// The additive private CA was not one valid canonical CA document.
    #[error("PostgreSQL private CA source must contain one valid canonical CA certificate")]
    InvalidPrivateCa,
}

fn reject_ambient_postgres_environment(
    keys: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Result<(), PostgresConnectionConfigError> {
    if keys.into_iter().any(|key| {
        key.as_ref()
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("PG")
    }) {
        return Err(PostgresConnectionConfigError::AmbientEnvironment);
    }
    Ok(())
}

fn decode_required_component(
    value: &str,
) -> Result<Zeroizing<String>, PostgresConnectionConfigError> {
    if value.is_empty() || !valid_percent_encoding(value.as_bytes()) {
        return Err(PostgresConnectionConfigError::InvalidUrl);
    }
    let decoded = percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| PostgresConnectionConfigError::InvalidUrl)?
        .into_owned();
    if decoded.is_empty() || decoded.chars().any(char::is_control) {
        return Err(PostgresConnectionConfigError::InvalidUrl);
    }
    Ok(Zeroizing::new(decoded))
}

fn valid_percent_encoding(value: &[u8]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= value.len()
            || !value[index + 1].is_ascii_hexdigit()
            || !value[index + 2].is_ascii_hexdigit()
        {
            return false;
        }
        index += 3;
    }
    true
}

fn literal_loopback(url: &Url) -> bool {
    url.host_str()
        .map(|host| {
            host.strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(host)
        })
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
}

fn canonical_tcp_host(url: &Url) -> Result<String, PostgresConnectionConfigError> {
    let serialized_host = url
        .host_str()
        .ok_or(PostgresConnectionConfigError::InvalidUrl)?;
    let host = serialized_host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(serialized_host);
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    if host.is_empty()
        || host.len() > 253
        || host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return Err(PostgresConnectionConfigError::InvalidUrl);
    }
    Ok(host.to_owned())
}

#[cfg(test)]
mod tests {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    use super::*;

    fn web_pki() -> PostgresTransportSecurity {
        PostgresTransportSecurity::web_pki_verify_full()
    }

    fn ca_pem() -> Vec<u8> {
        let key = KeyPair::generate().expect("CA key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params
            .self_signed(&key)
            .expect("self-signed CA")
            .pem()
            .into_bytes()
    }

    #[test]
    fn exact_url_builds_only_explicit_tcp_options() {
        let config = PostgresConnectionConfig::parse(
            "postgresql://automata:p%40ssword@database.invalid:6432/automata",
            web_pki(),
        )
        .expect("exact URL");
        let options = config.into_connect_options();

        assert_eq!(options.get_host(), "database.invalid");
        assert_eq!(options.get_port(), 6432);
        assert_eq!(options.get_username(), "automata");
        assert_eq!(options.get_database(), Some("automata"));
        assert_eq!(options.get_socket(), None);
        assert_eq!(options.get_application_name(), Some(APPLICATION_NAME));
        assert_eq!(options.get_options(), Some("-c search_path=public"));
        assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
    }

    #[test]
    fn additive_ca_mode_is_explicit_validated_and_redacted() {
        let certificate_pem = ca_pem();
        let pem_marker = std::str::from_utf8(&certificate_pem)
            .expect("PEM is ASCII")
            .lines()
            .nth(1)
            .expect("PEM body")
            .get(..32)
            .expect("PEM marker")
            .to_owned();
        let transport =
            PostgresTransportSecurity::web_pki_plus_private_ca_verify_full(certificate_pem)
                .expect("validated additive CA");
        let transport_debug = format!("{transport:?}");
        assert!(transport_debug.contains("WebPkiPlusPrivateCaVerifyFull"));
        assert!(!transport_debug.contains(&pem_marker));

        let config = PostgresConnectionConfig::parse(
            "postgresql://automata:password@database.automata.invalid:5432/automata",
            transport,
        )
        .expect("reserved local DNS identity");
        let options = config.into_connect_options();
        assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
        assert!(format!("{options:?}").contains("ssl_root_cert: Some"));

        assert!(matches!(
            PostgresTransportSecurity::web_pki_plus_private_ca_verify_full(b"not a CA".to_vec()),
            Err(PostgresConnectionConfigError::InvalidPrivateCa)
        ));
    }

    #[test]
    fn rejects_every_implicit_or_alternate_url_shape_without_echoing_secrets() {
        for invalid in [
            "postgres://user:secret@database.invalid:5432/automata",
            "POSTGRESQL://user:secret@database.invalid:5432/automata",
            "postgresql://user:secret@database.invalid/automata",
            "postgresql://user:secret@database.invalid:0/automata",
            "postgresql://:secret@database.invalid:5432/automata",
            "postgresql://user@database.invalid:5432/automata",
            "postgresql://user:@database.invalid:5432/automata",
            "postgresql://user:secret@:5432/automata",
            "postgresql://user:secret@database.invalid:5432/",
            "postgresql://user:secret@database.invalid:5432/automata/extra",
            "postgresql://user:secret@database.invalid:5432/automata?sslmode=disable",
            "postgresql://user:secret@database.invalid:5432/automata?host=%2Frun%2Fpostgresql",
            "postgresql://user:secret@database.invalid:5432/automata#fragment",
            "postgresql://user:%ZZ@database.invalid:5432/automata",
            "postgresql://user:secret@database.invalid:5432/automata\n",
            "postgresql:///automata?host=/run/postgresql&user=user&password=secret&port=5432",
            "postgresql://user:secret@127.1:5432/automata",
            "postgresql://user:secret@database_.invalid:5432/automata",
            "postgresql://user:secret@-database.invalid:5432/automata",
            "postgresql://user:secret@database.invalid.:5432/automata",
        ] {
            let Err(error) = PostgresConnectionConfig::parse(invalid, web_pki()) else {
                panic!("invalid URL accepted: {invalid}");
            };
            assert_eq!(
                error,
                PostgresConnectionConfigError::InvalidUrl,
                "{invalid}"
            );
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[test]
    fn plaintext_accepts_only_literal_loopback_tcp() {
        for (valid, expected_host) in [
            (
                "postgresql://user:secret@127.0.0.1:5432/automata",
                "127.0.0.1",
            ),
            (
                "postgresql://user:secret@127.42.0.9:5432/automata",
                "127.42.0.9",
            ),
            ("postgresql://user:secret@[::1]:5432/automata", "::1"),
        ] {
            let config = PostgresConnectionConfig::parse(
                valid,
                PostgresTransportSecurity::loopback_plaintext(),
            )
            .unwrap_or_else(|error| panic!("literal loopback rejected: {valid}: {error}"));
            let options = config.into_connect_options();
            assert_eq!(options.get_host(), expected_host);
            assert!(matches!(options.get_ssl_mode(), PgSslMode::Disable));
        }

        for invalid in [
            "postgresql://user:secret@localhost:5432/automata",
            "postgresql://user:secret@database.invalid:5432/automata",
            "postgresql://user:secret@192.0.2.1:5432/automata",
        ] {
            assert!(
                matches!(
                    PostgresConnectionConfig::parse(
                        invalid,
                        PostgresTransportSecurity::loopback_plaintext(),
                    ),
                    Err(PostgresConnectionConfigError::InsecureTransport)
                ),
                "{invalid}"
            );
        }
    }

    #[test]
    fn every_postgres_environment_key_and_passfile_authority_is_rejected() {
        const URL: &str = "postgresql://user:password@database.invalid:5432/automata";
        for key in [
            "PGHOST",
            "PGHOSTADDR",
            "PGPORT",
            "PGDATABASE",
            "PGUSER",
            "PGPASSWORD",
            "PGPASSFILE",
            "PGAPPNAME",
            "PGOPTIONS",
            "PGSSLMODE",
            "PGSSLROOTCERT",
            "PGSSLCERT",
            "PGSSLKEY",
            "PGSERVICE",
            "PGSERVICEFILE",
            "PGFUTURE_SQLX_OPTION",
            "pghost",
        ] {
            assert_eq!(
                reject_ambient_postgres_environment([key]),
                Err(PostgresConnectionConfigError::AmbientEnvironment),
                "{key}"
            );
            assert!(matches!(
                PostgresConnectionConfig::parse_with_environment(URL, web_pki(), [key]),
                Err(PostgresConnectionConfigError::AmbientEnvironment)
            ));
        }
        assert_eq!(
            reject_ambient_postgres_environment(["PATH", "PAGER"]),
            Ok(())
        );
        PostgresConnectionConfig::parse_with_environment(URL, web_pki(), ["HOME", "APPDATA"])
            .expect("default passfile location variables are inert without apply_pgpass");
    }

    #[test]
    fn debug_and_errors_redact_connection_credentials_and_ca() {
        let secret = "unique-database-password";
        let config = PostgresConnectionConfig::parse(
            &format!(
                "postgresql://sensitive-user:{secret}@sensitive-host.invalid:5432/sensitive-database"
            ),
            web_pki(),
        )
        .expect("exact URL");
        let debug = format!("{config:?}");
        for marker in [
            secret,
            "sensitive-user",
            "sensitive-host",
            "sensitive-database",
        ] {
            assert!(!debug.contains(marker));
        }
        assert!(debug.contains("[redacted]"));
    }

    #[tokio::test]
    async fn store_consumes_only_a_validated_configuration_and_nonzero_pool_bound() {
        let config = PostgresConnectionConfig::parse(
            "postgresql://automata:password@127.0.0.1:5432/automata",
            PostgresTransportSecurity::loopback_plaintext(),
        )
        .expect("validated connection");

        assert!(matches!(
            crate::PostgresStore::connect(config, 0).await,
            Err(crate::PostgresStoreError::InvalidPoolSize)
        ));
    }
}
