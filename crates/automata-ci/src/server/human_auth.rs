//! Production composition for GitHub human authentication.
//!
//! This module deliberately constructs ports and services only. HTTP routes and
//! middleware consume the resulting runtime from their separately owned seams.

use std::{fmt, sync::Arc, time::Duration};

use automata_ci_auth::{
    github::{
        GithubAppAuthenticationProvider, GithubAppConfig, GithubAppProtocol, GithubEndpoint,
        GithubEndpoints, GithubLoginProofKey, GithubLoginProofKeyring, GithubLoginService,
        GithubLoginSessionLifetimes,
    },
    human::{AuthenticationProvider, ProviderId},
    installation::{
        InstallationProof, InstallationProofDigest, InstallationProofKeyId, InstallationRepository,
    },
    login::{LoginBindingDigestKeyId, LoginTransactionRepository},
    request_auth::RequestAuthenticationResolver,
    secret::{SecretBytes, SecretString, SecureRandom, SystemSecureRandom},
    session::{HumanSessionRepository, SessionKind, SessionTokenDigestKeyId},
    session_credential::{
        SessionCredentialKey, SessionCredentialKeyring, SessionCredentialService,
    },
    sign_in::HumanSignInFinalizer,
    time::{Clock, SystemClock},
};
use automata_ci_auth_postgres::{
    PostgresHumanSessionRepository, PostgresHumanSignInFinalizer, PostgresInstallationRepository,
    PostgresLoginTransactionRepository, PostgresRequestAuthenticationResolver,
};
use automata_ci_github::GithubHttpEndpoint;
use automata_ci_key_management::KeyEncryptionProvider;
use automata_ci_store_postgres::PostgresStore;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use super::{HumanAuthConfig, SecretEncryptionLoadError};
use crate::app::human_auth::HumanAuthOrigin;

const GITHUB_PROVIDER_ID: &str = "github";
const GITHUB_WEB_TRANSACTION_TTL_SECONDS: u64 = 10 * 60;
const GITHUB_HTTP_USER_AGENT: &str = concat!("automata-ci/", env!("CARGO_PKG_VERSION"));
const BROWSER_IDLE_LIFETIME_CAP: Duration = Duration::from_mins(30);
const CLI_IDLE_LIFETIME_CAP: Duration = Duration::from_hours(12);
const HMAC_KDF_DOMAIN: &[u8] = b"automata-ci/human-auth/hmac-kdf/hmac-sha256/v1\0";
const SESSION_HMAC_DOMAIN: &[u8] = b"session-credential";
const LOGIN_PROOF_HMAC_DOMAIN: &[u8] = b"github-login-proof";
const INSTALLATION_PROOF_HMAC_DOMAIN: &[u8] = b"installation-bootstrap-proof";
const INSTALLATION_TOKEN_DIGEST_DOMAIN: &[u8] =
    b"automata-ci/installation-bootstrap/token-digest/hmac-sha256/v1\0";
const SHA256_BLOCK_BYTES: usize = 64;

/// Browser and CLI idle/absolute lifetimes selected at the product boundary.
///
/// The current deployment configuration exposes absolute lifetimes only. Idle
/// lifetimes therefore use conservative caps and are clamped to the matching
/// absolute lifetime. They remain a distinct type so later configuration work
/// can add explicit rotation and idle policy without changing router seams.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HumanAuthSessionLifetimes {
    browser_idle: Duration,
    browser_absolute: Duration,
    cli_idle: Duration,
    cli_absolute: Duration,
}

impl HumanAuthSessionLifetimes {
    fn from_absolute(
        browser_absolute: Duration,
        cli_absolute: Duration,
    ) -> Result<Self, HumanAuthRuntimeError> {
        if browser_absolute.is_zero()
            || cli_absolute.is_zero()
            || browser_absolute.subsec_nanos() != 0
            || cli_absolute.subsec_nanos() != 0
        {
            return Err(HumanAuthRuntimeError::InvalidSessionLifetime);
        }
        Ok(Self {
            browser_idle: browser_absolute.min(BROWSER_IDLE_LIFETIME_CAP),
            browser_absolute,
            cli_idle: cli_absolute.min(CLI_IDLE_LIFETIME_CAP),
            cli_absolute,
        })
    }

    #[must_use]
    pub(crate) const fn idle(self, kind: SessionKind) -> Duration {
        match kind {
            SessionKind::Browser => self.browser_idle,
            SessionKind::Cli => self.cli_idle,
        }
    }

    #[must_use]
    pub(crate) const fn absolute(self, kind: SessionKind) -> Duration {
        match kind {
            SessionKind::Browser => self.browser_absolute,
            SessionKind::Cli => self.cli_absolute,
        }
    }

    fn github(self) -> Result<GithubLoginSessionLifetimes, HumanAuthRuntimeError> {
        GithubLoginSessionLifetimes::new(
            self.browser_idle,
            self.browser_absolute,
            self.cli_idle,
            self.cli_absolute,
        )
        .map_err(|_| HumanAuthRuntimeError::InvalidSessionLifetime)
    }
}

/// Keyed bootstrap-token digest service kept entirely inside product composition.
pub(crate) struct InstallationProofHasher {
    key_id: InstallationProofKeyId,
    key: Zeroizing<[u8; 32]>,
}

impl InstallationProofHasher {
    fn new(
        key_id: InstallationProofKeyId,
        material: SecretBytes,
    ) -> Result<Self, HumanAuthRuntimeError> {
        if material.expose_secret().len() != 32 {
            return Err(HumanAuthRuntimeError::InvalidHmacKeyConfiguration);
        }
        let mut key = Zeroizing::new([0_u8; 32]);
        key.copy_from_slice(material.expose_secret());
        drop(material);
        Ok(Self { key_id, key })
    }

    #[must_use]
    pub(crate) fn proof(&self, token: &str) -> InstallationProof {
        let digest = hmac_sha256(
            self.key.as_slice(),
            INSTALLATION_TOKEN_DIGEST_DOMAIN,
            token.as_bytes(),
        );
        InstallationProof::new(self.key_id.clone(), InstallationProofDigest::new(digest))
    }
}

impl fmt::Debug for InstallationProofHasher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallationProofHasher")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Fully constructed production human-auth services for later HTTP composition.
#[derive(Clone)]
pub(crate) struct HumanAuthRuntime {
    login_service: Arc<GithubLoginService>,
    session_service: Arc<SessionCredentialService>,
    request_resolver: Arc<dyn RequestAuthenticationResolver>,
    installation_repository: Arc<dyn InstallationRepository>,
    installation_proofs: Arc<InstallationProofHasher>,
    clock: Arc<dyn Clock>,
    origin: HumanAuthOrigin,
    lifetimes: HumanAuthSessionLifetimes,
}

impl HumanAuthRuntime {
    /// Constructs the GitHub.com protocol and durable `PostgreSQL` adapters.
    ///
    /// Secret sources are loaded once into redacted, zeroizing owners. Provider
    /// tokens and login state are envelope encrypted by the configured local
    /// key-management provider; session and login-proof HMAC material is derived
    /// under independent fixed domains and is never persisted.
    pub(crate) fn build(
        config: &HumanAuthConfig,
        store: &PostgresStore,
    ) -> Result<Self, HumanAuthRuntimeError> {
        let origin = HumanAuthOrigin::new(config.external_url())
            .map_err(|_| HumanAuthRuntimeError::InvalidOrigin)?;
        let lifetimes = HumanAuthSessionLifetimes::from_absolute(
            config.browser_session_ttl(),
            config.cli_session_ttl(),
        )?;
        let (session_keys, login_proof_keys, installation_proofs) = build_hmac_keyrings(config)?;

        let encryption_provider: Arc<dyn KeyEncryptionProvider> = Arc::new(
            config
                .encryption()
                .load_local_keyring()
                .map_err(|error| map_encryption_error(&error))?,
        );
        let pool = store.postgres_pool().clone();
        let session_repository: Arc<dyn HumanSessionRepository> =
            Arc::new(PostgresHumanSessionRepository::new(pool.clone()));
        let transactions: Arc<dyn LoginTransactionRepository> = Arc::new(
            PostgresLoginTransactionRepository::new(pool.clone(), Arc::clone(&encryption_provider)),
        );
        let finalizer: Arc<dyn HumanSignInFinalizer> = Arc::new(PostgresHumanSignInFinalizer::new(
            pool.clone(),
            Arc::clone(&encryption_provider),
        ));
        let installation_repository: Arc<dyn InstallationRepository> = Arc::new(
            PostgresInstallationRepository::new(pool.clone(), Arc::clone(&encryption_provider)),
        );
        let request_resolver: Arc<dyn RequestAuthenticationResolver> =
            Arc::new(PostgresRequestAuthenticationResolver::new(pool));
        let random: Arc<dyn SecureRandom> = Arc::new(SystemSecureRandom);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let session_service = Arc::new(SessionCredentialService::new(
            session_keys,
            session_repository,
            Arc::clone(&random),
            Arc::clone(&clock),
        ));

        let endpoint: Arc<dyn GithubEndpoint> = Arc::new(
            GithubHttpEndpoint::github_dot_com(GITHUB_HTTP_USER_AGENT)
                .map_err(|_| HumanAuthRuntimeError::GithubHttpConfiguration)?,
        );
        let provider_id = ProviderId::new(GITHUB_PROVIDER_ID)
            .map_err(|_| HumanAuthRuntimeError::GithubConfiguration)?;
        let authentication_provider: Arc<dyn AuthenticationProvider> =
            Arc::new(GithubAppAuthenticationProvider::new(
                provider_id.clone(),
                Arc::clone(&endpoint),
                Arc::clone(&clock),
            ));
        let protocol = GithubAppProtocol::new(
            GithubAppConfig::new(
                provider_id,
                config.github_client_id().clone(),
                load_github_client_secret(config)?,
                config.callback_url().clone(),
                GithubEndpoints::github_dot_com()
                    .map_err(|_| HumanAuthRuntimeError::GithubConfiguration)?,
                GITHUB_WEB_TRANSACTION_TTL_SECONDS,
            )
            .map_err(|_| HumanAuthRuntimeError::GithubConfiguration)?,
        );
        let login_service = Arc::new(
            GithubLoginService::new(
                protocol,
                endpoint,
                authentication_provider,
                transactions,
                Arc::clone(&session_service),
                finalizer,
                login_proof_keys,
                random,
                Arc::clone(&clock),
                lifetimes.github()?,
            )
            .map_err(|_| HumanAuthRuntimeError::GithubConfiguration)?,
        );

        Ok(Self {
            login_service,
            session_service,
            request_resolver,
            installation_repository,
            installation_proofs: Arc::new(installation_proofs),
            clock,
            origin,
            lifetimes,
        })
    }

    #[must_use]
    pub(crate) const fn login_service(&self) -> &Arc<GithubLoginService> {
        &self.login_service
    }

    #[must_use]
    pub(crate) const fn session_service(&self) -> &Arc<SessionCredentialService> {
        &self.session_service
    }

    #[must_use]
    pub(crate) const fn request_resolver(&self) -> &Arc<dyn RequestAuthenticationResolver> {
        &self.request_resolver
    }

    #[must_use]
    pub(crate) const fn installation_repository(&self) -> &Arc<dyn InstallationRepository> {
        &self.installation_repository
    }

    #[must_use]
    pub(crate) const fn installation_proofs(&self) -> &Arc<InstallationProofHasher> {
        &self.installation_proofs
    }

    /// Returns the same logical clock supplied to both credential services.
    #[must_use]
    pub(crate) const fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    #[must_use]
    pub(crate) const fn origin(&self) -> &HumanAuthOrigin {
        &self.origin
    }

    #[must_use]
    pub(crate) const fn lifetimes(&self) -> HumanAuthSessionLifetimes {
        self.lifetimes
    }
}

impl fmt::Debug for HumanAuthRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanAuthRuntime")
            .field("login_service", &self.login_service)
            .field("session_service", &self.session_service)
            .field("request_resolver", &self.request_resolver)
            .field("installation_repository", &self.installation_repository)
            .field("installation_proofs", &self.installation_proofs)
            .field("clock", &self.clock)
            .field("origin", &self.origin)
            .field("lifetimes", &self.lifetimes)
            .finish()
    }
}

fn load_github_client_secret(
    config: &HumanAuthConfig,
) -> Result<SecretString, HumanAuthRuntimeError> {
    let mut loaded = config
        .load_github_client_secret()
        .map_err(|_| HumanAuthRuntimeError::SecretUnavailable)?;
    SecretString::new(std::mem::take(&mut *loaded))
        .map_err(|_| HumanAuthRuntimeError::InvalidSecretConfiguration)
}

fn build_hmac_keyrings(
    config: &HumanAuthConfig,
) -> Result<
    (
        SessionCredentialKeyring,
        GithubLoginProofKeyring,
        InstallationProofHasher,
    ),
    HumanAuthRuntimeError,
> {
    let public_key_id = config.encryption_key_id();
    let session_id = SessionTokenDigestKeyId::new(public_key_id.to_owned())
        .map_err(|_| HumanAuthRuntimeError::InvalidHmacKeyConfiguration)?;
    let login_id = LoginBindingDigestKeyId::new(public_key_id.to_owned())
        .map_err(|_| HumanAuthRuntimeError::InvalidHmacKeyConfiguration)?;
    let installation_id = InstallationProofKeyId::new(public_key_id.to_owned())
        .map_err(|_| HumanAuthRuntimeError::InvalidHmacKeyConfiguration)?;
    let root = config
        .load_session_hash_key()
        .map_err(|_| HumanAuthRuntimeError::SecretUnavailable)?;
    let session_material = derive_hmac_material(root.as_slice(), SESSION_HMAC_DOMAIN)?;
    let login_material = derive_hmac_material(root.as_slice(), LOGIN_PROOF_HMAC_DOMAIN)?;
    let installation_material =
        derive_hmac_material(root.as_slice(), INSTALLATION_PROOF_HMAC_DOMAIN)?;
    drop(root);

    let session_key = SessionCredentialKey::new(session_id, session_material)
        .map_err(|_| HumanAuthRuntimeError::InvalidHmacKeyConfiguration)?;
    let login_key = GithubLoginProofKey::new(login_id, login_material)
        .map_err(|_| HumanAuthRuntimeError::InvalidHmacKeyConfiguration)?;
    let session_keys = SessionCredentialKeyring::new(session_key, Vec::new())
        .map_err(|_| HumanAuthRuntimeError::InvalidHmacKeyConfiguration)?;
    let login_keys = GithubLoginProofKeyring::new(login_key, Vec::new())
        .map_err(|_| HumanAuthRuntimeError::InvalidHmacKeyConfiguration)?;
    let installation_proofs = InstallationProofHasher::new(installation_id, installation_material)?;
    Ok((session_keys, login_keys, installation_proofs))
}

fn derive_hmac_material(root: &[u8], purpose: &[u8]) -> Result<SecretBytes, HumanAuthRuntimeError> {
    if root.len() != 32 || purpose.is_empty() {
        return Err(HumanAuthRuntimeError::InvalidHmacKeyConfiguration);
    }
    let purpose_length = u64::try_from(purpose.len())
        .map_err(|_| HumanAuthRuntimeError::InvalidHmacKeyConfiguration)?;
    let mut key_block = Zeroizing::new([0_u8; SHA256_BLOCK_BYTES]);
    key_block[..root.len()].copy_from_slice(root);
    let mut inner_pad = Zeroizing::new([0x36_u8; SHA256_BLOCK_BYTES]);
    let mut outer_pad = Zeroizing::new([0x5c_u8; SHA256_BLOCK_BYTES]);
    for ((inner, outer), key) in inner_pad
        .iter_mut()
        .zip(outer_pad.iter_mut())
        .zip(key_block.iter())
    {
        *inner ^= *key;
        *outer ^= *key;
    }
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(inner_pad.as_slice());
    inner_hasher.update(HMAC_KDF_DOMAIN);
    inner_hasher.update(purpose_length.to_be_bytes());
    inner_hasher.update(purpose);
    let mut inner_digest = inner_hasher.finalize();
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(outer_pad.as_slice());
    outer_hasher.update(inner_digest.as_slice());
    let mut digest = outer_hasher.finalize();
    let mut material = Zeroizing::new(digest.to_vec());
    inner_digest.as_mut_slice().zeroize();
    digest.as_mut_slice().zeroize();
    SecretBytes::new(std::mem::take(&mut *material))
        .map_err(|_| HumanAuthRuntimeError::InvalidHmacKeyConfiguration)
}

fn hmac_sha256(key: &[u8], domain: &[u8], message: &[u8]) -> [u8; 32] {
    debug_assert_eq!(key.len(), 32);
    let mut key_block = Zeroizing::new([0_u8; SHA256_BLOCK_BYTES]);
    key_block[..key.len()].copy_from_slice(key);
    let mut inner_pad = Zeroizing::new([0x36_u8; SHA256_BLOCK_BYTES]);
    let mut outer_pad = Zeroizing::new([0x5c_u8; SHA256_BLOCK_BYTES]);
    for ((inner, outer), key) in inner_pad
        .iter_mut()
        .zip(outer_pad.iter_mut())
        .zip(key_block.iter())
    {
        *inner ^= *key;
        *outer ^= *key;
    }
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(inner_pad.as_slice());
    inner_hasher.update(domain);
    inner_hasher.update(message);
    let mut inner_digest = inner_hasher.finalize();
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(outer_pad.as_slice());
    outer_hasher.update(inner_digest.as_slice());
    let mut digest = outer_hasher.finalize();
    let mut output = [0_u8; 32];
    output.copy_from_slice(digest.as_slice());
    inner_digest.as_mut_slice().zeroize();
    digest.as_mut_slice().zeroize();
    output
}

fn map_encryption_error(error: &SecretEncryptionLoadError) -> HumanAuthRuntimeError {
    match error {
        SecretEncryptionLoadError::Source(_) => HumanAuthRuntimeError::SecretUnavailable,
        SecretEncryptionLoadError::InvalidKeyConfiguration => {
            HumanAuthRuntimeError::InvalidEncryptionConfiguration
        }
    }
}

/// Sanitized human-auth runtime construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum HumanAuthRuntimeError {
    #[error("human authentication origin configuration is invalid")]
    InvalidOrigin,
    #[error("a human authentication secret is unavailable")]
    SecretUnavailable,
    #[error("human authentication secret configuration is invalid")]
    InvalidSecretConfiguration,
    #[error("human authentication HMAC key configuration is invalid")]
    InvalidHmacKeyConfiguration,
    #[error("human authentication encryption configuration is invalid")]
    InvalidEncryptionConfiguration,
    #[error("GitHub authentication configuration is invalid")]
    GithubConfiguration,
    #[error("the hardened GitHub HTTP client could not be configured")]
    GithubHttpConfiguration,
    #[error("human authentication session lifetime is invalid")]
    InvalidSessionLifetime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_material_is_deterministic_and_domain_separated() {
        let root = [0x5a_u8; 32];
        let session = derive_hmac_material(&root, SESSION_HMAC_DOMAIN).expect("session key");
        let session_again = derive_hmac_material(&root, SESSION_HMAC_DOMAIN).expect("session key");
        let login = derive_hmac_material(&root, LOGIN_PROOF_HMAC_DOMAIN).expect("login key");

        assert_eq!(session.expose_secret(), session_again.expose_secret());
        assert_ne!(session.expose_secret(), login.expose_secret());
        assert_ne!(session.expose_secret(), root.as_slice());
        assert_ne!(login.expose_secret(), root.as_slice());
    }

    #[test]
    fn hmac_derivation_rejects_wrong_root_length_and_empty_domain() {
        assert_eq!(
            derive_hmac_material(&[0_u8; 31], SESSION_HMAC_DOMAIN).unwrap_err(),
            HumanAuthRuntimeError::InvalidHmacKeyConfiguration
        );
        assert_eq!(
            derive_hmac_material(&[0_u8; 32], b"").unwrap_err(),
            HumanAuthRuntimeError::InvalidHmacKeyConfiguration
        );
    }

    #[test]
    fn idle_lifetimes_are_conservatively_capped_and_clamped() {
        let long = HumanAuthSessionLifetimes::from_absolute(
            Duration::from_hours(8),
            Duration::from_hours(720),
        )
        .expect("lifetimes");
        assert_eq!(long.idle(SessionKind::Browser), BROWSER_IDLE_LIFETIME_CAP);
        assert_eq!(long.idle(SessionKind::Cli), CLI_IDLE_LIFETIME_CAP);

        let short = HumanAuthSessionLifetimes::from_absolute(
            Duration::from_mins(5),
            Duration::from_mins(10),
        )
        .expect("lifetimes");
        assert_eq!(
            short.idle(SessionKind::Browser),
            short.absolute(SessionKind::Browser)
        );
        assert_eq!(
            short.idle(SessionKind::Cli),
            short.absolute(SessionKind::Cli)
        );
        assert!(short.github().is_ok());
    }

    #[test]
    fn lifetime_and_error_diagnostics_are_sanitized() {
        assert_eq!(
            HumanAuthSessionLifetimes::from_absolute(Duration::ZERO, Duration::from_mins(5))
                .unwrap_err(),
            HumanAuthRuntimeError::InvalidSessionLifetime
        );
        for error in [
            HumanAuthRuntimeError::SecretUnavailable,
            HumanAuthRuntimeError::InvalidSecretConfiguration,
            HumanAuthRuntimeError::InvalidHmacKeyConfiguration,
            HumanAuthRuntimeError::InvalidEncryptionConfiguration,
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains("secret-value"));
            assert!(!rendered.contains("env:"));
            assert!(!rendered.contains("file:"));
        }
    }
}
