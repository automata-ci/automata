//! Operator-proof-bound GitHub installation setup orchestration.
//!
//! The raw bootstrap token remains inside this product boundary long enough to
//! derive a keyed digest. Durable repositories receive only that digest, and
//! provider/session credentials remain linearly owned redacted values.

use std::{fmt, sync::Arc, time::Duration};

use automata_ci_auth::{
    github::{
        GithubBrowserBindingCookie, GithubDeviceLoginStart, GithubDevicePollCredential,
        GithubInstallationAuthentication, GithubInstallationDevicePollOutcome, GithubLoginError,
        GithubLoginService, GithubWebCallback, GithubWebLoginStart,
        MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS,
    },
    human::{AuthenticatedHuman, ProviderId, ProviderIdentityAssertion, ProviderSubject},
    installation::{
        ArmInstallationSetup, BindInstallationLogin, CompleteInstallationOutcome,
        CompleteInstallationSetup, InstallationProviderAuthentication, InstallationRepository,
        InstallationRepositoryError, InstallationRevision, InstallationState, InstallationTenant,
    },
    login::{LoginReturnPath, LoginTransactionId},
    session::{DurableSession, SessionKind},
    session_credential::{
        SessionCredential, SessionCredentialService, SessionCredentialServiceError,
    },
    time::{Clock, UnixTimestamp},
};
use thiserror::Error;

use super::human_auth::{HumanAuthSessionLifetimes, InstallationProofHasher};

const GITHUB_PROVIDER_ID: &str = "github";
const SETUP_CHALLENGE_LIFETIME: Duration = Duration::from_hours(1);
const MIN_BOOTSTRAP_TOKEN_BYTES: usize = 32;
const MAX_BOOTSTRAP_TOKEN_BYTES: usize = 4 * 1_024;

/// Fully composed installation setup service for one configured tenant/identity.
pub(crate) struct InstallationSetupService {
    login: Arc<GithubLoginService>,
    installations: Arc<dyn InstallationRepository>,
    sessions: Arc<SessionCredentialService>,
    proofs: Arc<InstallationProofHasher>,
    tenant: InstallationTenant,
    provider_id: ProviderId,
    expected_subject: ProviderSubject,
    clock: Arc<dyn Clock>,
    lifetimes: HumanAuthSessionLifetimes,
}

impl InstallationSetupService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        login: Arc<GithubLoginService>,
        installations: Arc<dyn InstallationRepository>,
        sessions: Arc<SessionCredentialService>,
        proofs: Arc<InstallationProofHasher>,
        tenant: InstallationTenant,
        expected_subject: ProviderSubject,
        clock: Arc<dyn Clock>,
        lifetimes: HumanAuthSessionLifetimes,
    ) -> Result<Self, InstallationSetupError> {
        let provider_id = ProviderId::new(GITHUB_PROVIDER_ID)
            .map_err(|_| InstallationSetupError::IntegrityFailure)?;
        Ok(Self {
            login,
            installations,
            sessions,
            proofs,
            tenant,
            provider_id,
            expected_subject,
            clock,
            lifetimes,
        })
    }

    /// Arms a fresh or expired installation challenge from operator config.
    pub(crate) async fn ensure_armed(
        &self,
        bootstrap_token: &str,
    ) -> Result<InstallationState, InstallationSetupError> {
        validate_bootstrap_token(bootstrap_token)?;
        let now = self.clock.now();
        let current = self
            .installations
            .load()
            .await
            .map_err(map_installation_error)?;
        match &current {
            InstallationState::Configured { .. } => return Ok(current),
            InstallationState::Armed {
                tenant_id,
                provider_id,
                expected_provider_subject,
                expires_at,
                ..
            }
            | InstallationState::LoginBound {
                tenant_id,
                provider_id,
                expected_provider_subject,
                expires_at,
                ..
            } if *expires_at > now => {
                if tenant_id != self.tenant.tenant_id()
                    || provider_id != &self.provider_id
                    || expected_provider_subject != &self.expected_subject
                {
                    return Err(InstallationSetupError::StateConflict);
                }
            }
            InstallationState::Unconfigured { .. }
            | InstallationState::Armed { .. }
            | InstallationState::LoginBound { .. } => {}
        }
        let expires_at = now
            .checked_add(SETUP_CHALLENGE_LIFETIME.as_secs())
            .map_err(|_| InstallationSetupError::IntegrityFailure)?;
        let request = ArmInstallationSetup::new(
            self.tenant.clone(),
            self.proofs.proof(bootstrap_token),
            self.provider_id.clone(),
            self.expected_subject.clone(),
            now,
            expires_at,
        )
        .map_err(|_| InstallationSetupError::IntegrityFailure)?;
        self.installations
            .arm(request)
            .await
            .map_err(map_installation_error)
    }

    /// Begins and proof-binds one browser setup transaction.
    pub(crate) async fn begin_web(
        &self,
        bootstrap_token: &str,
        return_path: LoginReturnPath,
    ) -> Result<GithubWebLoginStart, InstallationSetupError> {
        self.ensure_armed(bootstrap_token).await?;
        let now = self.clock.now();
        let revision = self.bindable_revision(now).await?;
        let started = self
            .login
            .begin_installation_web(return_path)
            .await
            .map_err(map_login_error)?;
        let transaction_id = started.binding_cookie().transaction_id().clone();
        self.bind_transaction(revision, bootstrap_token, transaction_id, now)
            .await?;
        Ok(started)
    }

    /// Completes the exact consumed browser transaction and issues its first session.
    pub(crate) async fn complete_web(
        &self,
        binding: GithubBrowserBindingCookie,
        callback: &GithubWebCallback,
    ) -> Result<InstallationSetupCompletion, InstallationSetupError> {
        let authenticated = self
            .login
            .complete_installation_web(binding, callback)
            .await
            .map_err(map_login_error)?;
        self.complete_authenticated(authenticated, SessionKind::Browser)
            .await
    }

    /// Begins and proof-binds one CLI device setup transaction.
    pub(crate) async fn begin_device(
        &self,
        bootstrap_token: &str,
        return_path: Option<LoginReturnPath>,
    ) -> Result<GithubDeviceLoginStart, InstallationSetupError> {
        self.ensure_armed(bootstrap_token).await?;
        let now = self.clock.now();
        let revision = self.bindable_revision(now).await?;
        let started = self
            .login
            .begin_installation_device(return_path)
            .await
            .map_err(map_login_error)?;
        let transaction_id = started.poll_credential().transaction_id().clone();
        self.bind_transaction(revision, bootstrap_token, transaction_id, now)
            .await?;
        Ok(started)
    }

    /// Polls a bound setup device flow and issues the initial CLI session once.
    pub(crate) async fn poll_device(
        &self,
        poll_credential: GithubDevicePollCredential,
    ) -> Result<InstallationDevicePollOutcome, InstallationSetupError> {
        match self
            .login
            .poll_installation_device(poll_credential)
            .await
            .map_err(map_login_error)?
        {
            GithubInstallationDevicePollOutcome::Pending { next_poll_at } => {
                Ok(InstallationDevicePollOutcome::Pending { next_poll_at })
            }
            GithubInstallationDevicePollOutcome::SlowDown { next_poll_at } => {
                Ok(InstallationDevicePollOutcome::SlowDown { next_poll_at })
            }
            GithubInstallationDevicePollOutcome::Complete(authenticated) => self
                .complete_authenticated(*authenticated, SessionKind::Cli)
                .await
                .map(|completion| InstallationDevicePollOutcome::Complete(Box::new(completion))),
            GithubInstallationDevicePollOutcome::Denied => {
                Ok(InstallationDevicePollOutcome::Denied)
            }
            GithubInstallationDevicePollOutcome::Expired => {
                Ok(InstallationDevicePollOutcome::Expired)
            }
        }
    }

    async fn bindable_revision(
        &self,
        now: UnixTimestamp,
    ) -> Result<automata_ci_auth::installation::InstallationRevision, InstallationSetupError> {
        match self
            .installations
            .load()
            .await
            .map_err(map_installation_error)?
        {
            InstallationState::Armed {
                revision,
                tenant_id,
                provider_id,
                expected_provider_subject,
                expires_at,
            }
            | InstallationState::LoginBound {
                revision,
                tenant_id,
                provider_id,
                expected_provider_subject,
                expires_at,
                ..
            } if expires_at > now
                && tenant_id == *self.tenant.tenant_id()
                && provider_id == self.provider_id
                && expected_provider_subject == self.expected_subject =>
            {
                Ok(revision)
            }
            InstallationState::Configured { .. } => Err(InstallationSetupError::AlreadyConfigured),
            InstallationState::Armed { expires_at, .. }
            | InstallationState::LoginBound { expires_at, .. }
                if expires_at <= now =>
            {
                Err(InstallationSetupError::Expired)
            }
            InstallationState::Unconfigured { .. }
            | InstallationState::Armed { .. }
            | InstallationState::LoginBound { .. } => Err(InstallationSetupError::NotArmed),
        }
    }

    async fn bind_transaction(
        &self,
        revision: automata_ci_auth::installation::InstallationRevision,
        bootstrap_token: &str,
        transaction_id: LoginTransactionId,
        now: UnixTimestamp,
    ) -> Result<(), InstallationSetupError> {
        let expected_transaction_id = transaction_id.clone();
        let request = BindInstallationLogin::new(
            revision,
            self.proofs.proof(bootstrap_token),
            transaction_id,
            now,
        );
        match self
            .installations
            .bind_login(request)
            .await
            .map_err(map_installation_error)?
        {
            InstallationState::LoginBound {
                tenant_id,
                provider_id,
                expected_provider_subject,
                login_transaction_id,
                expires_at,
                ..
            } if tenant_id == *self.tenant.tenant_id()
                && provider_id == self.provider_id
                && expected_provider_subject == self.expected_subject
                && login_transaction_id == expected_transaction_id
                && expires_at > now =>
            {
                Ok(())
            }
            InstallationState::LoginBound { .. }
            | InstallationState::Unconfigured { .. }
            | InstallationState::Armed { .. }
            | InstallationState::Configured { .. } => Err(InstallationSetupError::IntegrityFailure),
        }
    }

    async fn completion_revision(
        &self,
        transaction_id: &LoginTransactionId,
        now: UnixTimestamp,
    ) -> Result<InstallationRevision, InstallationSetupError> {
        match self
            .installations
            .load()
            .await
            .map_err(map_installation_error)?
        {
            InstallationState::LoginBound {
                revision,
                login_transaction_id,
                expires_at,
                ..
            } if login_transaction_id == transaction_id.clone() && expires_at > now => Ok(revision),
            InstallationState::Configured { .. } => Err(InstallationSetupError::AlreadyConfigured),
            InstallationState::LoginBound { expires_at, .. } if expires_at <= now => {
                Err(InstallationSetupError::Expired)
            }
            InstallationState::Unconfigured { .. }
            | InstallationState::Armed { .. }
            | InstallationState::LoginBound { .. } => Err(InstallationSetupError::StateConflict),
        }
    }

    async fn complete_authenticated(
        &self,
        authenticated: GithubInstallationAuthentication,
        kind: SessionKind,
    ) -> Result<InstallationSetupCompletion, InstallationSetupError> {
        let (transaction_id, identity, provider_tokens, membership, return_path) =
            authenticated.into_parts();
        if !matches_expected_identity(&identity, &self.provider_id, &self.expected_subject) {
            return Err(InstallationSetupError::NotAuthorized);
        }
        let now = self.clock.now();
        let revision = self.completion_revision(&transaction_id, now).await?;
        let human_identity = identity.clone();
        let authentication = InstallationProviderAuthentication::new(
            transaction_id,
            identity,
            provider_tokens,
            membership,
        )
        .map_err(|_| InstallationSetupError::IntegrityFailure)?;
        let prepared = self
            .sessions
            .prepare(
                kind,
                self.lifetimes.idle(kind),
                self.lifetimes.absolute(kind),
            )
            .map_err(map_session_error)?;
        let (mut credential, candidate) = prepared.into_parts();
        let mut request = CompleteInstallationSetup::new(
            revision,
            self.tenant.clone(),
            authentication,
            candidate,
            self.clock.now(),
        )
        .map_err(|_| InstallationSetupError::IntegrityFailure)?;

        for attempt in 0..MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS {
            match self
                .installations
                .complete(request)
                .await
                .map_err(map_installation_error)?
            {
                CompleteInstallationOutcome::Completed(completed) => {
                    let human = human_identity
                        .clone()
                        .into_authenticated_human(completed.principal_id().clone());
                    let session = completed.into_session();
                    if session.identity().tenant_id() != self.tenant.tenant_id()
                        || session.identity().principal_id() != human.principal_id()
                        || session.identity().provider_id() != human.provider_id()
                        || session.identity().provider_subject() != human.provider_subject()
                        || session.identity().kind() != kind
                    {
                        return Err(InstallationSetupError::IntegrityFailure);
                    }
                    return Ok(InstallationSetupCompletion {
                        credential,
                        human,
                        session,
                        return_path,
                    });
                }
                CompleteInstallationOutcome::SessionConflict { retry, .. }
                    if attempt + 1 < MAX_GITHUB_LOGIN_COLLISION_ATTEMPTS =>
                {
                    drop(credential);
                    let prepared = self
                        .sessions
                        .prepare(
                            kind,
                            self.lifetimes.idle(kind),
                            self.lifetimes.absolute(kind),
                        )
                        .map_err(map_session_error)?;
                    let (replacement_credential, candidate) = prepared.into_parts();
                    request = retry
                        .with_session(candidate, self.clock.now())
                        .map_err(|_| InstallationSetupError::IntegrityFailure)?;
                    credential = replacement_credential;
                }
                CompleteInstallationOutcome::SessionConflict { .. } => {
                    return Err(InstallationSetupError::CollisionLimitExceeded);
                }
            }
        }
        Err(InstallationSetupError::CollisionLimitExceeded)
    }
}

fn matches_expected_identity(
    identity: &ProviderIdentityAssertion,
    provider_id: &ProviderId,
    expected_subject: &ProviderSubject,
) -> bool {
    identity.provider_id() == provider_id && identity.provider_subject() == expected_subject
}

impl fmt::Debug for InstallationSetupService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallationSetupService")
            .field("login", &self.login)
            .field("installations", &self.installations)
            .field("sessions", &"SessionCredentialService(..)")
            .field("proofs", &self.proofs)
            .field("tenant", &self.tenant)
            .field("provider_id", &self.provider_id)
            .field("expected_subject", &self.expected_subject)
            .field("lifetimes", &self.lifetimes)
            .finish_non_exhaustive()
    }
}

/// Successful installation plus its newly persisted first session.
pub(crate) struct InstallationSetupCompletion {
    credential: SessionCredential,
    human: AuthenticatedHuman,
    session: Box<DurableSession>,
    return_path: Option<LoginReturnPath>,
}

impl InstallationSetupCompletion {
    pub(crate) fn into_parts(
        self,
    ) -> (
        SessionCredential,
        AuthenticatedHuman,
        Box<DurableSession>,
        Option<LoginReturnPath>,
    ) {
        (self.credential, self.human, self.session, self.return_path)
    }
}

impl fmt::Debug for InstallationSetupCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallationSetupCompletion")
            .field("credential", &"[REDACTED]")
            .field("human", &self.human)
            .field("session", &self.session)
            .field("return_path", &self.return_path)
            .finish()
    }
}

pub(crate) enum InstallationDevicePollOutcome {
    Pending { next_poll_at: UnixTimestamp },
    SlowDown { next_poll_at: UnixTimestamp },
    Complete(Box<InstallationSetupCompletion>),
    Denied,
    Expired,
}

fn validate_bootstrap_token(token: &str) -> Result<(), InstallationSetupError> {
    if token.len() < MIN_BOOTSTRAP_TOKEN_BYTES
        || token.len() > MAX_BOOTSTRAP_TOKEN_BYTES
        || token.chars().any(char::is_control)
    {
        return Err(InstallationSetupError::InvalidProof);
    }
    Ok(())
}

fn map_login_error(error: GithubLoginError) -> InstallationSetupError {
    match error {
        GithubLoginError::Invalid => InstallationSetupError::InvalidRequest,
        GithubLoginError::Replay => InstallationSetupError::Replay,
        GithubLoginError::Expired => InstallationSetupError::Expired,
        GithubLoginError::Denied => InstallationSetupError::Denied,
        GithubLoginError::PollTooEarly { next_poll_at } => {
            InstallationSetupError::PollTooEarly { next_poll_at }
        }
        GithubLoginError::RateLimited {
            retry_after_seconds,
        } => InstallationSetupError::RateLimited {
            retry_after_seconds,
        },
        GithubLoginError::ProviderUnavailable => InstallationSetupError::ProviderUnavailable,
        GithubLoginError::StorageUnavailable => InstallationSetupError::StorageUnavailable,
        GithubLoginError::RandomnessUnavailable => InstallationSetupError::RandomnessUnavailable,
        GithubLoginError::NotAuthorized => InstallationSetupError::NotAuthorized,
        GithubLoginError::CollisionLimitExceeded => InstallationSetupError::CollisionLimitExceeded,
        GithubLoginError::IntegrityFailure => InstallationSetupError::IntegrityFailure,
    }
}

fn map_installation_error(error: InstallationRepositoryError) -> InstallationSetupError {
    match error {
        InstallationRepositoryError::InvalidRequest => InstallationSetupError::InvalidRequest,
        InstallationRepositoryError::NotArmed => InstallationSetupError::NotArmed,
        InstallationRepositoryError::ProofRejected => InstallationSetupError::InvalidProof,
        InstallationRepositoryError::Expired => InstallationSetupError::Expired,
        InstallationRepositoryError::AlreadyBound
        | InstallationRepositoryError::VersionConflict
        | InstallationRepositoryError::IdentityConflict => InstallationSetupError::StateConflict,
        InstallationRepositoryError::AlreadyConfigured => InstallationSetupError::AlreadyConfigured,
        InstallationRepositoryError::CredentialCustody => {
            InstallationSetupError::StorageUnavailable
        }
        InstallationRepositoryError::Unavailable => InstallationSetupError::StorageUnavailable,
        InstallationRepositoryError::CorruptData => InstallationSetupError::IntegrityFailure,
    }
}

fn map_session_error(error: SessionCredentialServiceError) -> InstallationSetupError {
    match error {
        SessionCredentialServiceError::RepositoryUnavailable => {
            InstallationSetupError::StorageUnavailable
        }
        SessionCredentialServiceError::RandomnessUnavailable => {
            InstallationSetupError::RandomnessUnavailable
        }
        SessionCredentialServiceError::CollisionLimitExceeded => {
            InstallationSetupError::CollisionLimitExceeded
        }
        SessionCredentialServiceError::InvalidCredential
        | SessionCredentialServiceError::InvalidLifetime
        | SessionCredentialServiceError::LifetimeOverflow
        | SessionCredentialServiceError::InternalFailure => {
            InstallationSetupError::IntegrityFailure
        }
    }
}

/// Sanitized installation-setup failure contract for HTTP/CLI adapters.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum InstallationSetupError {
    #[error("installation setup request is invalid")]
    InvalidRequest,
    #[error("installation bootstrap proof was rejected")]
    InvalidProof,
    #[error("installation setup is not armed")]
    NotArmed,
    #[error("installation setup state changed")]
    StateConflict,
    #[error("installation setup request was already used")]
    Replay,
    #[error("installation setup challenge expired")]
    Expired,
    #[error("GitHub authorization was denied")]
    Denied,
    #[error("GitHub device authorization was polled too early")]
    PollTooEarly { next_poll_at: UnixTimestamp },
    #[error("GitHub rate limit was exceeded")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("GitHub authentication is unavailable")]
    ProviderUnavailable,
    #[error("installation storage is unavailable")]
    StorageUnavailable,
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("the authenticated GitHub identity is not the configured bootstrap identity")]
    NotAuthorized,
    #[error("installation setup collision budget was exhausted")]
    CollisionLimitExceeded,
    #[error("installation is already configured")]
    AlreadyConfigured,
    #[error("installation setup failed an integrity check")]
    IntegrityFailure,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(provider: &str, subject: &str) -> ProviderIdentityAssertion {
        ProviderIdentityAssertion::new(
            ProviderId::new(provider).expect("provider ID"),
            ProviderSubject::new(subject).expect("provider subject"),
            "octocat",
            Some("The Octocat".to_owned()),
            UnixTimestamp::from_seconds(10),
        )
        .expect("provider identity")
    }

    #[test]
    fn configured_provider_and_stable_subject_must_both_match() {
        let provider = ProviderId::new("github").expect("provider ID");
        let subject = ProviderSubject::new("42").expect("provider subject");

        assert!(matches_expected_identity(
            &identity("github", "42"),
            &provider,
            &subject
        ));
        assert!(!matches_expected_identity(
            &identity("github", "43"),
            &provider,
            &subject
        ));
        assert!(!matches_expected_identity(
            &identity("gitlab", "42"),
            &provider,
            &subject
        ));
    }

    #[test]
    fn bootstrap_tokens_are_bounded_before_hashing_or_storage() {
        assert!(validate_bootstrap_token(&"x".repeat(MIN_BOOTSTRAP_TOKEN_BYTES)).is_ok());
        for invalid in [
            "x".repeat(MIN_BOOTSTRAP_TOKEN_BYTES - 1),
            "x".repeat(MAX_BOOTSTRAP_TOKEN_BYTES + 1),
            format!("{}\n", "x".repeat(MIN_BOOTSTRAP_TOKEN_BYTES)),
        ] {
            assert_eq!(
                validate_bootstrap_token(&invalid),
                Err(InstallationSetupError::InvalidProof)
            );
        }
    }
}
