use std::fmt;

use automata_ci_auth::time::UnixTimestamp;
use automata_ci_auth::{
    human::{PrincipalId, ProviderId, ProviderSubject, TenantId},
    session::{
        ActivateCliSession, ActivateCliSessionOutcome, CLI_SESSION_ACTIVATION_LIFETIME_SECONDS,
        CreateSession, CreateSessionOutcome, DurableSession, DurableSessionIdentity,
        HumanSessionRepository, ResolveSession, ResolveSessionOutcome, RevokeOwnSession,
        RevokeOwnSessionOutcome, RevokePrincipalSessions, RevokePrincipalSessionsOutcome,
        SessionId, SessionKind, SessionRepositoryError, SessionRepositoryFuture,
        SessionResolutionStatus, SessionTokenLookup, TouchSession, TouchSessionOutcome,
    },
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::support::{
    canonical_uuid, constraint, is_integrity_violation, timestamp_from_milliseconds,
    timestamp_to_milliseconds,
};

/// `PostgreSQL` implementation of the durable human-session boundary.
#[derive(Clone)]
pub struct PostgresHumanSessionRepository {
    pool: PgPool,
}

impl PostgresHumanSessionRepository {
    /// Creates a human-session repository backed by `pool`.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub(crate) async fn create_in_transaction(
        transaction: &mut Transaction<'_, Postgres>,
        request: CreateSession,
    ) -> Result<(CreateSessionOutcome, Option<DurableSession>), SessionRepositoryError> {
        create_session(transaction, request).await
    }
}

const MAX_CALLER_CLOCK_SKEW_MILLISECONDS: u64 = 60_000;

pub(crate) async fn database_time_milliseconds(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000")
        .fetch_one(&mut **transaction)
        .await
}

pub(crate) fn validate_caller_time(
    caller: UnixTimestamp,
    database_time_ms: i64,
) -> Result<UnixTimestamp, ()> {
    let caller_ms = timestamp_to_milliseconds(caller)?;
    if caller_ms.abs_diff(database_time_ms) > MAX_CALLER_CLOCK_SKEW_MILLISECONDS {
        return Err(());
    }
    timestamp_from_milliseconds(database_time_ms)
}

async fn lock_session_authority(
    transaction: &mut Transaction<'_, Postgres>,
    lookup: &SessionTokenLookup,
    exclusive: bool,
) -> Result<bool, SessionRepositoryError> {
    // Canonical existing-session order: session, principal, membership. The
    // explicit statements make this compatible with sign-in's principal,
    // provider-identity, membership order regardless of join planning.
    let owner: Option<(String, Uuid)> = if exclusive {
        sqlx::query_as(
            r"
            SELECT tenant_id,principal_id FROM human_sessions
            WHERE token_hash_key_id=$1 AND token_hash=$2 FOR UPDATE
            ",
        )
        .bind(lookup.key_id().as_str())
        .bind(lookup.digest().as_bytes().as_slice())
        .fetch_optional(&mut **transaction)
        .await
    } else {
        sqlx::query_as(
            r"
            SELECT tenant_id,principal_id FROM human_sessions
            WHERE token_hash_key_id=$1 AND token_hash=$2 FOR KEY SHARE
            ",
        )
        .bind(lookup.key_id().as_str())
        .bind(lookup.digest().as_bytes().as_slice())
        .fetch_optional(&mut **transaction)
        .await
    }
    .map_err(|_| SessionRepositoryError::Unavailable)?;
    let Some((tenant_id, principal_id)) = owner else {
        return Ok(false);
    };
    let principal: Option<Uuid> = if exclusive {
        sqlx::query_scalar("SELECT id FROM human_principals WHERE id=$1 FOR UPDATE")
            .bind(principal_id)
            .fetch_optional(&mut **transaction)
            .await
    } else {
        sqlx::query_scalar("SELECT id FROM human_principals WHERE id=$1 FOR KEY SHARE")
            .bind(principal_id)
            .fetch_optional(&mut **transaction)
            .await
    }
    .map_err(|_| SessionRepositoryError::Unavailable)?;
    if principal != Some(principal_id) {
        return Ok(false);
    }
    let membership: Option<Uuid> = if exclusive {
        sqlx::query_scalar(
            "SELECT principal_id FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2 FOR UPDATE",
        )
        .bind(&tenant_id)
        .bind(principal_id)
        .fetch_optional(&mut **transaction)
        .await
    } else {
        sqlx::query_scalar(
            "SELECT principal_id FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2 FOR KEY SHARE",
        )
        .bind(&tenant_id)
        .bind(principal_id)
        .fetch_optional(&mut **transaction)
        .await
    }
    .map_err(|_| SessionRepositoryError::Unavailable)?;
    Ok(membership == Some(principal_id))
}

impl fmt::Debug for PostgresHumanSessionRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresHumanSessionRepository")
            .finish_non_exhaustive()
    }
}

#[derive(FromRow)]
struct SessionRow {
    id: Uuid,
    tenant_id: String,
    principal_id: Uuid,
    provider_id: String,
    provider_subject: String,
    session_kind: String,
    audience: String,
    authorization_revision: i64,
    issued_at_ms: i64,
    last_seen_at_ms: i64,
    idle_expires_at_ms: i64,
    expires_at_ms: i64,
    revoked_at_ms: Option<i64>,
    lifecycle_status: String,
    activation_deadline_ms: Option<i64>,
    activated_at_ms: Option<i64>,
    principal_status: String,
    membership_status: String,
    current_authorization_revision: i64,
}

enum ClassifiedSession {
    Active(DurableSession),
    WrongKindOrAudience,
    Revoked,
    Expired,
    NotYetValid,
    PrincipalDisabled,
    MembershipSuspended,
    AuthorizationRevisionChanged {
        session_revision: u64,
        current_revision: u64,
    },
}

#[derive(Clone, Copy)]
enum SessionLifecycle {
    Active,
    PendingActivation {
        deadline: automata_ci_auth::time::UnixTimestamp,
    },
}

enum CliActivationClassification {
    Pending(DurableSession),
    AlreadyActive(DurableSession),
    ActivationExpired,
    Closed(ClassifiedSession),
}

impl SessionRow {
    fn classify(
        &self,
        expected_kind: SessionKind,
        now: automata_ci_auth::time::UnixTimestamp,
    ) -> Result<ClassifiedSession, SessionRepositoryError> {
        let lifecycle = self.lifecycle(now)?;
        let classified = self.classify_authority(expected_kind, now)?;
        Ok(match (classified, lifecycle) {
            (ClassifiedSession::Active(_), SessionLifecycle::PendingActivation { .. }) => {
                ClassifiedSession::NotYetValid
            }
            (classified, _) => classified,
        })
    }

    fn classify_authority(
        &self,
        expected_kind: SessionKind,
        now: automata_ci_auth::time::UnixTimestamp,
    ) -> Result<ClassifiedSession, SessionRepositoryError> {
        let session = self.to_domain()?;
        if self.principal_status == "disabled" {
            return Ok(ClassifiedSession::PrincipalDisabled);
        }
        if self.principal_status != "active" {
            return Err(SessionRepositoryError::CorruptData);
        }
        if self.membership_status == "suspended" {
            return Ok(ClassifiedSession::MembershipSuspended);
        }
        if self.membership_status != "active" {
            return Err(SessionRepositoryError::CorruptData);
        }
        let current_revision = positive_revision(self.current_authorization_revision)?;
        Ok(
            match session.resolution_status(expected_kind, now, current_revision) {
                SessionResolutionStatus::Active => ClassifiedSession::Active(session),
                SessionResolutionStatus::WrongKindOrAudience => {
                    ClassifiedSession::WrongKindOrAudience
                }
                SessionResolutionStatus::Revoked => ClassifiedSession::Revoked,
                SessionResolutionStatus::Expired => ClassifiedSession::Expired,
                SessionResolutionStatus::NotYetValid => ClassifiedSession::NotYetValid,
                SessionResolutionStatus::AuthorizationRevisionChanged {
                    session_revision,
                    current_revision,
                } => ClassifiedSession::AuthorizationRevisionChanged {
                    session_revision,
                    current_revision,
                },
            },
        )
    }

    fn classify_cli_activation(
        &self,
        now: automata_ci_auth::time::UnixTimestamp,
    ) -> Result<CliActivationClassification, SessionRepositoryError> {
        let lifecycle = self.lifecycle(now)?;
        let classified = self.classify_authority(SessionKind::Cli, now)?;
        Ok(match (classified, lifecycle) {
            (ClassifiedSession::Active(session), SessionLifecycle::Active) => {
                CliActivationClassification::AlreadyActive(session)
            }
            (ClassifiedSession::Active(_), SessionLifecycle::PendingActivation { deadline })
                if deadline <= now =>
            {
                CliActivationClassification::ActivationExpired
            }
            (ClassifiedSession::Active(session), SessionLifecycle::PendingActivation { .. }) => {
                CliActivationClassification::Pending(session)
            }
            (classified, _) => CliActivationClassification::Closed(classified),
        })
    }

    fn lifecycle(
        &self,
        now: automata_ci_auth::time::UnixTimestamp,
    ) -> Result<SessionLifecycle, SessionRepositoryError> {
        match (
            self.session_kind.as_str(),
            self.audience.as_str(),
            self.lifecycle_status.as_str(),
            self.activation_deadline_ms,
            self.activated_at_ms,
        ) {
            ("browser", "automata.web", "active", None, None) => Ok(SessionLifecycle::Active),
            ("cli", "automata.cli", "pending_activation", Some(deadline), None) => {
                let deadline = timestamp_from_milliseconds(deadline)
                    .map_err(|()| SessionRepositoryError::CorruptData)?;
                let issued_at = timestamp_from_milliseconds(self.issued_at_ms)
                    .map_err(|()| SessionRepositoryError::CorruptData)?;
                if deadline <= issued_at
                    || deadline
                        > timestamp_from_milliseconds(self.expires_at_ms)
                            .map_err(|()| SessionRepositoryError::CorruptData)?
                    || deadline.as_seconds() - issued_at.as_seconds()
                        > CLI_SESSION_ACTIVATION_LIFETIME_SECONDS
                {
                    return Err(SessionRepositoryError::CorruptData);
                }
                Ok(SessionLifecycle::PendingActivation { deadline })
            }
            ("cli", "automata.cli", "active", Some(deadline), Some(activated_at)) => {
                let deadline = timestamp_from_milliseconds(deadline)
                    .map_err(|()| SessionRepositoryError::CorruptData)?;
                let activated_at = timestamp_from_milliseconds(activated_at)
                    .map_err(|()| SessionRepositoryError::CorruptData)?;
                let issued_at = timestamp_from_milliseconds(self.issued_at_ms)
                    .map_err(|()| SessionRepositoryError::CorruptData)?;
                if deadline <= issued_at
                    || deadline
                        > timestamp_from_milliseconds(self.expires_at_ms)
                            .map_err(|()| SessionRepositoryError::CorruptData)?
                    || deadline.as_seconds() - issued_at.as_seconds()
                        > CLI_SESSION_ACTIVATION_LIFETIME_SECONDS
                    || activated_at < issued_at
                    || activated_at >= deadline
                    || activated_at > now
                {
                    return Err(SessionRepositoryError::CorruptData);
                }
                Ok(SessionLifecycle::Active)
            }
            _ => Err(SessionRepositoryError::CorruptData),
        }
    }

    fn to_domain(&self) -> Result<DurableSession, SessionRepositoryError> {
        let kind = match (self.session_kind.as_str(), self.audience.as_str()) {
            ("browser", "automata.web") => SessionKind::Browser,
            ("cli", "automata.cli") => SessionKind::Cli,
            _ => return Err(SessionRepositoryError::CorruptData),
        };
        let identity = DurableSessionIdentity::new(
            SessionId::new(self.id.hyphenated().to_string())
                .map_err(|_| SessionRepositoryError::CorruptData)?,
            TenantId::new(self.tenant_id.clone())
                .map_err(|_| SessionRepositoryError::CorruptData)?,
            PrincipalId::new(self.principal_id.hyphenated().to_string())
                .map_err(|_| SessionRepositoryError::CorruptData)?,
            ProviderId::new(self.provider_id.clone())
                .map_err(|_| SessionRepositoryError::CorruptData)?,
            ProviderSubject::new(self.provider_subject.clone())
                .map_err(|_| SessionRepositoryError::CorruptData)?,
            kind,
        )
        .map_err(|_| SessionRepositoryError::CorruptData)?;
        DurableSession::new(
            identity,
            positive_revision(self.authorization_revision)?,
            timestamp_from_milliseconds(self.issued_at_ms)
                .map_err(|()| SessionRepositoryError::CorruptData)?,
            timestamp_from_milliseconds(self.last_seen_at_ms)
                .map_err(|()| SessionRepositoryError::CorruptData)?,
            timestamp_from_milliseconds(self.idle_expires_at_ms)
                .map_err(|()| SessionRepositoryError::CorruptData)?,
            timestamp_from_milliseconds(self.expires_at_ms)
                .map_err(|()| SessionRepositoryError::CorruptData)?,
            self.revoked_at_ms
                .map(timestamp_from_milliseconds)
                .transpose()
                .map_err(|()| SessionRepositoryError::CorruptData)?,
        )
        .map_err(|_| SessionRepositoryError::CorruptData)
    }
}

fn positive_revision(value: i64) -> Result<u64, SessionRepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(SessionRepositoryError::CorruptData)
}

const SESSION_SELECT: &str = r"
    SELECT s.id, s.tenant_id, s.principal_id, s.provider_id, s.provider_subject,
           s.session_kind, s.audience, s.authorization_revision,
           s.issued_at_ms, s.last_seen_at_ms, s.idle_expires_at_ms,
           s.expires_at_ms, s.revoked_at_ms, s.lifecycle_status,
           s.activation_deadline_ms, s.activated_at_ms,
           p.status AS principal_status, m.status AS membership_status,
           m.authorization_revision AS current_authorization_revision
    FROM human_sessions s
    JOIN human_principals p ON p.id = s.principal_id
    JOIN tenant_human_memberships m
      ON m.tenant_id = s.tenant_id AND m.principal_id = s.principal_id
    WHERE s.token_hash_key_id = $1 AND s.token_hash = $2
";

fn resolve_outcome(classified: ClassifiedSession) -> ResolveSessionOutcome {
    match classified {
        ClassifiedSession::Active(session) => ResolveSessionOutcome::Active(Box::new(session)),
        ClassifiedSession::WrongKindOrAudience => ResolveSessionOutcome::WrongKindOrAudience,
        ClassifiedSession::Revoked => ResolveSessionOutcome::Revoked,
        ClassifiedSession::Expired => ResolveSessionOutcome::Expired,
        ClassifiedSession::NotYetValid => ResolveSessionOutcome::NotYetValid,
        ClassifiedSession::PrincipalDisabled => ResolveSessionOutcome::PrincipalDisabled,
        ClassifiedSession::MembershipSuspended => ResolveSessionOutcome::MembershipSuspended,
        ClassifiedSession::AuthorizationRevisionChanged {
            session_revision,
            current_revision,
        } => ResolveSessionOutcome::AuthorizationRevisionChanged {
            session_revision,
            current_revision,
        },
    }
}

fn touch_outcome(classified: ClassifiedSession) -> TouchSessionOutcome {
    match classified {
        ClassifiedSession::Active(session) => TouchSessionOutcome::Unchanged(Box::new(session)),
        ClassifiedSession::WrongKindOrAudience => TouchSessionOutcome::WrongKindOrAudience,
        ClassifiedSession::Revoked => TouchSessionOutcome::Revoked,
        ClassifiedSession::Expired => TouchSessionOutcome::Expired,
        ClassifiedSession::NotYetValid => TouchSessionOutcome::NotYetValid,
        ClassifiedSession::PrincipalDisabled => TouchSessionOutcome::PrincipalDisabled,
        ClassifiedSession::MembershipSuspended => TouchSessionOutcome::MembershipSuspended,
        ClassifiedSession::AuthorizationRevisionChanged {
            session_revision,
            current_revision,
        } => TouchSessionOutcome::AuthorizationRevisionChanged {
            session_revision,
            current_revision,
        },
    }
}

fn activation_closed_outcome(
    classified: &ClassifiedSession,
) -> Result<ActivateCliSessionOutcome, SessionRepositoryError> {
    Ok(match classified {
        ClassifiedSession::Active(_) => return Err(SessionRepositoryError::CorruptData),
        ClassifiedSession::WrongKindOrAudience => ActivateCliSessionOutcome::WrongKindOrAudience,
        ClassifiedSession::Revoked => ActivateCliSessionOutcome::Revoked,
        ClassifiedSession::Expired => ActivateCliSessionOutcome::Expired,
        ClassifiedSession::NotYetValid => ActivateCliSessionOutcome::NotYetValid,
        ClassifiedSession::PrincipalDisabled => ActivateCliSessionOutcome::PrincipalDisabled,
        ClassifiedSession::MembershipSuspended => ActivateCliSessionOutcome::MembershipSuspended,
        ClassifiedSession::AuthorizationRevisionChanged {
            session_revision,
            current_revision,
        } => ActivateCliSessionOutcome::AuthorizationRevisionChanged {
            session_revision: *session_revision,
            current_revision: *current_revision,
        },
    })
}

async fn create_session(
    transaction: &mut Transaction<'_, Postgres>,
    request: CreateSession,
) -> Result<(CreateSessionOutcome, Option<DurableSession>), SessionRepositoryError> {
    let (lookup, session) = request.into_parts();
    if session.revoked_at().is_some() {
        return Err(SessionRepositoryError::InvalidRequest);
    }
    let identity = session.identity();
    let id = canonical_uuid(identity.session_id().as_str())
        .map_err(|()| SessionRepositoryError::InvalidRequest)?;
    let principal_id = canonical_uuid(identity.principal_id().as_str())
        .map_err(|()| SessionRepositoryError::InvalidRequest)?;
    // Canonical human-authority row order: principal, provider identity,
    // membership. Separate statements make the order independent of join plans.
    let principal_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM human_principals WHERE id=$1 FOR KEY SHARE")
            .bind(principal_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|_| SessionRepositoryError::Unavailable)?;
    if principal_status.as_deref() != Some("active") {
        return Err(SessionRepositoryError::InvalidRequest);
    }
    let locked_identity: Option<Uuid> = sqlx::query_scalar(
        r"
        SELECT principal_id
        FROM human_provider_identities
        WHERE principal_id=$1 AND provider_id=$2 AND provider_subject=$3
        FOR KEY SHARE
        ",
    )
    .bind(principal_id)
    .bind(identity.provider_id().as_str())
    .bind(identity.provider_subject().as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| SessionRepositoryError::Unavailable)?;
    if locked_identity != Some(principal_id) {
        return Err(SessionRepositoryError::InvalidRequest);
    }
    let current_membership: Option<(String, i64)> = sqlx::query_as(
        r"
        SELECT status,authorization_revision
        FROM tenant_human_memberships
        WHERE tenant_id=$1 AND principal_id=$2
        FOR KEY SHARE
        ",
    )
    .bind(identity.tenant_id().as_str())
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| SessionRepositoryError::Unavailable)?;
    let requested_authorization_revision = i64::try_from(session.authorization_revision())
        .map_err(|_| SessionRepositoryError::InvalidRequest)?;
    if current_membership
        .as_ref()
        .map(|(status, revision)| (status.as_str(), *revision))
        != Some(("active", requested_authorization_revision))
    {
        return Err(SessionRepositoryError::InvalidRequest);
    }
    let database_time_ms = database_time_milliseconds(transaction)
        .await
        .map_err(|_| SessionRepositoryError::Unavailable)?;
    let database_time = validate_caller_time(session.issued_at(), database_time_ms)
        .map_err(|()| SessionRepositoryError::InvalidRequest)?;
    let rebased_session = rebase_new_session(&session, database_time)?;
    let outcome =
        insert_rebased_session(transaction, &lookup, id, principal_id, &rebased_session).await?;
    let created_session = (outcome == CreateSessionOutcome::Created).then_some(rebased_session);
    Ok((outcome, created_session))
}

async fn insert_rebased_session(
    transaction: &mut Transaction<'_, Postgres>,
    lookup: &SessionTokenLookup,
    id: Uuid,
    principal_id: Uuid,
    session: &DurableSession,
) -> Result<CreateSessionOutcome, SessionRepositoryError> {
    let identity = session.identity();
    let issued_at_ms = timestamp_to_milliseconds(session.issued_at())
        .map_err(|()| SessionRepositoryError::InvalidRequest)?;
    let last_seen_at_ms = timestamp_to_milliseconds(session.last_seen_at())
        .map_err(|()| SessionRepositoryError::InvalidRequest)?;
    let idle_expires_at_ms = timestamp_to_milliseconds(session.idle_expires_at())
        .map_err(|()| SessionRepositoryError::InvalidRequest)?;
    let expires_at_ms = timestamp_to_milliseconds(session.expires_at())
        .map_err(|()| SessionRepositoryError::InvalidRequest)?;
    let authorization_revision = i64::try_from(session.authorization_revision())
        .map_err(|_| SessionRepositoryError::InvalidRequest)?;
    let (lifecycle_status, activation_deadline_ms) = match identity.kind() {
        SessionKind::Browser => ("active", None),
        SessionKind::Cli => {
            let bounded_deadline = session
                .issued_at()
                .checked_add(CLI_SESSION_ACTIVATION_LIFETIME_SECONDS)
                .unwrap_or(session.expires_at())
                .min(session.expires_at());
            let deadline_ms = timestamp_to_milliseconds(bounded_deadline)
                .map_err(|()| SessionRepositoryError::InvalidRequest)?;
            ("pending_activation", Some(deadline_ms))
        }
    };
    let result = sqlx::query(
        r"
        INSERT INTO human_sessions (
            id, tenant_id, principal_id, provider_id, provider_subject,
            session_kind, audience, token_hash, token_hash_key_id,
            authorization_revision, issued_at_ms, last_seen_at_ms,
            idle_expires_at_ms, expires_at_ms, lifecycle_status,
            activation_deadline_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        ",
    )
    .bind(id)
    .bind(identity.tenant_id().as_str())
    .bind(principal_id)
    .bind(identity.provider_id().as_str())
    .bind(identity.provider_subject().as_str())
    .bind(match identity.kind() {
        SessionKind::Browser => "browser",
        SessionKind::Cli => "cli",
    })
    .bind(identity.audience())
    .bind(lookup.digest().as_bytes().as_slice())
    .bind(lookup.key_id().as_str())
    .bind(authorization_revision)
    .bind(issued_at_ms)
    .bind(last_seen_at_ms)
    .bind(idle_expires_at_ms)
    .bind(expires_at_ms)
    .bind(lifecycle_status)
    .bind(activation_deadline_ms)
    .execute(&mut **transaction)
    .await;
    match result {
        Ok(_) => Ok(CreateSessionOutcome::Created),
        Err(error) if constraint(&error) == Some("human_sessions_pkey") => {
            Ok(CreateSessionOutcome::SessionIdConflict)
        }
        Err(error) if constraint(&error) == Some("human_sessions_token_hash_unique") => {
            Ok(CreateSessionOutcome::TokenDigestConflict)
        }
        Err(error) if is_integrity_violation(&error) => Err(SessionRepositoryError::InvalidRequest),
        Err(_) => Err(SessionRepositoryError::Unavailable),
    }
}

fn rebase_new_session(
    session: &DurableSession,
    database_time: UnixTimestamp,
) -> Result<DurableSession, SessionRepositoryError> {
    let issued_at = session.issued_at().as_seconds();
    let rebase = |timestamp: UnixTimestamp| {
        let offset = timestamp.as_seconds().checked_sub(issued_at).ok_or(())?;
        database_time.checked_add(offset).map_err(|_| ())
    };
    DurableSession::new(
        session.identity().clone(),
        session.authorization_revision(),
        database_time,
        rebase(session.last_seen_at()).map_err(|()| SessionRepositoryError::InvalidRequest)?,
        rebase(session.idle_expires_at()).map_err(|()| SessionRepositoryError::InvalidRequest)?,
        rebase(session.expires_at()).map_err(|()| SessionRepositoryError::InvalidRequest)?,
        None,
    )
    .map_err(|_| SessionRepositoryError::InvalidRequest)
}

async fn append_cli_activation_audit(
    transaction: &mut Transaction<'_, Postgres>,
    session: &DurableSession,
    session_id: Uuid,
    occurred_at_ms: i64,
) -> Result<(), SessionRepositoryError> {
    let authorization_revision = i64::try_from(session.authorization_revision())
        .map_err(|_| SessionRepositoryError::CorruptData)?;
    let principal_id = canonical_uuid(session.identity().principal_id().as_str())
        .map_err(|()| SessionRepositoryError::CorruptData)?;
    sqlx::query(
        r"
        INSERT INTO security_audit_events (
            event_id,tenant_id,occurred_at_ms,actor_kind,
            actor_principal_id,actor_session_id,authorization_revision,
            action,outcome,resource_kind,resource_id
        ) VALUES ($1,$2,$3,'human',$4,$5,$6,
                  'auth.session.cli.activate','succeeded',
                  'human_session',$7)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(session.identity().tenant_id().as_str())
    .bind(occurred_at_ms)
    .bind(principal_id)
    .bind(session_id)
    .bind(authorization_revision)
    .bind(session.identity().session_id().as_str())
    .execute(&mut **transaction)
    .await
    .map_err(|error| {
        if is_integrity_violation(&error) {
            SessionRepositoryError::CorruptData
        } else {
            SessionRepositoryError::Unavailable
        }
    })?;
    Ok(())
}

async fn activate_pending_cli_row(
    transaction: &mut Transaction<'_, Postgres>,
    id: Uuid,
    database_time_ms: i64,
) -> Result<u64, SessionRepositoryError> {
    Ok(sqlx::query(
        r"
        UPDATE human_sessions
        SET lifecycle_status = 'active', activated_at_ms = $2,
            revision = revision + 1
        WHERE id = $1
          AND session_kind = 'cli'
          AND audience = 'automata.cli'
          AND lifecycle_status = 'pending_activation'
          AND activated_at_ms IS NULL
          AND activation_deadline_ms > $2
          AND activation_deadline_ms >
              floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
          AND issued_at_ms <=
              floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
          AND idle_expires_at_ms >
              floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
          AND expires_at_ms >
              floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
          AND revoked_at_ms IS NULL
        ",
    )
    .bind(id)
    .bind(database_time_ms)
    .execute(&mut **transaction)
    .await
    .map_err(|error| {
        if is_integrity_violation(&error) {
            SessionRepositoryError::CorruptData
        } else {
            SessionRepositoryError::Unavailable
        }
    })?
    .rows_affected())
}

impl HumanSessionRepository for PostgresHumanSessionRepository {
    fn create(&self, request: CreateSession) -> SessionRepositoryFuture<'_, CreateSessionOutcome> {
        Box::pin(async move {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            let (outcome, _) = create_session(&mut transaction, request).await?;
            if outcome == CreateSessionOutcome::Created {
                transaction
                    .commit()
                    .await
                    .map_err(|_| SessionRepositoryError::Unavailable)?;
            }
            Ok(outcome)
        })
    }

    fn resolve<'a>(
        &'a self,
        request: &'a ResolveSession,
    ) -> SessionRepositoryFuture<'a, ResolveSessionOutcome> {
        Box::pin(async move {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            if !lock_session_authority(&mut transaction, request.lookup(), false).await? {
                transaction
                    .commit()
                    .await
                    .map_err(|_| SessionRepositoryError::Unavailable)?;
                return Ok(ResolveSessionOutcome::NotFound);
            }
            let row = sqlx::query_as::<_, SessionRow>(SESSION_SELECT)
                .bind(request.lookup().key_id().as_str())
                .bind(request.lookup().digest().as_bytes().as_slice())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            let Some(row) = row else {
                transaction
                    .commit()
                    .await
                    .map_err(|_| SessionRepositoryError::Unavailable)?;
                return Ok(ResolveSessionOutcome::NotFound);
            };
            let database_time_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            let database_time = validate_caller_time(request.now(), database_time_ms)
                .map_err(|()| SessionRepositoryError::InvalidRequest)?;
            let outcome = resolve_outcome(row.classify(request.expected_kind(), database_time)?);
            transaction
                .commit()
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            Ok(outcome)
        })
    }

    fn activate_cli<'a>(
        &'a self,
        request: &'a ActivateCliSession,
    ) -> SessionRepositoryFuture<'a, ActivateCliSessionOutcome> {
        Box::pin(async move {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            if !lock_session_authority(&mut transaction, request.lookup(), true).await? {
                return Ok(ActivateCliSessionOutcome::NotFound);
            }
            let row = sqlx::query_as::<_, SessionRow>(SESSION_SELECT)
                .bind(request.lookup().key_id().as_str())
                .bind(request.lookup().digest().as_bytes().as_slice())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            let Some(row) = row else {
                return Ok(ActivateCliSessionOutcome::NotFound);
            };
            let database_time_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            let database_time = validate_caller_time(request.now(), database_time_ms)
                .map_err(|()| SessionRepositoryError::InvalidRequest)?;
            match row.classify_cli_activation(database_time)? {
                CliActivationClassification::AlreadyActive(session) => {
                    transaction
                        .commit()
                        .await
                        .map_err(|_| SessionRepositoryError::Unavailable)?;
                    Ok(ActivateCliSessionOutcome::AlreadyActive(Box::new(session)))
                }
                CliActivationClassification::ActivationExpired => {
                    Ok(ActivateCliSessionOutcome::ActivationExpired)
                }
                CliActivationClassification::Closed(classified) => {
                    activation_closed_outcome(&classified)
                }
                CliActivationClassification::Pending(session) => {
                    let id = canonical_uuid(session.identity().session_id().as_str())
                        .map_err(|()| SessionRepositoryError::CorruptData)?;
                    let updated =
                        activate_pending_cli_row(&mut transaction, id, database_time_ms).await?;
                    if updated != 1 {
                        let final_time_ms = database_time_milliseconds(&mut transaction)
                            .await
                            .map_err(|_| SessionRepositoryError::Unavailable)?;
                        let final_time = timestamp_from_milliseconds(final_time_ms)
                            .map_err(|()| SessionRepositoryError::CorruptData)?;
                        return match row.classify_cli_activation(final_time)? {
                            CliActivationClassification::ActivationExpired => {
                                Ok(ActivateCliSessionOutcome::ActivationExpired)
                            }
                            CliActivationClassification::Closed(classified) => {
                                activation_closed_outcome(&classified)
                            }
                            CliActivationClassification::Pending(_)
                            | CliActivationClassification::AlreadyActive(_) => {
                                Err(SessionRepositoryError::CorruptData)
                            }
                        };
                    }
                    append_cli_activation_audit(&mut transaction, &session, id, database_time_ms)
                        .await?;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| SessionRepositoryError::Unavailable)?;
                    Ok(ActivateCliSessionOutcome::Activated(Box::new(session)))
                }
            }
        })
    }

    fn touch<'a>(
        &'a self,
        request: &'a TouchSession,
    ) -> SessionRepositoryFuture<'a, TouchSessionOutcome> {
        Box::pin(async move {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            if !lock_session_authority(&mut transaction, request.lookup(), true).await? {
                return Ok(TouchSessionOutcome::NotFound);
            }
            let row = sqlx::query_as::<_, SessionRow>(SESSION_SELECT)
                .bind(request.lookup().key_id().as_str())
                .bind(request.lookup().digest().as_bytes().as_slice())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            let Some(row) = row else {
                return Ok(TouchSessionOutcome::NotFound);
            };
            let database_time_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            let database_time = validate_caller_time(request.observed_at(), database_time_ms)
                .map_err(|()| SessionRepositoryError::InvalidRequest)?;
            let classified = row.classify(request.expected_kind(), database_time)?;
            let ClassifiedSession::Active(session) = classified else {
                return Ok(touch_outcome(classified));
            };
            if database_time <= session.last_seen_at() {
                return Ok(TouchSessionOutcome::Unchanged(Box::new(session)));
            }
            let requested_lifetime = request
                .idle_expires_at()
                .as_seconds()
                .checked_sub(request.observed_at().as_seconds())
                .ok_or(SessionRepositoryError::InvalidRequest)?;
            let idle_expires_at = database_time
                .checked_add(requested_lifetime)
                .map_err(|_| SessionRepositoryError::InvalidRequest)?
                .min(session.expires_at());
            if idle_expires_at <= database_time {
                return Err(SessionRepositoryError::InvalidRequest);
            }
            let idle_expires_at = idle_expires_at.max(session.idle_expires_at());
            let id = canonical_uuid(session.identity().session_id().as_str())
                .map_err(|()| SessionRepositoryError::CorruptData)?;
            let updated = sqlx::query(
                r"
                UPDATE human_sessions
                SET last_seen_at_ms = $2, idle_expires_at_ms = $3, revision = revision + 1
                WHERE id = $1
                  AND lifecycle_status = 'active'
                  AND revoked_at_ms IS NULL
                  AND issued_at_ms <=
                      floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                  AND idle_expires_at_ms >
                      floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                  AND expires_at_ms >
                      floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                ",
            )
            .bind(id)
            .bind(database_time_ms)
            .bind(
                timestamp_to_milliseconds(idle_expires_at)
                    .map_err(|()| SessionRepositoryError::InvalidRequest)?,
            )
            .execute(&mut *transaction)
            .await
            .map_err(|_| SessionRepositoryError::Unavailable)?
            .rows_affected();
            if updated != 1 {
                let final_time_ms = database_time_milliseconds(&mut transaction)
                    .await
                    .map_err(|_| SessionRepositoryError::Unavailable)?;
                let final_time = timestamp_from_milliseconds(final_time_ms)
                    .map_err(|()| SessionRepositoryError::CorruptData)?;
                let classified = row.classify(request.expected_kind(), final_time)?;
                return match classified {
                    ClassifiedSession::Active(_) => Err(SessionRepositoryError::CorruptData),
                    closed => Ok(touch_outcome(closed)),
                };
            }
            transaction
                .commit()
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            let touched = DurableSession::new(
                session.identity().clone(),
                session.authorization_revision(),
                session.issued_at(),
                database_time,
                idle_expires_at,
                session.expires_at(),
                None,
            )
            .map_err(|_| SessionRepositoryError::CorruptData)?;
            Ok(TouchSessionOutcome::Touched(Box::new(touched)))
        })
    }

    fn revoke_own<'a>(
        &'a self,
        request: &'a RevokeOwnSession,
    ) -> SessionRepositoryFuture<'a, RevokeOwnSessionOutcome> {
        Box::pin(async move {
            let id = canonical_uuid(request.session_id().as_str())
                .map_err(|()| SessionRepositoryError::InvalidRequest)?;
            let principal_id = canonical_uuid(request.principal_id().as_str())
                .map_err(|()| SessionRepositoryError::InvalidRequest)?;
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            let row: Option<(i64, Option<i64>)> = sqlx::query_as(
                r"
                SELECT issued_at_ms, revoked_at_ms
                FROM human_sessions
                WHERE id = $1 AND tenant_id = $2 AND principal_id = $3
                FOR UPDATE
                ",
            )
            .bind(id)
            .bind(request.tenant_id().as_str())
            .bind(principal_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| SessionRepositoryError::Unavailable)?;
            let Some((issued_at_ms, already_revoked)) = row else {
                return Ok(RevokeOwnSessionOutcome::NotFound);
            };
            if already_revoked.is_some() {
                return Ok(RevokeOwnSessionOutcome::AlreadyRevoked);
            }
            let database_time_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            validate_caller_time(request.revoked_at(), database_time_ms)
                .map_err(|()| SessionRepositoryError::InvalidRequest)?;
            if database_time_ms < issued_at_ms {
                return Err(SessionRepositoryError::CorruptData);
            }
            let result = sqlx::query(
                r"
                UPDATE human_sessions
                SET revoked_at_ms = $2, revocation_reason = 'self-revoked', revision = revision + 1
                WHERE id = $1 AND revoked_at_ms IS NULL
                ",
            )
            .bind(id)
            .bind(database_time_ms)
            .execute(&mut *transaction)
            .await
            .map_err(|_| SessionRepositoryError::Unavailable)?;
            let outcome = if result.rows_affected() == 1 {
                RevokeOwnSessionOutcome::Revoked
            } else {
                RevokeOwnSessionOutcome::AlreadyRevoked
            };
            transaction
                .commit()
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            Ok(outcome)
        })
    }

    fn revoke_principal<'a>(
        &'a self,
        request: &'a RevokePrincipalSessions,
    ) -> SessionRepositoryFuture<'a, RevokePrincipalSessionsOutcome> {
        Box::pin(async move {
            let principal_id = canonical_uuid(request.principal_id().as_str())
                .map_err(|()| SessionRepositoryError::InvalidRequest)?;
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            let locked_sessions: Vec<(Uuid, i64, Option<i64>)> = sqlx::query_as(
                r"
                SELECT id,issued_at_ms,revoked_at_ms
                FROM human_sessions
                WHERE tenant_id = $1 AND principal_id = $2
                ORDER BY id
                FOR UPDATE
                ",
            )
            .bind(request.tenant_id().as_str())
            .bind(principal_id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| SessionRepositoryError::Unavailable)?;
            let database_time_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            validate_caller_time(request.revoked_at(), database_time_ms)
                .map_err(|()| SessionRepositoryError::InvalidRequest)?;
            if locked_sessions
                .iter()
                .any(|(_, issued_at_ms, revoked_at_ms)| {
                    revoked_at_ms.is_none() && *issued_at_ms > database_time_ms
                })
            {
                return Err(SessionRepositoryError::CorruptData);
            }
            let result = sqlx::query(
                r"
                UPDATE human_sessions
                SET revoked_at_ms = $3, revocation_reason = 'principal-revoked',
                    revision = revision + 1
                WHERE tenant_id = $1 AND principal_id = $2
                  AND revoked_at_ms IS NULL AND issued_at_ms <= $3
                ",
            )
            .bind(request.tenant_id().as_str())
            .bind(principal_id)
            .bind(database_time_ms)
            .execute(&mut *transaction)
            .await
            .map_err(|_| SessionRepositoryError::Unavailable)?;
            let outcome = RevokePrincipalSessionsOutcome::new(result.rows_affected());
            transaction
                .commit()
                .await
                .map_err(|_| SessionRepositoryError::Unavailable)?;
            Ok(outcome)
        })
    }
}
