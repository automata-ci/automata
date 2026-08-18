use std::{fmt, sync::Arc};

use automata_ci_auth::{
    github::{
        GithubMembershipRepositoryError, PersistGithubMembershipSnapshot,
        PersistGithubMembershipSnapshotOutcome,
    },
    human::{PrincipalId, ProviderIdentityAssertion, TenantId},
    login::LoginTransactionVersion,
    session::{DurableSession, DurableSessionIdentity, SessionRepositoryError},
    sign_in::{
        FinalizeSignIn, FinalizeSignInOutcome, HumanSignInFinalizer, PendingSessionCandidate,
        PendingSessionConflict, SignInFinalizerError, SignInFinalizerFuture,
    },
    vault::{ProviderTokenKey, ProviderTokenVaultError},
};
use automata_ci_key_management::KeyEncryptionProvider;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{
    PostgresGithubMembershipRepository, PostgresHumanSessionRepository, PostgresProviderTokenVault,
    login::{LockSignInOutcome, lock_sign_in_for_finalization},
    session::{
        CreateSession, CreateSessionOutcome, database_time_milliseconds, validate_caller_time,
    },
    support::{
        canonical_uuid, is_integrity_violation, timestamp_from_milliseconds,
        timestamp_to_milliseconds,
    },
};

const SIGN_IN_AUDIT_ACTION: &str = "auth.sign_in";
const SESSION_AUDIT_RESOURCE: &str = "session";

/// Atomic `PostgreSQL` finalizer for an already provider-authenticated sign-in.
#[derive(Clone)]
pub struct PostgresHumanSignInFinalizer {
    pool: PgPool,
    provider_tokens: PostgresProviderTokenVault,
    memberships: PostgresGithubMembershipRepository,
}

impl PostgresHumanSignInFinalizer {
    /// Creates a sign-in finalizer backed by `pool`.
    ///
    /// `provider` protects provider-token envelopes written during successful
    /// finalization.
    #[must_use]
    pub fn new(pool: PgPool, provider: Arc<dyn KeyEncryptionProvider>) -> Self {
        Self {
            provider_tokens: PostgresProviderTokenVault::new(pool.clone(), provider),
            memberships: PostgresGithubMembershipRepository::new(pool.clone()),
            pool,
        }
    }
}

impl fmt::Debug for PostgresHumanSignInFinalizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresHumanSignInFinalizer")
            .field("provider_tokens", &self.provider_tokens)
            .field("memberships", &self.memberships)
            .finish_non_exhaustive()
    }
}

#[derive(FromRow)]
struct AdmissionRow {
    principal_id: Uuid,
    identity_revision: i64,
    first_authenticated_at_ms: i64,
}

enum Admission {
    Active(AdmissionRow),
    Unmapped,
    PrincipalDisabled,
    MembershipSuspended,
}

async fn resolve_admission(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &TenantId,
    identity: &ProviderIdentityAssertion,
) -> Result<Admission, SignInFinalizerError> {
    // Resolve the immutable mapping without a row lock, then acquire the shared
    // auth lock order explicitly: principal, identity, tenant membership. The
    // membership refresher uses the same order before locking provider tokens.
    let principal_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT principal_id FROM human_provider_identities
        WHERE provider_id=$1 AND provider_subject=$2
        ",
    )
    .bind(identity.provider_id().as_str())
    .bind(identity.provider_subject().as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    let Some(principal_id) = principal_id else {
        return Ok(Admission::Unmapped);
    };

    let principal_status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM human_principals WHERE id=$1 FOR UPDATE",
    )
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_error)?
    .ok_or(SignInFinalizerError::IntegrityFailure)?;
    match principal_status.as_str() {
        "disabled" => return Ok(Admission::PrincipalDisabled),
        "active" => {}
        _ => return Err(SignInFinalizerError::IntegrityFailure),
    }

    let locked_identity = sqlx::query_as::<_, (Uuid, i64, i64)>(
        r"
        SELECT principal_id,revision,first_authenticated_at_ms
        FROM human_provider_identities
        WHERE provider_id=$1 AND provider_subject=$2
        FOR UPDATE
        ",
    )
    .bind(identity.provider_id().as_str())
    .bind(identity.provider_subject().as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    let Some((locked_principal_id, identity_revision, first_authenticated_at_ms)) = locked_identity
    else {
        return Ok(Admission::Unmapped);
    };
    if locked_principal_id != principal_id {
        return Err(SignInFinalizerError::IntegrityFailure);
    }

    let membership = sqlx::query_as::<_, (String, i64)>(
        r"
        SELECT status,authorization_revision
        FROM tenant_human_memberships
        WHERE tenant_id=$1 AND principal_id=$2
        FOR UPDATE
        ",
    )
    .bind(tenant_id.as_str())
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    let Some((membership_status, authorization_revision)) = membership else {
        return Ok(Admission::Unmapped);
    };
    match membership_status.as_str() {
        "suspended" => return Ok(Admission::MembershipSuspended),
        "active" => {}
        _ => return Err(SignInFinalizerError::IntegrityFailure),
    }
    if identity_revision <= 0 || authorization_revision <= 0 {
        return Err(SignInFinalizerError::IntegrityFailure);
    }
    Ok(Admission::Active(AdmissionRow {
        principal_id,
        identity_revision,
        first_authenticated_at_ms,
    }))
}

async fn update_mutable_identity(
    transaction: &mut Transaction<'_, Postgres>,
    identity: &ProviderIdentityAssertion,
    principal_id: Uuid,
    expected_revision: i64,
    authenticated_at_ms: i64,
    now_ms: i64,
) -> Result<(), SignInFinalizerError> {
    let updated = sqlx::query(
        r"
        UPDATE human_provider_identities
        SET provider_login=CASE
                WHEN last_authenticated_at_ms <= $6 THEN $4
                ELSE provider_login
            END,
            normalized_login=CASE
                WHEN last_authenticated_at_ms <= $6 THEN $5
                ELSE normalized_login
            END,
            display_name=CASE
                WHEN last_authenticated_at_ms <= $6 THEN $7
                ELSE display_name
            END,
            last_authenticated_at_ms=GREATEST(last_authenticated_at_ms,$6),
            last_observed_at_ms=GREATEST(last_observed_at_ms,$8),
            updated_at_ms=GREATEST(updated_at_ms,$8), revision=revision+1
        WHERE principal_id=$1 AND provider_id=$2 AND provider_subject=$3
          AND revision=$9
        ",
    )
    .bind(principal_id)
    .bind(identity.provider_id().as_str())
    .bind(identity.provider_subject().as_str())
    .bind(identity.login())
    .bind(identity.login().to_ascii_lowercase())
    .bind(authenticated_at_ms)
    .bind(identity.display_name())
    .bind(now_ms)
    .bind(expected_revision)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?
    .rows_affected();
    if updated != 1 {
        return Err(SignInFinalizerError::IntegrityFailure);
    }
    Ok(())
}

async fn complete_consumed_login(
    transaction: &mut Transaction<'_, Postgres>,
    login_id: Uuid,
    principal_id: Uuid,
    expected_consumed_version: LoginTransactionVersion,
    now_ms: i64,
) -> Result<(), SignInFinalizerError> {
    let consumed_version = i64::try_from(expected_consumed_version.value())
        .map_err(|_| SignInFinalizerError::InvalidRequest)?;
    let completed = sqlx::query(
        r"
        UPDATE human_login_transactions
        SET status='succeeded', completed_principal_id=$2,
            updated_at_ms=$3, revision=revision+1
        WHERE id=$1 AND status='consumed' AND revision=$4
          AND expires_at_ms >
              floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
        ",
    )
    .bind(login_id)
    .bind(principal_id)
    .bind(now_ms)
    .bind(consumed_version)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?
    .rows_affected();
    if completed != 1 {
        return Err(SignInFinalizerError::IntegrityFailure);
    }
    Ok(())
}

async fn pending_session_conflict(
    transaction: &mut Transaction<'_, Postgres>,
    session: &PendingSessionCandidate,
) -> Result<Option<PendingSessionConflict>, SignInFinalizerError> {
    let session_id = canonical_uuid(session.session_id().as_str())
        .map_err(|()| SignInFinalizerError::InvalidRequest)?;
    let conflict: (bool, bool) = sqlx::query_as(
        r"
        SELECT EXISTS(SELECT 1 FROM human_sessions WHERE id=$1),
               EXISTS(
                   SELECT 1 FROM human_sessions
                   WHERE token_hash_key_id=$2 AND token_hash=$3
               )
        ",
    )
    .bind(session_id)
    .bind(session.lookup().key_id().as_str())
    .bind(session.lookup().digest().as_bytes().as_slice())
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(if conflict.0 {
        Some(PendingSessionConflict::SessionId)
    } else if conflict.1 {
        Some(PendingSessionConflict::TokenDigest)
    } else {
        None
    })
}

#[allow(clippy::too_many_arguments)]
async fn append_audit_event(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &TenantId,
    occurred_at_ms: i64,
    principal_id: Option<Uuid>,
    session_id: Option<Uuid>,
    authorization_revision: Option<i64>,
    outcome: &str,
    resource_kind: &str,
    resource_id: &str,
) -> Result<(), SignInFinalizerError> {
    let actor_kind = if principal_id.is_some() {
        "human"
    } else {
        "system"
    };
    sqlx::query(
        r"
        INSERT INTO security_audit_events (
            event_id, tenant_id, occurred_at_ms, actor_kind,
            actor_principal_id, actor_session_id, authorization_revision,
            action, outcome, resource_kind, resource_id
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id.as_str())
    .bind(occurred_at_ms)
    .bind(actor_kind)
    .bind(principal_id)
    .bind(session_id)
    .bind(authorization_revision)
    .bind(SIGN_IN_AUDIT_ACTION)
    .bind(outcome)
    .bind(resource_kind)
    .bind(resource_id)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

fn map_database_error(error: sqlx::Error) -> SignInFinalizerError {
    let classified = if is_integrity_violation(&error) {
        SignInFinalizerError::IntegrityFailure
    } else {
        SignInFinalizerError::Unavailable
    };
    drop(error);
    classified
}

fn map_login_error(
    error: automata_ci_auth::login::LoginTransactionRepositoryError,
) -> SignInFinalizerError {
    use automata_ci_auth::login::LoginTransactionRepositoryError as Error;
    match error {
        Error::InvalidRequest => SignInFinalizerError::InvalidRequest,
        Error::Unavailable => SignInFinalizerError::Unavailable,
        Error::IntegrityFailure | Error::CorruptData => SignInFinalizerError::IntegrityFailure,
    }
}

fn map_session_error(error: SessionRepositoryError) -> SignInFinalizerError {
    match error {
        SessionRepositoryError::Unavailable => SignInFinalizerError::Unavailable,
        SessionRepositoryError::InvalidRequest | SessionRepositoryError::CorruptData => {
            SignInFinalizerError::IntegrityFailure
        }
    }
}

fn map_membership_error(error: GithubMembershipRepositoryError) -> SignInFinalizerError {
    match error {
        GithubMembershipRepositoryError::Unavailable => SignInFinalizerError::Unavailable,
        GithubMembershipRepositoryError::InvalidRequest
        | GithubMembershipRepositoryError::CorruptData => SignInFinalizerError::IntegrityFailure,
    }
}

impl HumanSignInFinalizer for PostgresHumanSignInFinalizer {
    #[allow(clippy::too_many_lines)]
    fn finalize(&self, request: FinalizeSignIn) -> SignInFinalizerFuture<'_> {
        Box::pin(async move {
            let (retry, session) = request.into_retry_parts();
            let expected_version = retry.expected_version();
            let now = retry.now();
            let tenant_id = retry
                .access()
                .tenant_id()
                .cloned()
                .ok_or(SignInFinalizerError::InvalidRequest)?;
            let authenticated_at_ms =
                timestamp_to_milliseconds(retry.identity().authenticated_at())
                    .map_err(|()| SignInFinalizerError::InvalidRequest)?;
            let mut transaction = self.pool.begin().await.map_err(map_database_error)?;
            let locked = lock_sign_in_for_finalization(
                &mut transaction,
                retry.access(),
                expected_version,
                now,
            )
            .await
            .map_err(map_login_error)?;
            let consumed = match locked {
                LockSignInOutcome::Consumed(consumed) => consumed,
                LockSignInOutcome::NotFound => return Ok(FinalizeSignInOutcome::NotFound),
                LockSignInOutcome::Expired => return Ok(FinalizeSignInOutcome::Expired),
                LockSignInOutcome::AlreadyConsumed => {
                    return Ok(FinalizeSignInOutcome::AlreadyConsumed);
                }
                LockSignInOutcome::VersionConflict => {
                    return Ok(FinalizeSignInOutcome::VersionConflict);
                }
            };
            let now_ms = consumed.observed_at_ms();
            let admitted_at_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(map_database_error)?;
            let admitted_at = validate_caller_time(now, admitted_at_ms)
                .map_err(|()| SignInFinalizerError::InvalidRequest)?;
            // Database time is the admission authority. Reject authority that
            // is already dead before token encryption or any durable write;
            // the second check immediately before commit closes the time spent
            // performing those operations.
            if consumed.expires_at_ms() <= admitted_at_ms
                || retry
                    .provider_tokens()
                    .metadata()
                    .access_expires_at()
                    .is_none_or(|expires_at| expires_at <= admitted_at)
                || retry.membership().valid_until() <= admitted_at
                || session.idle_expires_at() <= admitted_at
                || session.expires_at() <= admitted_at
            {
                return Ok(FinalizeSignInOutcome::Expired);
            }
            if let Some(conflict) = pending_session_conflict(&mut transaction, &session).await? {
                return Ok(FinalizeSignInOutcome::SessionConflict {
                    conflict,
                    retry: Box::new(retry),
                });
            }
            let login_id = consumed.id();

            let admission =
                resolve_admission(&mut transaction, &tenant_id, retry.identity()).await?;
            let admission = match admission {
                Admission::Active(admission) => admission,
                Admission::Unmapped => return Ok(FinalizeSignInOutcome::Unmapped),
                Admission::PrincipalDisabled => {
                    return Ok(FinalizeSignInOutcome::PrincipalDisabled);
                }
                Admission::MembershipSuspended => {
                    return Ok(FinalizeSignInOutcome::MembershipSuspended);
                }
            };
            if authenticated_at_ms < admission.first_authenticated_at_ms {
                return Ok(FinalizeSignInOutcome::IdentityConflict);
            }
            let principal_id = PrincipalId::new(admission.principal_id.hyphenated().to_string())
                .map_err(|_| SignInFinalizerError::IntegrityFailure)?;
            let token_key = ProviderTokenKey::new(
                tenant_id.clone(),
                retry.identity().provider_id().clone(),
                retry.identity().provider_subject().clone(),
            );
            let provider_token_version = match self
                .provider_tokens
                .upsert_in_transaction(&mut transaction, &token_key, retry.provider_tokens())
                .await
            {
                Ok(version) => version,
                Err(error) => {
                    return match error {
                        ProviderTokenVaultError::Revoked | ProviderTokenVaultError::NotFound => {
                            Ok(FinalizeSignInOutcome::IdentityConflict)
                        }
                        ProviderTokenVaultError::Unavailable
                        | ProviderTokenVaultError::AlreadyExists
                        | ProviderTokenVaultError::VersionConflict => {
                            Err(SignInFinalizerError::Unavailable)
                        }
                        ProviderTokenVaultError::InvalidRequest
                        | ProviderTokenVaultError::IntegrityFailure => {
                            Err(SignInFinalizerError::IntegrityFailure)
                        }
                    };
                }
            };
            update_mutable_identity(
                &mut transaction,
                retry.identity(),
                admission.principal_id,
                admission.identity_revision,
                authenticated_at_ms,
                now_ms,
            )
            .await?;

            let membership_request = PersistGithubMembershipSnapshot::new(
                tenant_id.clone(),
                principal_id.clone(),
                retry.identity().provider_subject().clone(),
                provider_token_version,
                retry.membership().clone(),
            )
            .map_err(|_| SignInFinalizerError::IntegrityFailure)?;
            let authorization_revision = match self
                .memberships
                .persist_in_transaction(&mut transaction, &membership_request)
                .await
                .map_err(map_membership_error)?
            {
                PersistGithubMembershipSnapshotOutcome::Stored {
                    authorization_revision,
                    ..
                }
                | PersistGithubMembershipSnapshotOutcome::AlreadyStored {
                    authorization_revision,
                } => authorization_revision,
                PersistGithubMembershipSnapshotOutcome::PrincipalDisabled => {
                    return Ok(FinalizeSignInOutcome::PrincipalDisabled);
                }
                PersistGithubMembershipSnapshotOutcome::MembershipSuspended => {
                    return Ok(FinalizeSignInOutcome::MembershipSuspended);
                }
                PersistGithubMembershipSnapshotOutcome::ObservationOutOfOrder => {
                    return Err(SignInFinalizerError::Unavailable);
                }
                PersistGithubMembershipSnapshotOutcome::PrincipalNotFound
                | PersistGithubMembershipSnapshotOutcome::IdentityNotFound
                | PersistGithubMembershipSnapshotOutcome::MembershipNotFound
                | PersistGithubMembershipSnapshotOutcome::ProviderTokenNotFound
                | PersistGithubMembershipSnapshotOutcome::ProviderTokenRevoked
                | PersistGithubMembershipSnapshotOutcome::ProviderTokenNotYetValid
                | PersistGithubMembershipSnapshotOutcome::ProviderTokenExpired
                | PersistGithubMembershipSnapshotOutcome::ProviderTokenVersionChanged { .. }
                | PersistGithubMembershipSnapshotOutcome::SnapshotConflict => {
                    return Err(SignInFinalizerError::IntegrityFailure);
                }
            };

            let (session_id, lookup, kind, issued_at, idle_expires_at, expires_at) =
                session.into_parts();
            let durable_identity = DurableSessionIdentity::new(
                session_id,
                tenant_id.clone(),
                principal_id.clone(),
                retry.identity().provider_id().clone(),
                retry.identity().provider_subject().clone(),
                kind,
            )
            .map_err(|_| SignInFinalizerError::IntegrityFailure)?;
            let durable_session = DurableSession::new(
                durable_identity,
                authorization_revision,
                issued_at,
                issued_at,
                idle_expires_at,
                expires_at,
                None,
            )
            .map_err(|_| SignInFinalizerError::IntegrityFailure)?;
            let create_request = CreateSession::new(lookup, durable_session.clone());
            let (create_outcome, issued_session) =
                PostgresHumanSessionRepository::create_in_transaction(
                    &mut transaction,
                    create_request,
                )
                .await
                .map_err(map_session_error)?;
            match create_outcome {
                CreateSessionOutcome::Created => {}
                CreateSessionOutcome::SessionIdConflict => {
                    return Ok(FinalizeSignInOutcome::SessionConflict {
                        conflict: PendingSessionConflict::SessionId,
                        retry: Box::new(retry),
                    });
                }
                CreateSessionOutcome::TokenDigestConflict => {
                    return Ok(FinalizeSignInOutcome::SessionConflict {
                        conflict: PendingSessionConflict::TokenDigest,
                        retry: Box::new(retry),
                    });
                }
            }
            let durable_session = issued_session.ok_or(SignInFinalizerError::IntegrityFailure)?;
            let completed_at_ms = database_time_milliseconds(&mut transaction)
                .await
                .map_err(map_database_error)?;
            let completed_at = timestamp_from_milliseconds(completed_at_ms)
                .map_err(|()| SignInFinalizerError::IntegrityFailure)?;
            // Provider and membership authority must remain live at fresh
            // database time after the KMS and membership writes, immediately
            // before the session transaction is allowed to commit.
            if consumed.expires_at_ms() <= completed_at_ms
                || retry
                    .provider_tokens()
                    .metadata()
                    .access_expires_at()
                    .is_none_or(|expires_at| expires_at <= completed_at)
                || retry.membership().valid_until() <= completed_at
                || durable_session.idle_expires_at() <= completed_at
                || durable_session.expires_at() <= completed_at
            {
                return Ok(FinalizeSignInOutcome::Expired);
            }

            complete_consumed_login(
                &mut transaction,
                login_id,
                admission.principal_id,
                expected_version,
                completed_at_ms,
            )
            .await?;
            let session_uuid = canonical_uuid(durable_session.identity().session_id().as_str())
                .map_err(|()| SignInFinalizerError::IntegrityFailure)?;
            let resource_id = durable_session.identity().session_id().as_str();
            append_audit_event(
                &mut transaction,
                &tenant_id,
                completed_at_ms,
                Some(admission.principal_id),
                Some(session_uuid),
                Some(
                    i64::try_from(authorization_revision)
                        .map_err(|_| SignInFinalizerError::IntegrityFailure)?,
                ),
                "succeeded",
                SESSION_AUDIT_RESOURCE,
                resource_id,
            )
            .await?;
            transaction.commit().await.map_err(map_database_error)?;

            let human = retry
                .identity()
                .clone()
                .into_authenticated_human(principal_id);
            Ok(FinalizeSignInOutcome::Admitted {
                human,
                session: Box::new(durable_session),
                current_authorization_revision: authorization_revision,
                return_path: consumed.into_return_path(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use automata_ci_auth::sign_in::SignInFinalizerError;
    use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use static_assertions::assert_impl_all;

    use super::*;

    assert_impl_all!(PostgresHumanSignInFinalizer: HumanSignInFinalizer, Clone, Send, Sync);

    fn keyring() -> Arc<LocalAes256GcmKeyring> {
        let active = LocalKeyMaterial::new(
            KeyId::new("sign-in-kek-v1").expect("key ID"),
            SecretBytes::new(vec![0x73; 32]).expect("key bytes"),
        )
        .expect("key material");
        Arc::new(LocalAes256GcmKeyring::new(active, Vec::new(), []).expect("keyring"))
    }

    #[tokio::test]
    async fn adapter_debug_output_is_sanitized() {
        let pool = PgPoolOptions::new().connect_lazy_with(PgConnectOptions::new());
        let finalizer = PostgresHumanSignInFinalizer::new(pool, keyring());
        let debug = format!("{finalizer:?}");
        assert!(debug.contains("PostgresHumanSignInFinalizer"));
        assert!(debug.contains("auth/provider-token:v1"));
        assert!(!debug.contains("73"));
        assert!(!debug.contains("password"));
    }

    #[test]
    fn finalizer_errors_are_sanitized() {
        let rendered = [
            SignInFinalizerError::InvalidRequest,
            SignInFinalizerError::Unavailable,
            SignInFinalizerError::IntegrityFailure,
        ]
        .map(|error| error.to_string())
        .join(" ");
        assert!(!rendered.contains("SELECT"));
        assert!(!rendered.contains("postgres"));
        assert!(!rendered.contains("token"));
    }
}
