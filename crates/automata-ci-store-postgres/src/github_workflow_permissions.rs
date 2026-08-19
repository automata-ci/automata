use async_trait::async_trait;
use automata_ci_store::{
    FinalizeGithubWorkflowPermissionObservation, GITHUB_PROVIDER_REST_API_VERSION,
    GITHUB_WORKFLOW_PERMISSION_DEFAULT_FRESHNESS_MILLIS,
    GithubWorkflowPermissionDefaultsObservationError,
    GithubWorkflowPermissionDefaultsObservationRepository,
    GithubWorkflowPermissionObservationCandidate,
};
use sqlx::{Postgres, Transaction};

use super::{
    PostgresStore,
    github_provider_manifest::{
        bootstrap_locked_manifest, lock_current_manifest, lock_or_create_repository,
        lock_or_create_tenant,
    },
    pg_bigint,
    workflow_runtime_policy::{
        database_now, lock_current as lock_current_runtime_policy,
        register_locked_workflow_runtime_policy,
    },
};

#[async_trait]
impl GithubWorkflowPermissionDefaultsObservationRepository for PostgresStore {
    async fn prepare_github_workflow_permission_target(
        &self,
        manifest: &automata_ci_store::GithubProviderManifest,
    ) -> Result<(), GithubWorkflowPermissionDefaultsObservationError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        pin_read_committed(&mut transaction).await?;
        lock_or_create_tenant(&mut transaction, manifest.tenant().as_str())
            .await
            .map_err(|_| GithubWorkflowPermissionDefaultsObservationError::Operation)?;
        lock_or_create_repository(&mut transaction, manifest)
            .await
            .map_err(|_| GithubWorkflowPermissionDefaultsObservationError::Conflict)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(())
    }

    async fn claim_github_workflow_permission_observation(
        &self,
        candidate: GithubWorkflowPermissionObservationCandidate,
    ) -> Result<(), GithubWorkflowPermissionDefaultsObservationError> {
        let consumer = candidate.consumer();
        let inserted = sqlx::query(
            r"
            INSERT INTO github_workflow_permission_observation_candidates (
                observation_id, tenant_id, repository_id, provider_connection_id,
                proposed_manifest_revision, proposed_manifest_digest,
                proposed_runtime_policy_revision, proposed_runtime_policy_digest,
                provider_installation_id, github_repository_id, github_repository_name,
                github_app_id, github_app_client_id, github_app_jwt_issuer_kind,
                app_key_spki_sha256, app_configuration_revision, policy_revision,
                authority_id, authority_identity_digest, expected_default,
                expected_can_approve_pull_request_reviews,
                consumer_owner_id, consumer_claim_fence, consumer_action,
                consumer_revision, claimed_at_ms, expires_at_ms, candidate_digest
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                $12, $13, $14, $15, $16, $17, $18, $19, $20,
                $21, $22, $23, $24, $25, $26, $27, $28
            )
            ON CONFLICT (observation_id) DO NOTHING
            ",
        )
        .bind(candidate.observation_id().as_uuid())
        .bind(candidate.tenant().as_str())
        .bind(candidate.repository_id().as_uuid())
        .bind(candidate.connection_id().as_uuid())
        .bind(pg_bigint(candidate.manifest_revision().get()))
        .bind(candidate.manifest_digest().as_bytes().as_slice())
        .bind(pg_bigint(candidate.runtime_policy_revision().get()))
        .bind(candidate.runtime_policy_digest().as_bytes().as_slice())
        .bind(i64_from_u64(candidate.installation_id().get())?)
        .bind(i64_from_u64(candidate.github_repository_id().get())?)
        .bind(candidate.github_repository_name().as_str())
        .bind(pg_bigint(candidate.github_app_id().get()))
        .bind(candidate.github_app_client_id().as_str())
        .bind(candidate.github_app_jwt_issuer().as_str())
        .bind(candidate.app_key_spki_sha256().as_bytes().as_slice())
        .bind(pg_bigint(candidate.app_configuration_revision().get()))
        .bind(pg_bigint(candidate.policy_revision().get()))
        .bind(candidate.authority_selector().authority_id().as_uuid())
        .bind(candidate.authority_identity_digest().as_bytes().as_slice())
        .bind(candidate.expected_default().as_str())
        .bind(candidate.expected_can_approve_pull_request_reviews())
        .bind(consumer.owner().as_uuid())
        .bind(pg_bigint(consumer.fence().get()))
        .bind(consumer.action().as_str())
        .bind(pg_bigint(consumer.revision().get()))
        .bind(candidate.claimed_at().get())
        .bind(candidate.expires_at().get())
        .bind(candidate.digest().as_bytes().as_slice())
        .execute(&self.pool)
        .await
        .map_err(operation_error)?;
        if inserted.rows_affected() == 1 {
            return Ok(());
        }
        let exact: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM github_workflow_permission_observation_candidates
                WHERE observation_id = $1
                  AND tenant_id = $2
                  AND candidate_digest = $3
            )
            ",
        )
        .bind(candidate.observation_id().as_uuid())
        .bind(candidate.tenant().as_str())
        .bind(candidate.digest().as_bytes().as_slice())
        .fetch_one(&self.pool)
        .await
        .map_err(operation_error)?;
        if exact {
            Ok(())
        } else {
            Err(GithubWorkflowPermissionDefaultsObservationError::Conflict)
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn finalize_github_workflow_permission_observation(
        &self,
        request: FinalizeGithubWorkflowPermissionObservation,
    ) -> Result<bool, GithubWorkflowPermissionDefaultsObservationError> {
        let observation = request.observation();
        let candidate = observation.candidate();
        let desired = request.bootstrap().manifest().manifest();
        let matches = observation.matches_expected_default();
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        pin_read_committed(&mut transaction).await?;

        // Every finalizer takes locks in tenant/repository -> authority ->
        // current policy -> current manifest -> candidate order.
        lock_or_create_tenant(&mut transaction, desired.tenant().as_str())
            .await
            .map_err(|_| GithubWorkflowPermissionDefaultsObservationError::Operation)?;
        lock_or_create_repository(&mut transaction, desired)
            .await
            .map_err(|_| GithubWorkflowPermissionDefaultsObservationError::Conflict)?;
        let authority_exact: Option<bool> = sqlx::query_scalar(
            r"
            SELECT service_scope = 'workflow_permissions_read'
               AND identity_digest = $3
            FROM github_server_service_authorities
            WHERE tenant_id = $1 AND id = $2
            FOR UPDATE
            ",
        )
        .bind(candidate.tenant().as_str())
        .bind(candidate.authority_selector().authority_id().as_uuid())
        .bind(candidate.authority_identity_digest().as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if authority_exact != Some(true) {
            return Err(GithubWorkflowPermissionDefaultsObservationError::Conflict);
        }
        let policy_current = lock_current_runtime_policy(
            &mut transaction,
            request.bootstrap().runtime_policy().pin(),
        )
        .await
        .map_err(|_| GithubWorkflowPermissionDefaultsObservationError::Conflict)?;
        let manifest_current = lock_current_manifest(&mut transaction, desired.connection_id())
            .await
            .map_err(|_| GithubWorkflowPermissionDefaultsObservationError::Conflict)?;

        let candidate_exact: bool = sqlx::query_scalar(
            r"
            SELECT candidate_digest = $3
              AND tenant_id = $2
              AND repository_id = $4
              AND provider_connection_id = $5
              AND proposed_manifest_revision = $6
              AND proposed_manifest_digest = $7
              AND proposed_runtime_policy_revision = $8
              AND proposed_runtime_policy_digest = $9
              AND authority_id = $10
              AND authority_identity_digest = $11
              AND expected_default = $12
              AND expected_can_approve_pull_request_reviews = $13
              AND consumer_owner_id = $14
              AND consumer_claim_fence = $15
              AND consumer_action = $16
              AND consumer_revision = $17
              AND claimed_at_ms = $18
              AND expires_at_ms = $19
            FROM github_workflow_permission_observation_candidates
            WHERE observation_id = $1
            FOR UPDATE
            ",
        )
        .bind(candidate.observation_id().as_uuid())
        .bind(candidate.tenant().as_str())
        .bind(candidate.digest().as_bytes().as_slice())
        .bind(candidate.repository_id().as_uuid())
        .bind(candidate.connection_id().as_uuid())
        .bind(pg_bigint(candidate.manifest_revision().get()))
        .bind(candidate.manifest_digest().as_bytes().as_slice())
        .bind(pg_bigint(candidate.runtime_policy_revision().get()))
        .bind(candidate.runtime_policy_digest().as_bytes().as_slice())
        .bind(candidate.authority_selector().authority_id().as_uuid())
        .bind(candidate.authority_identity_digest().as_bytes().as_slice())
        .bind(candidate.expected_default().as_str())
        .bind(candidate.expected_can_approve_pull_request_reviews())
        .bind(candidate.consumer().owner().as_uuid())
        .bind(pg_bigint(candidate.consumer().fence().get()))
        .bind(candidate.consumer().action().as_str())
        .bind(pg_bigint(candidate.consumer().revision().get()))
        .bind(candidate.claimed_at().get())
        .bind(candidate.expires_at().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?
        .ok_or(GithubWorkflowPermissionDefaultsObservationError::CorruptData)?;
        if !candidate_exact {
            return Err(GithubWorkflowPermissionDefaultsObservationError::Conflict);
        }
        let candidate_is_current: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM github_provider_manifest_current AS manifest
                JOIN workflow_runtime_policy_current AS policy
                  ON policy.tenant_id = manifest.tenant_id
                 AND policy.repository_id = manifest.repository_id
                WHERE manifest.tenant_id = $1
                  AND manifest.repository_id = $2
                  AND manifest.provider_connection_id = $3
                  AND manifest.manifest_revision = $4
                  AND manifest.manifest_digest = $5
                  AND policy.policy_revision = $6
                  AND policy.policy_digest = $7
            )
            ",
        )
        .bind(candidate.tenant().as_str())
        .bind(candidate.repository_id().as_uuid())
        .bind(candidate.connection_id().as_uuid())
        .bind(pg_bigint(candidate.manifest_revision().get()))
        .bind(candidate.manifest_digest().as_bytes().as_slice())
        .bind(pg_bigint(candidate.runtime_policy_revision().get()))
        .bind(candidate.runtime_policy_digest().as_bytes().as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(operation_error)?;

        let existing: Option<bool> = sqlx::query_scalar(
            r"
            SELECT observation_digest = $2
               AND matches_expected_default = $3
               AND credential_request_digest = $4
               AND credential_generation = $5
            FROM github_workflow_permission_default_observations
            WHERE observation_id = $1
            FOR SHARE
            ",
        )
        .bind(candidate.observation_id().as_uuid())
        .bind(observation.digest().as_bytes().as_slice())
        .bind(matches)
        .bind(
            observation
                .credential_request_digest()
                .as_bytes()
                .as_slice(),
        )
        .bind(pg_bigint(observation.credential_generation().get()))
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if let Some(exact) = existing {
            if !exact {
                return Err(GithubWorkflowPermissionDefaultsObservationError::Conflict);
            }
            let head_ready = if matches || candidate_is_current {
                load_ready_permission_default_head(&mut transaction, observation).await?
            } else {
                false
            };
            transaction.commit().await.map_err(operation_error)?;
            return Ok(head_ready);
        }
        let recorded_at = database_now(&mut transaction)
            .await
            .map_err(|_| GithubWorkflowPermissionDefaultsObservationError::Operation)?;
        if recorded_at < observation.provider_observed_at() {
            return Err(GithubWorkflowPermissionDefaultsObservationError::CorruptData);
        }
        if matches && recorded_at > candidate.expires_at() {
            return Err(GithubWorkflowPermissionDefaultsObservationError::Conflict);
        }
        if matches {
            let policy_receipt = register_locked_workflow_runtime_policy(
                &mut transaction,
                request.bootstrap().runtime_policy(),
                policy_current,
                recorded_at,
            )
            .await
            .map_err(|_| GithubWorkflowPermissionDefaultsObservationError::Conflict)?;
            let manifest_receipt =
                bootstrap_locked_manifest(&mut transaction, desired, manifest_current, recorded_at)
                    .await
                    .map_err(|_| GithubWorkflowPermissionDefaultsObservationError::Conflict)?;
            if policy_receipt.pin().revision() != candidate.runtime_policy_revision()
                || policy_receipt.pin().digest() != candidate.runtime_policy_digest()
                || manifest_receipt.current().manifest() != desired
                || !manifest_receipt.current().is_current()
            {
                return Err(GithubWorkflowPermissionDefaultsObservationError::CorruptData);
            }
        }

        insert_observation(&mut transaction, observation, recorded_at).await?;
        let head_ready = if matches || candidate_is_current {
            upsert_permission_default_head(&mut transaction, observation).await?
        } else {
            false
        };

        transaction.commit().await.map_err(operation_error)?;
        Ok(head_ready)
    }
}

async fn insert_observation(
    transaction: &mut Transaction<'_, Postgres>,
    observation: &automata_ci_store::GithubWorkflowPermissionDefaultsObservation,
    recorded_at: automata_ci_core::UnixMillis,
) -> Result<(), GithubWorkflowPermissionDefaultsObservationError> {
    let candidate = observation.candidate();
    let inserted = sqlx::query(
        r"
        INSERT INTO github_workflow_permission_default_observations (
            observation_id, tenant_id, repository_id, provider_connection_id,
            candidate_digest,
            credential_request_digest, credential_generation,
            default_workflow_permissions, can_approve_pull_request_reviews,
            matches_expected_default, api_version,
            request_started_at_ms, provider_observed_at_ms,
            recorded_at_ms,
            activated_manifest_revision, activated_manifest_digest,
            activated_runtime_policy_revision, activated_runtime_policy_digest,
            observation_digest
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8,
            $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
        )
        ON CONFLICT (observation_id) DO NOTHING
        ",
    )
    .bind(candidate.observation_id().as_uuid())
    .bind(candidate.tenant().as_str())
    .bind(candidate.repository_id().as_uuid())
    .bind(candidate.connection_id().as_uuid())
    .bind(candidate.digest().as_bytes().as_slice())
    .bind(
        observation
            .credential_request_digest()
            .as_bytes()
            .as_slice(),
    )
    .bind(pg_bigint(observation.credential_generation().get()))
    .bind(observation.default_workflow_permissions().as_str())
    .bind(observation.can_approve_pull_request_reviews())
    .bind(observation.matches_expected_default())
    .bind(GITHUB_PROVIDER_REST_API_VERSION)
    .bind(candidate.claimed_at().get())
    .bind(observation.provider_observed_at().get())
    .bind(recorded_at.get())
    .bind(
        observation
            .matches_expected_default()
            .then(|| pg_bigint(candidate.manifest_revision().get())),
    )
    .bind(
        observation
            .matches_expected_default()
            .then(|| candidate.manifest_digest().as_bytes().to_vec()),
    )
    .bind(
        observation
            .matches_expected_default()
            .then(|| pg_bigint(candidate.runtime_policy_revision().get())),
    )
    .bind(
        observation
            .matches_expected_default()
            .then(|| candidate.runtime_policy_digest().as_bytes().to_vec()),
    )
    .bind(observation.digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if inserted.rows_affected() == 1 {
        return Ok(());
    }
    let exact: bool = sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM github_workflow_permission_default_observations
            WHERE observation_id = $1
              AND tenant_id = $2
              AND observation_digest = $3
        )
        ",
    )
    .bind(candidate.observation_id().as_uuid())
    .bind(candidate.tenant().as_str())
    .bind(observation.digest().as_bytes().as_slice())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if exact {
        Ok(())
    } else {
        Err(GithubWorkflowPermissionDefaultsObservationError::Conflict)
    }
}

async fn upsert_permission_default_head(
    transaction: &mut Transaction<'_, Postgres>,
    observation: &automata_ci_store::GithubWorkflowPermissionDefaultsObservation,
) -> Result<bool, GithubWorkflowPermissionDefaultsObservationError> {
    let candidate = observation.candidate();
    let recorded_at: i64 = sqlx::query_scalar(
        r"
        SELECT recorded_at_ms
        FROM github_workflow_permission_default_observations
        WHERE tenant_id = $1
          AND observation_id = $2
          AND observation_digest = $3
        FOR SHARE
        ",
    )
    .bind(candidate.tenant().as_str())
    .bind(candidate.observation_id().as_uuid())
    .bind(observation.digest().as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(GithubWorkflowPermissionDefaultsObservationError::CorruptData)?;
    let matches = observation.matches_expected_default();
    let fresh_through = if matches {
        observation
            .provider_observed_at()
            .get()
            .checked_add(GITHUB_WORKFLOW_PERMISSION_DEFAULT_FRESHNESS_MILLIS)
            .ok_or(GithubWorkflowPermissionDefaultsObservationError::CorruptData)?
    } else {
        observation.provider_observed_at().get()
    };
    let changed = sqlx::query(
        r"
        INSERT INTO github_workflow_permission_default_heads (
            tenant_id, repository_id, provider_connection_id,
            manifest_revision, manifest_digest,
            runtime_policy_revision, runtime_policy_digest,
            observation_id, observation_digest, status,
            provider_observed_at_ms, fresh_through_ms, updated_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11, $12, $13
        )
        ON CONFLICT (tenant_id, repository_id, provider_connection_id)
        DO UPDATE SET
            manifest_revision = EXCLUDED.manifest_revision,
            manifest_digest = EXCLUDED.manifest_digest,
            runtime_policy_revision = EXCLUDED.runtime_policy_revision,
            runtime_policy_digest = EXCLUDED.runtime_policy_digest,
            observation_id = EXCLUDED.observation_id,
            observation_digest = EXCLUDED.observation_digest,
            status = EXCLUDED.status,
            provider_observed_at_ms = EXCLUDED.provider_observed_at_ms,
            fresh_through_ms = EXCLUDED.fresh_through_ms,
            updated_at_ms = EXCLUDED.updated_at_ms
        WHERE EXCLUDED.provider_observed_at_ms >
                  github_workflow_permission_default_heads.provider_observed_at_ms
           OR EXCLUDED.provider_observed_at_ms =
                  github_workflow_permission_default_heads.provider_observed_at_ms
              AND (
                  EXCLUDED.status = 'invalid'
                  AND github_workflow_permission_default_heads.status = 'ready'
                  OR EXCLUDED.status =
                         github_workflow_permission_default_heads.status
                     AND EXCLUDED.observation_id >=
                         github_workflow_permission_default_heads.observation_id
              )
        ",
    )
    .bind(candidate.tenant().as_str())
    .bind(candidate.repository_id().as_uuid())
    .bind(candidate.connection_id().as_uuid())
    .bind(pg_bigint(candidate.manifest_revision().get()))
    .bind(candidate.manifest_digest().as_bytes().as_slice())
    .bind(pg_bigint(candidate.runtime_policy_revision().get()))
    .bind(candidate.runtime_policy_digest().as_bytes().as_slice())
    .bind(candidate.observation_id().as_uuid())
    .bind(observation.digest().as_bytes().as_slice())
    .bind(if matches { "ready" } else { "invalid" })
    .bind(observation.provider_observed_at().get())
    .bind(fresh_through)
    .bind(recorded_at)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if changed.rows_affected() == 1 {
        return Ok(matches);
    }

    // A newer replica may have advanced this monotonic head while the current
    // request was performing provider I/O. The immutable observation and exact
    // handoff release must still commit; only the older head write is skipped.
    load_ready_permission_default_head(transaction, observation).await
}

async fn load_ready_permission_default_head(
    transaction: &mut Transaction<'_, Postgres>,
    observation: &automata_ci_store::GithubWorkflowPermissionDefaultsObservation,
) -> Result<bool, GithubWorkflowPermissionDefaultsObservationError> {
    let candidate = observation.candidate();
    let readiness: Option<(bool, i64)> = sqlx::query_as(
        r"
        SELECT head.manifest_revision = $4
           AND head.manifest_digest = $5
           AND head.runtime_policy_revision = $6
           AND head.runtime_policy_digest = $7
           AND head.status = 'ready'
           AND evidence.matches_expected_default
           AND NOT evidence.can_approve_pull_request_reviews
           AND evidence.observation_digest = head.observation_digest
           AND evidence.candidate_digest = candidate.candidate_digest
           AND candidate.proposed_manifest_revision = head.manifest_revision
           AND candidate.proposed_manifest_digest = head.manifest_digest
           AND candidate.proposed_runtime_policy_revision = head.runtime_policy_revision
           AND candidate.proposed_runtime_policy_digest = head.runtime_policy_digest
           AND authority.state = 'active'
           AND authority.service_scope = 'workflow_permissions_read'
           AND authority.identity_digest = candidate.authority_identity_digest,
           head.fresh_through_ms
        FROM github_workflow_permission_default_heads AS head
        JOIN github_workflow_permission_default_observations AS evidence
          ON evidence.tenant_id = head.tenant_id
         AND evidence.observation_id = head.observation_id
        JOIN github_workflow_permission_observation_candidates AS candidate
          ON candidate.tenant_id = evidence.tenant_id
         AND candidate.observation_id = evidence.observation_id
        JOIN github_server_service_authorities AS authority
          ON authority.tenant_id = candidate.tenant_id
         AND authority.id = candidate.authority_id
        JOIN github_provider_manifest_current AS manifest_current
          ON manifest_current.tenant_id = head.tenant_id
         AND manifest_current.repository_id = head.repository_id
         AND manifest_current.provider_connection_id = head.provider_connection_id
         AND manifest_current.manifest_revision = head.manifest_revision
         AND manifest_current.manifest_digest = head.manifest_digest
        JOIN workflow_runtime_policy_current AS policy_current
          ON policy_current.tenant_id = head.tenant_id
         AND policy_current.repository_id = head.repository_id
         AND policy_current.policy_revision = head.runtime_policy_revision
         AND policy_current.policy_digest = head.runtime_policy_digest
        WHERE head.tenant_id = $1
          AND head.repository_id = $2
          AND head.provider_connection_id = $3
        FOR SHARE OF head, evidence, candidate, authority, manifest_current, policy_current
        ",
    )
    .bind(candidate.tenant().as_str())
    .bind(candidate.repository_id().as_uuid())
    .bind(candidate.connection_id().as_uuid())
    .bind(pg_bigint(candidate.manifest_revision().get()))
    .bind(candidate.manifest_digest().as_bytes().as_slice())
    .bind(pg_bigint(candidate.runtime_policy_revision().get()))
    .bind(candidate.runtime_policy_digest().as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let (ready, fresh_through_ms) =
        readiness.ok_or(GithubWorkflowPermissionDefaultsObservationError::CorruptData)?;
    if !ready {
        return Ok(false);
    }
    // Sample the database clock only after every evidence row is locked. A
    // transaction that waited across the freshness boundary must not admit
    // using the earlier pre-lock time.
    let now = database_now(transaction)
        .await
        .map_err(|_| GithubWorkflowPermissionDefaultsObservationError::Operation)?;
    Ok(now.get() < fresh_through_ms)
}

async fn pin_read_committed(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), GithubWorkflowPermissionDefaultsObservationError> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    Ok(())
}

fn i64_from_u64(value: u64) -> Result<i64, GithubWorkflowPermissionDefaultsObservationError> {
    i64::try_from(value).map_err(|_| GithubWorkflowPermissionDefaultsObservationError::CorruptData)
}

fn operation_error(
    _error: impl std::error::Error,
) -> GithubWorkflowPermissionDefaultsObservationError {
    GithubWorkflowPermissionDefaultsObservationError::Operation
}
