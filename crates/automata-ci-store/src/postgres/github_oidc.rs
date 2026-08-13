use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_core::Sha256Digest;
use automata_ci_oidc_github::{
    AuthorizedOidcIssuance, OidcAudience, OidcAuthorityId, OidcClaimSet, OidcIssuance,
    OidcIssuanceRepository, OidcKeyId, OidcRepositoryError, OidcRepositoryErrorKind, OidcSubject,
    OidcTokenId, ReserveOidcIssuance,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use super::{
    PostgresStore, durable_schema::current_durable_schemas,
    runtime_authority::github_manifest_origin_is_closed,
};
use crate::github_oidc::github_oidc_claim_evidence_digest;
use crate::{
    GithubOidcAuthorityRepository, GithubOidcCurrentPolicy, GithubOidcCurrentnessClock,
    GithubOidcKeyDeadline, GithubOidcKeyRetentionRepository, GithubOidcKeyUse, GithubOidcLoadedKey,
    GithubOidcStoreError, GithubOidcSubjectPolicyMode, GithubOidcSubjectPolicyRevision,
    GithubOidcValueError, MAX_GITHUB_OIDC_ISSUANCE_SLOTS, MAXIMUM_OIDC_KEYS_PER_KEYRING,
    ReserveGithubOidcAuthority, ReservedGithubOidcAuthority, RetainGithubOidcKey,
};

// foundation-governance: derived-contract owner=store kind=digest-domain
const AUDIENCE_SLOT_DOMAIN: &[u8] = b"automata/github-oidc/audience-slot:v1\0";
const KEY_RETENTION_LOCK_NAMESPACE: i64 = 5_554_449_119_617_405_696;

#[derive(Debug)]
struct CurrentExecutionRow {
    tenant_id: String,
    repository_id: Uuid,
    github_repository_id: i64,
    github_owner_id: i64,
    github_repository_name: String,
    github_run_subject_evidence_sha256: Vec<u8>,
    origin_kind: String,
    origin_id: Uuid,
    repository_visibility: String,
    private_source_authority_id: Option<Uuid>,
    invocation_id: Uuid,
    logical_job_id: Uuid,
    instance_id: Uuid,
    attempt_number: i32,
    plan_digest: Vec<u8>,
    event_digest: Vec<u8>,
    runtime_context_digest: Vec<u8>,
    workflow_path: String,
    event_name: String,
    git_ref: String,
    head_sha: Vec<u8>,
    workflow_name: String,
    run_number: i64,
    run_attempt: i32,
}

#[derive(Debug)]
struct ReservedAuthorityRow {
    authority_id: Uuid,
    workflow_id: Uuid,
    github_repository_name: String,
    run_id: Uuid,
    job_id: Uuid,
    attempt_id: Uuid,
    fencing_token: i64,
    lease_id: Uuid,
    lease_issued_at_ms: i64,
    lease_expires_at_ms: i64,
    runner_id: Uuid,
    runner_session_id: Uuid,
    runner_session_epoch: i64,
    runner_generation: i64,
    runner_slot: i32,
    job_ir_schema: i16,
    job_ir_size_bytes: i64,
    job_ir_digest: Vec<u8>,
    job_ir_object_key: String,
    permission_evidence_sha256: Vec<u8>,
    subject_policy_mode: String,
    subject_policy_revision: i64,
    subject_policy_sha256: Vec<u8>,
    github_run_subject_evidence_sha256: Vec<u8>,
    claim_evidence_sha256: Vec<u8>,
    github_owner_id: i64,
    subject: String,
    default_audience: String,
    additional_claims: Value,
    configuration_sha256: Vec<u8>,
    request_bearer_key_id: String,
    request_bearer_key_sha256: Vec<u8>,
    request_bearer_verification_skew_seconds: i16,
    id_token_verifier_skew_seconds: i16,
    request_bearer_iat_seconds: i64,
    request_bearer_exp_seconds: i64,
    request_bearer_sha256: Vec<u8>,
}

#[derive(Debug)]
struct MintAuthorityRow {
    permission_evidence_sha256: Vec<u8>,
    subject_policy_mode: String,
    subject_policy_revision: i64,
    subject_policy_sha256: Vec<u8>,
    github_run_subject_evidence_sha256: Vec<u8>,
    claim_evidence_sha256: Vec<u8>,
    github_owner_id: i64,
    configuration_sha256: Vec<u8>,
    subject: String,
    default_audience: String,
    additional_claims: Value,
    request_bearer_iat_seconds: i64,
    request_bearer_exp_seconds: i64,
    request_bearer_verification_skew_seconds: i16,
    id_token_verifier_skew_seconds: i16,
}

#[derive(Debug)]
struct IssuanceSlotRow {
    requested_audience: Option<String>,
    generation: i64,
    token_id: Uuid,
    signing_key_id: String,
    resolved_audience: String,
    issued_at_seconds: i64,
    not_before_seconds: i64,
    expires_at_seconds: i64,
}

#[derive(Debug)]
struct DerivedAuthorityPolicy {
    permission_evidence_sha256: Sha256Digest,
    current_policy: GithubOidcCurrentPolicy,
    github_run_subject_evidence_sha256: Sha256Digest,
    claim_evidence_sha256: Sha256Digest,
    github_owner_id: u64,
    subject: OidcSubject,
    default_audience: OidcAudience,
    additional_claims: OidcClaimSet,
}

/// Configured `PostgreSQL` authority adapter with post-lock trusted time.
#[derive(Clone)]
pub struct PostgresGithubOidcAuthorityRepository {
    store: PostgresStore,
    clock: Arc<dyn GithubOidcCurrentnessClock>,
}

impl PostgresGithubOidcAuthorityRepository {
    /// Creates an authority adapter whose clock is sampled only after all
    /// mutable currentness dependencies have been locked.
    #[must_use]
    pub fn new(store: PostgresStore, clock: Arc<dyn GithubOidcCurrentnessClock>) -> Self {
        Self { store, clock }
    }
}

impl fmt::Debug for PostgresGithubOidcAuthorityRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresGithubOidcAuthorityRepository")
            .field("store", &"[CONFIGURED]")
            .field("clock", &"[INJECTED]")
            .finish()
    }
}

/// Configured `PostgreSQL` issuance adapter with exact signing-key retention metadata.
///
/// The foundation keyring owns private signing material. This adapter receives only
/// the matching key IDs and SHA-256 fingerprints so it can reject key-ID reuse and
/// extend durable retirement deadlines without ever accepting private-key bytes.
#[derive(Clone)]
pub struct PostgresGithubOidcIssuanceRepository {
    store: PostgresStore,
    current_policy: GithubOidcCurrentPolicy,
    signing_keys: BTreeMap<OidcKeyId, Sha256Digest>,
    clock: Arc<dyn GithubOidcCurrentnessClock>,
}

impl PostgresGithubOidcIssuanceRepository {
    /// Creates a bounded issuance adapter from the complete loaded RS256 key metadata.
    ///
    /// # Errors
    ///
    /// Rejects an empty, excessive, duplicated, or non-signing key set.
    /// Fingerprints must be computed before private keys cross the foundation
    /// boundary; this constructor accepts no credential material. Both verifier
    /// skews come from the shared current-policy descriptor.
    pub fn new(
        store: PostgresStore,
        current_policy: GithubOidcCurrentPolicy,
        signing_keys: impl IntoIterator<Item = GithubOidcLoadedKey>,
        clock: Arc<dyn GithubOidcCurrentnessClock>,
    ) -> Result<Self, GithubOidcValueError> {
        if current_policy.subject_policy_mode() != GithubOidcSubjectPolicyMode::StableOwnerEvidence
        {
            return Err(GithubOidcValueError::InvalidPolicy);
        }
        let mut configured = BTreeMap::new();
        for key in signing_keys {
            if key.key_use() != GithubOidcKeyUse::IdTokenSigning
                || configured.len() >= MAXIMUM_OIDC_KEYS_PER_KEYRING
                || configured
                    .insert(key.key_id().clone(), key.key_sha256())
                    .is_some()
            {
                return Err(GithubOidcValueError::InvalidKeyConfiguration);
            }
        }
        if configured.is_empty() {
            return Err(GithubOidcValueError::InvalidKeyConfiguration);
        }
        Ok(Self {
            store,
            current_policy,
            signing_keys: configured,
            clock,
        })
    }

    /// Verifies startup readiness against all durable HMAC and RS256 deadlines.
    ///
    /// The request-bearer slice must describe the complete loaded HMAC keyring. The
    /// configured signing metadata is added automatically. Every unexpired durable
    /// key must have an exact non-null fingerprint in the combined loaded set.
    ///
    /// # Errors
    ///
    /// Fails closed on an invalid loaded set, a missing/mismatched key, an
    /// un-fingerprinted durable deadline, excessive durable state, or database error.
    pub async fn verify_github_oidc_key_readiness(
        &self,
        observed_at_seconds: u64,
        request_bearer_keys: &[GithubOidcLoadedKey],
    ) -> Result<(), GithubOidcStoreError> {
        if request_bearer_keys.len() > MAXIMUM_OIDC_KEYS_PER_KEYRING {
            return Err(GithubOidcStoreError::ResourceExhausted);
        }
        if request_bearer_keys.is_empty()
            || request_bearer_keys
                .iter()
                .any(|key| key.key_use() != GithubOidcKeyUse::RequestBearer)
        {
            return Err(GithubOidcStoreError::Conflict);
        }
        let mut loaded = Vec::with_capacity(request_bearer_keys.len() + self.signing_keys.len());
        loaded.extend_from_slice(request_bearer_keys);
        loaded.extend(self.signing_keys.iter().map(|(key_id, fingerprint)| {
            GithubOidcLoadedKey::new(
                GithubOidcKeyUse::IdTokenSigning,
                key_id.clone(),
                *fingerprint,
            )
        }));
        self.store
            .verify_github_oidc_key_readiness(observed_at_seconds, &loaded)
            .await
    }
}

impl fmt::Debug for PostgresGithubOidcIssuanceRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresGithubOidcIssuanceRepository")
            .field("store", &"[CONFIGURED]")
            .field("current_policy", &self.current_policy)
            .field("clock", &"[INJECTED]")
            .field(
                "signing_key_ids",
                &self.signing_keys.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[async_trait]
impl GithubOidcAuthorityRepository for PostgresGithubOidcAuthorityRepository {
    async fn reserve_github_oidc_authority(
        &self,
        request: ReserveGithubOidcAuthority,
    ) -> Result<ReservedGithubOidcAuthority, GithubOidcStoreError> {
        let mut transaction = self
            .store
            .pool
            .begin()
            .await
            .map_err(oidc_operation_error)?;
        let attempt_id = request.execution().attempt_id().as_uuid();
        let fencing_token = positive_i64(request.execution().fencing_token().get())?;
        if let Some(existing) =
            lock_reserved_authority(&mut transaction, attempt_id, fencing_token).await?
        {
            let result = validate_authority_replay(
                &mut transaction,
                &request,
                existing,
                self.clock.as_ref(),
            )
            .await?;
            transaction.commit().await.map_err(oidc_operation_error)?;
            return Ok(result);
        }

        let current = lock_current_execution(&mut transaction, &request).await?;
        let fresh_observed_at = post_lock_observation(self.clock.as_ref(), &request)?;
        let policy = derive_authority_policy(&request, &current)?;
        let inserted = insert_authority(
            &mut transaction,
            &request,
            &current,
            &policy,
            fresh_observed_at,
        )
        .await?;
        let reserved = if inserted {
            let reserved = proposal_result(&request);
            let retention = RetainGithubOidcKey::request_bearer(
                reserved.request_bearer_key_id().clone(),
                request.proposal().request_bearer_key_sha256(),
                reserved.expires_at_seconds(),
                request
                    .proposal()
                    .request_bearer_verification_skew_seconds(),
                u64::try_from(fresh_observed_at).map_err(|_| GithubOidcStoreError::CorruptData)?
                    / 1_000,
            )
            .map_err(|_| GithubOidcStoreError::CorruptData)?;
            let deadline = retain_key_in_transaction(&mut transaction, &retention).await?;
            if deadline.key_sha256() != Some(request.proposal().request_bearer_key_sha256())
                || deadline.not_after_seconds() < retention.not_after_seconds()
            {
                return Err(GithubOidcStoreError::CorruptData);
            }
            lock_and_observe_current_authority(
                &mut transaction,
                reserved.authority_id().as_uuid(),
                fresh_observed_at,
                request
                    .observed_at()
                    .get()
                    .checked_add(1)
                    .ok_or(GithubOidcStoreError::CorruptData)?,
                Some(request.execution().lease().expires_at().get()),
                self.clock.as_ref(),
            )
            .await?;
            reserved
        } else {
            let existing = lock_reserved_authority(&mut transaction, attempt_id, fencing_token)
                .await?
                .ok_or(GithubOidcStoreError::Conflict)?;
            validate_authority_replay(&mut transaction, &request, existing, self.clock.as_ref())
                .await?
        };
        transaction.commit().await.map_err(oidc_operation_error)?;
        Ok(reserved)
    }
}

#[async_trait]
impl GithubOidcKeyRetentionRepository for PostgresStore {
    async fn retain_github_oidc_key(
        &self,
        request: RetainGithubOidcKey,
    ) -> Result<GithubOidcKeyDeadline, GithubOidcStoreError> {
        let mut transaction = self.pool.begin().await.map_err(oidc_operation_error)?;
        let deadline = retain_key_in_transaction(&mut transaction, &request).await?;
        transaction.commit().await.map_err(oidc_operation_error)?;
        Ok(deadline)
    }

    async fn github_oidc_key_deadline(
        &self,
        key_use: GithubOidcKeyUse,
        key_id: &OidcKeyId,
    ) -> Result<Option<GithubOidcKeyDeadline>, GithubOidcStoreError> {
        sqlx::query(
            r"
            SELECT key_use, key_id, key_sha256, max_not_after_seconds
            FROM github_oidc_key_deadlines
            WHERE key_use = $1 AND key_id = $2
            ",
        )
        .bind(key_use.as_str())
        .bind(key_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(oidc_operation_error)?
        .as_ref()
        .map(decode_key_deadline)
        .transpose()
    }

    async fn required_github_oidc_keys(
        &self,
        observed_at_seconds: u64,
    ) -> Result<Vec<GithubOidcKeyDeadline>, GithubOidcStoreError> {
        let rows = sqlx::query(
            r#"
            SELECT key_use, key_id, key_sha256, max_not_after_seconds
            FROM github_oidc_key_deadlines
            WHERE max_not_after_seconds > $1
            ORDER BY key_use COLLATE "C", key_id COLLATE "C"
            LIMIT 33
            "#,
        )
        .bind(seconds_i64(observed_at_seconds)?)
        .fetch_all(&self.pool)
        .await
        .map_err(oidc_operation_error)?;
        let mut deadlines = Vec::with_capacity(rows.len());
        let mut request_bearers = 0_usize;
        let mut signing_keys = 0_usize;
        for row in &rows {
            let deadline = decode_key_deadline(row)?;
            match deadline.key_use() {
                GithubOidcKeyUse::RequestBearer => request_bearers += 1,
                GithubOidcKeyUse::IdTokenSigning => signing_keys += 1,
            }
            if request_bearers > MAXIMUM_OIDC_KEYS_PER_KEYRING
                || signing_keys > MAXIMUM_OIDC_KEYS_PER_KEYRING
            {
                return Err(GithubOidcStoreError::ResourceExhausted);
            }
            deadlines.push(deadline);
        }
        Ok(deadlines)
    }
}

#[async_trait]
impl OidcIssuanceRepository for PostgresGithubOidcIssuanceRepository {
    async fn reserve(
        &self,
        request: ReserveOidcIssuance,
    ) -> Result<AuthorizedOidcIssuance, OidcRepositoryError> {
        reserve_oidc_issuance(self, request)
            .await
            .map_err(map_repository_error)
    }
}

// Keeping the authority, slot, and retention steps together makes the transaction's
// lock order auditable at the call site.
#[allow(clippy::too_many_lines)]
async fn reserve_oidc_issuance(
    repository: &PostgresGithubOidcIssuanceRepository,
    request: ReserveOidcIssuance,
) -> Result<AuthorizedOidcIssuance, GithubOidcStoreError> {
    validate_mint_request(&request)?;
    let mut transaction = repository
        .store
        .pool
        .begin()
        .await
        .map_err(oidc_operation_error)?;
    let authority = lock_mint_authority(&mut transaction, request.authority_id()).await?;
    let (initial_observed_at_ms, requested_second_end_ms) =
        whole_second_millis(request.observed_at_seconds())?;
    let fresh_observed_at_ms = lock_and_observe_current_authority(
        &mut transaction,
        request.authority_id().as_uuid(),
        initial_observed_at_ms,
        requested_second_end_ms,
        None,
        repository.clock.as_ref(),
    )
    .await?;
    let authorized_at_seconds =
        u64::try_from(fresh_observed_at_ms).map_err(|_| GithubOidcStoreError::CorruptData)? / 1_000;
    if authorized_at_seconds >= request.maximum_expires_at_seconds()
        || authorized_at_seconds >= request.request_expires_at_seconds()
    {
        return Err(GithubOidcStoreError::Unauthorized);
    }
    let subject_policy_revision =
        GithubOidcSubjectPolicyRevision::new(u64_from_i64(authority.subject_policy_revision)?)
            .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let subject_policy_mode =
        GithubOidcSubjectPolicyMode::from_str(&authority.subject_policy_mode)?;
    let subject =
        OidcSubject::new(authority.subject).map_err(|_| GithubOidcStoreError::CorruptData)?;
    let default_audience = OidcAudience::new(authority.default_audience)
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let claims = decode_claims(&authority.additional_claims)?;
    let github_owner_id = u64_from_i64(authority.github_owner_id)?;
    if github_owner_id == 0 {
        return Err(GithubOidcStoreError::CorruptData);
    }
    let computed_claim_evidence = github_oidc_claim_evidence_digest(
        digest(&authority.permission_evidence_sha256)?,
        subject_policy_mode,
        subject_policy_revision,
        digest(&authority.subject_policy_sha256)?,
        digest(&authority.github_run_subject_evidence_sha256)?,
        github_owner_id,
        &subject,
        &default_audience,
        &claims,
        digest(&authority.configuration_sha256)?,
        u64::try_from(authority.request_bearer_verification_skew_seconds)
            .map_err(|_| GithubOidcStoreError::CorruptData)?,
        u64::try_from(authority.id_token_verifier_skew_seconds)
            .map_err(|_| GithubOidcStoreError::CorruptData)?,
    );
    if !digest_equals(&authority.claim_evidence_sha256, computed_claim_evidence) {
        return Err(GithubOidcStoreError::CorruptData);
    }
    if u64_from_i64(authority.request_bearer_iat_seconds)? != request.request_issued_at_seconds()
        || u64_from_i64(authority.request_bearer_exp_seconds)?
            != request.request_expires_at_seconds()
        || subject_policy_mode != repository.current_policy.subject_policy_mode()
        || subject_policy_revision != repository.current_policy.subject_policy_revision()
        || digest(&authority.subject_policy_sha256)?
            != repository.current_policy.subject_policy_sha256()
        || digest(&authority.configuration_sha256)?
            != repository.current_policy.configuration_sha256()
        || u64::try_from(authority.request_bearer_verification_skew_seconds)
            .map_err(|_| GithubOidcStoreError::CorruptData)?
            != repository
                .current_policy
                .request_bearer_verification_skew_seconds()
        || u64::try_from(authority.id_token_verifier_skew_seconds)
            .map_err(|_| GithubOidcStoreError::CorruptData)?
            != repository.current_policy.id_token_verifier_skew_seconds()
    {
        return Err(GithubOidcStoreError::Unauthorized);
    }

    let requested_audience = request.requested_audience().cloned();
    let audience_digest = audience_slot_digest(requested_audience.as_ref());
    let raw_audience = requested_audience.as_ref().map(OidcAudience::as_str);
    let resolved_audience = requested_audience
        .clone()
        .unwrap_or_else(|| default_audience.clone());
    let existing =
        lock_issuance_slot(&mut transaction, request.authority_id(), audience_digest).await?;

    let (issuance, is_live_replay) = if let Some(slot) = existing {
        if slot.requested_audience.as_deref() != raw_audience {
            return Err(GithubOidcStoreError::CorruptData);
        }
        if u64_from_i64(slot.expires_at_seconds)? > authorized_at_seconds {
            (
                decode_live_issuance(
                    &request,
                    &subject,
                    &resolved_audience,
                    &claims,
                    slot,
                    authorized_at_seconds,
                )?,
                true,
            )
        } else {
            replace_issuance_slot(
                &mut transaction,
                &request,
                audience_digest,
                raw_audience,
                &resolved_audience,
                slot.generation,
                authorized_at_seconds,
            )
            .await?;
            (
                proposed_issuance(
                    &request,
                    subject,
                    resolved_audience,
                    claims,
                    authorized_at_seconds,
                )?,
                false,
            )
        }
    } else {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM github_oidc_issuance_slots WHERE authority_id = $1",
        )
        .bind(request.authority_id().as_uuid())
        .fetch_one(&mut *transaction)
        .await
        .map_err(oidc_operation_error)?;
        if usize::try_from(count).map_err(|_| GithubOidcStoreError::CorruptData)?
            >= MAX_GITHUB_OIDC_ISSUANCE_SLOTS
        {
            return Err(GithubOidcStoreError::ResourceExhausted);
        }
        insert_issuance_slot(
            &mut transaction,
            &request,
            audience_digest,
            raw_audience,
            &resolved_audience,
            authorized_at_seconds,
        )
        .await?;
        (
            proposed_issuance(
                &request,
                subject,
                resolved_audience,
                claims,
                authorized_at_seconds,
            )?,
            false,
        )
    };
    ensure_signing_key_retained(
        &mut transaction,
        &issuance,
        &repository.signing_keys,
        repository.current_policy.id_token_verifier_skew_seconds(),
        authorized_at_seconds,
        is_live_replay,
    )
    .await?;
    let final_observed_at_ms = lock_and_observe_current_authority(
        &mut transaction,
        request.authority_id().as_uuid(),
        fresh_observed_at_ms,
        requested_second_end_ms,
        None,
        repository.clock.as_ref(),
    )
    .await?;
    let final_authorized_at_seconds =
        u64::try_from(final_observed_at_ms).map_err(|_| GithubOidcStoreError::CorruptData)? / 1_000;
    if issuance.issued_at_seconds() > final_authorized_at_seconds
        || issuance.not_before_seconds() > final_authorized_at_seconds
        || issuance.expires_at_seconds() <= final_authorized_at_seconds
        || final_authorized_at_seconds >= request.maximum_expires_at_seconds()
        || final_authorized_at_seconds >= request.request_expires_at_seconds()
    {
        return Err(GithubOidcStoreError::Unauthorized);
    }
    transaction.commit().await.map_err(oidc_operation_error)?;
    Ok(AuthorizedOidcIssuance::new(
        issuance,
        final_authorized_at_seconds,
    ))
}

// This single query deliberately locks and authenticates every execution dependency.
#[allow(clippy::too_many_lines)]
async fn lock_current_execution(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ReserveGithubOidcAuthority,
) -> Result<CurrentExecutionRow, GithubOidcStoreError> {
    let execution = request.execution();
    let lease = execution.lease();
    let session = execution.session();
    let schemas = current_durable_schemas();
    let row = sqlx::query(
        r#"
        SELECT repository.tenant_id, repository.id AS repository_id,
               origin.github_repository_id,
               origin.github_repository_owner_id,
               origin.github_repository_name,
               origin.subject_evidence_sha256,
               origin.origin_kind, origin.origin_id,
               origin.repository_visibility,
               origin.private_source_authority_id,
               concrete.invocation_id, concrete.logical_job_id, concrete.instance_id,
               attempt.attempt_number, invocation.plan_digest, run.event_digest,
               concrete.runtime_context_digest, origin.workflow_path,
               origin.event_name, origin.git_ref,
               origin.github_check_head_sha, run.workflow_name,
               run.run_number, run.run_attempt
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN workflow_definitions AS workflow
          ON workflow.id = run.workflow_id
         AND workflow.repository_id = run.repository_id
        JOIN workflow_snapshots AS snapshot
          ON snapshot.id = run.snapshot_id
         AND snapshot.workflow_id = run.workflow_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = run.id
        JOIN logical_workflow_concrete_jobs AS concrete ON concrete.job_id = job.id
        JOIN logical_workflow_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
         AND materialization.run_id = concrete.run_id
         AND materialization.invocation_id = concrete.invocation_id
         AND materialization.logical_job_id = concrete.logical_job_id
         AND materialization.descriptor_digest = concrete.descriptor_digest
         AND materialization.expected_job_id = concrete.job_id
         AND materialization.expected_attempt_id = concrete.initial_attempt_id
         AND materialization.owner_id = concrete.claim_owner_id
         AND materialization.generation = concrete.claim_generation
         AND materialization.claimed_at_ms = concrete.claim_started_at_ms
         AND materialization.expires_at_ms = concrete.claim_expires_at_ms
         AND materialization.updated_at_ms = concrete.committed_at_ms
        JOIN logical_workflow_instances AS instance
          ON instance.id = concrete.instance_id
         AND instance.run_id = concrete.run_id
         AND instance.invocation_id = concrete.invocation_id
         AND instance.logical_job_id = concrete.logical_job_id
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN logical_workflow_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = logical_job.run_id
         AND preparation_claim.invocation_id = logical_job.invocation_id
         AND preparation_claim.logical_job_id = logical_job.id
        JOIN logical_workflow_activation_preparations AS preparation
          ON preparation.run_id = preparation_claim.run_id
         AND preparation.invocation_id = preparation_claim.invocation_id
         AND preparation.logical_job_id = preparation_claim.logical_job_id
         AND preparation.descriptor_digest = preparation_claim.descriptor_digest
        JOIN logical_workflow_activation_publications AS publication
          ON publication.run_id = logical_job.run_id
         AND publication.invocation_id = logical_job.invocation_id
         AND publication.logical_job_id = logical_job.id
         AND publication.activation_input_digest = preparation.activation_input_digest
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = concrete.run_id
         AND invocation.id = concrete.invocation_id
        JOIN runners AS runner ON runner.id = attempt.runner_id
        JOIN runner_sessions AS session
          ON session.id = attempt.runner_session_id
         AND session.runner_id = attempt.runner_id
        JOIN github_workflow_run_manifest_origins AS origin
          ON origin.tenant_id = repository.tenant_id
         AND origin.repository_id = repository.id
         AND origin.workflow_id = run.workflow_id
         AND origin.snapshot_id = run.snapshot_id
         AND origin.run_id = run.id
         AND origin.root_invocation_id = marker.root_invocation_id
        JOIN workflow_admission_receipts AS admission_receipt
          ON admission_receipt.tenant_id = origin.tenant_id
         AND admission_receipt.idempotency_kind =
             origin.admission_idempotency_kind
         AND admission_receipt.idempotency_key =
             origin.admission_idempotency_key
         AND admission_receipt.request_digest = origin.logical_admission_digest
         AND admission_receipt.repository_id = origin.repository_id
         AND admission_receipt.run_id = origin.run_id
         AND admission_receipt.committed_at_ms = origin.admitted_at_ms
         AND admission_receipt.github_subject_evidence_required
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id =
             origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        JOIN github_server_service_authorities AS checks_authority
          ON checks_authority.tenant_id = origin.tenant_id
         AND checks_authority.id = origin.checks_authority_id
         AND checks_authority.repository_id = origin.repository_id
         AND checks_authority.provider_connection_id =
             origin.provider_connection_id
         AND checks_authority.provider_installation_id =
             origin.provider_installation_id
         AND checks_authority.github_repository_id =
             origin.github_repository_id
         AND checks_authority.github_repository_name =
             origin.github_repository_name
         AND checks_authority.service_scope = 'checks_write'
         AND checks_authority.identity_digest =
             origin.checks_authority_identity_digest
         AND checks_authority.app_configuration_revision =
             origin.checks_authority_app_configuration_revision
         AND checks_authority.policy_revision =
             origin.checks_authority_policy_revision
         AND checks_authority.state = 'active'
        WHERE attempt.id = $1
          AND attempt.job_id = $2
          AND attempt.fencing_token = $3
          AND attempt.lease_id = $4
          AND attempt.lease_issued_at_ms = $5
          AND attempt.lease_expires_at_ms = $6
          AND attempt.runner_id = $7
          AND attempt.runner_session_id = $8
          AND attempt.runner_session_epoch = $9
          AND attempt.runner_generation = $10
          AND attempt.runner_slot = $11
          AND attempt.lifecycle IN ('leased', 'preparing', 'running')
          AND job.id = $2
          AND job.run_id = $12
          AND job.admission_epoch = $25
          AND job.job_ir_schema = $19
          AND job.job_ir_schema = $13
          AND job.job_ir_size_bytes = $14
          AND job.job_ir_digest = $15
          AND job.job_ir_object_key = $16
          AND job.requirements @> '{"features":["automata.core/oidc-tokens@v1"]}'::jsonb
          AND run.id = $12
          AND run.workflow_id = $17
          AND run.admission_epoch = $25
          AND run.plan_schema = $20
          AND run.status IN ('queued', 'in_progress')
          AND (
              concrete.invocation_id <> marker.root_invocation_id
              OR run.plan_digest = invocation.plan_digest
          )
          AND run.plan_digest = origin.plan_digest
          AND run.event_digest = origin.event_digest
          AND run.head_sha = origin.github_check_head_sha
          AND run.event_name = origin.event_name
          AND run.git_ref = origin.git_ref
          AND repository.scm_provider = 'github'
          AND repository.owner || '/' || repository.name = $18
          AND repository.provider_repository_id =
              origin.github_repository_id::TEXT
          AND origin.github_repository_name = $18
          AND workflow.path = origin.workflow_path
          AND snapshot.source_digest = origin.source_digest
          AND marker.root_invocation_id = origin.root_invocation_id
          AND marker.admission_digest = origin.logical_admission_digest
          AND marker.admitted_at_ms = origin.admitted_at_ms
          AND manifest.webhook_verifier_fingerprint_sha256 =
              origin.authenticated_webhook_verifier_fingerprint_sha256
          AND manifest.webhook_verifier_revision =
              origin.authenticated_webhook_verifier_revision
          AND manifest.provider_installation_id = origin.provider_installation_id
          AND manifest.github_repository_id = origin.github_repository_id
          AND manifest.github_repository_name = origin.github_repository_name
          AND manifest.repository_visibility = origin.repository_visibility
          AND (
              origin.origin_kind = 'provider_delivery'
              AND origin.admission_idempotency_kind = 'provider_delivery'
              AND origin.github_repository_owner_id > 0
              OR origin.origin_kind IN ('scheduled_fire', 'workflow_rerun')
              AND origin.admission_idempotency_kind = 'operation'
              AND origin.github_repository_owner_id IS NOT NULL
              AND origin.github_repository_owner_id > 0
          )
          AND (
              origin.repository_visibility = 'public'
              AND origin.private_source_authority_id IS NULL
              OR origin.repository_visibility = 'private'
              AND origin.private_source_authority_id IS NOT NULL
          )
          AND marker.orchestration_schema = $21
          AND marker.state IN ('pending', 'active')
          AND automata_logical_workflow_invocation_published(
              run.id, concrete.invocation_id
          )
          AND automata_reusable_workflow_oidc_permission_authorized(
              run.id, concrete.invocation_id
          )
          AND invocation.plan_schema = $22
          AND invocation.state IN ('pending', 'active')
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND logical_job.activation_input_digest =
              preparation.activation_input_digest
          AND preparation_claim.state = 'prepared'
          AND publication.condition_matched
          AND publication.job_ir_version = $23
          AND publication.runtime_context_schema = $24
          AND manifest.authority_profile = 'standard'
          AND logical_job.authority_profile = 'standard'
          AND preparation_claim.authority_profile = 'standard'
          AND preparation.authority_profile = 'standard'
          AND publication.authority_profile = 'standard'
          AND instance.job_ir_version = $23
          AND instance.job_ir_digest = job.job_ir_digest
          AND instance.job_ir_object_key = job.job_ir_object_key
          AND instance.job_ir_size_bytes = job.job_ir_size_bytes
          AND concrete.runtime_context_schema = $24
          AND concrete.requirements = job.requirements
          AND materialization.state = 'materialized'
          AND materialization.authority_profile = 'standard'
          AND concrete.authority_profile = 'standard'
          AND runner.id = $7
          AND runner.tenant_id = repository.tenant_id
          AND runner.status = 'online'
          AND runner.desired_state IN ('active', 'draining')
          AND runner.capabilities @> '{"features":["automata.core/oidc-tokens@v1"]}'::jsonb
          AND runner.generation = $10
          AND runner.session_epoch = $9
          AND session.id = $8
          AND session.session_epoch = $9
          AND session.runner_generation = $10
          AND session.job_ir_schema = $19
          AND session.capability_snapshot @> '{"features":["automata.core/oidc-tokens@v1"]}'::jsonb
          AND session.disconnected_at_ms IS NULL
        FOR SHARE OF attempt, job, run, repository, workflow, snapshot, marker,
                     concrete, materialization, instance,
                     logical_job, preparation_claim, preparation, publication,
                     invocation, runner, session, admission_receipt, manifest,
                     checks_authority
        "#,
    )
    .bind(execution.attempt_id().as_uuid())
    .bind(execution.job_id().as_uuid())
    .bind(positive_i64(execution.fencing_token().get())?)
    .bind(lease.lease_id().as_uuid())
    .bind(lease.issued_at().get())
    .bind(lease.expires_at().get())
    .bind(execution.runner_id().as_uuid())
    .bind(execution.runner_session_id().as_uuid())
    .bind(positive_i64(session.session_epoch().get())?)
    .bind(positive_i64(session.runner_generation().get())?)
    .bind(i32::from(execution.slot().ordinal()))
    .bind(execution.run_id().as_uuid())
    .bind(i32::from(execution.job_ir().version().get()))
    .bind(positive_i64(execution.job_ir().encoded_size())?)
    .bind(execution.job_ir().digest().as_bytes().as_slice())
    .bind(execution.job_ir().object_key().as_str())
    .bind(execution.workflow_id().as_uuid())
    .bind(execution.github_repository_name().as_str())
    .bind(schemas.job_ir_i32)
    .bind(schemas.workflow_plan_i32)
    .bind(schemas.logical_orchestration_i16)
    .bind(schemas.workflow_plan_i16)
    .bind(schemas.job_ir_i16)
    .bind(schemas.runtime_context_i16)
    .bind(schemas.admission_epoch_i32)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?
    .ok_or(GithubOidcStoreError::Unauthorized)?;
    let current = decode_current_execution(&row)?;
    lock_private_source_authority(transaction, &current).await?;
    Ok(current)
}

fn post_lock_observation(
    clock: &dyn GithubOidcCurrentnessClock,
    request: &ReserveGithubOidcAuthority,
) -> Result<i64, GithubOidcStoreError> {
    let observed_at_ms = clock
        .now_millis()
        .map_err(|_| GithubOidcStoreError::Unavailable)?
        .get();
    let bearer_expires_at_ms = seconds_to_millis(request.proposal().expires_at_seconds())?;
    if observed_at_ms < request.observed_at().get()
        || observed_at_ms < request.execution().lease().issued_at().get()
        || observed_at_ms >= request.execution().lease().expires_at().get()
        || observed_at_ms >= bearer_expires_at_ms
    {
        return Err(GithubOidcStoreError::Unauthorized);
    }
    Ok(observed_at_ms)
}

fn decode_current_execution(
    row: &sqlx::postgres::PgRow,
) -> Result<CurrentExecutionRow, GithubOidcStoreError> {
    macro_rules! field {
        ($name:literal) => {
            row.try_get($name)
                .map_err(|_| GithubOidcStoreError::CorruptData)?
        };
    }
    let origin_kind: String = field!("origin_kind");
    let origin_id: Uuid = field!("origin_id");
    if !github_manifest_origin_is_closed(&origin_kind) || origin_id.is_nil() {
        return Err(GithubOidcStoreError::CorruptData);
    }
    Ok(CurrentExecutionRow {
        tenant_id: field!("tenant_id"),
        repository_id: field!("repository_id"),
        github_repository_id: field!("github_repository_id"),
        github_owner_id: field!("github_repository_owner_id"),
        github_repository_name: field!("github_repository_name"),
        github_run_subject_evidence_sha256: field!("subject_evidence_sha256"),
        origin_kind,
        origin_id,
        repository_visibility: field!("repository_visibility"),
        private_source_authority_id: field!("private_source_authority_id"),
        invocation_id: field!("invocation_id"),
        logical_job_id: field!("logical_job_id"),
        instance_id: field!("instance_id"),
        attempt_number: field!("attempt_number"),
        plan_digest: field!("plan_digest"),
        event_digest: field!("event_digest"),
        runtime_context_digest: field!("runtime_context_digest"),
        workflow_path: field!("workflow_path"),
        event_name: field!("event_name"),
        git_ref: field!("git_ref"),
        head_sha: field!("github_check_head_sha"),
        workflow_name: field!("workflow_name"),
        run_number: field!("run_number"),
        run_attempt: field!("run_attempt"),
    })
}

async fn lock_private_source_authority(
    transaction: &mut Transaction<'_, Postgres>,
    current: &CurrentExecutionRow,
) -> Result<(), GithubOidcStoreError> {
    match (
        current.repository_visibility.as_str(),
        current.private_source_authority_id,
    ) {
        ("public", None) => Ok(()),
        ("private", Some(authority_id)) => {
            let exact: bool = sqlx::query_scalar(
                r"
                SELECT TRUE
                FROM github_workflow_run_manifest_origins AS origin
                JOIN github_server_service_authorities AS authority
                  ON authority.tenant_id = origin.tenant_id
                 AND authority.id = origin.private_source_authority_id
                 AND authority.repository_id = origin.repository_id
                 AND authority.provider_connection_id = origin.provider_connection_id
                 AND authority.provider_installation_id = origin.provider_installation_id
                 AND authority.github_repository_id = origin.github_repository_id
                 AND authority.github_repository_name = origin.github_repository_name
                 AND authority.service_scope = 'private_repository_source_read'
                 AND authority.identity_digest =
                     origin.private_source_authority_identity_digest
                 AND authority.app_configuration_revision =
                     origin.private_source_authority_app_configuration_revision
                 AND authority.policy_revision =
                     origin.private_source_authority_policy_revision
                 AND authority.state = 'active'
                WHERE origin.origin_kind = $1
                  AND origin.origin_id = $2
                  AND origin.tenant_id = $3
                  AND origin.repository_id = $4
                  AND origin.private_source_authority_id = $5
                FOR SHARE OF authority
                ",
            )
            .bind(&current.origin_kind)
            .bind(current.origin_id)
            .bind(&current.tenant_id)
            .bind(current.repository_id)
            .bind(authority_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(oidc_operation_error)?
            .unwrap_or(false);
            if exact {
                Ok(())
            } else {
                Err(GithubOidcStoreError::Unauthorized)
            }
        }
        _ => Err(GithubOidcStoreError::CorruptData),
    }
}

fn derive_authority_policy(
    request: &ReserveGithubOidcAuthority,
    current: &CurrentExecutionRow,
) -> Result<DerivedAuthorityPolicy, GithubOidcStoreError> {
    let current_policy = request.current_policy();
    if current_policy.subject_policy_mode() != GithubOidcSubjectPolicyMode::StableOwnerEvidence
        || current.github_owner_id <= 0
        || current.run_number <= 0
        || current.run_attempt <= 0
        || current.head_sha.len() != 20
        || current.head_sha.iter().all(|byte| *byte == 0)
    {
        return Err(GithubOidcStoreError::CorruptData);
    }
    let github_owner_id = u64_from_i64(current.github_owner_id)?;
    let github_run_subject_evidence_sha256 = digest(&current.github_run_subject_evidence_sha256)?;
    let (repository_owner, _) = current
        .github_repository_name
        .split_once('/')
        .ok_or(GithubOidcStoreError::CorruptData)?;
    let subject = if current.event_name == "pull_request" {
        format!("repo:{}:pull_request", current.github_repository_name)
    } else {
        format!(
            "repo:{}:ref:{}",
            current.github_repository_name, current.git_ref
        )
    };
    let subject = OidcSubject::new(subject).map_err(|_| GithubOidcStoreError::CorruptData)?;
    let default_audience = OidcAudience::new(format!("https://github.com/{repository_owner}"))
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let head_sha = lowercase_hex(&current.head_sha);
    let additional_claims = OidcClaimSet::new([
        ("event_name".to_owned(), current.event_name.clone()),
        ("ref".to_owned(), current.git_ref.clone()),
        (
            "repository".to_owned(),
            current.github_repository_name.clone(),
        ),
        ("repository_owner".to_owned(), repository_owner.to_owned()),
        ("run_attempt".to_owned(), current.run_attempt.to_string()),
        ("run_number".to_owned(), current.run_number.to_string()),
        ("runner_environment".to_owned(), "self-hosted".to_owned()),
        ("sha".to_owned(), head_sha.clone()),
        ("workflow".to_owned(), current.workflow_name.clone()),
        (
            "workflow_ref".to_owned(),
            format!(
                "{}/{}@{}",
                current.github_repository_name, current.workflow_path, current.git_ref
            ),
        ),
        ("workflow_sha".to_owned(), head_sha),
    ])
    .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let permission_evidence_sha256 = request.execution().job_ir().digest();
    let claim_evidence_sha256 = github_oidc_claim_evidence_digest(
        permission_evidence_sha256,
        current_policy.subject_policy_mode(),
        current_policy.subject_policy_revision(),
        current_policy.subject_policy_sha256(),
        github_run_subject_evidence_sha256,
        github_owner_id,
        &subject,
        &default_audience,
        &additional_claims,
        current_policy.configuration_sha256(),
        current_policy.request_bearer_verification_skew_seconds(),
        current_policy.id_token_verifier_skew_seconds(),
    );
    Ok(DerivedAuthorityPolicy {
        permission_evidence_sha256,
        current_policy,
        github_run_subject_evidence_sha256,
        claim_evidence_sha256,
        github_owner_id,
        subject,
        default_audience,
        additional_claims,
    })
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[allow(clippy::too_many_lines)] // One auditable bind sequence commits the exact authority tuple.
async fn insert_authority(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ReserveGithubOidcAuthority,
    current: &CurrentExecutionRow,
    policy: &DerivedAuthorityPolicy,
    fresh_observed_at: i64,
) -> Result<bool, GithubOidcStoreError> {
    let schemas = current_durable_schemas();
    let execution = request.execution();
    let lease = execution.lease();
    let session = execution.session();
    let proposal = request.proposal();
    let claims = serde_json::to_value(policy.additional_claims.as_map())
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let inserted = sqlx::query(
        r"
        INSERT INTO github_oidc_authorities (
            attempt_id, fencing_token, authority_id, tenant_id, repository_id,
            github_repository_id, github_repository_name, github_owner_id,
            workflow_id, run_id, invocation_id, logical_job_id, instance_id,
            job_id, attempt_number, lease_id, lease_issued_at_ms,
            lease_expires_at_ms, runner_id, runner_session_id,
            runner_session_epoch, runner_generation, runner_slot,
            admission_epoch, workflow_plan_schema, plan_digest, event_digest,
            runtime_context_digest, job_ir_schema, job_ir_size_bytes,
            job_ir_digest, job_ir_object_key, permission_mode,
            permission_evidence_sha256, subject_policy_mode,
            subject_policy_revision, subject_policy_sha256,
            github_run_subject_evidence_sha256, claim_evidence_sha256,
            subject, default_audience,
            additional_claims, configuration_sha256, request_bearer_key_id,
            request_bearer_key_sha256, request_bearer_verification_skew_seconds,
            id_token_verifier_skew_seconds,
            request_bearer_iat_seconds, request_bearer_exp_seconds,
            request_bearer_sha256, reserved_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18, $19, $20, $21, $22, $23,
            $48, $49, $24, $25, $26, $50, $27, $28, $29, 'id-token:write',
            $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40,
            $41, $42, $43, $44, $45, $46, $47
        )
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(execution.attempt_id().as_uuid())
    .bind(positive_i64(execution.fencing_token().get())?)
    .bind(proposal.authority_id().as_uuid())
    .bind(&current.tenant_id)
    .bind(current.repository_id)
    .bind(current.github_repository_id)
    .bind(&current.github_repository_name)
    .bind(positive_i64(policy.github_owner_id)?)
    .bind(execution.workflow_id().as_uuid())
    .bind(execution.run_id().as_uuid())
    .bind(current.invocation_id)
    .bind(current.logical_job_id)
    .bind(current.instance_id)
    .bind(execution.job_id().as_uuid())
    .bind(current.attempt_number)
    .bind(lease.lease_id().as_uuid())
    .bind(lease.issued_at().get())
    .bind(lease.expires_at().get())
    .bind(execution.runner_id().as_uuid())
    .bind(execution.runner_session_id().as_uuid())
    .bind(positive_i64(session.session_epoch().get())?)
    .bind(positive_i64(session.runner_generation().get())?)
    .bind(i32::from(execution.slot().ordinal()))
    .bind(&current.plan_digest)
    .bind(&current.event_digest)
    .bind(&current.runtime_context_digest)
    .bind(positive_i64(execution.job_ir().encoded_size())?)
    .bind(execution.job_ir().digest().as_bytes().as_slice())
    .bind(execution.job_ir().object_key().as_str())
    .bind(policy.permission_evidence_sha256.as_bytes().as_slice())
    .bind(policy.current_policy.subject_policy_mode().as_str())
    .bind(positive_i64(
        policy.current_policy.subject_policy_revision().get(),
    )?)
    .bind(
        policy
            .current_policy
            .subject_policy_sha256()
            .as_bytes()
            .as_slice(),
    )
    .bind(
        policy
            .github_run_subject_evidence_sha256
            .as_bytes()
            .as_slice(),
    )
    .bind(policy.claim_evidence_sha256.as_bytes().as_slice())
    .bind(policy.subject.as_str())
    .bind(policy.default_audience.as_str())
    .bind(claims)
    .bind(
        policy
            .current_policy
            .configuration_sha256()
            .as_bytes()
            .as_slice(),
    )
    .bind(proposal.request_bearer_key_id().as_str())
    .bind(proposal.request_bearer_key_sha256().as_bytes().as_slice())
    .bind(
        i16::try_from(proposal.request_bearer_verification_skew_seconds())
            .map_err(|_| GithubOidcStoreError::CorruptData)?,
    )
    .bind(
        i16::try_from(policy.current_policy.id_token_verifier_skew_seconds())
            .map_err(|_| GithubOidcStoreError::CorruptData)?,
    )
    .bind(seconds_i64(proposal.issued_at_seconds())?)
    .bind(seconds_i64(proposal.expires_at_seconds())?)
    .bind(proposal.request_bearer_sha256().as_bytes().as_slice())
    .bind(fresh_observed_at)
    .bind(schemas.admission_epoch_i32)
    .bind(schemas.workflow_plan_i32)
    .bind(schemas.job_ir_i32)
    .execute(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?;
    Ok(inserted.rows_affected() == 1)
}

async fn lock_reserved_authority(
    transaction: &mut Transaction<'_, Postgres>,
    attempt_id: Uuid,
    fencing_token: i64,
) -> Result<Option<ReservedAuthorityRow>, GithubOidcStoreError> {
    let row = sqlx::query(
        r"
        SELECT authority_id, workflow_id, github_repository_name, run_id, job_id,
               attempt_id, fencing_token, lease_id, lease_issued_at_ms,
               lease_expires_at_ms, runner_id, runner_session_id,
               runner_session_epoch, runner_generation, runner_slot,
               job_ir_schema, job_ir_size_bytes, job_ir_digest, job_ir_object_key,
               permission_evidence_sha256, subject_policy_mode,
               subject_policy_revision, subject_policy_sha256,
               github_run_subject_evidence_sha256, claim_evidence_sha256,
               github_owner_id, subject,
               default_audience, additional_claims, configuration_sha256,
               request_bearer_key_id, request_bearer_key_sha256,
               request_bearer_verification_skew_seconds,
               id_token_verifier_skew_seconds,
               request_bearer_iat_seconds, request_bearer_exp_seconds,
               request_bearer_sha256
        FROM github_oidc_authorities
        WHERE attempt_id = $1 AND fencing_token = $2
        FOR UPDATE
        ",
    )
    .bind(attempt_id)
    .bind(fencing_token)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?;
    row.map(|row| ReservedAuthorityRow::decode(&row))
        .transpose()
}

impl ReservedAuthorityRow {
    fn decode(row: &sqlx::postgres::PgRow) -> Result<Self, GithubOidcStoreError> {
        macro_rules! field {
            ($name:literal) => {
                row.try_get($name)
                    .map_err(|_| GithubOidcStoreError::CorruptData)?
            };
        }
        Ok(Self {
            authority_id: field!("authority_id"),
            workflow_id: field!("workflow_id"),
            github_repository_name: field!("github_repository_name"),
            run_id: field!("run_id"),
            job_id: field!("job_id"),
            attempt_id: field!("attempt_id"),
            fencing_token: field!("fencing_token"),
            lease_id: field!("lease_id"),
            lease_issued_at_ms: field!("lease_issued_at_ms"),
            lease_expires_at_ms: field!("lease_expires_at_ms"),
            runner_id: field!("runner_id"),
            runner_session_id: field!("runner_session_id"),
            runner_session_epoch: field!("runner_session_epoch"),
            runner_generation: field!("runner_generation"),
            runner_slot: field!("runner_slot"),
            job_ir_schema: field!("job_ir_schema"),
            job_ir_size_bytes: field!("job_ir_size_bytes"),
            job_ir_digest: field!("job_ir_digest"),
            job_ir_object_key: field!("job_ir_object_key"),
            permission_evidence_sha256: field!("permission_evidence_sha256"),
            subject_policy_mode: field!("subject_policy_mode"),
            subject_policy_revision: field!("subject_policy_revision"),
            subject_policy_sha256: field!("subject_policy_sha256"),
            github_run_subject_evidence_sha256: field!("github_run_subject_evidence_sha256"),
            claim_evidence_sha256: field!("claim_evidence_sha256"),
            github_owner_id: field!("github_owner_id"),
            subject: field!("subject"),
            default_audience: field!("default_audience"),
            additional_claims: field!("additional_claims"),
            configuration_sha256: field!("configuration_sha256"),
            request_bearer_key_id: field!("request_bearer_key_id"),
            request_bearer_key_sha256: field!("request_bearer_key_sha256"),
            request_bearer_verification_skew_seconds: field!(
                "request_bearer_verification_skew_seconds"
            ),
            id_token_verifier_skew_seconds: field!("id_token_verifier_skew_seconds"),
            request_bearer_iat_seconds: field!("request_bearer_iat_seconds"),
            request_bearer_exp_seconds: field!("request_bearer_exp_seconds"),
            request_bearer_sha256: field!("request_bearer_sha256"),
        })
    }
}

async fn validate_authority_replay(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ReserveGithubOidcAuthority,
    existing: ReservedAuthorityRow,
    clock: &dyn GithubOidcCurrentnessClock,
) -> Result<ReservedGithubOidcAuthority, GithubOidcStoreError> {
    let initial_observed_at_ms = request.observed_at().get();
    let required_current_before_ms = initial_observed_at_ms
        .checked_add(1)
        .ok_or(GithubOidcStoreError::CorruptData)?;
    let fresh_observed_at_ms = lock_and_observe_current_authority(
        transaction,
        existing.authority_id,
        initial_observed_at_ms,
        required_current_before_ms,
        Some(request.execution().lease().expires_at().get()),
        clock,
    )
    .await?;
    if !authority_replay_matches(request, &existing, fresh_observed_at_ms)? {
        return Err(GithubOidcStoreError::Conflict);
    }
    ensure_request_bearer_key_retained(transaction, &existing).await?;
    lock_and_observe_current_authority(
        transaction,
        existing.authority_id,
        fresh_observed_at_ms,
        required_current_before_ms,
        Some(request.execution().lease().expires_at().get()),
        clock,
    )
    .await?;
    decode_reserved_authority(&existing)
}

fn authority_replay_matches(
    request: &ReserveGithubOidcAuthority,
    existing: &ReservedAuthorityRow,
    fresh_observed_at_ms: i64,
) -> Result<bool, GithubOidcStoreError> {
    let execution = request.execution();
    let lease = execution.lease();
    let session = execution.session();
    let policy = request.current_policy();
    let proposal = request.proposal();
    let subject_policy_mode = GithubOidcSubjectPolicyMode::from_str(&existing.subject_policy_mode)?;
    let subject_policy_revision =
        GithubOidcSubjectPolicyRevision::new(u64_from_i64(existing.subject_policy_revision)?)
            .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let github_owner_id = u64_from_i64(existing.github_owner_id)?;
    if github_owner_id == 0 {
        return Err(GithubOidcStoreError::CorruptData);
    }
    let subject = OidcSubject::new(existing.subject.clone())
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let default_audience = OidcAudience::new(existing.default_audience.clone())
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let claims = decode_claims(&existing.additional_claims)?;
    let request_bearer_skew = u64::try_from(existing.request_bearer_verification_skew_seconds)
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let id_token_skew = u64::try_from(existing.id_token_verifier_skew_seconds)
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let computed_claim_evidence = github_oidc_claim_evidence_digest(
        digest(&existing.permission_evidence_sha256)?,
        subject_policy_mode,
        subject_policy_revision,
        digest(&existing.subject_policy_sha256)?,
        digest(&existing.github_run_subject_evidence_sha256)?,
        github_owner_id,
        &subject,
        &default_audience,
        &claims,
        digest(&existing.configuration_sha256)?,
        request_bearer_skew,
        id_token_skew,
    );
    let durable_bearer_iat_ms =
        seconds_to_millis(u64_from_i64(existing.request_bearer_iat_seconds)?)?;
    let durable_bearer_exp_ms =
        seconds_to_millis(u64_from_i64(existing.request_bearer_exp_seconds)?)?;
    Ok(existing.workflow_id == execution.workflow_id().as_uuid()
        && existing.github_repository_name == execution.github_repository_name().as_str()
        && existing.run_id == execution.run_id().as_uuid()
        && existing.job_id == execution.job_id().as_uuid()
        && existing.attempt_id == execution.attempt_id().as_uuid()
        && existing.fencing_token == positive_i64(execution.fencing_token().get())?
        && existing.lease_id == lease.lease_id().as_uuid()
        && existing.lease_issued_at_ms == lease.issued_at().get()
        && existing.lease_expires_at_ms <= lease.expires_at().get()
        && existing.runner_id == execution.runner_id().as_uuid()
        && existing.runner_session_id == execution.runner_session_id().as_uuid()
        && existing.runner_session_epoch == positive_i64(session.session_epoch().get())?
        && existing.runner_generation == positive_i64(session.runner_generation().get())?
        && existing.runner_slot == i32::from(execution.slot().ordinal())
        && existing.job_ir_schema
            == i16::try_from(execution.job_ir().version().get())
                .map_err(|_| GithubOidcStoreError::CorruptData)?
        && existing.job_ir_size_bytes == positive_i64(execution.job_ir().encoded_size())?
        && existing.job_ir_digest == execution.job_ir().digest().as_bytes()
        && existing.job_ir_object_key == execution.job_ir().object_key().as_str()
        && digest_equals(
            &existing.permission_evidence_sha256,
            execution.job_ir().digest(),
        )
        && subject_policy_mode == policy.subject_policy_mode()
        && existing.subject_policy_revision
            == positive_i64(policy.subject_policy_revision().get())?
        && digest_equals(
            &existing.subject_policy_sha256,
            policy.subject_policy_sha256(),
        )
        && digest_equals(&existing.claim_evidence_sha256, computed_claim_evidence)
        && digest_equals(
            &existing.configuration_sha256,
            policy.configuration_sha256(),
        )
        && request_bearer_skew == proposal.request_bearer_verification_skew_seconds()
        && request_bearer_skew == policy.request_bearer_verification_skew_seconds()
        && id_token_skew == policy.id_token_verifier_skew_seconds()
        && existing.request_bearer_iat_seconds == seconds_i64(proposal.issued_at_seconds())?
        && existing.request_bearer_exp_seconds <= seconds_i64(proposal.expires_at_seconds())?
        && durable_bearer_iat_ms <= fresh_observed_at_ms
        && fresh_observed_at_ms < durable_bearer_exp_ms)
}

fn decode_reserved_authority(
    row: &ReservedAuthorityRow,
) -> Result<ReservedGithubOidcAuthority, GithubOidcStoreError> {
    Ok(ReservedGithubOidcAuthority::new(
        OidcAuthorityId::from_uuid(row.authority_id)
            .map_err(|_| GithubOidcStoreError::CorruptData)?,
        OidcKeyId::new(row.request_bearer_key_id.clone())
            .map_err(|_| GithubOidcStoreError::CorruptData)?,
        u64_from_i64(row.request_bearer_iat_seconds)?,
        u64_from_i64(row.request_bearer_exp_seconds)?,
        digest(&row.request_bearer_sha256)?,
    ))
}

fn proposal_result(request: &ReserveGithubOidcAuthority) -> ReservedGithubOidcAuthority {
    let proposal = request.proposal();
    ReservedGithubOidcAuthority::new(
        proposal.authority_id(),
        proposal.request_bearer_key_id().clone(),
        proposal.issued_at_seconds(),
        proposal.expires_at_seconds(),
        proposal.request_bearer_sha256(),
    )
}

async fn lock_mint_authority(
    transaction: &mut Transaction<'_, Postgres>,
    authority_id: OidcAuthorityId,
) -> Result<MintAuthorityRow, GithubOidcStoreError> {
    let row = sqlx::query(
        r"
        SELECT permission_evidence_sha256, subject_policy_mode,
               subject_policy_revision, subject_policy_sha256,
               github_run_subject_evidence_sha256, claim_evidence_sha256,
               github_owner_id, configuration_sha256, subject,
               default_audience, additional_claims,
               request_bearer_iat_seconds, request_bearer_exp_seconds,
               request_bearer_verification_skew_seconds,
               id_token_verifier_skew_seconds
        FROM github_oidc_authorities
        WHERE authority_id = $1
        FOR UPDATE
        ",
    )
    .bind(authority_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?
    .ok_or(GithubOidcStoreError::Unauthorized)?;
    macro_rules! field {
        ($name:literal) => {
            row.try_get($name)
                .map_err(|_| GithubOidcStoreError::CorruptData)?
        };
    }
    Ok(MintAuthorityRow {
        permission_evidence_sha256: field!("permission_evidence_sha256"),
        subject_policy_mode: field!("subject_policy_mode"),
        subject_policy_revision: field!("subject_policy_revision"),
        subject_policy_sha256: field!("subject_policy_sha256"),
        github_run_subject_evidence_sha256: field!("github_run_subject_evidence_sha256"),
        claim_evidence_sha256: field!("claim_evidence_sha256"),
        github_owner_id: field!("github_owner_id"),
        configuration_sha256: field!("configuration_sha256"),
        subject: field!("subject"),
        default_audience: field!("default_audience"),
        additional_claims: field!("additional_claims"),
        request_bearer_iat_seconds: field!("request_bearer_iat_seconds"),
        request_bearer_exp_seconds: field!("request_bearer_exp_seconds"),
        request_bearer_verification_skew_seconds: field!(
            "request_bearer_verification_skew_seconds"
        ),
        id_token_verifier_skew_seconds: field!("id_token_verifier_skew_seconds"),
    })
}

async fn lock_and_observe_current_authority(
    transaction: &mut Transaction<'_, Postgres>,
    authority_id: Uuid,
    initial_observed_at_ms: i64,
    required_current_before_ms: i64,
    expected_lease_expires_at_ms: Option<i64>,
    clock: &dyn GithubOidcCurrentnessClock,
) -> Result<i64, GithubOidcStoreError> {
    let locked: bool = sqlx::query_scalar(
        r"
        SELECT automata_lock_github_oidc_authority_dependencies(authority)
        FROM github_oidc_authorities AS authority
        WHERE authority.authority_id = $1
        ",
    )
    .bind(authority_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?
    .ok_or(GithubOidcStoreError::Unauthorized)?;
    if !locked {
        return Err(GithubOidcStoreError::CorruptData);
    }
    if let Some(expected_lease_expires_at_ms) = expected_lease_expires_at_ms {
        let durable_lease_expires_at_ms: Option<Option<i64>> = sqlx::query_scalar(
            r"
            SELECT attempt.lease_expires_at_ms
            FROM github_oidc_authorities AS authority
            JOIN job_attempts AS attempt ON attempt.id = authority.attempt_id
            WHERE authority.authority_id = $1
            ",
        )
        .bind(authority_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(oidc_operation_error)?;
        let durable_lease_expires_at_ms = durable_lease_expires_at_ms
            .flatten()
            .ok_or(GithubOidcStoreError::Unauthorized)?;
        if durable_lease_expires_at_ms != expected_lease_expires_at_ms {
            return Err(GithubOidcStoreError::Unauthorized);
        }
    }
    let fresh_observed_at_ms = clock
        .now_millis()
        .map_err(|_| GithubOidcStoreError::Unavailable)?
        .get();
    if fresh_observed_at_ms < initial_observed_at_ms {
        return Err(GithubOidcStoreError::Unauthorized);
    }
    let required_current_before_ms = required_current_before_ms.max(
        fresh_observed_at_ms
            .checked_add(1)
            .ok_or(GithubOidcStoreError::CorruptData)?,
    );
    let current: bool = sqlx::query_scalar(
        r"
        SELECT automata_github_oidc_authority_is_current(authority, $2, $3)
        FROM github_oidc_authorities AS authority
        WHERE authority.authority_id = $1
        ",
    )
    .bind(authority_id)
    .bind(fresh_observed_at_ms)
    .bind(required_current_before_ms)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?
    .ok_or(GithubOidcStoreError::Unauthorized)?;
    if !current {
        return Err(GithubOidcStoreError::Unauthorized);
    }
    Ok(fresh_observed_at_ms)
}

async fn lock_issuance_slot(
    transaction: &mut Transaction<'_, Postgres>,
    authority_id: OidcAuthorityId,
    audience_digest: Sha256Digest,
) -> Result<Option<IssuanceSlotRow>, GithubOidcStoreError> {
    let row = sqlx::query(
        r"
        SELECT requested_audience, generation, token_id, signing_key_id,
               resolved_audience, issued_at_seconds, not_before_seconds,
               expires_at_seconds
        FROM github_oidc_issuance_slots
        WHERE authority_id = $1 AND audience_key_sha256 = $2
        FOR UPDATE
        ",
    )
    .bind(authority_id.as_uuid())
    .bind(audience_digest.as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?;
    row.map(|row| {
        macro_rules! field {
            ($name:literal) => {
                row.try_get($name)
                    .map_err(|_| GithubOidcStoreError::CorruptData)?
            };
        }
        Ok(IssuanceSlotRow {
            requested_audience: field!("requested_audience"),
            generation: field!("generation"),
            token_id: field!("token_id"),
            signing_key_id: field!("signing_key_id"),
            resolved_audience: field!("resolved_audience"),
            issued_at_seconds: field!("issued_at_seconds"),
            not_before_seconds: field!("not_before_seconds"),
            expires_at_seconds: field!("expires_at_seconds"),
        })
    })
    .transpose()
}

async fn insert_issuance_slot(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ReserveOidcIssuance,
    audience_digest: Sha256Digest,
    raw_audience: Option<&str>,
    resolved_audience: &OidcAudience,
    authorized_at_seconds: u64,
) -> Result<(), GithubOidcStoreError> {
    sqlx::query(
        r"
        INSERT INTO github_oidc_issuance_slots (
            authority_id, audience_key_sha256, requested_audience, generation,
            token_id, signing_key_id, resolved_audience, issued_at_seconds,
            not_before_seconds, expires_at_seconds, created_at_seconds,
            updated_at_seconds
        ) VALUES ($1, $2, $3, 1, $4, $5, $6, $7, $7, $8, $7, $7)
        ",
    )
    .bind(request.authority_id().as_uuid())
    .bind(audience_digest.as_bytes().as_slice())
    .bind(raw_audience)
    .bind(request.proposed_token_id().as_uuid())
    .bind(request.proposed_signing_key_id().as_str())
    .bind(resolved_audience.as_str())
    .bind(seconds_i64(authorized_at_seconds)?)
    .bind(seconds_i64(request.maximum_expires_at_seconds())?)
    .execute(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?;
    Ok(())
}

async fn replace_issuance_slot(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ReserveOidcIssuance,
    audience_digest: Sha256Digest,
    raw_audience: Option<&str>,
    resolved_audience: &OidcAudience,
    old_generation: i64,
    authorized_at_seconds: u64,
) -> Result<(), GithubOidcStoreError> {
    let generation = old_generation
        .checked_add(1)
        .ok_or(GithubOidcStoreError::ResourceExhausted)?;
    let result = sqlx::query(
        r"
        UPDATE github_oidc_issuance_slots
        SET generation = $3, token_id = $4, signing_key_id = $5,
            resolved_audience = $6, issued_at_seconds = $7,
            not_before_seconds = $7, expires_at_seconds = $8,
            updated_at_seconds = $7
        WHERE authority_id = $1 AND audience_key_sha256 = $2
          AND requested_audience IS NOT DISTINCT FROM $9
          AND generation = $10
        ",
    )
    .bind(request.authority_id().as_uuid())
    .bind(audience_digest.as_bytes().as_slice())
    .bind(generation)
    .bind(request.proposed_token_id().as_uuid())
    .bind(request.proposed_signing_key_id().as_str())
    .bind(resolved_audience.as_str())
    .bind(seconds_i64(authorized_at_seconds)?)
    .bind(seconds_i64(request.maximum_expires_at_seconds())?)
    .bind(raw_audience)
    .bind(old_generation)
    .execute(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?;
    if result.rows_affected() != 1 {
        return Err(GithubOidcStoreError::Conflict);
    }
    Ok(())
}

fn decode_live_issuance(
    request: &ReserveOidcIssuance,
    subject: &OidcSubject,
    resolved_audience: &OidcAudience,
    claims: &OidcClaimSet,
    slot: IssuanceSlotRow,
    authorized_at_seconds: u64,
) -> Result<OidcIssuance, GithubOidcStoreError> {
    let durable_audience =
        OidcAudience::new(slot.resolved_audience).map_err(|_| GithubOidcStoreError::CorruptData)?;
    let issued_at = u64_from_i64(slot.issued_at_seconds)?;
    let not_before = u64_from_i64(slot.not_before_seconds)?;
    let expires_at = u64_from_i64(slot.expires_at_seconds)?;
    if &durable_audience != resolved_audience
        || issued_at < request.request_issued_at_seconds()
        || not_before < request.request_issued_at_seconds()
        || not_before > issued_at
        || expires_at <= issued_at
    {
        return Err(GithubOidcStoreError::CorruptData);
    }
    if issued_at > authorized_at_seconds
        || not_before > authorized_at_seconds
        || expires_at <= authorized_at_seconds
        || expires_at > request.maximum_expires_at_seconds()
        || expires_at > request.request_expires_at_seconds()
    {
        return Err(GithubOidcStoreError::Conflict);
    }
    OidcIssuance::new(
        request.authority_id(),
        OidcTokenId::from_uuid(slot.token_id).map_err(|_| GithubOidcStoreError::CorruptData)?,
        OidcKeyId::new(slot.signing_key_id).map_err(|_| GithubOidcStoreError::CorruptData)?,
        subject.clone(),
        durable_audience,
        claims.clone(),
        issued_at,
        not_before,
        expires_at,
    )
    .map_err(|_| GithubOidcStoreError::CorruptData)
}

fn proposed_issuance(
    request: &ReserveOidcIssuance,
    subject: OidcSubject,
    audience: OidcAudience,
    claims: OidcClaimSet,
    authorized_at_seconds: u64,
) -> Result<OidcIssuance, GithubOidcStoreError> {
    OidcIssuance::new(
        request.authority_id(),
        request.proposed_token_id(),
        request.proposed_signing_key_id().clone(),
        subject,
        audience,
        claims,
        authorized_at_seconds,
        authorized_at_seconds,
        request.maximum_expires_at_seconds(),
    )
    .map_err(|_| GithubOidcStoreError::CorruptData)
}

async fn ensure_signing_key_retained(
    transaction: &mut Transaction<'_, Postgres>,
    issuance: &OidcIssuance,
    signing_keys: &BTreeMap<OidcKeyId, Sha256Digest>,
    verifier_skew_seconds: u64,
    observed_at_seconds: u64,
    is_live_replay: bool,
) -> Result<(), GithubOidcStoreError> {
    let fingerprint = signing_keys
        .get(issuance.signing_key_id())
        .copied()
        .ok_or(GithubOidcStoreError::Conflict)?;
    let retention = RetainGithubOidcKey::id_token_signing(
        issuance.signing_key_id().clone(),
        fingerprint,
        issuance.expires_at_seconds(),
        verifier_skew_seconds,
        observed_at_seconds,
    )
    .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let deadline = if is_live_replay {
        extend_existing_key_in_transaction(transaction, &retention).await?
    } else {
        retain_key_in_transaction(transaction, &retention).await?
    };
    if deadline.key_sha256() != Some(fingerprint)
        || deadline.not_after_seconds() < retention.not_after_seconds()
    {
        return Err(GithubOidcStoreError::CorruptData);
    }
    Ok(())
}

async fn ensure_request_bearer_key_retained(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &ReservedAuthorityRow,
) -> Result<(), GithubOidcStoreError> {
    let key_id = OidcKeyId::new(authority.request_bearer_key_id.clone())
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let fingerprint = digest(&authority.request_bearer_key_sha256)?;
    let skew = u64::try_from(authority.request_bearer_verification_skew_seconds)
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let required = u64_from_i64(authority.request_bearer_exp_seconds)?
        .checked_add(skew)
        .ok_or(GithubOidcStoreError::CorruptData)?;
    let deadline = lock_key_deadline(transaction, GithubOidcKeyUse::RequestBearer, &key_id)
        .await?
        .ok_or(GithubOidcStoreError::CorruptData)?;
    if deadline.key_sha256() != Some(fingerprint) || deadline.not_after_seconds() < required {
        return Err(GithubOidcStoreError::CorruptData);
    }
    Ok(())
}

async fn lock_key_deadline(
    transaction: &mut Transaction<'_, Postgres>,
    key_use: GithubOidcKeyUse,
    key_id: &OidcKeyId,
) -> Result<Option<GithubOidcKeyDeadline>, GithubOidcStoreError> {
    let row = sqlx::query(
        r"
        SELECT key_use, key_id, key_sha256, max_not_after_seconds
        FROM github_oidc_key_deadlines
        WHERE key_use = $1 AND key_id = $2
        FOR SHARE
        ",
    )
    .bind(key_use.as_str())
    .bind(key_id.as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?;
    row.as_ref().map(decode_key_deadline).transpose()
}

async fn extend_existing_key_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RetainGithubOidcKey,
) -> Result<GithubOidcKeyDeadline, GithubOidcStoreError> {
    let row = sqlx::query(
        r"
        SELECT key_sha256, max_not_after_seconds, updated_at_seconds
        FROM github_oidc_key_deadlines
        WHERE key_use = $1 AND key_id = $2
        FOR UPDATE
        ",
    )
    .bind(request.key_use().as_str())
    .bind(request.key_id().as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?
    .ok_or(GithubOidcStoreError::CorruptData)?;
    let durable_fingerprint: Option<Vec<u8>> = row
        .try_get("key_sha256")
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let requested_fingerprint = Some(request.key_sha256().as_bytes().to_vec());
    if durable_fingerprint != requested_fingerprint {
        return Err(GithubOidcStoreError::Conflict);
    }
    let durable_deadline: i64 = row
        .try_get("max_not_after_seconds")
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let durable_updated: i64 = row
        .try_get("updated_at_seconds")
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    lock_key_use_for_extension(transaction, request.key_use()).await?;
    let updated = sqlx::query(
        r"
        UPDATE github_oidc_key_deadlines
        SET max_not_after_seconds = greatest(max_not_after_seconds, $3),
            updated_at_seconds = greatest(updated_at_seconds, $4)
        WHERE key_use = $1 AND key_id = $2
          AND key_sha256 IS NOT DISTINCT FROM $5
          AND max_not_after_seconds = $6
          AND updated_at_seconds = $7
        ",
    )
    .bind(request.key_use().as_str())
    .bind(request.key_id().as_str())
    .bind(seconds_i64(request.not_after_seconds())?)
    .bind(seconds_i64(request.observed_at_seconds())?)
    .bind(&durable_fingerprint)
    .bind(durable_deadline)
    .bind(durable_updated)
    .execute(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?;
    if updated.rows_affected() != 1 {
        return Err(GithubOidcStoreError::CorruptData);
    }
    ensure_active_key_bound(transaction, request).await?;
    lock_key_deadline(transaction, request.key_use(), request.key_id())
        .await?
        .ok_or(GithubOidcStoreError::CorruptData)
}

async fn retain_key_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RetainGithubOidcKey,
) -> Result<GithubOidcKeyDeadline, GithubOidcStoreError> {
    let mut existing = lock_key_deadline_row(transaction, request).await?;
    if existing.as_ref().is_some_and(|row| {
        u64_from_i64(row.max_not_after_seconds)
            .is_ok_and(|deadline| deadline > request.observed_at_seconds())
    }) {
        lock_key_use_for_extension(transaction, request.key_use()).await?;
        update_locked_key_deadline(
            transaction,
            request,
            existing.as_ref().expect("checked above"),
        )
        .await?;
        ensure_active_key_bound(transaction, request).await?;
        return lock_key_deadline(transaction, request.key_use(), request.key_id())
            .await?
            .ok_or(GithubOidcStoreError::CorruptData);
    }

    // Re-activating an expired tombstone or introducing a new key can increase
    // the active-key count. Serialize only those rare transitions per use-domain;
    // ordinary deadline extensions remain row-local across all authorities.
    lock_key_use_for_transition(transaction, request.key_use()).await?;
    if existing.is_none() {
        existing = lock_key_deadline_row(transaction, request).await?;
    }
    let requested_fingerprint = Some(request.key_sha256().as_bytes().to_vec());
    if let Some(row) = existing.as_ref() {
        update_locked_key_deadline(transaction, request, row).await?;
    } else {
        sqlx::query(
            r"
            INSERT INTO github_oidc_key_deadlines (
                key_use, key_id, key_sha256, max_not_after_seconds,
                updated_at_seconds
            ) VALUES ($1, $2, $3, $4, $5)
            ",
        )
        .bind(request.key_use().as_str())
        .bind(request.key_id().as_str())
        .bind(&requested_fingerprint)
        .bind(seconds_i64(request.not_after_seconds())?)
        .bind(seconds_i64(request.observed_at_seconds())?)
        .execute(&mut **transaction)
        .await
        .map_err(oidc_operation_error)?;
    }
    ensure_active_key_bound(transaction, request).await?;
    lock_key_deadline(transaction, request.key_use(), request.key_id())
        .await?
        .ok_or(GithubOidcStoreError::CorruptData)
}

async fn lock_key_use_for_extension(
    transaction: &mut Transaction<'_, Postgres>,
    key_use: GithubOidcKeyUse,
) -> Result<(), GithubOidcStoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1, $2))")
        .bind(key_use.as_str())
        .bind(KEY_RETENTION_LOCK_NAMESPACE)
        .execute(&mut **transaction)
        .await
        .map_err(oidc_operation_error)?;
    Ok(())
}

async fn lock_key_use_for_transition(
    transaction: &mut Transaction<'_, Postgres>,
    key_use: GithubOidcKeyUse,
) -> Result<(), GithubOidcStoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
        .bind(key_use.as_str())
        .bind(KEY_RETENTION_LOCK_NAMESPACE)
        .execute(&mut **transaction)
        .await
        .map_err(oidc_operation_error)?;
    Ok(())
}

async fn ensure_active_key_bound(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RetainGithubOidcKey,
) -> Result<(), GithubOidcStoreError> {
    let active_count: i64 = sqlx::query_scalar(
        r"
        SELECT count(*) FROM github_oidc_key_deadlines
        WHERE key_use = $1 AND max_not_after_seconds > $2
        ",
    )
    .bind(request.key_use().as_str())
    .bind(seconds_i64(request.observed_at_seconds())?)
    .fetch_one(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?;
    if usize::try_from(active_count).map_err(|_| GithubOidcStoreError::CorruptData)?
        > MAXIMUM_OIDC_KEYS_PER_KEYRING
    {
        return Err(GithubOidcStoreError::ResourceExhausted);
    }
    Ok(())
}

#[derive(Debug)]
struct LockedKeyDeadlineRow {
    key_sha256: Option<Vec<u8>>,
    max_not_after_seconds: i64,
    updated_at_seconds: i64,
}

async fn lock_key_deadline_row(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RetainGithubOidcKey,
) -> Result<Option<LockedKeyDeadlineRow>, GithubOidcStoreError> {
    let row = sqlx::query(
        r"
        SELECT key_sha256, max_not_after_seconds, updated_at_seconds
        FROM github_oidc_key_deadlines
        WHERE key_use = $1 AND key_id = $2
        FOR UPDATE
        ",
    )
    .bind(request.key_use().as_str())
    .bind(request.key_id().as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?;
    row.map(|row| {
        Ok(LockedKeyDeadlineRow {
            key_sha256: row
                .try_get("key_sha256")
                .map_err(|_| GithubOidcStoreError::CorruptData)?,
            max_not_after_seconds: row
                .try_get("max_not_after_seconds")
                .map_err(|_| GithubOidcStoreError::CorruptData)?,
            updated_at_seconds: row
                .try_get("updated_at_seconds")
                .map_err(|_| GithubOidcStoreError::CorruptData)?,
        })
    })
    .transpose()
}

async fn update_locked_key_deadline(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RetainGithubOidcKey,
    durable: &LockedKeyDeadlineRow,
) -> Result<(), GithubOidcStoreError> {
    let requested_fingerprint = Some(request.key_sha256().as_bytes().to_vec());
    if requested_fingerprint.is_some() && requested_fingerprint != durable.key_sha256 {
        return Err(GithubOidcStoreError::Conflict);
    }
    if durable
        .key_sha256
        .as_ref()
        .is_some_and(|value| value.len() != 32)
        || durable.max_not_after_seconds <= 0
        || durable.updated_at_seconds < 0
        || durable.updated_at_seconds > durable.max_not_after_seconds
    {
        return Err(GithubOidcStoreError::CorruptData);
    }
    let updated = sqlx::query(
        r"
        UPDATE github_oidc_key_deadlines
        SET max_not_after_seconds = greatest(max_not_after_seconds, $3),
            updated_at_seconds = greatest(updated_at_seconds, $4)
        WHERE key_use = $1 AND key_id = $2
          AND key_sha256 IS NOT DISTINCT FROM $5
          AND max_not_after_seconds = $6
          AND updated_at_seconds = $7
        ",
    )
    .bind(request.key_use().as_str())
    .bind(request.key_id().as_str())
    .bind(seconds_i64(request.not_after_seconds())?)
    .bind(seconds_i64(request.observed_at_seconds())?)
    .bind(&durable.key_sha256)
    .bind(durable.max_not_after_seconds)
    .bind(durable.updated_at_seconds)
    .execute(&mut **transaction)
    .await
    .map_err(oidc_operation_error)?;
    if updated.rows_affected() != 1 {
        return Err(GithubOidcStoreError::CorruptData);
    }
    Ok(())
}

fn decode_key_deadline(
    row: &sqlx::postgres::PgRow,
) -> Result<GithubOidcKeyDeadline, GithubOidcStoreError> {
    let key_use: String = row
        .try_get("key_use")
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let key_id: String = row
        .try_get("key_id")
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let key_sha256: Option<Vec<u8>> = row
        .try_get("key_sha256")
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    let not_after: i64 = row
        .try_get("max_not_after_seconds")
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    Ok(GithubOidcKeyDeadline::new(
        GithubOidcKeyUse::from_str(&key_use)?,
        OidcKeyId::new(key_id).map_err(|_| GithubOidcStoreError::CorruptData)?,
        key_sha256.as_deref().map(digest).transpose()?,
        u64_from_i64(not_after)?,
    ))
}

fn validate_mint_request(request: &ReserveOidcIssuance) -> Result<(), GithubOidcStoreError> {
    if request.request_issued_at_seconds() > request.observed_at_seconds()
        || request.request_expires_at_seconds() <= request.observed_at_seconds()
        || request.maximum_expires_at_seconds() > request.request_expires_at_seconds()
        || request.maximum_expires_at_seconds() <= request.observed_at_seconds()
        || whole_second_millis(request.observed_at_seconds()).is_err()
    {
        return Err(GithubOidcStoreError::Unauthorized);
    }
    Ok(())
}

fn decode_claims(value: &Value) -> Result<OidcClaimSet, GithubOidcStoreError> {
    let object = value.as_object().ok_or(GithubOidcStoreError::CorruptData)?;
    let mut claims = Vec::with_capacity(object.len());
    for (name, value) in object {
        let value = value.as_str().ok_or(GithubOidcStoreError::CorruptData)?;
        claims.push((name.clone(), value.to_owned()));
    }
    OidcClaimSet::new(claims).map_err(|_| GithubOidcStoreError::CorruptData)
}

fn audience_slot_digest(audience: Option<&OidcAudience>) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(AUDIENCE_SLOT_DOMAIN);
    match audience {
        None => hasher.update([0]),
        Some(audience) => {
            hasher.update([1]);
            hasher.update(
                u64::try_from(audience.as_str().len())
                    .expect("OIDC audience length is bounded")
                    .to_be_bytes(),
            );
            hasher.update(audience.as_str().as_bytes());
        }
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn map_repository_error(error: GithubOidcStoreError) -> OidcRepositoryError {
    let kind = match error {
        GithubOidcStoreError::Unauthorized => OidcRepositoryErrorKind::Unauthorized,
        GithubOidcStoreError::Conflict => OidcRepositoryErrorKind::Conflict,
        GithubOidcStoreError::ResourceExhausted => OidcRepositoryErrorKind::ResourceExhausted,
        GithubOidcStoreError::CorruptData => OidcRepositoryErrorKind::CorruptData,
        GithubOidcStoreError::Unavailable => OidcRepositoryErrorKind::Unavailable,
    };
    OidcRepositoryError::new(kind)
}

// `map_err` consumes the SQLx error; retaining that callback shape avoids a closure at
// every database operation while diagnostics remain fully sanitized.
#[allow(clippy::needless_pass_by_value)]
fn oidc_operation_error(error: sqlx::Error) -> GithubOidcStoreError {
    match &error {
        sqlx::Error::Io(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed => GithubOidcStoreError::Unavailable,
        sqlx::Error::Database(database) => {
            let constraint = database.constraint().unwrap_or_default();
            if matches!(
                constraint,
                "github_oidc_authority_current_execution"
                    | "github_oidc_issuance_current_authority"
            ) {
                return GithubOidcStoreError::Unauthorized;
            }
            if constraint == "github_oidc_issuance_slot_bound" {
                return GithubOidcStoreError::ResourceExhausted;
            }
            let code = database.code().unwrap_or_default();
            if code == "23505" {
                GithubOidcStoreError::Conflict
            } else if code.starts_with("08")
                || matches!(code.as_ref(), "40001" | "40P01" | "55P03" | "57014")
            {
                GithubOidcStoreError::Unavailable
            } else {
                GithubOidcStoreError::CorruptData
            }
        }
        _ => GithubOidcStoreError::CorruptData,
    }
}

fn digest(bytes: &[u8]) -> Result<Sha256Digest, GithubOidcStoreError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| GithubOidcStoreError::CorruptData)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn digest_equals(bytes: &[u8], expected: Sha256Digest) -> bool {
    bytes == expected.as_bytes()
}

fn seconds_i64(seconds: u64) -> Result<i64, GithubOidcStoreError> {
    i64::try_from(seconds).map_err(|_| GithubOidcStoreError::CorruptData)
}

fn seconds_to_millis(seconds: u64) -> Result<i64, GithubOidcStoreError> {
    seconds
        .checked_mul(1_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(GithubOidcStoreError::CorruptData)
}

fn whole_second_millis(seconds: u64) -> Result<(i64, i64), GithubOidcStoreError> {
    let observed_at_ms = seconds_to_millis(seconds)?;
    let required_current_before_ms = seconds
        .checked_add(1)
        .and_then(|value| value.checked_mul(1_000))
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(GithubOidcStoreError::CorruptData)?;
    Ok((observed_at_ms, required_current_before_ms))
}

fn u64_from_i64(value: i64) -> Result<u64, GithubOidcStoreError> {
    u64::try_from(value).map_err(|_| GithubOidcStoreError::CorruptData)
}

fn positive_i64(value: u64) -> Result<i64, GithubOidcStoreError> {
    if value == 0 {
        return Err(GithubOidcStoreError::CorruptData);
    }
    i64::try_from(value).map_err(|_| GithubOidcStoreError::CorruptData)
}
