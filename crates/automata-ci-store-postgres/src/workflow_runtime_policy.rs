use std::collections::BTreeMap;

use async_trait::async_trait;
use automata_ci_core::{
    Architecture, ContainerFeature, EnvironmentProfile, EnvironmentProfileId, OperatingSystem,
    RunId, RunnerFeature, RunnerLabel, Sha256Digest, UnixMillis,
};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};

use super::{PostgresStore, durable_schema::current_durable_schemas, pg_bigint};
use automata_ci_store::{
    PinnedWorkflowRuntimePolicy, RegisterWorkflowRuntimePolicy, RepositoryId, StoreError,
    TenantScope, WORKFLOW_RUNTIME_POLICY_RUNNER_FEATURE_SCHEMA, WorkflowRunnerFeaturePolicy,
    WorkflowRuntimePolicy, WorkflowRuntimePolicyMapping, WorkflowRuntimePolicyPin,
    WorkflowRuntimePolicyReceipt, WorkflowRuntimePolicyRepository, WorkflowRuntimePolicyRevision,
    WorkflowRuntimePolicyStoreError,
};

#[async_trait]
impl WorkflowRuntimePolicyRepository for PostgresStore {
    async fn load_workflow_runtime_policy_for_run(
        &self,
        run_id: RunId,
    ) -> Result<PinnedWorkflowRuntimePolicy, WorkflowRuntimePolicyStoreError> {
        if run_id.as_uuid().is_nil() {
            return Err(WorkflowRuntimePolicyStoreError::InvalidTarget);
        }
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(operation_error)?;
        let pinned = load_pinned_runtime_policy_for_run(&mut transaction, run_id).await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(pinned)
    }
}

pub(super) async fn load_pinned_runtime_policy_for_run(
    transaction: &mut Transaction<'_, Postgres>,
    run_id: RunId,
) -> Result<PinnedWorkflowRuntimePolicy, WorkflowRuntimePolicyStoreError> {
    let row = sqlx::query(
        r"
        SELECT pin.tenant_id, pin.repository_id, pin.policy_revision,
               pin.policy_digest
        FROM logical_workflow_runtime_policy_pins AS pin
        JOIN logical_workflow_runs AS marker ON marker.run_id = pin.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN repositories AS repository
          ON repository.id = pin.repository_id
         AND repository.tenant_id = pin.tenant_id
         AND run.repository_id = pin.repository_id
        WHERE pin.run_id = $1
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(WorkflowRuntimePolicyStoreError::InvalidTarget)?;
    let tenant = TenantScope::from_authenticated_tenant_id(
        row.try_get::<String, _>("tenant_id")
            .map_err(operation_error)?,
    )
    .map_err(corrupt_value)?;
    let repository_id =
        RepositoryId::from_uuid(row.try_get("repository_id").map_err(operation_error)?);
    let revision = decode_revision(&row)?;
    let digest = decode_digest(&row, "policy_digest")?;
    let pin = WorkflowRuntimePolicyPin::new(tenant, repository_id, revision, digest);
    let policy = load_revision(
        transaction,
        pin.tenant(),
        pin.repository_id(),
        pin.revision(),
    )
    .await?;
    PinnedWorkflowRuntimePolicy::new(run_id, pin, policy).map_err(corrupt_value)
}

pub(super) async fn lock_current(
    transaction: &mut Transaction<'_, Postgres>,
    pin: &WorkflowRuntimePolicyPin,
) -> Result<Option<PgRow>, WorkflowRuntimePolicyStoreError> {
    sqlx::query(
        r"
        SELECT policy_revision, policy_digest, activated_at_ms
        FROM workflow_runtime_policy_current
        WHERE tenant_id = $1 AND repository_id = $2
        FOR UPDATE
        ",
    )
    .bind(pin.tenant().as_str())
    .bind(pin.repository_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)
}

pub(super) async fn register_locked_workflow_runtime_policy(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterWorkflowRuntimePolicy,
    current: Option<PgRow>,
    authoritative_at: UnixMillis,
) -> Result<WorkflowRuntimePolicyReceipt, WorkflowRuntimePolicyStoreError> {
    if i16::try_from(request.policy().schema()).ok()
        != Some(current_durable_schemas().workflow_runtime_policy_i16)
    {
        return Err(WorkflowRuntimePolicyStoreError::Conflict);
    }
    if let Some(current) = current {
        let revision: i64 = current
            .try_get("policy_revision")
            .map_err(operation_error)?;
        let digest = decode_digest(&current, "policy_digest")?;
        let activated_at: i64 = current
            .try_get("activated_at_ms")
            .map_err(operation_error)?;
        if revision == pg_bigint(request.pin().revision().get()) {
            if digest != request.pin().digest() {
                return Err(WorkflowRuntimePolicyStoreError::Conflict);
            }
            let loaded = load_revision(
                transaction,
                request.pin().tenant(),
                request.pin().repository_id(),
                request.pin().revision(),
            )
            .await?;
            if &loaded != request.policy() {
                return Err(WorkflowRuntimePolicyStoreError::Conflict);
            }
            return Ok(WorkflowRuntimePolicyReceipt::new(
                request.pin().clone(),
                UnixMillis::new(activated_at),
                true,
            ));
        }
        let next = revision
            .checked_add(1)
            .ok_or(WorkflowRuntimePolicyStoreError::Conflict)?;
        if next != pg_bigint(request.pin().revision().get())
            || digest == request.pin().digest()
            || authoritative_at.get() < activated_at
        {
            return Err(WorkflowRuntimePolicyStoreError::Conflict);
        }
    } else if request.pin().revision().get() != 1 {
        return Err(WorkflowRuntimePolicyStoreError::Conflict);
    }

    insert_revision(transaction, request, authoritative_at).await?;
    insert_mappings(transaction, request).await?;
    seal_revision(transaction, request).await?;
    select_current(transaction, request, authoritative_at).await?;
    Ok(WorkflowRuntimePolicyReceipt::new(
        request.pin().clone(),
        authoritative_at,
        false,
    ))
}

pub(super) async fn database_now(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<UnixMillis, WorkflowRuntimePolicyStoreError> {
    let value: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut **transaction)
            .await
            .map_err(operation_error)?;
    Ok(UnixMillis::new(value))
}

async fn insert_revision(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterWorkflowRuntimePolicy,
    registered_at: UnixMillis,
) -> Result<(), WorkflowRuntimePolicyStoreError> {
    let schemas = current_durable_schemas();
    let rows = sqlx::query(
        r"
        INSERT INTO workflow_runtime_policy_revisions (
            tenant_id, repository_id, policy_revision, policy_digest,
            canonical_policy, permission_policy_canonical, resource_policy_canonical,
            policy_schema, workspace_root, workspace_derivation_version,
            mapping_count, state, registered_at_ms, sealed_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$12,$10,'staging',$11,NULL)
        ",
    )
    .bind(request.pin().tenant().as_str())
    .bind(request.pin().repository_id().as_uuid())
    .bind(pg_bigint(request.pin().revision().get()))
    .bind(request.pin().digest().as_bytes().as_slice())
    .bind(request.policy().canonical_bytes().map_err(corrupt_value)?)
    .bind(
        request
            .policy()
            .permission_policy()
            .canonical_bytes()
            .map_err(corrupt_value)?,
    )
    .bind(serde_json::to_vec(&request.policy().resource_policy()).map_err(corrupt_value)?)
    .bind(schemas.workflow_runtime_policy_i16)
    .bind(request.policy().workspace_root())
    .bind(count_i32(request.policy().mappings().len())?)
    .bind(registered_at.get())
    .bind(schemas.workflow_workspace_derivation_i16)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "workflow runtime policy revision insert")
}

async fn insert_mappings(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterWorkflowRuntimePolicy,
) -> Result<(), WorkflowRuntimePolicyStoreError> {
    let schemas = current_durable_schemas();
    for mapping in request.policy().mappings() {
        let rows = sqlx::query(
            r"
            INSERT INTO workflow_runtime_policy_mappings (
                tenant_id, repository_id, policy_revision, selector,
                environment_profile_id, environment_profile_digest,
                operating_system, architecture, feature_count,
                runner_feature_schema, runner_feature_count
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            ",
        )
        .bind(request.pin().tenant().as_str())
        .bind(request.pin().repository_id().as_uuid())
        .bind(pg_bigint(request.pin().revision().get()))
        .bind(mapping.selector().as_str())
        .bind(mapping.environment().id().as_str())
        .bind(mapping.environment().digest().as_bytes().as_slice())
        .bind(operating_system_name(mapping.operating_system()))
        .bind(architecture_name(mapping.architecture()))
        .bind(count_i32(mapping.container_features().len())?)
        .bind(
            mapping
                .runner_feature_policy()
                .map(|_| schemas.workflow_runtime_runner_feature_policy_i16),
        )
        .bind(count_i32(
            mapping
                .runner_feature_policy()
                .map_or(0, |policy| policy.supported().len()),
        )?)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?
        .rows_affected();
        exact_one(rows, "workflow runtime policy mapping insert")?;
        for feature in mapping.container_features() {
            let rows = sqlx::query(
                r"
                INSERT INTO workflow_runtime_policy_features (
                    tenant_id, repository_id, policy_revision, selector, feature
                ) VALUES ($1,$2,$3,$4,$5)
                ",
            )
            .bind(request.pin().tenant().as_str())
            .bind(request.pin().repository_id().as_uuid())
            .bind(pg_bigint(request.pin().revision().get()))
            .bind(mapping.selector().as_str())
            .bind(feature.as_str())
            .execute(&mut **transaction)
            .await
            .map_err(operation_error)?
            .rows_affected();
            exact_one(rows, "workflow runtime policy feature insert")?;
        }
        if let Some(policy) = mapping.runner_feature_policy() {
            for feature in policy.supported() {
                let rows = sqlx::query(
                    r"
                    INSERT INTO workflow_runtime_policy_runner_features (
                        tenant_id, repository_id, policy_revision, selector, feature
                    ) VALUES ($1,$2,$3,$4,$5)
                    ",
                )
                .bind(request.pin().tenant().as_str())
                .bind(request.pin().repository_id().as_uuid())
                .bind(pg_bigint(request.pin().revision().get()))
                .bind(mapping.selector().as_str())
                .bind(feature.as_str())
                .execute(&mut **transaction)
                .await
                .map_err(operation_error)?
                .rows_affected();
                exact_one(rows, "workflow runtime policy runner feature insert")?;
            }
        }
    }
    Ok(())
}

async fn seal_revision(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterWorkflowRuntimePolicy,
) -> Result<(), WorkflowRuntimePolicyStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE workflow_runtime_policy_revisions
        SET state = 'sealed', sealed_at_ms = registered_at_ms
        WHERE tenant_id = $1 AND repository_id = $2
          AND policy_revision = $3 AND policy_digest = $4
          AND state = 'staging' AND sealed_at_ms IS NULL
        ",
    )
    .bind(request.pin().tenant().as_str())
    .bind(request.pin().repository_id().as_uuid())
    .bind(pg_bigint(request.pin().revision().get()))
    .bind(request.pin().digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    exact_one(rows, "workflow runtime policy seal")
}

async fn select_current(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RegisterWorkflowRuntimePolicy,
    activated_at: UnixMillis,
) -> Result<(), WorkflowRuntimePolicyStoreError> {
    let rows = if request.pin().revision().get() == 1 {
        sqlx::query(
            r"
            INSERT INTO workflow_runtime_policy_current (
                tenant_id, repository_id, policy_revision,
                policy_digest, activated_at_ms
            ) VALUES ($1,$2,$3,$4,$5)
            ",
        )
        .bind(request.pin().tenant().as_str())
        .bind(request.pin().repository_id().as_uuid())
        .bind(pg_bigint(request.pin().revision().get()))
        .bind(request.pin().digest().as_bytes().as_slice())
        .bind(activated_at.get())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?
        .rows_affected()
    } else {
        let predecessor = pg_bigint(request.pin().revision().get())
            .checked_sub(1)
            .ok_or(WorkflowRuntimePolicyStoreError::Conflict)?;
        sqlx::query(
            r"
            UPDATE workflow_runtime_policy_current
            SET policy_revision = $3, policy_digest = $4, activated_at_ms = $5
            WHERE tenant_id = $1 AND repository_id = $2
              AND policy_revision = $6
            ",
        )
        .bind(request.pin().tenant().as_str())
        .bind(request.pin().repository_id().as_uuid())
        .bind(pg_bigint(request.pin().revision().get()))
        .bind(request.pin().digest().as_bytes().as_slice())
        .bind(activated_at.get())
        .bind(predecessor)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?
        .rows_affected()
    };
    exact_one(rows, "workflow runtime policy current transition")
}

#[allow(clippy::too_many_lines)] // One decode validates the complete canonical policy aggregate.
pub(super) async fn load_revision(
    transaction: &mut Transaction<'_, Postgres>,
    tenant: &TenantScope,
    repository_id: RepositoryId,
    revision: WorkflowRuntimePolicyRevision,
) -> Result<WorkflowRuntimePolicy, WorkflowRuntimePolicyStoreError> {
    let schemas = current_durable_schemas();
    let header = sqlx::query(
        r"
        SELECT policy_digest, canonical_policy, permission_policy_canonical,
               resource_policy_canonical,
               policy_schema, workspace_root, workspace_derivation_version,
               mapping_count, state
        FROM workflow_runtime_policy_revisions
        WHERE tenant_id = $1 AND repository_id = $2 AND policy_revision = $3
        ",
    )
    .bind(tenant.as_str())
    .bind(repository_id.as_uuid())
    .bind(pg_bigint(revision.get()))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or(WorkflowRuntimePolicyStoreError::InvalidTarget)?;
    let expected_digest = decode_digest(&header, "policy_digest")?;
    let expected_canonical: Vec<u8> = header
        .try_get("canonical_policy")
        .map_err(operation_error)?;
    let expected_resource_policy: Vec<u8> = header
        .try_get("resource_policy_canonical")
        .map_err(operation_error)?;
    let expected_permission_policy: Vec<u8> = header
        .try_get("permission_policy_canonical")
        .map_err(operation_error)?;
    let canonical_policy =
        WorkflowRuntimePolicy::decode_canonical(&expected_canonical).map_err(corrupt_value)?;
    let schema: i16 = header.try_get("policy_schema").map_err(operation_error)?;
    let derivation: i16 = header
        .try_get("workspace_derivation_version")
        .map_err(operation_error)?;
    let expected_mappings: i32 = header.try_get("mapping_count").map_err(operation_error)?;
    let state: String = header.try_get("state").map_err(operation_error)?;
    if i16::try_from(canonical_policy.schema()).ok() != Some(schema)
        || derivation != schemas.workflow_workspace_derivation_i16
        || state != "sealed"
        || canonical_policy
            .permission_policy()
            .canonical_bytes()
            .map_err(corrupt_value)?
            != expected_permission_policy
    {
        return Err(
            StoreError::corrupt_data("workflow runtime policy header is not current").into(),
        );
    }
    let rows = sqlx::query(
        r"
        SELECT mapping.selector, mapping.environment_profile_id,
               mapping.environment_profile_digest, mapping.operating_system,
               mapping.architecture, mapping.feature_count,
               mapping.runner_feature_schema, mapping.runner_feature_count,
               ARRAY(
                   SELECT runner_feature.feature
                   FROM workflow_runtime_policy_runner_features AS runner_feature
                   WHERE runner_feature.tenant_id = mapping.tenant_id
                     AND runner_feature.repository_id = mapping.repository_id
                     AND runner_feature.policy_revision = mapping.policy_revision
                     AND runner_feature.selector = mapping.selector
                   ORDER BY runner_feature.feature
               ) AS runner_features,
               feature.feature
        FROM workflow_runtime_policy_mappings AS mapping
        LEFT JOIN workflow_runtime_policy_features AS feature
          ON feature.tenant_id = mapping.tenant_id
         AND feature.repository_id = mapping.repository_id
         AND feature.policy_revision = mapping.policy_revision
         AND feature.selector = mapping.selector
        WHERE mapping.tenant_id = $1 AND mapping.repository_id = $2
          AND mapping.policy_revision = $3
        ORDER BY mapping.selector, feature.feature
        ",
    )
    .bind(tenant.as_str())
    .bind(repository_id.as_uuid())
    .bind(pg_bigint(revision.get()))
    .fetch_all(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if rows.len() > 64 * 64 {
        return Err(StoreError::corrupt_data("workflow runtime policy row bound exceeded").into());
    }
    let mut grouped: BTreeMap<String, MappingParts> = BTreeMap::new();
    for row in rows {
        let selector: String = row.try_get("selector").map_err(operation_error)?;
        let profile_id = row
            .try_get("environment_profile_id")
            .map_err(operation_error)?;
        let profile_digest = row
            .try_get::<Vec<u8>, _>("environment_profile_digest")
            .map_err(operation_error)?;
        let operating_system = row.try_get("operating_system").map_err(operation_error)?;
        let architecture = row.try_get("architecture").map_err(operation_error)?;
        let expected_features = row.try_get("feature_count").map_err(operation_error)?;
        let runner_feature_schema = row
            .try_get::<Option<i16>, _>("runner_feature_schema")
            .map_err(operation_error)?;
        let expected_runner_features = row
            .try_get("runner_feature_count")
            .map_err(operation_error)?;
        let runner_features = row.try_get("runner_features").map_err(operation_error)?;
        let entry = grouped.entry(selector).or_insert_with(|| MappingParts {
            profile_id,
            profile_digest,
            operating_system,
            architecture,
            expected_features,
            features: Vec::new(),
            runner_feature_schema,
            expected_runner_features,
            runner_features,
        });
        if let Some(feature) = row
            .try_get::<Option<String>, _>("feature")
            .map_err(operation_error)?
        {
            entry.features.push(feature);
        }
    }
    if i32::try_from(grouped.len()).ok() != Some(expected_mappings) {
        return Err(
            StoreError::corrupt_data("workflow runtime policy mapping count disagrees").into(),
        );
    }
    let mappings = grouped
        .into_iter()
        .map(|(selector, parts)| decode_mapping(selector, parts))
        .collect::<Result<Vec<_>, _>>()?;
    let workspace_root: String = header.try_get("workspace_root").map_err(operation_error)?;
    if canonical_policy.workspace_root() != workspace_root
        || canonical_policy.mappings().len() != mappings.len()
        || canonical_policy
            .mappings()
            .iter()
            .zip(&mappings)
            .any(|(canonical, relational)| !relational.matches(canonical))
        || canonical_policy.digest() != expected_digest
        || serde_json::to_vec(&canonical_policy.resource_policy()).map_err(corrupt_value)?
            != expected_resource_policy
    {
        return Err(StoreError::corrupt_data("workflow runtime policy digest disagrees").into());
    }
    if canonical_policy.canonical_bytes().map_err(corrupt_value)? != expected_canonical {
        return Err(
            StoreError::corrupt_data("workflow runtime policy canonical bytes disagree").into(),
        );
    }
    Ok(canonical_policy)
}

struct MappingParts {
    profile_id: String,
    profile_digest: Vec<u8>,
    operating_system: String,
    architecture: String,
    expected_features: i32,
    features: Vec<String>,
    runner_feature_schema: Option<i16>,
    expected_runner_features: i32,
    runner_features: Vec<String>,
}

struct RelationalMapping {
    selector: RunnerLabel,
    environment: EnvironmentProfile,
    operating_system: OperatingSystem,
    architecture: Architecture,
    container_features: std::collections::BTreeSet<ContainerFeature>,
    runner_feature_policy: Option<WorkflowRunnerFeaturePolicy>,
}

impl RelationalMapping {
    fn matches(&self, mapping: &WorkflowRuntimePolicyMapping) -> bool {
        self.selector == *mapping.selector()
            && self.environment == *mapping.environment()
            && self.operating_system == *mapping.operating_system()
            && self.architecture == *mapping.architecture()
            && self.container_features == *mapping.container_features()
            && self.runner_feature_policy.as_ref() == mapping.runner_feature_policy()
    }
}

fn decode_mapping(
    selector: String,
    parts: MappingParts,
) -> Result<RelationalMapping, WorkflowRuntimePolicyStoreError> {
    if i32::try_from(parts.features.len()).ok() != Some(parts.expected_features) {
        return Err(
            StoreError::corrupt_data("workflow runtime policy feature count disagrees").into(),
        );
    }
    let selector = RunnerLabel::new(selector).map_err(corrupt_value)?;
    let profile_id = EnvironmentProfileId::new(parts.profile_id).map_err(corrupt_value)?;
    let profile_digest = decode_digest_value(parts.profile_digest)?;
    let environment = EnvironmentProfile::new(profile_id, profile_digest);
    let operating_system = match parts.operating_system.as_str() {
        "linux" => OperatingSystem::Linux,
        "windows" => OperatingSystem::Windows,
        "macos" => OperatingSystem::Macos,
        _ => return Err(StoreError::corrupt_data("workflow runtime policy OS is unknown").into()),
    };
    let architecture = match parts.architecture.as_str() {
        "x86_64" => Architecture::X86_64,
        "aarch64" => Architecture::Aarch64,
        _ => {
            return Err(StoreError::corrupt_data(
                "workflow runtime policy architecture is unknown",
            )
            .into());
        }
    };
    let features = parts
        .features
        .into_iter()
        .map(ContainerFeature::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(corrupt_value)?;
    let container_features = features
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if i32::try_from(parts.runner_features.len()).ok() != Some(parts.expected_runner_features) {
        return Err(StoreError::corrupt_data(
            "workflow runtime policy runner feature count disagrees",
        )
        .into());
    }
    let runner_feature_policy = match parts.runner_feature_schema {
        None if parts.runner_features.is_empty() => None,
        Some(schema)
            if u16::try_from(schema).ok()
                == Some(WORKFLOW_RUNTIME_POLICY_RUNNER_FEATURE_SCHEMA) =>
        {
            let features = parts
                .runner_features
                .into_iter()
                .map(RunnerFeature::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(corrupt_value)?;
            Some(WorkflowRunnerFeaturePolicy::new(features).map_err(corrupt_value)?)
        }
        _ => {
            return Err(StoreError::corrupt_data(
                "workflow runtime policy runner feature schema is invalid",
            )
            .into());
        }
    };
    if let Some(policy) = &runner_feature_policy {
        WorkflowRuntimePolicyMapping::new(
            selector.clone(),
            environment.clone(),
            operating_system.clone(),
            architecture.clone(),
            policy.clone(),
            container_features.iter().cloned(),
        )
        .map_err(corrupt_value)?;
    }
    Ok(RelationalMapping {
        selector,
        environment,
        operating_system,
        architecture,
        container_features,
        runner_feature_policy,
    })
}

fn decode_revision(
    row: &PgRow,
) -> Result<WorkflowRuntimePolicyRevision, WorkflowRuntimePolicyStoreError> {
    let value: i64 = row.try_get("policy_revision").map_err(operation_error)?;
    u64::try_from(value)
        .ok()
        .and_then(|value| WorkflowRuntimePolicyRevision::new(value).ok())
        .ok_or_else(|| {
            StoreError::corrupt_data("workflow runtime policy revision is invalid").into()
        })
}

fn decode_digest(
    row: &PgRow,
    column: &str,
) -> Result<Sha256Digest, WorkflowRuntimePolicyStoreError> {
    let value: Vec<u8> = row.try_get(column).map_err(operation_error)?;
    decode_digest_value(value)
}

fn decode_digest_value(value: Vec<u8>) -> Result<Sha256Digest, WorkflowRuntimePolicyStoreError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| StoreError::corrupt_data("workflow runtime policy digest is invalid"))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn operating_system_name(value: &OperatingSystem) -> &'static str {
    match value {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Windows => "windows",
        OperatingSystem::Macos => "macos",
        OperatingSystem::Other(_) => "invalid",
    }
}

fn architecture_name(value: &Architecture) -> &'static str {
    match value {
        Architecture::X86_64 => "x86_64",
        Architecture::Aarch64 => "aarch64",
        Architecture::Other(_) => "invalid",
    }
}

fn count_i32(value: usize) -> Result<i32, WorkflowRuntimePolicyStoreError> {
    i32::try_from(value)
        .map_err(|_| StoreError::corrupt_data("workflow runtime policy count overflow").into())
}

fn exact_one(rows: u64, operation: &'static str) -> Result<(), WorkflowRuntimePolicyStoreError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(StoreError::corrupt_data(operation).into())
    }
}

fn operation_error(error: sqlx::Error) -> WorkflowRuntimePolicyStoreError {
    StoreError::operation(error).into()
}

fn corrupt_value(error: impl std::fmt::Display) -> WorkflowRuntimePolicyStoreError {
    let _ = error;
    StoreError::corrupt_data("workflow runtime policy value is invalid").into()
}
