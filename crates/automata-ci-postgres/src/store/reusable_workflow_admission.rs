use automata_ci_core::{InvocationInputType, OutputSensitivity, PermissionLevel};
use sqlx::Row as _;
use sqlx::{Postgres, Transaction};

use super::durable_schema::current_durable_schemas;

use automata_ci_store::{
    AdmitLogicalWorkflowRun, AdmittedReusableInvocation, AdmittedReusableWorkflowExpansion,
    JobEnvironmentRequirement, LogicalWorkflowAdmissionStoreError, StoreError,
};

pub(super) async fn insert_reusable_workflow_expansion(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    expansion: &AdmittedReusableWorkflowExpansion,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let schemas = current_durable_schemas();
    let catalog_count = count_i32(expansion.catalog().len())?;
    let invocation_count = count_i32(expansion.invocations().len())?;
    let job_count = count_i32(expansion.job_count())?;
    sqlx::query(
        r"
        INSERT INTO logical_workflow_reusable_workflow_runs (
            tenant_id, repository_id, run_id, root_invocation_id,
            expansion_digest, catalog_entry_count, invocation_count,
            expanded_job_count, maximum_depth, planned_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.repository().id().as_uuid())
    .bind(command.run_id().as_uuid())
    .bind(command.root_invocation_id().as_uuid())
    .bind(expansion.digest().as_bytes().as_slice())
    .bind(catalog_count)
    .bind(invocation_count)
    .bind(job_count)
    .bind(i16::try_from(expansion.maximum_depth()).map_err(|_| corrupt("reusable depth"))?)
    .bind(command.admitted_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;

    for entry in expansion.catalog() {
        sqlx::query(
            r"
            INSERT INTO logical_workflow_reusable_workflow_catalog (
                run_id, catalog_entry_id, workflow_path, source_revision,
                source_digest, source_object_key, source_size_bytes,
                source_media_type, plan_digest, plan_object_key,
                plan_size_bytes, plan_media_type, plan_schema,
                invocation_contract_digest, descriptor_digest,
                logical_job_count, reusable_call_count, created_at_ms
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$18,$13,$14,$15,$16,$17
            )
            ",
        )
        .bind(command.run_id().as_uuid())
        .bind(entry.id().as_uuid())
        .bind(entry.workflow_path())
        .bind(entry.source_revision())
        .bind(entry.source().digest().as_bytes().as_slice())
        .bind(entry.source().object_key().as_str())
        .bind(size_i64(entry.source().encoded_size())?)
        .bind(entry.source().media_type())
        .bind(entry.plan().digest().as_bytes().as_slice())
        .bind(entry.plan().object_key().as_str())
        .bind(size_i64(entry.plan().encoded_size())?)
        .bind(entry.plan().media_type())
        .bind(
            entry
                .invocation_contract_digest()
                .map(|digest| digest.as_bytes().to_vec()),
        )
        .bind(entry.descriptor_digest().as_bytes().as_slice())
        .bind(i32::from(entry.logical_job_count()))
        .bind(i32::from(entry.reusable_call_count()))
        .bind(command.admitted_at().get())
        .bind(schemas.workflow_plan_i16)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }

    for invocation in expansion.invocations() {
        insert_invocation(transaction, command, invocation).await?;
    }
    Ok(())
}

pub(super) async fn validate_reusable_workflow_expansion_replay(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let row = sqlx::query(
        r"
        SELECT expansion_digest, catalog_entry_count, invocation_count,
               expanded_job_count, maximum_depth
        FROM logical_workflow_reusable_workflow_runs
        WHERE run_id = $1 AND root_invocation_id = $2
        FOR SHARE
        ",
    )
    .bind(command.run_id().as_uuid())
    .bind(command.root_invocation_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    match (command.reusable_workflows(), row) {
        (None, None) => Ok(()),
        (Some(expansion), Some(row))
            if row
                .try_get::<Vec<u8>, _>("expansion_digest")
                .map_err(operation_error)?
                .as_slice()
                == expansion.digest().as_bytes()
                && row
                    .try_get::<i32, _>("catalog_entry_count")
                    .map_err(operation_error)?
                    == count_i32(expansion.catalog().len())?
                && row
                    .try_get::<i32, _>("invocation_count")
                    .map_err(operation_error)?
                    == count_i32(expansion.invocations().len())?
                && row
                    .try_get::<i32, _>("expanded_job_count")
                    .map_err(operation_error)?
                    == count_i32(expansion.job_count())?
                && row
                    .try_get::<i16, _>("maximum_depth")
                    .map_err(operation_error)?
                    == i16::try_from(expansion.maximum_depth())
                        .map_err(|_| corrupt("reusable depth"))? =>
        {
            Ok(())
        }
        _ => Err(corrupt(
            "reusable expansion replay disagrees with its receipt",
        )),
    }
}

async fn insert_invocation(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    invocation: &AdmittedReusableInvocation,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    insert_invocation_descriptor(transaction, command, invocation).await?;
    insert_invocation_contract(transaction, command, invocation).await?;
    insert_invocation_jobs(transaction, command, invocation).await
}

async fn insert_invocation_descriptor(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    invocation: &AdmittedReusableInvocation,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    sqlx::query(
        r"
        INSERT INTO logical_workflow_reusable_invocation_expansions (
            run_id, invocation_id, parent_invocation_id, caller_logical_job_id,
            catalog_entry_id, depth, call_path, workflow_path, source_digest,
            plan_digest, call_reference_digest, input_bindings_digest,
            secret_bindings_digest, output_contract_digest, permission_digest,
            descriptor_digest, input_binding_count, secret_binding_count,
            output_count, permission_grant_count, dependency_count, created_at_ms
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
            $17,$18,$19,$20,$21,$22
        )
        ",
    )
    .bind(command.run_id().as_uuid())
    .bind(invocation.id().as_uuid())
    .bind(
        invocation
            .parent_id()
            .map(automata_ci_store::LogicalWorkflowInvocationId::as_uuid),
    )
    .bind(
        invocation
            .caller_job_id()
            .map(automata_ci_store::LogicalWorkflowJobId::as_uuid),
    )
    .bind(invocation.catalog_entry_id().as_uuid())
    .bind(i16::try_from(invocation.depth()).map_err(|_| corrupt("reusable depth"))?)
    .bind(invocation.call_path())
    .bind(invocation.workflow_path())
    .bind(invocation.source_digest().as_bytes().as_slice())
    .bind(invocation.plan_digest().as_bytes().as_slice())
    .bind(
        invocation
            .call_reference_digest()
            .map(|digest| digest.as_bytes().to_vec()),
    )
    .bind(invocation.input_bindings_digest().as_bytes().as_slice())
    .bind(invocation.secret_bindings_digest().as_bytes().as_slice())
    .bind(invocation.output_contract_digest().as_bytes().as_slice())
    .bind(invocation.permissions().digest().as_bytes().as_slice())
    .bind(invocation.descriptor_digest().as_bytes().as_slice())
    .bind(count_i32(invocation.inputs().len())?)
    .bind(count_i32(invocation.secrets().len())?)
    .bind(count_i32(invocation.outputs().len())?)
    .bind(count_i32(invocation.permissions().grants().len())?)
    .bind(count_i32(invocation.dependency_count())?)
    .bind(command.admitted_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
}

async fn insert_invocation_contract(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    invocation: &AdmittedReusableInvocation,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    for (source_order, input) in invocation.inputs().iter().enumerate() {
        sqlx::query(
            r"
            INSERT INTO logical_workflow_reusable_input_bindings (
                run_id, invocation_id, input_key, input_type, binding_kind,
                value_digest, source_order
            ) VALUES ($1,$2,$3,$4,$5,$6,$7)
            ",
        )
        .bind(command.run_id().as_uuid())
        .bind(invocation.id().as_uuid())
        .bind(input.key())
        .bind(input_type_name(input.input_type()))
        .bind(input.kind().as_str())
        .bind(
            input
                .value_digest()
                .map(|digest| digest.as_bytes().to_vec()),
        )
        .bind(count_i32(source_order)?)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    for (source_order, secret) in invocation.secrets().iter().enumerate() {
        sqlx::query(
            r"
            INSERT INTO logical_workflow_reusable_secret_bindings (
                run_id, invocation_id, target_name, source_name, source_order
            ) VALUES ($1,$2,$3,$4,$5)
            ",
        )
        .bind(command.run_id().as_uuid())
        .bind(invocation.id().as_uuid())
        .bind(secret.target())
        .bind(secret.source())
        .bind(count_i32(source_order)?)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    for (source_order, output) in invocation.outputs().iter().enumerate() {
        sqlx::query(
            r"
            INSERT INTO logical_workflow_reusable_outputs (
                run_id, invocation_id, output_key, sensitivity, source_order
            ) VALUES ($1,$2,$3,$4,$5)
            ",
        )
        .bind(command.run_id().as_uuid())
        .bind(invocation.id().as_uuid())
        .bind(output.key())
        .bind(sensitivity_name(output.sensitivity()))
        .bind(count_i32(source_order)?)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }

    let permissions = invocation.permissions();
    sqlx::query(
        r"
        INSERT INTO logical_workflow_reusable_permission_snapshots (
            run_id, invocation_id, default_level, permission_digest
        ) VALUES ($1,$2,$3,$4)
        ",
    )
    .bind(command.run_id().as_uuid())
    .bind(invocation.id().as_uuid())
    .bind(permission_level_name(permissions.default_level()))
    .bind(permissions.digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    for (name, level) in permissions.grants() {
        sqlx::query(
            r"
            INSERT INTO logical_workflow_reusable_permission_grants (
                run_id, invocation_id, permission_name, permission_level
            ) VALUES ($1,$2,$3,$4)
            ",
        )
        .bind(command.run_id().as_uuid())
        .bind(invocation.id().as_uuid())
        .bind(name)
        .bind(permission_level_name(*level))
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    Ok(())
}

async fn insert_invocation_jobs(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    invocation: &AdmittedReusableInvocation,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let schemas = current_durable_schemas();
    for job in invocation.jobs() {
        sqlx::query(
            r"
            INSERT INTO logical_workflow_reusable_expanded_jobs (
                run_id, invocation_id, logical_job_id, logical_key,
                source_order, execution_kind, descriptor_digest,
                environment_requirement_kind, environment_template_digest,
                secret_reference_names, variable_reference_names,
                credential_requirements_schema
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            ",
        )
        .bind(command.run_id().as_uuid())
        .bind(invocation.id().as_uuid())
        .bind(job.id().as_uuid())
        .bind(job.key().as_str())
        .bind(i32::from(job.source_order()))
        .bind(if job.is_reusable() {
            "reusable_workflow"
        } else {
            "steps"
        })
        .bind(job.descriptor_digest().as_bytes().as_slice())
        .bind(job_environment_requirement_name(
            job.credential_requirements().environment(),
        ))
        .bind(
            job.credential_requirements()
                .environment()
                .template_digest()
                .map(|digest| digest.as_bytes().as_slice().to_vec()),
        )
        .bind(job.credential_requirements().secret_names())
        .bind(job.credential_requirements().variable_names())
        .bind(schemas.runner_requirements_i16)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    for job in invocation.jobs() {
        for prerequisite in job.prerequisites() {
            sqlx::query(
                r"
                INSERT INTO logical_workflow_reusable_expanded_dependencies (
                    run_id, invocation_id, logical_job_id, prerequisite_job_id
                ) VALUES ($1,$2,$3,$4)
                ",
            )
            .bind(command.run_id().as_uuid())
            .bind(invocation.id().as_uuid())
            .bind(job.id().as_uuid())
            .bind(prerequisite.as_uuid())
            .execute(&mut **transaction)
            .await
            .map_err(operation_error)?;
        }
    }
    Ok(())
}

fn count_i32(value: usize) -> Result<i32, LogicalWorkflowAdmissionStoreError> {
    i32::try_from(value).map_err(|_| corrupt("reusable expansion count"))
}

const fn input_type_name(value: InvocationInputType) -> &'static str {
    match value {
        InvocationInputType::Boolean => "boolean",
        InvocationInputType::Number => "number",
        InvocationInputType::String => "string",
    }
}

const fn permission_level_name(value: PermissionLevel) -> &'static str {
    match value {
        PermissionLevel::None => "none",
        PermissionLevel::Read => "read",
        PermissionLevel::Write => "write",
    }
}

const fn sensitivity_name(value: OutputSensitivity) -> &'static str {
    match value {
        OutputSensitivity::Public => "public",
        OutputSensitivity::SecretDerived => "secret_derived",
    }
}

const fn job_environment_requirement_name(value: JobEnvironmentRequirement) -> &'static str {
    match value {
        JobEnvironmentRequirement::None => "none",
        JobEnvironmentRequirement::Environment(_) => "environment",
    }
}

fn size_i64(value: u64) -> Result<i64, LogicalWorkflowAdmissionStoreError> {
    i64::try_from(value).map_err(|_| corrupt("reusable object size"))
}

fn corrupt(message: &'static str) -> LogicalWorkflowAdmissionStoreError {
    StoreError::corrupt_data(message).into()
}

fn operation_error(error: sqlx::Error) -> LogicalWorkflowAdmissionStoreError {
    StoreError::operation(error).into()
}
