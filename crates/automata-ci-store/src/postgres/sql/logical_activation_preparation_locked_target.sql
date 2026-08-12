SELECT job.logical_key, job.source_order, job.created_at_ms,
       manifest.authority_profile,
       manifest.runner_policy_digest,
       manifest.runner_policy_object_key,
       manifest.runner_policy_size_bytes,
       manifest.runner_policy_media_type,
       run.workflow_id, run.workflow_name, run.git_ref, run.event_name,
       run.actor,
       run.triggering_actor,
       run.public_run_id_alias AS run_id_alias,
       run.run_number, run.run_attempt,
       invocation.plan_digest, invocation.plan_object_key,
       invocation.plan_size_bytes, invocation.plan_media_type,
       run.event_digest, run.event_object_key, run.event_size_bytes,
       run.event_media_type,
       CASE WHEN invocation.invocation_kind = 'root'
            THEN marker.base_context_digest
            ELSE reusable_call.runtime_context_digest
       END AS base_context_digest,
       CASE WHEN invocation.invocation_kind = 'root'
            THEN marker.base_context_object_key
            ELSE reusable_call.runtime_context_object_key
       END AS base_context_object_key,
       CASE WHEN invocation.invocation_kind = 'root'
            THEN marker.base_context_size_bytes
            ELSE reusable_call.runtime_context_size_bytes
       END AS base_context_size_bytes,
       CASE WHEN invocation.invocation_kind = 'root'
            THEN marker.base_context_media_type
            ELSE reusable_call.runtime_context_media_type
       END AS base_context_media_type,
       CASE WHEN invocation.invocation_kind = 'root'
            THEN marker.base_context_schema
            ELSE reusable_call.runtime_context_schema
       END AS base_context_schema,
       claim.logical_job_id AS durable_logical_job_id,
       claim.run_id AS durable_run_id,
       claim.invocation_id AS durable_invocation_id,
       claim.descriptor_digest AS durable_descriptor_digest,
       claim.logical_key AS durable_logical_key,
       claim.source_order AS durable_source_order,
       claim.authority_profile AS durable_authority_profile,
       claim.runtime_policy_revision AS durable_runtime_policy_revision,
       claim.runtime_policy_digest AS durable_runtime_policy_digest,
       claim.runner_policy_digest AS durable_runner_policy_digest,
       claim.runner_policy_object_key AS durable_runner_policy_object_key,
       claim.runner_policy_size_bytes AS durable_runner_policy_size_bytes,
       claim.runner_policy_media_type AS durable_runner_policy_media_type,
       claim.workflow_id AS durable_workflow_id,
       claim.workflow_name AS durable_workflow_name,
       claim.git_ref AS durable_git_ref,
       run.event_name AS durable_event_name,
       claim.actor AS durable_actor,
       run.triggering_actor AS durable_triggering_actor,
       run.public_run_id_alias AS durable_run_id_alias,
       claim.run_number AS durable_run_number,
       claim.run_attempt AS durable_run_attempt,
       claim.plan_digest AS durable_plan_digest,
       claim.plan_object_key AS durable_plan_object_key,
       claim.plan_size_bytes AS durable_plan_size_bytes,
       claim.plan_media_type AS durable_plan_media_type,
       claim.plan_schema AS durable_plan_schema,
       claim.event_digest AS durable_event_digest,
       claim.event_object_key AS durable_event_object_key,
       claim.event_size_bytes AS durable_event_size_bytes,
       claim.event_media_type AS durable_event_media_type,
       claim.base_context_kind AS durable_base_context_kind,
       claim.base_context_digest AS durable_base_context_digest,
       claim.base_context_object_key AS durable_base_context_object_key,
       claim.base_context_size_bytes AS durable_base_context_size_bytes,
       claim.base_context_media_type AS durable_base_context_media_type,
       claim.base_context_schema AS durable_base_context_schema,
       claim.workspace AS durable_workspace,
       claim.prerequisite_count AS durable_prerequisite_count,
       claim.prerequisites_digest AS durable_prerequisites_digest,
       claim.aggregate_status AS durable_aggregate_status,
       claim.evidence_ready_at_ms AS durable_evidence_ready_at_ms,
       claim.state AS durable_state, claim.owner_id AS durable_owner_id,
       claim.generation AS durable_generation,
       claim.claimed_at_ms AS durable_claimed_at_ms,
       claim.expires_at_ms AS durable_expires_at_ms,
       claim.origin_selection_id AS durable_origin_selection_id
FROM workflow_plan_v2_jobs AS job
JOIN workflow_plan_v2_invocations AS invocation
  ON invocation.run_id = job.run_id AND invocation.id = job.invocation_id
JOIN workflow_plan_v2_runs AS marker ON marker.run_id = job.run_id
LEFT JOIN workflow_plan_v2_reusable_call_publications AS reusable_call
  ON reusable_call.run_id = invocation.run_id
 AND reusable_call.child_invocation_id = invocation.id
 AND reusable_call.child_graph_sealed_at_ms IS NOT NULL
JOIN workflow_runs AS run ON run.id = marker.run_id
JOIN repositories AS repository ON repository.id = run.repository_id
JOIN github_workflow_run_manifest_origins AS origin
  ON origin.tenant_id = repository.tenant_id
 AND origin.repository_id = run.repository_id
 AND origin.workflow_id = run.workflow_id
 AND origin.snapshot_id = run.snapshot_id
 AND origin.run_id = run.id
JOIN github_provider_manifest_revisions AS manifest
  ON manifest.tenant_id = origin.tenant_id
 AND manifest.repository_id = origin.repository_id
 AND manifest.provider_connection_id = origin.provider_connection_id
 AND manifest.manifest_revision = origin.provider_manifest_revision
 AND manifest.manifest_digest = origin.provider_manifest_digest
LEFT JOIN workflow_plan_v2_activation_preparation_claims AS claim
  ON claim.logical_job_id = job.id
WHERE repository.tenant_id = $1
  AND job.run_id = $2 AND job.invocation_id = $3 AND job.id = $4
  AND job.execution_kind = $5
  AND automata_workflow_plan_v2_invocation_published(
      marker.run_id, invocation.id
  )
  AND invocation.plan_schema = 2
  AND invocation.plan_media_type =
      'application/vnd.automata.workflow-plan+json'
  AND invocation.state IN ('pending', 'active')
  AND marker.orchestration_schema = 1
  AND marker.base_context_schema = 2
  AND marker.state IN ('pending', 'active')
  AND run.admission_epoch = 4 AND run.plan_schema = 2
  AND run.event_media_type = 'application/json'
  AND (job.state = 'pending' OR claim.state = 'prepared')
FOR UPDATE OF job
