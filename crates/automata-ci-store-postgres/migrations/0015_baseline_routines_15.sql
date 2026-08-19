-- Canonical greenfield schema stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_validate_logical_workflow_job_result_instance() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_job_results AS logical_result
        JOIN logical_workflow_job_result_claims AS logical_claim
          ON logical_claim.logical_job_id = logical_result.logical_job_id
        JOIN logical_workflow_instance_results AS instance_result
          ON instance_result.logical_job_id = logical_result.logical_job_id
         AND instance_result.instance_id = NEW.instance_id
        JOIN logical_workflow_instances AS instance
          ON instance.id = instance_result.instance_id
         AND instance.logical_job_id = instance_result.logical_job_id
        JOIN logical_workflow_instance_result_claims AS instance_claim
          ON instance_claim.instance_id = instance_result.instance_id
        WHERE logical_result.logical_job_id = NEW.logical_job_id
          AND logical_claim.state = 'aggregating'
          AND logical_result.claim_owner_id = logical_claim.owner_id
          AND logical_result.claim_generation = logical_claim.generation
          AND instance.matrix_index = NEW.matrix_index
          AND instance_result.terminal_ordinal = NEW.terminal_ordinal
          AND instance_result.descriptor_digest = NEW.instance_descriptor_digest
          AND instance_result.outputs_digest = NEW.instance_outputs_digest
          AND instance_result.commit_digest = NEW.instance_commit_digest
          AND instance_result.raw_conclusion = NEW.raw_conclusion
          AND instance_result.effective_conclusion = NEW.effective_conclusion
          AND instance_claim.state = 'finalized'
    ) AND NOT EXISTS (
        SELECT 1
        FROM logical_workflow_job_results AS logical_result
        JOIN logical_workflow_job_result_claims AS logical_claim
          ON logical_claim.logical_job_id = logical_result.logical_job_id
        JOIN logical_workflow_reusable_call_results AS call_result
          ON call_result.run_id = logical_result.run_id
         AND call_result.parent_invocation_id = logical_result.invocation_id
         AND call_result.caller_logical_job_id = logical_result.logical_job_id
        JOIN logical_workflow_reusable_call_publications AS publication
          ON publication.run_id = call_result.run_id
         AND publication.parent_invocation_id = call_result.parent_invocation_id
         AND publication.caller_logical_job_id = call_result.caller_logical_job_id
        WHERE logical_result.logical_job_id = NEW.logical_job_id
          AND logical_claim.state = 'aggregating'
          AND logical_result.claim_owner_id = logical_claim.owner_id
          AND logical_result.claim_generation = logical_claim.generation
          AND publication.condition_matched
          AND call_result.sealed_at_ms IS NOT NULL
          AND call_result.caller_instance_id = NEW.instance_id
          AND NEW.matrix_index = 0
          AND NEW.terminal_ordinal = 1
          AND call_result.descriptor_digest = NEW.instance_descriptor_digest
          AND call_result.outputs_digest = NEW.instance_outputs_digest
          AND call_result.commit_digest = NEW.instance_commit_digest
          AND call_result.effective_conclusion = NEW.raw_conclusion
          AND call_result.effective_conclusion = NEW.effective_conclusion
    ) THEN
        RAISE EXCEPTION 'logical workflow logical result instance evidence is not exact'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_job_result_output() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_job_results AS logical_result
        JOIN logical_workflow_job_result_claims AS claim
          ON claim.logical_job_id = logical_result.logical_job_id
        JOIN logical_workflow_jobs AS job
          ON job.run_id = logical_result.run_id
         AND job.invocation_id = logical_result.invocation_id
         AND job.id = logical_result.logical_job_id
        WHERE logical_result.logical_job_id = NEW.logical_job_id
          AND claim.state = 'aggregating'
          AND logical_result.claim_owner_id = claim.owner_id
          AND logical_result.claim_generation = claim.generation
          AND logical_result.claim_started_at_ms = claim.claimed_at_ms
          AND logical_result.claim_expires_at_ms = claim.expires_at_ms
          AND (
              job.execution_kind = 'steps'
              OR (
                  job.execution_kind = 'reusable_workflow'
                  AND EXISTS (
                      SELECT 1
                      FROM logical_workflow_reusable_call_output_mappings AS mapping
                      JOIN logical_workflow_reusable_call_results AS call_result
                        ON call_result.run_id = mapping.run_id
                       AND call_result.child_invocation_id =
                           mapping.child_invocation_id
                       AND call_result.parent_invocation_id = job.invocation_id
                       AND call_result.caller_logical_job_id = job.id
                       AND call_result.sealed_at_ms IS NOT NULL
                      JOIN logical_workflow_reusable_call_result_outputs AS child_output
                        ON child_output.run_id = call_result.run_id
                       AND child_output.parent_invocation_id =
                           call_result.parent_invocation_id
                       AND child_output.caller_logical_job_id =
                           call_result.caller_logical_job_id
                       AND child_output.callee_output_name =
                           mapping.child_output_name
                      WHERE mapping.run_id = job.run_id
                        AND mapping.parent_output_name = NEW.output_name
                        AND mapping.sensitivity = NEW.sensitivity
                        AND NEW.public_value IS NOT DISTINCT FROM CASE
                            WHEN mapping.sensitivity = 'public'
                            THEN child_output.public_value
                            ELSE NULL
                        END
                  )
              )
          )
    ) THEN
        RAISE EXCEPTION 'logical workflow logical output lacks exact result evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_job_result_prerequisite() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_job_results AS logical_result
        JOIN logical_workflow_job_result_claims AS logical_claim
          ON logical_claim.logical_job_id = logical_result.logical_job_id
        JOIN logical_workflow_dependencies AS dependency
          ON dependency.logical_job_id = logical_result.logical_job_id
         AND dependency.run_id = logical_result.run_id
         AND dependency.invocation_id = logical_result.invocation_id
         AND dependency.prerequisite_job_id = NEW.prerequisite_job_id
        JOIN logical_workflow_jobs AS prerequisite_job
          ON prerequisite_job.id = dependency.prerequisite_job_id
        JOIN logical_workflow_effective_job_results AS prerequisite
          ON prerequisite.run_id = dependency.run_id
         AND prerequisite.invocation_id = dependency.invocation_id
         AND prerequisite.logical_job_id = dependency.prerequisite_job_id
         AND prerequisite.claim_state = 'finalized'
        WHERE logical_result.logical_job_id = NEW.logical_job_id
          AND logical_claim.state = 'aggregating'
          AND prerequisite_job.source_order = NEW.prerequisite_source_order
          AND prerequisite.commit_digest = NEW.prerequisite_commit_digest
          AND prerequisite.outputs_digest = NEW.prerequisite_outputs_digest
          AND prerequisite.effective_conclusion = NEW.effective_conclusion
          AND prerequisite.closure_has_failure = NEW.closure_has_failure
          AND prerequisite.closure_has_cancelled = NEW.closure_has_cancelled
          AND prerequisite.closure_has_skipped = NEW.closure_has_skipped
    ) THEN
        RAISE EXCEPTION 'logical workflow prerequisite closure evidence is not exact'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_job_result_quarantine() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    current_due logical_workflow_job_result_due%ROWTYPE;
BEGIN
    SELECT due.* INTO current_due
    FROM logical_workflow_job_result_due AS due
    WHERE due.logical_job_id = NEW.logical_job_id
    FOR UPDATE;
    IF NOT FOUND OR ROW(
        NEW.tenant_id, NEW.run_id, NEW.invocation_id, NEW.source_order,
        NEW.ready_at_ms, NEW.available_at_ms
    ) IS DISTINCT FROM ROW(
        current_due.tenant_id, current_due.run_id, current_due.invocation_id,
        current_due.source_order, current_due.ready_at_ms,
        current_due.available_at_ms
    ) THEN
        RAISE EXCEPTION 'job-result quarantine lacks its exact current due target'
            USING ERRCODE = '23514',
                  CONSTRAINT =
                      'logical_workflow_job_result_quarantines_due_exact';
    END IF;

    IF NEW.claim_owner_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM logical_workflow_job_result_claims AS claim
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.state = 'aggregating'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_claimed_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND claim.descriptor_digest = NEW.claim_descriptor_digest
    ) THEN
        RAISE EXCEPTION 'job-result quarantine lacks its exact live claim'
            USING ERRCODE = '23514',
                  CONSTRAINT =
                      'logical_workflow_job_result_quarantines_claim_exact';
    END IF;

    NEW.quarantined_at_ms :=
        floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_materialization_claim() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_instances AS instance
        JOIN logical_workflow_activation_publications AS publication
          ON publication.run_id = instance.run_id
         AND publication.invocation_id = instance.invocation_id
         AND publication.logical_job_id = instance.logical_job_id
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = instance.run_id
         AND logical_job.invocation_id = instance.invocation_id
         AND logical_job.id = instance.logical_job_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = logical_job.run_id
         AND invocation.id = logical_job.invocation_id
        JOIN logical_workflow_runs AS marker
          ON marker.run_id = instance.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE instance.id = NEW.instance_id
          AND instance.run_id = NEW.run_id
          AND instance.invocation_id = NEW.invocation_id
          AND instance.logical_job_id = NEW.logical_job_id
          AND instance.job_ir_version = 1
          AND instance.job_ir_media_type =
              'application/vnd.automata.job-ir.protobuf'
          AND instance.runtime_context_schema = 1
          AND instance.runtime_context_media_type =
              'application/vnd.automata.job-runtime-context.protobuf'
          AND publication.condition_matched
          AND publication.instance_count > 0
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND invocation.plan_schema = 1
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 1
          AND run.plan_schema = 1
    ) THEN
        RAISE EXCEPTION 'logical workflow materialization lacks an activated current instance'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_root() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.invocation_kind = 'root' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM logical_workflow_runs AS marker
            JOIN workflow_runs AS run ON run.id = marker.run_id
            WHERE marker.run_id = NEW.run_id
              AND marker.root_invocation_id = NEW.id
              AND run.admission_epoch = 1
              AND run.plan_schema = 1
              AND run.plan_digest = NEW.plan_digest
              AND run.plan_object_key = NEW.plan_object_key
              AND run.plan_size_bytes = NEW.plan_size_bytes
              AND run.plan_media_type = NEW.plan_media_type
              AND run.created_at_ms = NEW.created_at_ms
        ) THEN
            RAISE EXCEPTION 'logical workflow root descriptor does not match its admitted run'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'logical_workflow_invocation_root_exact';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS expansion
        JOIN logical_workflow_reusable_workflow_catalog AS catalog
          ON catalog.run_id = expansion.run_id
         AND catalog.catalog_entry_id = expansion.catalog_entry_id
        WHERE expansion.run_id = NEW.run_id
          AND expansion.invocation_id = NEW.id
          AND expansion.depth > 0
          AND catalog.plan_digest = NEW.plan_digest
          AND catalog.plan_object_key = NEW.plan_object_key
          AND catalog.plan_size_bytes = NEW.plan_size_bytes
          AND catalog.plan_media_type = NEW.plan_media_type
          AND catalog.plan_schema = NEW.plan_schema
    ) THEN
        RAISE EXCEPTION 'logical workflow reusable invocation lacks exact planned evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_invocation_plan_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_run_result() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_run_result_claims AS claim
        JOIN logical_workflow_runs AS marker ON marker.run_id = claim.run_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE claim.run_id = NEW.run_id
          AND claim.root_invocation_id = NEW.root_invocation_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.state = 'aggregating'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND marker.root_invocation_id = NEW.root_invocation_id
          AND marker.admission_digest = NEW.admission_digest
          AND marker.state = NEW.marker_state
          AND marker.revision = NEW.marker_revision
          AND marker.updated_at_ms = NEW.marker_updated_at_ms
          AND invocation.state = NEW.invocation_state
          AND invocation.revision = NEW.invocation_revision
          AND invocation.updated_at_ms = NEW.invocation_updated_at_ms
          AND run.status = NEW.workflow_status
          AND run.updated_at_ms = NEW.workflow_updated_at_ms
          AND NEW.job_count = (
              SELECT count(*)::INTEGER
              FROM logical_workflow_jobs AS job
              WHERE job.run_id = NEW.run_id
                AND job.invocation_id = NEW.root_invocation_id
          )
          AND NEW.finalized_at_ms >= greatest(
              NEW.marker_updated_at_ms,
              NEW.invocation_updated_at_ms,
              NEW.workflow_updated_at_ms,
              COALESCE((
                  SELECT max(result.finalized_at_ms)
                  FROM logical_workflow_effective_job_results AS result
                  WHERE result.run_id = NEW.run_id
                    AND result.invocation_id = NEW.root_invocation_id
              ), 0)
          )
          AND NEW.finalized_at_ms < claim.expires_at_ms
    ) THEN
        RAISE EXCEPTION 'logical workflow run result lacks exact descriptor/fence evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_run_result_claim() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.state <> 'aggregating' THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_runs AS marker
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE marker.run_id = NEW.run_id
          AND marker.root_invocation_id = NEW.root_invocation_id
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND marker.revision < 9223372036854775807
          AND invocation.plan_schema = 1
          AND invocation.state IN ('pending', 'active')
          AND invocation.revision < 9223372036854775807
          AND run.admission_epoch = 1
          AND run.plan_schema = 1
          AND run.status IN ('queued', 'in_progress', 'cancelled')
          AND NEW.claimed_at_ms >= greatest(
              marker.updated_at_ms,
              invocation.updated_at_ms,
              run.updated_at_ms,
              COALESCE((
                  SELECT max(result.finalized_at_ms)
                  FROM logical_workflow_effective_job_results AS result
                  WHERE result.run_id = marker.run_id
                    AND result.invocation_id = marker.root_invocation_id
              ), 0)
          )
          AND (SELECT count(*)
               FROM logical_workflow_jobs AS job
               WHERE job.run_id = marker.run_id
                 AND job.invocation_id = marker.root_invocation_id)
              BETWEEN 1 AND 1024
          AND NOT EXISTS (
              SELECT 1
              FROM logical_workflow_jobs AS job
              LEFT JOIN logical_workflow_effective_job_results AS result
                ON result.run_id = job.run_id
               AND result.invocation_id = job.invocation_id
               AND result.logical_job_id = job.id
              WHERE job.run_id = marker.run_id
                AND job.invocation_id = marker.root_invocation_id
                AND (
                    result.logical_job_id IS NULL
                    OR result.claim_state IS DISTINCT FROM 'finalized'
                    OR result.logical_key IS DISTINCT FROM job.logical_key
                    OR result.source_order IS DISTINCT FROM job.source_order
                    OR job.state IS DISTINCT FROM CASE result.effective_conclusion
                        WHEN 'success' THEN 'completed'
                        WHEN 'failure' THEN 'failed'
                        WHEN 'timed_out' THEN 'failed'
                        WHEN 'cancelled' THEN 'cancelled'
                        WHEN 'skipped' THEN 'skipped'
                    END
                    OR result.prerequisite_count IS DISTINCT FROM (
                        SELECT count(*)::INTEGER
                        FROM logical_workflow_dependencies AS dependency
                        WHERE dependency.run_id = job.run_id
                          AND dependency.invocation_id = job.invocation_id
                          AND dependency.logical_job_id = job.id
                    )
                )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM (
                  SELECT job.source_order,
                         row_number() OVER (ORDER BY job.source_order) - 1 AS expected_order
                  FROM logical_workflow_jobs AS job
                  WHERE job.run_id = marker.run_id
                    AND job.invocation_id = marker.root_invocation_id
              ) AS ordered
              WHERE ordered.source_order <> ordered.expected_order
          )
    ) THEN
        RAISE EXCEPTION 'logical workflow run-result claim is not exactly ready'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_run_result_job() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_run_results AS run_result
        JOIN logical_workflow_run_result_claims AS run_claim
          ON run_claim.run_id = run_result.run_id
        JOIN logical_workflow_jobs AS job
          ON job.run_id = run_result.run_id
         AND job.invocation_id = run_result.root_invocation_id
         AND job.id = NEW.logical_job_id
        JOIN logical_workflow_effective_job_results AS logical_result
          ON logical_result.run_id = job.run_id
         AND logical_result.invocation_id = job.invocation_id
         AND logical_result.logical_job_id = job.id
        WHERE run_result.run_id = NEW.run_id
          AND run_result.root_invocation_id = NEW.root_invocation_id
          AND run_claim.state = 'aggregating'
          AND job.logical_key = NEW.logical_key
          AND job.source_order = NEW.source_order
          AND logical_result.claim_state = 'finalized'
          AND logical_result.descriptor_digest = NEW.descriptor_digest
          AND logical_result.effective_conclusion = NEW.effective_conclusion
          AND logical_result.closure_has_failure = NEW.closure_has_failure
          AND logical_result.closure_has_cancelled = NEW.closure_has_cancelled
          AND logical_result.closure_has_skipped = NEW.closure_has_skipped
          AND logical_result.instance_count = NEW.instance_count
          AND logical_result.instances_digest = NEW.instances_digest
          AND logical_result.prerequisite_count = NEW.prerequisite_count
          AND logical_result.prerequisites_digest = NEW.prerequisites_digest
          AND logical_result.output_count = NEW.output_count
          AND logical_result.outputs_digest = NEW.outputs_digest
          AND logical_result.commit_digest = NEW.job_commit_digest
          AND logical_result.finalized_at_ms = NEW.job_finalized_at_ms
    ) THEN
        RAISE EXCEPTION 'logical workflow run-result job evidence is not exact'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_workflow_rerun_attempt_lineage() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_runs AS run
        JOIN workflow_runs AS root ON root.id = NEW.root_run_id
        JOIN workflow_runs AS source_run
          ON source_run.id = COALESCE(NEW.source_run_id, NEW.run_id)
        JOIN logical_workflow_runs AS source_marker
          ON source_marker.run_id = source_run.id
        LEFT JOIN workflow_rerun_attempts AS source
          ON source.run_id = NEW.source_run_id
        WHERE run.id = NEW.run_id
          AND run.run_attempt = NEW.attempt
          AND run.created_at_ms = NEW.created_at_ms
          AND run.workflow_id = root.workflow_id
          AND run.public_run_id_alias = root.public_run_id_alias
          AND run.run_number = root.run_number
          AND root.run_attempt = 1
          AND run.repository_id = source_run.repository_id
          AND source_run.workflow_id = root.workflow_id
          AND source_run.public_run_id_alias = root.public_run_id_alias
          AND run.snapshot_id = source_run.snapshot_id
          AND run.run_number = source_run.run_number
          AND run.event_name = source_run.event_name
          AND run.event_object_key = source_run.event_object_key
          AND run.head_sha = source_run.head_sha
          AND run.concurrency_group_key IS NOT DISTINCT FROM
              source_run.concurrency_group_key
          AND run.concurrency_queue_policy IS NOT DISTINCT FROM
              source_run.concurrency_queue_policy
          AND run.concurrency_cancel_in_progress IS NOT DISTINCT FROM
              source_run.concurrency_cancel_in_progress
          AND (
              run.concurrency_group_key IS NULL
              AND run.concurrency_queue_policy IS NULL
              AND run.concurrency_cancel_in_progress IS NULL
              OR run.concurrency_group_key IS NOT NULL
              AND run.concurrency_queue_policy IS NOT NULL
              AND run.concurrency_cancel_in_progress IS NOT NULL
          )
          AND run.admission_epoch = source_run.admission_epoch
          AND run.event_digest = source_run.event_digest
          AND run.event_size_bytes = source_run.event_size_bytes
          AND run.event_media_type = source_run.event_media_type
          AND run.plan_digest = source_run.plan_digest
          AND run.plan_object_key = source_run.plan_object_key
          AND run.plan_size_bytes = source_run.plan_size_bytes
          AND run.plan_media_type = source_run.plan_media_type
          AND run.plan_schema = source_run.plan_schema
          AND run.workflow_name IS NOT DISTINCT FROM source_run.workflow_name
          AND run.git_ref IS NOT DISTINCT FROM source_run.git_ref
          AND run.actor IS NOT DISTINCT FROM source_run.actor
          AND run.display_title IS NOT DISTINCT FROM source_run.display_title
          AND run.commit_subject IS NOT DISTINCT FROM source_run.commit_subject
          AND run.publication_policy_revision IS NOT DISTINCT FROM
              source_run.publication_policy_revision
          AND run.requested_dashboard_visibility IS NOT DISTINCT FROM
              source_run.requested_dashboard_visibility
          AND run.effective_dashboard_visibility IS NOT DISTINCT FROM
              source_run.effective_dashboard_visibility
          AND run.requested_log_visibility IS NOT DISTINCT FROM
              source_run.requested_log_visibility
          AND run.requested_artifact_visibility IS NOT DISTINCT FROM
              source_run.requested_artifact_visibility
          AND run.publication_safety_reason IS NOT DISTINCT FROM
              source_run.publication_safety_reason
          AND run.publication_safety_schema IS NOT DISTINCT FROM
              source_run.publication_safety_schema
          AND source_marker.admission_digest = NEW.source_admission_digest
          AND source_run.plan_digest = NEW.source_plan_digest
          AND source_run.event_digest = NEW.source_event_digest
          AND (
              NEW.attempt = 1
              AND NEW.run_id = NEW.root_run_id
              AND NEW.source_run_id IS NULL
              OR NEW.attempt > 1
              AND NEW.run_id <> NEW.root_run_id
              AND NEW.source_run_id IS NOT NULL
              AND source.root_run_id = NEW.root_run_id
              AND source.attempt < NEW.attempt
          )
    ) OR EXISTS (
        SELECT 1
        FROM generate_series(1, NEW.attempt) AS expected(attempt)
        WHERE NOT EXISTS (
            SELECT 1
            FROM workflow_rerun_attempts AS durable
            WHERE durable.root_run_id = NEW.root_run_id
              AND durable.attempt = expected.attempt
        )
    ) THEN
        RAISE EXCEPTION 'workflow rerun attempt lineage is not contiguous and exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_attempts_lineage_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_validate_workflow_rerun_audit_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_rerun_attempts AS attempt
        JOIN workflow_rerun_requests AS request
          ON request.tenant_id = NEW.tenant_id
         AND request.operation_id = NEW.operation_id
         AND request.rerun_run_id = attempt.run_id
         AND request.source_run_id = attempt.source_run_id
        JOIN security_audit_events AS audit
          ON audit.event_id = NEW.event_id
         AND audit.tenant_id = request.tenant_id
        WHERE attempt.run_id = NEW.run_id
          AND attempt.source_run_id IS NOT NULL
          AND request.request_digest = NEW.request_digest
          AND request.committed_at_ms = attempt.created_at_ms
          AND NEW.recorded_at_ms = attempt.created_at_ms
          AND audit.occurred_at_ms = attempt.created_at_ms
          AND audit.actor_kind = 'human'
          AND audit.actor_principal_id = request.actor_principal_id
          AND audit.actor_session_id = request.actor_session_id
          AND audit.authorization_revision = request.authorization_revision
          AND audit.action = 'workflow.rerun'
          AND audit.outcome = 'succeeded'
          AND audit.resource_kind = 'workflow_run'
          AND audit.resource_id = attempt.run_id::TEXT
    ) THEN
        RAISE EXCEPTION 'workflow rerun audit evidence is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_audit_evidence_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_workflow_rerun_carried_result_source() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    carried workflow_rerun_carried_job_results%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'workflow_rerun_carried_job_results' THEN
        carried := NEW;
    ELSE
        SELECT * INTO carried
        FROM workflow_rerun_carried_job_results
        WHERE logical_job_id = NEW.logical_job_id;
    END IF;

    IF carried.logical_job_id IS NULL OR NOT EXISTS (
        SELECT 1
        FROM logical_workflow_effective_job_results AS source
        WHERE source.run_id = carried.source_run_id
          AND source.logical_job_id = carried.source_logical_job_id
          AND source.claim_state = 'finalized'
          AND source.descriptor_digest = carried.result_descriptor_digest
          AND source.logical_key = carried.logical_key
          AND source.source_order = carried.source_order
          AND source.plan_digest = carried.plan_digest
          AND source.plan_object_key = carried.plan_object_key
          AND source.plan_size_bytes = carried.plan_size_bytes
          AND source.plan_media_type = carried.plan_media_type
          AND source.plan_schema = carried.plan_schema
          AND source.activation_output_digest = carried.activation_output_digest
          AND source.condition_matched = carried.condition_matched
          AND source.instance_count = carried.instance_count
          AND source.instances_digest = carried.instances_digest
          AND source.prerequisite_count = carried.prerequisite_count
          AND source.prerequisites_digest = carried.prerequisites_digest
          AND source.effective_conclusion = carried.effective_conclusion
          AND source.closure_has_failure = carried.closure_has_failure
          AND source.closure_has_cancelled = carried.closure_has_cancelled
          AND source.closure_has_skipped = carried.closure_has_skipped
          AND source.output_count = carried.output_count
          AND source.outputs_digest = carried.outputs_digest
          AND source.commit_digest = carried.commit_digest
          AND source.claim_owner_id = carried.claim_owner_id
          AND source.claim_generation = carried.claim_generation
          AND source.claim_started_at_ms = carried.claim_started_at_ms
          AND source.claim_expires_at_ms = carried.claim_expires_at_ms
          AND source.finalized_at_ms = carried.finalized_at_ms
          AND NOT EXISTS (
              (SELECT output_name, sensitivity, public_value
               FROM logical_workflow_effective_job_result_outputs
               WHERE logical_job_id = carried.source_logical_job_id)
              EXCEPT
              (SELECT output_name, sensitivity, public_value
               FROM workflow_rerun_carried_job_outputs
               WHERE logical_job_id = carried.logical_job_id)
          )
          AND NOT EXISTS (
              (SELECT output_name, sensitivity, public_value
               FROM workflow_rerun_carried_job_outputs
               WHERE logical_job_id = carried.logical_job_id)
              EXCEPT
              (SELECT output_name, sensitivity, public_value
               FROM logical_workflow_effective_job_result_outputs
               WHERE logical_job_id = carried.source_logical_job_id)
          )
    ) THEN
        RAISE EXCEPTION 'carried workflow result differs from its immutable source result'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_carried_job_source_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_validate_workflow_rerun_check_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    exact BOOLEAN;
    contents_exact BOOLEAN;
BEGIN
    SELECT TRUE INTO exact
    FROM workflow_rerun_attempts AS attempt
    JOIN workflow_rerun_requests AS request
      ON request.tenant_id = NEW.tenant_id
     AND request.operation_id = NEW.operation_id
     AND request.rerun_run_id = attempt.run_id
     AND request.source_run_id = attempt.source_run_id
    JOIN workflow_admission_receipts AS receipt
      ON receipt.tenant_id = request.tenant_id
     AND receipt.idempotency_kind = 'operation'
     AND receipt.idempotency_key =
         'workflow-rerun:' || request.operation_id::TEXT
     AND receipt.request_digest = request.request_digest
     AND receipt.repository_id = request.repository_id
     AND receipt.run_id = attempt.run_id
     AND receipt.committed_at_ms = attempt.created_at_ms
     AND receipt.github_subject_evidence_required
    JOIN workflow_runs AS run ON run.id = attempt.run_id
    JOIN github_workflow_run_base_manifest_origins AS origin
      ON origin.run_id = attempt.root_run_id
     AND origin.tenant_id = request.tenant_id
     AND origin.repository_id = request.repository_id
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = origin.tenant_id
     AND manifest.repository_id = origin.repository_id
     AND manifest.provider_connection_id = origin.provider_connection_id
     AND manifest.manifest_revision = origin.provider_manifest_revision
     AND manifest.manifest_digest = origin.provider_manifest_digest
    JOIN github_server_service_authorities AS authority
      ON authority.tenant_id = origin.tenant_id
     AND authority.id = NEW.checks_authority_id
     AND authority.repository_id = origin.repository_id
     AND authority.provider_connection_id = origin.provider_connection_id
     AND authority.provider_installation_id = origin.provider_installation_id
     AND authority.github_app_id = manifest.github_app_id
     AND authority.github_repository_id = origin.github_repository_id
     AND authority.github_repository_name = origin.github_repository_name
     AND authority.service_scope = 'checks_write'
     AND authority.github_app_client_id = manifest.github_app_client_id
     AND authority.github_app_jwt_issuer_kind =
         manifest.github_app_jwt_issuer_kind
     AND authority.app_key_spki_sha256 = manifest.app_key_spki_sha256
     AND authority.app_configuration_revision =
         manifest.app_configuration_revision
     AND authority.policy_revision = manifest.policy_revision
     AND authority.identity_digest = NEW.checks_authority_identity_digest
     AND authority.state = 'active'
     AND authority.created_at_ms <= NEW.recorded_at_ms
     AND authority.state_updated_at_ms <= NEW.recorded_at_ms
    JOIN github_check_subjects AS source
      ON source.id = NEW.source_github_check_subject_id
     AND source.workflow_run_id = attempt.source_run_id
    JOIN github_check_subjects AS target
      ON target.id = NEW.github_check_subject_id
     AND target.workflow_run_id = attempt.run_id
    WHERE attempt.run_id = NEW.run_id
      AND attempt.source_run_id = NEW.source_run_id
      AND attempt.source_run_id IS NOT NULL
      AND request.tenant_id = NEW.tenant_id
      AND request.operation_id = NEW.operation_id
      AND request.repository_id = NEW.repository_id
      AND request.committed_at_ms = attempt.created_at_ms
      AND run.repository_id = NEW.repository_id
      AND run.status = 'queued'
      AND origin.tenant_id = NEW.tenant_id
      AND origin.repository_id = NEW.repository_id
      AND origin.provider_connection_id = NEW.provider_connection_id
      AND origin.provider_manifest_revision = NEW.provider_manifest_revision
      AND origin.provider_manifest_digest = NEW.provider_manifest_digest
      AND manifest.app_configuration_revision =
          NEW.checks_authority_app_configuration_revision
      AND manifest.policy_revision =
          NEW.checks_authority_policy_revision
      AND NEW.repository_contents_authority_id =
          origin.repository_contents_authority_id
      AND NEW.repository_contents_authority_identity_digest =
          origin.repository_contents_authority_identity_digest
      AND NEW.repository_contents_authority_app_configuration_revision =
          origin.repository_contents_authority_app_configuration_revision
      AND NEW.repository_contents_authority_policy_revision =
          origin.repository_contents_authority_policy_revision
      AND EXISTS (
              SELECT 1
              FROM github_server_service_authorities AS contents_authority
              WHERE contents_authority.tenant_id = origin.tenant_id
                AND contents_authority.id =
                    origin.repository_contents_authority_id
                AND contents_authority.repository_id = origin.repository_id
                AND contents_authority.provider_connection_id =
                    origin.provider_connection_id
                AND contents_authority.provider_installation_id =
                    origin.provider_installation_id
                AND contents_authority.github_app_id = manifest.github_app_id
                AND contents_authority.github_repository_id =
                    origin.github_repository_id
                AND contents_authority.github_repository_name =
                    origin.github_repository_name
                AND contents_authority.service_scope =
                    'repository_contents_read'
                AND contents_authority.github_app_client_id =
                    manifest.github_app_client_id
                AND contents_authority.github_app_jwt_issuer_kind =
                    manifest.github_app_jwt_issuer_kind
                AND contents_authority.app_key_spki_sha256 =
                    manifest.app_key_spki_sha256
                AND contents_authority.identity_digest =
                    NEW.repository_contents_authority_identity_digest
                AND contents_authority.app_configuration_revision =
                    NEW.repository_contents_authority_app_configuration_revision
                AND contents_authority.policy_revision =
                    NEW.repository_contents_authority_policy_revision
                AND contents_authority.state = 'active'
                AND contents_authority.created_at_ms <= NEW.recorded_at_ms
                AND contents_authority.state_updated_at_ms <= NEW.recorded_at_ms
          )
      AND source.tenant_id = NEW.tenant_id
      AND source.repository_id = NEW.repository_id
      AND source.provider_connection_id = NEW.provider_connection_id
      AND source.head_sha = origin.github_check_head_sha
      AND source.provider_installation_id = origin.provider_installation_id
      AND source.github_repository_id = origin.github_repository_id
      AND source.github_repository_name = origin.github_repository_name
      AND source.github_app_id = manifest.github_app_id
      AND source.subject_key = manifest.check_subject_key
      AND source.check_name = manifest.check_name
      AND source.desired_state = 'completed'
      AND source.desired_conclusion IS NOT NULL
      AND source.terminal_cause IS NOT NULL
      AND source.desired_revision = 3
      AND target.tenant_id = source.tenant_id
      AND target.repository_id = source.repository_id
      AND target.origin_kind = 'workflow_rerun'
      AND target.provider_delivery_id IS NULL
      AND target.workflow_rerun_run_id = attempt.run_id
      AND target.subject_key = source.subject_key
      AND target.provider_connection_id = source.provider_connection_id
      AND target.provider_installation_id = source.provider_installation_id
      AND target.github_repository_id = source.github_repository_id
      AND target.github_repository_name = source.github_repository_name
      AND target.github_app_id = source.github_app_id
      AND target.head_sha = source.head_sha
      AND target.head_sha = run.head_sha
      AND target.head_sha = NEW.github_check_head_sha
      AND target.check_name = source.check_name
      AND target.workflow_run_id = attempt.run_id
      AND target.linked_at_ms = attempt.created_at_ms
      AND target.desired_state = 'in_progress'
      AND target.desired_conclusion IS NULL
      AND target.terminal_cause IS NULL
      AND target.desired_revision = 2
      AND target.created_at_ms = attempt.created_at_ms
      AND target.desired_updated_at_ms = attempt.created_at_ms
      AND NEW.recorded_at_ms = attempt.created_at_ms
    FOR SHARE OF attempt, request, receipt, run, manifest, authority,
                 source, target;

    SELECT TRUE INTO contents_exact
        FROM workflow_rerun_attempts AS attempt
        JOIN workflow_rerun_requests AS request
          ON request.tenant_id = NEW.tenant_id
         AND request.operation_id = NEW.operation_id
         AND request.rerun_run_id = attempt.run_id
        JOIN github_workflow_run_base_manifest_origins AS origin
          ON origin.run_id = attempt.root_run_id
         AND origin.tenant_id = request.tenant_id
         AND origin.repository_id = request.repository_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        JOIN github_server_service_authorities AS contents_authority
          ON contents_authority.tenant_id = origin.tenant_id
         AND contents_authority.id = NEW.repository_contents_authority_id
         AND contents_authority.repository_id = origin.repository_id
         AND contents_authority.provider_connection_id =
             origin.provider_connection_id
         AND contents_authority.provider_installation_id =
             origin.provider_installation_id
         AND contents_authority.github_app_id = manifest.github_app_id
         AND contents_authority.github_repository_id =
             origin.github_repository_id
         AND contents_authority.github_repository_name =
             origin.github_repository_name
         AND contents_authority.service_scope =
             'repository_contents_read'
         AND contents_authority.github_app_client_id =
             manifest.github_app_client_id
         AND contents_authority.github_app_jwt_issuer_kind =
             manifest.github_app_jwt_issuer_kind
         AND contents_authority.app_key_spki_sha256 =
             manifest.app_key_spki_sha256
         AND contents_authority.identity_digest =
             NEW.repository_contents_authority_identity_digest
         AND contents_authority.app_configuration_revision =
             NEW.repository_contents_authority_app_configuration_revision
         AND contents_authority.policy_revision =
             NEW.repository_contents_authority_policy_revision
         AND contents_authority.state = 'active'
         AND contents_authority.created_at_ms <= NEW.recorded_at_ms
         AND contents_authority.state_updated_at_ms <= NEW.recorded_at_ms
        WHERE attempt.run_id = NEW.run_id
          AND origin.repository_contents_authority_id =
              NEW.repository_contents_authority_id
          AND origin.repository_contents_authority_identity_digest =
              NEW.repository_contents_authority_identity_digest
          AND origin.repository_contents_authority_app_configuration_revision =
              NEW.repository_contents_authority_app_configuration_revision
          AND origin.repository_contents_authority_policy_revision =
              NEW.repository_contents_authority_policy_revision
        FOR SHARE OF manifest, contents_authority;

    IF exact IS DISTINCT FROM TRUE OR contents_exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow rerun Check evidence is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_check_evidence_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_workflow_rerun_concurrency_slot() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    candidate_run_id UUID;
    exact_slot_count BIGINT;
    all_slot_count BIGINT;
    concurrency_key TEXT;
    repository UUID;
    admitted_at BIGINT;
BEGIN
    candidate_run_id := NEW.run_id;
    SELECT run.repository_id, run.concurrency_group_key, attempt.created_at_ms
      INTO repository, concurrency_key, admitted_at
    FROM workflow_rerun_attempts AS attempt
    JOIN workflow_runs AS run ON run.id = attempt.run_id
    WHERE attempt.run_id = candidate_run_id
      AND attempt.source_run_id IS NOT NULL;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT count(*) INTO all_slot_count
    FROM (
        SELECT concurrency.repository_id, concurrency.normalized_key,
               concurrency.running_run_id AS run_id,
               concurrency.updated_at_ms AS slot_at_ms
        FROM concurrency_groups AS concurrency
        WHERE concurrency.running_run_id = candidate_run_id
        UNION ALL
        SELECT pending.repository_id, pending.normalized_key,
               pending.run_id, pending.enqueued_at_ms
        FROM concurrency_group_pending_runs AS pending
        WHERE pending.run_id = candidate_run_id
    ) AS slots;

    IF concurrency_key IS NULL THEN
        exact_slot_count := 0;
    ELSE
        SELECT count(*) INTO exact_slot_count
        FROM (
            SELECT concurrency.repository_id, concurrency.normalized_key,
                   concurrency.running_run_id AS run_id,
                   concurrency.updated_at_ms AS slot_at_ms
            FROM concurrency_groups AS concurrency
            WHERE concurrency.repository_id = repository
              AND concurrency.normalized_key = concurrency_key
              AND concurrency.running_run_id = candidate_run_id
            UNION ALL
            SELECT pending.repository_id, pending.normalized_key,
                   pending.run_id, pending.enqueued_at_ms
            FROM concurrency_group_pending_runs AS pending
            WHERE pending.repository_id = repository
              AND pending.normalized_key = concurrency_key
              AND pending.run_id = candidate_run_id
        ) AS exact_slots
        WHERE exact_slots.slot_at_ms = admitted_at;
    END IF;

    IF all_slot_count <> exact_slot_count
        OR concurrency_key IS NULL AND exact_slot_count <> 0
        OR concurrency_key IS NOT NULL AND exact_slot_count <> 1
    THEN
        RAISE EXCEPTION 'workflow rerun concurrency slot is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_concurrency_slot_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_validate_workflow_rerun_graph_exact() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    candidate_run_id UUID;
    candidate_source_run_id UUID;
    exact BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'workflow_rerun_requests' THEN
        candidate_run_id := NEW.rerun_run_id;
    ELSE
        candidate_run_id := NEW.run_id;
    END IF;
    IF candidate_run_id IS NULL THEN
        RETURN NULL;
    END IF;

    SELECT source_run_id INTO candidate_source_run_id
    FROM workflow_rerun_attempts
    WHERE run_id = candidate_run_id;
    IF NOT FOUND OR candidate_source_run_id IS NULL THEN
        RETURN NULL;
    END IF;

    WITH RECURSIVE
    context AS (
        SELECT attempt.run_id, attempt.source_run_id, attempt.created_at_ms,
               target_marker.root_invocation_id AS target_invocation_id,
               source_marker.root_invocation_id AS source_invocation_id,
               request.selection_kind, request.selected_source_job_id
        FROM workflow_rerun_attempts AS attempt
        JOIN workflow_rerun_requests AS request
          ON request.rerun_run_id = attempt.run_id
         AND request.source_run_id = attempt.source_run_id
         AND request.committed_at_ms = attempt.created_at_ms
        JOIN logical_workflow_runs AS target_marker
          ON target_marker.run_id = attempt.run_id
         AND target_marker.admission_graph_sealed_at_ms IS NOT NULL
        JOIN logical_workflow_runs AS source_marker
          ON source_marker.run_id = attempt.source_run_id
         AND target_marker.orchestration_schema = source_marker.orchestration_schema
         AND target_marker.runner_requirements_schema = 1
         AND source_marker.runner_requirements_schema = 1
         AND target_marker.state = 'pending'
         AND target_marker.revision = 1
         AND target_marker.admitted_at_ms = attempt.created_at_ms
         AND target_marker.updated_at_ms >= attempt.created_at_ms
         AND source_marker.base_context_digest IS NOT NULL
         AND source_marker.base_context_object_key IS NOT NULL
         AND source_marker.base_context_size_bytes IS NOT NULL
         AND source_marker.base_context_media_type =
             'application/vnd.automata.job-runtime-context.protobuf'
         AND source_marker.base_context_schema = 1
         AND target_marker.base_context_digest = source_marker.base_context_digest
         AND target_marker.base_context_object_key =
             source_marker.base_context_object_key
         AND target_marker.base_context_size_bytes =
             source_marker.base_context_size_bytes
         AND target_marker.base_context_media_type =
             source_marker.base_context_media_type
         AND target_marker.base_context_schema = source_marker.base_context_schema
        JOIN logical_workflow_invocations AS target_invocation
          ON target_invocation.run_id = attempt.run_id
         AND target_invocation.id = target_marker.root_invocation_id
         AND target_invocation.invocation_kind = 'root'
         AND target_invocation.state = 'pending'
         AND target_invocation.revision = 1
         AND target_invocation.created_at_ms = attempt.created_at_ms
         AND target_invocation.updated_at_ms = attempt.created_at_ms
        JOIN human_provider_identities AS identity
          ON identity.principal_id = request.actor_principal_id
        JOIN human_sessions AS session
          ON session.tenant_id = request.tenant_id
         AND session.principal_id = request.actor_principal_id
         AND session.id = request.actor_session_id
         AND session.provider_id = identity.provider_id
         AND session.provider_subject = identity.provider_subject
        JOIN workflow_runs AS target_run
          ON target_run.id = attempt.run_id
         AND target_run.triggering_actor = identity.provider_login
         AND target_run.runner_requirements_schema = 1
         AND target_run.status = 'queued'
         AND target_run.created_at_ms = attempt.created_at_ms
         AND target_run.updated_at_ms = attempt.created_at_ms
         AND target_run.concurrency_group_key IS NULL
         AND target_run.concurrency_queue_policy IS NULL
         AND target_run.concurrency_cancel_in_progress IS NULL
        JOIN workflow_runs AS source_run
          ON source_run.id = attempt.source_run_id
         AND source_run.runner_requirements_schema = 1
         AND source_run.concurrency_group_key IS NULL
         AND source_run.concurrency_queue_policy IS NULL
         AND source_run.concurrency_cancel_in_progress IS NULL
        WHERE attempt.run_id = candidate_run_id
          AND attempt.source_run_id = candidate_source_run_id
    ),
    source_jobs AS (
        SELECT job.*
        FROM context
        JOIN logical_workflow_jobs AS job
          ON job.run_id = context.source_run_id
         AND job.invocation_id = context.source_invocation_id
        JOIN logical_workflow_run_result_jobs AS aggregate
          ON aggregate.run_id = job.run_id
         AND aggregate.root_invocation_id = job.invocation_id
         AND aggregate.logical_job_id = job.id
    ),
    target_jobs AS (
        SELECT job.*
        FROM context
        JOIN logical_workflow_jobs AS job
          ON job.run_id = context.run_id
         AND job.invocation_id = context.target_invocation_id
    ),
    mapping AS (
        SELECT mapped.*
        FROM context
        JOIN workflow_rerun_attempt_jobs AS mapped
          ON mapped.run_id = context.run_id
         AND mapped.source_run_id = context.source_run_id
    ),
    expected_selected(source_logical_job_id) AS (
        SELECT source.id
        FROM context
        JOIN source_jobs AS source ON TRUE
        LEFT JOIN logical_workflow_effective_job_results AS result
          ON result.run_id = context.source_run_id
         AND result.logical_job_id = source.id
         AND result.claim_state = 'finalized'
        WHERE context.selection_kind = 'entire_workflow'
           OR context.selection_kind = 'job_and_dependents'
              AND source.id = context.selected_source_job_id
           OR context.selection_kind = 'failed_jobs_and_dependents'
              AND result.effective_conclusion IN ('failure', 'timed_out')
        UNION
        SELECT dependency.logical_job_id
        FROM expected_selected AS selected
        JOIN context ON TRUE
        JOIN logical_workflow_dependencies AS dependency
          ON dependency.run_id = context.source_run_id
         AND dependency.invocation_id = context.source_invocation_id
         AND dependency.prerequisite_job_id = selected.source_logical_job_id
    ),
    expected_edges AS (
        SELECT dependent.logical_job_id,
               prerequisite.logical_job_id AS prerequisite_job_id
        FROM context
        JOIN logical_workflow_dependencies AS source_edge
          ON source_edge.run_id = context.source_run_id
         AND source_edge.invocation_id = context.source_invocation_id
        JOIN mapping AS dependent
          ON dependent.source_logical_job_id = source_edge.logical_job_id
        JOIN mapping AS prerequisite
          ON prerequisite.source_logical_job_id = source_edge.prerequisite_job_id
    ),
    target_edges AS (
        SELECT dependency.logical_job_id, dependency.prerequisite_job_id
        FROM context
        JOIN logical_workflow_dependencies AS dependency
          ON dependency.run_id = context.run_id
         AND dependency.invocation_id = context.target_invocation_id
    )
    SELECT EXISTS (SELECT 1 FROM context)
       AND EXISTS (SELECT 1 FROM expected_selected)
       AND (SELECT count(*) FROM logical_workflow_invocations AS invocation
            JOIN context ON invocation.run_id = context.source_run_id) = 1
       AND (SELECT count(*) FROM logical_workflow_invocations AS invocation
            JOIN context ON invocation.run_id = context.run_id) = 1
       AND NOT EXISTS (
           SELECT 1 FROM source_jobs WHERE execution_kind <> 'steps'
       )
       AND NOT EXISTS (
           SELECT 1 FROM target_jobs WHERE execution_kind <> 'steps'
       )
       AND NOT EXISTS (
           SELECT 1
           FROM context
           JOIN logical_workflow_effective_job_results AS result
             ON result.run_id = context.source_run_id
            AND result.claim_state = 'finalized'
           WHERE context.selection_kind <> 'entire_workflow'
             AND result.instance_count > 1
       )
       AND NOT EXISTS (
           (SELECT id FROM source_jobs)
           EXCEPT
           (SELECT source_logical_job_id FROM mapping)
       )
       AND NOT EXISTS (
           (SELECT source_logical_job_id FROM mapping)
           EXCEPT
           (SELECT id FROM source_jobs)
       )
       AND NOT EXISTS (
           (SELECT id FROM target_jobs)
           EXCEPT
           (SELECT logical_job_id FROM mapping)
       )
       AND NOT EXISTS (
           (SELECT logical_job_id FROM mapping)
           EXCEPT
           (SELECT id FROM target_jobs)
       )
       AND NOT EXISTS (
           (SELECT source_logical_job_id FROM mapping WHERE selected)
           EXCEPT
           (SELECT source_logical_job_id FROM expected_selected)
       )
       AND NOT EXISTS (
           (SELECT source_logical_job_id FROM expected_selected)
           EXCEPT
           (SELECT source_logical_job_id FROM mapping WHERE selected)
       )
       AND NOT EXISTS (
           SELECT 1
           FROM mapping AS mapped
           JOIN context ON TRUE
           JOIN source_jobs AS source ON source.id = mapped.source_logical_job_id
           JOIN target_jobs AS target ON target.id = mapped.logical_job_id
           WHERE target.logical_key IS DISTINCT FROM source.logical_key
              OR target.source_order IS DISTINCT FROM source.source_order
              OR target.execution_kind IS DISTINCT FROM source.execution_kind
              OR target.runtime_policy_revision IS DISTINCT FROM
                 source.runtime_policy_revision
              OR target.runtime_policy_digest IS DISTINCT FROM
                 source.runtime_policy_digest
              OR target.environment_requirement_kind IS DISTINCT FROM
                 source.environment_requirement_kind
              OR target.environment_template_digest IS DISTINCT FROM
                 source.environment_template_digest
              OR target.secret_reference_names IS DISTINCT FROM
                 source.secret_reference_names
              OR target.variable_reference_names IS DISTINCT FROM
                 source.variable_reference_names
              OR target.credential_requirements_schema IS DISTINCT FROM
                 source.credential_requirements_schema
              OR target.rerun_carried IS DISTINCT FROM NOT mapped.selected
              OR target.created_at_ms IS DISTINCT FROM context.created_at_ms
              OR target.updated_at_ms IS DISTINCT FROM context.created_at_ms
              OR mapped.selected AND (
                  target.state IS DISTINCT FROM 'pending'
                  OR target.activation_fence IS DISTINCT FROM 0
                  OR target.activation_input_digest IS NOT NULL
                  OR target.authority_profile IS NOT NULL
                  OR target.activation_origin_selection_id IS NOT NULL
              )
              OR NOT mapped.selected AND (
                  target.state IS DISTINCT FROM source.state
                  OR target.activation_fence IS DISTINCT FROM
                     source.activation_fence
                  OR target.activation_input_digest IS DISTINCT FROM
                     source.activation_input_digest
                  OR target.authority_profile IS DISTINCT FROM
                     source.authority_profile
                  OR target.activation_origin_selection_id IS DISTINCT FROM
                     source.activation_origin_selection_id
              )
       )
       AND NOT EXISTS (
           (SELECT logical_job_id, prerequisite_job_id FROM expected_edges)
           EXCEPT
           (SELECT logical_job_id, prerequisite_job_id FROM target_edges)
       )
       AND NOT EXISTS (
           (SELECT logical_job_id, prerequisite_job_id FROM target_edges)
           EXCEPT
           (SELECT logical_job_id, prerequisite_job_id FROM expected_edges)
       )
    INTO exact;

    IF exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow rerun graph or selection closure is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_graph_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_validate_workflow_rerun_job_classification() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    durable_job logical_workflow_jobs%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'logical_workflow_jobs' THEN
        durable_job := NEW;
    ELSE
        SELECT * INTO durable_job
        FROM logical_workflow_jobs
        WHERE run_id = NEW.run_id
          AND id = NEW.logical_job_id;
    END IF;

    IF durable_job.id IS NULL THEN
        RAISE EXCEPTION 'workflow rerun classification has no exact logical job'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_carried_job_exact';
    ELSIF durable_job.rerun_carried THEN
        IF EXISTS (
            SELECT 1
            FROM logical_workflow_job_results AS executed
            WHERE executed.run_id = durable_job.run_id
              AND executed.logical_job_id = durable_job.id
        ) OR NOT EXISTS (
            SELECT 1
            FROM workflow_rerun_attempt_jobs AS mapping
            JOIN workflow_rerun_carried_job_results AS carried
              ON carried.run_id = mapping.run_id
             AND carried.logical_job_id = mapping.logical_job_id
             AND carried.source_run_id = mapping.source_run_id
             AND carried.source_logical_job_id = mapping.source_logical_job_id
            WHERE mapping.run_id = durable_job.run_id
              AND mapping.logical_job_id = durable_job.id
              AND NOT mapping.selected
              AND durable_job.state = CASE carried.effective_conclusion
                  WHEN 'success' THEN 'completed'
                  WHEN 'failure' THEN 'failed'
                  WHEN 'timed_out' THEN 'failed'
                  WHEN 'cancelled' THEN 'cancelled'
                  WHEN 'skipped' THEN 'skipped'
              END
        ) THEN
            RAISE EXCEPTION 'carried logical job lacks exact immutable source evidence'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'workflow_rerun_carried_job_exact';
        END IF;
    ELSIF EXISTS (
        SELECT 1
        FROM workflow_rerun_attempt_jobs AS mapping
        WHERE mapping.run_id = durable_job.run_id
          AND mapping.logical_job_id = durable_job.id
          AND NOT mapping.selected
    ) OR EXISTS (
        SELECT 1
        FROM workflow_rerun_carried_job_results AS carried
        WHERE carried.run_id = durable_job.run_id
          AND carried.logical_job_id = durable_job.id
    ) THEN
        RAISE EXCEPTION 'unselected rerun job is not classified as carried'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_carried_job_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_validate_workflow_rerun_request_complete() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    admitted_at BIGINT;
    root_created_at BIGINT;
    actor_exact BOOLEAN;
    mapped_snapshot_id UUID;
    mapped_organization_id BIGINT;
    mapped_team_id BIGINT;
BEGIN
    IF NEW.rerun_run_id IS NULL OR NEW.committed_at_ms IS NULL THEN
        RAISE EXCEPTION 'workflow rerun requests must commit complete'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_rerun_requests_completion_exact';
    END IF;
    SELECT attempt.created_at_ms, root.created_at_ms
      INTO admitted_at, root_created_at
    FROM workflow_rerun_attempts AS attempt
    JOIN workflow_runs AS root ON root.id = attempt.root_run_id
    WHERE attempt.run_id = NEW.rerun_run_id
      AND attempt.source_run_id = NEW.source_run_id;
    IF NOT FOUND
        OR root_created_at > admitted_at
        OR admitted_at - root_created_at > 2592000000
        OR automata_workflow_rerun_now_ms() - root_created_at > 2592000000
        OR admitted_at <> automata_workflow_rerun_now_ms()
    THEN
        RAISE EXCEPTION 'workflow rerun request age is not exact'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_rerun_requests_age_exact';
    END IF;

    SELECT TRUE INTO actor_exact
    FROM human_sessions AS session
    JOIN human_principals AS principal
      ON principal.id = session.principal_id
    JOIN tenant_human_memberships AS membership
      ON membership.tenant_id = session.tenant_id
     AND membership.principal_id = session.principal_id
    WHERE session.tenant_id = NEW.tenant_id
      AND session.principal_id = NEW.actor_principal_id
      AND session.id = NEW.actor_session_id
      AND principal.status = 'active'
      AND membership.status = 'active'
      AND membership.authorization_revision = NEW.authorization_revision
      AND session.authorization_revision = NEW.authorization_revision
      AND session.revoked_at_ms IS NULL
      AND session.issued_at_ms <= admitted_at
      AND session.idle_expires_at_ms > admitted_at
      AND session.expires_at_ms > admitted_at
      AND (
          session.session_kind = 'browser'
          AND session.audience = 'automata.web'
          OR session.session_kind = 'cli'
          AND session.audience = 'automata.cli'
      )
      AND EXISTS (
          SELECT 1
          FROM rbac_role_bindings AS binding
          JOIN rbac_role_permissions AS permission
            ON permission.tenant_id = binding.tenant_id
           AND permission.role_id = binding.role_id
          WHERE binding.tenant_id = NEW.tenant_id
            AND binding.principal_id = NEW.actor_principal_id
            AND binding.status = 'active'
            AND (
                binding.valid_until_ms IS NULL
                OR binding.valid_until_ms > admitted_at
            )
            AND permission.permission_name = 'runs:rerun'
            AND (
                binding.scope_kind = 'tenant'
                AND binding.repository_id IS NULL
                AND binding.runner_group_id IS NULL
                OR binding.scope_kind = 'repository'
                AND binding.repository_id = NEW.repository_id
                AND binding.runner_group_id IS NULL
            )
          UNION ALL
          SELECT 1
          FROM github_membership_snapshots AS snapshot
          JOIN human_provider_identities AS identity
            ON identity.principal_id = snapshot.principal_id
           AND identity.provider_id = snapshot.provider_id
           AND identity.provider_subject = snapshot.provider_subject
          JOIN human_provider_tokens AS provider_token
            ON provider_token.tenant_id = snapshot.tenant_id
           AND provider_token.principal_id = snapshot.principal_id
           AND provider_token.provider_id = snapshot.provider_id
           AND provider_token.provider_subject = snapshot.provider_subject
           AND provider_token.version = snapshot.provider_token_version
          JOIN github_role_mappings AS mapping
            ON mapping.tenant_id = snapshot.tenant_id
           AND mapping.provider_id = snapshot.provider_id
           AND mapping.status = 'active'
          JOIN rbac_role_permissions AS mapped_permission
            ON mapped_permission.tenant_id = mapping.tenant_id
           AND mapped_permission.role_id = mapping.role_id
          WHERE snapshot.tenant_id = NEW.tenant_id
            AND snapshot.principal_id = NEW.actor_principal_id
            AND snapshot.provider_id = 'github'
            AND snapshot.provider_id = session.provider_id
            AND snapshot.provider_subject = session.provider_subject
            AND snapshot.observed_at_ms <= admitted_at
            AND snapshot.valid_until_ms > admitted_at
            AND provider_token.revoked_at_ms IS NULL
            AND provider_token.issued_at_ms <= snapshot.observed_at_ms
            AND (
                provider_token.access_expires_at_ms IS NULL
                OR provider_token.access_expires_at_ms > admitted_at
                AND snapshot.valid_until_ms <=
                    provider_token.access_expires_at_ms
            )
            AND mapped_permission.permission_name = 'runs:rerun'
            AND (
                mapping.scope_kind = 'tenant'
                AND mapping.repository_id IS NULL
                AND mapping.runner_group_id IS NULL
                OR mapping.scope_kind = 'repository'
                AND mapping.repository_id = NEW.repository_id
                AND mapping.runner_group_id IS NULL
            )
            AND (
                mapping.team_id IS NULL
                AND EXISTS (
                    SELECT 1
                    FROM github_organization_membership_observations AS organization
                    WHERE organization.tenant_id = snapshot.tenant_id
                      AND organization.snapshot_id = snapshot.id
                      AND organization.organization_id =
                          mapping.organization_id
                )
                OR mapping.team_id IS NOT NULL
                AND EXISTS (
                    SELECT 1
                    FROM github_team_membership_observations AS team
                    WHERE team.tenant_id = snapshot.tenant_id
                      AND team.snapshot_id = snapshot.id
                      AND team.organization_id = mapping.organization_id
                      AND team.team_id = mapping.team_id
                )
            )
            AND NOT EXISTS (
                SELECT 1
                FROM github_membership_snapshots AS newer
                WHERE newer.tenant_id = snapshot.tenant_id
                  AND newer.principal_id = snapshot.principal_id
                  AND newer.provider_id = snapshot.provider_id
                  AND newer.provider_subject = snapshot.provider_subject
                  AND newer.observed_at_ms <= admitted_at
                  AND (
                      newer.observed_at_ms > snapshot.observed_at_ms
                      OR newer.observed_at_ms = snapshot.observed_at_ms
                      AND newer.id <> snapshot.id
                  )
            )
      )
    FOR SHARE OF session, principal, membership;
    IF actor_exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow rerun request actor is not currently authorized'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_rerun_requests_authority_exact';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM rbac_role_bindings AS binding
        JOIN rbac_role_permissions AS permission
          ON permission.tenant_id = binding.tenant_id
         AND permission.role_id = binding.role_id
        WHERE binding.tenant_id = NEW.tenant_id
          AND binding.principal_id = NEW.actor_principal_id
          AND binding.status = 'active'
          AND (binding.valid_until_ms IS NULL OR binding.valid_until_ms > admitted_at)
          AND permission.permission_name = 'runs:rerun'
          AND (
              binding.scope_kind = 'tenant'
              AND binding.repository_id IS NULL
              AND binding.runner_group_id IS NULL
              OR binding.scope_kind = 'repository'
              AND binding.repository_id = NEW.repository_id
              AND binding.runner_group_id IS NULL
          )
    ) THEN
        SELECT snapshot.id, mapping.organization_id, mapping.team_id
          INTO mapped_snapshot_id, mapped_organization_id, mapped_team_id
        FROM github_membership_snapshots AS snapshot
        JOIN human_provider_identities AS identity
          ON identity.principal_id = snapshot.principal_id
         AND identity.provider_id = snapshot.provider_id
         AND identity.provider_subject = snapshot.provider_subject
        JOIN human_provider_tokens AS provider_token
          ON provider_token.tenant_id = snapshot.tenant_id
         AND provider_token.principal_id = snapshot.principal_id
         AND provider_token.provider_id = snapshot.provider_id
         AND provider_token.provider_subject = snapshot.provider_subject
         AND provider_token.version = snapshot.provider_token_version
        JOIN github_role_mappings AS mapping
          ON mapping.tenant_id = snapshot.tenant_id
         AND mapping.provider_id = snapshot.provider_id
         AND mapping.status = 'active'
        JOIN rbac_role_permissions AS mapped_permission
          ON mapped_permission.tenant_id = mapping.tenant_id
         AND mapped_permission.role_id = mapping.role_id
        WHERE snapshot.tenant_id = NEW.tenant_id
          AND snapshot.principal_id = NEW.actor_principal_id
          AND snapshot.provider_id = 'github'
          AND snapshot.provider_id = (
              SELECT session.provider_id FROM human_sessions AS session
              WHERE session.tenant_id = NEW.tenant_id
                AND session.principal_id = NEW.actor_principal_id
                AND session.id = NEW.actor_session_id
          )
          AND snapshot.provider_subject = (
              SELECT session.provider_subject FROM human_sessions AS session
              WHERE session.tenant_id = NEW.tenant_id
                AND session.principal_id = NEW.actor_principal_id
                AND session.id = NEW.actor_session_id
          )
          AND snapshot.provider_subject ~ '^[1-9][0-9]*$'
          AND length(snapshot.provider_subject) <= 20
          AND snapshot.provider_subject::NUMERIC <= 18446744073709551615
          AND snapshot.observed_at_ms <= admitted_at
          AND snapshot.valid_until_ms > admitted_at
          AND provider_token.revoked_at_ms IS NULL
          AND provider_token.issued_at_ms <= snapshot.observed_at_ms
          AND (
              provider_token.access_expires_at_ms IS NULL
              OR provider_token.access_expires_at_ms > admitted_at
              AND snapshot.valid_until_ms <= provider_token.access_expires_at_ms
          )
          AND mapped_permission.permission_name = 'runs:rerun'
          AND (
              mapping.scope_kind = 'tenant'
              AND mapping.repository_id IS NULL
              AND mapping.runner_group_id IS NULL
              OR mapping.scope_kind = 'repository'
              AND mapping.repository_id = NEW.repository_id
              AND mapping.runner_group_id IS NULL
          )
          AND (
              mapping.team_id IS NULL
              AND
              EXISTS (
                  SELECT 1
                  FROM github_organization_membership_observations AS organization
                  WHERE organization.tenant_id = snapshot.tenant_id
                    AND organization.snapshot_id = snapshot.id
                    AND organization.organization_id = mapping.organization_id
              )
              OR mapping.team_id IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM github_team_membership_observations AS team
                  WHERE team.tenant_id = snapshot.tenant_id
                    AND team.snapshot_id = snapshot.id
                    AND team.organization_id = mapping.organization_id
                    AND team.team_id = mapping.team_id
              )
          )
          AND NOT EXISTS (
              SELECT 1 FROM github_membership_snapshots AS newer
              WHERE newer.tenant_id = snapshot.tenant_id
                AND newer.principal_id = snapshot.principal_id
                AND newer.provider_id = snapshot.provider_id
                AND newer.provider_subject = snapshot.provider_subject
                AND newer.observed_at_ms <= admitted_at
                AND (
                    newer.observed_at_ms > snapshot.observed_at_ms
                    OR newer.observed_at_ms = snapshot.observed_at_ms
                    AND newer.id <> snapshot.id
                )
          )
        ORDER BY snapshot.observed_at_ms DESC, snapshot.id DESC
        LIMIT 1
        FOR SHARE OF snapshot, identity, provider_token, mapping,
                     mapped_permission;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'workflow rerun mapped actor evidence is not exact'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'workflow_rerun_requests_authority_exact';
        END IF;
        IF mapped_team_id IS NULL THEN
            PERFORM 1
            FROM github_organization_membership_observations AS organization
            WHERE organization.tenant_id = NEW.tenant_id
              AND organization.snapshot_id = mapped_snapshot_id
              AND organization.organization_id = mapped_organization_id
            FOR SHARE OF organization;
        ELSE
            PERFORM 1
            FROM github_organization_membership_observations AS organization
            JOIN github_team_membership_observations AS team
              ON team.tenant_id = organization.tenant_id
             AND team.snapshot_id = organization.snapshot_id
             AND team.organization_id = organization.organization_id
            WHERE organization.tenant_id = NEW.tenant_id
              AND organization.snapshot_id = mapped_snapshot_id
              AND organization.organization_id = mapped_organization_id
              AND team.team_id = mapped_team_id
            FOR SHARE OF organization, team;
        END IF;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'workflow rerun mapped membership evidence is not exact'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'workflow_rerun_requests_authority_exact';
        END IF;
    END IF;
    RETURN NEW;
END;
$_$;
