-- Frozen greenfield baseline. Add a new migration instead of editing this stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_validate_reusable_call_result() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    matched BOOLEAN;
    expected_conclusion TEXT;
    durable logical_workflow_reusable_call_results%ROWTYPE;
BEGIN
    SELECT * INTO durable
    FROM logical_workflow_reusable_call_results AS result
    WHERE result.run_id = NEW.run_id
      AND result.parent_invocation_id = NEW.parent_invocation_id
      AND result.caller_logical_job_id = NEW.caller_logical_job_id;

    SELECT publication.condition_matched
      INTO matched
    FROM logical_workflow_reusable_call_publications AS publication
    WHERE publication.run_id = NEW.run_id
      AND publication.parent_invocation_id = NEW.parent_invocation_id
      AND publication.caller_logical_job_id = NEW.caller_logical_job_id;

    IF durable.run_id IS NULL
        OR durable.sealed_at_ms IS NULL
        OR matched IS NULL
        OR durable.child_job_count <> (
            SELECT count(*)
            FROM logical_workflow_reusable_call_result_jobs AS evidence
            WHERE evidence.run_id = NEW.run_id
              AND evidence.parent_invocation_id = NEW.parent_invocation_id
              AND evidence.caller_logical_job_id = NEW.caller_logical_job_id
        )
        OR durable.output_count <> (
            SELECT count(*)
            FROM logical_workflow_reusable_call_result_outputs AS output
            WHERE output.run_id = NEW.run_id
              AND output.parent_invocation_id = NEW.parent_invocation_id
              AND output.caller_logical_job_id = NEW.caller_logical_job_id
        )
        OR EXISTS (
            SELECT 1
            FROM logical_workflow_reusable_call_result_jobs AS evidence
            LEFT JOIN logical_workflow_jobs AS child_job
              ON child_job.run_id = evidence.run_id
             AND child_job.invocation_id = durable.child_invocation_id
             AND child_job.id = evidence.child_logical_job_id
             AND child_job.source_order = evidence.source_order
            LEFT JOIN logical_workflow_job_results AS child_result
              ON child_result.run_id = child_job.run_id
             AND child_result.invocation_id = child_job.invocation_id
             AND child_result.logical_job_id = child_job.id
             AND child_result.descriptor_digest = evidence.descriptor_digest
             AND child_result.outputs_digest = evidence.outputs_digest
             AND child_result.commit_digest = evidence.commit_digest
             AND child_result.effective_conclusion = evidence.effective_conclusion
             AND child_result.closure_has_failure = evidence.closure_has_failure
             AND child_result.closure_has_cancelled = evidence.closure_has_cancelled
             AND child_result.closure_has_skipped = evidence.closure_has_skipped
            LEFT JOIN logical_workflow_job_result_claims AS child_claim
              ON child_claim.logical_job_id = child_result.logical_job_id
             AND child_claim.state = 'finalized'
            WHERE evidence.run_id = NEW.run_id
              AND evidence.parent_invocation_id = NEW.parent_invocation_id
              AND evidence.caller_logical_job_id = NEW.caller_logical_job_id
              AND (child_result.logical_job_id IS NULL
                   OR child_claim.logical_job_id IS NULL)
        )
        OR EXISTS (
            SELECT 1
            FROM logical_workflow_reusable_call_result_outputs AS output
            LEFT JOIN logical_workflow_reusable_outputs AS declared
              ON declared.run_id = output.run_id
             AND declared.invocation_id = durable.child_invocation_id
             AND declared.output_key = output.callee_output_name
             AND declared.source_order = output.source_order
             AND declared.sensitivity = output.sensitivity
            WHERE output.run_id = NEW.run_id
              AND output.parent_invocation_id = NEW.parent_invocation_id
              AND output.caller_logical_job_id = NEW.caller_logical_job_id
              AND declared.output_key IS NULL
        )
    THEN
        RAISE EXCEPTION 'reusable call result did not seal exact child evidence and outputs'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_call_result_exact';
    END IF;

    IF NOT matched THEN
        IF durable.child_job_count <> 0
            OR durable.output_count <> 0
            OR durable.effective_conclusion <> 'skipped'
        THEN
            RAISE EXCEPTION 'skipped reusable call result is not exact'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'logical_workflow_reusable_call_result_skipped';
        END IF;
        RETURN NULL;
    END IF;

    SELECT CASE
        WHEN bool_or(evidence.effective_conclusion = 'failure') THEN 'failure'
        WHEN bool_or(evidence.effective_conclusion = 'timed_out') THEN 'timed_out'
        WHEN bool_or(evidence.effective_conclusion = 'cancelled') THEN 'cancelled'
        WHEN bool_or(evidence.effective_conclusion = 'success') THEN 'success'
        ELSE 'skipped'
    END
      INTO expected_conclusion
    FROM logical_workflow_reusable_call_result_jobs AS evidence
    WHERE evidence.run_id = NEW.run_id
      AND evidence.parent_invocation_id = NEW.parent_invocation_id
      AND evidence.caller_logical_job_id = NEW.caller_logical_job_id;
    IF expected_conclusion IS DISTINCT FROM durable.effective_conclusion THEN
        RAISE EXCEPTION 'reusable call result conclusion is inexact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_call_result_conclusion';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_validate_reusable_workflow_expansion() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    expected_catalog_count BIGINT;
    expected_invocation_count BIGINT;
    expected_job_count BIGINT;
    expected_maximum_depth SMALLINT;
    expected_root_invocation_id UUID;
    durable_catalog_count BIGINT;
    durable_invocation_count BIGINT;
    durable_job_count BIGINT;
    durable_maximum_depth SMALLINT;
BEGIN
    SELECT catalog_entry_count,
           invocation_count,
           expanded_job_count,
           maximum_depth,
           root_invocation_id
      INTO expected_catalog_count,
           expected_invocation_count,
           expected_job_count,
           expected_maximum_depth,
           expected_root_invocation_id
    FROM logical_workflow_reusable_workflow_runs
    WHERE run_id = NEW.run_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'reusable workflow expansion lacks its replay receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_receipt_required';
    END IF;

    SELECT count(*) INTO durable_catalog_count
    FROM logical_workflow_reusable_workflow_catalog
    WHERE run_id = NEW.run_id;

    SELECT count(*) INTO durable_invocation_count
    FROM logical_workflow_reusable_invocation_expansions
    WHERE run_id = NEW.run_id;

    SELECT count(*) INTO durable_job_count
    FROM logical_workflow_reusable_expanded_jobs
    WHERE run_id = NEW.run_id;

    SELECT COALESCE(max(depth), 0) INTO durable_maximum_depth
    FROM logical_workflow_reusable_invocation_expansions
    WHERE run_id = NEW.run_id;

    IF durable_catalog_count <> expected_catalog_count
        OR durable_invocation_count <> expected_invocation_count
        OR durable_job_count <> expected_job_count
        OR durable_maximum_depth <> expected_maximum_depth
    THEN
        RAISE EXCEPTION 'reusable workflow expansion counts disagree with its replay receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_counts_exact';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_runs AS marker
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN workflow_definitions AS workflow ON workflow.id = run.workflow_id
        JOIN workflow_snapshots AS snapshot ON snapshot.id = run.snapshot_id
        JOIN logical_workflow_reusable_invocation_expansions AS root
          ON root.run_id = marker.run_id
         AND root.invocation_id = marker.root_invocation_id
         AND root.depth = 0
        JOIN logical_workflow_reusable_workflow_catalog AS catalog
          ON catalog.run_id = root.run_id
         AND catalog.catalog_entry_id = root.catalog_entry_id
        WHERE marker.run_id = NEW.run_id
          AND marker.root_invocation_id = expected_root_invocation_id
          AND marker.admission_graph_sealed_at_ms IS NOT NULL
          AND catalog.workflow_path = workflow.path
          AND catalog.source_digest = snapshot.source_digest
          AND catalog.source_revision = encode(run.head_sha, 'hex')
          AND catalog.source_object_key = snapshot.source_object_key
          AND catalog.source_size_bytes = snapshot.source_size_bytes
          AND catalog.source_media_type = snapshot.source_media_type
          AND catalog.plan_digest = run.plan_digest
          AND catalog.plan_object_key = run.plan_object_key
          AND catalog.plan_size_bytes = run.plan_size_bytes
          AND catalog.plan_media_type = run.plan_media_type
          AND catalog.plan_schema = run.plan_schema
    ) THEN
        RAISE EXCEPTION 'reusable workflow expansion lacks its exact sealed root'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_root_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS child
        LEFT JOIN logical_workflow_reusable_invocation_expansions AS parent
          ON parent.run_id = child.run_id
         AND parent.invocation_id = child.parent_invocation_id
        WHERE child.run_id = NEW.run_id
          AND child.depth > 0
          AND (
              parent.invocation_id IS NULL
              OR child.depth <> parent.depth + 1
              OR child.call_path[1:parent.depth + 1] <> parent.call_path
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow expansion parent lineage is inexact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_parent_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS invocation
        JOIN logical_workflow_reusable_workflow_catalog AS catalog
          ON catalog.run_id = invocation.run_id
         AND catalog.catalog_entry_id = invocation.catalog_entry_id
        JOIN workflow_runs AS run ON run.id = invocation.run_id
        WHERE invocation.run_id = NEW.run_id
          AND (
              invocation.workflow_path <> catalog.workflow_path
              OR catalog.source_revision <> encode(run.head_sha, 'hex')
              OR (
                  invocation.depth > 0
                  AND catalog.invocation_contract_digest IS NULL
              )
              OR (
                  SELECT count(*)
                  FROM logical_workflow_reusable_expanded_jobs AS job
                  WHERE job.run_id = invocation.run_id
                    AND job.invocation_id = invocation.invocation_id
              ) <> catalog.logical_job_count
              OR (
                  SELECT count(*)
                  FROM logical_workflow_reusable_expanded_jobs AS job
                  WHERE job.run_id = invocation.run_id
                    AND job.invocation_id = invocation.invocation_id
                    AND job.execution_kind = 'reusable_workflow'
              ) <> catalog.reusable_call_count
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow catalog and expanded invocation disagree'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_catalog_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS invocation
        CROSS JOIN LATERAL unnest(invocation.call_path) AS path(value)
        WHERE invocation.run_id = NEW.run_id
        GROUP BY invocation.invocation_id
        HAVING count(*) <> count(DISTINCT path.value)
    ) THEN
        RAISE EXCEPTION 'reusable workflow expansion contains a call cycle'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_acyclic';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS child
        JOIN logical_workflow_reusable_expanded_jobs AS caller
          ON caller.run_id = child.run_id
         AND caller.invocation_id = child.parent_invocation_id
         AND caller.logical_job_id = child.caller_logical_job_id
        WHERE child.run_id = NEW.run_id
          AND child.depth > 0
          AND caller.execution_kind <> 'reusable_workflow'
    ) OR EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_expanded_jobs AS caller
        WHERE caller.run_id = NEW.run_id
          AND caller.execution_kind = 'reusable_workflow'
          AND NOT EXISTS (
              SELECT 1
              FROM logical_workflow_reusable_invocation_expansions AS child
              WHERE child.run_id = caller.run_id
                AND child.parent_invocation_id = caller.invocation_id
                AND child.caller_logical_job_id = caller.logical_job_id
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow callsites and child invocations disagree'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_callsites_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS invocation
        LEFT JOIN logical_workflow_reusable_permission_snapshots AS permissions
          ON permissions.run_id = invocation.run_id
         AND permissions.invocation_id = invocation.invocation_id
         AND permissions.permission_digest = invocation.permission_digest
        WHERE invocation.run_id = NEW.run_id
          AND permissions.invocation_id IS NULL
    ) THEN
        RAISE EXCEPTION 'reusable workflow expansion lacks an exact permission reduction'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_permissions_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS child
        JOIN logical_workflow_reusable_invocation_expansions AS parent
          ON parent.run_id = child.run_id
         AND parent.invocation_id = child.parent_invocation_id
        JOIN logical_workflow_reusable_permission_snapshots AS child_permissions
          ON child_permissions.run_id = child.run_id
         AND child_permissions.invocation_id = child.invocation_id
        JOIN logical_workflow_reusable_permission_snapshots AS parent_permissions
          ON parent_permissions.run_id = parent.run_id
         AND parent_permissions.invocation_id = parent.invocation_id
        WHERE child.run_id = NEW.run_id
          AND child.depth > 0
          AND (
              CASE child_permissions.default_level
                  WHEN 'none' THEN 0 WHEN 'read' THEN 1 ELSE 2
              END > CASE parent_permissions.default_level
                  WHEN 'none' THEN 0 WHEN 'read' THEN 1 ELSE 2
              END
              OR EXISTS (
                  SELECT 1
                  FROM (
                      SELECT permission_name
                      FROM logical_workflow_reusable_permission_grants
                      WHERE run_id = child.run_id
                        AND invocation_id = child.invocation_id
                      UNION
                      SELECT permission_name
                      FROM logical_workflow_reusable_permission_grants
                      WHERE run_id = parent.run_id
                        AND invocation_id = parent.invocation_id
                  ) AS scope
                  LEFT JOIN logical_workflow_reusable_permission_grants AS child_grant
                    ON child_grant.run_id = child.run_id
                   AND child_grant.invocation_id = child.invocation_id
                   AND child_grant.permission_name = scope.permission_name
                  LEFT JOIN logical_workflow_reusable_permission_grants AS parent_grant
                    ON parent_grant.run_id = parent.run_id
                   AND parent_grant.invocation_id = parent.invocation_id
                   AND parent_grant.permission_name = scope.permission_name
                  WHERE CASE COALESCE(
                      child_grant.permission_level,
                      child_permissions.default_level
                  ) WHEN 'none' THEN 0 WHEN 'read' THEN 1 ELSE 2 END
                  > CASE COALESCE(
                      parent_grant.permission_level,
                      parent_permissions.default_level
                  ) WHEN 'none' THEN 0 WHEN 'read' THEN 1 ELSE 2 END
              )
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow permissions exceed their caller ceiling'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_permission_reduction';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_invocation_expansions AS invocation
        WHERE invocation.run_id = NEW.run_id
          AND (
              invocation.input_binding_count <> (
                  SELECT count(*)
                  FROM logical_workflow_reusable_input_bindings AS input
                  WHERE input.run_id = invocation.run_id
                    AND input.invocation_id = invocation.invocation_id
              )
              OR invocation.secret_binding_count <> (
                  SELECT count(*)
                  FROM logical_workflow_reusable_secret_bindings AS secret
                  WHERE secret.run_id = invocation.run_id
                    AND secret.invocation_id = invocation.invocation_id
              )
              OR invocation.output_count <> (
                  SELECT count(*)
                  FROM logical_workflow_reusable_outputs AS output
                  WHERE output.run_id = invocation.run_id
                    AND output.invocation_id = invocation.invocation_id
              )
              OR invocation.permission_grant_count <> (
                  SELECT count(*)
                  FROM logical_workflow_reusable_permission_grants AS permission_grant
                  WHERE permission_grant.run_id = invocation.run_id
                    AND permission_grant.invocation_id = invocation.invocation_id
              )
              OR invocation.dependency_count <> (
                  SELECT count(*)
                  FROM logical_workflow_reusable_expanded_dependencies AS dependency
                  WHERE dependency.run_id = invocation.run_id
                    AND dependency.invocation_id = invocation.invocation_id
              )
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow typed boundary counts are inexact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_contract_counts_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_validate_secret_key_rotation_item() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM secret_version_envelopes
        WHERE tenant_id = NEW.tenant_id
          AND secret_version_id = NEW.secret_version_id
          AND envelope_generation = NEW.previous_envelope_generation
    ) THEN
        RAISE EXCEPTION 'rotation source envelope does not exist'
            USING ERRCODE = 'foreign_key_violation',
                  CONSTRAINT = 'secret_key_rotation_items_previous_envelope';
    END IF;
    IF NEW.replacement_envelope_generation IS NOT NULL
       AND NOT EXISTS (
           SELECT 1
           FROM secret_version_envelopes
           WHERE tenant_id = NEW.tenant_id
             AND secret_version_id = NEW.secret_version_id
             AND envelope_generation = NEW.replacement_envelope_generation
       ) THEN
        RAISE EXCEPTION 'rotation replacement envelope does not exist'
            USING ERRCODE = 'foreign_key_violation',
                  CONSTRAINT = 'secret_key_rotation_items_replacement_envelope';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_secret_workload_grant() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    stored_scope TEXT;
    stored_repository UUID;
    stored_environment UUID;
    stored_secret_status TEXT;
    stored_version_status TEXT;
    repository_access_mode TEXT;
    minimum_trust TEXT;
    permits_forks BOOLEAN;
    permits_dependabot BOOLEAN;
    attempt_exposure TEXT;
    environment_protection TEXT;
    approval_status TEXT;
BEGIN
    SELECT
        secret.scope_kind,
        secret.repository_id,
        secret.environment_id,
        secret.status,
        policy.tenant_repository_access_mode,
        policy.minimum_event_trust,
        policy.allow_fork_pull_requests,
        policy.allow_dependabot
    INTO STRICT
        stored_scope,
        stored_repository,
        stored_environment,
        stored_secret_status,
        repository_access_mode,
        minimum_trust,
        permits_forks,
        permits_dependabot
    FROM secrets AS secret
    JOIN secret_policies AS policy
      ON policy.tenant_id = secret.tenant_id
     AND policy.secret_id = secret.id
    WHERE secret.tenant_id = NEW.tenant_id
      AND secret.id = NEW.secret_id;

    IF stored_secret_status <> 'active' THEN
        RAISE EXCEPTION 'only active secrets may be granted to workloads'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_active_secret';
    END IF;

    SELECT status
    INTO STRICT stored_version_status
    FROM secret_version_lifecycle
    WHERE tenant_id = NEW.tenant_id
      AND secret_version_id = NEW.secret_version_id;

    IF stored_version_status <> 'active' THEN
        RAISE EXCEPTION 'only active secret versions may be granted to workloads'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_active_version';
    END IF;

    IF stored_scope = 'tenant' THEN
        IF repository_access_mode = 'selected_repositories'
           AND NOT EXISTS (
               SELECT 1
               FROM secret_repository_access AS access
               WHERE access.tenant_id = NEW.tenant_id
                 AND access.secret_id = NEW.secret_id
                 AND access.repository_id = NEW.repository_id
           ) THEN
            RAISE EXCEPTION 'tenant secret is not granted to this repository'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'secret_workload_grants_scope';
        END IF;
    ELSIF stored_scope = 'repository' THEN
        IF stored_repository <> NEW.repository_id THEN
            RAISE EXCEPTION 'repository secret does not enclose this workload'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'secret_workload_grants_scope';
        END IF;
    ELSIF stored_scope = 'environment' THEN
        IF stored_repository <> NEW.repository_id
           OR stored_environment IS DISTINCT FROM NEW.environment_id THEN
            RAISE EXCEPTION 'environment secret does not enclose this workload'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'secret_workload_grants_scope';
        END IF;
    ELSE
        RAISE EXCEPTION 'unknown secret scope'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_scope';
    END IF;

    IF minimum_trust = 'trusted' AND NEW.event_trust <> 'trusted' THEN
        RAISE EXCEPTION 'secret policy rejects untrusted events'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_event_policy';
    END IF;
    IF NEW.source_kind = 'fork' AND NOT permits_forks THEN
        RAISE EXCEPTION 'secret policy rejects fork pull requests'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_event_policy';
    END IF;
    IF NEW.source_kind = 'dependabot' AND NOT permits_dependabot THEN
        RAISE EXCEPTION 'secret policy rejects Dependabot workloads'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_event_policy';
    END IF;

    SELECT secret_exposure_class
    INTO STRICT attempt_exposure
    FROM job_attempts
    WHERE id = NEW.attempt_id;

    IF NEW.grant_mode = 'readable_secret'
       AND attempt_exposure <> 'readable_secret' THEN
        RAISE EXCEPTION 'readable grants require a readable-secret attempt cap'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_exposure_class';
    END IF;
    IF NEW.grant_mode = 'capability_only'
       AND attempt_exposure = 'secretless' THEN
        RAISE EXCEPTION 'capability grants require a credential-aware attempt cap'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_exposure_class';
    END IF;

    IF NEW.environment_id IS NOT NULL THEN
        SELECT protection_mode
        INTO STRICT environment_protection
        FROM repository_environments
        WHERE tenant_id = NEW.tenant_id
          AND repository_id = NEW.repository_id
          AND id = NEW.environment_id;

        IF environment_protection = 'required_approvals' THEN
            IF NEW.environment_approval_request_id IS NULL THEN
                RAISE EXCEPTION 'protected environment approval is required'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'secret_workload_grants_environment_approval';
            END IF;
            SELECT status
            INTO STRICT approval_status
            FROM protected_environment_approval_requests
            WHERE tenant_id = NEW.tenant_id
              AND id = NEW.environment_approval_request_id;
            IF approval_status <> 'approved' THEN
                RAISE EXCEPTION 'protected environment is not approved'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'secret_workload_grants_environment_approval';
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_server_cancellation_terminal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    cancellation attempt_cancellation_intents%ROWTYPE;
    attempt job_attempts%ROWTYPE;
    expected_digest BYTEA;
BEGIN
    IF NEW.terminal_authority IS DISTINCT FROM 'server_cancellation' THEN
        RETURN NEW;
    END IF;

    SELECT * INTO STRICT cancellation
    FROM attempt_cancellation_intents
    WHERE attempt_id = NEW.attempt_id
      AND operation_id = NEW.server_cancellation_operation_id;

    SELECT * INTO STRICT attempt
    FROM job_attempts
    WHERE id = NEW.attempt_id;

    expected_digest := automata_server_cancellation_terminal_digest(
        cancellation.attempt_id,
        cancellation.operation_id,
        cancellation.requested_by,
        cancellation.reason,
        cancellation.requested_at_ms
    );
    IF cancellation.delivery_session_id IS NOT NULL
       OR cancellation.delivery_command_sequence IS NOT NULL
       OR cancellation.acknowledged_at_ms IS NOT NULL
       OR attempt.lifecycle <> 'queued'
       OR attempt.fencing_token <> 0
       OR attempt.lease_id IS NOT NULL
       OR attempt.runner_id IS NOT NULL
       OR attempt.runner_session_id IS NOT NULL
       OR attempt.runner_session_epoch IS NOT NULL
       OR attempt.runner_generation IS NOT NULL
       OR attempt.runner_slot IS NOT NULL
       OR attempt.lease_issued_at_ms IS NOT NULL
       OR attempt.lease_expires_at_ms IS NOT NULL
       OR NEW.server_cancellation_digest IS DISTINCT FROM expected_digest
       OR NEW.conclusion <> 'cancelled'
       OR NEW.completed_at_ms <> cancellation.requested_at_ms
       OR NEW.committed_at_ms <> cancellation.requested_at_ms
    THEN
        RAISE EXCEPTION 'server cancellation terminal lacks exact queued intent authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
EXCEPTION
    WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
        RAISE EXCEPTION 'server cancellation terminal lacks exact queued intent authority'
            USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_activation_publication() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_jobs AS job
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = job.run_id
         AND invocation.id = job.invocation_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN logical_workflow_activation_preparations AS preparation
          ON preparation.run_id = job.run_id
         AND preparation.invocation_id = job.invocation_id
         AND preparation.logical_job_id = job.id
        JOIN logical_workflow_activation_preparation_claims AS preparation_claim
          ON preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.state = 'prepared'
        WHERE job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.id = NEW.logical_job_id
          AND job.execution_kind = 'steps'
          AND job.state = 'activating'
          AND job.activation_owner_id = NEW.activation_owner_id
          AND job.activation_fence = NEW.activation_generation
          AND job.activation_input_digest = NEW.activation_input_digest
          AND job.activation_claimed_at_ms = NEW.activation_claimed_at_ms
          AND job.activation_expires_at_ms = NEW.activation_expires_at_ms
          AND job.activation_claimed_at_ms <= NEW.published_at_ms
          AND job.activation_expires_at_ms > NEW.published_at_ms
          AND preparation.activation_input_digest = NEW.activation_input_digest
          AND preparation.bound_at_ms <= job.activation_claimed_at_ms
          AND invocation.plan_schema = 1
          AND invocation.state IN ('pending', 'active')
          AND automata_logical_workflow_invocation_published(
              marker.run_id, invocation.id
          )
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 1
          AND run.plan_schema = 1
    ) THEN
        RAISE EXCEPTION 'logical workflow publication lacks an exact prepared live claim'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_activation_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.state = 'pending'
        AND NEW.state IN ('activated', 'skipped')
        AND EXISTS (
            SELECT 1
            FROM logical_workflow_reusable_call_publications AS publication
            WHERE publication.run_id = NEW.run_id
              AND publication.parent_invocation_id = NEW.invocation_id
              AND publication.caller_logical_job_id = NEW.id
              AND publication.child_graph_sealed_at_ms IS NOT NULL
              AND publication.activation_generation = NEW.activation_fence
              AND publication.activation_input_digest = NEW.activation_input_digest
              AND publication.authority_profile = NEW.authority_profile
              AND publication.published_at_ms = NEW.updated_at_ms
              AND NEW.state = CASE WHEN publication.condition_matched
                  THEN 'activated' ELSE 'skipped' END
        )
    THEN
        RETURN NEW;
    END IF;

    IF NEW.state IN ('completed', 'failed', 'cancelled', 'skipped')
        AND NEW.state IS DISTINCT FROM OLD.state
        AND OLD.state IN ('activated', 'skipped')
        AND EXISTS (
            SELECT 1
            FROM logical_workflow_job_results AS result
            WHERE result.run_id = NEW.run_id
              AND result.invocation_id = NEW.invocation_id
              AND result.logical_job_id = NEW.id
              AND result.finalized_at_ms = NEW.updated_at_ms
              AND NEW.state = CASE result.effective_conclusion
                  WHEN 'success' THEN 'completed'
                  WHEN 'failure' THEN 'failed'
                  WHEN 'timed_out' THEN 'failed'
                  WHEN 'cancelled' THEN 'cancelled'
                  WHEN 'skipped' THEN 'skipped'
              END
        )
    THEN
        RETURN NEW;
    END IF;

    IF NEW.state IN ('activated', 'skipped')
        AND NEW.state IS DISTINCT FROM OLD.state
        AND NOT (
            OLD.state = 'activating'
            AND NEW.activation_owner_id IS NULL
            AND NEW.activation_claimed_at_ms IS NULL
            AND NEW.activation_expires_at_ms IS NULL
            AND EXISTS (
                SELECT 1
                FROM logical_workflow_activation_publications AS publication
                WHERE publication.run_id = NEW.run_id
                  AND publication.invocation_id = NEW.invocation_id
                  AND publication.logical_job_id = NEW.id
                  AND publication.activation_owner_id = OLD.activation_owner_id
                  AND publication.activation_generation = OLD.activation_fence
                  AND publication.activation_input_digest = OLD.activation_input_digest
                  AND publication.activation_claimed_at_ms = OLD.activation_claimed_at_ms
                  AND publication.activation_expires_at_ms = OLD.activation_expires_at_ms
                  AND publication.published_at_ms = NEW.updated_at_ms
                  AND (
                      (NEW.state = 'activated' AND publication.condition_matched)
                      OR (NEW.state = 'skipped'
                          AND NOT publication.condition_matched
                          AND publication.instance_count = 0)
                  )
            )
        )
    THEN
        RAISE EXCEPTION 'logical workflow activation transition lacks exact publication'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_concrete_job() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_materialization_claims AS claim
        JOIN logical_workflow_instances AS instance
          ON instance.id = claim.instance_id
         AND instance.run_id = claim.run_id
         AND instance.invocation_id = claim.invocation_id
         AND instance.logical_job_id = claim.logical_job_id
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = instance.run_id
         AND logical_job.invocation_id = instance.invocation_id
         AND logical_job.id = instance.logical_job_id
        JOIN workflow_runs AS run ON run.id = instance.run_id
        JOIN jobs AS job ON job.id = NEW.job_id
        JOIN job_attempts AS attempt ON attempt.id = NEW.initial_attempt_id
        WHERE claim.instance_id = NEW.instance_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
          AND claim.state = 'materializing'
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.expected_job_id = NEW.job_id
          AND claim.expected_attempt_id = NEW.initial_attempt_id
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND NEW.committed_at_ms >= claim.claimed_at_ms
          AND NEW.committed_at_ms < claim.expires_at_ms
          AND logical_job.state = 'activated'
          AND run.admission_epoch = 1
          AND run.plan_schema = 1
          AND run.event_digest = NEW.event_digest
          AND run.event_object_key = NEW.event_object_key
          AND run.event_size_bytes = NEW.event_size_bytes
          AND run.event_media_type = NEW.event_media_type
          AND instance.job_ir_digest = job.job_ir_digest
          AND instance.job_ir_object_key = job.job_ir_object_key
          AND instance.job_ir_size_bytes = job.job_ir_size_bytes
          AND instance.job_ir_version = job.job_ir_schema
          AND instance.runtime_context_digest = NEW.runtime_context_digest
          AND instance.runtime_context_object_key =
              NEW.runtime_context_object_key
          AND instance.runtime_context_size_bytes =
              NEW.runtime_context_size_bytes
          AND instance.runtime_context_media_type =
              NEW.runtime_context_media_type
          AND instance.runtime_context_schema = NEW.runtime_context_schema
          AND job.run_id = NEW.run_id
          AND job.job_key = NEW.job_key
          AND job.display_name = NEW.display_name
          AND job.requirements = NEW.requirements
          AND job.admission_epoch = 1
          AND job.job_ir_schema = 1
          AND attempt.job_id = job.id
          AND attempt.attempt_number = 1
          AND attempt.lifecycle = 'queued'
          AND attempt.fencing_token = 0
          AND attempt.lease_id IS NULL
          AND attempt.runner_id IS NULL
          AND attempt.lease_issued_at_ms IS NULL
          AND attempt.lease_expires_at_ms IS NULL
          AND attempt.lease_failures = 0
          AND attempt.queued_at_ms = NEW.committed_at_ms
          AND attempt.changed_at_ms = NEW.committed_at_ms
    ) THEN
        RAISE EXCEPTION 'logical workflow concrete job lacks exact live materialization evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_concurrency_cancellation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_runs AS target
        JOIN logical_workflow_runs AS marker ON marker.run_id = target.id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_runs AS preempting ON preempting.id = NEW.preempting_run_id
        WHERE target.id = NEW.run_id
          AND target.repository_id = preempting.repository_id
          AND target.concurrency_group_key IS NOT NULL
          AND target.concurrency_group_key = preempting.concurrency_group_key
          AND target.status = NEW.prior_workflow_status
          AND target.updated_at_ms = NEW.prior_workflow_updated_at_ms
          AND marker.root_invocation_id = NEW.root_invocation_id
          AND marker.state = NEW.prior_marker_state
          AND marker.revision = NEW.prior_marker_revision
          AND marker.updated_at_ms = NEW.prior_marker_updated_at_ms
          AND invocation.state = NEW.prior_invocation_state
          AND invocation.revision = NEW.prior_invocation_revision
          AND invocation.updated_at_ms = NEW.prior_invocation_updated_at_ms
          AND preempting.status IN ('queued', 'in_progress')
          AND preempting.created_at_ms <= NEW.cancelled_at_ms
        FOR KEY SHARE OF target, marker, invocation, preempting
    ) THEN
        RAISE EXCEPTION 'Logical concurrency cancellation lacks exact active-run evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_concurrency_cancellation_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_instance() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    expected_count INTEGER;
    expected_time BIGINT;
BEGIN
    SELECT publication.instance_count, publication.published_at_ms
      INTO expected_count, expected_time
    FROM logical_workflow_activation_publications AS publication
    WHERE publication.run_id = NEW.run_id
      AND publication.invocation_id = NEW.invocation_id
      AND publication.logical_job_id = NEW.logical_job_id;
    IF NOT FOUND
        OR expected_count = 0
        OR NEW.matrix_total <> expected_count
        OR NEW.matrix_index >= expected_count
        OR NEW.created_at_ms <> expected_time
    THEN
        RAISE EXCEPTION 'logical workflow instance disagrees with its publication'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_instance_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    target_run UUID;
    target_invocation UUID;
    target_job UUID;
    expected_count INTEGER;
    actual_count BIGINT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_run := OLD.run_id;
        target_invocation := OLD.invocation_id;
        target_job := OLD.logical_job_id;
    ELSE
        target_run := NEW.run_id;
        target_invocation := NEW.invocation_id;
        target_job := NEW.logical_job_id;
    END IF;
    SELECT publication.instance_count
      INTO expected_count
    FROM logical_workflow_activation_publications AS publication
    WHERE publication.run_id = target_run
      AND publication.invocation_id = target_invocation
      AND publication.logical_job_id = target_job;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT count(*) INTO actual_count
    FROM logical_workflow_instances AS instance
    WHERE instance.run_id = target_run
      AND instance.invocation_id = target_invocation
      AND instance.logical_job_id = target_job;
    IF actual_count <> expected_count THEN
        RAISE EXCEPTION 'logical workflow publication instance count is incomplete'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_instance_result() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_instance_result_claims AS claim
        JOIN attempt_terminal_results AS terminal
          ON terminal.attempt_id = claim.attempt_id
        JOIN job_attempts AS attempt ON attempt.id = terminal.attempt_id
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.instance_id = claim.instance_id
         AND concrete.job_id = claim.job_id
         AND concrete.initial_attempt_id = claim.attempt_id
        JOIN logical_workflow_instances AS instance
          ON instance.id = concrete.instance_id
        JOIN workflow_runs AS run ON run.id = concrete.run_id
        WHERE claim.attempt_id = NEW.attempt_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
          AND claim.instance_id = NEW.instance_id
          AND claim.job_id = NEW.job_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.state = 'projecting'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND NEW.finalized_at_ms >= claim.claimed_at_ms
          AND NEW.finalized_at_ms < claim.expires_at_ms
          AND terminal.terminal_authority = NEW.terminal_authority
          AND (
              (
                  terminal.terminal_authority = 'runner'
                  AND terminal.result_digest = NEW.result_digest
                  AND terminal.result_object_key = NEW.result_object_key
                  AND terminal.result_size_bytes = NEW.result_size_bytes
                  AND terminal.result_schema = NEW.result_schema
                  AND NEW.server_cancellation_operation_id IS NULL
                  AND NEW.server_cancellation_digest IS NULL
                  AND (
                      (attempt.secret_exposure_class = 'secretless'
                       AND NEW.secret_exposure_class = 'secretless')
                      OR (attempt.secret_exposure_class = 'capability_only'
                          AND NEW.secret_exposure_class IN (
                              'secretless', 'capability_only'
                          ))
                      OR (attempt.secret_exposure_class = 'readable_secret'
                          AND NEW.secret_exposure_class = 'readable_secret')
                  )
              ) OR (
                  terminal.terminal_authority = 'server_cancellation'
                  AND terminal.server_cancellation_operation_id =
                      NEW.server_cancellation_operation_id
                  AND terminal.server_cancellation_digest =
                      NEW.server_cancellation_digest
                  AND NEW.result_digest IS NULL
                  AND NEW.result_object_key IS NULL
                  AND NEW.result_size_bytes IS NULL
                  AND NEW.result_schema IS NULL
                  AND NEW.secret_exposure_class = 'secretless'
                  AND NEW.output_count = 0
              )
          )
          AND terminal.conclusion = NEW.raw_conclusion
          AND terminal.completed_at_ms = NEW.result_completed_at_ms
          AND terminal.committed_at_ms = NEW.result_committed_at_ms
          AND terminal.logical_workflow_logical_job_id = NEW.logical_job_id
          AND terminal.logical_workflow_terminal_ordinal = NEW.terminal_ordinal
          AND job.run_id = NEW.run_id
          AND job.job_ir_digest = NEW.job_ir_digest
          AND job.job_ir_object_key = NEW.job_ir_object_key
          AND job.job_ir_size_bytes = NEW.job_ir_size_bytes
          AND job.job_ir_schema = NEW.job_ir_schema
          AND job.admission_epoch = 1
          AND instance.run_id = NEW.run_id
          AND instance.invocation_id = NEW.invocation_id
          AND instance.logical_job_id = NEW.logical_job_id
          AND instance.job_ir_digest = NEW.job_ir_digest
          AND instance.job_ir_object_key = NEW.job_ir_object_key
          AND instance.job_ir_size_bytes = NEW.job_ir_size_bytes
          AND instance.job_ir_media_type = NEW.job_ir_media_type
          AND instance.job_ir_version = NEW.job_ir_schema
          AND run.admission_epoch = 1
          AND run.plan_schema = 1
    ) THEN
        RAISE EXCEPTION 'logical workflow instance result lacks exact terminal authority/fence evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_instance_result_claim() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM attempt_terminal_results AS terminal
        JOIN job_attempts AS attempt ON attempt.id = terminal.attempt_id
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.job_id = job.id
         AND concrete.initial_attempt_id = attempt.id
        JOIN logical_workflow_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
        JOIN logical_workflow_instances AS instance
          ON instance.id = concrete.instance_id
         AND instance.run_id = concrete.run_id
         AND instance.invocation_id = concrete.invocation_id
         AND instance.logical_job_id = concrete.logical_job_id
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = logical_job.run_id
         AND invocation.id = logical_job.invocation_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = concrete.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE terminal.attempt_id = NEW.attempt_id
          AND concrete.run_id = NEW.run_id
          AND concrete.invocation_id = NEW.invocation_id
          AND concrete.logical_job_id = NEW.logical_job_id
          AND concrete.instance_id = NEW.instance_id
          AND concrete.job_id = NEW.job_id
          AND materialization.state = 'materialized'
          AND job.run_id = concrete.run_id
          AND job.admission_epoch = 1
          AND job.job_ir_schema = 1
          AND job.job_ir_digest = instance.job_ir_digest
          AND job.job_ir_object_key = instance.job_ir_object_key
          AND job.job_ir_size_bytes = instance.job_ir_size_bytes
          AND instance.job_ir_version = 1
          AND instance.job_ir_media_type =
              'application/vnd.automata.job-ir.protobuf'
          AND (
              (terminal.terminal_authority = 'runner'
               AND terminal.result_schema = 1)
              OR terminal.terminal_authority = 'server_cancellation'
          )
          AND terminal.completed_at_ms >= 0
          AND terminal.committed_at_ms >= terminal.completed_at_ms
          AND NEW.claimed_at_ms >= terminal.committed_at_ms
          AND (
              (terminal.conclusion = 'success' AND attempt.lifecycle = 'succeeded')
              OR (terminal.conclusion = 'failure' AND attempt.lifecycle = 'failed')
              OR (terminal.conclusion = 'cancelled' AND attempt.lifecycle = 'cancelled')
              OR (terminal.conclusion = 'timed_out' AND attempt.lifecycle = 'timed_out')
              OR (terminal.conclusion = 'skipped' AND attempt.lifecycle = 'skipped')
          )
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND invocation.plan_schema = 1
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 1
          AND run.plan_schema = 1
    ) THEN
        RAISE EXCEPTION 'logical workflow result claim lacks one exact current terminal attempt'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_instance_result_output() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_instance_results AS result
        JOIN logical_workflow_instance_result_claims AS claim
          ON claim.instance_id = result.instance_id
        WHERE result.instance_id = NEW.instance_id
          AND claim.state = 'projecting'
          AND result.claim_owner_id = claim.owner_id
          AND result.claim_generation = claim.generation
          AND result.claim_started_at_ms = claim.claimed_at_ms
          AND result.claim_expires_at_ms = claim.expires_at_ms
    ) THEN
        RAISE EXCEPTION 'logical workflow output lacks a live instance-result fence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_instance_result_quarantine() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    current_due logical_workflow_instance_result_due%ROWTYPE;
BEGIN
    SELECT due.* INTO current_due
    FROM logical_workflow_instance_result_due AS due
    WHERE due.attempt_id = NEW.attempt_id
    FOR UPDATE;
    IF NOT FOUND OR ROW(
        NEW.tenant_id, NEW.run_id, NEW.invocation_id, NEW.logical_job_id,
        NEW.source_order, NEW.ready_at_ms, NEW.available_at_ms
    ) IS DISTINCT FROM ROW(
        current_due.tenant_id, current_due.run_id, current_due.invocation_id,
        current_due.logical_job_id, current_due.source_order,
        current_due.ready_at_ms, current_due.available_at_ms
    ) THEN
        RAISE EXCEPTION 'instance-result quarantine lacks its exact current due target'
            USING ERRCODE = '23514',
                  CONSTRAINT =
                      'logical_workflow_instance_result_quarantines_due_exact';
    END IF;

    IF NEW.claim_owner_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM logical_workflow_instance_result_claims AS claim
        WHERE claim.attempt_id = NEW.attempt_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
          AND claim.state = 'projecting'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_claimed_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND claim.descriptor_digest = NEW.claim_descriptor_digest
    ) THEN
        RAISE EXCEPTION 'instance-result quarantine lacks its exact live claim'
            USING ERRCODE = '23514',
                  CONSTRAINT =
                      'logical_workflow_instance_result_quarantines_claim_exact';
    END IF;

    NEW.quarantined_at_ms :=
        floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_job_result() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_job_result_claims AS claim
        JOIN logical_workflow_jobs AS job
          ON job.id = claim.logical_job_id
         AND job.run_id = claim.run_id
         AND job.invocation_id = claim.invocation_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = job.run_id
         AND invocation.id = job.invocation_id
        JOIN logical_workflow_activation_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.invocation_id = job.invocation_id
         AND publication.logical_job_id = job.id
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.state = 'aggregating'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND NEW.finalized_at_ms >= claim.claimed_at_ms
          AND NEW.finalized_at_ms < claim.expires_at_ms
          AND job.logical_key = NEW.logical_key
          AND job.source_order = NEW.source_order
          AND job.execution_kind = 'steps'
          AND job.state IN ('activated', 'skipped')
          AND invocation.plan_digest = NEW.plan_digest
          AND invocation.plan_object_key = NEW.plan_object_key
          AND invocation.plan_size_bytes = NEW.plan_size_bytes
          AND invocation.plan_media_type = NEW.plan_media_type
          AND invocation.plan_schema = NEW.plan_schema
          AND publication.activation_output_digest = NEW.activation_output_digest
          AND publication.condition_matched = NEW.condition_matched
          AND publication.instance_count = NEW.instance_count
    ) AND NOT EXISTS (
        SELECT 1
        FROM logical_workflow_job_result_claims AS claim
        JOIN logical_workflow_jobs AS job
          ON job.id = claim.logical_job_id
         AND job.run_id = claim.run_id
         AND job.invocation_id = claim.invocation_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = job.run_id
         AND invocation.id = job.invocation_id
        JOIN logical_workflow_reusable_call_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.parent_invocation_id = job.invocation_id
         AND publication.caller_logical_job_id = job.id
        JOIN logical_workflow_reusable_call_results AS call_result
          ON call_result.run_id = publication.run_id
         AND call_result.parent_invocation_id = publication.parent_invocation_id
         AND call_result.caller_logical_job_id = publication.caller_logical_job_id
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.state = 'aggregating'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND NEW.finalized_at_ms >= claim.claimed_at_ms
          AND NEW.finalized_at_ms < claim.expires_at_ms
          AND job.logical_key = NEW.logical_key
          AND job.source_order = NEW.source_order
          AND job.execution_kind = 'reusable_workflow'
          AND job.state IN ('activated', 'skipped')
          AND invocation.plan_digest = NEW.plan_digest
          AND invocation.plan_object_key = NEW.plan_object_key
          AND invocation.plan_size_bytes = NEW.plan_size_bytes
          AND invocation.plan_media_type = NEW.plan_media_type
          AND invocation.plan_schema = NEW.plan_schema
          AND publication.publication_digest = NEW.activation_output_digest
          AND publication.condition_matched = NEW.condition_matched
          AND NEW.instance_count = CASE WHEN publication.condition_matched
              THEN 1 ELSE 0 END
          AND call_result.sealed_at_ms IS NOT NULL
          AND call_result.parent_result_descriptor_digest = NEW.descriptor_digest
          AND call_result.parent_instances_digest = NEW.instances_digest
          AND call_result.parent_prerequisites_digest = NEW.prerequisites_digest
          AND call_result.parent_outputs_digest = NEW.outputs_digest
          AND call_result.parent_commit_digest = NEW.commit_digest
          AND call_result.effective_conclusion = NEW.effective_conclusion
          AND NEW.output_count = CASE WHEN publication.condition_matched
              THEN publication.output_mapping_count ELSE 0 END
          AND NEW.prerequisite_count = (
              SELECT count(*)
              FROM logical_workflow_dependencies AS dependency
              WHERE dependency.run_id = job.run_id
                AND dependency.invocation_id = job.invocation_id
                AND dependency.logical_job_id = job.id
          )
    ) THEN
        RAISE EXCEPTION 'logical workflow job result lacks exact plan/publication/fence evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_workflow_job_result_claim() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_jobs AS job
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = job.run_id
         AND invocation.id = job.invocation_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN logical_workflow_activation_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.invocation_id = job.invocation_id
         AND publication.logical_job_id = job.id
        WHERE job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.id = NEW.logical_job_id
          AND job.execution_kind = 'steps'
          AND job.state IN ('activated', 'skipped')
          AND invocation.plan_schema = 1
          AND invocation.plan_media_type =
              'application/vnd.automata.workflow-plan+json'
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 1
          AND run.plan_schema = 1
          AND NEW.claimed_at_ms >= publication.published_at_ms
          AND (
              (publication.instance_count = 0 AND NOT EXISTS (
                  SELECT 1 FROM logical_workflow_instances AS instance
                  WHERE instance.run_id = job.run_id
                    AND instance.invocation_id = job.invocation_id
                    AND instance.logical_job_id = job.id
              )) OR (
                  publication.instance_count > 0
                  AND publication.instance_count = (
                      SELECT count(*)
                      FROM logical_workflow_instances AS instance
                      JOIN logical_workflow_instance_results AS result
                        ON result.instance_id = instance.id
                       AND result.run_id = instance.run_id
                       AND result.invocation_id = instance.invocation_id
                       AND result.logical_job_id = instance.logical_job_id
                      JOIN logical_workflow_instance_result_claims AS claim
                        ON claim.instance_id = result.instance_id
                       AND claim.state = 'finalized'
                      WHERE instance.run_id = job.run_id
                        AND instance.invocation_id = job.invocation_id
                        AND instance.logical_job_id = job.id
                  )
                  AND NEW.claimed_at_ms >= COALESCE((
                      SELECT max(result.finalized_at_ms)
                      FROM logical_workflow_instance_results AS result
                      WHERE result.run_id = job.run_id
                        AND result.invocation_id = job.invocation_id
                        AND result.logical_job_id = job.id
                  ), 0)
              )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM logical_workflow_dependencies AS dependency
              LEFT JOIN logical_workflow_effective_job_results AS prerequisite
                ON prerequisite.logical_job_id = dependency.prerequisite_job_id
               AND prerequisite.run_id = dependency.run_id
               AND prerequisite.invocation_id = dependency.invocation_id
              WHERE dependency.run_id = job.run_id
                AND dependency.invocation_id = job.invocation_id
                AND dependency.logical_job_id = job.id
                AND (prerequisite.logical_job_id IS NULL
                     OR prerequisite.claim_state IS DISTINCT FROM 'finalized'
                     OR NEW.claimed_at_ms < prerequisite.finalized_at_ms)
          )
    ) AND NOT EXISTS (
        SELECT 1
        FROM logical_workflow_jobs AS job
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = job.run_id
         AND invocation.id = job.invocation_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN logical_workflow_reusable_call_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.parent_invocation_id = job.invocation_id
         AND publication.caller_logical_job_id = job.id
        JOIN logical_workflow_reusable_call_results AS call_result
          ON call_result.run_id = publication.run_id
         AND call_result.parent_invocation_id = publication.parent_invocation_id
         AND call_result.caller_logical_job_id = publication.caller_logical_job_id
        WHERE job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.id = NEW.logical_job_id
          AND job.execution_kind = 'reusable_workflow'
          AND job.state IN ('activated', 'skipped')
          AND invocation.plan_schema = 1
          AND invocation.plan_media_type =
              'application/vnd.automata.workflow-plan+json'
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 1
          AND run.plan_schema = 1
          AND publication.child_graph_sealed_at_ms IS NOT NULL
          AND call_result.sealed_at_ms IS NOT NULL
          AND call_result.parent_result_descriptor_digest = NEW.descriptor_digest
          AND NEW.claimed_at_ms >= call_result.completed_at_ms
          AND NOT EXISTS (
              SELECT 1
              FROM logical_workflow_dependencies AS dependency
              LEFT JOIN logical_workflow_effective_job_results AS prerequisite
                ON prerequisite.logical_job_id = dependency.prerequisite_job_id
               AND prerequisite.run_id = dependency.run_id
               AND prerequisite.invocation_id = dependency.invocation_id
              WHERE dependency.run_id = job.run_id
                AND dependency.invocation_id = job.invocation_id
                AND dependency.logical_job_id = job.id
                AND (prerequisite.logical_job_id IS NULL
                     OR prerequisite.claim_state IS DISTINCT FROM 'finalized'
                     OR NEW.claimed_at_ms < prerequisite.finalized_at_ms)
          )
    ) THEN
        RAISE EXCEPTION 'logical workflow job-result claim is not exactly ready'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
