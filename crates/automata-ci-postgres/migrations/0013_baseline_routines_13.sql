-- Frozen greenfield baseline. Add a new migration instead of editing this stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_validate_github_runtime_authority_lease_renewal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now BIGINT;
BEGIN
    -- Match the Store's global runner/session -> attempt -> authority order.
    -- These separate row-lock phases also make direct SQL writers deterministic
    -- instead of relying on a multi-relation plan's row-mark order.
    PERFORM 1
    FROM runners AS runner
    JOIN runner_sessions AS session
      ON session.runner_id = runner.id
     AND session.id = NEW.runner_session_id
     AND session.session_epoch = NEW.runner_session_epoch
     AND session.runner_generation = NEW.runner_generation
    WHERE runner.id = NEW.runner_id
      AND runner.generation = NEW.runner_generation
      AND runner.session_epoch = NEW.runner_session_epoch
      AND runner.status = 'online'
      AND runner.desired_state IN ('active', 'draining')
      AND session.disconnected_at_ms IS NULL
      AND session.job_ir_schema = 1
    FOR SHARE OF runner, session;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'GitHub runtime authority lease renewal lacks a live runner session'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_lease_renewal_receipts_authority';
    END IF;

    PERFORM 1
    FROM job_attempts AS attempt
    WHERE attempt.id = NEW.attempt_id
      AND attempt.fencing_token = NEW.fencing_token
      AND attempt.lease_id = NEW.lease_id
      AND attempt.lease_expires_at_ms = NEW.previous_lease_expires_at_ms
      AND attempt.runner_id = NEW.runner_id
      AND attempt.runner_session_id = NEW.runner_session_id
      AND attempt.runner_session_epoch = NEW.runner_session_epoch
      AND attempt.runner_generation = NEW.runner_generation
      AND attempt.lifecycle IN ('leased', 'preparing', 'running', 'cancelling')
      AND attempt.changed_at_ms <= NEW.authorized_at_ms
    FOR UPDATE OF attempt;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'GitHub runtime authority lease renewal lacks the exact current attempt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_lease_renewal_receipts_authority';
    END IF;

    -- Sample after every preceding row lock. A writer that queued while the
    -- predecessor was live must not renew it after waiting past its horizon.
    database_now := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    IF NEW.authorized_at_ms > database_now
        OR NEW.previous_lease_expires_at_ms <= database_now
    THEN
        RAISE EXCEPTION 'GitHub runtime authority lease renewal uses a stale lease horizon'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_lease_renewal_receipts_authority';
    END IF;

    PERFORM 1
    FROM github_runtime_authority_issuances AS authority
    JOIN job_attempts AS exact_attempt
      ON exact_attempt.id = authority.attempt_id
     AND exact_attempt.job_id = authority.job_id
    WHERE authority.attempt_id = NEW.attempt_id
      AND authority.fencing_token = NEW.fencing_token
      AND authority.lease_id = NEW.lease_id
      AND authority.runner_id = NEW.runner_id
      AND authority.runner_session_id = NEW.runner_session_id
      AND authority.runner_session_epoch = NEW.runner_session_epoch
      AND authority.runner_generation = NEW.runner_generation
      AND authority.state = 'ready'
      AND authority.ready_at_ms <= NEW.authorized_at_ms
      AND authority.provider_expires_at_ms IS NOT NULL
      AND authority.provider_expires_at_ms - 60000
            >= NEW.renewed_lease_expires_at_ms
      AND exact_attempt.fencing_token = authority.fencing_token
      AND exact_attempt.lease_id = authority.lease_id
      AND exact_attempt.lease_issued_at_ms = authority.lease_issued_at_ms
      AND automata_github_runtime_authority_lease_horizon_is_tail(
          authority,
          NEW.previous_lease_expires_at_ms,
          NEW.authorized_at_ms
      )
    FOR SHARE OF authority;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'GitHub runtime authority lease renewal lacks exact durable authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_lease_renewal_receipts_authority';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_github_runtime_authority_operation_receipt() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM github_runtime_authority_operation_transitions AS transition
        WHERE transition.attempt_id = NEW.attempt_id
          AND transition.fencing_token = NEW.fencing_token
          AND transition.tenant_id = NEW.tenant_id
          AND transition.operation_kind = NEW.operation_kind
          AND transition.claim_fence = NEW.claim_fence
          AND transition.operation_digest = NEW.operation_digest
          AND transition.disposition = NEW.disposition
          AND transition.claim_owner_id IS NOT DISTINCT FROM NEW.claim_owner_id
          AND transition.claim_claimed_at_ms
              IS NOT DISTINCT FROM NEW.claim_claimed_at_ms
          AND transition.claim_expires_at_ms
              IS NOT DISTINCT FROM NEW.claim_expires_at_ms
          AND transition.result_state = NEW.result_state
          AND transition.result_updated_at_ms = NEW.result_updated_at_ms
          AND transition.result_terminal_reason
              IS NOT DISTINCT FROM NEW.result_terminal_reason
        FOR KEY SHARE
    ) THEN
        RAISE EXCEPTION 'GitHub runtime-authority receipt lacks its canonical transition'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_operation_receipt_transition_exact';
    END IF;
    NEW.applied_at_ms := database_now;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_github_runtime_authority_identity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM 1
    FROM job_attempts AS attempt
    JOIN jobs AS job
      ON job.id = attempt.job_id
     AND job.id = NEW.job_id
     AND job.run_id = NEW.run_id
    JOIN workflow_runs AS run
      ON run.id = job.run_id
     AND run.repository_id = NEW.repository_id
    JOIN repositories AS repository
      ON repository.id = run.repository_id
     AND repository.tenant_id = NEW.tenant_id
    JOIN workflow_definitions AS workflow
      ON workflow.id = run.workflow_id
     AND workflow.repository_id = run.repository_id
    JOIN workflow_snapshots AS snapshot
      ON snapshot.id = run.snapshot_id
     AND snapshot.workflow_id = run.workflow_id
    JOIN logical_workflow_concrete_jobs AS concrete
      ON concrete.run_id = run.id
     AND concrete.job_id = job.id
    JOIN logical_workflow_invocations AS invocation
      ON invocation.run_id = concrete.run_id
     AND invocation.id = concrete.invocation_id
    JOIN logical_workflow_runs AS marker
      ON marker.run_id = concrete.run_id
    JOIN runners AS runner
      ON runner.id = NEW.runner_id
     AND runner.tenant_id = repository.tenant_id
    JOIN runner_sessions AS session
      ON session.id = NEW.runner_session_id
     AND session.runner_id = runner.id
    WHERE attempt.id = NEW.attempt_id
      AND attempt.job_id = NEW.job_id
      AND job.job_ir_schema = NEW.job_ir_schema
      AND job.job_ir_size_bytes = NEW.job_ir_size_bytes
      AND job.job_ir_digest = NEW.job_ir_digest
      AND job.job_ir_digest = NEW.policy_digest
      AND repository.scm_provider = 'github'
      AND repository.provider_repository_id = NEW.github_repository_id::TEXT
      AND repository.owner || '/' || repository.name = NEW.github_repository_name
      AND runner.id = NEW.runner_id
      AND session.id = NEW.runner_session_id
      AND session.session_epoch = NEW.runner_session_epoch
      AND session.runner_generation = NEW.runner_generation
      AND invocation.plan_schema = 1
      AND automata_logical_workflow_invocation_published(
          run.id, invocation.id
      )
    FOR SHARE OF attempt, job, run, repository, workflow, snapshot, concrete,
                 invocation, marker, runner, session;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'GitHub runtime authority lacks exact execution provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_execution_provenance';
    END IF;

    IF NOT automata_github_runtime_authority_has_provenance(NEW) THEN
        RAISE EXCEPTION 'GitHub runtime authority lacks exact historical policy provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_historical_provenance';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_github_workflow_rerun_subject_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    exact BOOLEAN;
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
    JOIN workflow_runs AS run
      ON run.id = attempt.run_id
     AND run.repository_id = request.repository_id
    JOIN workflow_definitions AS workflow
      ON workflow.repository_id = run.repository_id
     AND workflow.id = run.workflow_id
    JOIN workflow_snapshots AS snapshot
      ON snapshot.id = run.snapshot_id
     AND snapshot.workflow_id = run.workflow_id
    JOIN logical_workflow_runs AS marker ON marker.run_id = run.id
    JOIN workflow_rerun_check_evidence AS check_evidence
      ON check_evidence.tenant_id = request.tenant_id
     AND check_evidence.operation_id = request.operation_id
     AND check_evidence.run_id = attempt.run_id
     AND check_evidence.source_run_id = attempt.source_run_id
    JOIN github_check_subjects AS subject
      ON subject.tenant_id = check_evidence.tenant_id
     AND subject.id = check_evidence.github_check_subject_id
     AND subject.workflow_rerun_run_id = check_evidence.run_id
    JOIN github_workflow_run_base_manifest_origins AS origin
      ON origin.tenant_id = request.tenant_id
     AND origin.repository_id = request.repository_id
     AND origin.run_id = attempt.root_run_id
     AND origin.provider_connection_id = check_evidence.provider_connection_id
     AND origin.provider_manifest_revision =
         check_evidence.provider_manifest_revision
     AND origin.provider_manifest_digest = check_evidence.provider_manifest_digest
    WHERE attempt.run_id = NEW.run_id
      AND attempt.source_run_id = NEW.source_run_id
      AND attempt.source_run_id IS NOT NULL
      AND request.repository_id = NEW.repository_id
      AND request.committed_at_ms = NEW.admitted_at_ms
      AND request.committed_at_ms = attempt.created_at_ms
      AND run.workflow_id = NEW.workflow_id
      AND run.snapshot_id = NEW.snapshot_id
      AND run.head_sha = NEW.github_check_head_sha
      AND run.event_name = NEW.event_name
      AND run.event_digest = NEW.event_digest
      AND run.git_ref = NEW.git_ref
      AND run.plan_schema = NEW.workflow_plan_schema
      AND run.plan_digest = NEW.plan_digest
      AND run.created_at_ms = NEW.admitted_at_ms
      AND run.status = 'queued'
      AND workflow.path = NEW.workflow_path
      AND snapshot.source_digest = NEW.source_digest
      AND marker.root_invocation_id = NEW.root_invocation_id
      AND marker.admission_digest = NEW.logical_admission_digest
      AND marker.admitted_at_ms = NEW.admitted_at_ms
      AND check_evidence.github_check_subject_id =
          NEW.github_check_subject_id
      AND check_evidence.github_check_head_sha = NEW.github_check_head_sha
      AND check_evidence.recorded_at_ms = NEW.admitted_at_ms
      AND subject.workflow_run_id = run.id
      AND subject.linked_at_ms = NEW.admitted_at_ms
      AND subject.desired_state = 'in_progress'
      AND subject.desired_conclusion IS NULL
      AND subject.terminal_cause IS NULL
      AND subject.desired_revision = 2
      AND subject.desired_updated_at_ms = NEW.admitted_at_ms
      AND origin.github_check_head_sha = NEW.github_check_head_sha
      AND origin.github_repository_owner_id =
          NEW.github_repository_owner_id
      AND origin.workflow_path = NEW.workflow_path
      AND origin.source_digest = NEW.source_digest
      AND origin.event_name = NEW.event_name
      AND origin.event_digest = NEW.event_digest
      AND origin.git_ref = NEW.git_ref
      AND origin.workflow_plan_schema = NEW.workflow_plan_schema
      AND origin.plan_digest = NEW.plan_digest
    FOR KEY SHARE OF attempt, request, receipt, run, workflow, snapshot,
                     marker, check_evidence, subject;

    IF exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'GitHub workflow rerun run-subject evidence is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_rerun_subject_evidence_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_job_credential_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    gate job_environment_gates%ROWTYPE;
    logical_job logical_workflow_jobs%ROWTYPE;
BEGIN
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.attempt_id FOR SHARE;
    SELECT * INTO STRICT logical_job FROM logical_workflow_jobs
    WHERE run_id = gate.run_id AND invocation_id = gate.invocation_id
      AND id = gate.logical_job_id;
    IF TG_TABLE_NAME LIKE '%secret%' THEN
        IF NOT NEW.canonical_name = ANY(logical_job.secret_reference_names) THEN
            RAISE EXCEPTION 'secret binding was not declared by the logical job'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'job_secret_bindings_declared';
        END IF;
    ELSE
        IF NOT NEW.canonical_name = ANY(logical_job.variable_reference_names) THEN
            RAISE EXCEPTION 'variable binding was not declared by the logical job'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'job_variable_bindings_declared';
        END IF;
    END IF;
    IF gate.state <> 'resolving' THEN
        RAISE EXCEPTION 'credential bindings require a live resolving gate'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_credential_bindings_gate_live';
    END IF;
    IF TG_TABLE_NAME = 'job_secret_selections' AND EXISTS (
        SELECT 1 FROM job_missing_secret_bindings
        WHERE attempt_id = NEW.attempt_id AND canonical_name = NEW.canonical_name
    ) OR TG_TABLE_NAME = 'job_missing_secret_bindings' AND EXISTS (
        SELECT 1 FROM job_secret_selections
        WHERE attempt_id = NEW.attempt_id AND canonical_name = NEW.canonical_name
    ) OR TG_TABLE_NAME = 'job_variable_bindings' AND EXISTS (
        SELECT 1 FROM job_missing_variable_bindings
        WHERE attempt_id = NEW.attempt_id AND canonical_name = NEW.canonical_name
    ) OR TG_TABLE_NAME = 'job_missing_variable_bindings' AND EXISTS (
        SELECT 1 FROM job_variable_bindings
        WHERE attempt_id = NEW.attempt_id AND canonical_name = NEW.canonical_name
    ) THEN
        RAISE EXCEPTION 'credential name already has an opposite resolution'
            USING ERRCODE = 'unique_violation',
                  CONSTRAINT = 'job_credential_bindings_one_resolution';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_job_environment_activation_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    instance logical_workflow_instances%ROWTYPE;
    logical_job logical_workflow_jobs%ROWTYPE;
    root_invocation UUID;
    all_reusable_secret_references_bound BOOLEAN;
BEGIN
    SELECT * INTO STRICT instance
    FROM logical_workflow_instances
    WHERE id = NEW.instance_id
    FOR SHARE;
    SELECT * INTO STRICT logical_job
    FROM logical_workflow_jobs
    WHERE run_id = instance.run_id
      AND invocation_id = instance.invocation_id
      AND id = instance.logical_job_id
    FOR SHARE;
    SELECT marker.root_invocation_id INTO STRICT root_invocation
    FROM logical_workflow_runs AS marker
    WHERE marker.run_id = instance.run_id
    FOR SHARE;
    SELECT NOT EXISTS (
        SELECT 1
        FROM unnest(logical_job.secret_reference_names) AS referenced_secret(name)
        WHERE NOT automata_reusable_secret_identity_chain_is_exact(
            instance.run_id,
            instance.invocation_id,
            referenced_secret.name
        )
    ) INTO all_reusable_secret_references_bound;

    IF NEW.created_at_ms <> instance.created_at_ms
       OR logical_job.environment_requirement_kind = 'unclassified'
       OR (
           logical_job.environment_requirement_kind = 'environment'
           AND NEW.environment_normalized_name IS NULL
       )
       OR (
           logical_job.environment_requirement_kind = 'none'
           AND NEW.environment_normalized_name IS NOT NULL
       )
       OR (
           instance.invocation_id = root_invocation
           AND NEW.reusable_secret_permission <> 'none'
       )
       OR (
           instance.invocation_id <> root_invocation
           AND cardinality(logical_job.secret_reference_names) > 0
           AND (
               NOT all_reusable_secret_references_bound
               OR NEW.reusable_secret_permission <> 'explicit'
           )
       )
       OR (
           instance.invocation_id <> root_invocation
           AND cardinality(logical_job.secret_reference_names) = 0
           AND NEW.reusable_secret_permission <> 'none'
       ) THEN
        RAISE EXCEPTION 'activation environment evidence is not exact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_environment_evidence_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_job_secret_binding_exact() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    gate job_environment_gates%ROWTYPE;
    selection job_secret_selections%ROWTYPE;
    workload_grant secret_workload_grants%ROWTYPE;
    attempt job_attempts%ROWTYPE;
    database_now_ms BIGINT;
    expected_digest BYTEA;
BEGIN
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.attempt_id FOR SHARE;
    SELECT * INTO STRICT selection FROM job_secret_selections
    WHERE attempt_id = NEW.attempt_id AND canonical_name = NEW.canonical_name FOR SHARE;
    SELECT * INTO STRICT workload_grant FROM secret_workload_grants
    WHERE tenant_id = NEW.tenant_id AND id = NEW.grant_id FOR SHARE;
    SELECT * INTO STRICT attempt FROM job_attempts
    WHERE id = NEW.attempt_id FOR SHARE;
    expected_digest := automata_job_secret_binding_digest(
        NEW.attempt_id, NEW.canonical_name, NEW.tenant_id, NEW.grant_id,
        NEW.lease_id, NEW.fencing_token
    );
    IF attempt.lifecycle <> 'leased'
       OR attempt.lease_id <> NEW.lease_id
       OR attempt.fencing_token <> NEW.fencing_token
       OR attempt.lease_expires_at_ms IS NULL
       OR database_now_ms >= attempt.lease_expires_at_ms
       OR selection.tenant_id <> NEW.tenant_id
       OR workload_grant.repository_id <> gate.repository_id
       OR workload_grant.run_id <> gate.run_id
       OR workload_grant.job_id <> gate.job_id
       OR workload_grant.attempt_id <> gate.attempt_id
       OR workload_grant.secret_id <> selection.secret_id
       OR workload_grant.secret_version_id <> selection.secret_version_id
       OR workload_grant.secret_version_number <> selection.secret_version_number
       OR workload_grant.environment_id IS DISTINCT FROM gate.environment_id
       OR workload_grant.environment_approval_request_id IS DISTINCT FROM gate.approval_request_id
       OR workload_grant.event_trust <> gate.event_trust
       OR workload_grant.source_kind <> gate.source_kind
       OR workload_grant.invocation_kind <> gate.invocation_kind
       OR workload_grant.reusable_secret_permission <> gate.reusable_secret_permission
       OR workload_grant.grant_mode <> 'readable_secret'
       OR workload_grant.lease_id <> NEW.lease_id
       OR workload_grant.fencing_token <> NEW.fencing_token
       OR workload_grant.status <> 'active'
       OR workload_grant.issued_at_ms > database_now_ms
       OR database_now_ms >= workload_grant.expires_at_ms
       OR workload_grant.expires_at_ms > attempt.lease_expires_at_ms
       OR expected_digest IS NULL
       OR NEW.binding_digest IS DISTINCT FROM expected_digest THEN
        RAISE EXCEPTION 'secret binding is not exact for the live lease fence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_secret_bindings_live_lease_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_job_secret_selection_exact() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    gate job_environment_gates%ROWTYPE;
    secret secrets%ROWTYPE;
    policy secret_policies%ROWTYPE;
    expected_digest BYTEA;
BEGIN
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.attempt_id FOR SHARE;
    SELECT * INTO STRICT secret FROM secrets
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id FOR SHARE;
    SELECT * INTO STRICT policy FROM secret_policies
    WHERE tenant_id = NEW.tenant_id AND secret_id = NEW.secret_id FOR SHARE;
    expected_digest := automata_job_secret_selection_digest(
        NEW.attempt_id, NEW.canonical_name, NEW.tenant_id, NEW.secret_id,
        NEW.secret_version_id, NEW.secret_version_number,
        NEW.scope_kind, NEW.environment_id
    );
    IF secret.canonical_name <> NEW.canonical_name
       OR secret.scope_kind <> NEW.scope_kind
       OR secret.environment_id IS DISTINCT FROM NEW.environment_id
       OR secret.current_version_id <> NEW.secret_version_id
       OR secret.current_version_number <> NEW.secret_version_number
       OR NOT automata_secret_is_available_to_gate(secret, policy, gate)
       OR expected_digest IS NULL
       OR NEW.binding_digest IS DISTINCT FROM expected_digest
       OR (NEW.scope_kind = 'repository' AND EXISTS (
           SELECT 1 FROM secrets AS higher
           JOIN secret_policies AS higher_policy
             ON higher_policy.tenant_id = higher.tenant_id
            AND higher_policy.secret_id = higher.id
           WHERE higher.tenant_id = gate.tenant_id
             AND higher.repository_id = gate.repository_id
             AND higher.environment_id = gate.environment_id
             AND higher.scope_kind = 'environment'
             AND higher.canonical_name = NEW.canonical_name
             AND automata_secret_is_available_to_gate(higher, higher_policy, gate)
       ))
       OR (NEW.scope_kind = 'tenant' AND EXISTS (
           SELECT 1 FROM secrets AS higher
           JOIN secret_policies AS higher_policy
             ON higher_policy.tenant_id = higher.tenant_id
            AND higher_policy.secret_id = higher.id
           WHERE higher.tenant_id = gate.tenant_id
             AND higher.repository_id = gate.repository_id
             AND higher.canonical_name = NEW.canonical_name
             AND higher.scope_kind IN ('repository', 'environment')
             AND (higher.scope_kind = 'repository'
                  OR higher.environment_id = gate.environment_id)
             AND automata_secret_is_available_to_gate(higher, higher_policy, gate)
       )) THEN
        RAISE EXCEPTION 'secret selection is not current, permitted, or highest precedence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_secret_selections_current_precedence';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_job_variable_binding_exact() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    gate job_environment_gates%ROWTYPE;
    variable workflow_variables%ROWTYPE;
    expected_digest BYTEA;
BEGIN
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.attempt_id FOR SHARE;
    SELECT * INTO STRICT variable FROM workflow_variables
    WHERE tenant_id = NEW.tenant_id AND id = NEW.variable_id FOR SHARE;
    expected_digest := automata_job_variable_binding_digest(
        NEW.attempt_id, NEW.canonical_name, NEW.tenant_id, NEW.variable_id,
        NEW.variable_version_id, NEW.variable_version_number,
        NEW.scope_kind, NEW.environment_id
    );
    IF variable.status <> 'active'
       OR variable.repository_id <> gate.repository_id
       OR variable.canonical_name <> NEW.canonical_name
       OR variable.scope_kind <> NEW.scope_kind
       OR variable.environment_id IS DISTINCT FROM NEW.environment_id
       OR variable.current_version_id <> NEW.variable_version_id
       OR variable.current_version_number <> NEW.variable_version_number
       OR expected_digest IS NULL
       OR NEW.binding_digest IS DISTINCT FROM expected_digest
       OR (NEW.scope_kind = 'environment'
           AND NEW.environment_id IS DISTINCT FROM gate.environment_id)
       OR (NEW.scope_kind = 'repository' AND EXISTS (
           SELECT 1 FROM workflow_variables AS higher
           WHERE higher.tenant_id = gate.tenant_id
             AND higher.repository_id = gate.repository_id
             AND higher.environment_id = gate.environment_id
             AND higher.scope_kind = 'environment'
             AND higher.canonical_name = NEW.canonical_name
             AND higher.status = 'active'
       )) THEN
        RAISE EXCEPTION 'variable binding is not the current highest-precedence version'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_variable_bindings_current_precedence';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_activation_preparation_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_activation_preparation_claims AS claim
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.state = 'preparing'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND NEW.bound_at_ms >= claim.claimed_at_ms
          AND NEW.bound_at_ms < claim.expires_at_ms
    ) THEN
        RAISE EXCEPTION 'logical activation preparation binding lacks a live exact fence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_activation_preparation_claim() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    expected_count BIGINT;
    finalized_count BIGINT;
    latest_ready BIGINT;
    expected_status TEXT;
BEGIN
    SELECT count(dependency.prerequisite_job_id),
           count(result.logical_job_id),
           greatest(job.created_at_ms, coalesce(max(result.finalized_at_ms), 0)),
           CASE
               WHEN coalesce(bool_or(
                   result.closure_has_failure
                   OR result.effective_conclusion IN ('failure', 'timed_out')
               ), FALSE) THEN 'failure'
               WHEN coalesce(bool_or(
                   result.closure_has_cancelled
                   OR result.effective_conclusion = 'cancelled'
               ), FALSE) THEN 'cancelled'
               WHEN coalesce(bool_or(
                   result.closure_has_skipped
                   OR result.effective_conclusion = 'skipped'
               ), FALSE) THEN 'skipped'
               ELSE 'success'
           END
      INTO expected_count, finalized_count, latest_ready, expected_status
    FROM logical_workflow_jobs AS job
    JOIN logical_workflow_invocations AS invocation
      ON invocation.run_id = job.run_id AND invocation.id = job.invocation_id
    JOIN logical_workflow_runs AS marker ON marker.run_id = job.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    LEFT JOIN logical_workflow_dependencies AS dependency
      ON dependency.run_id = job.run_id
     AND dependency.invocation_id = job.invocation_id
     AND dependency.logical_job_id = job.id
    LEFT JOIN logical_workflow_effective_job_results AS result
      ON result.run_id = dependency.run_id
     AND result.invocation_id = dependency.invocation_id
     AND result.logical_job_id = dependency.prerequisite_job_id
     AND result.claim_state = 'finalized'
    WHERE job.run_id = NEW.run_id
      AND job.invocation_id = NEW.invocation_id
      AND job.id = NEW.logical_job_id
      AND job.logical_key = NEW.logical_key
      AND job.source_order = NEW.source_order
      AND job.execution_kind = 'steps'
      AND job.state = 'pending'
      AND automata_logical_workflow_invocation_published(
          marker.run_id, invocation.id
      )
      AND invocation.plan_digest = NEW.plan_digest
      AND invocation.plan_object_key = NEW.plan_object_key
      AND invocation.plan_size_bytes = NEW.plan_size_bytes
      AND invocation.plan_media_type = NEW.plan_media_type
      AND invocation.plan_schema = NEW.plan_schema
      AND invocation.state IN ('pending', 'active')
      AND marker.orchestration_schema = 1
      AND marker.state IN ('pending', 'active')
      AND run.admission_epoch = 1
      AND run.plan_schema = 1
      AND run.workflow_id = NEW.workflow_id
      AND run.workflow_name = NEW.workflow_name
      AND run.git_ref = NEW.git_ref
      AND run.actor IS NOT DISTINCT FROM NEW.actor
      AND run.run_number = NEW.run_number
      AND run.run_attempt = NEW.run_attempt
      AND run.event_digest = NEW.event_digest
      AND run.event_object_key = NEW.event_object_key
      AND run.event_size_bytes = NEW.event_size_bytes
      AND run.event_media_type = NEW.event_media_type
    GROUP BY job.created_at_ms;

    IF NOT FOUND
        OR expected_count <> finalized_count
        OR expected_count <> NEW.prerequisite_count
        OR latest_ready <> NEW.evidence_ready_at_ms
        OR expected_status <> NEW.aggregate_status
        OR NEW.claimed_at_ms < latest_ready
        OR NEW.created_at_ms <> NEW.claimed_at_ms
    THEN
        RAISE EXCEPTION 'logical activation preparation claim lacks exact current evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_activation_preparation_complete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    expected_prerequisites INTEGER;
    actual_prerequisites BIGINT;
BEGIN
    SELECT claim.prerequisite_count
      INTO expected_prerequisites
    FROM logical_workflow_activation_preparation_claims AS claim
    WHERE claim.logical_job_id = NEW.logical_job_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT count(*) INTO actual_prerequisites
    FROM logical_workflow_activation_preparation_prerequisites AS pin
    WHERE pin.logical_job_id = NEW.logical_job_id
      AND pin.output_count = (
          SELECT count(*)
          FROM logical_workflow_activation_preparation_outputs AS output
          WHERE output.logical_job_id = pin.logical_job_id
            AND output.prerequisite_job_id = pin.prerequisite_job_id
      );
    IF actual_prerequisites <> expected_prerequisites THEN
        RAISE EXCEPTION 'logical activation preparation pin set is incomplete'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_validate_logical_activation_preparation_output() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_activation_preparation_prerequisites AS pin
        JOIN logical_workflow_activation_preparation_claims AS claim
          ON claim.logical_job_id = pin.logical_job_id
         AND claim.state = 'preparing'
        JOIN logical_workflow_effective_job_result_outputs AS output
          ON output.logical_job_id = pin.prerequisite_job_id
         AND output.output_name = NEW.output_name
        WHERE pin.logical_job_id = NEW.logical_job_id
          AND pin.prerequisite_job_id = NEW.prerequisite_job_id
          AND output.sensitivity = NEW.sensitivity
          AND output.public_value IS NOT DISTINCT FROM NEW.public_value
    ) THEN
        RAISE EXCEPTION 'logical activation output pin lacks exact classified result output'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_activation_preparation_prerequisite() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_activation_preparation_claims AS claim
        JOIN logical_workflow_dependencies AS dependency
          ON dependency.run_id = claim.run_id
         AND dependency.invocation_id = claim.invocation_id
         AND dependency.logical_job_id = claim.logical_job_id
         AND dependency.prerequisite_job_id = NEW.prerequisite_job_id
        JOIN logical_workflow_jobs AS prerequisite_job
          ON prerequisite_job.run_id = dependency.run_id
         AND prerequisite_job.invocation_id = dependency.invocation_id
         AND prerequisite_job.id = dependency.prerequisite_job_id
        JOIN logical_workflow_effective_job_results AS result
          ON result.run_id = dependency.run_id
         AND result.invocation_id = dependency.invocation_id
         AND result.logical_job_id = dependency.prerequisite_job_id
         AND result.claim_state = 'finalized'
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.state = 'preparing'
          AND prerequisite_job.logical_key = NEW.logical_key
          AND prerequisite_job.source_order = NEW.source_order
          AND result.descriptor_digest = NEW.result_descriptor_digest
          AND result.outputs_digest = NEW.outputs_digest
          AND result.commit_digest = NEW.commit_digest
          AND result.effective_conclusion = NEW.effective_conclusion
          AND result.closure_has_failure = NEW.closure_has_failure
          AND result.closure_has_cancelled = NEW.closure_has_cancelled
          AND result.closure_has_skipped = NEW.closure_has_skipped
          AND result.output_count = NEW.output_count
          AND result.finalized_at_ms = NEW.finalized_at_ms
          AND NEW.finalized_at_ms <= claim.evidence_ready_at_ms
    ) THEN
        RAISE EXCEPTION 'logical activation prerequisite pin lacks exact finalized result'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_logical_job_credential_requirements() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    name TEXT;
    previous TEXT;
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.environment_requirement_kind IS DISTINCT FROM OLD.environment_requirement_kind
        OR NEW.environment_template_digest IS DISTINCT FROM OLD.environment_template_digest
        OR NEW.secret_reference_names IS DISTINCT FROM OLD.secret_reference_names
        OR NEW.variable_reference_names IS DISTINCT FROM OLD.variable_reference_names
        OR NEW.credential_requirements_schema IS DISTINCT FROM OLD.credential_requirements_schema
    ) THEN
        RAISE EXCEPTION 'logical job credential requirements are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'logical_workflow_jobs_credential_requirements_immutable';
    END IF;

    IF COALESCE(array_ndims(NEW.secret_reference_names), 1) <> 1
       OR COALESCE(array_lower(NEW.secret_reference_names, 1), 1) <> 1
       OR array_position(NEW.secret_reference_names, NULL) IS NOT NULL
       OR COALESCE(array_ndims(NEW.variable_reference_names), 1) <> 1
       OR COALESCE(array_lower(NEW.variable_reference_names, 1), 1) <> 1
       OR array_position(NEW.variable_reference_names, NULL) IS NOT NULL THEN
        RAISE EXCEPTION 'credential references require dense one-dimensional arrays'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_jobs_credential_reference_arrays';
    END IF;

    FOREACH name IN ARRAY NEW.secret_reference_names LOOP
        IF name !~ '^[A-Z_][A-Z0-9_]*$'
           OR name ~ '^(GITHUB_|ACTIONS_|RUNNER_|AUTOMATA_)'
           OR octet_length(name) > 255
           OR (previous IS NOT NULL AND name <= previous) THEN
            RAISE EXCEPTION 'secret references must be sorted unique canonical names'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'logical_workflow_jobs_secret_references_canonical';
        END IF;
        previous := name;
    END LOOP;

    previous := NULL;
    FOREACH name IN ARRAY NEW.variable_reference_names LOOP
        IF name !~ '^[A-Z_][A-Z0-9_]*$'
           OR name ~ '^(GITHUB_|ACTIONS_|RUNNER_|AUTOMATA_)'
           OR octet_length(name) > 255
           OR (previous IS NOT NULL AND name <= previous) THEN
            RAISE EXCEPTION 'variable references must be sorted unique canonical names'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'logical_workflow_jobs_variable_references_canonical';
        END IF;
        previous := name;
    END LOOP;
    RETURN NEW;
END;
$_$;

CREATE FUNCTION automata_validate_logical_preparation_base_context() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_runs AS marker
        WHERE marker.run_id = NEW.run_id
          AND (
              (
                  marker.root_invocation_id = NEW.invocation_id
                  AND (
                      (
                          NEW.base_context_kind = 'root_empty'
                          AND marker.base_context_digest IS NULL
                          AND marker.base_context_object_key IS NULL
                          AND marker.base_context_size_bytes IS NULL
                          AND marker.base_context_media_type IS NULL
                          AND marker.base_context_schema IS NULL
                      ) OR (
                          NEW.base_context_kind = 'admission'
                          AND marker.base_context_digest = NEW.base_context_digest
                          AND marker.base_context_object_key =
                              NEW.base_context_object_key
                          AND marker.base_context_size_bytes =
                              NEW.base_context_size_bytes
                          AND marker.base_context_media_type =
                              NEW.base_context_media_type
                          AND marker.base_context_schema = NEW.base_context_schema
                          AND marker.base_context_schema = 1
                      )
                  )
              ) OR (
                  marker.root_invocation_id <> NEW.invocation_id
                  AND NEW.base_context_kind = 'admission'
                  AND automata_logical_workflow_invocation_published(
                      NEW.run_id, NEW.invocation_id
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM logical_workflow_reusable_call_publications AS publication
                      WHERE publication.run_id = NEW.run_id
                        AND publication.child_invocation_id = NEW.invocation_id
                        AND publication.condition_matched
                        AND publication.child_graph_sealed_at_ms =
                            publication.published_at_ms
                        AND publication.runtime_context_digest =
                            NEW.base_context_digest
                        AND publication.runtime_context_object_key =
                            NEW.base_context_object_key
                        AND publication.runtime_context_size_bytes =
                            NEW.base_context_size_bytes
                        AND publication.runtime_context_media_type =
                            NEW.base_context_media_type
                        AND publication.runtime_context_schema =
                            NEW.base_context_schema
                        AND publication.runtime_context_schema = 1
                  )
              )
          )
    ) THEN
        RAISE EXCEPTION 'logical preparation base context disagrees with admission'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_workflow_activation_preparation_base_context_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_materialization_authority_profile() RETURNS trigger
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
        WHERE instance.id = NEW.instance_id
          AND instance.run_id = NEW.run_id
          AND instance.invocation_id = NEW.invocation_id
          AND instance.logical_job_id = NEW.logical_job_id
          AND publication.authority_profile = NEW.authority_profile
    ) THEN
        RAISE EXCEPTION 'materialization claim authority profile is inconsistent'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_workflow_materialization_claims_profile_binding';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_materialization_real_claim_quarantine() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now BIGINT;
    receipt logical_workflow_materialization_work_selections%ROWTYPE;
    existing_quarantine logical_workflow_materialization_work_quarantines%ROWTYPE;
    authority RECORD;
    internal_poison BOOLEAN := FALSE;
BEGIN
    SELECT * INTO receipt
    FROM logical_workflow_materialization_work_selections
    WHERE selection_id = NEW.selection_id
    FOR UPDATE;
    PERFORM 1
    FROM logical_workflow_work_selection_replay_horizons
    WHERE queue_name = 'materialization'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'materialization quarantine replay horizon is absent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_quarantine_horizon_required';
    END IF;
    SELECT * INTO existing_quarantine
    FROM logical_workflow_materialization_work_quarantines
    WHERE instance_id = NEW.instance_id
    FOR UPDATE;
    IF existing_quarantine.instance_id IS NOT NULL THEN
        RAISE EXCEPTION 'materialization quarantine already has immutable evidence'
            USING ERRCODE = 'unique_violation',
                  CONSTRAINT = 'workflow_materialization_quarantine_already_exists';
    END IF;

    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NEW.instance_id
    );

    SELECT repository.tenant_id, instance.run_id, instance.invocation_id,
           instance.logical_job_id, claim.origin_selection_id,
           claim.owner_id, claim.generation,
           claim.descriptor_digest AS digest, claim.claimed_at_ms,
           claim.expires_at_ms, claim.state
      INTO authority
    FROM logical_workflow_materialization_claims AS claim
    JOIN logical_workflow_instances AS instance ON instance.id = claim.instance_id
    JOIN workflow_runs AS run ON run.id = instance.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    WHERE claim.instance_id = NEW.instance_id
    FOR UPDATE OF claim, instance;

    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    internal_poison := NEW.failure_kind = 'generation_exhausted'
        AND receipt.outcome = 'selecting';
    IF receipt.selection_id IS NULL
        OR receipt.owner_id IS DISTINCT FROM NEW.selection_owner_id
        OR receipt.requested_at_ms IS DISTINCT FROM NEW.selection_requested_at_ms
        OR receipt.duration_ms IS DISTINCT FROM NEW.selection_duration_ms
    THEN
        RAISE EXCEPTION 'materialization quarantine lacks its exact selection request'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_quarantine_selection_request_exact';
    END IF;
    IF internal_poison THEN
        IF receipt.claimed_at_ms IS NOT NULL OR receipt.expires_at_ms IS NOT NULL
            OR receipt.tenant_id IS NOT NULL OR receipt.run_id IS NOT NULL
            OR receipt.invocation_id IS NOT NULL OR receipt.logical_job_id IS NOT NULL
            OR receipt.instance_id IS NOT NULL OR receipt.generation IS NOT NULL
            OR receipt.authority_digest IS NOT NULL
            OR NEW.selection_generation <> NEW.authority_generation
            OR NEW.selection_claimed_at_ms > database_now
            OR database_now - NEW.selection_claimed_at_ms > 60000
            OR NEW.selection_expires_at_ms - database_now < 1000
            OR NEW.authority_generation <> 9223372036854775807
            OR NEW.authority_expires_at_ms > database_now
        THEN
            RAISE EXCEPTION 'materialization generation poison is not an exact provisional capture'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_materialization_quarantine_generation_poison_exact';
        END IF;
    ELSIF NEW.failure_kind = 'generation_exhausted'
        OR receipt.outcome <> 'claimed'
        OR receipt.claimed_at_ms IS DISTINCT FROM NEW.selection_claimed_at_ms
        OR receipt.expires_at_ms IS DISTINCT FROM NEW.selection_expires_at_ms
        OR receipt.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR receipt.run_id IS DISTINCT FROM NEW.run_id
        OR receipt.invocation_id IS DISTINCT FROM NEW.invocation_id
        OR receipt.logical_job_id IS DISTINCT FROM NEW.logical_job_id
        OR receipt.instance_id IS DISTINCT FROM NEW.instance_id
        OR receipt.generation IS DISTINCT FROM NEW.selection_generation
        OR receipt.authority_digest IS DISTINCT FROM NEW.authority_digest
    THEN
        RAISE EXCEPTION 'materialization quarantine lacks the exact claimed receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_quarantine_selection_exact';
    END IF;

    IF authority IS NULL
        OR (authority.tenant_id, authority.run_id, authority.invocation_id,
            authority.logical_job_id)
           IS DISTINCT FROM
           (NEW.tenant_id, NEW.run_id, NEW.invocation_id, NEW.logical_job_id)
        OR authority.owner_id IS DISTINCT FROM NEW.authority_owner_id
        OR authority.generation IS DISTINCT FROM NEW.authority_generation
        OR authority.generation < NEW.selection_generation
        OR authority.digest IS DISTINCT FROM NEW.authority_digest
        OR authority.claimed_at_ms IS DISTINCT FROM NEW.authority_claimed_at_ms
        OR authority.expires_at_ms IS DISTINCT FROM NEW.authority_expires_at_ms
        OR authority.claimed_at_ms > database_now
        OR authority.state IS DISTINCT FROM 'materializing'
        OR (NOT internal_poison AND (
            authority.origin_selection_id IS DISTINCT FROM NEW.selection_id
            OR authority.owner_id IS DISTINCT FROM NEW.selection_owner_id))
    THEN
        RAISE EXCEPTION 'materialization quarantine lacks exact unsuperseded authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_quarantine_authority_exact';
    END IF;
    NEW.quarantined_at_ms := database_now;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_materialization_real_claim_renewal_receipt() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    selection logical_workflow_materialization_work_selections%ROWTYPE;
    authority RECORD;
    database_now BIGINT;
    receipt_count BIGINT;
    predecessor_exact BOOLEAN := FALSE;
BEGIN
    SELECT * INTO selection
    FROM logical_workflow_materialization_work_selections
    WHERE selection_id = NEW.selection_id;
    SELECT count(*) INTO receipt_count
    FROM logical_workflow_materialization_renewal_receipts
    WHERE selection_id = NEW.selection_id;
    SELECT claim.state, claim.origin_selection_id, claim.owner_id,
           claim.generation, claim.claimed_at_ms, claim.expires_at_ms,
           claim.descriptor_digest AS authority_digest,
           claim.runtime_policy_revision, claim.runtime_policy_digest,
           claim.expected_job_id, claim.expected_attempt_id
      INTO authority
    FROM logical_workflow_materialization_claims AS claim
    WHERE claim.instance_id = NEW.instance_id
    FOR UPDATE;
    IF selection.selection_id IS NULL OR selection.outcome <> 'claimed'
        OR (selection.tenant_id, selection.run_id, selection.invocation_id,
            selection.logical_job_id, selection.instance_id,
            selection.owner_id, selection.authority_digest)
           IS DISTINCT FROM
           (NEW.tenant_id, NEW.run_id, NEW.invocation_id,
            NEW.logical_job_id, NEW.instance_id,
            NEW.owner_id, NEW.authority_digest)
        OR (authority.expected_job_id, authority.expected_attempt_id)
           IS DISTINCT FROM (NEW.expected_job_id, NEW.expected_attempt_id)
    THEN
        RAISE EXCEPTION 'materialization renewal lacks its exact selection origin'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_renewal_selection_exact';
    END IF;
    IF NEW.predecessor_generation = selection.generation THEN
        predecessor_exact :=
            (NEW.predecessor_claimed_at_ms, NEW.predecessor_expires_at_ms,
             NEW.owner_id, NEW.authority_digest)
            IS NOT DISTINCT FROM
            (selection.claimed_at_ms, selection.expires_at_ms,
             selection.owner_id, selection.authority_digest);
    ELSE
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_materialization_renewal_receipts AS prior
            WHERE prior.selection_id = NEW.selection_id
              AND prior.instance_id = NEW.instance_id
              AND prior.successor_generation = NEW.predecessor_generation
              AND prior.successor_claimed_at_ms = NEW.predecessor_claimed_at_ms
              AND prior.successor_expires_at_ms = NEW.predecessor_expires_at_ms
              AND prior.owner_id = NEW.owner_id
              AND prior.runtime_policy_revision = NEW.runtime_policy_revision
              AND prior.runtime_policy_digest = NEW.runtime_policy_digest
              AND prior.authority_digest = NEW.authority_digest
              AND prior.expected_job_id = NEW.expected_job_id
              AND prior.expected_attempt_id = NEW.expected_attempt_id
        ) INTO predecessor_exact;
    END IF;
    IF predecessor_exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'materialization renewal does not extend its exact predecessor chain'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_renewal_predecessor_exact';
    END IF;
    IF receipt_count >= 64 THEN
        RAISE EXCEPTION 'materialization selection renewal history is full'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_renewal_history_bounded';
    END IF;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF authority IS NULL OR authority.state IS DISTINCT FROM 'materializing'
        OR authority.origin_selection_id IS DISTINCT FROM NEW.selection_id
        OR authority.owner_id IS DISTINCT FROM NEW.owner_id
        OR authority.generation IS DISTINCT FROM NEW.successor_generation
        OR authority.claimed_at_ms IS DISTINCT FROM NEW.successor_claimed_at_ms
        OR authority.expires_at_ms IS DISTINCT FROM NEW.successor_expires_at_ms
        OR authority.authority_digest IS DISTINCT FROM NEW.authority_digest
        OR (authority.runtime_policy_revision, authority.runtime_policy_digest)
           IS DISTINCT FROM
           (NEW.runtime_policy_revision, NEW.runtime_policy_digest)
        OR (authority.expected_job_id, authority.expected_attempt_id)
           IS DISTINCT FROM (NEW.expected_job_id, NEW.expected_attempt_id)
        OR NEW.successor_expires_at_ms - database_now < 1000
    THEN
        RAISE EXCEPTION 'materialization renewal lacks the exact live successor authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_renewal_successor_exact';
    END IF;
    NEW.validated_at_ms := database_now;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_materialization_work_selection_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now BIGINT;
    replay_floor BIGINT;
    exact_evidence BOOLEAN := FALSE;
    ready_exists BOOLEAN := FALSE;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.outcome <> 'selecting' THEN
            RAISE EXCEPTION 'materialization selection must begin as a provisional reservation'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_materialization_selection_reservation_first';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.outcome <> 'selecting'
        OR NEW.selection_id IS DISTINCT FROM OLD.selection_id
        OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
        OR NEW.requested_at_ms IS DISTINCT FROM OLD.requested_at_ms
        OR NEW.duration_ms IS DISTINCT FROM OLD.duration_ms
        OR NEW.outcome = 'selecting'
    THEN
        RAISE EXCEPTION 'materialization selection transition is immutable or invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_transition';
    END IF;
    SELECT replay_floor_ms INTO replay_floor
    FROM logical_workflow_work_selection_replay_horizons
    WHERE queue_name = 'materialization'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'materialization selection replay authority is absent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_horizon_required';
    END IF;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF NEW.requested_at_ms <= replay_floor
        OR NEW.requested_at_ms < database_now - 60000
        OR NEW.requested_at_ms > database_now + 60000
    THEN
        RAISE EXCEPTION 'materialization selection request is outside replay authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_request_time';
    END IF;
    IF NEW.claimed_at_ms > database_now
        OR database_now - NEW.claimed_at_ms > 60000
        OR (NEW.outcome <> 'quarantined' AND (
            NEW.expires_at_ms <= database_now
            OR NEW.expires_at_ms - database_now < 1000
        ))
    THEN
        RAISE EXCEPTION 'materialization selection issue time is not database-current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_database_time';
    END IF;

    IF NEW.outcome = 'claimed' THEN
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_materialization_claims AS claim
            JOIN logical_workflow_instances AS instance
              ON instance.id = claim.instance_id
            JOIN workflow_runs AS run ON run.id = instance.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE claim.instance_id = NEW.instance_id
              AND repository.tenant_id = NEW.tenant_id
              AND instance.run_id = NEW.run_id
              AND instance.invocation_id = NEW.invocation_id
              AND instance.logical_job_id = NEW.logical_job_id
              AND claim.origin_selection_id = NEW.selection_id
              AND claim.owner_id = NEW.owner_id
              AND claim.generation = NEW.generation
              AND claim.descriptor_digest = NEW.authority_digest
              AND claim.claimed_at_ms = NEW.claimed_at_ms
              AND claim.expires_at_ms = NEW.expires_at_ms
              AND claim.state = 'materializing'
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'quarantined' THEN
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_materialization_work_quarantines AS quarantine
            WHERE quarantine.instance_id = NEW.instance_id
              AND quarantine.tenant_id = NEW.tenant_id
              AND quarantine.run_id = NEW.run_id
              AND quarantine.invocation_id = NEW.invocation_id
              AND quarantine.logical_job_id = NEW.logical_job_id
              AND quarantine.selection_id = NEW.selection_id
              AND quarantine.selection_owner_id = NEW.owner_id
              AND quarantine.selection_requested_at_ms = NEW.requested_at_ms
              AND quarantine.selection_duration_ms = NEW.duration_ms
              AND quarantine.selection_generation = NEW.generation
              AND quarantine.selection_claimed_at_ms = NEW.claimed_at_ms
              AND quarantine.selection_expires_at_ms = NEW.expires_at_ms
              AND quarantine.authority_digest = NEW.authority_digest
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'contended' THEN
        exact_evidence := TRUE;
    ELSE
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_instances AS instance
            JOIN logical_workflow_activation_publications AS activation_publication
              ON activation_publication.run_id = instance.run_id
             AND activation_publication.invocation_id = instance.invocation_id
             AND activation_publication.logical_job_id = instance.logical_job_id
            JOIN logical_workflow_jobs AS job ON job.id = instance.logical_job_id
            JOIN logical_workflow_invocations AS invocation
              ON invocation.run_id = instance.run_id
             AND invocation.id = instance.invocation_id
            JOIN logical_workflow_runs AS marker ON marker.run_id = instance.run_id
            JOIN workflow_runs AS run ON run.id = marker.run_id
            LEFT JOIN logical_workflow_materialization_claims AS claim
              ON claim.instance_id = instance.id
            LEFT JOIN logical_workflow_materialization_work_quarantines AS quarantine
              ON quarantine.instance_id = instance.id
            WHERE activation_publication.condition_matched
              AND activation_publication.instance_count > 0
              AND job.state = 'activated'
              AND automata_logical_workflow_invocation_published(
                  marker.run_id, invocation.id
              )
              AND invocation.state IN ('pending', 'active')
              AND marker.state IN ('pending', 'active')
              AND run.status IN ('queued', 'in_progress')
              AND quarantine.instance_id IS NULL
              AND (claim.instance_id IS NULL OR (
                  claim.state = 'materializing'
                  AND claim.expires_at_ms <= NEW.claimed_at_ms
              ))
        ) INTO ready_exists;
        exact_evidence := NOT ready_exists;
    END IF;
    IF exact_evidence IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'materialization selection lacks exact durable evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_receipt_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_missing_job_secret() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    gate job_environment_gates%ROWTYPE;
BEGIN
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.attempt_id FOR SHARE;
    IF EXISTS (
        SELECT 1 FROM secrets AS secret
        JOIN secret_policies AS policy
          ON policy.tenant_id = secret.tenant_id AND policy.secret_id = secret.id
        WHERE secret.tenant_id = gate.tenant_id
          AND secret.canonical_name = NEW.canonical_name
          AND automata_secret_is_available_to_gate(secret, policy, gate)
    ) THEN
        RAISE EXCEPTION 'an available secret cannot resolve as missing'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_missing_secret_bindings_unavailable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_missing_job_variable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    gate job_environment_gates%ROWTYPE;
BEGIN
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.attempt_id FOR SHARE;
    IF EXISTS (
        SELECT 1 FROM workflow_variables AS variable
        WHERE variable.tenant_id = gate.tenant_id
          AND variable.repository_id = gate.repository_id
          AND variable.canonical_name = NEW.canonical_name
          AND variable.status = 'active'
          AND (variable.scope_kind = 'repository'
               OR (variable.scope_kind = 'environment'
                   AND variable.environment_id = gate.environment_id))
    ) THEN
        RAISE EXCEPTION 'an available variable cannot resolve as missing'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_missing_variable_bindings_unavailable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_prepared_authority_profile() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_activation_preparation_claims AS claim
        JOIN logical_workflow_jobs AS job ON job.id = claim.logical_job_id
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.authority_profile = NEW.authority_profile
          AND job.authority_profile = NEW.authority_profile
    ) THEN
        RAISE EXCEPTION 'prepared activation authority profile is inconsistent'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_workflow_activation_preparations_profile_binding';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_reusable_call_output_contract() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_call_output_contracts AS contract
        WHERE contract.run_id = NEW.run_id
          AND contract.child_invocation_id = NEW.child_invocation_id
          AND contract.mapping_count = (
              SELECT count(*)
              FROM logical_workflow_reusable_call_output_mappings AS mapping
              WHERE mapping.run_id = contract.run_id
                AND mapping.child_invocation_id = contract.child_invocation_id
          )
    ) OR EXISTS (
        SELECT 1
        FROM logical_workflow_reusable_call_output_mappings AS mapping
        JOIN logical_workflow_reusable_outputs AS callee
          ON callee.run_id = mapping.run_id
         AND callee.invocation_id = mapping.child_invocation_id
         AND callee.output_key = mapping.child_output_name
        WHERE mapping.run_id = NEW.run_id
          AND mapping.child_invocation_id = NEW.child_invocation_id
          AND mapping.sensitivity = 'public'
          AND callee.sensitivity = 'secret_derived'
    ) THEN
        RAISE EXCEPTION 'reusable call output aliases disagree with their fixed contract'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_call_output_contract_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_validate_reusable_call_publication() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    durable logical_workflow_reusable_call_publications%ROWTYPE;
BEGIN
    SELECT * INTO durable
    FROM logical_workflow_reusable_call_publications AS publication
    WHERE publication.run_id = NEW.run_id
      AND publication.parent_invocation_id = NEW.parent_invocation_id
      AND publication.caller_logical_job_id = NEW.caller_logical_job_id;

    IF NOT FOUND
        OR durable.child_graph_sealed_at_ms IS NULL
        OR NOT EXISTS (
            SELECT 1
            FROM logical_workflow_reusable_invocation_expansions AS planned
            JOIN logical_workflow_jobs AS caller
              ON caller.run_id = planned.run_id
             AND caller.invocation_id = planned.parent_invocation_id
             AND caller.id = planned.caller_logical_job_id
            WHERE planned.run_id = durable.run_id
              AND planned.invocation_id = durable.child_invocation_id
              AND planned.parent_invocation_id = durable.parent_invocation_id
              AND planned.caller_logical_job_id = durable.caller_logical_job_id
              AND caller.execution_kind = 'reusable_workflow'
              AND caller.state = CASE WHEN durable.condition_matched
                  THEN 'activated' ELSE 'skipped' END
              AND caller.activation_fence = durable.activation_generation
              AND caller.activation_input_digest = durable.activation_input_digest
              AND caller.authority_profile = durable.authority_profile
              AND caller.activation_owner_id IS NULL
              AND caller.activation_claimed_at_ms IS NULL
              AND caller.activation_expires_at_ms IS NULL
              AND caller.activation_origin_selection_id IS NULL
              AND caller.updated_at_ms = durable.published_at_ms
        )
        OR NOT EXISTS (
            SELECT 1
            FROM logical_workflow_reusable_call_output_contracts AS contract
            WHERE contract.run_id = durable.run_id
              AND contract.child_invocation_id = durable.child_invocation_id
              AND contract.mapping_count = durable.output_mapping_count
              AND contract.mapping_digest = durable.output_mapping_digest
        )
        OR (durable.condition_matched AND NOT EXISTS (
            SELECT 1
            FROM logical_workflow_reusable_invocation_expansions AS planned
            JOIN logical_workflow_reusable_workflow_catalog AS catalog
              ON catalog.run_id = planned.run_id
             AND catalog.catalog_entry_id = planned.catalog_entry_id
            JOIN logical_workflow_invocations AS child
              ON child.run_id = planned.run_id
             AND child.id = planned.invocation_id
            WHERE planned.run_id = durable.run_id
              AND planned.invocation_id = durable.child_invocation_id
              AND child.invocation_kind = 'reusable'
              AND child.plan_digest = catalog.plan_digest
              AND child.plan_object_key = catalog.plan_object_key
              AND child.plan_size_bytes = catalog.plan_size_bytes
              AND child.plan_media_type = catalog.plan_media_type
              AND child.plan_schema = catalog.plan_schema
              AND child.state = 'active'
        ))
        OR (durable.condition_matched AND (SELECT count(*)
            FROM logical_workflow_jobs
            WHERE run_id = durable.run_id
              AND invocation_id = durable.child_invocation_id)
           <> (SELECT count(*)
               FROM logical_workflow_reusable_expanded_jobs
               WHERE run_id = durable.run_id
                 AND invocation_id = durable.child_invocation_id))
        OR (durable.condition_matched AND EXISTS (
            SELECT 1
            FROM logical_workflow_reusable_expanded_jobs AS planned
            LEFT JOIN logical_workflow_jobs AS active
              ON active.run_id = planned.run_id
             AND active.invocation_id = planned.invocation_id
             AND active.id = planned.logical_job_id
             AND active.logical_key = planned.logical_key
             AND active.source_order = planned.source_order
             AND active.execution_kind = planned.execution_kind
             AND active.state = 'pending'
             AND active.activation_fence = 0
             AND active.runtime_policy_revision = durable.runtime_policy_revision
             AND active.runtime_policy_digest = durable.runtime_policy_digest
            WHERE planned.run_id = durable.run_id
              AND planned.invocation_id = durable.child_invocation_id
              AND active.id IS NULL
        ))
        OR (durable.condition_matched AND (SELECT count(*)
            FROM logical_workflow_dependencies
            WHERE run_id = durable.run_id
              AND invocation_id = durable.child_invocation_id)
           <> (SELECT count(*)
               FROM logical_workflow_reusable_expanded_dependencies
               WHERE run_id = durable.run_id
                 AND invocation_id = durable.child_invocation_id))
        OR (durable.condition_matched AND EXISTS (
            SELECT 1
            FROM logical_workflow_reusable_expanded_dependencies AS planned
            LEFT JOIN logical_workflow_dependencies AS active
              ON active.run_id = planned.run_id
             AND active.invocation_id = planned.invocation_id
             AND active.logical_job_id = planned.logical_job_id
             AND active.prerequisite_job_id = planned.prerequisite_job_id
            WHERE planned.run_id = durable.run_id
              AND planned.invocation_id = durable.child_invocation_id
              AND active.logical_job_id IS NULL
        ))
        OR (NOT durable.condition_matched AND EXISTS (
            SELECT 1
            FROM logical_workflow_invocations AS child
            WHERE child.run_id = durable.run_id
              AND child.id = durable.child_invocation_id
        ))
    THEN
        RAISE EXCEPTION 'reusable call publication did not seal its exact child graph'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_call_graph_exact';
    END IF;
    RETURN NULL;
END;
$$;
