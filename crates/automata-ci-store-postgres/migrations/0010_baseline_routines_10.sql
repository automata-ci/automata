-- Frozen greenfield baseline. Add a new migration instead of editing this stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_require_github_runtime_authority_lease_final_exact() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT automata_github_runtime_authority_lease_final_exact(
        NEW.attempt_id,
        NEW.fencing_token
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority lease renewal is not reciprocal'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_lease_renewal_final_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_github_runtime_authority_operation_receipt() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM github_runtime_authority_operation_receipts AS receipt
        WHERE receipt.attempt_id = NEW.attempt_id
          AND receipt.fencing_token = NEW.fencing_token
          AND receipt.tenant_id = NEW.tenant_id
          AND receipt.operation_kind = NEW.operation_kind
          AND receipt.claim_fence = NEW.claim_fence
          AND receipt.operation_digest = NEW.operation_digest
          AND receipt.disposition = NEW.disposition
          AND receipt.claim_owner_id IS NOT DISTINCT FROM NEW.claim_owner_id
          AND receipt.claim_claimed_at_ms
              IS NOT DISTINCT FROM NEW.claim_claimed_at_ms
          AND receipt.claim_expires_at_ms
              IS NOT DISTINCT FROM NEW.claim_expires_at_ms
          AND receipt.result_state = NEW.result_state
          AND receipt.result_updated_at_ms = NEW.result_updated_at_ms
          AND receipt.result_terminal_reason
              IS NOT DISTINCT FROM NEW.result_terminal_reason
        FOR KEY SHARE
    ) THEN
        RAISE EXCEPTION 'GitHub runtime-authority transition lacks its exact receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_operation_transition_receipt_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_github_schedule_fire_terminal_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    exact BOOLEAN;
BEGIN
    IF NEW.state NOT IN ('admitted', 'skipped', 'failed') THEN
        RETURN NULL;
    END IF;
    IF NEW.failure_kind = 'registry_superseded' THEN
        SELECT NOT EXISTS (
                   SELECT 1
                     FROM github_schedule_registry_current AS current
                    WHERE current.tenant_id = NEW.tenant_id
                      AND current.repository_id = NEW.repository_id
                      AND current.provider_connection_id = NEW.provider_connection_id
                      AND current.registry_id = NEW.registry_id
               )
               AND NOT EXISTS (
                   SELECT 1
                     FROM github_schedule_runtime AS runtime
                    WHERE runtime.tenant_id = NEW.tenant_id
                      AND runtime.repository_id = NEW.repository_id
                      AND runtime.provider_connection_id = NEW.provider_connection_id
                      AND runtime.registry_id = NEW.registry_id
                      AND runtime.entry_ordinal = NEW.entry_ordinal
               )
          INTO exact;
        IF exact IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'superseded GitHub schedule fire lacks an inactive registry'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_schedule_fire_terminal_evidence';
        END IF;
        IF NEW.attempt_count = 0 THEN
            RETURN NULL;
        END IF;
    END IF;

    SELECT EXISTS (
               SELECT 1
                 FROM github_schedule_fire_attempts AS attempt
                WHERE attempt.fire_id = NEW.fire_id
                  AND attempt.attempt = NEW.attempt_count
                  AND attempt.claim_fence = NEW.claim_fence
                  AND attempt.outcome = NEW.state
                  AND attempt.failure_kind IS NOT DISTINCT FROM NEW.failure_kind
           )
           AND CASE
               WHEN NEW.failure_kind IN (
                   'registry_superseded',
                   'github.schedule.registry_invalid'
               ) THEN
                   NOT EXISTS (
                       SELECT 1
                         FROM github_schedule_runtime AS runtime
                        WHERE runtime.tenant_id = NEW.tenant_id
                          AND runtime.repository_id = NEW.repository_id
                          AND runtime.provider_connection_id = NEW.provider_connection_id
                          AND runtime.registry_id = NEW.registry_id
                          AND runtime.entry_ordinal = NEW.entry_ordinal
                   )
               ELSE EXISTS (
                   SELECT 1
                     FROM github_schedule_runtime AS runtime
                    WHERE runtime.tenant_id = NEW.tenant_id
                      AND runtime.repository_id = NEW.repository_id
                      AND runtime.provider_connection_id = NEW.provider_connection_id
                      AND runtime.registry_id = NEW.registry_id
                      AND runtime.entry_ordinal = NEW.entry_ordinal
                      AND runtime.next_fire_at_ms > NEW.scheduled_at_ms
               )
           END
      INTO exact;
    IF exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'terminal GitHub schedule fire lacks exact attempt and advancement evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_fire_terminal_evidence';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_inserted_manifest_revision_current() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM github_provider_manifest_current AS current_manifest
        WHERE current_manifest.tenant_id = NEW.tenant_id
          AND current_manifest.repository_id = NEW.repository_id
          AND current_manifest.provider_connection_id = NEW.provider_connection_id
          AND current_manifest.manifest_revision = NEW.manifest_revision
          AND current_manifest.manifest_digest = NEW.manifest_digest
    ) THEN
        RAISE EXCEPTION 'inserted provider manifest revision must become current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_revision_must_be_current';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_job_environment_activation_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM logical_workflow_instances AS instance
        WHERE instance.id = NEW.id
    ) AND NOT EXISTS (
        SELECT 1
        FROM logical_workflow_job_environment_evidence AS evidence
        WHERE evidence.instance_id = NEW.id
    ) THEN
        RAISE EXCEPTION 'new activation instance requires environment evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_instances_environment_evidence_required';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_job_environment_gate_before_lease() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    gate job_environment_gates%ROWTYPE;
    environment repository_environments%ROWTYPE;
    approval protected_environment_approval_requests%ROWTYPE;
    logical_job logical_workflow_jobs%ROWTYPE;
    database_now_ms BIGINT;
    secret_count BIGINT;
    missing_secret_count BIGINT;
    variable_count BIGINT;
    missing_variable_count BIGINT;
BEGIN
    IF OLD.lifecycle <> 'queued' OR NEW.lifecycle <> 'leased' THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM logical_workflow_concrete_jobs WHERE job_id = NEW.job_id
    ) THEN
        RETURN NEW;
    END IF;
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT * INTO STRICT gate FROM job_environment_gates
    WHERE attempt_id = NEW.id AND job_id = NEW.job_id FOR SHARE;
    SELECT * INTO STRICT logical_job FROM logical_workflow_jobs
    WHERE run_id = gate.run_id AND invocation_id = gate.invocation_id
      AND id = gate.logical_job_id FOR SHARE;
    IF gate.state <> 'ready'
       OR gate.environment_requirement_kind <> logical_job.environment_requirement_kind
       OR gate.environment_template_digest IS DISTINCT FROM logical_job.environment_template_digest
       OR gate.resolution_digest IS NULL
       OR gate.event_trust = 'unknown' AND cardinality(logical_job.secret_reference_names) > 0
       OR gate.source_kind = 'unknown' AND cardinality(logical_job.secret_reference_names) > 0
       OR gate.invocation_kind = 'reusable'
          AND cardinality(logical_job.secret_reference_names) > 0
          AND gate.reusable_secret_permission <> 'explicit' THEN
        RAISE EXCEPTION 'job environment and credential gate is not ready'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_environment_gate_ready';
    END IF;

    SELECT count(*) INTO secret_count FROM job_secret_selections WHERE attempt_id = NEW.id;
    SELECT count(*) INTO missing_secret_count FROM job_missing_secret_bindings WHERE attempt_id = NEW.id;
    SELECT count(*) INTO variable_count FROM job_variable_bindings WHERE attempt_id = NEW.id;
    SELECT count(*) INTO missing_variable_count FROM job_missing_variable_bindings WHERE attempt_id = NEW.id;
    IF secret_count <> gate.resolved_secret_count
       OR missing_secret_count <> gate.missing_secret_count
       OR variable_count <> gate.resolved_variable_count
       OR missing_variable_count <> gate.missing_variable_count
       OR secret_count + missing_secret_count <> cardinality(logical_job.secret_reference_names)
       OR variable_count + missing_variable_count <> cardinality(logical_job.variable_reference_names) THEN
        RAISE EXCEPTION 'job credential resolution is incomplete'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_credential_resolution_complete';
    END IF;
    IF EXISTS (
        SELECT 1 FROM job_secret_selections AS selection
        WHERE selection.attempt_id = NEW.id
          AND selection.binding_digest IS DISTINCT FROM automata_job_secret_selection_digest(
              selection.attempt_id, selection.canonical_name, selection.tenant_id,
              selection.secret_id, selection.secret_version_id,
              selection.secret_version_number, selection.scope_kind,
              selection.environment_id
          )
    ) OR EXISTS (
        SELECT 1 FROM job_variable_bindings AS binding
        WHERE binding.attempt_id = NEW.id
          AND binding.binding_digest IS DISTINCT FROM automata_job_variable_binding_digest(
              binding.attempt_id, binding.canonical_name, binding.tenant_id,
              binding.variable_id, binding.variable_version_id,
              binding.variable_version_number, binding.scope_kind,
              binding.environment_id
          )
    ) THEN
        RAISE EXCEPTION 'job credential selection is no longer current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_credential_selection_current';
    END IF;

    IF gate.environment_id IS NOT NULL THEN
        SELECT * INTO STRICT environment FROM repository_environments
        WHERE tenant_id = gate.tenant_id AND repository_id = gate.repository_id
          AND id = gate.environment_id FOR SHARE;
        IF environment.status <> 'active'
           OR environment.revision <> gate.environment_revision THEN
            RAISE EXCEPTION 'job environment policy is stale'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'job_attempts_environment_gate_current';
        END IF;
        IF environment.protection_mode = 'required_approvals' THEN
            SELECT * INTO STRICT approval FROM protected_environment_approval_requests
            WHERE tenant_id = gate.tenant_id AND id = gate.approval_request_id FOR SHARE;
            IF approval.status <> 'approved'
               OR approval.environment_revision <> environment.revision
               OR approval.required_approvals <> environment.required_approvals
               OR approval.prevent_self_review <> environment.prevent_self_review
               OR approval.resolved_at_ms IS NULL
               OR approval.resolved_at_ms >= approval.expires_at_ms
               OR database_now_ms >= approval.expires_at_ms
               OR NOT automata_protected_environment_approval_is_current(
                   gate.tenant_id, gate.approval_request_id, database_now_ms
               ) THEN
                RAISE EXCEPTION 'protected environment approval is stale'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'job_attempts_environment_approval_current';
            END IF;
        ELSIF gate.approval_request_id IS NOT NULL THEN
            RAISE EXCEPTION 'unprotected environment has approval evidence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'job_attempts_environment_approval_current';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_live_concrete_job_authority() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    current_claim logical_workflow_materialization_claims%ROWTYPE;
    database_now BIGINT;
BEGIN
    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NEW.instance_id
    );
    SELECT * INTO current_claim
    FROM logical_workflow_materialization_claims
    WHERE instance_id = NEW.instance_id
    FOR UPDATE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF current_claim.instance_id IS NULL
        OR current_claim.state <> 'materializing'
        OR current_claim.run_id IS DISTINCT FROM NEW.run_id
        OR current_claim.invocation_id IS DISTINCT FROM NEW.invocation_id
        OR current_claim.logical_job_id IS DISTINCT FROM NEW.logical_job_id
        OR current_claim.descriptor_digest IS DISTINCT FROM NEW.descriptor_digest
        OR current_claim.expected_job_id IS DISTINCT FROM NEW.job_id
        OR current_claim.expected_attempt_id IS DISTINCT FROM
           NEW.initial_attempt_id
        OR current_claim.owner_id IS DISTINCT FROM NEW.claim_owner_id
        OR current_claim.generation IS DISTINCT FROM NEW.claim_generation
        OR current_claim.claimed_at_ms IS DISTINCT FROM NEW.claim_started_at_ms
        OR current_claim.expires_at_ms IS DISTINCT FROM NEW.claim_expires_at_ms
        OR current_claim.runtime_policy_revision IS DISTINCT FROM
           NEW.runtime_policy_revision
        OR current_claim.runtime_policy_digest IS DISTINCT FROM
           NEW.runtime_policy_digest
        OR database_now < current_claim.claimed_at_ms
        OR database_now >= current_claim.expires_at_ms
    THEN
        RAISE EXCEPTION 'concrete job insert lacks live exact materialization authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_concrete_job_live_authority_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_materialization_claim_lineage() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    current_claim logical_workflow_materialization_claims%ROWTYPE;
    current_state TEXT;
    event_exact BOOLEAN := FALSE;
    current_exact BOOLEAN := FALSE;
    database_now BIGINT;
BEGIN
    IF NEW.state = 'materializing' THEN
        SELECT (
            EXISTS (
                SELECT 1
                FROM logical_workflow_materialization_work_selections AS selection
                JOIN workflow_runs AS run ON run.id = NEW.run_id
                JOIN repositories AS repository ON repository.id = run.repository_id
                WHERE selection.selection_id = NEW.origin_selection_id
                  AND selection.outcome = 'claimed'
                  AND selection.tenant_id = repository.tenant_id
                  AND selection.run_id = NEW.run_id
                  AND selection.invocation_id = NEW.invocation_id
                  AND selection.logical_job_id = NEW.logical_job_id
                  AND selection.instance_id = NEW.instance_id
                  AND selection.owner_id = NEW.owner_id
                  AND selection.generation = NEW.generation
                  AND selection.claimed_at_ms = NEW.claimed_at_ms
                  AND selection.expires_at_ms = NEW.expires_at_ms
                  AND selection.authority_digest = NEW.descriptor_digest
            ) OR EXISTS (
                SELECT 1
                FROM logical_workflow_materialization_renewal_receipts AS renewal
                JOIN workflow_runs AS run ON run.id = NEW.run_id
                JOIN repositories AS repository ON repository.id = run.repository_id
                WHERE renewal.selection_id = NEW.origin_selection_id
                  AND renewal.tenant_id = repository.tenant_id
                  AND renewal.run_id = NEW.run_id
                  AND renewal.invocation_id = NEW.invocation_id
                  AND renewal.logical_job_id = NEW.logical_job_id
                  AND renewal.instance_id = NEW.instance_id
                  AND renewal.owner_id = NEW.owner_id
                  AND renewal.successor_generation = NEW.generation
                  AND renewal.successor_claimed_at_ms = NEW.claimed_at_ms
                  AND renewal.successor_expires_at_ms = NEW.expires_at_ms
                  AND renewal.authority_digest = NEW.descriptor_digest
                  AND renewal.runtime_policy_revision =
                      NEW.runtime_policy_revision
                  AND renewal.runtime_policy_digest = NEW.runtime_policy_digest
                  AND renewal.expected_job_id = NEW.expected_job_id
                  AND renewal.expected_attempt_id = NEW.expected_attempt_id
            )
        ) INTO event_exact;
        IF event_exact IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'materialization claim event lacks exact selection lineage'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_materialization_claim_lineage_exact';
        END IF;
    END IF;

    SELECT state INTO current_state
    FROM logical_workflow_materialization_claims
    WHERE instance_id = NEW.instance_id;
    IF current_state IS NULL THEN
        RAISE EXCEPTION 'materialization claim lineage target disappeared'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_claim_lineage_retained';
    END IF;
    IF current_state <> 'materializing' THEN
        RETURN NULL;
    END IF;

    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NEW.instance_id
    );
    SELECT * INTO current_claim
    FROM logical_workflow_materialization_claims
    WHERE instance_id = NEW.instance_id
    FOR UPDATE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT (
        EXISTS (
            SELECT 1
            FROM logical_workflow_materialization_work_selections AS selection
            JOIN workflow_runs AS run ON run.id = current_claim.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE selection.selection_id = current_claim.origin_selection_id
              AND selection.outcome = 'claimed'
              AND selection.tenant_id = repository.tenant_id
              AND selection.run_id = current_claim.run_id
              AND selection.invocation_id = current_claim.invocation_id
              AND selection.logical_job_id = current_claim.logical_job_id
              AND selection.instance_id = current_claim.instance_id
              AND selection.owner_id = current_claim.owner_id
              AND selection.generation = current_claim.generation
              AND selection.claimed_at_ms = current_claim.claimed_at_ms
              AND selection.expires_at_ms = current_claim.expires_at_ms
              AND selection.authority_digest = current_claim.descriptor_digest
        ) OR EXISTS (
            SELECT 1
            FROM logical_workflow_materialization_renewal_receipts AS renewal
            JOIN workflow_runs AS run ON run.id = current_claim.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE renewal.selection_id = current_claim.origin_selection_id
              AND renewal.tenant_id = repository.tenant_id
              AND renewal.run_id = current_claim.run_id
              AND renewal.invocation_id = current_claim.invocation_id
              AND renewal.logical_job_id = current_claim.logical_job_id
              AND renewal.instance_id = current_claim.instance_id
              AND renewal.owner_id = current_claim.owner_id
              AND renewal.successor_generation = current_claim.generation
              AND renewal.successor_claimed_at_ms = current_claim.claimed_at_ms
              AND renewal.successor_expires_at_ms = current_claim.expires_at_ms
              AND renewal.authority_digest = current_claim.descriptor_digest
              AND renewal.runtime_policy_revision =
                  current_claim.runtime_policy_revision
              AND renewal.runtime_policy_digest =
                  current_claim.runtime_policy_digest
              AND renewal.expected_job_id = current_claim.expected_job_id
              AND renewal.expected_attempt_id = current_claim.expected_attempt_id
        )
    ) INTO current_exact;
    IF current_exact IS DISTINCT FROM TRUE
        OR database_now < current_claim.claimed_at_ms
        OR current_claim.expires_at_ms - database_now < 1000
    THEN
        RAISE EXCEPTION 'active materialization claim lacks live exact lineage'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_claim_lineage_current';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_materialization_state_closure() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    current_claim logical_workflow_materialization_claims%ROWTYPE;
    concrete logical_workflow_concrete_jobs%ROWTYPE;
    database_now BIGINT;
    closed BOOLEAN := FALSE;
BEGIN
    SELECT * INTO current_claim
    FROM logical_workflow_materialization_claims
    WHERE instance_id = NEW.instance_id;
    IF current_claim.instance_id IS NULL THEN
        RAISE EXCEPTION 'materialization closure lost its durable claim'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_claim_retained';
    END IF;
    PERFORM automata_require_active_unquarantined_workflow_phase(
        current_claim.run_id, current_claim.invocation_id,
        current_claim.logical_job_id, current_claim.instance_id
    );
    SELECT * INTO current_claim
    FROM logical_workflow_materialization_claims
    WHERE instance_id = NEW.instance_id
    FOR UPDATE;
    SELECT * INTO concrete
    FROM logical_workflow_concrete_jobs
    WHERE instance_id = NEW.instance_id
    FOR SHARE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;

    IF current_claim.state = 'materializing' THEN
        closed := concrete.instance_id IS NULL;
    ELSE
        closed := current_claim.state = 'materialized'
            AND concrete.instance_id IS NOT NULL
            AND concrete.run_id = current_claim.run_id
            AND concrete.invocation_id = current_claim.invocation_id
            AND concrete.logical_job_id = current_claim.logical_job_id
            AND concrete.descriptor_digest = current_claim.descriptor_digest
            AND concrete.job_id = current_claim.expected_job_id
            AND concrete.initial_attempt_id = current_claim.expected_attempt_id
            AND concrete.claim_owner_id = current_claim.owner_id
            AND concrete.claim_generation = current_claim.generation
            AND concrete.claim_started_at_ms = current_claim.claimed_at_ms
            AND concrete.claim_expires_at_ms = current_claim.expires_at_ms
            AND concrete.committed_at_ms = current_claim.updated_at_ms
            AND concrete.runtime_policy_revision =
                current_claim.runtime_policy_revision
            AND concrete.runtime_policy_digest = current_claim.runtime_policy_digest
            AND database_now >= current_claim.claimed_at_ms
            AND database_now < current_claim.expires_at_ms;
    END IF;
    IF closed IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'materialization claim and concrete job are not closed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_state_closure';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_open_workflow_admission_graph() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM 1
    FROM logical_workflow_runs AS marker
    JOIN workflow_admission_receipts AS receipt ON receipt.run_id = marker.run_id
    JOIN github_workflow_run_manifest_origins AS origin
      ON origin.run_id = marker.run_id
     AND origin.root_invocation_id = marker.root_invocation_id
    JOIN logical_workflow_runtime_policy_pins AS pin ON pin.run_id = marker.run_id
    WHERE marker.run_id = NEW.run_id
      AND marker.root_invocation_id = NEW.invocation_id
      AND marker.admission_graph_sealed_at_ms IS NULL
      AND receipt.committed_at_ms IS NOT NULL
      AND receipt.idempotency_kind = origin.admission_idempotency_kind
      AND receipt.idempotency_key = origin.admission_idempotency_key
      AND receipt.request_digest = marker.admission_digest
      AND origin.logical_admission_digest = marker.admission_digest
      AND origin.admitted_at_ms = receipt.committed_at_ms
      AND pin.pinned_at_ms = origin.admitted_at_ms
    FOR KEY SHARE OF marker, receipt, pin;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM logical_workflow_runs AS marker
    JOIN workflow_admission_receipts AS receipt ON receipt.run_id = marker.run_id
    JOIN logical_workflow_runtime_policy_pins AS pin ON pin.run_id = marker.run_id
    JOIN security_audit_events AS audit
      ON audit.tenant_id = pin.tenant_id
     AND audit.action = 'workflow.dispatch'
     AND audit.outcome = 'succeeded'
     AND audit.resource_kind = 'workflow_run'
     AND audit.resource_id = marker.run_id::TEXT
     AND audit.occurred_at_ms = pin.pinned_at_ms
     AND audit.actor_kind = 'human'
     AND audit.actor_principal_id IS NOT NULL
     AND audit.actor_session_id IS NOT NULL
     AND audit.authorization_revision IS NOT NULL
    WHERE marker.run_id = NEW.run_id
      AND marker.root_invocation_id = NEW.invocation_id
      AND marker.admission_graph_sealed_at_ms IS NULL
      AND receipt.committed_at_ms IS NOT NULL
      AND receipt.github_subject_evidence_required = FALSE
      AND receipt.request_digest = marker.admission_digest
      AND pin.pinned_at_ms = receipt.committed_at_ms
    FOR KEY SHARE OF marker, receipt, pin, audit;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM logical_workflow_reusable_call_publications AS publication
    JOIN logical_workflow_runs AS marker ON marker.run_id = publication.run_id
    WHERE publication.run_id = NEW.run_id
      AND publication.child_invocation_id = NEW.invocation_id
      AND publication.child_graph_sealed_at_ms IS NULL
      AND marker.admission_graph_sealed_at_ms IS NOT NULL
      AND marker.state IN ('pending', 'active')
      AND NOT EXISTS (
          SELECT 1 FROM logical_workflow_run_result_claims AS claim
          WHERE claim.run_id = marker.run_id
      )
    FOR KEY SHARE OF publication, marker;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workflow graph insertion is outside an authenticated publication window'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_admission_graph_construction_window';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_preparation_binding_state_closure() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    current_claim logical_workflow_activation_preparation_claims%ROWTYPE;
    binding logical_workflow_activation_preparations%ROWTYPE;
    database_now BIGINT;
    closed BOOLEAN := FALSE;
BEGIN
    SELECT * INTO current_claim
    FROM logical_workflow_activation_preparation_claims
    WHERE logical_job_id = NEW.logical_job_id;
    IF current_claim.logical_job_id IS NULL THEN
        RAISE EXCEPTION 'preparation binding closure lost its durable claim'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_binding_claim_retained';
    END IF;
    PERFORM automata_require_active_unquarantined_workflow_phase(
        current_claim.run_id, current_claim.invocation_id,
        current_claim.logical_job_id, NULL
    );
    SELECT * INTO current_claim
    FROM logical_workflow_activation_preparation_claims
    WHERE logical_job_id = NEW.logical_job_id
    FOR UPDATE;
    SELECT * INTO binding
    FROM logical_workflow_activation_preparations
    WHERE logical_job_id = NEW.logical_job_id
    FOR SHARE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;

    IF current_claim.state = 'preparing' THEN
        closed := binding.logical_job_id IS NULL;
    ELSE
        closed := current_claim.state = 'prepared'
            AND binding.logical_job_id IS NOT NULL
            AND binding.run_id = current_claim.run_id
            AND binding.invocation_id = current_claim.invocation_id
            AND binding.descriptor_digest = current_claim.descriptor_digest
            AND binding.claim_owner_id = current_claim.owner_id
            AND binding.claim_generation = current_claim.generation
            AND binding.claim_started_at_ms = current_claim.claimed_at_ms
            AND binding.claim_expires_at_ms = current_claim.expires_at_ms
            AND binding.claim_origin_selection_id =
                current_claim.origin_selection_id
            AND binding.bound_at_ms = current_claim.updated_at_ms
            AND binding.runtime_policy_revision =
                current_claim.runtime_policy_revision
            AND binding.runtime_policy_digest = current_claim.runtime_policy_digest
            AND database_now >= current_claim.claimed_at_ms
            AND database_now < current_claim.expires_at_ms;
    END IF;
    IF closed IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'preparation binding and claim state are not closed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_binding_state_closure';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_preparation_claim_lineage() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    current_claim logical_workflow_activation_preparation_claims%ROWTYPE;
    current_state TEXT;
    event_exact BOOLEAN := FALSE;
    current_exact BOOLEAN := FALSE;
    database_now BIGINT;
BEGIN
    IF NEW.state = 'preparing' THEN
        SELECT (
            EXISTS (
                SELECT 1
                FROM logical_workflow_activation_work_selections AS selection
                JOIN workflow_runs AS run ON run.id = NEW.run_id
                JOIN repositories AS repository ON repository.id = run.repository_id
                WHERE selection.selection_id = NEW.origin_selection_id
                  AND selection.outcome = 'claimed'
                  AND selection.authority_kind = 'preparation'
                  AND selection.tenant_id = repository.tenant_id
                  AND selection.run_id = NEW.run_id
                  AND selection.invocation_id = NEW.invocation_id
                  AND selection.logical_job_id = NEW.logical_job_id
                  AND selection.owner_id = NEW.owner_id
                  AND selection.generation = NEW.generation
                  AND selection.claimed_at_ms = NEW.claimed_at_ms
                  AND selection.expires_at_ms = NEW.expires_at_ms
                  AND selection.authority_digest = NEW.descriptor_digest
            ) OR EXISTS (
                SELECT 1
                FROM logical_workflow_activation_renewal_receipts AS renewal
                JOIN workflow_runs AS run ON run.id = NEW.run_id
                JOIN repositories AS repository ON repository.id = run.repository_id
                WHERE renewal.selection_id = NEW.origin_selection_id
                  AND renewal.authority_kind = 'preparation'
                  AND renewal.tenant_id = repository.tenant_id
                  AND renewal.run_id = NEW.run_id
                  AND renewal.invocation_id = NEW.invocation_id
                  AND renewal.logical_job_id = NEW.logical_job_id
                  AND renewal.owner_id = NEW.owner_id
                  AND renewal.successor_generation = NEW.generation
                  AND renewal.successor_claimed_at_ms = NEW.claimed_at_ms
                  AND renewal.successor_expires_at_ms = NEW.expires_at_ms
                  AND renewal.authority_digest = NEW.descriptor_digest
                  AND renewal.runtime_policy_revision =
                      NEW.runtime_policy_revision
                  AND renewal.runtime_policy_digest = NEW.runtime_policy_digest
            )
        ) INTO event_exact;
        IF event_exact IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'preparation claim event lacks exact selection lineage'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_preparation_claim_lineage_exact';
        END IF;
    END IF;

    SELECT state INTO current_state
    FROM logical_workflow_activation_preparation_claims
    WHERE logical_job_id = NEW.logical_job_id;
    IF current_state IS NULL THEN
        RAISE EXCEPTION 'preparation claim lineage target disappeared'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_claim_lineage_retained';
    END IF;
    IF current_state <> 'preparing' THEN
        RETURN NULL;
    END IF;

    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
    );
    SELECT * INTO current_claim
    FROM logical_workflow_activation_preparation_claims
    WHERE logical_job_id = NEW.logical_job_id
    FOR UPDATE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT (
        EXISTS (
            SELECT 1
            FROM logical_workflow_activation_work_selections AS selection
            JOIN workflow_runs AS run ON run.id = current_claim.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE selection.selection_id = current_claim.origin_selection_id
              AND selection.outcome = 'claimed'
              AND selection.authority_kind = 'preparation'
              AND selection.tenant_id = repository.tenant_id
              AND selection.run_id = current_claim.run_id
              AND selection.invocation_id = current_claim.invocation_id
              AND selection.logical_job_id = current_claim.logical_job_id
              AND selection.owner_id = current_claim.owner_id
              AND selection.generation = current_claim.generation
              AND selection.claimed_at_ms = current_claim.claimed_at_ms
              AND selection.expires_at_ms = current_claim.expires_at_ms
              AND selection.authority_digest = current_claim.descriptor_digest
        ) OR EXISTS (
            SELECT 1
            FROM logical_workflow_activation_renewal_receipts AS renewal
            JOIN workflow_runs AS run ON run.id = current_claim.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE renewal.selection_id = current_claim.origin_selection_id
              AND renewal.authority_kind = 'preparation'
              AND renewal.tenant_id = repository.tenant_id
              AND renewal.run_id = current_claim.run_id
              AND renewal.invocation_id = current_claim.invocation_id
              AND renewal.logical_job_id = current_claim.logical_job_id
              AND renewal.owner_id = current_claim.owner_id
              AND renewal.successor_generation = current_claim.generation
              AND renewal.successor_claimed_at_ms = current_claim.claimed_at_ms
              AND renewal.successor_expires_at_ms = current_claim.expires_at_ms
              AND renewal.authority_digest = current_claim.descriptor_digest
              AND renewal.runtime_policy_revision =
                  current_claim.runtime_policy_revision
              AND renewal.runtime_policy_digest =
                  current_claim.runtime_policy_digest
        )
    ) INTO current_exact;
    IF current_exact IS DISTINCT FROM TRUE
        OR database_now < current_claim.claimed_at_ms
        OR current_claim.expires_at_ms - database_now < 1000
    THEN
        RAISE EXCEPTION 'active preparation claim lacks live exact lineage'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_claim_lineage_current';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_preparation_runner_policy_provenance() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.runner_policy_digest IS DISTINCT FROM OLD.runner_policy_digest
            OR NEW.runner_policy_object_key IS DISTINCT FROM OLD.runner_policy_object_key
            OR NEW.runner_policy_size_bytes IS DISTINCT FROM OLD.runner_policy_size_bytes
            OR NEW.runner_policy_media_type IS DISTINCT FROM OLD.runner_policy_media_type
        THEN
            RAISE EXCEPTION 'logical preparation runner policy is immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_preparation_runner_policy_immutable';
        END IF;
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM logical_workflow_jobs AS job
    JOIN logical_workflow_runtime_policy_pins AS pin ON pin.run_id = job.run_id
    JOIN github_workflow_run_manifest_origins AS origin
      ON origin.run_id = job.run_id
     AND origin.tenant_id = pin.tenant_id
     AND origin.repository_id = pin.repository_id
    JOIN workflow_admission_receipts AS receipt
      ON receipt.tenant_id = origin.tenant_id
     AND receipt.idempotency_kind = origin.admission_idempotency_kind
     AND receipt.idempotency_key = origin.admission_idempotency_key
     AND receipt.repository_id = origin.repository_id
     AND receipt.run_id = origin.run_id
     AND receipt.request_digest = origin.logical_admission_digest
     AND receipt.committed_at_ms = origin.admitted_at_ms
     AND receipt.github_subject_evidence_required
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = origin.tenant_id
     AND manifest.repository_id = origin.repository_id
     AND manifest.provider_connection_id = origin.provider_connection_id
     AND manifest.manifest_revision = origin.provider_manifest_revision
     AND manifest.manifest_digest = origin.provider_manifest_digest
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = pin.tenant_id
     AND policy.repository_id = pin.repository_id
     AND policy.policy_revision = pin.policy_revision
     AND policy.policy_digest = pin.policy_digest
     AND policy.state = 'sealed'
    WHERE job.run_id = NEW.run_id
      AND job.invocation_id = NEW.invocation_id
      AND job.id = NEW.logical_job_id
      AND NEW.runtime_policy_revision = pin.policy_revision
      AND NEW.runtime_policy_digest = pin.policy_digest
      AND manifest.runtime_policy_revision = pin.policy_revision
      AND manifest.runtime_policy_digest = pin.policy_digest
      AND NEW.runner_policy_digest = manifest.runner_policy_digest
      AND NEW.runner_policy_object_key = manifest.runner_policy_object_key
      AND NEW.runner_policy_size_bytes = manifest.runner_policy_size_bytes
      AND NEW.runner_policy_media_type = manifest.runner_policy_media_type
      AND NEW.runner_policy_digest = pg_catalog.sha256(policy.canonical_policy)
      AND NEW.runner_policy_size_bytes = pg_catalog.octet_length(policy.canonical_policy)
    FOR KEY SHARE OF job, pin, receipt, manifest, policy;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'logical preparation runner policy lacks authenticated manifest provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_runner_policy_provenance';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_pristine_logical_job_admission() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.rerun_carried THEN
        IF NEW.state NOT IN ('completed', 'skipped', 'cancelled', 'failed')
            OR NEW.activation_owner_id IS NOT NULL
            OR NEW.activation_claimed_at_ms IS NOT NULL
            OR NEW.activation_expires_at_ms IS NOT NULL
        THEN
            RAISE EXCEPTION 'carried logical job admission is not exact terminal evidence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_rerun_carried_job_terminal';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.state IS DISTINCT FROM 'pending'
        OR NEW.activation_fence IS DISTINCT FROM 0
        OR NEW.activation_owner_id IS NOT NULL
        OR NEW.activation_claimed_at_ms IS NOT NULL
        OR NEW.activation_expires_at_ms IS NOT NULL
        OR NEW.activation_input_digest IS NOT NULL
        OR NEW.authority_profile IS NOT NULL
        OR NEW.activation_origin_selection_id IS NOT NULL
    THEN
        RAISE EXCEPTION 'logical job admission must begin without activation authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_jobs_activation_admission_pristine';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_provider_delivery_workflow_progress_completion() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    requires_inventory BOOLEAN;
    inventory_count INTEGER;
    entry_count INTEGER;
    progress_count INTEGER;
    outcome_count INTEGER;
BEGIN
    IF NEW.state <> 'completed' OR OLD.state = 'completed' THEN
        RETURN NEW;
    END IF;

    SELECT manifest.workflow_selection_kind = 'all_direct'
      INTO requires_inventory
    FROM github_provider_delivery_evidence AS evidence
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = evidence.tenant_id
     AND manifest.repository_id = evidence.repository_id
     AND manifest.provider_connection_id = evidence.provider_connection_id
     AND manifest.manifest_revision = evidence.provider_manifest_revision
     AND manifest.manifest_digest = evidence.provider_manifest_digest
    WHERE evidence.provider_delivery_id = NEW.id;

    IF requires_inventory IS DISTINCT FROM TRUE
       AND NOT EXISTS (
           SELECT 1 FROM provider_delivery_workflow_inventories
           WHERE inbox_id = NEW.id
       )
    THEN
        RETURN NEW;
    END IF;

    SELECT inventory.workflow_count,
           (SELECT count(*) FROM provider_delivery_workflow_inventory_entries AS entry
             WHERE entry.inbox_id = NEW.id),
           (SELECT count(*) FROM provider_delivery_workflow_progress AS progress
             WHERE progress.inbox_id = NEW.id),
           (SELECT count(*) FROM provider_delivery_workflow_outcomes AS outcome
             WHERE outcome.inbox_id = NEW.id)
      INTO inventory_count, entry_count, progress_count, outcome_count
    FROM provider_delivery_workflow_inventories AS inventory
    WHERE inventory.inbox_id = NEW.id;

    IF NOT FOUND
        OR inventory_count <> entry_count
        OR inventory_count <> progress_count
        OR inventory_count <> outcome_count
        OR EXISTS (
            SELECT 1
            FROM provider_delivery_workflow_progress AS progress
            FULL JOIN provider_delivery_workflow_outcomes AS outcome
              ON outcome.inbox_id = progress.inbox_id
             AND outcome.workflow_path = progress.workflow_path
            WHERE coalesce(progress.inbox_id, outcome.inbox_id) = NEW.id
              AND (
                  progress.workflow_path IS NULL OR outcome.workflow_path IS NULL
                  OR progress.outcome_kind <> outcome.outcome_kind
                  OR progress.run_id IS DISTINCT FROM outcome.run_id
                  OR progress.failure_kind IS DISTINCT FROM outcome.failure_kind
              )
        )
    THEN
        RAISE EXCEPTION 'provider delivery completion does not match durable workflow progress'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'provider_delivery_workflow_progress_completion_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_renewal_receipt_parent_deleted() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    parent_exists BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'logical_workflow_activation_renewal_receipts' THEN
        SELECT EXISTS (
            SELECT 1 FROM logical_workflow_activation_work_selections
            WHERE selection_id = OLD.selection_id
        ) INTO parent_exists;
    ELSE
        SELECT EXISTS (
            SELECT 1 FROM logical_workflow_materialization_work_selections
            WHERE selection_id = OLD.selection_id
        ) INTO parent_exists;
    END IF;
    IF parent_exists THEN
        RAISE EXCEPTION 'renewal evidence is retained with its selection receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_real_claim_renewal_receipt_retained';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_runner_requirements_current() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT (
        NEW.requirements @> '{"schema_version": 1}'::jsonb
        AND NEW.requirements ? 'resource_allocation'
    ) OR NOT EXISTS (
        SELECT 1
        FROM workflow_runs AS run
        WHERE run.id = NEW.run_id
          AND run.runner_requirements_schema = 1
    ) THEN
        RAISE EXCEPTION 'new executable rows require runner-requirements schema v1'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_requirements_current_new_rows_only';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_runner_requirements_current_attempt() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM jobs AS job
        WHERE job.id = NEW.job_id
          AND job.requirements @> '{"schema_version": 1}'::jsonb
          AND job.requirements ? 'resource_allocation'
    ) THEN
        RAISE EXCEPTION 'new attempts require runner-requirements schema v1'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_runner_requirements_current_new_only';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_sealed_workflow_runtime_policy_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    durable_state TEXT;
    selected_current BOOLEAN := FALSE;
BEGIN
    SELECT state INTO durable_state
    FROM workflow_runtime_policy_revisions
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND policy_revision = NEW.policy_revision;
    SELECT EXISTS (
        SELECT 1
        FROM workflow_runtime_policy_current AS current_policy
        WHERE current_policy.tenant_id = NEW.tenant_id
          AND current_policy.repository_id = NEW.repository_id
          AND current_policy.policy_revision = NEW.policy_revision
          AND current_policy.policy_digest = NEW.policy_digest
    ) INTO selected_current;
    IF durable_state IS DISTINCT FROM 'sealed' OR selected_current IS NOT TRUE THEN
        RAISE EXCEPTION 'workflow runtime policy revision must seal and become current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_revision_must_be_current';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_secret_bindings_before_preparing() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    selected_count BIGINT;
    bound_count BIGINT;
    database_now_ms BIGINT;
BEGIN
    IF OLD.lifecycle <> 'leased' OR NEW.lifecycle <> 'preparing'
       OR NOT EXISTS (
           SELECT 1 FROM logical_workflow_concrete_jobs WHERE job_id = NEW.job_id
       ) THEN
        RETURN NEW;
    END IF;
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT count(*) INTO selected_count
    FROM job_secret_selections WHERE attempt_id = NEW.id;
    SELECT count(*) INTO bound_count
    FROM job_secret_bindings AS binding
    JOIN secret_workload_grants AS workload_grant
      ON workload_grant.tenant_id = binding.tenant_id
     AND workload_grant.id = binding.grant_id
    WHERE binding.attempt_id = NEW.id
      AND binding.lease_id = NEW.lease_id
      AND binding.fencing_token = NEW.fencing_token
      AND workload_grant.status = 'active'
      AND workload_grant.lease_id = NEW.lease_id
      AND workload_grant.fencing_token = NEW.fencing_token
      AND database_now_ms < workload_grant.expires_at_ms;
    IF bound_count <> selected_count THEN
        RAISE EXCEPTION 'job cannot prepare before every selected secret is lease-bound'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_secret_bindings_complete';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_staging_workflow_runtime_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    parent_state TEXT;
    declared_count INTEGER;
    inserted_count INTEGER;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'workflow runtime policy catalog rows are immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_catalog_immutable';
    END IF;
    SELECT state INTO parent_state
    FROM workflow_runtime_policy_revisions
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND policy_revision = NEW.policy_revision
    FOR UPDATE;
    IF parent_state IS DISTINCT FROM 'staging' THEN
        RAISE EXCEPTION 'workflow runtime policy catalog is sealed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_catalog_sealed';
    END IF;
    IF TG_TABLE_NAME = 'workflow_runtime_policy_mappings' THEN
        SELECT mapping_count INTO declared_count
        FROM workflow_runtime_policy_revisions
        WHERE tenant_id = NEW.tenant_id
          AND repository_id = NEW.repository_id
          AND policy_revision = NEW.policy_revision;
        SELECT count(*)::INTEGER INTO inserted_count
        FROM workflow_runtime_policy_mappings
        WHERE tenant_id = NEW.tenant_id
          AND repository_id = NEW.repository_id
          AND policy_revision = NEW.policy_revision;
        IF inserted_count >= declared_count OR inserted_count >= 64 THEN
            RAISE EXCEPTION 'workflow runtime policy mapping census exceeded'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_runtime_policy_mapping_insert_census';
        END IF;
    ELSE
        SELECT feature_count INTO declared_count
        FROM workflow_runtime_policy_mappings
        WHERE tenant_id = NEW.tenant_id
          AND repository_id = NEW.repository_id
          AND policy_revision = NEW.policy_revision
          AND selector = NEW.selector
        FOR UPDATE;
        SELECT count(*)::INTEGER INTO inserted_count
        FROM workflow_runtime_policy_features
        WHERE tenant_id = NEW.tenant_id
          AND repository_id = NEW.repository_id
          AND policy_revision = NEW.policy_revision
          AND selector = NEW.selector;
        IF declared_count IS NULL
            OR inserted_count >= declared_count
            OR inserted_count >= 64
        THEN
            RAISE EXCEPTION 'workflow runtime policy feature census exceeded'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_runtime_policy_feature_insert_census';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_standard_github_oidc_profile() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM github_workflow_run_manifest_origins AS origin
        JOIN logical_workflow_runs AS marker
          ON marker.run_id = origin.run_id
         AND marker.root_invocation_id = origin.root_invocation_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.instance_id = NEW.instance_id
         AND concrete.run_id = NEW.run_id
         AND concrete.invocation_id = NEW.invocation_id
         AND concrete.logical_job_id = NEW.logical_job_id
         AND concrete.job_id = NEW.job_id
         AND concrete.initial_attempt_id = NEW.attempt_id
        WHERE origin.tenant_id = NEW.tenant_id
          AND origin.repository_id = NEW.repository_id
          AND origin.workflow_id = NEW.workflow_id
          AND origin.run_id = NEW.run_id
          AND origin.subject_evidence_sha256 =
              NEW.github_run_subject_evidence_sha256
          AND (
              origin.origin_kind = 'provider_delivery'
              AND origin.admission_idempotency_kind = 'provider_delivery'
              OR origin.origin_kind IN ('scheduled_fire', 'workflow_rerun')
              AND origin.admission_idempotency_kind = 'operation'
          )
          AND automata_logical_workflow_invocation_published(
              NEW.run_id, NEW.invocation_id
          )
          AND automata_reusable_workflow_oidc_permission_authorized(
              NEW.run_id, NEW.invocation_id
          )
          AND manifest.authority_profile = 'standard'
          AND concrete.authority_profile = 'standard'
    ) THEN
        RAISE EXCEPTION 'GitHub-compatible OIDC requires historical Standard authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'github_oidc_historical_standard_authority';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_logical_workflow_concrete_job_link() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM logical_workflow_runs WHERE run_id = NEW.run_id
    ) AND NOT EXISTS (
        SELECT 1
        FROM logical_workflow_concrete_jobs AS concrete
        JOIN logical_workflow_materialization_claims AS claim
          ON claim.instance_id = concrete.instance_id
        WHERE concrete.run_id = NEW.run_id
          AND concrete.job_id = NEW.id
          AND claim.state = 'materialized'
    ) THEN
        RAISE EXCEPTION 'logical workflow concrete job is not linked to materialized instance'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_logical_workflow_nonempty_root() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    target_run UUID;
BEGIN
    target_run := CASE WHEN TG_OP = 'DELETE' THEN OLD.run_id ELSE NEW.run_id END;
    IF EXISTS (
        SELECT 1
        FROM logical_workflow_runs AS marker
        WHERE marker.run_id = target_run
          AND NOT EXISTS (
              SELECT 1
              FROM logical_workflow_jobs AS job
              WHERE job.run_id = marker.run_id
                AND job.invocation_id = marker.root_invocation_id
          )
    ) THEN
        RAISE EXCEPTION 'current logical workflow admission requires at least one job'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_workflow_run_results_nonempty_current_run';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_logical_workflow_runner_requirements_current() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.runner_requirements_schema <> 1
       OR NOT EXISTS (
           SELECT 1
           FROM workflow_runs AS run
           WHERE run.id = NEW.run_id
             AND run.runner_requirements_schema = 1
       )
    THEN
        RAISE EXCEPTION 'new logical workflow runs require runner-requirements schema v1'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_runs_runner_requirements_current_new_only';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_workflow_rerun_audit_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    candidate_run_id UUID;
BEGIN
    candidate_run_id := NEW.run_id;
    IF EXISTS (
        SELECT 1
        FROM workflow_rerun_attempts AS attempt
        WHERE attempt.run_id = candidate_run_id
          AND attempt.source_run_id IS NOT NULL
    ) AND NOT EXISTS (
        SELECT 1
        FROM workflow_rerun_audit_evidence AS evidence
        WHERE evidence.run_id = candidate_run_id
    ) THEN
        RAISE EXCEPTION 'workflow rerun requires atomic audit evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_audit_evidence_required';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_workflow_run_runner_requirements_current() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.runner_requirements_schema <> 1 THEN
        RAISE EXCEPTION 'new workflow runs require the current runner-requirements schema'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runs_runner_requirements_current_new_only';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_workflow_runtime_policy_pin() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_runtime_policy_pins AS pin
        WHERE pin.run_id = NEW.run_id
    ) OR EXISTS (
        SELECT 1 FROM logical_workflow_runs AS marker
        WHERE marker.run_id = NEW.run_id
          AND marker.admission_graph_sealed_at_ms IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM logical_workflow_jobs AS job WHERE job.run_id = NEW.run_id
    ) OR EXISTS (
        SELECT 1
        FROM logical_workflow_jobs AS job
        JOIN logical_workflow_runtime_policy_pins AS pin ON pin.run_id = job.run_id
        WHERE job.run_id = NEW.run_id
          AND (job.runtime_policy_revision, job.runtime_policy_digest)
              IS DISTINCT FROM (pin.policy_revision, pin.policy_digest)
    ) THEN
        RAISE EXCEPTION 'logical workflow admission requires authenticated provider runtime policy'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_runtime_policy_pin_required';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_workflow_runtime_policy_pin_provenance() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM 1
    FROM github_workflow_run_manifest_origins AS origin
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = origin.tenant_id
     AND manifest.repository_id = origin.repository_id
     AND manifest.provider_connection_id = origin.provider_connection_id
     AND manifest.manifest_revision = origin.provider_manifest_revision
     AND manifest.manifest_digest = origin.provider_manifest_digest
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = manifest.tenant_id
     AND policy.repository_id = manifest.repository_id
     AND policy.policy_revision = manifest.runtime_policy_revision
     AND policy.policy_digest = manifest.runtime_policy_digest
     AND policy.state = 'sealed'
    JOIN workflow_runs AS run
      ON run.id = origin.run_id
     AND run.repository_id = origin.repository_id
    JOIN logical_workflow_runs AS marker ON marker.run_id = origin.run_id
    WHERE origin.run_id = NEW.run_id
      AND origin.tenant_id = NEW.tenant_id
      AND origin.repository_id = NEW.repository_id
      AND origin.admitted_at_ms = NEW.pinned_at_ms
      AND manifest.runtime_policy_revision = NEW.policy_revision
      AND manifest.runtime_policy_digest = NEW.policy_digest
    FOR SHARE OF manifest, policy, run, marker;
    IF FOUND THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM workflow_runs AS run
    JOIN logical_workflow_runs AS marker ON marker.run_id = run.id
    JOIN security_audit_events AS audit
      ON audit.tenant_id = NEW.tenant_id
     AND audit.action = 'workflow.dispatch'
     AND audit.outcome = 'succeeded'
     AND audit.resource_kind = 'workflow_run'
     AND audit.resource_id = NEW.run_id::TEXT
     AND audit.occurred_at_ms = NEW.pinned_at_ms
     AND audit.actor_kind = 'human'
     AND audit.actor_principal_id IS NOT NULL
     AND audit.actor_session_id IS NOT NULL
     AND audit.authorization_revision IS NOT NULL
    JOIN github_provider_manifest_current AS current_manifest
      ON current_manifest.tenant_id = NEW.tenant_id
     AND current_manifest.repository_id = NEW.repository_id
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = current_manifest.tenant_id
     AND manifest.repository_id = current_manifest.repository_id
     AND manifest.provider_connection_id = current_manifest.provider_connection_id
     AND manifest.manifest_revision = current_manifest.manifest_revision
     AND manifest.manifest_digest = current_manifest.manifest_digest
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = manifest.tenant_id
     AND policy.repository_id = manifest.repository_id
     AND policy.policy_revision = manifest.runtime_policy_revision
     AND policy.policy_digest = manifest.runtime_policy_digest
     AND policy.state = 'sealed'
    WHERE run.id = NEW.run_id
      AND run.repository_id = NEW.repository_id
      AND manifest.runtime_policy_revision = NEW.policy_revision
      AND manifest.runtime_policy_digest = NEW.policy_digest
    FOR SHARE OF run, marker, audit, current_manifest, manifest, policy;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workflow runtime policy pin lacks authenticated manifest provenance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_runtime_policy_pin_provenance';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_required_github_subject_evidence_committed() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    receipt workflow_admission_receipts%ROWTYPE;
    evidence_count BIGINT;
BEGIN
    IF NOT NEW.github_subject_evidence_required THEN
        RETURN NULL;
    END IF;

    SELECT * INTO receipt
    FROM workflow_admission_receipts
    WHERE tenant_id = NEW.tenant_id
      AND idempotency_kind = NEW.idempotency_kind
      AND idempotency_key = NEW.idempotency_key;

    IF receipt.github_subject_evidence_required
        AND receipt.idempotency_kind = 'provider_delivery'
        AND receipt.repository_id IS NOT NULL
        AND receipt.run_id IS NOT NULL
        AND receipt.committed_at_ms IS NOT NULL
    THEN
        SELECT count(*) INTO evidence_count
        FROM github_workflow_run_subject_evidence AS evidence
        WHERE evidence.tenant_id = receipt.tenant_id
          AND evidence.repository_id = receipt.repository_id
          AND evidence.run_id = receipt.run_id
          AND evidence.provider_delivery_idempotency_key = receipt.idempotency_key
          AND evidence.logical_admission_digest = receipt.request_digest
          AND evidence.admitted_at_ms = receipt.committed_at_ms;
    ELSIF receipt.github_subject_evidence_required
        AND receipt.idempotency_kind = 'operation'
        AND receipt.idempotency_key LIKE 'workflow-rerun:%'
        AND receipt.repository_id IS NOT NULL
        AND receipt.run_id IS NOT NULL
        AND receipt.committed_at_ms IS NOT NULL
    THEN
        SELECT count(*) INTO evidence_count
        FROM github_workflow_rerun_subject_evidence AS evidence
        WHERE evidence.tenant_id = receipt.tenant_id
          AND evidence.repository_id = receipt.repository_id
          AND evidence.run_id = receipt.run_id
          AND 'workflow-rerun:' || evidence.operation_id::TEXT =
              receipt.idempotency_key
          AND evidence.logical_admission_digest = receipt.request_digest
          AND evidence.admitted_at_ms = receipt.committed_at_ms;
    END IF;

    IF evidence_count IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'authenticated GitHub admission requires exact subject evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_admission_required_github_evidence_exact';
    END IF;
    RETURN NULL;
END;
$$;
