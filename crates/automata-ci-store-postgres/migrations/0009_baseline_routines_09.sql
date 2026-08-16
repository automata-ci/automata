-- Frozen greenfield baseline. Add a new migration instead of editing this stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_reject_github_runtime_authority_claim_evidence_truncat() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'GitHub runtime-authority claim evidence cannot be truncated'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_runtime_authority_claim_evidence_truncate';
END;
$$;

CREATE FUNCTION automata_reject_github_runtime_authority_lease_renewal_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'GitHub runtime authority lease renewal evidence is append-only'
        USING ERRCODE = 'check_violation',
              CONSTRAINT =
                  'github_runtime_authority_lease_renewal_receipts_append_only';
END;
$$;

CREATE FUNCTION automata_reject_github_runtime_authority_operation_receipt_trun() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'GitHub runtime-authority operation receipts cannot be truncated'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_runtime_authority_operation_receipt_truncate';
END;
$$;

CREATE FUNCTION automata_reject_github_runtime_authority_removal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'GitHub runtime authority audit identity cannot be removed'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_runtime_authority_removal_forbidden';
END;
$$;

CREATE FUNCTION automata_reject_github_schedule_evidence_truncate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'GitHub schedule evidence cannot be truncated'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'github_schedule_evidence_truncate_forbidden';
END;
$$;

CREATE FUNCTION automata_reject_github_schedule_immutable_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'immutable GitHub schedule evidence cannot be mutated'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'github_schedule_immutable_evidence';
END;
$$;

CREATE FUNCTION automata_reject_installation_singleton_replacement() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'installation singleton cannot be inserted, deleted, or truncated'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'installation_state_singleton_immutable';
END;
$$;

CREATE FUNCTION automata_reject_job_environment_evidence_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'activation environment evidence is append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'job_environment_evidence_append_only';
END;
$$;

CREATE FUNCTION automata_reject_job_plan_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'immutable Automata job plans cannot be updated'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'jobs_plan_immutable';
END;
$$;

CREATE FUNCTION automata_reject_job_variable_lease_without_custody() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.lifecycle = 'queued'
       AND NEW.lifecycle = 'leased'
       AND EXISTS (
           SELECT 1
           FROM logical_workflow_concrete_jobs AS concrete
           JOIN logical_workflow_jobs AS logical_job
             ON logical_job.run_id = concrete.run_id
            AND logical_job.invocation_id = concrete.invocation_id
            AND logical_job.id = concrete.logical_job_id
           WHERE concrete.job_id = NEW.job_id
             AND cardinality(logical_job.variable_reference_names) > 0
       ) THEN
        RAISE EXCEPTION 'variable-bearing jobs require an exact custody receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_variable_custody_required';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_reject_logical_activation_preparation_claim_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'logical activation preparation claim is durable'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_reject_logical_activation_preparation_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'logical activation preparation evidence is immutable'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_reject_logical_preparation_base_context_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.base_context_digest IS DISTINCT FROM OLD.base_context_digest
        OR NEW.base_context_object_key IS DISTINCT FROM OLD.base_context_object_key
        OR NEW.base_context_size_bytes IS DISTINCT FROM OLD.base_context_size_bytes
        OR NEW.base_context_media_type IS DISTINCT FROM OLD.base_context_media_type
        OR NEW.base_context_schema IS DISTINCT FROM OLD.base_context_schema
    THEN
        RAISE EXCEPTION 'logical preparation base context is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_workflow_activation_preparation_base_context_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_reject_logical_run_base_context_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.base_context_digest IS DISTINCT FROM OLD.base_context_digest
        OR NEW.base_context_object_key IS DISTINCT FROM OLD.base_context_object_key
        OR NEW.base_context_size_bytes IS DISTINCT FROM OLD.base_context_size_bytes
        OR NEW.base_context_media_type IS DISTINCT FROM OLD.base_context_media_type
        OR NEW.base_context_schema IS DISTINCT FROM OLD.base_context_schema
    THEN
        RAISE EXCEPTION 'logical workflow base context is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_workflow_runs_base_context_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_reject_provider_delivery_outcome_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'provider delivery terminal outcomes are immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'provider_delivery_workflow_outcomes_immutable';
END;
$$;

CREATE FUNCTION automata_reject_provider_delivery_removal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'provider delivery evidence cannot be removed'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'provider_delivery_inbox_removal_forbidden';
END;
$$;

CREATE FUNCTION automata_reject_provider_delivery_workflow_progress_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'provider delivery workflow progress is immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'provider_delivery_workflow_progress_immutable';
END;
$$;

CREATE FUNCTION automata_reject_retained_attempt_terminal_result_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM job_attempts AS attempt WHERE attempt.id = OLD.attempt_id
    ) THEN
        RAISE EXCEPTION 'retained attempt terminal result evidence is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION automata_reject_retained_logical_workflow_instance_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM logical_workflow_activation_publications AS publication
        WHERE publication.run_id = OLD.run_id
          AND publication.invocation_id = OLD.invocation_id
          AND publication.logical_job_id = OLD.logical_job_id
    ) THEN
        RAISE EXCEPTION 'retained logical workflow instance evidence is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION automata_reject_reusable_runtime_evidence_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'reusable workflow runtime evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'logical_workflow_reusable_runtime_immutable';
END;
$$;

CREATE FUNCTION automata_reject_reusable_workflow_ledger_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'reusable workflow catalog and expansion evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'logical_workflow_reusable_expansion_immutable';
END;
$$;

CREATE FUNCTION automata_reject_logical_workflow_concrete_job_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'logical workflow concrete materialization evidence is immutable'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_reject_logical_workflow_concurrency_cancellation_mutat() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'Logical concurrency cancellation evidence is immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'logical_workflow_concurrency_cancellation_immutable';
END;
$$;

CREATE FUNCTION automata_reject_logical_workflow_dependency_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'logical workflow dependency edges are immutable'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_reject_logical_workflow_instance_result_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'logical workflow instance-result evidence is immutable'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_reject_logical_workflow_instance_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'logical workflow instance descriptor is immutable'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_reject_logical_workflow_job_result_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'logical workflow logical-job result evidence is immutable'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_reject_logical_workflow_dependency() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM logical_workflow_runs WHERE run_id = NEW.run_id
    ) THEN
        RAISE EXCEPTION 'logical workflow jobs do not use job dependencies'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_reject_logical_workflow_publication_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM logical_workflow_jobs AS job
        WHERE job.run_id = OLD.run_id
          AND job.invocation_id = OLD.invocation_id
          AND job.id = OLD.logical_job_id
    ) THEN
        RAISE EXCEPTION 'logical workflow activation publication is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION automata_reject_logical_workflow_publication_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'logical workflow activation publication is immutable'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_reject_logical_workflow_result_evidence_removal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'logical workflow logical result evidence cannot be removed'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_reject_logical_workflow_result_selection_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    target_queue_name TEXT;
    replay_floor BIGINT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_queue_name := CASE TG_TABLE_NAME
            WHEN 'logical_workflow_instance_result_selections' THEN 'instance'
            WHEN 'logical_workflow_job_result_selections' THEN 'job'
            ELSE NULL
        END;
        SELECT horizon.replay_floor_ms INTO replay_floor
        FROM logical_workflow_result_selection_replay_horizons AS horizon
        WHERE horizon.queue_name = target_queue_name;
        IF OLD.expires_at_ms <= replay_floor THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'logical result selection receipts are immutable'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_reject_logical_workflow_run_result_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'logical workflow run-result evidence is immutable'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_reject_workflow_rerun_attempt_job_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'workflow rerun graph evidence is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'workflow_rerun_attempt_jobs_immutable';
END;
$$;

CREATE FUNCTION automata_reject_workflow_rerun_attempt_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'workflow rerun attempt evidence is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'workflow_rerun_attempts_immutable';
END;
$$;

CREATE FUNCTION automata_reject_workflow_rerun_audit_evidence_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'workflow rerun audit evidence is immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'workflow_rerun_audit_evidence_immutable';
END;
$$;

CREATE FUNCTION automata_reject_workflow_rerun_carried_flag_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.rerun_carried IS DISTINCT FROM OLD.rerun_carried THEN
        RAISE EXCEPTION 'logical job rerun carry classification is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_workflow_jobs_rerun_carried_immutable';
    END IF;
    IF OLD.rerun_carried AND (
        NEW.state IS DISTINCT FROM OLD.state
        OR NEW.updated_at_ms IS DISTINCT FROM OLD.updated_at_ms
        OR NEW.activation_fence IS DISTINCT FROM OLD.activation_fence
        OR NEW.activation_owner_id IS DISTINCT FROM OLD.activation_owner_id
        OR NEW.activation_claimed_at_ms IS DISTINCT FROM OLD.activation_claimed_at_ms
        OR NEW.activation_expires_at_ms IS DISTINCT FROM OLD.activation_expires_at_ms
        OR NEW.activation_input_digest IS DISTINCT FROM OLD.activation_input_digest
        OR NEW.authority_profile IS DISTINCT FROM OLD.authority_profile
        OR NEW.activation_origin_selection_id IS DISTINCT FROM
           OLD.activation_origin_selection_id
    ) THEN
        RAISE EXCEPTION 'carried logical job execution evidence is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_rerun_carried_job_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_reject_workflow_rerun_carry_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'workflow rerun carry-forward evidence is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'workflow_rerun_carry_forward_immutable';
END;
$$;

CREATE FUNCTION automata_reject_workflow_rerun_check_evidence_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'workflow rerun Check evidence is immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'workflow_rerun_check_evidence_immutable';
END;
$$;

CREATE FUNCTION automata_reject_workflow_rerun_request_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'workflow rerun request evidence is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'workflow_rerun_requests_immutable';
END;
$$;

CREATE FUNCTION automata_reject_workflow_rerun_subject_evidence_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'workflow rerun run-subject evidence is immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'github_workflow_rerun_subject_evidence_immutable';
END;
$$;

CREATE FUNCTION automata_reject_workflow_run_id_alias_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.run_id_alias IS DISTINCT FROM OLD.run_id_alias THEN
        RAISE EXCEPTION 'workflow run ID alias is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_runs_id_alias_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_reject_workflow_run_rerun_identity_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.public_run_id_alias IS DISTINCT FROM OLD.public_run_id_alias
       OR NEW.triggering_actor IS DISTINCT FROM OLD.triggering_actor
       OR NEW.concurrency_cancel_in_progress IS DISTINCT FROM
          OLD.concurrency_cancel_in_progress
    THEN
        RAISE EXCEPTION 'workflow rerun identity is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_runs_rerun_identity_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_reject_workflow_runtime_policy_retained_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'retained workflow runtime policy evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'workflow_runtime_policy_retained_immutable';
END;
$$;

CREATE FUNCTION automata_reject_workflow_variable_version_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'workflow variable versions are append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'workflow_variable_versions_append_only';
END;
$$;

CREATE FUNCTION automata_reject_workflow_work_evidence_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'workflow work-selection evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'workflow_work_selection_evidence_immutable';
END;
$$;

CREATE FUNCTION automata_repository_environment_reviewer_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    current_revision BIGINT;
    current_status TEXT;
    current_protection TEXT;
    reviewer_status TEXT;
    reviewer_authorization_revision BIGINT;
    grantor_status TEXT;
    current_grantor_authorization_revision BIGINT;
    database_now_ms BIGINT;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'environment reviewer assignments are append-only'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'repository_environment_reviewers_append_only';
    END IF;
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT revision, status, protection_mode
    INTO STRICT current_revision, current_status, current_protection
    FROM repository_environments
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND id = NEW.environment_id
    FOR SHARE;
    SELECT status, authorization_revision
    INTO STRICT reviewer_status, reviewer_authorization_revision
    FROM tenant_human_memberships
    WHERE tenant_id = NEW.tenant_id AND principal_id = NEW.principal_id
    FOR SHARE;
    IF NEW.granted_by_principal_id IS NOT NULL THEN
        SELECT status, authorization_revision
        INTO STRICT grantor_status, current_grantor_authorization_revision
        FROM tenant_human_memberships
        WHERE tenant_id = NEW.tenant_id
          AND principal_id = NEW.granted_by_principal_id
        FOR SHARE;
    END IF;
    IF NEW.environment_revision <> current_revision
       OR current_status <> 'active'
       OR current_protection <> 'required_approvals'
       OR reviewer_status <> 'active'
       OR NEW.principal_authorization_revision <> reviewer_authorization_revision
       OR NOT automata_principal_has_repository_permission(
           NEW.tenant_id, NEW.principal_id, NEW.repository_id,
           'environments:approve', database_now_ms
       )
       OR grantor_status <> 'active'
       OR NEW.grantor_authorization_revision <>
          current_grantor_authorization_revision
       OR NOT automata_principal_has_repository_permission(
           NEW.tenant_id, NEW.granted_by_principal_id, NEW.repository_id,
           'environments:manage', database_now_ms
       )
       OR NEW.granted_at_ms > database_now_ms
       OR database_now_ms - NEW.granted_at_ms > 60000 THEN
        RAISE EXCEPTION 'environment reviewer assignment is stale'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'repository_environment_reviewers_current';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_repository_environment_revision_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    settings_changed BOOLEAN;
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.name IS DISTINCT FROM OLD.name
       OR NEW.normalized_name IS DISTINCT FROM OLD.normalized_name
       OR NEW.created_by_principal_id IS DISTINCT FROM OLD.created_by_principal_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'protected environment identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'repository_environments_identity_immutable';
    END IF;

    settings_changed :=
        NEW.protection_mode IS DISTINCT FROM OLD.protection_mode
        OR NEW.required_approvals IS DISTINCT FROM OLD.required_approvals
        OR NEW.prevent_self_review IS DISTINCT FROM OLD.prevent_self_review
        OR NEW.status IS DISTINCT FROM OLD.status;
    IF settings_changed AND NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'protected environment settings require one revision increment'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'repository_environments_revision_guard';
    ELSIF NOT settings_changed AND NEW.revision <> OLD.revision THEN
        RAISE EXCEPTION 'protected environment revision changed without settings'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'repository_environments_revision_guard';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_activation_claim_lineage() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    current_job logical_workflow_jobs%ROWTYPE;
    current_state TEXT;
    event_exact BOOLEAN := FALSE;
    current_exact BOOLEAN := FALSE;
    database_now BIGINT;
BEGIN
    IF NEW.state = 'activating' THEN
        SELECT (
            EXISTS (
                SELECT 1
                FROM logical_workflow_activation_work_selections AS selection
                JOIN workflow_runs AS run ON run.id = NEW.run_id
                JOIN repositories AS repository ON repository.id = run.repository_id
                WHERE selection.selection_id =
                      NEW.activation_origin_selection_id
                  AND selection.outcome = 'claimed'
                  AND selection.authority_kind = 'activation'
                  AND selection.tenant_id = repository.tenant_id
                  AND selection.run_id = NEW.run_id
                  AND selection.invocation_id = NEW.invocation_id
                  AND selection.logical_job_id = NEW.id
                  AND selection.owner_id = NEW.activation_owner_id
                  AND selection.generation = NEW.activation_fence
                  AND selection.claimed_at_ms = NEW.activation_claimed_at_ms
                  AND selection.expires_at_ms = NEW.activation_expires_at_ms
                  AND selection.authority_digest = NEW.activation_input_digest
            ) OR EXISTS (
                SELECT 1
                FROM logical_workflow_activation_renewal_receipts AS renewal
                JOIN workflow_runs AS run ON run.id = NEW.run_id
                JOIN repositories AS repository ON repository.id = run.repository_id
                WHERE renewal.selection_id =
                      NEW.activation_origin_selection_id
                  AND renewal.authority_kind = 'activation'
                  AND renewal.tenant_id = repository.tenant_id
                  AND renewal.run_id = NEW.run_id
                  AND renewal.invocation_id = NEW.invocation_id
                  AND renewal.logical_job_id = NEW.id
                  AND renewal.owner_id = NEW.activation_owner_id
                  AND renewal.successor_generation = NEW.activation_fence
                  AND renewal.successor_claimed_at_ms =
                      NEW.activation_claimed_at_ms
                  AND renewal.successor_expires_at_ms =
                      NEW.activation_expires_at_ms
                  AND renewal.authority_digest = NEW.activation_input_digest
                  AND renewal.runtime_policy_revision =
                      NEW.runtime_policy_revision
                  AND renewal.runtime_policy_digest = NEW.runtime_policy_digest
            )
        ) INTO event_exact;
        IF event_exact IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'activation claim event lacks exact selection lineage'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_claim_lineage_exact';
        END IF;
    END IF;

    SELECT state INTO current_state
    FROM logical_workflow_jobs
    WHERE run_id = NEW.run_id
      AND invocation_id = NEW.invocation_id
      AND id = NEW.id;
    IF current_state IS NULL THEN
        RAISE EXCEPTION 'activation claim lineage target disappeared'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_claim_lineage_retained';
    END IF;
    IF current_state <> 'activating' THEN
        RETURN NULL;
    END IF;

    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.id, NULL
    );
    SELECT * INTO current_job
    FROM logical_workflow_jobs
    WHERE run_id = NEW.run_id
      AND invocation_id = NEW.invocation_id
      AND id = NEW.id
    FOR UPDATE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT (
        EXISTS (
            SELECT 1
            FROM logical_workflow_activation_work_selections AS selection
            JOIN workflow_runs AS run ON run.id = current_job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE selection.selection_id =
                  current_job.activation_origin_selection_id
              AND selection.outcome = 'claimed'
              AND selection.authority_kind = 'activation'
              AND selection.tenant_id = repository.tenant_id
              AND selection.run_id = current_job.run_id
              AND selection.invocation_id = current_job.invocation_id
              AND selection.logical_job_id = current_job.id
              AND selection.owner_id = current_job.activation_owner_id
              AND selection.generation = current_job.activation_fence
              AND selection.claimed_at_ms =
                  current_job.activation_claimed_at_ms
              AND selection.expires_at_ms =
                  current_job.activation_expires_at_ms
              AND selection.authority_digest =
                  current_job.activation_input_digest
        ) OR EXISTS (
            SELECT 1
            FROM logical_workflow_activation_renewal_receipts AS renewal
            JOIN workflow_runs AS run ON run.id = current_job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE renewal.selection_id =
                  current_job.activation_origin_selection_id
              AND renewal.authority_kind = 'activation'
              AND renewal.tenant_id = repository.tenant_id
              AND renewal.run_id = current_job.run_id
              AND renewal.invocation_id = current_job.invocation_id
              AND renewal.logical_job_id = current_job.id
              AND renewal.owner_id = current_job.activation_owner_id
              AND renewal.successor_generation = current_job.activation_fence
              AND renewal.successor_claimed_at_ms =
                  current_job.activation_claimed_at_ms
              AND renewal.successor_expires_at_ms =
                  current_job.activation_expires_at_ms
              AND renewal.authority_digest =
                  current_job.activation_input_digest
              AND renewal.runtime_policy_revision =
                  current_job.runtime_policy_revision
              AND renewal.runtime_policy_digest =
                  current_job.runtime_policy_digest
        )
    ) INTO current_exact;
    IF current_exact IS DISTINCT FROM TRUE
        OR database_now < current_job.activation_claimed_at_ms
        OR current_job.activation_expires_at_ms - database_now < 1000
    THEN
        RAISE EXCEPTION 'active activation claim lacks live exact lineage'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_claim_lineage_current';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_activation_publication_state_closure() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    closed BOOLEAN := FALSE;
    database_now BIGINT;
BEGIN
    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
    );
    SELECT job.activation_fence = NEW.activation_generation
           AND job.activation_input_digest = NEW.activation_input_digest
           AND job.runtime_policy_revision = NEW.runtime_policy_revision
           AND job.runtime_policy_digest = NEW.runtime_policy_digest
           AND ((NEW.condition_matched AND job.state IN
                    ('activated', 'completed', 'failed', 'cancelled'))
                OR (NOT NEW.condition_matched AND job.state = 'skipped'))
      INTO closed
    FROM logical_workflow_jobs AS job
    WHERE job.run_id = NEW.run_id
      AND job.invocation_id = NEW.invocation_id
      AND job.id = NEW.logical_job_id
    FOR UPDATE OF job;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF closed IS DISTINCT FROM TRUE
        OR database_now < NEW.activation_claimed_at_ms
        OR database_now >= NEW.activation_expires_at_ms
    THEN
        RAISE EXCEPTION 'activation publication and terminal job state are not closed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_publication_state_closure';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_active_unquarantined_phase_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
    );
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_active_unquarantined_workflow_phase(target_run_id uuid, target_invocation_id uuid, target_logical_job_id uuid, target_instance_id uuid) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    graph_active BOOLEAN;
BEGIN
    SELECT run.status IN ('queued', 'in_progress')
           AND run.admission_epoch = 1
           AND run.plan_schema = 1
      INTO graph_active
    FROM workflow_runs AS run
    WHERE run.id = target_run_id
    FOR SHARE OF run;
    IF graph_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow phase mutation requires an active run'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_run_active';
    END IF;

    SELECT marker.state IN ('pending', 'active')
           AND marker.orchestration_schema = 1
           AND marker.admission_graph_sealed_at_ms IS NOT NULL
           AND automata_logical_workflow_invocation_published(
               marker.run_id, target_invocation_id
           )
      INTO graph_active
    FROM logical_workflow_runs AS marker
    WHERE marker.run_id = target_run_id
    FOR SHARE OF marker;
    IF graph_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow phase mutation requires an active published marker'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_marker_active';
    END IF;

    SELECT invocation.state IN ('pending', 'active')
           AND invocation.plan_schema = 1
      INTO graph_active
    FROM logical_workflow_invocations AS invocation
    WHERE invocation.run_id = target_run_id
      AND invocation.id = target_invocation_id
    FOR SHARE OF invocation;
    IF graph_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow phase mutation requires an active invocation'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_invocation_active';
    END IF;

    SELECT TRUE INTO graph_active
    FROM logical_workflow_jobs AS job
    WHERE job.run_id = target_run_id
      AND job.invocation_id = target_invocation_id
      AND job.id = target_logical_job_id
    FOR SHARE OF job;
    IF graph_active IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'workflow phase mutation requires its exact logical job'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_logical_job_exact';
    END IF;

    IF target_instance_id IS NOT NULL THEN
        SELECT TRUE INTO graph_active
        FROM logical_workflow_instances AS instance
        WHERE instance.id = target_instance_id
          AND instance.run_id = target_run_id
          AND instance.invocation_id = target_invocation_id
          AND instance.logical_job_id = target_logical_job_id
        FOR SHARE OF instance;
        IF graph_active IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'workflow phase mutation requires its exact instance'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_phase_instance_exact';
        END IF;
    END IF;

    IF target_instance_id IS NULL THEN
        PERFORM 1
        FROM logical_workflow_activation_work_quarantines AS quarantine
        WHERE quarantine.logical_job_id = target_logical_job_id
        FOR SHARE OF quarantine;
    ELSE
        PERFORM 1
        FROM logical_workflow_materialization_work_quarantines AS quarantine
        WHERE quarantine.instance_id = target_instance_id
        FOR SHARE OF quarantine;
    END IF;
    IF FOUND THEN
        RAISE EXCEPTION 'workflow phase mutation is quarantined'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_phase_quarantine_dominates';
    END IF;
END;
$$;

CREATE FUNCTION automata_require_classified_credentials_before_graph_seal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.admission_graph_sealed_at_ms IS NULL
       AND NEW.admission_graph_sealed_at_ms IS NOT NULL
       AND EXISTS (
           SELECT 1 FROM logical_workflow_jobs
           WHERE run_id = NEW.run_id
             AND environment_requirement_kind = 'unclassified'
       ) THEN
        RAISE EXCEPTION 'logical graph contains unclassified credential requirements'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_runs_credential_requirements_classified';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_classified_logical_job_credentials() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.state <> 'pending'
       AND NEW.environment_requirement_kind = 'unclassified' THEN
        RAISE EXCEPTION 'logical job credential requirements are unclassified'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_jobs_credential_requirements_classified';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_current_approval_before_secret_grant() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    environment repository_environments%ROWTYPE;
    database_now_ms BIGINT;
BEGIN
    IF NEW.environment_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT * INTO STRICT environment
    FROM repository_environments
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND id = NEW.environment_id
    FOR SHARE;
    IF environment.protection_mode = 'required_approvals'
       AND (
           NEW.environment_approval_request_id IS NULL
           OR NOT automata_protected_environment_approval_is_current(
               NEW.tenant_id, NEW.environment_approval_request_id,
               floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
           )
       ) THEN
        RAISE EXCEPTION 'protected environment approval no longer has current reviewer authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_environment_current';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_current_job_environment_gate_before_lease() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now_ms BIGINT;
BEGIN
    IF OLD.lifecycle <> 'queued' OR NEW.lifecycle <> 'leased' THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_concrete_jobs
        WHERE job_id = NEW.job_id
    ) THEN
        RETURN NEW;
    END IF;

    -- Parent-before-child SHARE locks conflict with every INSERT/UPDATE/DELETE
    -- of mutable authority while remaining compatible with ordinary readers.
    -- The following proof is a distinct statement, so READ COMMITTED observes
    -- every mutation that finished before these locks were obtained; the locks
    -- then hold the proved authority stable through lease commit.
    LOCK TABLE
        repository_environments,
        protected_environment_approval_requests,
        protected_environment_approval_decisions,
        repository_environment_reviewers,
        tenant_human_memberships,
        rbac_role_bindings,
        rbac_role_permissions,
        secrets,
        secret_policies,
        secret_repository_access,
        workflow_variables,
        workflow_variable_versions,
        logical_workflow_reusable_invocation_expansions,
        logical_workflow_reusable_secret_bindings
    IN SHARE MODE;

    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF NOT automata_job_environment_gate_ready_authority_is_current(
        NEW.id,
        database_now_ms
    ) THEN
        RAISE EXCEPTION 'job environment and credential authority is no longer current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_environment_gate_ready_current';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_current_manifest_runtime_policy_pair() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    pair_exists BOOLEAN;
    durable_tenant TEXT;
    durable_repository UUID;
BEGIN
    durable_tenant := NEW.tenant_id;
    durable_repository := NEW.repository_id;
    SELECT EXISTS (
        SELECT 1
        FROM workflow_runtime_policy_current AS current_policy
        JOIN github_provider_manifest_current AS current_manifest
          ON current_manifest.tenant_id = current_policy.tenant_id
         AND current_manifest.repository_id = current_policy.repository_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = current_manifest.tenant_id
         AND manifest.repository_id = current_manifest.repository_id
         AND manifest.provider_connection_id = current_manifest.provider_connection_id
         AND manifest.manifest_revision = current_manifest.manifest_revision
         AND manifest.manifest_digest = current_manifest.manifest_digest
        WHERE current_policy.tenant_id = durable_tenant
          AND current_policy.repository_id = durable_repository
          AND manifest.runtime_policy_revision = current_policy.policy_revision
          AND manifest.runtime_policy_digest = current_policy.policy_digest
    ) INTO pair_exists;
    IF pair_exists IS NOT TRUE THEN
        RAISE EXCEPTION 'current provider manifest and runtime policy are not an exact pair'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_current_runtime_policy_pair';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_environment_reviewer() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    request protected_environment_approval_requests%ROWTYPE;
    database_now_ms BIGINT;
BEGIN
    SELECT * INTO STRICT request
    FROM protected_environment_approval_requests
    WHERE tenant_id = NEW.tenant_id AND id = NEW.request_id
    FOR SHARE;
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF NOT automata_environment_reviewer_assignment_is_current(
        request.tenant_id, request.repository_id, request.environment_id,
        request.environment_revision, NEW.principal_id, database_now_ms
    ) THEN
        RAISE EXCEPTION 'principal is not a current environment reviewer'
            USING ERRCODE = 'insufficient_privilege',
                  CONSTRAINT = 'protected_environment_approval_decisions_reviewer';
    END IF;
    IF request.prevent_self_review
       AND NEW.decision = 'approve'
       AND request.requested_by_principal_id IS NULL THEN
        RAISE EXCEPTION 'self-review-separated request has no exact requester identity'
            USING ERRCODE = 'insufficient_privilege',
                  CONSTRAINT = 'protected_environment_approval_requester_required';
    END IF;
    IF request.prevent_self_review
       AND request.requested_by_principal_id IS NOT NULL
       AND NEW.principal_id = request.requested_by_principal_id THEN
        RAISE EXCEPTION 'requester cannot review this protected environment request'
            USING ERRCODE = 'insufficient_privilege',
                  CONSTRAINT = 'protected_environment_approval_decisions_self_review';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_exact_reusable_child_credentials_at_seal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.child_graph_sealed_at_ms IS NULL
       AND NEW.child_graph_sealed_at_ms IS NOT NULL
       AND NEW.condition_matched
       AND EXISTS (
           SELECT 1
           FROM logical_workflow_reusable_expanded_jobs AS planned
           LEFT JOIN logical_workflow_jobs AS active
             ON active.run_id = planned.run_id
            AND active.invocation_id = planned.invocation_id
            AND active.id = planned.logical_job_id
           WHERE planned.run_id = NEW.run_id
             AND planned.invocation_id = NEW.child_invocation_id
             AND (
                 planned.environment_requirement_kind = 'unclassified'
                 OR active.environment_requirement_kind IS DISTINCT FROM
                    planned.environment_requirement_kind
                 OR active.environment_template_digest IS DISTINCT FROM
                    planned.environment_template_digest
                 OR active.secret_reference_names IS DISTINCT FROM
                    planned.secret_reference_names
                 OR active.variable_reference_names IS DISTINCT FROM
                    planned.variable_reference_names
                 OR active.credential_requirements_schema IS DISTINCT FROM
                    planned.credential_requirements_schema
             )
       ) THEN
        RAISE EXCEPTION 'reusable child credential requirements do not match immutable expansion evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_call_credential_requirements_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_final_activation_work_quarantine() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    receipt logical_workflow_activation_work_selections%ROWTYPE;
    expected_outcome TEXT;
BEGIN
    SELECT * INTO receipt
    FROM logical_workflow_activation_work_selections
    WHERE selection_id = NEW.selection_id
    FOR UPDATE;
    expected_outcome := CASE
        WHEN NEW.failure_kind = 'generation_exhausted' THEN 'quarantined'
        ELSE 'claimed'
    END;
    IF receipt.selection_id IS NULL
        OR receipt.outcome IS DISTINCT FROM expected_outcome
        OR (receipt.owner_id, receipt.requested_at_ms, receipt.duration_ms,
            receipt.claimed_at_ms, receipt.expires_at_ms, receipt.tenant_id,
            receipt.run_id, receipt.invocation_id, receipt.logical_job_id,
            receipt.generation, receipt.authority_kind, receipt.authority_digest)
           IS DISTINCT FROM
           (NEW.selection_owner_id, NEW.selection_requested_at_ms,
            NEW.selection_duration_ms, NEW.selection_claimed_at_ms,
            NEW.selection_expires_at_ms, NEW.tenant_id, NEW.run_id,
            NEW.invocation_id, NEW.logical_job_id, NEW.selection_generation,
            NEW.authority_kind, NEW.authority_digest)
    THEN
        RAISE EXCEPTION 'activation quarantine lacks its exact final selection parent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_quarantine_parent_final_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_final_activation_work_selection() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    receipt logical_workflow_activation_work_selections%ROWTYPE;
    authority RECORD;
    exact_evidence BOOLEAN := FALSE;
    database_now BIGINT;
BEGIN
    SELECT * INTO receipt
    FROM logical_workflow_activation_work_selections
    WHERE selection_id = NEW.selection_id
    FOR UPDATE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF receipt.selection_id IS NULL OR receipt.outcome = 'selecting'
        OR receipt.expires_at_ms IS NULL
    THEN
        RAISE EXCEPTION 'activation selection may not commit without a live handoff budget'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_must_finalize_live';
    END IF;
    IF receipt.outcome = 'quarantined' THEN
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_activation_work_quarantines AS quarantine
            WHERE quarantine.selection_id = receipt.selection_id
              AND quarantine.logical_job_id = receipt.logical_job_id
              AND quarantine.tenant_id = receipt.tenant_id
              AND quarantine.run_id = receipt.run_id
              AND quarantine.invocation_id = receipt.invocation_id
              AND quarantine.selection_owner_id = receipt.owner_id
              AND quarantine.selection_requested_at_ms = receipt.requested_at_ms
              AND quarantine.selection_duration_ms = receipt.duration_ms
              AND quarantine.selection_generation = receipt.generation
              AND quarantine.selection_claimed_at_ms = receipt.claimed_at_ms
              AND quarantine.selection_expires_at_ms = receipt.expires_at_ms
              AND quarantine.authority_kind = receipt.authority_kind
              AND quarantine.authority_digest = receipt.authority_digest
        ) INTO exact_evidence;
    ELSIF receipt.expires_at_ms - database_now < 1000 THEN
        RAISE EXCEPTION 'activation selection may not commit without a live handoff budget'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_must_finalize_live';
    ELSIF receipt.outcome IN ('idle', 'contended') THEN
        RETURN NULL;
    ELSIF receipt.authority_kind = 'preparation' THEN
        SELECT claim.state, claim.origin_selection_id, claim.owner_id,
               claim.generation, claim.descriptor_digest AS authority_digest,
               claim.claimed_at_ms, claim.expires_at_ms,
               claim.runtime_policy_revision, claim.runtime_policy_digest
          INTO authority
        FROM logical_workflow_activation_preparation_claims AS claim
        WHERE claim.logical_job_id = receipt.logical_job_id
        FOR UPDATE;
        exact_evidence := authority IS NOT NULL
            AND authority.state = 'preparing'
            AND authority.origin_selection_id = receipt.selection_id
            AND authority.owner_id = receipt.owner_id
            AND authority.authority_digest = receipt.authority_digest
            AND authority.expires_at_ms - database_now >= 1000
            AND (
                (authority.generation = receipt.generation
                 AND authority.claimed_at_ms = receipt.claimed_at_ms
                 AND authority.expires_at_ms = receipt.expires_at_ms)
                OR EXISTS (
                    SELECT 1
                    FROM logical_workflow_activation_renewal_receipts AS renewal
                    WHERE renewal.selection_id = receipt.selection_id
                      AND renewal.logical_job_id = receipt.logical_job_id
                      AND renewal.authority_kind = 'preparation'
                      AND renewal.successor_generation = authority.generation
                      AND renewal.successor_claimed_at_ms = authority.claimed_at_ms
                      AND renewal.successor_expires_at_ms = authority.expires_at_ms
                      AND renewal.owner_id = authority.owner_id
                      AND renewal.authority_digest = authority.authority_digest
                      AND renewal.runtime_policy_revision = authority.runtime_policy_revision
                      AND renewal.runtime_policy_digest = authority.runtime_policy_digest
                )
            );
    ELSE
        SELECT job.state,
               job.activation_origin_selection_id AS origin_selection_id,
               job.activation_owner_id AS owner_id,
               job.activation_fence AS generation,
               job.activation_input_digest AS authority_digest,
               job.activation_claimed_at_ms AS claimed_at_ms,
               job.activation_expires_at_ms AS expires_at_ms,
               job.runtime_policy_revision, job.runtime_policy_digest
          INTO authority
        FROM logical_workflow_jobs AS job
        WHERE job.id = receipt.logical_job_id
        FOR UPDATE;
        exact_evidence := authority IS NOT NULL
            AND authority.state = 'activating'
            AND authority.origin_selection_id = receipt.selection_id
            AND authority.owner_id = receipt.owner_id
            AND authority.authority_digest = receipt.authority_digest
            AND authority.expires_at_ms - database_now >= 1000
            AND (
                (authority.generation = receipt.generation
                 AND authority.claimed_at_ms = receipt.claimed_at_ms
                 AND authority.expires_at_ms = receipt.expires_at_ms)
                OR EXISTS (
                    SELECT 1
                    FROM logical_workflow_activation_renewal_receipts AS renewal
                    WHERE renewal.selection_id = receipt.selection_id
                      AND renewal.logical_job_id = receipt.logical_job_id
                      AND renewal.authority_kind = 'activation'
                      AND renewal.successor_generation = authority.generation
                      AND renewal.successor_claimed_at_ms = authority.claimed_at_ms
                      AND renewal.successor_expires_at_ms = authority.expires_at_ms
                      AND renewal.owner_id = authority.owner_id
                      AND renewal.authority_digest = authority.authority_digest
                      AND renewal.runtime_policy_revision = authority.runtime_policy_revision
                      AND renewal.runtime_policy_digest = authority.runtime_policy_digest
                )
            );
    END IF;
    IF exact_evidence IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'final activation selection lacks exact current durable evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_final_evidence_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_final_materialization_work_quarantine() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    receipt logical_workflow_materialization_work_selections%ROWTYPE;
    expected_outcome TEXT;
BEGIN
    SELECT * INTO receipt
    FROM logical_workflow_materialization_work_selections
    WHERE selection_id = NEW.selection_id
    FOR UPDATE;
    expected_outcome := CASE
        WHEN NEW.failure_kind = 'generation_exhausted' THEN 'quarantined'
        ELSE 'claimed'
    END;
    IF receipt.selection_id IS NULL
        OR receipt.outcome IS DISTINCT FROM expected_outcome
        OR (receipt.owner_id, receipt.requested_at_ms, receipt.duration_ms,
            receipt.claimed_at_ms, receipt.expires_at_ms, receipt.tenant_id,
            receipt.run_id, receipt.invocation_id, receipt.logical_job_id,
            receipt.instance_id, receipt.generation, receipt.authority_digest)
           IS DISTINCT FROM
           (NEW.selection_owner_id, NEW.selection_requested_at_ms,
            NEW.selection_duration_ms, NEW.selection_claimed_at_ms,
            NEW.selection_expires_at_ms, NEW.tenant_id, NEW.run_id,
            NEW.invocation_id, NEW.logical_job_id, NEW.instance_id,
            NEW.selection_generation, NEW.authority_digest)
    THEN
        RAISE EXCEPTION 'materialization quarantine lacks its exact final selection parent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_quarantine_parent_final_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_final_materialization_work_selection() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    receipt logical_workflow_materialization_work_selections%ROWTYPE;
    authority RECORD;
    exact_evidence BOOLEAN := FALSE;
    database_now BIGINT;
BEGIN
    SELECT * INTO receipt
    FROM logical_workflow_materialization_work_selections
    WHERE selection_id = NEW.selection_id
    FOR UPDATE;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF receipt.selection_id IS NULL OR receipt.outcome = 'selecting'
        OR receipt.expires_at_ms IS NULL
    THEN
        RAISE EXCEPTION 'materialization selection may not commit without a live handoff budget'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_must_finalize_live';
    END IF;
    IF receipt.outcome = 'quarantined' THEN
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_materialization_work_quarantines AS quarantine
            WHERE quarantine.selection_id = receipt.selection_id
              AND quarantine.instance_id = receipt.instance_id
              AND quarantine.tenant_id = receipt.tenant_id
              AND quarantine.run_id = receipt.run_id
              AND quarantine.invocation_id = receipt.invocation_id
              AND quarantine.logical_job_id = receipt.logical_job_id
              AND quarantine.selection_owner_id = receipt.owner_id
              AND quarantine.selection_requested_at_ms = receipt.requested_at_ms
              AND quarantine.selection_duration_ms = receipt.duration_ms
              AND quarantine.selection_generation = receipt.generation
              AND quarantine.selection_claimed_at_ms = receipt.claimed_at_ms
              AND quarantine.selection_expires_at_ms = receipt.expires_at_ms
              AND quarantine.authority_digest = receipt.authority_digest
        ) INTO exact_evidence;
    ELSIF receipt.expires_at_ms - database_now < 1000 THEN
        RAISE EXCEPTION 'materialization selection may not commit without a live handoff budget'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_must_finalize_live';
    ELSIF receipt.outcome IN ('idle', 'contended') THEN
        RETURN NULL;
    ELSE
        SELECT claim.state, claim.origin_selection_id, claim.owner_id,
               claim.generation, claim.descriptor_digest AS authority_digest,
               claim.claimed_at_ms, claim.expires_at_ms,
               claim.runtime_policy_revision, claim.runtime_policy_digest,
               claim.expected_job_id, claim.expected_attempt_id
          INTO authority
        FROM logical_workflow_materialization_claims AS claim
        WHERE claim.instance_id = receipt.instance_id
        FOR UPDATE;
        exact_evidence := authority IS NOT NULL
            AND authority.state = 'materializing'
            AND authority.origin_selection_id = receipt.selection_id
            AND authority.owner_id = receipt.owner_id
            AND authority.authority_digest = receipt.authority_digest
            AND authority.expires_at_ms - database_now >= 1000
            AND (
                (authority.generation = receipt.generation
                 AND authority.claimed_at_ms = receipt.claimed_at_ms
                 AND authority.expires_at_ms = receipt.expires_at_ms)
                OR EXISTS (
                    SELECT 1
                    FROM logical_workflow_materialization_renewal_receipts AS renewal
                    WHERE renewal.selection_id = receipt.selection_id
                      AND renewal.instance_id = receipt.instance_id
                      AND renewal.successor_generation = authority.generation
                      AND renewal.successor_claimed_at_ms = authority.claimed_at_ms
                      AND renewal.successor_expires_at_ms = authority.expires_at_ms
                      AND renewal.owner_id = authority.owner_id
                      AND renewal.authority_digest = authority.authority_digest
                      AND renewal.runtime_policy_revision = authority.runtime_policy_revision
                      AND renewal.runtime_policy_digest = authority.runtime_policy_digest
                      AND renewal.expected_job_id = authority.expected_job_id
                      AND renewal.expected_attempt_id = authority.expected_attempt_id
                )
            );
    END IF;
    IF exact_evidence IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'final materialization selection lacks exact current durable evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_final_evidence_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_require_github_manifest_runtime_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    policy workflow_runtime_policy_revisions%ROWTYPE;
BEGIN
    SELECT revision.* INTO policy
    FROM workflow_runtime_policy_current AS current_policy
    JOIN workflow_runtime_policy_revisions AS revision
      ON revision.tenant_id = current_policy.tenant_id
     AND revision.repository_id = current_policy.repository_id
     AND revision.policy_revision = current_policy.policy_revision
     AND revision.policy_digest = current_policy.policy_digest
    WHERE current_policy.tenant_id = NEW.tenant_id
      AND current_policy.repository_id = NEW.repository_id
      AND current_policy.policy_revision = NEW.runtime_policy_revision
      AND current_policy.policy_digest = NEW.runtime_policy_digest
    FOR SHARE OF current_policy, revision;
    IF policy.state IS DISTINCT FROM 'sealed'
        OR pg_catalog.sha256(policy.canonical_policy) IS DISTINCT FROM
            NEW.runner_policy_digest
        OR pg_catalog.octet_length(policy.canonical_policy) IS DISTINCT FROM
            NEW.runner_policy_size_bytes
    THEN
        RAISE EXCEPTION 'GitHub manifest runtime policy is not exact sealed evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_provider_manifest_runtime_policy_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_require_github_runtime_authority_attempt_renewal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM github_runtime_authority_issuances AS authority
        WHERE authority.attempt_id = NEW.id
          AND authority.fencing_token = NEW.fencing_token
          AND authority.state = 'ready'
    ) AND NOT automata_github_runtime_authority_lease_final_exact(
        NEW.id,
        NEW.fencing_token
    ) THEN
        RAISE EXCEPTION 'ready GitHub runtime authority lease edit lacks evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_attempt_renewal_final_exact';
    END IF;
    RETURN NULL;
END;
$$;
