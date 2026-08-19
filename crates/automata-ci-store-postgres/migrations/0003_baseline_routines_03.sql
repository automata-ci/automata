-- Canonical greenfield schema stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_enforce_logical_workflow_terminal_counter() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF pg_trigger_depth() <= 1 THEN
        RAISE EXCEPTION 'logical workflow terminal counter is trigger-authoritative'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' AND NEW.last_ordinal <> 1 THEN
        RAISE EXCEPTION 'logical workflow terminal counter must begin at one'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' AND (
        NEW.logical_job_id IS DISTINCT FROM OLD.logical_job_id
        OR NEW.last_ordinal <> OLD.last_ordinal + 1
    ) THEN
        RAISE EXCEPTION 'logical workflow terminal counter must advance exactly once'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_workflow_run_requirements_schema_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.runner_requirements_schema IS DISTINCT FROM
       OLD.runner_requirements_schema
    THEN
        RAISE EXCEPTION 'workflow-run runner-requirements schema is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_runs_runner_requirements_schema_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_workflow_runtime_policy_current() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    revision workflow_runtime_policy_revisions%ROWTYPE;
BEGIN
    SELECT * INTO revision
    FROM workflow_runtime_policy_revisions
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND policy_revision = NEW.policy_revision
    FOR SHARE;
    IF revision.state IS DISTINCT FROM 'sealed'
        OR revision.policy_digest IS DISTINCT FROM NEW.policy_digest
        OR NEW.activated_at_ms IS DISTINCT FROM revision.sealed_at_ms
    THEN
        RAISE EXCEPTION 'current workflow runtime policy lacks exact sealed evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_current_exact';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.policy_revision <> 1 THEN
            RAISE EXCEPTION 'initial workflow runtime policy revision must be one'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_runtime_policy_current_initial';
        END IF;
    ELSIF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR OLD.policy_revision = 9223372036854775807
        OR NEW.policy_revision <> OLD.policy_revision + 1
        OR NEW.policy_digest IS NOT DISTINCT FROM OLD.policy_digest
        OR NEW.activated_at_ms < OLD.activated_at_ms
    THEN
        RAISE EXCEPTION 'workflow runtime policy current transition is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_current_transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_workflow_runtime_policy_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    actual_digest BYTEA;
    actual_canonical BYTEA;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'staging' OR NEW.sealed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'workflow runtime policy must be inserted as staging'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_runtime_policy_insert_staging';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.policy_revision IS DISTINCT FROM OLD.policy_revision
        OR NEW.policy_digest IS DISTINCT FROM OLD.policy_digest
        OR NEW.canonical_policy IS DISTINCT FROM OLD.canonical_policy
        OR NEW.permission_policy_canonical IS DISTINCT FROM OLD.permission_policy_canonical
        OR NEW.resource_policy_canonical IS DISTINCT FROM OLD.resource_policy_canonical
        OR NEW.policy_schema IS DISTINCT FROM OLD.policy_schema
        OR NEW.workspace_root IS DISTINCT FROM OLD.workspace_root
        OR NEW.workspace_derivation_version IS DISTINCT FROM OLD.workspace_derivation_version
        OR NEW.mapping_count IS DISTINCT FROM OLD.mapping_count
        OR OLD.state <> 'staging'
        OR NEW.state <> 'sealed'
        OR NEW.registered_at_ms IS DISTINCT FROM OLD.registered_at_ms
        OR NEW.sealed_at_ms IS DISTINCT FROM NEW.registered_at_ms
    THEN
        RAISE EXCEPTION 'workflow runtime policy revision is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_revision_immutable';
    END IF;

    actual_digest := automata_workflow_runtime_policy_digest(
        NEW.tenant_id, NEW.repository_id, NEW.policy_revision
    );
    IF actual_digest IS NULL OR actual_digest IS DISTINCT FROM NEW.policy_digest THEN
        RAISE EXCEPTION 'workflow runtime policy content digest is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_digest_exact';
    END IF;
    actual_canonical := automata_workflow_runtime_policy_canonical(
        NEW.tenant_id, NEW.repository_id, NEW.policy_revision
    );
    IF actual_canonical IS NULL
        OR actual_canonical IS DISTINCT FROM NEW.canonical_policy
        OR pg_catalog.octet_length(actual_canonical) NOT BETWEEN 1 AND 65536
    THEN
        RAISE EXCEPTION 'workflow runtime policy canonical object is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_canonical_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_workflow_work_selection_horizon() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now BIGINT;
    expected_floor BIGINT;
    cursor_exact BOOLEAN := TRUE;
BEGIN
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    expected_floor := greatest(
        OLD.replay_floor_ms,
        least(
            OLD.replay_floor_ms + (NEW.updated_at_ms - OLD.updated_at_ms),
            greatest(0, NEW.updated_at_ms - 60000)
        )
    );
    IF NEW.cursor_target_id IS NOT NULL THEN
        IF NEW.queue_name = 'activation' THEN
            SELECT EXISTS (
                SELECT 1
                FROM logical_workflow_jobs AS job
                WHERE job.id = NEW.cursor_target_id
                  AND job.run_id = NEW.cursor_run_id
                  AND job.invocation_id = NEW.cursor_invocation_id
                  AND job.source_order = NEW.cursor_source_order
                  AND job.created_at_ms = NEW.cursor_ready_at_ms
            ) INTO cursor_exact;
        ELSE
            SELECT EXISTS (
                SELECT 1
                FROM logical_workflow_instances AS instance
                JOIN logical_workflow_jobs AS job
                  ON job.run_id = instance.run_id
                 AND job.invocation_id = instance.invocation_id
                 AND job.id = instance.logical_job_id
                JOIN logical_workflow_activation_publications AS publication
                  ON publication.run_id = instance.run_id
                 AND publication.invocation_id = instance.invocation_id
                 AND publication.logical_job_id = instance.logical_job_id
                WHERE instance.id = NEW.cursor_target_id
                  AND instance.run_id = NEW.cursor_run_id
                  AND instance.invocation_id = NEW.cursor_invocation_id
                  AND job.source_order = NEW.cursor_source_order
                  AND instance.matrix_index = NEW.cursor_matrix_index
                  AND publication.published_at_ms = NEW.cursor_ready_at_ms
            ) INTO cursor_exact;
        END IF;
    END IF;
    IF NEW.queue_name IS DISTINCT FROM OLD.queue_name
        OR OLD.updated_at_ms > database_now
        OR NEW.updated_at_ms < OLD.updated_at_ms
        OR NEW.updated_at_ms > database_now
        OR database_now - NEW.updated_at_ms > 60000
        OR NEW.replay_floor_ms IS DISTINCT FROM expected_floor
        OR cursor_exact IS DISTINCT FROM TRUE
    THEN
        RAISE EXCEPTION 'workflow work-selection replay horizon transition is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_work_selection_horizon_advance';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_environment_reviewer_assignment_is_current(target_tenant_id text, target_repository_id uuid, target_environment_id uuid, target_environment_revision bigint, target_principal_id uuid, target_now_ms bigint) RETURNS boolean
    LANGUAGE sql STABLE
    AS $_$
SELECT EXISTS (
    SELECT 1
    FROM repository_environment_reviewers AS reviewer
    JOIN tenant_human_memberships AS reviewer_membership
      ON reviewer_membership.tenant_id = reviewer.tenant_id
     AND reviewer_membership.principal_id = reviewer.principal_id
    JOIN tenant_human_memberships AS assigning_membership
      ON assigning_membership.tenant_id = reviewer.tenant_id
     AND assigning_membership.principal_id = reviewer.granted_by_principal_id
    WHERE reviewer.tenant_id = $1
      AND reviewer.repository_id = $2
      AND reviewer.environment_id = $3
      AND reviewer.environment_revision = $4
      AND reviewer.principal_id = $5
      AND reviewer_membership.status = 'active'
      AND reviewer_membership.authorization_revision =
          reviewer.principal_authorization_revision
      AND assigning_membership.status = 'active'
      AND assigning_membership.authorization_revision =
          reviewer.grantor_authorization_revision
      AND automata_principal_has_repository_permission(
          $1, reviewer.principal_id, $2, 'environments:approve', $6
      )
      AND automata_principal_has_repository_permission(
          $1, reviewer.granted_by_principal_id, $2, 'environments:manage', $6
      )
);
$_$;

CREATE FUNCTION automata_expire_managed_secret_delivery_for_attempt() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.lifecycle IN ('leased', 'preparing', 'running')
       AND NEW.lifecycle NOT IN ('leased', 'preparing', 'running') THEN
        UPDATE managed_secret_delivery_operations
        SET state = 'expired'
        WHERE attempt_id = NEW.id AND state = 'pending';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_expire_managed_secret_delivery_for_session() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.disconnected_at_ms IS NULL AND NEW.disconnected_at_ms IS NOT NULL THEN
        UPDATE managed_secret_delivery_operations
        SET state = 'expired'
        WHERE runner_session_id = NEW.id AND state = 'pending';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_fence_logical_workflow_run_completion() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.status = 'completed'
        AND NEW.status IS DISTINCT FROM OLD.status
        AND EXISTS (
            SELECT 1
            FROM logical_workflow_runs AS marker
            WHERE marker.run_id = NEW.id
              AND marker.state NOT IN ('completed', 'failed')
        )
    THEN
        RAISE EXCEPTION 'logical workflow run cannot complete before orchestration finalization'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_freeze_logical_workflow_run_graph() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    target_run UUID;
BEGIN
    target_run := CASE WHEN TG_OP = 'DELETE' THEN OLD.run_id ELSE NEW.run_id END;

    PERFORM 1
    FROM logical_workflow_runs AS marker
    WHERE marker.run_id = target_run
    FOR SHARE;

    IF FOUND AND EXISTS (
        SELECT 1
        FROM logical_workflow_run_result_claims AS claim
        WHERE claim.run_id = target_run
    ) THEN
        RAISE EXCEPTION 'logical workflow run graph is frozen by result aggregation'
            USING ERRCODE = '23514';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE FUNCTION automata_github_authenticated_event_exact() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    inbox_media_type TEXT;
BEGIN
    SELECT raw_event_media_type
      INTO inbox_media_type
    FROM provider_delivery_inbox
    WHERE id = NEW.provider_delivery_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;

    IF inbox_media_type IS DISTINCT FROM
        'application/vnd.automata.github-authenticated-event+json'
    THEN
        RAISE EXCEPTION 'GitHub authenticated-event envelope does not match its raw object'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_authenticated_event_exact';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_check_credential_rejection_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    expected github_check_projection_outbox%ROWTYPE;
BEGIN
    IF OLD.state = 'blocked' AND OLD.blocked_reason = 'credential_rejected' THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'GitHub Check credential-rejection evidence is immutable'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_projection_credential_rejection_immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.state = 'blocked' AND NEW.blocked_reason = 'credential_rejected' THEN
        expected := OLD;
        expected.state := 'blocked';
        expected.claim_owner_id := NULL;
        expected.claim_action := NULL;
        expected.claimed_desired_revision := NULL;
        expected.claimed_desired_state := NULL;
        expected.claimed_desired_conclusion := NULL;
        expected.claimed_at_ms := NULL;
        expected.claim_expires_at_ms := NULL;
        expected.next_attempt_at_ms := NULL;
        expected.last_failure_kind := NULL;
        expected.blocked_reason := 'credential_rejected';
        expected.state_updated_at_ms := NEW.state_updated_at_ms;

        IF OLD.state <> 'claimed'
            OR NEW.state_updated_at_ms < OLD.claimed_at_ms
            OR NEW.state_updated_at_ms >= OLD.claim_expires_at_ms
            OR NEW IS DISTINCT FROM expected
        THEN
            RAISE EXCEPTION 'GitHub Check credential rejection did not consume its exact live claim'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_projection_credential_rejection_exact';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_check_outbox_update_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    subject github_check_subjects%ROWTYPE;
BEGIN
    IF NEW.subject_id IS DISTINCT FROM OLD.subject_id
        OR NEW.claim_fence < OLD.claim_fence
        OR NEW.projected_revision < OLD.projected_revision
        OR NEW.state_updated_at_ms < OLD.state_updated_at_ms
    THEN
        RAISE EXCEPTION 'GitHub Check outbox monotonic identity regressed'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_outbox_monotonic';
    END IF;
    IF NEW.claim_fence <> OLD.claim_fence
        AND (
            NEW.state <> 'claimed'
            OR NEW.claim_fence <> OLD.claim_fence + 1
        )
    THEN
        RAISE EXCEPTION 'GitHub Check claims require the next fencing token'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_claim_fence_exact';
    END IF;
    IF OLD.external_suite_id IS NOT NULL
        AND NEW.external_suite_id IS DISTINCT FROM OLD.external_suite_id
        OR OLD.external_run_id IS NOT NULL
        AND NEW.external_run_id IS DISTINCT FROM OLD.external_run_id
        OR OLD.external_bound_at_ms IS NOT NULL
        AND NEW.external_bound_at_ms IS DISTINCT FROM OLD.external_bound_at_ms
    THEN
        RAISE EXCEPTION 'GitHub Check external identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_external_immutable';
    END IF;
    IF OLD.external_suite_id IS NULL AND NEW.external_suite_id IS NOT NULL
        AND NOT (
            OLD.state = 'claimed'
            AND OLD.claim_action = 'ensure_suite'
            AND NEW.state = 'pending'
        )
    THEN
        RAISE EXCEPTION 'GitHub Check suite binding did not close an ensure claim'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_suite_binding_exact';
    END IF;
    IF OLD.external_run_id IS NULL AND NEW.external_run_id IS NOT NULL
        AND NOT (
            NEW.external_suite_id IS NOT DISTINCT FROM OLD.external_suite_id
            AND NEW.provider_state = 'queued'
            AND NEW.provider_conclusion IS NULL
            AND (
                OLD.state = 'create_indeterminate'
                OR OLD.state = 'claimed'
                   AND OLD.claim_action = 'reconcile_run_create'
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub Check Run binding lacks create/reconciliation evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_run_binding_exact';
    END IF;
    IF NEW.state = 'create_indeterminate'
        AND OLD.state <> 'create_indeterminate'
        AND NOT (
            OLD.state = 'claimed'
            AND OLD.claim_action = 'prepare_run_create'
            AND OLD.create_started_at_ms IS NULL
            AND NEW.create_owner_id IS NOT DISTINCT FROM OLD.claim_owner_id
            AND NEW.create_fence IS NOT DISTINCT FROM OLD.claim_fence
            AND NEW.create_started_at_ms >= OLD.claimed_at_ms
            AND NEW.create_started_at_ms < OLD.claim_expires_at_ms
            AND NEW.create_issue_expires_at_ms IS NOT DISTINCT FROM OLD.claim_expires_at_ms
            AND NEW.next_reconcile_at_ms IS NOT DISTINCT FROM NEW.reconcile_not_before_ms
            OR OLD.state = 'claimed'
            AND OLD.claim_action = 'reconcile_run_create'
            AND OLD.attempt_count < 64
            AND NEW.create_owner_id IS NOT DISTINCT FROM OLD.create_owner_id
            AND NEW.create_fence IS NOT DISTINCT FROM OLD.create_fence
            AND NEW.create_started_at_ms IS NOT DISTINCT FROM OLD.create_started_at_ms
            AND NEW.create_issue_expires_at_ms IS NOT DISTINCT FROM OLD.create_issue_expires_at_ms
            AND NEW.reconcile_not_before_ms IS NOT DISTINCT FROM OLD.reconcile_not_before_ms
            AND NEW.next_reconcile_at_ms IS DISTINCT FROM OLD.next_reconcile_at_ms
            AND NEW.next_reconcile_at_ms > NEW.state_updated_at_ms
            AND NEW.next_reconcile_at_ms - NEW.state_updated_at_ms <= 86400000
            AND NEW.blocked_reason IS NULL
        )
    THEN
        RAISE EXCEPTION 'GitHub Check create cutoff must consume its exact claim'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_create_fence_exact';
    END IF;
    IF OLD.create_started_at_ms IS NOT NULL
        AND (
            NEW.create_owner_id IS DISTINCT FROM OLD.create_owner_id
            OR NEW.create_fence IS DISTINCT FROM OLD.create_fence
            OR NEW.create_started_at_ms IS DISTINCT FROM OLD.create_started_at_ms
            OR NEW.create_issue_expires_at_ms IS DISTINCT FROM OLD.create_issue_expires_at_ms
            OR NEW.reconcile_not_before_ms IS DISTINCT FROM OLD.reconcile_not_before_ms
        )
        AND NOT (
            NEW.create_owner_id IS NULL
            AND NEW.create_fence IS NULL
            AND NEW.create_started_at_ms IS NULL
            AND NEW.create_issue_expires_at_ms IS NULL
            AND NEW.reconcile_not_before_ms IS NULL
            AND NEW.next_reconcile_at_ms IS NULL
            AND (
                OLD.external_run_id IS NULL
                AND NEW.external_run_id IS NOT NULL
                OR OLD.state = 'create_indeterminate'
                AND OLD.next_reconcile_at_ms IS NOT DISTINCT FROM OLD.reconcile_not_before_ms
                AND NEW.external_run_id IS NULL
                AND (
                    OLD.attempt_count < 64
                    AND NEW.state = 'retry'
                    AND NEW.last_failure_kind = 'create_not_issued'
                    OR OLD.attempt_count >= 64
                    AND NEW.state = 'blocked'
                    AND NEW.blocked_reason = 'attempt_limit'
                )
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub Check create evidence changed outside exact bind or unissued release'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_create_evidence_immutable';
    END IF;
    IF OLD.create_started_at_ms IS NOT NULL
        AND NEW.create_started_at_ms IS NOT NULL
        AND NEW.next_reconcile_at_ms IS DISTINCT FROM OLD.next_reconcile_at_ms
        AND NOT (
            OLD.state = 'claimed'
            AND OLD.claim_action = 'reconcile_run_create'
            AND NEW.next_reconcile_at_ms > NEW.state_updated_at_ms
            AND NEW.next_reconcile_at_ms - NEW.state_updated_at_ms <= 86400000
            AND (
                OLD.attempt_count < 64
                AND NEW.state = 'create_indeterminate'
                AND NEW.blocked_reason IS NULL
                OR OLD.attempt_count >= 64
                AND NEW.state = 'blocked'
                AND NEW.blocked_reason = 'attempt_limit'
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub Check next reconciliation time lacks exact missing evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_next_reconcile_exact';
    END IF;
    IF NEW.state = 'claimed' AND NEW.claim_fence <> OLD.claim_fence THEN
        SELECT * INTO subject
        FROM github_check_subjects
        WHERE id = NEW.subject_id;
        IF NOT FOUND
            OR NEW.attempted_revision <> subject.desired_revision
            OR NEW.claimed_desired_revision <> subject.desired_revision
            OR NEW.claimed_desired_state <> subject.desired_state
            OR NEW.claimed_desired_conclusion IS DISTINCT FROM subject.desired_conclusion
            OR NEW.attempt_count <> (CASE
                WHEN OLD.attempted_revision IS DISTINCT FROM subject.desired_revision
                    THEN 1
                ELSE OLD.attempt_count + 1
            END)
        THEN
            RAISE EXCEPTION 'GitHub Check claim snapshot is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_projection_claim_snapshot_exact';
        END IF;
    END IF;
    IF (
        NEW.provider_state IS DISTINCT FROM OLD.provider_state
        OR NEW.provider_conclusion IS DISTINCT FROM OLD.provider_conclusion
        OR NEW.provider_observed_at_ms IS DISTINCT FROM OLD.provider_observed_at_ms
        OR NEW.projected_revision IS DISTINCT FROM OLD.projected_revision
    ) AND NOT (
        OLD.external_run_id IS NULL
        AND NEW.external_run_id IS NOT NULL
        AND NEW.provider_state = 'queued'
        AND NEW.provider_conclusion IS NULL
        OR OLD.state = 'claimed'
        AND OLD.claim_action = 'publish'
        AND NEW.projected_revision = OLD.claimed_desired_revision
        AND NEW.provider_state = OLD.claimed_desired_state
        AND NEW.provider_conclusion IS NOT DISTINCT FROM OLD.claimed_desired_conclusion
    )
    THEN
        RAISE EXCEPTION 'GitHub Check provider observation lacks exact claim evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_projection_provider_observation_exact';
    END IF;
    IF NEW.state = 'delivered' THEN
        SELECT * INTO subject
        FROM github_check_subjects
        WHERE id = NEW.subject_id;
        IF NOT FOUND
            OR NEW.projected_revision <> subject.desired_revision
            OR NEW.provider_state <> subject.desired_state
            OR NEW.provider_conclusion IS DISTINCT FROM subject.desired_conclusion
        THEN
            RAISE EXCEPTION 'GitHub Check delivered projection is not current and exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_projection_delivery_exact';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_check_subject_canonical_name() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    delivery provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
    canonical_name TEXT;
BEGIN
    IF NEW.subject_kind = 'job' THEN
        SELECT parent.github_repository_name INTO canonical_name
        FROM github_check_subjects AS parent
        WHERE parent.id = NEW.parent_subject_id
          AND parent.tenant_id = NEW.tenant_id
          AND parent.subject_kind = 'workflow'
        FOR SHARE OF parent;
        IF canonical_name IS NULL THEN
            RAISE EXCEPTION 'GitHub job Check has no exact workflow authority'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_parent_exact';
        END IF;
        NEW.github_repository_name := canonical_name;
        RETURN NEW;
    END IF;

    SELECT * INTO repository
    FROM repositories
    WHERE id = NEW.repository_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;

    IF NEW.origin_kind = 'provider_delivery' THEN
        SELECT * INTO delivery
        FROM provider_delivery_inbox
        WHERE id = NEW.provider_delivery_id
          AND tenant_id = NEW.tenant_id
        FOR SHARE;
        IF delivery.id IS NULL
            OR repository.id IS NULL
            OR delivery.provider <> 'github'
            OR delivery.provider_repository_id <> NEW.github_repository_id
            OR delivery.repository_identity <>
                repository.owner || '/' || repository.name
        THEN
            RAISE EXCEPTION 'GitHub Check canonical repository identity is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_canonical_name_exact';
        END IF;
        NEW.github_repository_name := delivery.repository_identity;
    ELSIF NEW.origin_kind = 'workflow_rerun' THEN
        SELECT source.github_repository_name INTO canonical_name
        FROM workflow_rerun_attempts AS attempt
        JOIN github_check_subjects AS source
          ON source.workflow_run_id = attempt.source_run_id
         AND source.subject_kind = 'workflow'
        WHERE attempt.run_id = NEW.workflow_rerun_run_id
          AND attempt.source_run_id IS NOT NULL
          AND source.desired_state = 'completed'
          AND source.desired_revision = 3
          AND 1 = (
              SELECT count(*)
              FROM github_check_subjects AS exact_source
              WHERE exact_source.workflow_run_id = attempt.source_run_id
                AND exact_source.subject_kind = 'workflow'
          )
        FOR SHARE OF attempt, source;
        IF canonical_name IS NULL
            OR repository.id IS NULL
            OR repository.scm_provider <> 'github'
            OR repository.provider_repository_id <>
                NEW.github_repository_id::TEXT
            OR canonical_name <> repository.owner || '/' || repository.name
        THEN
            RAISE EXCEPTION 'GitHub rerun Check canonical identity is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_canonical_name_exact';
        END IF;
        NEW.github_repository_name := canonical_name;
    ELSE
        RAISE EXCEPTION 'GitHub Check subject origin is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_origin_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_check_subject_canonical_name_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.github_repository_name IS DISTINCT FROM OLD.github_repository_name THEN
        RAISE EXCEPTION 'GitHub Check canonical repository identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_canonical_name_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_check_subject_delivery_evidence_exact() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    authority RECORD;
    workflow_authorized BOOLEAN := FALSE;
BEGIN
    IF NEW.subject_kind = 'job' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM github_check_subjects AS parent
            WHERE parent.id = NEW.parent_subject_id
              AND parent.tenant_id = NEW.tenant_id
              AND parent.repository_id = NEW.repository_id
              AND parent.subject_kind = 'workflow'
              AND parent.origin_kind = NEW.origin_kind
              AND parent.provider_delivery_id IS NOT DISTINCT FROM
                  NEW.provider_delivery_id
              AND parent.workflow_rerun_run_id IS NOT DISTINCT FROM
                  NEW.workflow_rerun_run_id
              AND parent.provider_connection_id = NEW.provider_connection_id
              AND parent.provider_installation_id = NEW.provider_installation_id
              AND parent.github_repository_id = NEW.github_repository_id
              AND parent.github_repository_name = NEW.github_repository_name
              AND parent.github_app_id = NEW.github_app_id
              AND parent.head_sha = NEW.head_sha
            FOR SHARE OF parent
        ) THEN
            RAISE EXCEPTION 'GitHub job Check does not match its workflow authority'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_parent_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.origin_kind = 'workflow_rerun' THEN
        RETURN NEW;
    END IF;
    SELECT evidence_source.repository_id,
           evidence_source.provider_connection_id,
           evidence_source.provider_installation_id,
           evidence_source.github_repository_id,
           evidence_source.github_repository_name,
           evidence_source.github_check_subject_id,
           evidence_source.github_check_head_sha,
           inbox_source.accepted_at_ms,
           inbox_source.state AS inbox_state,
           manifest_source.workflow_selection_kind,
           manifest_source.check_subject_key,
           manifest_source.github_app_id,
           manifest_source.check_name,
           manifest_source.manifest_digest
      INTO authority
    FROM github_provider_delivery_evidence AS evidence_source
    JOIN provider_delivery_inbox AS inbox_source
      ON inbox_source.id = evidence_source.provider_delivery_id
     AND inbox_source.tenant_id = evidence_source.tenant_id
    JOIN github_provider_manifest_revisions AS manifest_source
      ON manifest_source.tenant_id = evidence_source.tenant_id
     AND manifest_source.repository_id = evidence_source.repository_id
     AND manifest_source.provider_connection_id =
         evidence_source.provider_connection_id
     AND manifest_source.manifest_revision =
         evidence_source.provider_manifest_revision
     AND manifest_source.manifest_digest =
         evidence_source.provider_manifest_digest
    WHERE evidence_source.provider_delivery_id = NEW.provider_delivery_id
      AND evidence_source.tenant_id = NEW.tenant_id
    FOR SHARE OF evidence_source, inbox_source, manifest_source;

    IF FOUND
       AND authority.workflow_selection_kind = 'all_direct'
       AND NEW.id <> authority.github_check_subject_id
    THEN
        SELECT TRUE INTO workflow_authorized
        FROM provider_delivery_workflow_inventories AS inventory
        JOIN provider_delivery_workflow_inventory_entries AS entry
          ON entry.inbox_id = inventory.inbox_id
         AND entry.tenant_id = inventory.tenant_id
        WHERE inventory.inbox_id = NEW.provider_delivery_id
          AND inventory.tenant_id = NEW.tenant_id
          AND inventory.manifest_digest = authority.manifest_digest
          AND entry.workflow_path = NEW.subject_key
          AND (
              entry.source_state = 'ready'
              OR EXISTS (
                  SELECT 1
                  FROM provider_delivery_workflow_progress AS progress
                  WHERE progress.inbox_id = inventory.inbox_id
                    AND progress.tenant_id = inventory.tenant_id
                    AND progress.inventory_digest = inventory.inventory_digest
                    AND progress.workflow_path = entry.workflow_path
                    AND progress.outcome_kind = 'failed'
              )
          )
        FOR SHARE OF inventory, entry;
    END IF;

    IF authority.repository_id IS NULL
        OR NEW.origin_kind <> 'provider_delivery'
        OR NEW.repository_id <> authority.repository_id
        OR NEW.provider_connection_id <> authority.provider_connection_id
        OR NEW.provider_installation_id <> authority.provider_installation_id
        OR NEW.github_repository_id <> authority.github_repository_id
        OR NEW.github_repository_name <> authority.github_repository_name
        OR NEW.github_app_id <> authority.github_app_id
        OR NEW.head_sha <> authority.github_check_head_sha
        OR NEW.check_name <> authority.check_name
        OR NEW.created_at_ms <> authority.accepted_at_ms
        OR NOT (
            NEW.id = authority.github_check_subject_id
            AND NEW.subject_key = authority.check_subject_key
            OR authority.workflow_selection_kind = 'all_direct'
            AND authority.inbox_state = 'claimed'
            AND NEW.id <> authority.github_check_subject_id
            AND workflow_authorized
        )
    THEN
        RAISE EXCEPTION 'GitHub Check subject does not match its signed delivery evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_delivery_evidence_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_check_subject_insert_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    delivery provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
    rerun RECORD;
    job_check RECORD;
BEGIN
    IF NEW.desired_state <> 'queued'
        OR NEW.desired_revision <> 1
        OR NEW.desired_updated_at_ms <> NEW.created_at_ms
        OR NEW.workflow_run_id IS NOT NULL
        OR NEW.linked_at_ms IS NOT NULL
    THEN
        RAISE EXCEPTION 'GitHub Check subjects must begin queued and unlinked'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_initial_state';
    END IF;

    SELECT * INTO repository
    FROM repositories
    WHERE id = NEW.repository_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;
    IF repository.id IS NULL
        OR repository.scm_provider <> 'github'
        OR repository.provider_repository_id <> NEW.github_repository_id::TEXT
        OR repository.owner || '/' || repository.name <>
            NEW.github_repository_name
    THEN
        RAISE EXCEPTION 'GitHub Check subject repository is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_authority_exact';
    END IF;

    IF NEW.subject_kind = 'job' THEN
        SELECT parent.id AS parent_id,
               parent.workflow_run_id AS parent_run_id,
               parent.tenant_id AS parent_tenant_id,
               parent.repository_id AS parent_repository_id,
               parent.provider_connection_id AS parent_connection_id,
               parent.provider_installation_id AS parent_installation_id,
               parent.github_repository_id AS parent_github_repository_id,
               parent.github_repository_name AS parent_repository_name,
               parent.github_app_id AS parent_app_id,
               parent.head_sha AS parent_head_sha,
               job.run_id AS job_run_id,
               attempt.job_id AS attempt_job_id,
               attempt.queued_at_ms
          INTO job_check
        FROM github_check_subjects AS parent
        JOIN jobs AS job ON job.id = NEW.job_id
        JOIN job_attempts AS attempt
          ON attempt.id = NEW.job_attempt_id
         AND attempt.job_id = job.id
        WHERE parent.id = NEW.parent_subject_id
          AND parent.subject_kind = 'workflow'
          AND parent.workflow_run_id = job.run_id
        FOR SHARE OF parent, job, attempt;
        IF NOT FOUND
            OR job_check.parent_run_id IS NULL
            OR job_check.parent_tenant_id <> NEW.tenant_id
            OR job_check.parent_repository_id <> NEW.repository_id
            OR job_check.parent_connection_id <> NEW.provider_connection_id
            OR job_check.parent_installation_id <> NEW.provider_installation_id
            OR job_check.parent_github_repository_id <> NEW.github_repository_id
            OR job_check.parent_repository_name <> NEW.github_repository_name
            OR job_check.parent_app_id <> NEW.github_app_id
            OR job_check.parent_head_sha <> NEW.head_sha
            OR NEW.created_at_ms <> job_check.queued_at_ms
            OR NEW.subject_key <>
                'job/' || NEW.job_id::TEXT || '/attempt/' || NEW.job_attempt_id::TEXT
        THEN
            RAISE EXCEPTION 'GitHub job Check authority is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_job_authority_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.origin_kind = 'provider_delivery' THEN
        SELECT * INTO delivery
        FROM provider_delivery_inbox
        WHERE id = NEW.provider_delivery_id
          AND tenant_id = NEW.tenant_id
        FOR SHARE;
        IF delivery.id IS NULL
            OR delivery.provider <> 'github'
            OR delivery.connection_id <> NEW.provider_connection_id
            OR delivery.installation_id <> NEW.provider_installation_id
            OR delivery.provider_repository_id <> NEW.github_repository_id
        THEN
            RAISE EXCEPTION 'GitHub Check delivery authority is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_authority_exact';
        END IF;
    ELSIF NEW.origin_kind = 'workflow_rerun' THEN
        SELECT attempt.run_id,
               attempt.source_run_id,
               attempt.created_at_ms,
               request.tenant_id,
               request.repository_id,
               request.committed_at_ms,
               run.head_sha AS run_head_sha,
               run.status AS run_status,
               source.id AS source_subject_id,
               source.tenant_id AS source_tenant_id,
               source.repository_id AS source_repository_id,
               source.subject_key AS source_subject_key,
               source.provider_connection_id AS source_connection_id,
               source.provider_installation_id AS source_installation_id,
               source.github_repository_id AS source_repository_provider_id,
               source.github_repository_name AS source_repository_name,
               source.github_app_id AS source_app_id,
               source.head_sha AS source_head_sha,
               source.check_name AS source_check_name,
               source.desired_state AS source_desired_state,
               source.desired_revision AS source_desired_revision
          INTO rerun
        FROM workflow_rerun_attempts AS attempt
        JOIN workflow_rerun_requests AS request
          ON request.rerun_run_id = attempt.run_id
         AND request.source_run_id = attempt.source_run_id
        JOIN workflow_runs AS run ON run.id = attempt.run_id
        JOIN github_check_subjects AS source
          ON source.workflow_run_id = attempt.source_run_id
         AND source.subject_kind = 'workflow'
        WHERE attempt.run_id = NEW.workflow_rerun_run_id
          AND attempt.source_run_id IS NOT NULL
          AND 1 = (
              SELECT count(*)
              FROM github_check_subjects AS exact_source
              WHERE exact_source.workflow_run_id = attempt.source_run_id
                AND exact_source.subject_kind = 'workflow'
          )
        FOR SHARE OF attempt, request, run, source;
        IF NOT FOUND
            OR rerun.tenant_id <> NEW.tenant_id
            OR rerun.repository_id <> NEW.repository_id
            OR rerun.committed_at_ms <> rerun.created_at_ms
            OR rerun.run_status <> 'queued'
            OR rerun.run_head_sha <> NEW.head_sha
            OR rerun.source_tenant_id <> NEW.tenant_id
            OR rerun.source_repository_id <> NEW.repository_id
            OR rerun.source_desired_state <> 'completed'
            OR rerun.source_desired_revision <> 3
            OR NEW.created_at_ms <> rerun.created_at_ms
            OR NEW.subject_key <> rerun.source_subject_key
            OR NEW.provider_connection_id <> rerun.source_connection_id
            OR NEW.provider_installation_id <> rerun.source_installation_id
            OR NEW.github_repository_id <>
                rerun.source_repository_provider_id
            OR NEW.github_repository_name <> rerun.source_repository_name
            OR NEW.github_app_id <> rerun.source_app_id
            OR NEW.head_sha <> rerun.source_head_sha
            OR NEW.check_name <> rerun.source_check_name
        THEN
            RAISE EXCEPTION 'GitHub rerun Check authority is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_rerun_authority_exact';
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub Check subject origin is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_origin_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_check_subject_origin_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.origin_kind IS DISTINCT FROM OLD.origin_kind
        OR NEW.provider_delivery_id IS DISTINCT FROM OLD.provider_delivery_id
        OR NEW.workflow_rerun_run_id IS DISTINCT FROM OLD.workflow_rerun_run_id
    THEN
        RAISE EXCEPTION 'GitHub Check subject origin is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_origin_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_check_subject_update_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    run_row workflow_runs%ROWTYPE;
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.provider_delivery_id IS DISTINCT FROM OLD.provider_delivery_id
        OR NEW.subject_key IS DISTINCT FROM OLD.subject_key
        OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
        OR NEW.provider_installation_id IS DISTINCT FROM OLD.provider_installation_id
        OR NEW.github_repository_id IS DISTINCT FROM OLD.github_repository_id
        OR NEW.github_app_id IS DISTINCT FROM OLD.github_app_id
        OR NEW.head_sha IS DISTINCT FROM OLD.head_sha
        OR NEW.check_name IS DISTINCT FROM OLD.check_name
        OR NEW.external_id IS DISTINCT FROM OLD.external_id
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR NEW.subject_kind IS DISTINCT FROM OLD.subject_kind
        OR NEW.parent_subject_id IS DISTINCT FROM OLD.parent_subject_id
        OR NEW.job_id IS DISTINCT FROM OLD.job_id
        OR NEW.job_attempt_id IS DISTINCT FROM OLD.job_attempt_id
    THEN
        RAISE EXCEPTION 'GitHub Check subject identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_identity_immutable';
    END IF;

    IF OLD.workflow_run_id IS NOT NULL
        AND (
            NEW.workflow_run_id IS DISTINCT FROM OLD.workflow_run_id
            OR NEW.linked_at_ms IS DISTINCT FROM OLD.linked_at_ms
        )
    THEN
        RAISE EXCEPTION 'GitHub Check run linkage is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_run_immutable';
    END IF;
    IF OLD.workflow_run_id IS NULL AND NEW.workflow_run_id IS NOT NULL THEN
        SELECT * INTO run_row
        FROM workflow_runs
        WHERE repository_id = NEW.repository_id
          AND id = NEW.workflow_run_id
        FOR SHARE;
        IF NOT FOUND OR run_row.head_sha IS DISTINCT FROM NEW.head_sha THEN
            RAISE EXCEPTION 'GitHub Check run does not match repository and SHA'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_run_exact';
        END IF;
    ELSIF NEW.workflow_run_id IS DISTINCT FROM OLD.workflow_run_id
        OR NEW.linked_at_ms IS DISTINCT FROM OLD.linked_at_ms
    THEN
        RAISE EXCEPTION 'GitHub Check run linkage transition is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_run_transition';
    END IF;

    IF NEW.desired_state IS DISTINCT FROM OLD.desired_state
        OR NEW.desired_conclusion IS DISTINCT FROM OLD.desired_conclusion
        OR NEW.terminal_cause IS DISTINCT FROM OLD.terminal_cause
    THEN
        IF OLD.desired_state = 'completed'
            OR NEW.desired_revision <> OLD.desired_revision + 1
            OR NEW.desired_updated_at_ms < OLD.desired_updated_at_ms
            OR NOT (
                OLD.desired_state = 'queued'
                AND NEW.desired_state IN ('in_progress', 'completed')
                OR OLD.desired_state = 'in_progress'
                AND NEW.desired_state = 'completed'
            )
        THEN
            RAISE EXCEPTION 'GitHub Check desired transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_check_subjects_desired_transition';
        END IF;
    ELSIF NEW.desired_revision IS DISTINCT FROM OLD.desired_revision
        OR NEW.desired_updated_at_ms IS DISTINCT FROM OLD.desired_updated_at_ms
    THEN
        RAISE EXCEPTION 'GitHub Check desired revision changed without state'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_desired_revision_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_delivery_requires_atomic_queued_check() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    evidence github_provider_delivery_evidence%ROWTYPE;
    pending github_repository_dispatch_pending_evidence%ROWTYPE;
    manifest github_provider_manifest_revisions%ROWTYPE;
    subject github_check_subjects%ROWTYPE;
    outbox github_check_projection_outbox%ROWTYPE;
BEGIN
    IF NEW.provider <> 'github' THEN
        RETURN NULL;
    END IF;

    SELECT * INTO evidence
    FROM github_provider_delivery_evidence
    WHERE provider_delivery_id = NEW.id
      AND tenant_id = NEW.tenant_id;

    IF evidence.provider_delivery_id IS NULL THEN
        SELECT * INTO pending
        FROM github_repository_dispatch_pending_evidence
        WHERE provider_delivery_id = NEW.id
          AND tenant_id = NEW.tenant_id;
        IF pending.provider_delivery_id IS NOT NULL
            AND pending.authenticated_event_envelope_version = 1
            AND pending.authenticated_event_name = 'repository_dispatch'
            AND NEW.raw_event_media_type =
                'application/vnd.automata.github-authenticated-event+json'
        THEN
            RETURN NULL;
        END IF;
    END IF;

    IF evidence.provider_delivery_id IS NOT NULL THEN
        SELECT * INTO manifest
        FROM github_provider_manifest_revisions
        WHERE tenant_id = evidence.tenant_id
          AND repository_id = evidence.repository_id
          AND provider_connection_id = evidence.provider_connection_id
          AND manifest_revision = evidence.provider_manifest_revision
          AND manifest_digest = evidence.provider_manifest_digest;

        SELECT * INTO subject
        FROM github_check_subjects
        WHERE id = evidence.github_check_subject_id
          AND provider_delivery_id = NEW.id
          AND tenant_id = NEW.tenant_id
          AND subject_key = manifest.check_subject_key;

        IF subject.id IS NOT NULL THEN
            SELECT * INTO outbox
            FROM github_check_projection_outbox
            WHERE subject_id = subject.id;
        END IF;
    END IF;

    IF evidence.provider_delivery_id IS NULL
        OR manifest.provider_connection_id IS NULL
        OR subject.id IS NULL
        OR subject.head_sha <> evidence.github_check_head_sha
        OR subject.workflow_run_id IS NOT NULL
        OR subject.linked_at_ms IS NOT NULL
        OR subject.desired_state <> 'queued'
        OR subject.desired_conclusion IS NOT NULL
        OR subject.terminal_cause IS NOT NULL
        OR subject.desired_revision <> 1
        OR subject.created_at_ms <> NEW.accepted_at_ms
        OR subject.desired_updated_at_ms <> NEW.accepted_at_ms
        OR outbox.subject_id IS NULL
        OR outbox.state <> 'pending'
        OR outbox.attempted_revision IS NOT NULL
        OR outbox.attempt_count <> 0
        OR outbox.claim_fence <> 0
        OR outbox.projected_revision <> 0
        OR outbox.state_updated_at_ms <> NEW.accepted_at_ms
    THEN
        RAISE EXCEPTION 'GitHub delivery requires pinned pending dispatch or one queued Check'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_delivery_atomic_evidence_required';
    END IF;

    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_github_mapping_authorization_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP <> 'DELETE' THEN
        UPDATE tenant_human_memberships
        SET authorization_revision = authorization_revision + 1
        WHERE tenant_id = NEW.tenant_id;
    END IF;
    IF TG_OP <> 'INSERT'
       AND (TG_OP = 'DELETE' OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id) THEN
        UPDATE tenant_human_memberships
        SET authorization_revision = authorization_revision + 1
        WHERE tenant_id = OLD.tenant_id;
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_github_oidc_claim_set_valid(claims jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE STRICT
    AS $_$
DECLARE
    claim RECORD;
    claim_count INTEGER := 0;
    claim_bytes INTEGER := 0;
    claim_value TEXT;
BEGIN
    IF jsonb_typeof(claims) <> 'object' THEN
        RETURN FALSE;
    END IF;
    FOR claim IN SELECT key, value FROM jsonb_each(claims) LOOP
        claim_count := claim_count + 1;
        IF claim_count > 32
            OR jsonb_typeof(claim.value) <> 'string'
            OR claim.key !~ '^[a-z][a-z0-9_]{0,63}$'
            OR claim.key IN ('aud', 'exp', 'iat', 'iss', 'jti', 'nbf', 'sub')
        THEN
            RETURN FALSE;
        END IF;
        claim_value := claim.value #>> '{}';
        claim_bytes := claim_bytes
            + octet_length(claim.key) + octet_length(claim_value);
        IF octet_length(claim_value) > 2048
            OR claim_value ~ '[[:cntrl:]]'
            OR claim_bytes > 16384
        THEN
            RETURN FALSE;
        END IF;
    END LOOP;
    RETURN TRUE;
END;
$_$;

SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TABLE github_oidc_authorities (
    attempt_id uuid NOT NULL,
    fencing_token bigint NOT NULL,
    authority_id uuid NOT NULL,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    github_repository_id bigint NOT NULL,
    github_repository_name text NOT NULL COLLATE pg_catalog."C",
    github_owner_id bigint NOT NULL,
    workflow_id uuid NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    logical_job_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    job_id uuid NOT NULL,
    attempt_number integer NOT NULL,
    lease_id uuid NOT NULL,
    lease_issued_at_ms bigint NOT NULL,
    lease_expires_at_ms bigint NOT NULL,
    runner_id uuid NOT NULL,
    runner_session_id uuid NOT NULL,
    runner_session_epoch bigint NOT NULL,
    runner_generation bigint NOT NULL,
    runner_slot integer NOT NULL,
    admission_epoch smallint NOT NULL,
    workflow_plan_schema smallint NOT NULL,
    plan_digest bytea NOT NULL,
    event_digest bytea NOT NULL,
    runtime_context_digest bytea NOT NULL,
    job_ir_schema smallint NOT NULL,
    job_ir_size_bytes bigint NOT NULL,
    job_ir_digest bytea NOT NULL,
    job_ir_object_key text NOT NULL COLLATE pg_catalog."C",
    permission_mode text NOT NULL COLLATE pg_catalog."C",
    permission_evidence_sha256 bytea NOT NULL,
    subject_policy_mode text NOT NULL COLLATE pg_catalog."C",
    subject_policy_revision bigint NOT NULL,
    subject_policy_sha256 bytea NOT NULL,
    github_run_subject_evidence_sha256 bytea CONSTRAINT github_oidc_authorities_source_evidence_sha256_not_null NOT NULL,
    claim_evidence_sha256 bytea NOT NULL,
    subject text NOT NULL COLLATE pg_catalog."C",
    default_audience text NOT NULL COLLATE pg_catalog."C",
    additional_claims jsonb NOT NULL,
    configuration_sha256 bytea NOT NULL,
    request_bearer_key_id text NOT NULL COLLATE pg_catalog."C",
    request_bearer_key_sha256 bytea NOT NULL,
    request_bearer_verification_skew_seconds smallint CONSTRAINT github_oidc_authorities_request_bearer_verification_sk_not_null NOT NULL,
    id_token_verifier_skew_seconds smallint NOT NULL,
    request_bearer_iat_seconds bigint NOT NULL,
    request_bearer_exp_seconds bigint NOT NULL,
    request_bearer_sha256 bytea NOT NULL,
    reserved_at_ms bigint NOT NULL,
    CONSTRAINT github_oidc_authorities_bearer_interval CHECK (((lease_issued_at_ms >= 0) AND (lease_expires_at_ms > lease_issued_at_ms) AND (reserved_at_ms >= lease_issued_at_ms) AND (reserved_at_ms < lease_expires_at_ms) AND (request_bearer_iat_seconds = (lease_issued_at_ms / 1000)) AND ((reserved_at_ms / 1000) < request_bearer_exp_seconds) AND (request_bearer_exp_seconds > request_bearer_iat_seconds) AND ((request_bearer_exp_seconds - request_bearer_iat_seconds) <= 86400) AND (request_bearer_iat_seconds <= '9223372036854775'::bigint) AND (request_bearer_exp_seconds <= '9223372036854775'::bigint) AND ((request_bearer_verification_skew_seconds >= 0) AND (request_bearer_verification_skew_seconds <= 300)) AND ((id_token_verifier_skew_seconds >= 0) AND (id_token_verifier_skew_seconds <= 300)) AND (request_bearer_exp_seconds <= ('9223372036854775807'::bigint - request_bearer_verification_skew_seconds)))),
    CONSTRAINT github_oidc_authorities_current_evidence_sha256 CHECK (((octet_length(plan_digest) = 32) AND (octet_length(event_digest) = 32) AND (octet_length(runtime_context_digest) = 32) AND (octet_length(permission_evidence_sha256) = 32) AND (permission_evidence_sha256 = job_ir_digest) AND (octet_length(subject_policy_sha256) = 32) AND (octet_length(github_run_subject_evidence_sha256) = 32) AND (octet_length(claim_evidence_sha256) = 32) AND (octet_length(configuration_sha256) = 32) AND (octet_length(request_bearer_sha256) = 32) AND (octet_length(request_bearer_key_sha256) = 32))),
    CONSTRAINT github_oidc_authorities_current_schemas CHECK (((admission_epoch = 1) AND (workflow_plan_schema = 1) AND (job_ir_schema = 1) AND ((job_ir_size_bytes >= 1) AND (job_ir_size_bytes <= 16777216)) AND (octet_length(job_ir_digest) = 32) AND ((octet_length(job_ir_object_key) >= 1) AND (octet_length(job_ir_object_key) <= 1024)) AND (job_ir_object_key !~ '[[:cntrl:]]'::text) AND ("left"(job_ir_object_key, 1) <> '/'::text) AND (job_ir_object_key !~ '(^|/)\.\.(/|$)'::text))),
    CONSTRAINT github_oidc_authorities_execution_numbers CHECK (((fencing_token > 0) AND (attempt_number > 0) AND (runner_session_epoch > 0) AND (runner_generation > 0) AND ((runner_slot >= 1) AND (runner_slot <= 65535)))),
    CONSTRAINT github_oidc_authorities_github_repository CHECK (((github_repository_id > 0) AND ((octet_length(github_repository_name) >= 3) AND (octet_length(github_repository_name) <= 140)) AND (github_repository_name ~ '^[^/]+/[^/]+$'::text) AND ((octet_length(split_part(github_repository_name, '/'::text, 1)) >= 1) AND (octet_length(split_part(github_repository_name, '/'::text, 1)) <= 39)) AND (split_part(github_repository_name, '/'::text, 1) ~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$'::text) AND (split_part(github_repository_name, '/'::text, 1) !~~ '%--%'::text) AND ((octet_length(split_part(github_repository_name, '/'::text, 2)) >= 1) AND (octet_length(split_part(github_repository_name, '/'::text, 2)) <= 100)) AND (split_part(github_repository_name, '/'::text, 2) ~ '^[A-Za-z0-9._-]+$'::text) AND (split_part(github_repository_name, '/'::text, 2) <> ALL (ARRAY['.'::text, '..'::text])) AND (lower(split_part(github_repository_name, '/'::text, 2)) !~~ '%.git'::text))),
    CONSTRAINT github_oidc_authorities_key_id CHECK ((((octet_length(request_bearer_key_id) >= 1) AND (octet_length(request_bearer_key_id) <= 128)) AND (request_bearer_key_id ~ '^[A-Za-z0-9._-]+$'::text))),
    CONSTRAINT github_oidc_authorities_non_nil_ids CHECK (((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (authority_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (repository_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (workflow_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (run_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (instance_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (job_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (lease_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (runner_id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (runner_session_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT github_oidc_authorities_permission_exact CHECK ((permission_mode = 'id-token:write'::text)),
    CONSTRAINT github_oidc_authorities_principals CHECK ((((octet_length(subject) >= 1) AND (octet_length(subject) <= 2048)) AND (btrim(subject) <> ''::text) AND (subject !~ '[[:cntrl:]]'::text) AND ((octet_length(default_audience) >= 1) AND (octet_length(default_audience) <= 2048)) AND (btrim(default_audience) <> ''::text) AND (default_audience !~ '[[:cntrl:]]'::text) AND automata_github_oidc_claim_set_valid(additional_claims))),
    CONSTRAINT github_oidc_authorities_stable_owner_policy CHECK (((subject_policy_mode = 'stable_owner_evidence'::text) AND (subject_policy_revision > 0) AND (github_owner_id > 0)))
);

CREATE FUNCTION automata_github_oidc_authority_is_current(authority github_oidc_authorities, observed_at_ms bigint, required_current_before_ms bigint) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT EXISTS (
        SELECT 1
        FROM job_attempts AS attempt
        JOIN jobs AS job
          ON job.id = attempt.job_id
         AND job.id = authority.job_id
         AND job.run_id = authority.run_id
        JOIN workflow_runs AS run
          ON run.id = job.run_id
         AND run.id = authority.run_id
         AND run.repository_id = authority.repository_id
         AND run.workflow_id = authority.workflow_id
        JOIN repositories AS repository
          ON repository.id = run.repository_id
         AND repository.id = authority.repository_id
         AND repository.tenant_id = authority.tenant_id
        JOIN workflow_definitions AS workflow
          ON workflow.id = run.workflow_id
         AND workflow.repository_id = run.repository_id
        JOIN workflow_snapshots AS snapshot
          ON snapshot.id = run.snapshot_id
         AND snapshot.workflow_id = run.workflow_id
        JOIN logical_workflow_runs AS marker
          ON marker.run_id = run.id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = run.id
         AND invocation.id = authority.invocation_id
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = run.id
         AND logical_job.invocation_id = invocation.id
         AND logical_job.id = authority.logical_job_id
        JOIN logical_workflow_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = logical_job.run_id
         AND preparation_claim.invocation_id = logical_job.invocation_id
         AND preparation_claim.logical_job_id = logical_job.id
        JOIN logical_workflow_activation_preparations AS preparation
          ON preparation.run_id = preparation_claim.run_id
         AND preparation.invocation_id = preparation_claim.invocation_id
         AND preparation.logical_job_id = preparation_claim.logical_job_id
         AND preparation.descriptor_digest = preparation_claim.descriptor_digest
        JOIN logical_workflow_activation_publications AS activation_publication
          ON activation_publication.run_id = logical_job.run_id
         AND activation_publication.invocation_id = logical_job.invocation_id
         AND activation_publication.logical_job_id = logical_job.id
         AND activation_publication.activation_input_digest =
             preparation.activation_input_digest
        JOIN logical_workflow_instances AS instance
          ON instance.run_id = run.id
         AND instance.invocation_id = invocation.id
         AND instance.logical_job_id = logical_job.id
         AND instance.id = authority.instance_id
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.instance_id = instance.id
         AND concrete.run_id = run.id
         AND concrete.invocation_id = invocation.id
         AND concrete.logical_job_id = logical_job.id
         AND concrete.job_id = job.id
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
        JOIN runners AS runner
          ON runner.id = attempt.runner_id
         AND runner.id = authority.runner_id
         AND runner.tenant_id = authority.tenant_id
         AND runner.generation = authority.runner_generation
         AND runner.session_epoch = authority.runner_session_epoch
        JOIN runner_sessions AS session
          ON session.id = attempt.runner_session_id
         AND session.id = authority.runner_session_id
         AND session.runner_id = authority.runner_id
         AND session.session_epoch = authority.runner_session_epoch
         AND session.runner_generation = authority.runner_generation
        JOIN github_workflow_run_manifest_origins AS origin
          ON origin.tenant_id = authority.tenant_id
         AND origin.repository_id = authority.repository_id
         AND origin.workflow_id = authority.workflow_id
         AND origin.run_id = authority.run_id
         AND origin.root_invocation_id = marker.root_invocation_id
         AND origin.subject_evidence_sha256 =
             authority.github_run_subject_evidence_sha256
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
         AND manifest.provider_connection_id = origin.provider_connection_id
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
        JOIN github_server_service_authorities AS contents_authority
          ON contents_authority.tenant_id = origin.tenant_id
         AND contents_authority.id = origin.repository_contents_authority_id
         AND contents_authority.repository_id = origin.repository_id
         AND contents_authority.provider_connection_id =
             origin.provider_connection_id
         AND contents_authority.provider_installation_id =
             origin.provider_installation_id
         AND contents_authority.github_repository_id =
             origin.github_repository_id
         AND contents_authority.github_repository_name =
             origin.github_repository_name
         AND contents_authority.service_scope =
             'repository_contents_read'
         AND contents_authority.identity_digest =
             origin.repository_contents_authority_identity_digest
         AND contents_authority.app_configuration_revision =
             origin.repository_contents_authority_app_configuration_revision
         AND contents_authority.policy_revision =
             origin.repository_contents_authority_policy_revision
        WHERE attempt.id = authority.attempt_id
          AND attempt.job_id = authority.job_id
          AND attempt.attempt_number = authority.attempt_number
          AND attempt.fencing_token = authority.fencing_token
          AND attempt.lease_id = authority.lease_id
          AND attempt.lease_issued_at_ms = authority.lease_issued_at_ms
          AND attempt.lease_expires_at_ms >= authority.lease_expires_at_ms
          AND required_current_before_ms > observed_at_ms
          AND attempt.lease_expires_at_ms >= required_current_before_ms
          AND attempt.runner_id = authority.runner_id
          AND attempt.runner_session_id = authority.runner_session_id
          AND attempt.runner_session_epoch = authority.runner_session_epoch
          AND attempt.runner_generation = authority.runner_generation
          AND attempt.runner_slot = authority.runner_slot
          AND attempt.lifecycle IN ('leased', 'preparing', 'running')
          AND attempt.changed_at_ms <= observed_at_ms
          AND job.admission_epoch = 1
          AND job.job_ir_schema = 1
          AND job.job_ir_schema = authority.job_ir_schema
          AND job.job_ir_size_bytes = authority.job_ir_size_bytes
          AND job.job_ir_digest = authority.job_ir_digest
          AND job.job_ir_object_key = authority.job_ir_object_key
          AND authority.permission_evidence_sha256 = authority.job_ir_digest
          AND job.requirements @>
              '{"features":["automata.core/oidc-tokens@v1"]}'::JSONB
          AND run.admission_epoch = 1
          AND run.plan_schema = 1
          AND (
              invocation.id <> marker.root_invocation_id
              OR run.plan_digest = authority.plan_digest
          )
          AND run.plan_digest = origin.plan_digest
          AND run.event_digest = authority.event_digest
          AND run.event_digest = origin.event_digest
          AND run.snapshot_id = origin.snapshot_id
          AND run.head_sha = origin.github_check_head_sha
          AND run.event_name = origin.event_name
          AND run.git_ref = origin.git_ref
          AND run.status IN ('queued', 'in_progress')
          AND (
              origin.origin_kind = 'provider_delivery'
              AND origin.admission_idempotency_kind = 'provider_delivery'
              OR origin.origin_kind IN ('scheduled_fire', 'workflow_rerun')
              AND origin.admission_idempotency_kind = 'operation'
          )
          AND workflow.path = origin.workflow_path
          AND snapshot.source_digest = origin.source_digest
          AND marker.orchestration_schema = 1
          AND marker.root_invocation_id = origin.root_invocation_id
          AND marker.admission_digest = origin.logical_admission_digest
          AND marker.admitted_at_ms = origin.admitted_at_ms
          AND marker.state IN ('pending', 'active')
          AND automata_logical_workflow_invocation_published(
              run.id, invocation.id
          )
          AND automata_reusable_workflow_oidc_permission_authorized(
              run.id, invocation.id
          )
          AND invocation.plan_schema = 1
          AND invocation.plan_digest = authority.plan_digest
          AND invocation.state IN ('pending', 'active')
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND instance.job_ir_version = 1
          AND instance.job_ir_digest = authority.job_ir_digest
          AND instance.job_ir_object_key = authority.job_ir_object_key
          AND instance.job_ir_size_bytes = authority.job_ir_size_bytes
          AND concrete.runtime_context_schema = 1
          AND concrete.runtime_context_digest = authority.runtime_context_digest
          AND concrete.requirements = job.requirements
          AND materialization.state = 'materialized'
          AND logical_job.activation_input_digest =
              preparation.activation_input_digest
          AND preparation_claim.state = 'prepared'
          AND activation_publication.condition_matched
          AND activation_publication.job_ir_version = 1
          AND activation_publication.runtime_context_schema = 1
          AND manifest.authority_profile = 'standard'
          AND logical_job.authority_profile = 'standard'
          AND preparation_claim.authority_profile = 'standard'
          AND preparation.authority_profile = 'standard'
          AND activation_publication.authority_profile = 'standard'
          AND materialization.authority_profile = 'standard'
          AND concrete.authority_profile = 'standard'
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id =
              origin.github_repository_id::TEXT
          AND repository.owner || '/' || repository.name =
              origin.github_repository_name
          AND authority.github_repository_id =
              origin.github_repository_id
          AND authority.github_repository_name =
              origin.github_repository_name
          AND authority.github_owner_id =
              origin.github_repository_owner_id
          AND authority.subject_policy_mode = 'stable_owner_evidence'
          AND authority.subject_policy_revision > 0
          AND authority.subject = CASE
              WHEN origin.event_name = 'pull_request'
              THEN 'repo:' || origin.github_repository_name ||
                   ':pull_request'
              ELSE 'repo:' || origin.github_repository_name ||
                   ':ref:' || origin.git_ref
          END
          AND authority.default_audience = 'https://github.com/' ||
              split_part(origin.github_repository_name, '/', 1)
          AND authority.additional_claims = jsonb_build_object(
              'event_name', origin.event_name,
              'ref', origin.git_ref,
              'repository', origin.github_repository_name,
              'repository_owner',
                  split_part(origin.github_repository_name, '/', 1),
              'run_attempt', run.run_attempt::TEXT,
              'run_number', run.run_number::TEXT,
              'runner_environment', 'self-hosted',
              'sha', encode(origin.github_check_head_sha, 'hex'),
              'workflow', run.workflow_name,
              'workflow_ref', origin.github_repository_name || '/' ||
                  origin.workflow_path || '@' || origin.git_ref,
              'workflow_sha', encode(origin.github_check_head_sha, 'hex')
          )
          AND manifest.webhook_verifier_fingerprint_sha256 =
              origin.authenticated_webhook_verifier_fingerprint_sha256
          AND manifest.webhook_verifier_revision =
              origin.authenticated_webhook_verifier_revision
          AND manifest.provider_installation_id =
              origin.provider_installation_id
          AND manifest.github_repository_id =
              origin.github_repository_id
          AND manifest.github_repository_name =
              origin.github_repository_name
          AND manifest.repository_visibility =
              origin.repository_visibility
          AND manifest.registered_at_ms <= observed_at_ms
          AND checks_authority.state = 'active'
          AND checks_authority.created_at_ms <= observed_at_ms
          AND checks_authority.state_updated_at_ms <= observed_at_ms
          AND contents_authority.state = 'active'
          AND contents_authority.created_at_ms <= observed_at_ms
          AND contents_authority.state_updated_at_ms <= observed_at_ms
          AND origin.admitted_at_ms <= observed_at_ms
          AND authority.request_bearer_iat_seconds * 1000 <= observed_at_ms
          AND authority.request_bearer_exp_seconds * 1000 > observed_at_ms
          AND runner.status = 'online'
          AND runner.desired_state IN ('active', 'draining')
          AND runner.capabilities @>
              '{"features":["automata.core/oidc-tokens@v1"]}'::JSONB
          AND session.job_ir_schema = 1
          AND session.capability_snapshot @>
              '{"features":["automata.core/oidc-tokens@v1"]}'::JSONB
          AND session.disconnected_at_ms IS NULL
    )
$$;
