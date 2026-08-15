-- Frozen greenfield baseline. Add a new migration instead of editing this stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_enforce_logical_activation_preparation_claim_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.logical_job_id IS DISTINCT FROM OLD.logical_job_id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.invocation_id IS DISTINCT FROM OLD.invocation_id
        OR NEW.descriptor_digest IS DISTINCT FROM OLD.descriptor_digest
        OR NEW.logical_key IS DISTINCT FROM OLD.logical_key
        OR NEW.source_order IS DISTINCT FROM OLD.source_order
        OR NEW.workflow_id IS DISTINCT FROM OLD.workflow_id
        OR NEW.workflow_name IS DISTINCT FROM OLD.workflow_name
        OR NEW.git_ref IS DISTINCT FROM OLD.git_ref
        OR NEW.actor IS DISTINCT FROM OLD.actor
        OR NEW.run_number IS DISTINCT FROM OLD.run_number
        OR NEW.run_attempt IS DISTINCT FROM OLD.run_attempt
        OR NEW.plan_digest IS DISTINCT FROM OLD.plan_digest
        OR NEW.plan_object_key IS DISTINCT FROM OLD.plan_object_key
        OR NEW.plan_size_bytes IS DISTINCT FROM OLD.plan_size_bytes
        OR NEW.plan_media_type IS DISTINCT FROM OLD.plan_media_type
        OR NEW.plan_schema IS DISTINCT FROM OLD.plan_schema
        OR NEW.event_digest IS DISTINCT FROM OLD.event_digest
        OR NEW.event_object_key IS DISTINCT FROM OLD.event_object_key
        OR NEW.event_size_bytes IS DISTINCT FROM OLD.event_size_bytes
        OR NEW.event_media_type IS DISTINCT FROM OLD.event_media_type
        OR NEW.base_context_kind IS DISTINCT FROM OLD.base_context_kind
        OR NEW.workspace IS DISTINCT FROM OLD.workspace
        OR NEW.prerequisite_count IS DISTINCT FROM OLD.prerequisite_count
        OR NEW.prerequisites_digest IS DISTINCT FROM OLD.prerequisites_digest
        OR NEW.aggregate_status IS DISTINCT FROM OLD.aggregate_status
        OR NEW.evidence_ready_at_ms IS DISTINCT FROM OLD.evidence_ready_at_ms
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'logical activation preparation evidence is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_jobs AS job
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = job.run_id AND invocation.id = job.invocation_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE job.run_id = OLD.run_id
          AND job.invocation_id = OLD.invocation_id
          AND job.id = OLD.logical_job_id
          AND job.execution_kind = 'steps'
          AND job.state = 'pending'
          AND automata_logical_workflow_invocation_published(
              marker.run_id, invocation.id
          )
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 1
          AND run.plan_schema = 1
    ) THEN
        RAISE EXCEPTION 'logical activation preparation target is no longer current'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state = 'prepared' THEN
        RAISE EXCEPTION 'bound logical activation preparation is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.state = 'prepared' THEN
        IF NEW.owner_id IS DISTINCT FROM OLD.owner_id
            OR NEW.generation IS DISTINCT FROM OLD.generation
            OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
            OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
            OR NOT EXISTS (
                SELECT 1
                FROM logical_workflow_activation_preparations AS preparation
                WHERE preparation.logical_job_id = OLD.logical_job_id
                  AND preparation.run_id = OLD.run_id
                  AND preparation.invocation_id = OLD.invocation_id
                  AND preparation.descriptor_digest = OLD.descriptor_digest
                  AND preparation.claim_owner_id = OLD.owner_id
                  AND preparation.claim_generation = OLD.generation
                  AND preparation.claim_started_at_ms = OLD.claimed_at_ms
                  AND preparation.claim_expires_at_ms = OLD.expires_at_ms
                  AND preparation.bound_at_ms = NEW.updated_at_ms
            )
        THEN
            RAISE EXCEPTION 'logical activation preparation transition lacks exact binding'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.state <> 'preparing'
        OR NEW.generation <> OLD.generation + 1
        OR NEW.updated_at_ms <> NEW.claimed_at_ms
        OR NOT (
            (NEW.claimed_at_ms >= OLD.expires_at_ms)
            OR (
                NEW.owner_id = OLD.owner_id
                AND NEW.claimed_at_ms >= OLD.claimed_at_ms
                AND NEW.claimed_at_ms < OLD.expires_at_ms
                AND NEW.expires_at_ms > OLD.expires_at_ms
            )
        )
    THEN
        RAISE EXCEPTION 'logical activation preparation fence update is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_logical_job_authority_profile() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.authority_profile IS NOT NULL
        AND NEW.authority_profile IS DISTINCT FROM OLD.authority_profile
    THEN
        RAISE EXCEPTION 'logical job authority profile is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_workflow_jobs_authority_profile_immutable';
    END IF;
    IF OLD.authority_profile IS NULL AND NEW.authority_profile IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
            FROM logical_workflow_activation_preparation_claims AS claim
            WHERE claim.logical_job_id = NEW.id
              AND claim.run_id = NEW.run_id
              AND claim.invocation_id = NEW.invocation_id
              AND claim.authority_profile = NEW.authority_profile
        )
        AND NOT EXISTS (
            SELECT 1
            FROM logical_workflow_reusable_call_publications AS publication
            WHERE publication.run_id = NEW.run_id
              AND publication.parent_invocation_id = NEW.invocation_id
              AND publication.caller_logical_job_id = NEW.id
              AND publication.child_graph_sealed_at_ms IS NOT NULL
              AND publication.authority_profile = NEW.authority_profile
              AND publication.authority_profile = 'credential_free'
        )
    THEN
        RAISE EXCEPTION 'logical job authority profile lacks exact activation evidence'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_workflow_jobs_authority_profile_binding';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_logical_job_runtime_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    expected_revision BIGINT;
    expected_digest BYTEA;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT policy_revision, policy_digest
          INTO expected_revision, expected_digest
        FROM logical_workflow_runtime_policy_pins AS pin
        WHERE run_id = NEW.run_id
        FOR KEY SHARE OF pin;
        IF NOT FOUND
            OR NEW.runtime_policy_revision IS DISTINCT FROM expected_revision
            OR NEW.runtime_policy_digest IS DISTINCT FROM expected_digest
        THEN
            RAISE EXCEPTION 'inserted logical job runtime policy lacks its run pin'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'logical_workflow_jobs_runtime_policy_binding';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.runtime_policy_revision IS DISTINCT FROM OLD.runtime_policy_revision
        OR NEW.runtime_policy_digest IS DISTINCT FROM OLD.runtime_policy_digest
    THEN
        RAISE EXCEPTION 'logical job runtime policy is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_jobs_runtime_policy_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_materialization_authority_profile() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.authority_profile IS DISTINCT FROM OLD.authority_profile THEN
        RAISE EXCEPTION 'materialization authority profile is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_workflow_materialization_claims_profile_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_materialization_claim_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now BIGINT :=
        floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    claim_duration BIGINT;
    is_takeover BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        claim_duration := NEW.expires_at_ms - NEW.claimed_at_ms;
        IF NEW.state <> 'materializing'
            OR NEW.origin_selection_id IS NULL
            OR NEW.generation <> 1
            OR NEW.claimed_at_ms > database_now
            OR database_now - NEW.claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
        THEN
            RAISE EXCEPTION 'initial materialization authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_materialization_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NEW.instance_id
        );
        RETURN NEW;
    END IF;

    IF OLD.state = 'materializing' AND NEW.state = 'materializing' THEN
        claim_duration := NEW.expires_at_ms - NEW.claimed_at_ms;
        is_takeover :=
            NEW.origin_selection_id IS DISTINCT FROM OLD.origin_selection_id;
        IF NEW.generation <> OLD.generation + 1
            OR NEW.origin_selection_id IS NULL
            OR NEW.updated_at_ms <> NEW.claimed_at_ms
            OR (NOT is_takeover
                AND NEW.owner_id IS DISTINCT FROM OLD.owner_id)
            OR (is_takeover AND NEW.claimed_at_ms < OLD.expires_at_ms)
            OR (NOT is_takeover AND NEW.claimed_at_ms >= OLD.expires_at_ms)
            OR (NOT is_takeover AND database_now >= OLD.expires_at_ms)
            OR NEW.claimed_at_ms > database_now
            OR database_now - NEW.claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
            OR NEW.expires_at_ms <= OLD.expires_at_ms
        THEN
            RAISE EXCEPTION 'materialization authority successor is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_materialization_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NEW.instance_id
        );
    ELSIF OLD.state = 'materializing' AND NEW.state = 'materialized' THEN
        IF (NEW.owner_id, NEW.generation, NEW.claimed_at_ms, NEW.expires_at_ms,
            NEW.origin_selection_id, NEW.descriptor_digest)
           IS DISTINCT FROM
           (OLD.owner_id, OLD.generation, OLD.claimed_at_ms, OLD.expires_at_ms,
            OLD.origin_selection_id, OLD.descriptor_digest)
            OR database_now < OLD.claimed_at_ms
            OR database_now >= OLD.expires_at_ms
        THEN
            RAISE EXCEPTION 'materialization terminal authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_materialization_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NEW.instance_id
        );
    ELSIF (NEW.owner_id, NEW.generation, NEW.claimed_at_ms, NEW.expires_at_ms,
           NEW.origin_selection_id)
          IS DISTINCT FROM
          (OLD.owner_id, OLD.generation, OLD.claimed_at_ms, OLD.expires_at_ms,
           OLD.origin_selection_id)
    THEN
        RAISE EXCEPTION 'materialization retained authority is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_claim_transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_materialization_selection_receipt_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    replay_floor BIGINT;
    live_origin BOOLEAN := FALSE;
BEGIN
    SELECT replay_floor_ms INTO replay_floor
    FROM logical_workflow_work_selection_replay_horizons
    WHERE queue_name = 'materialization'
    FOR UPDATE;
    SELECT EXISTS (
        SELECT 1
        FROM logical_workflow_materialization_claims AS claim
        WHERE claim.instance_id = OLD.instance_id
          AND claim.origin_selection_id = OLD.selection_id
          AND claim.state = 'materializing'
    ) INTO live_origin;
    IF replay_floor IS NULL OR OLD.outcome = 'selecting'
        OR OLD.expires_at_ms > replay_floor
        OR OLD.requested_at_ms >= replay_floor
        OR live_origin
    THEN
        RAISE EXCEPTION 'materialization selection receipt remains inside replay authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_materialization_selection_receipt_retained';
    END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION automata_enforce_preparation_authority_profile() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.authority_profile IS DISTINCT FROM OLD.authority_profile THEN
        RAISE EXCEPTION 'logical activation preparation authority profile is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_workflow_activation_preparation_profile_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_preparation_claim_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now BIGINT :=
        floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    claim_duration BIGINT;
    is_takeover BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        claim_duration := NEW.expires_at_ms - NEW.claimed_at_ms;
        IF NEW.state <> 'preparing'
            OR NEW.origin_selection_id IS NULL
            OR NEW.generation <> 1
            OR NEW.claimed_at_ms > database_now
            OR database_now - NEW.claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
        THEN
            RAISE EXCEPTION 'initial preparation authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_preparation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
        );
        RETURN NEW;
    END IF;

    IF OLD.state = 'preparing' AND NEW.state = 'preparing' THEN
        claim_duration := NEW.expires_at_ms - NEW.claimed_at_ms;
        is_takeover :=
            NEW.origin_selection_id IS DISTINCT FROM OLD.origin_selection_id;
        IF NEW.generation <> OLD.generation + 1
            OR NEW.origin_selection_id IS NULL
            OR NEW.updated_at_ms <> NEW.claimed_at_ms
            OR (NOT is_takeover
                AND NEW.owner_id IS DISTINCT FROM OLD.owner_id)
            OR (is_takeover AND NEW.claimed_at_ms < OLD.expires_at_ms)
            OR (NOT is_takeover AND NEW.claimed_at_ms >= OLD.expires_at_ms)
            OR (NOT is_takeover AND database_now >= OLD.expires_at_ms)
            OR NEW.claimed_at_ms > database_now
            OR database_now - NEW.claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
            OR NEW.expires_at_ms <= OLD.expires_at_ms
        THEN
            RAISE EXCEPTION 'preparation authority successor is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_preparation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
        );
    ELSIF OLD.state = 'preparing' AND NEW.state = 'prepared' THEN
        IF (NEW.owner_id, NEW.generation, NEW.claimed_at_ms, NEW.expires_at_ms,
            NEW.origin_selection_id, NEW.descriptor_digest)
           IS DISTINCT FROM
           (OLD.owner_id, OLD.generation, OLD.claimed_at_ms, OLD.expires_at_ms,
            OLD.origin_selection_id, OLD.descriptor_digest)
            OR database_now < OLD.claimed_at_ms
            OR database_now >= OLD.expires_at_ms
        THEN
            RAISE EXCEPTION 'preparation terminal authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_preparation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
        );
    ELSIF (NEW.owner_id, NEW.generation, NEW.claimed_at_ms, NEW.expires_at_ms,
           NEW.origin_selection_id)
          IS DISTINCT FROM
          (OLD.owner_id, OLD.generation, OLD.claimed_at_ms, OLD.expires_at_ms,
           OLD.origin_selection_id)
    THEN
        RAISE EXCEPTION 'preparation retained authority is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_preparation_claim_transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_provider_delivery_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.provider IS DISTINCT FROM OLD.provider
        OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
        OR NEW.installation_id IS DISTINCT FROM OLD.installation_id
        OR NEW.provider_repository_id IS DISTINCT FROM OLD.provider_repository_id
        OR NEW.repository_visibility IS DISTINCT FROM OLD.repository_visibility
        OR NEW.repository_identity IS DISTINCT FROM OLD.repository_identity
        OR NEW.delivery_id IS DISTINCT FROM OLD.delivery_id
        OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
        OR NEW.raw_event_digest IS DISTINCT FROM OLD.raw_event_digest
        OR NEW.raw_event_object_key IS DISTINCT FROM OLD.raw_event_object_key
        OR NEW.raw_event_size_bytes IS DISTINCT FROM OLD.raw_event_size_bytes
        OR NEW.raw_event_media_type IS DISTINCT FROM OLD.raw_event_media_type
        OR NEW.accepted_at_ms IS DISTINCT FROM OLD.accepted_at_ms
    THEN
        RAISE EXCEPTION 'provider delivery immutable evidence cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'provider_delivery_inbox_evidence_immutable';
    END IF;

    IF NEW.state_updated_at_ms < OLD.state_updated_at_ms THEN
        RAISE EXCEPTION 'provider delivery state time cannot regress'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'provider_delivery_inbox_time_regression';
    END IF;

    IF OLD.state IN ('pending', 'retry') AND NEW.state = 'claimed' THEN
        IF NEW.claim_fence <> OLD.claim_fence + 1
            OR NEW.attempt_count <> OLD.attempt_count + 1
            OR NEW.claimed_at_ms < OLD.state_updated_at_ms
            OR NEW.state_updated_at_ms IS DISTINCT FROM NEW.claimed_at_ms
            OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
            OR (
                OLD.state = 'retry'
                AND NEW.claimed_at_ms < OLD.next_attempt_at_ms
            )
            OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
        THEN
            RAISE EXCEPTION 'provider delivery claim must advance exact retry state'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_claim_transition';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'claimed' THEN
        IF NEW.claim_fence = OLD.claim_fence + 1
            AND NEW.claimed_at_ms IS NOT DISTINCT FROM OLD.claimed_at_ms
        THEN
            IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                OR NEW.claim_owner_id IS DISTINCT FROM OLD.claim_owner_id
                OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
                OR NEW.claim_expires_at_ms <= OLD.claim_expires_at_ms
                OR NEW.state_updated_at_ms <= OLD.state_updated_at_ms
                OR NEW.state_updated_at_ms >= OLD.claim_expires_at_ms
                OR NEW.renewal_predecessor_expires_at_ms
                    IS DISTINCT FROM OLD.claim_expires_at_ms
            THEN
                RAISE EXCEPTION 'provider delivery renewal must rotate and strictly extend the live exact claim'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'provider_delivery_inbox_renewal_transition';
            END IF;
        ELSIF NEW.claim_fence = OLD.claim_fence + 1 THEN
            IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                OR NEW.claimed_at_ms < OLD.claim_expires_at_ms
                OR NEW.state_updated_at_ms IS DISTINCT FROM NEW.claimed_at_ms
                OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
                OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
            THEN
                RAISE EXCEPTION 'provider delivery crash reclaim must advance only its fence'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'provider_delivery_inbox_reclaim_transition';
            END IF;
        ELSE
            RAISE EXCEPTION 'provider delivery claimed-state transition has an invalid fence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_claimed_fence_transition';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'retry' THEN
        IF NEW.claim_fence <> OLD.claim_fence
            OR NEW.attempt_count <> OLD.attempt_count
            OR NEW.state_updated_at_ms < OLD.claimed_at_ms
            OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
        THEN
            RAISE EXCEPTION 'provider delivery retry must close the exact claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_retry_transition';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'completed' THEN
        IF NEW.claim_fence <> OLD.claim_fence
            OR NEW.attempt_count <> OLD.attempt_count
            OR NEW.state_updated_at_ms < OLD.claimed_at_ms
            OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
            OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
            OR NEW.terminal_claim_owner_id IS DISTINCT FROM OLD.claim_owner_id
            OR NEW.terminal_claim_fence IS DISTINCT FROM OLD.claim_fence
        THEN
            RAISE EXCEPTION 'provider delivery completion must close the exact claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_completion_transition';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'rejected' THEN
        IF NEW.claim_fence <> OLD.claim_fence
            OR NEW.attempt_count <> OLD.attempt_count
            OR NEW.state_updated_at_ms < OLD.claimed_at_ms
            OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
            OR NEW.terminal_claim_owner_id IS DISTINCT FROM OLD.claim_owner_id
            OR NEW.terminal_claim_fence IS DISTINCT FROM OLD.claim_fence
        THEN
            RAISE EXCEPTION 'provider delivery rejection must close the exact claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_rejection_transition';
        END IF;
    ELSE
        RAISE EXCEPTION 'provider delivery lifecycle transition is not permitted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'provider_delivery_inbox_lifecycle_transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_provider_delivery_outcome_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    durable_state TEXT;
    durable_count SMALLINT;
    durable_completed_at BIGINT;
BEGIN
    SELECT state, completion_outcome_count, completed_at_ms
    INTO durable_state, durable_count, durable_completed_at
    FROM provider_delivery_inbox
    WHERE id = NEW.inbox_id AND tenant_id = NEW.tenant_id;

    IF durable_state IS DISTINCT FROM 'completed'
        OR NEW.ordinal >= durable_count
        OR NEW.created_at_ms IS DISTINCT FROM durable_completed_at
        OR EXISTS (
            SELECT 1
            FROM provider_delivery_workflow_outcomes AS outcome
            WHERE outcome.inbox_id = NEW.inbox_id
              AND (
                (outcome.ordinal < NEW.ordinal
                    AND outcome.workflow_path >= NEW.workflow_path)
                OR (outcome.ordinal > NEW.ordinal
                    AND outcome.workflow_path <= NEW.workflow_path)
              )
        )
    THEN
        RAISE EXCEPTION 'provider delivery outcome does not match terminal ordering'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'provider_delivery_workflow_outcomes_terminal_order';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_provider_token_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'provider-token tombstones cannot be deleted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_provider_tokens_tombstone_immutable';
    END IF;

    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR OLD.principal_id IS DISTINCT FROM NEW.principal_id
        OR OLD.provider_id IS DISTINCT FROM NEW.provider_id
        OR OLD.provider_subject IS DISTINCT FROM NEW.provider_subject
        OR OLD.envelope_record_id IS DISTINCT FROM NEW.envelope_record_id
        OR OLD.created_at_ms IS DISTINCT FROM NEW.created_at_ms
    THEN
        RAISE EXCEPTION 'provider-token identity is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_provider_tokens_identity_immutable';
    END IF;

    IF OLD.revoked_at_ms IS NOT NULL THEN
        RAISE EXCEPTION 'revoked provider-token tombstones are immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_provider_tokens_tombstone_immutable';
    END IF;

    IF NEW.version <> OLD.version + 1 OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'provider-token updates require the next CAS version and monotonic time'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_provider_tokens_update_cas';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_runner_lease_offer_authority_horizon() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.offer_valid_until_ms IS DISTINCT FROM OLD.offer_valid_until_ms THEN
        RAISE EXCEPTION 'runner lease-offer authority horizon is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_lease_offer_authority_horizon_immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION automata_enforce_runner_lease_offer_delivery_revocation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now_ms BIGINT;
    exact_active_attempt BOOLEAN;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.delivery_revoked_at_ms IS NOT NULL
           OR OLD.delivery_revocation_reason IS NOT NULL THEN
            IF NEW.delivery_revoked_at_ms
                    IS DISTINCT FROM OLD.delivery_revoked_at_ms
               OR NEW.delivery_revocation_reason
                    IS DISTINCT FROM OLD.delivery_revocation_reason THEN
                RAISE EXCEPTION 'runner lease-offer delivery revocation is immutable'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'runner_lease_offer_delivery_revocation_immutable';
            END IF;
            RETURN NEW;
        END IF;
    END IF;

    IF NEW.delivery_revoked_at_ms IS NULL
       AND NEW.delivery_revocation_reason IS NULL THEN
        RETURN NEW;
    END IF;
    IF NEW.delivery_revoked_at_ms IS NULL
       OR NEW.delivery_revocation_reason IS NULL THEN
        RAISE EXCEPTION 'runner lease-offer delivery revocation evidence is incomplete'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_lease_offer_publications_delivery_revocation';
    END IF;

    SELECT COALESCE(
               attempt.lifecycle IN (
                   'leased', 'preparing', 'running', 'cancelling', 'finalizing'
               )
               AND attempt.job_id = NEW.job_id
               AND attempt.runner_id = NEW.runner_id
               AND attempt.runner_session_id = NEW.runner_session_id
               AND attempt.runner_session_epoch = NEW.runner_session_epoch
               AND attempt.runner_generation = NEW.runner_generation
               AND attempt.runner_slot = NEW.runner_slot
               AND attempt.lease_id = NEW.lease_id
               AND attempt.fencing_token = NEW.fencing_token
               AND attempt.lease_issued_at_ms = NEW.lease_issued_at_ms
               AND attempt.lease_expires_at_ms >= NEW.lease_expires_at_ms,
               FALSE
           )
    INTO exact_active_attempt
    FROM job_attempts AS attempt
    WHERE attempt.id = NEW.attempt_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'runner lease-offer delivery authority is missing'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_lease_offer_delivery_revocation_authority';
    END IF;

    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    CASE NEW.delivery_revocation_reason
        WHEN 'attempt_superseded' THEN
            IF exact_active_attempt THEN
                RAISE EXCEPTION 'live runner lease offer cannot be revoked as superseded'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'runner_lease_offer_delivery_revocation_authority';
            END IF;
        WHEN 'authority_expired' THEN
            IF NOT exact_active_attempt
               OR database_now_ms < NEW.offer_valid_until_ms THEN
                RAISE EXCEPTION 'runner lease offer lacks expired delivery authority'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'runner_lease_offer_delivery_revocation_authority';
            END IF;
        ELSE
            RAISE EXCEPTION 'runner lease-offer delivery revocation reason is invalid'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'runner_lease_offer_publications_delivery_revocation';
    END CASE;

    -- The marker is authority evidence, so its observation time is always issued
    -- by PostgreSQL after the exact attempt lock rather than accepted from a caller.
    NEW.delivery_revoked_at_ms := database_now_ms;
    RETURN NEW;
END
$$;

CREATE FUNCTION automata_enforce_runner_rpc_receipt_lease_offer_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.lease_offer_request_operation_id
            IS DISTINCT FROM OLD.lease_offer_request_operation_id
       OR NEW.lease_offer_command_sequence
            IS DISTINCT FROM OLD.lease_offer_command_sequence
       OR NEW.lease_offer_response_disposition
            IS DISTINCT FROM OLD.lease_offer_response_disposition
       OR NEW.lease_offer_primary_response_schema
            IS DISTINCT FROM OLD.lease_offer_primary_response_schema
       OR NEW.lease_offer_primary_response_digest
            IS DISTINCT FROM OLD.lease_offer_primary_response_digest
       OR NEW.lease_offer_fallback_version
            IS DISTINCT FROM OLD.lease_offer_fallback_version
       OR NEW.lease_offer_fallback_operation_id
            IS DISTINCT FROM OLD.lease_offer_fallback_operation_id
       OR NEW.lease_offer_fallback_retry_after_millis
            IS DISTINCT FROM OLD.lease_offer_fallback_retry_after_millis
       OR NEW.lease_offer_fallback_response_schema
            IS DISTINCT FROM OLD.lease_offer_fallback_response_schema
       OR NEW.lease_offer_fallback_response_digest
            IS DISTINCT FROM OLD.lease_offer_fallback_response_digest THEN
        RAISE EXCEPTION 'runner lease-request receipt offer binding is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_rpc_receipt_lease_offer_binding_immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION automata_enforce_runtime_policy_columns_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.runtime_policy_revision IS DISTINCT FROM OLD.runtime_policy_revision
        OR NEW.runtime_policy_digest IS DISTINCT FROM OLD.runtime_policy_digest
    THEN
        RAISE EXCEPTION 'logical runtime policy evidence is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runtime_policy_downstream_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_workflow_admission_graph_seal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.admission_graph_sealed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'workflow admission graph must begin unsealed'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_admission_graph_construction_window';
        END IF;
        RETURN NEW;
    END IF;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF OLD.admission_graph_sealed_at_ms IS NOT NULL THEN
        IF NEW.admission_graph_sealed_at_ms IS DISTINCT FROM
           OLD.admission_graph_sealed_at_ms
        THEN
            RAISE EXCEPTION 'workflow admission graph seal is immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_admission_graph_seal_immutable';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.admission_graph_sealed_at_ms IS NULL
        OR NEW.admission_graph_sealed_at_ms <> NEW.updated_at_ms
        OR NEW.admission_graph_sealed_at_ms > database_now
        OR database_now - NEW.admission_graph_sealed_at_ms > 60000
    THEN
        RAISE EXCEPTION 'workflow admission graph seal transition is invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_admission_graph_seal_transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_workflow_concurrency_policy_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.concurrency_queue_policy IS DISTINCT FROM OLD.concurrency_queue_policy THEN
        RAISE EXCEPTION 'Workflow concurrency queue policy is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_activation_input() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.activation_input_digest IS NOT NULL
        AND NEW.activation_input_digest IS DISTINCT FROM OLD.activation_input_digest
    THEN
        RAISE EXCEPTION 'logical workflow activation input digest is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.state = 'activating' AND NOT EXISTS (
        SELECT 1
        FROM logical_workflow_activation_preparations AS preparation
        JOIN logical_workflow_activation_preparation_claims AS preparation_claim
          ON preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.state = 'prepared'
        WHERE preparation.run_id = NEW.run_id
          AND preparation.invocation_id = NEW.invocation_id
          AND preparation.logical_job_id = NEW.id
          AND preparation.activation_input_digest = NEW.activation_input_digest
          AND preparation.authority_profile = NEW.authority_profile
          AND preparation_claim.authority_profile = NEW.authority_profile
          AND preparation.bound_at_ms <= NEW.activation_claimed_at_ms
    ) THEN
        RAISE EXCEPTION 'logical workflow activation input lacks exact profiled preparation'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_instance_result_claim_transit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.invocation_id IS DISTINCT FROM OLD.invocation_id
        OR NEW.logical_job_id IS DISTINCT FROM OLD.logical_job_id
        OR NEW.instance_id IS DISTINCT FROM OLD.instance_id
        OR NEW.job_id IS DISTINCT FROM OLD.job_id
        OR NEW.descriptor_digest IS DISTINCT FROM OLD.descriptor_digest
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'logical workflow instance-result claim identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state = 'projecting' AND NEW.state = 'projecting' THEN
        IF NOT (
            NEW.generation = OLD.generation + 1
            AND NEW.claimed_at_ms >= OLD.expires_at_ms
            AND NEW.expires_at_ms > NEW.claimed_at_ms
            AND NEW.expires_at_ms - NEW.claimed_at_ms <= 900000
            AND NEW.updated_at_ms = NEW.claimed_at_ms
        ) THEN
            RAISE EXCEPTION 'logical workflow instance-result takeover is not fenced'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'projecting' AND NEW.state = 'finalized' THEN
        IF NEW.owner_id IS DISTINCT FROM OLD.owner_id
            OR NEW.generation IS DISTINCT FROM OLD.generation
            OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
            OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
            OR NOT EXISTS (
                SELECT 1
                FROM logical_workflow_instance_results AS result
                WHERE result.attempt_id = NEW.attempt_id
                  AND result.run_id = NEW.run_id
                  AND result.invocation_id = NEW.invocation_id
                  AND result.logical_job_id = NEW.logical_job_id
                  AND result.instance_id = NEW.instance_id
                  AND result.job_id = NEW.job_id
                  AND result.descriptor_digest = NEW.descriptor_digest
                  AND result.claim_owner_id = OLD.owner_id
                  AND result.claim_generation = OLD.generation
                  AND result.claim_started_at_ms = OLD.claimed_at_ms
                  AND result.claim_expires_at_ms = OLD.expires_at_ms
                  AND result.finalized_at_ms = NEW.updated_at_ms
                  AND result.output_count = (
                      SELECT count(*)
                      FROM logical_workflow_instance_result_outputs AS output
                      WHERE output.instance_id = result.instance_id
                  )
            )
        THEN
            RAISE EXCEPTION 'logical workflow instance-result transition lacks exact evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'logical workflow instance-result claim transition is invalid'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_instance_result_selection() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.selection_id IS DISTINCT FROM OLD.selection_id
        OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
        OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
        OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR OLD.outcome <> 'selecting'
        OR NEW.updated_at_ms <> OLD.updated_at_ms
    THEN
        RAISE EXCEPTION 'instance-result selection transition is not exact'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.outcome = 'idle' THEN
        RETURN NEW;
    END IF;
    IF NEW.outcome = 'quarantined' AND EXISTS (
        SELECT 1
        FROM logical_workflow_instance_result_quarantines AS quarantine
        WHERE quarantine.attempt_id = NEW.attempt_id
          AND quarantine.tenant_id = NEW.tenant_id
    ) THEN
        RETURN NEW;
    END IF;
    IF NEW.outcome <> 'claimed' OR NOT EXISTS (
        SELECT 1
        FROM logical_workflow_instance_result_claims AS claim
        JOIN attempt_terminal_results AS terminal ON terminal.attempt_id = claim.attempt_id
        JOIN job_attempts AS attempt ON attempt.id = terminal.attempt_id
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE claim.attempt_id = NEW.attempt_id
          AND repository.tenant_id = NEW.tenant_id
          AND claim.owner_id = NEW.owner_id
          AND claim.generation = NEW.generation
          AND claim.claimed_at_ms = NEW.claimed_at_ms
          AND claim.expires_at_ms = NEW.expires_at_ms
          AND claim.state = 'projecting'
    ) THEN
        RAISE EXCEPTION 'instance-result selection lacks its exact live claim'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_invocation_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.invocation_kind IS DISTINCT FROM OLD.invocation_kind
        OR NEW.plan_digest IS DISTINCT FROM OLD.plan_digest
        OR NEW.plan_object_key IS DISTINCT FROM OLD.plan_object_key
        OR NEW.plan_size_bytes IS DISTINCT FROM OLD.plan_size_bytes
        OR NEW.plan_media_type IS DISTINCT FROM OLD.plan_media_type
        OR NEW.plan_schema IS DISTINCT FROM OLD.plan_schema
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'logical workflow invocation descriptor is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_invocation_descriptor_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_job_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.invocation_id IS DISTINCT FROM OLD.invocation_id
        OR NEW.logical_key IS DISTINCT FROM OLD.logical_key
        OR NEW.source_order IS DISTINCT FROM OLD.source_order
        OR NEW.execution_kind IS DISTINCT FROM OLD.execution_kind
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'logical workflow logical-job descriptor is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_job_result_claim_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    expected_conclusion TEXT;
BEGIN
    IF NEW.logical_job_id IS DISTINCT FROM OLD.logical_job_id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.invocation_id IS DISTINCT FROM OLD.invocation_id
        OR NEW.descriptor_digest IS DISTINCT FROM OLD.descriptor_digest
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'logical workflow job-result claim identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state = 'aggregating' AND NEW.state = 'aggregating' THEN
        IF NOT (
            NEW.generation = OLD.generation + 1
            AND NEW.claimed_at_ms >= OLD.expires_at_ms
            AND NEW.expires_at_ms > NEW.claimed_at_ms
            AND NEW.expires_at_ms - NEW.claimed_at_ms <= 900000
            AND NEW.updated_at_ms = NEW.claimed_at_ms
        ) THEN
            RAISE EXCEPTION 'logical workflow job-result takeover is not fenced'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'aggregating' AND NEW.state = 'finalized' THEN
        SELECT CASE
            WHEN result.instance_count = 0 THEN 'skipped'
            WHEN bool_or(instance.effective_conclusion = 'failure') THEN 'failure'
            WHEN bool_or(instance.effective_conclusion = 'timed_out') THEN 'timed_out'
            WHEN bool_or(instance.effective_conclusion = 'cancelled') THEN 'cancelled'
            WHEN bool_or(instance.effective_conclusion = 'success') THEN 'success'
            ELSE 'skipped'
        END
        INTO expected_conclusion
        FROM logical_workflow_job_results AS result
        LEFT JOIN logical_workflow_job_result_instances AS instance
          ON instance.logical_job_id = result.logical_job_id
        WHERE result.logical_job_id = NEW.logical_job_id
        GROUP BY result.logical_job_id, result.instance_count;

        IF NEW.owner_id IS DISTINCT FROM OLD.owner_id
            OR NEW.generation IS DISTINCT FROM OLD.generation
            OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
            OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
            OR NOT EXISTS (
                SELECT 1
                FROM logical_workflow_job_results AS result
                JOIN logical_workflow_jobs AS job
                  ON job.id = result.logical_job_id
                 AND job.run_id = result.run_id
                 AND job.invocation_id = result.invocation_id
                WHERE result.logical_job_id = NEW.logical_job_id
                  AND result.descriptor_digest = NEW.descriptor_digest
                  AND result.claim_owner_id = OLD.owner_id
                  AND result.claim_generation = OLD.generation
                  AND result.claim_started_at_ms = OLD.claimed_at_ms
                  AND result.claim_expires_at_ms = OLD.expires_at_ms
                  AND result.finalized_at_ms = NEW.updated_at_ms
                  AND result.effective_conclusion = expected_conclusion
                  AND result.instance_count = (
                      SELECT count(*)
                      FROM logical_workflow_job_result_instances AS instance
                      WHERE instance.logical_job_id = result.logical_job_id
                  )
                  AND result.prerequisite_count = (
                      SELECT count(*)
                      FROM logical_workflow_job_result_prerequisites AS prerequisite
                      WHERE prerequisite.logical_job_id = result.logical_job_id
                  )
                  AND result.output_count = (
                      SELECT count(*)
                      FROM logical_workflow_job_result_outputs AS output
                      WHERE output.logical_job_id = result.logical_job_id
                  )
                  AND result.closure_has_failure = (
                      result.effective_conclusion IN ('failure', 'timed_out')
                      OR EXISTS (
                          SELECT 1
                          FROM logical_workflow_job_result_prerequisites AS prerequisite
                          WHERE prerequisite.logical_job_id = result.logical_job_id
                            AND prerequisite.closure_has_failure
                      )
                  )
                  AND result.closure_has_cancelled = (
                      result.effective_conclusion = 'cancelled'
                      OR EXISTS (
                          SELECT 1
                          FROM logical_workflow_job_result_prerequisites AS prerequisite
                          WHERE prerequisite.logical_job_id = result.logical_job_id
                            AND prerequisite.closure_has_cancelled
                      )
                  )
                  AND result.closure_has_skipped = (
                      result.effective_conclusion = 'skipped'
                      OR EXISTS (
                          SELECT 1
                          FROM logical_workflow_job_result_prerequisites AS prerequisite
                          WHERE prerequisite.logical_job_id = result.logical_job_id
                            AND prerequisite.closure_has_skipped
                      )
                  )
                  AND job.updated_at_ms = result.finalized_at_ms
                  AND job.state = CASE result.effective_conclusion
                      WHEN 'success' THEN 'completed'
                      WHEN 'failure' THEN 'failed'
                      WHEN 'timed_out' THEN 'failed'
                      WHEN 'cancelled' THEN 'cancelled'
                      WHEN 'skipped' THEN 'skipped'
                  END
            )
        THEN
            RAISE EXCEPTION 'logical workflow job-result finalization lacks exact evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'logical workflow job-result claim transition is invalid'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_job_result_selection() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.selection_id IS DISTINCT FROM OLD.selection_id
        OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
        OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
        OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR OLD.outcome <> 'selecting'
        OR NEW.updated_at_ms <> OLD.updated_at_ms
    THEN
        RAISE EXCEPTION 'job-result selection transition is not exact'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.outcome = 'idle' THEN
        RETURN NEW;
    END IF;
    IF NEW.outcome = 'quarantined' AND EXISTS (
        SELECT 1
        FROM logical_workflow_job_result_quarantines AS quarantine
        WHERE quarantine.logical_job_id = NEW.logical_job_id
          AND quarantine.tenant_id = NEW.tenant_id
          AND quarantine.run_id = NEW.run_id
          AND quarantine.invocation_id = NEW.invocation_id
    ) THEN
        RETURN NEW;
    END IF;
    IF NEW.outcome <> 'claimed' OR NOT EXISTS (
        SELECT 1
        FROM logical_workflow_job_result_claims AS claim
        JOIN logical_workflow_jobs AS job
          ON job.run_id = claim.run_id
         AND job.invocation_id = claim.invocation_id
         AND job.id = claim.logical_job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
          AND repository.tenant_id = NEW.tenant_id
          AND claim.owner_id = NEW.owner_id
          AND claim.generation = NEW.generation
          AND claim.claimed_at_ms = NEW.claimed_at_ms
          AND claim.expires_at_ms = NEW.expires_at_ms
          AND claim.state = 'aggregating'
    ) THEN
        RAISE EXCEPTION 'job-result selection lacks its exact live claim'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_marker_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.root_invocation_id IS DISTINCT FROM OLD.root_invocation_id
        OR NEW.orchestration_schema IS DISTINCT FROM OLD.orchestration_schema
        OR NEW.admission_digest IS DISTINCT FROM OLD.admission_digest
        OR NEW.admitted_at_ms IS DISTINCT FROM OLD.admitted_at_ms
    THEN
        RAISE EXCEPTION 'logical workflow admission marker is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_materialization_claim_transit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.instance_id IS DISTINCT FROM OLD.instance_id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.invocation_id IS DISTINCT FROM OLD.invocation_id
        OR NEW.logical_job_id IS DISTINCT FROM OLD.logical_job_id
        OR NEW.descriptor_digest IS DISTINCT FROM OLD.descriptor_digest
        OR NEW.expected_job_id IS DISTINCT FROM OLD.expected_job_id
        OR NEW.expected_attempt_id IS DISTINCT FROM OLD.expected_attempt_id
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'logical workflow materialization claim identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state = 'materializing' AND NEW.state = 'materializing' THEN
        IF NEW.generation <> OLD.generation + 1
            OR NEW.expires_at_ms <= NEW.claimed_at_ms
            OR NEW.expires_at_ms - NEW.claimed_at_ms > 900000
            OR NEW.updated_at_ms <> NEW.claimed_at_ms
            OR NOT (
                (NEW.origin_selection_id IS NOT DISTINCT FROM OLD.origin_selection_id
                 AND NEW.owner_id IS NOT DISTINCT FROM OLD.owner_id
                 AND NEW.claimed_at_ms >= OLD.claimed_at_ms
                 AND NEW.claimed_at_ms < OLD.expires_at_ms
                 AND NEW.expires_at_ms > OLD.expires_at_ms)
                OR
                (NEW.origin_selection_id IS DISTINCT FROM OLD.origin_selection_id
                 AND NEW.origin_selection_id IS NOT NULL
                 AND NEW.claimed_at_ms >= OLD.expires_at_ms)
            )
        THEN
            RAISE EXCEPTION 'logical workflow materialization successor is not fenced'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'materializing' AND NEW.state = 'materialized' THEN
        IF NEW.owner_id IS DISTINCT FROM OLD.owner_id
            OR NEW.generation IS DISTINCT FROM OLD.generation
            OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
            OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
            OR NEW.origin_selection_id IS DISTINCT FROM OLD.origin_selection_id
            OR NOT EXISTS (
                SELECT 1
                FROM logical_workflow_concrete_jobs AS concrete
                WHERE concrete.instance_id = NEW.instance_id
                  AND concrete.run_id = NEW.run_id
                  AND concrete.invocation_id = NEW.invocation_id
                  AND concrete.logical_job_id = NEW.logical_job_id
                  AND concrete.descriptor_digest = NEW.descriptor_digest
                  AND concrete.job_id = NEW.expected_job_id
                  AND concrete.initial_attempt_id = NEW.expected_attempt_id
                  AND concrete.claim_owner_id = OLD.owner_id
                  AND concrete.claim_generation = OLD.generation
                  AND concrete.claim_started_at_ms = OLD.claimed_at_ms
                  AND concrete.claim_expires_at_ms = OLD.expires_at_ms
                  AND concrete.committed_at_ms = NEW.updated_at_ms
            )
        THEN
            RAISE EXCEPTION 'logical workflow materialization transition lacks exact evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'logical workflow materialization claim transition is invalid'
        USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_requirements_schema_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.runner_requirements_schema IS DISTINCT FROM
       OLD.runner_requirements_schema
    THEN
        RAISE EXCEPTION 'logical workflow runner-requirements schema is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'logical_workflow_runs_runner_requirements_schema_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_result_due_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' OR pg_trigger_depth() <= 1 THEN
        RAISE EXCEPTION 'logical workflow result due queues are trigger-authoritative'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_result_replay_horizon() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    authoritative_now_ms BIGINT;
BEGIN
    authoritative_now_ms :=
        floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF NEW.queue_name IS DISTINCT FROM OLD.queue_name
        OR NEW.replay_floor_ms < OLD.replay_floor_ms
        OR NEW.updated_at_ms < OLD.updated_at_ms
        OR NEW.replay_floor_ms > NEW.updated_at_ms
        OR NEW.updated_at_ms > authoritative_now_ms
        OR NEW.replay_floor_ms - OLD.replay_floor_ms > GREATEST(
            60000, NEW.updated_at_ms - OLD.updated_at_ms
        )
    THEN
        RAISE EXCEPTION 'logical result replay horizon advancement is not authoritative and bounded'
            USING ERRCODE = '23514',
                  CONSTRAINT =
                      'logical_workflow_result_selection_replay_horizons_advance';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_run_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM logical_workflow_runs WHERE run_id = OLD.id
    ) AND (
        NEW.id IS DISTINCT FROM OLD.id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.workflow_id IS DISTINCT FROM OLD.workflow_id
        OR NEW.snapshot_id IS DISTINCT FROM OLD.snapshot_id
        OR NEW.run_number IS DISTINCT FROM OLD.run_number
        OR NEW.run_attempt IS DISTINCT FROM OLD.run_attempt
        OR NEW.event_name IS DISTINCT FROM OLD.event_name
        OR NEW.event_object_key IS DISTINCT FROM OLD.event_object_key
        OR NEW.head_sha IS DISTINCT FROM OLD.head_sha
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR NEW.concurrency_group_key IS DISTINCT FROM OLD.concurrency_group_key
        OR NEW.admission_epoch IS DISTINCT FROM OLD.admission_epoch
        OR NEW.event_digest IS DISTINCT FROM OLD.event_digest
        OR NEW.event_size_bytes IS DISTINCT FROM OLD.event_size_bytes
        OR NEW.event_media_type IS DISTINCT FROM OLD.event_media_type
        OR NEW.plan_digest IS DISTINCT FROM OLD.plan_digest
        OR NEW.plan_object_key IS DISTINCT FROM OLD.plan_object_key
        OR NEW.plan_size_bytes IS DISTINCT FROM OLD.plan_size_bytes
        OR NEW.plan_media_type IS DISTINCT FROM OLD.plan_media_type
        OR NEW.plan_schema IS DISTINCT FROM OLD.plan_schema
        OR NEW.workflow_name IS DISTINCT FROM OLD.workflow_name
        OR NEW.git_ref IS DISTINCT FROM OLD.git_ref
        OR NEW.actor IS DISTINCT FROM OLD.actor
        OR NEW.display_title IS DISTINCT FROM OLD.display_title
        OR NEW.commit_subject IS DISTINCT FROM OLD.commit_subject
    ) THEN
        RAISE EXCEPTION 'logical workflow admitted run descriptor is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_logical_workflow_run_result_claim_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.root_invocation_id IS DISTINCT FROM OLD.root_invocation_id
        OR NEW.descriptor_digest IS DISTINCT FROM OLD.descriptor_digest
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'logical workflow run-result claim identity is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.state = 'aggregating' AND NEW.state = 'aggregating' THEN
        IF NEW.generation <> OLD.generation + 1
            OR NEW.claimed_at_ms < OLD.expires_at_ms
            OR NEW.expires_at_ms <= NEW.claimed_at_ms
            OR NEW.expires_at_ms - NEW.claimed_at_ms > 900000
            OR NEW.updated_at_ms <> NEW.claimed_at_ms
        THEN
            RAISE EXCEPTION 'logical workflow run-result takeover is not fenced'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'aggregating' AND NEW.state = 'finalized' THEN
        IF NEW.owner_id IS DISTINCT FROM OLD.owner_id
            OR NEW.generation IS DISTINCT FROM OLD.generation
            OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
            OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
            OR NOT EXISTS (
                SELECT 1
                FROM logical_workflow_run_results AS result
                JOIN logical_workflow_invocations AS invocation
                  ON invocation.run_id = result.run_id
                 AND invocation.id = result.root_invocation_id
                JOIN logical_workflow_runs AS marker ON marker.run_id = result.run_id
                JOIN workflow_runs AS run ON run.id = result.run_id
                WHERE result.run_id = NEW.run_id
                  AND result.root_invocation_id = NEW.root_invocation_id
                  AND result.descriptor_digest = NEW.descriptor_digest
                  AND result.claim_owner_id = OLD.owner_id
                  AND result.claim_generation = OLD.generation
                  AND result.claim_started_at_ms = OLD.claimed_at_ms
                  AND result.claim_expires_at_ms = OLD.expires_at_ms
                  AND result.finalized_at_ms = NEW.updated_at_ms
                  AND result.job_count = (
                      SELECT count(*)::INTEGER
                      FROM logical_workflow_run_result_jobs AS evidence
                      WHERE evidence.run_id = result.run_id
                  )
                  AND result.job_count = (
                      SELECT count(*)::INTEGER
                      FROM logical_workflow_jobs AS job
                      WHERE job.run_id = result.run_id
                        AND job.invocation_id = result.root_invocation_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM logical_workflow_jobs AS job
                      LEFT JOIN logical_workflow_run_result_jobs AS evidence
                        ON evidence.run_id = job.run_id
                       AND evidence.root_invocation_id = job.invocation_id
                       AND evidence.logical_job_id = job.id
                      LEFT JOIN logical_workflow_effective_job_results AS logical_result
                        ON logical_result.run_id = job.run_id
                       AND logical_result.invocation_id = job.invocation_id
                       AND logical_result.logical_job_id = job.id
                      WHERE job.run_id = result.run_id
                        AND job.invocation_id = result.root_invocation_id
                        AND (
                            evidence.logical_job_id IS NULL
                            OR logical_result.logical_job_id IS NULL
                            OR logical_result.claim_state IS DISTINCT FROM 'finalized'
                            OR evidence.logical_key IS DISTINCT FROM job.logical_key
                            OR evidence.source_order IS DISTINCT FROM job.source_order
                            OR evidence.descriptor_digest IS DISTINCT FROM logical_result.descriptor_digest
                            OR evidence.effective_conclusion IS DISTINCT FROM logical_result.effective_conclusion
                            OR evidence.closure_has_failure IS DISTINCT FROM logical_result.closure_has_failure
                            OR evidence.closure_has_cancelled IS DISTINCT FROM logical_result.closure_has_cancelled
                            OR evidence.closure_has_skipped IS DISTINCT FROM logical_result.closure_has_skipped
                            OR evidence.instance_count IS DISTINCT FROM logical_result.instance_count
                            OR evidence.instances_digest IS DISTINCT FROM logical_result.instances_digest
                            OR evidence.prerequisite_count IS DISTINCT FROM logical_result.prerequisite_count
                            OR evidence.prerequisites_digest IS DISTINCT FROM logical_result.prerequisites_digest
                            OR evidence.output_count IS DISTINCT FROM logical_result.output_count
                            OR evidence.outputs_digest IS DISTINCT FROM logical_result.outputs_digest
                            OR evidence.job_commit_digest IS DISTINCT FROM logical_result.commit_digest
                            OR evidence.job_finalized_at_ms IS DISTINCT FROM logical_result.finalized_at_ms
                        )
                  )
                  AND result.effective_conclusion = CASE
                      WHEN result.workflow_status = 'cancelled' THEN 'cancelled'
                      WHEN EXISTS (
                          SELECT 1 FROM logical_workflow_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion = 'failure'
                      ) THEN 'failure'
                      WHEN EXISTS (
                          SELECT 1 FROM logical_workflow_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion = 'timed_out'
                      ) THEN 'timed_out'
                      WHEN EXISTS (
                          SELECT 1 FROM logical_workflow_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion = 'cancelled'
                      ) THEN 'cancelled'
                      WHEN NOT EXISTS (
                          SELECT 1 FROM logical_workflow_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion <> 'skipped'
                      ) THEN 'skipped'
                      ELSE 'success'
                  END
                  AND invocation.state = CASE result.effective_conclusion
                      WHEN 'success' THEN 'completed'
                      WHEN 'skipped' THEN 'completed'
                      WHEN 'cancelled' THEN 'cancelled'
                      ELSE 'failed'
                  END
                  AND invocation.revision = result.invocation_revision + 1
                  AND invocation.updated_at_ms = result.finalized_at_ms
                  AND marker.state = CASE result.effective_conclusion
                      WHEN 'success' THEN 'completed'
                      WHEN 'skipped' THEN 'completed'
                      WHEN 'cancelled' THEN 'cancelled'
                      ELSE 'failed'
                  END
                  AND marker.revision = result.marker_revision + 1
                  AND marker.updated_at_ms = result.finalized_at_ms
                  AND run.status = CASE result.effective_conclusion
                      WHEN 'cancelled' THEN 'cancelled'
                      ELSE 'completed'
                  END
                  AND run.updated_at_ms = result.finalized_at_ms
            )
        THEN
            RAISE EXCEPTION 'logical workflow run-result finalization lacks exact evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'logical workflow run-result claim transition is invalid'
        USING ERRCODE = '23514';
END;
$$;
