-- Frozen greenfield baseline. Add a new migration instead of editing this stage.

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

CREATE FUNCTION automata_artifact_safety_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.secret_exposure_class IS DISTINCT FROM OLD.secret_exposure_class
       OR NEW.requested_visibility IS DISTINCT FROM OLD.requested_visibility
       OR NEW.effective_visibility IS DISTINCT FROM OLD.effective_visibility
       OR NEW.publication_safety_reason IS DISTINCT FROM OLD.publication_safety_reason
       OR NEW.publication_safety_schema IS DISTINCT FROM OLD.publication_safety_schema THEN
        RAISE EXCEPTION 'artifact safety snapshots are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_artifacts_output_safety_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_assert_cancellation_payload_retention() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.acknowledged_at_ms IS NOT NULL
        AND NEW.delivery_session_id IS NOT NULL
        AND EXISTS (
            SELECT 1
            FROM runner_command_outbox AS command
            WHERE command.runner_session_id = NEW.delivery_session_id
              AND command.command_sequence = NEW.delivery_command_sequence
              AND command.payload_tombstone_reason IS NULL
            LIMIT 1
        )
    THEN
        RAISE EXCEPTION 'acknowledged cancellation retained its command envelope'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_cancellation_payload_retention';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_assert_runner_payload_row_retention() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    retained_live BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'runner_command_outbox' THEN
        SELECT command.payload_tombstone_reason IS NULL
               AND (
                   session.disconnected_at_ms IS NOT NULL
                   OR command.command_sequence <= session.acknowledged_command_sequence
               )
        INTO retained_live
        FROM runner_command_outbox AS command
        JOIN runner_sessions AS session ON session.id = command.runner_session_id
        WHERE command.runner_session_id = NEW.runner_session_id
          AND command.command_sequence = NEW.command_sequence;
    ELSE
        SELECT receipt.payload_tombstone_reason IS NULL
               AND session.disconnected_at_ms IS NOT NULL
        INTO retained_live
        FROM runner_rpc_receipts AS receipt
        JOIN runner_sessions AS session ON session.id = receipt.runner_session_id
        WHERE receipt.runner_session_id = NEW.runner_session_id
          AND receipt.operation_id = NEW.operation_id;
    END IF;
    IF coalesce(retained_live, FALSE) THEN
        RAISE EXCEPTION 'expired runner payload envelope must be tombstoned before commit'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_payload_row_retention';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_assert_runner_session_payload_retention() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM runner_command_outbox AS command
        WHERE command.runner_session_id = NEW.id
          AND command.payload_tombstone_reason IS NULL
          AND (
              NEW.disconnected_at_ms IS NOT NULL
              OR command.command_sequence <= NEW.acknowledged_command_sequence
          )
        LIMIT 1
    ) OR (
        NEW.disconnected_at_ms IS NOT NULL
        AND EXISTS (
            SELECT 1
            FROM runner_rpc_receipts AS receipt
            WHERE receipt.runner_session_id = NEW.id
              AND receipt.payload_tombstone_reason IS NULL
            LIMIT 1
        )
    ) THEN
        RAISE EXCEPTION 'runner session transition retained an expired payload envelope'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_session_payload_retention';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_assign_logical_workflow_terminal_ordinal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    target_logical_job UUID;
    assigned_ordinal BIGINT;
BEGIN
    IF NEW.logical_workflow_logical_job_id IS NOT NULL
        OR NEW.logical_workflow_terminal_ordinal IS NOT NULL
    THEN
        RAISE EXCEPTION 'logical workflow terminal order must not be supplied by a writer'
            USING ERRCODE = '23514';
    END IF;

    SELECT concrete.logical_job_id
      INTO target_logical_job
    FROM job_attempts AS attempt
    JOIN logical_workflow_concrete_jobs AS concrete
      ON concrete.job_id = attempt.job_id
     AND concrete.initial_attempt_id = attempt.id
    WHERE attempt.id = NEW.attempt_id;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    INSERT INTO logical_workflow_job_terminal_counters (
        logical_job_id, last_ordinal
    ) VALUES (target_logical_job, 1)
    ON CONFLICT (logical_job_id) DO UPDATE
    SET last_ordinal = logical_workflow_job_terminal_counters.last_ordinal + 1
    WHERE logical_workflow_job_terminal_counters.last_ordinal < 9223372036854775807
    RETURNING last_ordinal INTO assigned_ordinal;

    IF assigned_ordinal IS NULL THEN
        RAISE EXCEPTION 'logical workflow terminal ordinal is exhausted'
            USING ERRCODE = '22003';
    END IF;

    UPDATE attempt_terminal_results
    SET logical_workflow_logical_job_id = target_logical_job,
        logical_workflow_terminal_ordinal = assigned_ordinal
    WHERE attempt_id = NEW.attempt_id
      AND logical_workflow_logical_job_id IS NULL
      AND logical_workflow_terminal_ordinal IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'logical workflow terminal ordinal assignment lost its row'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_attempt_log_safety_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.secret_exposure_class IS DISTINCT FROM OLD.secret_exposure_class
       OR NEW.raw_log_disposition IS DISTINCT FROM OLD.raw_log_disposition
       OR NEW.requested_visibility IS DISTINCT FROM OLD.requested_visibility
       OR NEW.effective_visibility IS DISTINCT FROM OLD.effective_visibility
       OR NEW.output_safety_reason IS DISTINCT FROM OLD.output_safety_reason
       OR NEW.output_safety_schema IS DISTINCT FROM OLD.output_safety_schema THEN
        RAISE EXCEPTION 'attempt log safety snapshots are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'attempt_log_streams_output_safety_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_cancel_pending_environment_gate_for_attempt() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now_ms BIGINT;
BEGIN
    IF NEW.lifecycle NOT IN ('cancelled', 'timed_out')
       OR OLD.lifecycle = NEW.lifecycle THEN
        RETURN NEW;
    END IF;
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    UPDATE protected_environment_approval_requests AS request
    SET status = 'cancelled',
        resolved_at_ms = database_now_ms,
        resolution_reason = CASE
            WHEN environment.status = 'disabled' THEN 'environment_disabled'
            WHEN request.environment_revision <> environment.revision
              OR request.required_approvals <> environment.required_approvals
              OR request.prevent_self_review <> environment.prevent_self_review
              OR environment.protection_mode <> 'required_approvals'
                THEN 'policy_changed'
            ELSE 'workload_cancelled'
        END,
        revision = request.revision + 1
    FROM job_environment_gates AS gate
    JOIN repository_environments AS environment
      ON environment.tenant_id = gate.tenant_id
     AND environment.repository_id = gate.repository_id
     AND environment.id = gate.environment_id
    WHERE gate.attempt_id = NEW.id
      AND gate.approval_request_id = request.id
      AND request.status = 'pending';
    UPDATE job_environment_gates
    SET state = 'cancelled', updated_at_ms = database_now_ms,
        revision = revision + 1
    WHERE attempt_id = NEW.id
      AND state IN ('selection_pending', 'waiting', 'resolving');
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_cancel_secret_version_mutations_on_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.status = 'deleted' OR NEW.status <> 'deleted' THEN
        RETURN NEW;
    END IF;

    IF EXISTS (
        SELECT 1 FROM secret_version_mutations
        WHERE tenant_id = NEW.tenant_id
          AND secret_id = NEW.id
          AND state = 'reserved'
    ) THEN
        RAISE EXCEPTION 'secret deletion requires exact terminal mutation receipts'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_delete_terminal';
    END IF;

    UPDATE secret_version_mutations
    SET state = 'superseded',
        terminal_reason = 'applied_then_deleted',
        revision = revision + 1
    WHERE tenant_id = NEW.tenant_id
      AND secret_id = NEW.id
      AND state = 'confirmed';
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_capture_github_runtime_authority_claim_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.state = 'claimed'
        AND NEW.mint_claim_owner_id IS NOT NULL
        AND NEW.mint_claim_expires_at_ms IS NOT NULL
    THEN
        INSERT INTO github_runtime_authority_mint_claims (
            tenant_id, attempt_id, fencing_token, claim_fence,
            claim_owner_id, claimed_at_ms, expires_at_ms
        ) VALUES (
            NEW.tenant_id, NEW.attempt_id, NEW.fencing_token,
            NEW.mint_claim_fence, NEW.mint_claim_owner_id,
            NEW.mint_claimed_at_ms, NEW.mint_claim_expires_at_ms
        )
        ON CONFLICT (attempt_id, fencing_token, claim_fence) DO NOTHING;
    END IF;
    IF NEW.state = 'revoke_pending'
        AND NEW.revoke_claim_owner_id IS NOT NULL
        AND NEW.revoke_claimed_at_ms IS NOT NULL
        AND NEW.revoke_claim_expires_at_ms IS NOT NULL
    THEN
        INSERT INTO github_runtime_authority_revocation_claims (
            tenant_id, attempt_id, fencing_token, claim_fence,
            claim_owner_id, claimed_at_ms, expires_at_ms,
            aad_digest, safe_erase_after_ms
        ) VALUES (
            NEW.tenant_id, NEW.attempt_id, NEW.fencing_token,
            NEW.revoke_claim_fence, NEW.revoke_claim_owner_id,
            NEW.revoke_claimed_at_ms, NEW.revoke_claim_expires_at_ms,
            NEW.aad_digest, NEW.safe_erase_after_ms
        )
        ON CONFLICT (attempt_id, fencing_token, claim_fence) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_capture_github_runtime_authority_mint_begin() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.state = 'claimed' AND NEW.state = 'minting' THEN
        INSERT INTO github_runtime_authority_mint_begins (
            tenant_id, attempt_id, fencing_token, claim_fence,
            claim_owner_id, claimed_at_ms, expires_at_ms,
            started_at_ms, provider_request_millis
        ) VALUES (
            NEW.tenant_id, NEW.attempt_id, NEW.fencing_token,
            NEW.mint_claim_fence, NEW.mint_claim_owner_id,
            NEW.mint_claimed_at_ms, OLD.mint_claim_expires_at_ms,
            NEW.mint_started_at_ms, NEW.mint_provider_request_millis
        );
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_capture_github_runtime_authority_operation_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    predecessor_claimed_at BIGINT;
    predecessor_expires_at BIGINT;
    operation_kind TEXT;
    receipt_disposition TEXT;
BEGIN
    IF OLD.state IN ('minting', 'indeterminate')
        AND NEW.state IN ('ready', 'revoke_pending', 'revoked')
        AND OLD.safe_erase_after_ms IS NULL
        AND NEW.safe_erase_after_ms IS NOT NULL
    THEN
        operation_kind := 'mint_commit';
        receipt_disposition := 'applied';
        SELECT claim.claimed_at_ms, claim.expires_at_ms
          INTO STRICT predecessor_claimed_at, predecessor_expires_at
        FROM github_runtime_authority_mint_claims AS claim
        WHERE claim.attempt_id = OLD.attempt_id
          AND claim.fencing_token = OLD.fencing_token
          AND claim.claim_fence = OLD.mint_claim_fence
          AND claim.tenant_id = OLD.tenant_id
          AND claim.claim_owner_id = OLD.mint_claim_owner_id
          AND claim.claimed_at_ms = OLD.mint_claimed_at_ms
        FOR KEY SHARE;
        IF NEW.operation_request_kind <> 'mint_commit'
            OR NEW.operation_request_claim_fence <> OLD.mint_claim_fence
            OR NEW.operation_request_claim_owner_id IS DISTINCT FROM
                OLD.mint_claim_owner_id
            OR NEW.operation_request_commit_disposition IS DISTINCT FROM
                NEW.commit_disposition
            OR NEW.operation_request_provider_expires_at_ms IS DISTINCT FROM
                NEW.provider_expires_at_ms
            OR NEW.operation_request_safe_erase_after_ms IS DISTINCT FROM
                NEW.safe_erase_after_ms
            OR NEW.operation_request_plaintext_schema IS DISTINCT FROM
                NEW.plaintext_schema
            OR NEW.operation_request_plaintext_size_bytes IS DISTINCT FROM
                NEW.plaintext_size_bytes
            OR NEW.operation_request_plaintext_digest IS DISTINCT FROM
                NEW.plaintext_digest
            OR NEW.operation_request_aad_digest IS DISTINCT FROM NEW.aad_digest
            OR NEW.operation_request_observed_at_ms < predecessor_claimed_at
            OR NEW.operation_request_observed_at_ms >=
                NEW.conservative_expiry_at_ms
            OR NEW.envelope_schema IS NOT NULL AND
                NEW.operation_request_envelope_digest IS DISTINCT FROM
                    automata_github_runtime_authority_envelope_digest(
                        NEW.envelope_schema, NEW.wrapping_key_id,
                        NEW.wrapped_data_key, NEW.nonce, NEW.ciphertext
                    )
        THEN
            RAISE EXCEPTION 'GitHub mint transition request evidence is not exact'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_transition_exact';
        END IF;
    ELSIF OLD.state IN ('ready', 'revoke_pending')
        AND NEW.state IN ('quarantined', 'revoked')
        AND NEW.quarantine_at_ms IS DISTINCT FROM OLD.quarantine_at_ms
    THEN
        operation_kind := 'quarantine';
        receipt_disposition := 'applied';
        IF NEW.operation_request_kind <> 'quarantine'
            OR NEW.operation_request_claim_fence <> 0
            OR NEW.operation_request_claim_owner_id IS NOT NULL
            OR NEW.operation_request_failure_kind IS DISTINCT FROM
                NEW.quarantine_kind
            OR NEW.operation_request_aad_digest IS DISTINCT FROM OLD.aad_digest
            OR NEW.operation_request_observed_at_ms < NEW.requested_at_ms
            OR NEW.operation_request_observed_at_ms >= OLD.safe_erase_after_ms
        THEN
            RAISE EXCEPTION 'GitHub quarantine transition request evidence is not exact'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_quarantine_transition_exact';
        END IF;
    ELSIF OLD.state = 'revoke_pending'
        AND OLD.revoke_claim_owner_id IS NOT NULL
        AND (
            NEW.state = 'revoked'
            AND NEW.terminal_reason = 'provider_revocation_confirmed'
            OR NEW.state = 'revoke_pending'
            AND NEW.revoke_claim_owner_id IS NULL
            AND NEW.last_revoke_failure_kind <> 'claim_budget_exhausted'
        )
    THEN
        operation_kind := 'revocation_outcome';
        receipt_disposition := 'applied';
        predecessor_claimed_at := OLD.revoke_claimed_at_ms;
        predecessor_expires_at := OLD.revoke_claim_expires_at_ms;
        IF NEW.operation_request_kind NOT IN (
                'revocation_retry', 'revocation_defer', 'revocation_confirm'
            )
            OR NEW.operation_request_claim_fence <> OLD.revoke_claim_fence
            OR NEW.operation_request_claim_owner_id IS DISTINCT FROM
                OLD.revoke_claim_owner_id
            OR NEW.operation_request_observed_at_ms < predecessor_claimed_at
            OR NEW.operation_request_observed_at_ms >= predecessor_expires_at
            OR NEW.operation_request_kind = 'revocation_retry' AND (
                NEW.last_revoke_failure_kind IS DISTINCT FROM
                    NEW.operation_request_failure_kind
                OR NEW.next_revoke_at_ms::NUMERIC <> LEAST(
                    NEW.safe_erase_after_ms::NUMERIC,
                    NEW.state_updated_at_ms::NUMERIC
                        + NEW.operation_request_retry_at_ms::NUMERIC
                        - NEW.operation_request_observed_at_ms::NUMERIC
                )
                OR NEW.operation_request_retry_at_ms >=
                    NEW.safe_erase_after_ms
            )
            OR NEW.operation_request_kind = 'revocation_defer' AND
                NEW.last_revoke_failure_kind IS DISTINCT FROM
                    NEW.operation_request_failure_kind
            OR NEW.operation_request_kind = 'revocation_confirm' AND NOT (
                NEW.state = 'revoked'
                AND NEW.terminal_reason = 'provider_revocation_confirmed'
            )
        THEN
            RAISE EXCEPTION 'GitHub revocation transition request evidence is not exact'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_revocation_transition_exact';
        END IF;
    ELSIF OLD.state = NEW.state
        AND NEW.operation_request_kind IS NOT NULL
        AND automata_github_runtime_authority_same_non_operation_state(
            OLD, NEW
        )
    THEN
        receipt_disposition := 'terminal_erasable';
        IF NEW.operation_request_kind = 'mint_commit' THEN
            operation_kind := 'mint_commit';
            SELECT claim.claimed_at_ms, claim.expires_at_ms
              INTO STRICT predecessor_claimed_at, predecessor_expires_at
            FROM github_runtime_authority_mint_claims AS claim
            WHERE claim.attempt_id = NEW.attempt_id
              AND claim.fencing_token = NEW.fencing_token
              AND claim.claim_fence = NEW.operation_request_claim_fence
              AND claim.tenant_id = NEW.tenant_id
              AND claim.claim_owner_id = NEW.operation_request_claim_owner_id
            FOR KEY SHARE;
            IF NEW.state <> 'revoked'
                OR NEW.terminal_reason <> 'indeterminate_authority_expired'
                OR NEW.envelope_schema IS NOT NULL
                OR database_now < NEW.conservative_expiry_at_ms
                OR NEW.mint_started_at_ms IS NULL
                OR NEW.operation_request_observed_at_ms <
                    predecessor_claimed_at
                OR NEW.operation_request_observed_at_ms >=
                    NEW.conservative_expiry_at_ms
            THEN
                RAISE EXCEPTION 'GitHub mint terminal observation is not erasable'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_mint_terminal_exact';
            END IF;
        ELSIF NEW.operation_request_kind = 'quarantine' THEN
            operation_kind := 'quarantine';
            IF NEW.operation_request_claim_fence <> 0
                OR NEW.operation_request_claim_owner_id IS NOT NULL
                OR NEW.state <> 'revoked'
                OR NEW.envelope_schema IS NOT NULL
                OR NEW.safe_erase_after_ms IS NULL
                OR database_now < NEW.safe_erase_after_ms
                OR NEW.operation_request_aad_digest IS DISTINCT FROM NEW.aad_digest
                OR NEW.operation_request_observed_at_ms < NEW.requested_at_ms
                OR NEW.operation_request_observed_at_ms >=
                    NEW.safe_erase_after_ms
            THEN
                RAISE EXCEPTION 'GitHub quarantine terminal observation is not erasable'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_quarantine_terminal_exact';
            END IF;
        ELSIF NEW.operation_request_kind IN (
            'revocation_retry', 'revocation_defer', 'revocation_confirm'
        ) THEN
            operation_kind := 'revocation_outcome';
            SELECT claim.claimed_at_ms, claim.expires_at_ms
              INTO STRICT predecessor_claimed_at, predecessor_expires_at
            FROM github_runtime_authority_revocation_claims AS claim
            WHERE claim.attempt_id = NEW.attempt_id
              AND claim.fencing_token = NEW.fencing_token
              AND claim.claim_fence = NEW.operation_request_claim_fence
              AND claim.tenant_id = NEW.tenant_id
              AND claim.claim_owner_id = NEW.operation_request_claim_owner_id
              AND claim.aad_digest = NEW.aad_digest
              AND claim.safe_erase_after_ms = NEW.safe_erase_after_ms
            FOR KEY SHARE;
            IF NOT (
                NEW.state IN ('quarantined', 'revoked')
                OR NEW.revoke_claim_fence <>
                    NEW.operation_request_claim_fence
                OR database_now >= predecessor_expires_at
            )
                OR NEW.operation_request_observed_at_ms < predecessor_claimed_at
                OR NEW.operation_request_observed_at_ms >= predecessor_expires_at
                OR NEW.operation_request_kind = 'revocation_retry'
                AND NEW.operation_request_retry_at_ms >=
                    NEW.safe_erase_after_ms
            THEN
                RAISE EXCEPTION 'GitHub revocation terminal observation is not erasable'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revocation_terminal_exact';
            END IF;
        ELSE
            RETURN NEW;
        END IF;
    ELSE
        RETURN NEW;
    END IF;

    INSERT INTO github_runtime_authority_operation_transitions (
        tenant_id, attempt_id, fencing_token, operation_kind, claim_fence,
        claim_owner_id, claim_claimed_at_ms, claim_expires_at_ms,
        disposition, request_kind, request_observed_at_ms,
        request_retry_at_ms, request_failure_kind,
        request_commit_disposition, request_provider_expires_at_ms,
        request_safe_erase_after_ms, request_plaintext_schema,
        request_plaintext_size_bytes, request_plaintext_digest,
        request_aad_digest, request_envelope_digest,
        predecessor_state, predecessor_updated_at_ms,
        result_state, result_updated_at_ms, result_terminal_reason
    ) VALUES (
        NEW.tenant_id, NEW.attempt_id, NEW.fencing_token, operation_kind,
        COALESCE(NEW.operation_request_claim_fence, 0),
        NEW.operation_request_claim_owner_id, predecessor_claimed_at,
        predecessor_expires_at, receipt_disposition,
        NEW.operation_request_kind, NEW.operation_request_observed_at_ms,
        NEW.operation_request_retry_at_ms, NEW.operation_request_failure_kind,
        NEW.operation_request_commit_disposition,
        NEW.operation_request_provider_expires_at_ms,
        NEW.operation_request_safe_erase_after_ms,
        NEW.operation_request_plaintext_schema,
        NEW.operation_request_plaintext_size_bytes,
        NEW.operation_request_plaintext_digest,
        NEW.operation_request_aad_digest,
        NEW.operation_request_envelope_digest,
        OLD.state, OLD.state_updated_at_ms,
        NEW.state, NEW.state_updated_at_ms, NEW.terminal_reason
    );
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_clear_stale_github_runtime_authority_operation_request() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.operation_request_kind IS NOT NULL
        AND automata_github_runtime_authority_same_operation_request(OLD, NEW)
        AND NOT automata_github_runtime_authority_same_non_operation_state(OLD, NEW)
    THEN
        NEW.operation_request_kind := NULL;
        NEW.operation_request_claim_fence := NULL;
        NEW.operation_request_claim_owner_id := NULL;
        NEW.operation_request_observed_at_ms := NULL;
        NEW.operation_request_retry_at_ms := NULL;
        NEW.operation_request_failure_kind := NULL;
        NEW.operation_request_commit_disposition := NULL;
        NEW.operation_request_provider_expires_at_ms := NULL;
        NEW.operation_request_safe_erase_after_ms := NULL;
        NEW.operation_request_plaintext_schema := NULL;
        NEW.operation_request_plaintext_size_bytes := NULL;
        NEW.operation_request_plaintext_digest := NULL;
        NEW.operation_request_aad_digest := NULL;
        NEW.operation_request_envelope_digest := NULL;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_complete_secret_mutation_recovery() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    recovery_resolution TEXT;
BEGIN
    IF OLD.state <> 'reserved' OR NEW.state = 'reserved' THEN
        RETURN NEW;
    END IF;

    recovery_resolution := CASE
        WHEN NEW.completion_kind = 'reservation_expired'
             AND NEW.abandoned_version_id IS NULL
            THEN 'expired_without_stage'
        WHEN NEW.completion_kind = 'reservation_expired'
            THEN 'expired_with_cleanup'
        ELSE 'human_terminal'
    END;

    UPDATE secret_mutation_recovery_outbox
    SET status = 'completed',
        completed_by = CASE
            WHEN recovery_resolution = 'human_terminal' THEN NULL ELSE locked_by
        END,
        completed_claim_generation = CASE
            WHEN recovery_resolution = 'human_terminal' THEN NULL ELSE claim_generation
        END,
        completed_locked_at_ms = CASE
            WHEN recovery_resolution = 'human_terminal' THEN NULL ELSE locked_at_ms
        END,
        locked_by = NULL, locked_at_ms = NULL,
        resolution = recovery_resolution,
        completed_at_ms = NEW.confirmed_at_ms
    WHERE tenant_id = NEW.tenant_id
      AND mutation_id = NEW.mutation_id
      AND status IN ('pending', 'in_progress');

    IF NOT FOUND THEN
        RAISE EXCEPTION 'terminal secret mutation has no open recovery schedule'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_mutation_recovery_terminal_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_create_github_check_projection_outbox() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO github_check_projection_outbox (subject_id, state_updated_at_ms)
    VALUES (NEW.id, NEW.created_at_ms);
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_default_workflow_public_run_id_alias() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.public_run_id_alias IS NULL THEN
        NEW.public_run_id_alias := NEW.run_id_alias;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_activation_claim_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now BIGINT :=
        floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    claim_duration BIGINT;
    is_takeover BOOLEAN;
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
       AND NEW.activation_owner_id IS NULL
       AND NEW.activation_claimed_at_ms IS NULL
       AND NEW.activation_expires_at_ms IS NULL
       AND NEW.activation_origin_selection_id IS NULL
    THEN
        RETURN NEW;
    END IF;

    IF OLD.state IN ('pending', 'activating', 'activated', 'skipped')
       AND NEW.state = 'cancelled'
       AND NEW.activation_fence = OLD.activation_fence
       AND NEW.activation_owner_id IS NULL
       AND NEW.activation_claimed_at_ms IS NULL
       AND NEW.activation_expires_at_ms IS NULL
       AND NEW.activation_input_digest IS NOT DISTINCT FROM OLD.activation_input_digest
       AND NEW.activation_origin_selection_id IS NOT DISTINCT FROM
           OLD.activation_origin_selection_id
       AND EXISTS (
           SELECT 1
           FROM logical_workflow_concurrency_cancellations AS cancellation
           WHERE cancellation.run_id = NEW.run_id
             AND cancellation.root_invocation_id = NEW.invocation_id
             AND cancellation.cancelled_at_ms = NEW.updated_at_ms
       )
    THEN
        RETURN NEW;
    END IF;

    IF OLD.state = 'pending' AND NEW.state = 'activating' THEN
        claim_duration :=
            NEW.activation_expires_at_ms - NEW.activation_claimed_at_ms;
        IF NEW.activation_origin_selection_id IS NULL
            OR NEW.activation_fence <> OLD.activation_fence + 1
            OR NEW.activation_claimed_at_ms > database_now
            OR database_now - NEW.activation_claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
        THEN
            RAISE EXCEPTION 'initial activation authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.id, NULL
        );
    ELSIF OLD.state = 'activating' AND NEW.state = 'activating' THEN
        claim_duration :=
            NEW.activation_expires_at_ms - NEW.activation_claimed_at_ms;
        is_takeover := NEW.activation_origin_selection_id IS DISTINCT FROM
                       OLD.activation_origin_selection_id;
        IF NEW.activation_fence <> OLD.activation_fence + 1
            OR NEW.activation_origin_selection_id IS NULL
            OR NEW.updated_at_ms <> NEW.activation_claimed_at_ms
            OR (NOT is_takeover AND NEW.activation_owner_id IS DISTINCT FROM
                OLD.activation_owner_id)
            OR (is_takeover AND NEW.activation_claimed_at_ms <
                OLD.activation_expires_at_ms)
            OR (NOT is_takeover AND NEW.activation_claimed_at_ms >=
                OLD.activation_expires_at_ms)
            OR (NOT is_takeover
                AND database_now >= OLD.activation_expires_at_ms)
            OR NEW.activation_claimed_at_ms > database_now
            OR database_now - NEW.activation_claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
            OR NEW.activation_expires_at_ms <= OLD.activation_expires_at_ms
            OR NEW.activation_input_digest IS DISTINCT FROM
               OLD.activation_input_digest
        THEN
            RAISE EXCEPTION 'activation authority successor is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.id, NULL
        );
    ELSIF OLD.state = 'activating'
        AND NEW.state IN ('activated', 'skipped')
    THEN
        IF NEW.activation_fence <> OLD.activation_fence
            OR NEW.activation_origin_selection_id IS DISTINCT FROM
               OLD.activation_origin_selection_id
            OR NEW.activation_input_digest IS DISTINCT FROM
               OLD.activation_input_digest
            OR NEW.activation_owner_id IS NOT NULL
            OR NEW.activation_claimed_at_ms IS NOT NULL
            OR NEW.activation_expires_at_ms IS NOT NULL
            OR database_now < OLD.activation_claimed_at_ms
            OR database_now >= OLD.activation_expires_at_ms
        THEN
            RAISE EXCEPTION 'activation terminal authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.id, NULL
        );
    ELSIF (NEW.activation_fence, NEW.activation_owner_id,
           NEW.activation_claimed_at_ms, NEW.activation_expires_at_ms,
           NEW.activation_input_digest, NEW.activation_origin_selection_id)
          IS DISTINCT FROM
          (OLD.activation_fence, OLD.activation_owner_id,
           OLD.activation_claimed_at_ms, OLD.activation_expires_at_ms,
           OLD.activation_input_digest, OLD.activation_origin_selection_id)
    THEN
        RAISE EXCEPTION 'activation retained authority is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_claim_transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_activation_selection_receipt_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    replay_floor BIGINT;
    live_origin BOOLEAN := FALSE;
BEGIN
    SELECT replay_floor_ms INTO replay_floor
    FROM logical_workflow_work_selection_replay_horizons
    WHERE queue_name = 'activation'
    FOR UPDATE;
    SELECT EXISTS (
        SELECT 1
        FROM logical_workflow_activation_preparation_claims AS claim
        WHERE OLD.authority_kind = 'preparation'
          AND claim.logical_job_id = OLD.logical_job_id
          AND claim.origin_selection_id = OLD.selection_id
          AND claim.state = 'preparing'
        UNION ALL
        SELECT 1
        FROM logical_workflow_jobs AS job
        WHERE OLD.authority_kind = 'activation'
          AND job.id = OLD.logical_job_id
          AND job.activation_origin_selection_id = OLD.selection_id
          AND job.state = 'activating'
    ) INTO live_origin;
    IF replay_floor IS NULL OR OLD.outcome = 'selecting'
        OR OLD.expires_at_ms > replay_floor
        OR OLD.requested_at_ms >= replay_floor
        OR live_origin
    THEN
        RAISE EXCEPTION 'activation selection receipt remains inside replay authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_receipt_retained';
    END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION automata_enforce_workload_oidc_issuance_replacement() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.authority_id IS DISTINCT FROM OLD.authority_id
        OR NEW.audience_key_sha256 IS DISTINCT FROM OLD.audience_key_sha256
        OR NEW.requested_audience IS DISTINCT FROM OLD.requested_audience
        OR NEW.created_at_seconds IS DISTINCT FROM OLD.created_at_seconds
        OR NEW.generation <> OLD.generation + 1
        OR NEW.issued_at_seconds < OLD.expires_at_seconds
    THEN
        RAISE EXCEPTION 'Automata workload OIDC slot replacement is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workload_oidc_issuance_slot_replacement';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_workload_oidc_key_deadline() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.key_use IS DISTINCT FROM OLD.key_use
        OR NEW.key_id IS DISTINCT FROM OLD.key_id
        OR NEW.key_sha256 IS DISTINCT FROM OLD.key_sha256
        OR NEW.max_not_after_seconds < OLD.max_not_after_seconds
        OR NEW.updated_at_seconds < OLD.updated_at_seconds
    THEN
        RAISE EXCEPTION 'Automata workload OIDC key retention cannot regress'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workload_oidc_key_deadline_monotonic';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_github_runtime_authority_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
        OR NEW.fencing_token IS DISTINCT FROM OLD.fencing_token
        OR NEW.lease_id IS DISTINCT FROM OLD.lease_id
        OR NEW.lease_issued_at_ms IS DISTINCT FROM OLD.lease_issued_at_ms
        OR NEW.lease_expires_at_ms IS DISTINCT FROM OLD.lease_expires_at_ms
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.job_id IS DISTINCT FROM OLD.job_id
        OR NEW.runner_id IS DISTINCT FROM OLD.runner_id
        OR NEW.runner_session_id IS DISTINCT FROM OLD.runner_session_id
        OR NEW.runner_session_epoch IS DISTINCT FROM OLD.runner_session_epoch
        OR NEW.runner_generation IS DISTINCT FROM OLD.runner_generation
        OR NEW.runner_slot IS DISTINCT FROM OLD.runner_slot
        OR NEW.job_ir_schema IS DISTINCT FROM OLD.job_ir_schema
        OR NEW.job_ir_size_bytes IS DISTINCT FROM OLD.job_ir_size_bytes
        OR NEW.job_ir_digest IS DISTINCT FROM OLD.job_ir_digest
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
        OR NEW.provider_installation_id IS DISTINCT FROM OLD.provider_installation_id
        OR NEW.github_app_id IS DISTINCT FROM OLD.github_app_id
        OR NEW.github_app_client_id IS DISTINCT FROM OLD.github_app_client_id
        OR NEW.github_app_jwt_issuer_kind IS DISTINCT FROM OLD.github_app_jwt_issuer_kind
        OR NEW.github_app_jwt_issuer_value IS DISTINCT FROM OLD.github_app_jwt_issuer_value
        OR NEW.github_repository_id IS DISTINCT FROM OLD.github_repository_id
        OR NEW.github_repository_name IS DISTINCT FROM OLD.github_repository_name
        OR NEW.authority_namespace IS DISTINCT FROM OLD.authority_namespace
        OR NEW.policy_digest IS DISTINCT FROM OLD.policy_digest
        OR NEW.issuer_fingerprint IS DISTINCT FROM OLD.issuer_fingerprint
        OR NEW.configuration_fingerprint IS DISTINCT FROM OLD.configuration_fingerprint
        OR NEW.preparation_selection_id IS DISTINCT FROM OLD.preparation_selection_id
        OR NEW.preparation_selection_owner_id IS DISTINCT FROM
            OLD.preparation_selection_owner_id
        OR NEW.preparation_selection_generation IS DISTINCT FROM
            OLD.preparation_selection_generation
        OR NEW.preparation_selection_descriptor_digest IS DISTINCT FROM
            OLD.preparation_selection_descriptor_digest
        OR NEW.preparation_selection_claimed_at_ms IS DISTINCT FROM
            OLD.preparation_selection_claimed_at_ms
        OR NEW.preparation_selection_expires_at_ms IS DISTINCT FROM
            OLD.preparation_selection_expires_at_ms
        OR NEW.activation_selection_id IS DISTINCT FROM OLD.activation_selection_id
        OR NEW.activation_selection_owner_id IS DISTINCT FROM
            OLD.activation_selection_owner_id
        OR NEW.activation_selection_generation IS DISTINCT FROM
            OLD.activation_selection_generation
        OR NEW.activation_selection_input_digest IS DISTINCT FROM
            OLD.activation_selection_input_digest
        OR NEW.activation_selection_claimed_at_ms IS DISTINCT FROM
            OLD.activation_selection_claimed_at_ms
        OR NEW.activation_selection_expires_at_ms IS DISTINCT FROM
            OLD.activation_selection_expires_at_ms
        OR NEW.materialization_selection_id IS DISTINCT FROM
            OLD.materialization_selection_id
        OR NEW.materialization_selection_owner_id IS DISTINCT FROM
            OLD.materialization_selection_owner_id
        OR NEW.materialization_selection_generation IS DISTINCT FROM
            OLD.materialization_selection_generation
        OR NEW.materialization_selection_descriptor_digest IS DISTINCT FROM
            OLD.materialization_selection_descriptor_digest
        OR NEW.materialization_selection_claimed_at_ms IS DISTINCT FROM
            OLD.materialization_selection_claimed_at_ms
        OR NEW.materialization_selection_expires_at_ms IS DISTINCT FROM
            OLD.materialization_selection_expires_at_ms
        OR NEW.requested_at_ms IS DISTINCT FROM OLD.requested_at_ms
        OR NEW.request_deadline_at_ms IS DISTINCT FROM OLD.request_deadline_at_ms
        OR NEW.conservative_expiry_at_ms IS DISTINCT FROM OLD.conservative_expiry_at_ms
    THEN
        RAISE EXCEPTION 'GitHub runtime authority immutable identity cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_identity_immutable';
    END IF;

    IF NEW.state_updated_at_ms < OLD.state_updated_at_ms THEN
        RAISE EXCEPTION 'GitHub runtime authority state time cannot regress'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_time_regression';
    END IF;

    IF OLD.safe_erase_after_ms IS NOT NULL AND (
        NEW.provider_expires_at_ms IS DISTINCT FROM OLD.provider_expires_at_ms
        OR NEW.safe_erase_after_ms IS DISTINCT FROM OLD.safe_erase_after_ms
        OR NEW.commit_disposition IS DISTINCT FROM OLD.commit_disposition
        OR NEW.plaintext_schema IS DISTINCT FROM OLD.plaintext_schema
        OR NEW.plaintext_size_bytes IS DISTINCT FROM OLD.plaintext_size_bytes
        OR NEW.plaintext_digest IS DISTINCT FROM OLD.plaintext_digest
        OR NEW.aad_digest IS DISTINCT FROM OLD.aad_digest
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority protected metadata cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_protected_metadata_immutable';
    END IF;

    IF NOT (
            OLD.state IN ('claimed', 'mint_retry_pending')
            AND NEW.state = 'claimed'
        ) AND (
            NEW.mint_attempt_count IS DISTINCT FROM OLD.mint_attempt_count
            OR NEW.mint_claim_fence IS DISTINCT FROM OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.mint_claimed_at_ms IS DISTINCT FROM OLD.mint_claimed_at_ms
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority mint claim history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_history_immutable';
    END IF;

    IF (
        NEW.mint_started_at_ms IS DISTINCT FROM OLD.mint_started_at_ms
        OR NEW.mint_provider_request_millis IS DISTINCT FROM
            OLD.mint_provider_request_millis
    )
        AND NOT (
            (
                OLD.state = 'claimed'
                AND NEW.state = 'minting'
                AND NEW.mint_started_at_ms IS NOT NULL
                AND NEW.mint_provider_request_millis BETWEEN 1 AND 120000
            )
            OR (
                OLD.state = 'mint_retry_pending'
                AND NEW.state = 'claimed'
                AND NEW.mint_started_at_ms IS NULL
                AND NEW.mint_provider_request_millis IS NULL
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority mint boundary history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_boundary_immutable';
    END IF;

    IF (
            NEW.next_mint_at_ms IS DISTINCT FROM OLD.next_mint_at_ms
            AND NOT (
                (OLD.state = 'minting' AND NEW.state = 'mint_retry_pending')
                OR (
                    OLD.state = 'mint_retry_pending'
                    AND NEW.state IN ('claimed', 'rejected')
                )
            )
        ) OR (
            NEW.last_mint_rejection_kind
                IS DISTINCT FROM OLD.last_mint_rejection_kind
            AND NOT (
                OLD.state = 'minting'
                AND NEW.state IN ('mint_retry_pending', 'rejected')
            )
        ) OR (
            NEW.rejected_at_ms IS DISTINCT FROM OLD.rejected_at_ms
            AND NOT (
                OLD.state IN ('minting', 'mint_retry_pending')
                AND NEW.state = 'rejected'
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority rejection history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_rejection_history_immutable';
    END IF;

    IF (
            NEW.indeterminate_at_ms IS DISTINCT FROM OLD.indeterminate_at_ms
            AND NOT (OLD.state = 'minting' AND NEW.state = 'indeterminate')
        ) OR (
            NEW.ready_at_ms IS DISTINCT FROM OLD.ready_at_ms
            AND NOT (OLD.state = 'minting' AND NEW.state = 'ready')
        ) OR (
            NEW.revoke_pending_at_ms IS DISTINCT FROM OLD.revoke_pending_at_ms
            AND NOT (
                OLD.state IN ('minting', 'indeterminate') AND (
                    NEW.state = 'revoke_pending'
                    OR NEW.state = 'revoked'
                    AND NEW.terminal_reason IN (
                        'provider_authority_expired',
                        'conservative_authority_expired'
                    )
                )
                OR OLD.state = 'ready' AND NEW.state = 'revoke_pending'
            )
        ) OR (
            (
                NEW.quarantine_at_ms IS DISTINCT FROM OLD.quarantine_at_ms
                OR NEW.quarantine_kind IS DISTINCT FROM OLD.quarantine_kind
            )
            AND NOT (
                OLD.state IN ('ready', 'revoke_pending')
                AND (
                    NEW.state = 'quarantined'
                    OR NEW.state = 'revoked'
                    AND NEW.terminal_reason = 'quarantined_authority_expired'
                )
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority lifecycle history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_lifecycle_history_immutable';
    END IF;

    IF NOT (OLD.state = 'revoke_pending' AND NEW.state = 'revoke_pending') AND (
        NEW.revoke_attempt_count IS DISTINCT FROM OLD.revoke_attempt_count
        OR NEW.revoke_claim_fence IS DISTINCT FROM OLD.revoke_claim_fence
        OR NEW.last_revoke_failure_kind IS DISTINCT FROM OLD.last_revoke_failure_kind
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority revocation history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_revoke_history_immutable';
    END IF;

    IF OLD.envelope_schema IS NOT NULL AND NEW.state <> 'revoked' AND (
        NEW.envelope_schema IS DISTINCT FROM OLD.envelope_schema
        OR NEW.wrapping_key_id IS DISTINCT FROM OLD.wrapping_key_id
        OR NEW.wrapped_data_key IS DISTINCT FROM OLD.wrapped_data_key
        OR NEW.nonce IS DISTINCT FROM OLD.nonce
        OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority envelope cannot change before erasure'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_envelope_immutable';
    END IF;

    IF NEW.operation_request_kind IS NOT NULL
        AND NOT automata_github_runtime_authority_same_non_operation_state(
            OLD, NEW
        )
        AND NOT (
            OLD.state IN ('minting', 'indeterminate')
            AND NEW.state IN ('ready', 'revoke_pending', 'revoked')
            AND OLD.safe_erase_after_ms IS NULL
            AND NEW.safe_erase_after_ms IS NOT NULL
            OR OLD.state IN ('ready', 'revoke_pending')
            AND NEW.state IN ('quarantined', 'revoked')
            AND NEW.quarantine_at_ms IS DISTINCT FROM OLD.quarantine_at_ms
            OR OLD.state = 'revoke_pending'
            AND OLD.revoke_claim_owner_id IS NOT NULL
            AND (
                NEW.state = 'revoked'
                AND NEW.terminal_reason = 'provider_revocation_confirmed'
                OR NEW.state = 'revoke_pending'
                AND NEW.revoke_claim_owner_id IS NULL
                AND NEW.last_revoke_failure_kind <> 'claim_budget_exhausted'
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub operation request may only describe its exact lifecycle edge'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT =
                      'github_runtime_authority_operation_observation_exact';
    END IF;

    IF OLD.state = NEW.state
        AND NEW.operation_request_kind IS NOT NULL
        AND automata_github_runtime_authority_same_non_operation_state(
            OLD, NEW
        )
    THEN
        NULL;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'claimed' THEN
        IF NEW.mint_attempt_count <> OLD.mint_attempt_count + 1
            OR NEW.mint_claim_fence <> OLD.mint_claim_fence + 1
            OR NEW.mint_claimed_at_ms < OLD.mint_claim_expires_at_ms
            OR NOT automata_github_runtime_authority_is_current(
                NEW, NEW.mint_claimed_at_ms
            )
        THEN
            RAISE EXCEPTION 'expired GitHub authority mint claim takeover is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_reclaim';
        END IF;
    ELSIF OLD.state = 'mint_retry_pending' AND NEW.state = 'claimed' THEN
        IF NEW.mint_attempt_count <> OLD.mint_attempt_count + 1
            OR NEW.mint_claim_fence <> OLD.mint_claim_fence + 1
            OR NEW.mint_claimed_at_ms < OLD.next_mint_at_ms
            OR NEW.last_mint_rejection_kind IS DISTINCT FROM OLD.last_mint_rejection_kind
            OR NOT automata_github_runtime_authority_is_current(
                NEW, NEW.mint_claimed_at_ms
            )
        THEN
            RAISE EXCEPTION 'definitive no-token GitHub mint retry claim is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_retry_claim';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'minting' THEN
        IF NEW.mint_attempt_count <> OLD.mint_attempt_count
            OR NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.mint_claimed_at_ms <> OLD.mint_claimed_at_ms
            OR NEW.mint_started_at_ms < OLD.mint_claimed_at_ms
            OR NEW.mint_started_at_ms >= OLD.mint_claim_expires_at_ms
            OR NEW.mint_started_at_ms::NUMERIC
                + NEW.mint_provider_request_millis::NUMERIC
                > OLD.mint_claim_expires_at_ms::NUMERIC
            OR NEW.mint_started_at_ms::NUMERIC
                + NEW.mint_provider_request_millis::NUMERIC
                > NEW.request_deadline_at_ms::NUMERIC
            OR NOT automata_github_runtime_authority_is_current(
                NEW, NEW.mint_started_at_ms
            )
        THEN
            RAISE EXCEPTION 'GitHub authority mint must begin under the exact live claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_begin';
        END IF;
    ELSIF OLD.state = 'minting' AND NEW.state = 'mint_retry_pending' THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.next_mint_at_ms <= NEW.state_updated_at_ms
            OR NEW.next_mint_at_ms >= NEW.request_deadline_at_ms
            OR NEW.last_mint_rejection_kind IS NULL
            OR NOT automata_github_runtime_authority_is_current(
                NEW, NEW.state_updated_at_ms
            )
        THEN
            RAISE EXCEPTION 'GitHub no-token mint retry scheduling is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_retry_schedule';
        END IF;
    ELSIF OLD.state IN ('minting', 'mint_retry_pending') AND NEW.state = 'rejected' THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.last_mint_rejection_kind IS NULL
            OR NEW.rejected_at_ms <> NEW.state_updated_at_ms
            OR NEW.terminal_reason NOT IN (
                'provider_mint_rejected', 'provider_mint_retry_expired'
            )
            OR (
                OLD.state = 'mint_retry_pending'
                AND NEW.terminal_reason <> 'provider_mint_retry_expired'
            )
        THEN
            RAISE EXCEPTION 'definitive GitHub mint rejection is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_rejection';
        END IF;
    ELSIF OLD.state = 'minting' AND NEW.state = 'indeterminate' THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.indeterminate_at_ms < OLD.mint_started_at_ms
            OR NEW.indeterminate_at_ms >= OLD.conservative_expiry_at_ms
        THEN
            RAISE EXCEPTION 'ambiguous GitHub mint must retain its irreversible fence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_indeterminate';
        END IF;
    ELSIF OLD.state IN ('minting', 'indeterminate')
          AND NEW.state IN ('ready', 'revoke_pending') THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.safe_erase_after_ms IS NULL
            OR NEW.envelope_schema IS NULL
            OR NEW.state_updated_at_ms >= NEW.safe_erase_after_ms
            OR (
                NEW.state = 'ready' AND (
                    OLD.state <> 'minting'
                    OR NEW.commit_disposition <> 'deliverable'
                    OR NEW.provider_expires_at_ms IS NULL
                    OR NEW.provider_expires_at_ms::NUMERIC
                        <= NEW.state_updated_at_ms::NUMERIC + 60000
                    OR NOT automata_github_runtime_authority_is_current(
                        NEW, NEW.state_updated_at_ms
                    )
                )
            )
            OR (
                NEW.state = 'revoke_pending' AND (
                    NEW.ready_at_ms IS NOT NULL
                    OR NEW.revoke_pending_at_ms <> NEW.state_updated_at_ms
                    OR NEW.next_revoke_at_ms <> NEW.state_updated_at_ms
                )
            )
        THEN
            RAISE EXCEPTION 'minted GitHub authority finalization is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_finalize';
        END IF;
    ELSIF OLD.state = 'ready' AND NEW.state = 'revoke_pending' THEN
        IF NEW.revoke_pending_at_ms < OLD.ready_at_ms
            OR NEW.revoke_pending_at_ms >= OLD.safe_erase_after_ms
            OR NEW.revoke_pending_at_ms <> NEW.state_updated_at_ms
            OR NEW.next_revoke_at_ms <> NEW.state_updated_at_ms
        THEN
            RAISE EXCEPTION 'ready GitHub authority revocation transition is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_revoke_pending';
        END IF;
    ELSIF OLD.state IN ('ready', 'revoke_pending') AND NEW.state = 'quarantined' THEN
        IF NEW.quarantine_at_ms <> NEW.state_updated_at_ms
            OR NEW.quarantine_kind IS NULL
            OR NEW.state_updated_at_ms >= NEW.safe_erase_after_ms
            OR NEW.aad_digest IS DISTINCT FROM OLD.aad_digest
        THEN
            RAISE EXCEPTION 'GitHub authority quarantine observation is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_quarantine';
        END IF;
    ELSIF OLD.state = 'revoke_pending' AND NEW.state = 'revoke_pending' THEN
        IF OLD.revoke_claim_owner_id IS NULL
            AND NEW.revoke_claim_owner_id IS NOT NULL THEN
            IF NEW.revoke_attempt_count <> OLD.revoke_attempt_count + 1
                OR NEW.revoke_claim_fence <> OLD.revoke_claim_fence + 1
                OR NEW.revoke_claimed_at_ms < OLD.next_revoke_at_ms
                OR NEW.revoke_claimed_at_ms <> NEW.state_updated_at_ms
                OR NEW.revoke_claim_expires_at_ms >= NEW.safe_erase_after_ms
                OR NEW.last_revoke_failure_kind
                    IS DISTINCT FROM OLD.last_revoke_failure_kind
            THEN
                RAISE EXCEPTION 'GitHub authority revoke claim is invalid'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_claim';
            END IF;
        ELSIF OLD.revoke_claim_owner_id IS NOT NULL
            AND NEW.revoke_claim_owner_id IS NOT NULL THEN
            IF NEW.revoke_attempt_count <> OLD.revoke_attempt_count + 1
                OR NEW.revoke_claim_fence <> OLD.revoke_claim_fence + 1
                OR NEW.revoke_claimed_at_ms < OLD.revoke_claim_expires_at_ms
                OR NEW.revoke_claimed_at_ms <> NEW.state_updated_at_ms
                OR NEW.revoke_claim_expires_at_ms >= NEW.safe_erase_after_ms
                OR NEW.last_revoke_failure_kind
                    IS DISTINCT FROM OLD.last_revoke_failure_kind
            THEN
                RAISE EXCEPTION 'expired GitHub authority revoke claim takeover is invalid'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_reclaim';
            END IF;
        ELSIF OLD.revoke_claim_owner_id IS NOT NULL
            AND NEW.revoke_claim_owner_id IS NULL THEN
            IF NOT (
                NEW.revoke_attempt_count = OLD.revoke_attempt_count
                AND NEW.revoke_claim_fence = OLD.revoke_claim_fence
                AND NEW.last_revoke_failure_kind IS NOT NULL
                AND NEW.state_updated_at_ms >= OLD.revoke_claimed_at_ms
                AND (
                    (
                        NEW.state_updated_at_ms < OLD.revoke_claim_expires_at_ms
                        AND (
                            (
                                NEW.next_revoke_at_ms > NEW.state_updated_at_ms
                                AND NEW.next_revoke_at_ms < NEW.safe_erase_after_ms
                            ) OR NEW.next_revoke_at_ms = NEW.safe_erase_after_ms
                        )
                    ) OR (
                        NEW.state_updated_at_ms >= OLD.revoke_claim_expires_at_ms
                        AND NEW.state_updated_at_ms < NEW.safe_erase_after_ms
                        AND NEW.next_revoke_at_ms = NEW.safe_erase_after_ms
                        AND NEW.last_revoke_failure_kind = 'claim_budget_exhausted'
                        AND (
                            OLD.revoke_attempt_count = 64
                            OR OLD.revoke_claim_fence = 9223372036854775807
                        )
                    )
                )
            )
            THEN
                RAISE EXCEPTION 'GitHub authority revoke retry/defer is invalid'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_retry';
            END IF;
        ELSE
            RAISE EXCEPTION 'GitHub authority revoke self-transition is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_revoke_self_transition';
        END IF;
    ELSIF OLD.state IN (
              'claimed', 'minting', 'indeterminate', 'ready',
              'revoke_pending', 'quarantined'
          ) AND NEW.state = 'revoked' THEN
        IF NEW.envelope_schema IS NOT NULL
            OR (
                NEW.terminal_reason = 'provider_revocation_confirmed' AND (
                    OLD.state <> 'revoke_pending'
                    OR OLD.revoke_claim_owner_id IS NULL
                    OR NEW.revoked_at_ms < OLD.revoke_claimed_at_ms
                    OR NEW.revoked_at_ms >= OLD.revoke_claim_expires_at_ms
                )
            )
            OR (
                NEW.terminal_reason = 'provider_authority_expired' AND NOT (
                    OLD.state IN ('ready', 'revoke_pending')
                    AND OLD.provider_expires_at_ms IS NOT NULL
                    AND NEW.revoked_at_ms >= OLD.safe_erase_after_ms
                    OR OLD.state IN ('minting', 'indeterminate')
                    AND NEW.provider_expires_at_ms IS NOT NULL
                    AND NEW.revoke_pending_at_ms = NEW.state_updated_at_ms
                    AND NEW.revoked_at_ms >= NEW.safe_erase_after_ms
                )
            )
            OR (
                NEW.terminal_reason = 'conservative_authority_expired' AND NOT (
                    OLD.state IN ('ready', 'revoke_pending')
                    AND OLD.provider_expires_at_ms IS NULL
                    AND NEW.revoked_at_ms >= OLD.safe_erase_after_ms
                    OR OLD.state IN ('minting', 'indeterminate')
                    AND NEW.provider_expires_at_ms IS NULL
                    AND NEW.revoke_pending_at_ms = NEW.state_updated_at_ms
                    AND NEW.revoked_at_ms >= NEW.safe_erase_after_ms
                )
            )
            OR (
                NEW.terminal_reason = 'quarantined_authority_expired' AND NOT (
                    OLD.state = 'quarantined'
                    AND NEW.revoked_at_ms >= OLD.safe_erase_after_ms
                    OR OLD.state IN ('ready', 'revoke_pending')
                    AND NEW.quarantine_at_ms = NEW.state_updated_at_ms
                    AND NEW.quarantine_kind IS NOT NULL
                    AND NEW.aad_digest IS NOT DISTINCT FROM OLD.aad_digest
                    AND NEW.revoked_at_ms >= OLD.safe_erase_after_ms
                )
            )
            OR (
                NEW.terminal_reason = 'indeterminate_authority_expired' AND (
                    OLD.state NOT IN ('minting', 'indeterminate')
                    OR NEW.revoked_at_ms < OLD.conservative_expiry_at_ms
                )
            )
            OR (
                NEW.terminal_reason = 'superseded_before_mint' AND (
                    OLD.state <> 'claimed'
                    OR automata_github_runtime_authority_is_current(
                        OLD, NEW.revoked_at_ms
                    )
                )
            )
            OR (
                NEW.terminal_reason = 'request_expired_before_mint' AND (
                    OLD.state <> 'claimed'
                    OR NEW.revoked_at_ms < OLD.request_deadline_at_ms
                )
            )
        THEN
            RAISE EXCEPTION 'GitHub authority terminal erasure is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_terminal_erasure';
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub runtime authority lifecycle transition is not permitted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_lifecycle_transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_human_login_transaction_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.purpose IS DISTINCT FROM OLD.purpose
        OR NEW.flow_kind IS DISTINCT FROM OLD.flow_kind
        OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
        OR NEW.return_path IS DISTINCT FROM OLD.return_path
        OR NEW.state_hash IS DISTINCT FROM OLD.state_hash
        OR NEW.state_hash_key_id IS DISTINCT FROM OLD.state_hash_key_id
        OR NEW.browser_binding_hash IS DISTINCT FROM OLD.browser_binding_hash
        OR NEW.browser_binding_hash_key_id IS DISTINCT FROM OLD.browser_binding_hash_key_id
        OR NEW.poll_proof_hash IS DISTINCT FROM OLD.poll_proof_hash
        OR NEW.poll_proof_hash_key_id IS DISTINCT FROM OLD.poll_proof_hash_key_id
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
    THEN
        RAISE EXCEPTION 'login transaction identity is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_login_transactions_identity_immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1
        OR NEW.updated_at_ms < OLD.updated_at_ms
        OR NEW.poll_attempts < OLD.poll_attempts
        OR (
            OLD.consumed_at_ms IS NOT NULL
            AND NEW.consumed_at_ms IS DISTINCT FROM OLD.consumed_at_ms
        )
    THEN
        RAISE EXCEPTION 'login transaction updates require the next monotonic revision'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_login_transactions_update_cas';
    END IF;
    IF NOT (
        (OLD.status = 'pending' AND NEW.status IN ('pending', 'consumed', 'denied', 'expired'))
        OR (OLD.status = 'consumed' AND NEW.status = 'succeeded')
    ) THEN
        RAISE EXCEPTION 'login transaction status transition is not permitted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_login_transactions_status_transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_enforce_installation_state_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.singleton IS DISTINCT FROM OLD.singleton
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'installation singleton identity is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_auth_installation_state_identity_immutable';
    END IF;
    IF OLD.state = 'configured' THEN
        RAISE EXCEPTION 'configured installation state is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_auth_installation_state_configured_immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1 OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'installation state updates require the next CAS revision'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_auth_installation_state_update_cas';
    END IF;
    IF OLD.state = 'unconfigured' THEN
        IF NEW.state <> 'pending' OR NEW.setup_transaction_id IS NOT NULL THEN
            RAISE EXCEPTION 'installation must be armed before login binding'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'human_auth_installation_state_transition';
        END IF;
    ELSIF OLD.state = 'pending' AND NEW.state = 'pending' THEN
        IF OLD.setup_transaction_id IS NULL
            AND NEW.setup_transaction_id IS NOT NULL
        THEN
            IF NEW.bootstrap_token_hash IS DISTINCT FROM OLD.bootstrap_token_hash
                OR NEW.bootstrap_hash_key_id IS DISTINCT FROM OLD.bootstrap_hash_key_id
                OR NEW.expected_provider_id IS DISTINCT FROM OLD.expected_provider_id
                OR NEW.expected_provider_subject IS DISTINCT FROM OLD.expected_provider_subject
                OR NEW.challenge_expires_at_ms IS DISTINCT FROM OLD.challenge_expires_at_ms
                OR NEW.target_tenant_id IS DISTINCT FROM OLD.target_tenant_id
                OR NEW.target_tenant_display_name IS DISTINCT FROM OLD.target_tenant_display_name
                OR NOT EXISTS (
                    SELECT 1
                    FROM human_login_transactions AS login
                    WHERE login.id = NEW.setup_transaction_id
                      AND login.purpose = 'installation_setup'
                      AND login.tenant_id IS NULL
                      AND login.provider_id = OLD.expected_provider_id
                      AND login.status = 'pending'
                      AND login.created_at_ms >= OLD.updated_at_ms
                      AND login.created_at_ms <= NEW.updated_at_ms
                      AND login.expires_at_ms > NEW.updated_at_ms
                )
            THEN
                RAISE EXCEPTION 'login binding cannot rewrite the armed setup'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'human_auth_installation_state_bind_exact';
            END IF;
        ELSIF OLD.challenge_expires_at_ms <= NEW.updated_at_ms
            AND NEW.setup_transaction_id IS NULL
        THEN
            NULL;
        ELSE
            RAISE EXCEPTION 'pending setup may only bind once or be rearmed after expiry'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'human_auth_installation_state_pending_exact';
        END IF;
    ELSIF OLD.state = 'pending' AND NEW.state = 'configured' THEN
        IF OLD.setup_transaction_id IS NULL
            OR OLD.challenge_expires_at_ms <= NEW.updated_at_ms
            OR NEW.expected_provider_id IS DISTINCT FROM OLD.expected_provider_id
            OR NEW.expected_provider_subject IS DISTINCT FROM OLD.expected_provider_subject
            OR NEW.target_tenant_id IS DISTINCT FROM OLD.target_tenant_id
            OR NEW.target_tenant_display_name IS DISTINCT FROM OLD.target_tenant_display_name
            OR NEW.setup_transaction_id IS DISTINCT FROM OLD.setup_transaction_id
            OR NOT EXISTS (
                SELECT 1
                FROM human_login_transactions AS login
                WHERE login.id = OLD.setup_transaction_id
                  AND login.purpose = 'installation_setup'
                  AND login.tenant_id IS NULL
                  AND login.provider_id = OLD.expected_provider_id
                  AND login.status = 'succeeded'
                  AND login.completed_principal_id = NEW.configured_principal_id
            )
        THEN
            RAISE EXCEPTION 'installation completion is not bound to a succeeded setup login'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'human_auth_installation_state_completion_exact';
        END IF;
    ELSE
        RAISE EXCEPTION 'installation state transition is not permitted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_auth_installation_state_transition';
    END IF;
    RETURN NEW;
END;
$$;
