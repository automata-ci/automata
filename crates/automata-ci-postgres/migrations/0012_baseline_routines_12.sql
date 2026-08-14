-- Frozen greenfield baseline. Add a new migration instead of editing this stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_secret_version_mutation_delete_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'secret version mutation receipts are append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_version_mutations_append_only';
END;
$$;

CREATE FUNCTION automata_secret_version_mutation_insert_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    secret_row secrets%ROWTYPE;
    predecessor_lifecycle TEXT;
    predecessor_receipt_count BIGINT;
BEGIN
    IF NEW.state <> 'reserved' OR NEW.revision <> 1 THEN
        RAISE EXCEPTION 'secret version mutations must begin reserved at revision one'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_initial_state';
    END IF;

    SELECT * INTO secret_row
    FROM secrets
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id
    FOR UPDATE;
    IF NOT FOUND
       OR secret_row.scope_kind <> NEW.scope_kind
       OR secret_row.repository_id IS DISTINCT FROM NEW.repository_id
       OR secret_row.environment_id IS DISTINCT FROM NEW.environment_id
       OR secret_row.canonical_name <> NEW.canonical_name
       OR secret_row.provider_id <> NEW.provider_id THEN
        RAISE EXCEPTION 'secret version mutation descriptor is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_descriptor_exact';
    END IF;

    IF NEW.mutation_kind = 'create' THEN
        IF secret_row.status <> 'provisioning'
           OR secret_row.revision <> 1
           OR secret_row.current_version_id IS NOT NULL
           OR secret_row.current_version_number IS NOT NULL THEN
            RAISE EXCEPTION 'secret creation mutation does not name a fresh descriptor'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_create_head';
        END IF;
    ELSE
        IF secret_row.status <> 'active'
           OR secret_row.revision <> NEW.expected_secret_revision
           OR secret_row.revision <> NEW.reserved_secret_revision
           OR secret_row.current_version_id IS DISTINCT FROM NEW.expected_predecessor_version_id
           OR secret_row.current_version_number IS DISTINCT FROM NEW.expected_predecessor_version_number THEN
            RAISE EXCEPTION 'secret replacement mutation predecessor is not current'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_replace_head';
        END IF;

        SELECT status INTO predecessor_lifecycle
        FROM secret_version_lifecycle
        WHERE tenant_id = NEW.tenant_id
          AND secret_version_id = NEW.expected_predecessor_version_id
          AND secret_id = NEW.secret_id
          AND version_number = NEW.expected_predecessor_version_number
          AND provider_id = NEW.provider_id
        FOR SHARE;

        SELECT count(*) INTO predecessor_receipt_count
        FROM secret_version_mutations
        WHERE tenant_id = NEW.tenant_id
          AND secret_id = NEW.secret_id
          AND provider_id = NEW.provider_id
          AND state = 'confirmed'
          AND completion_kind = 'builtin_created'
          AND committed_version_id = NEW.expected_predecessor_version_id
          AND committed_version_number = NEW.expected_predecessor_version_number
          AND confirmed_secret_revision = reserved_secret_revision + 1;

        IF predecessor_lifecycle IS DISTINCT FROM 'active'
           OR predecessor_receipt_count <> 1 THEN
            RAISE EXCEPTION 'secret replacement predecessor is not confirmed and active'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_predecessor_confirmed';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_secret_version_mutation_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    secret_row secrets%ROWTYPE;
    winner_row secret_versions%ROWTYPE;
    winner_lifecycle secret_version_lifecycle%ROWTYPE;
    builtin_head_count BIGINT;
    external_reference_count BIGINT;
    confirmer_principal UUID;
    confirmer_revision BIGINT;
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.mutation_id IS DISTINCT FROM OLD.mutation_id
       OR NEW.secret_id IS DISTINCT FROM OLD.secret_id
       OR NEW.scope_kind IS DISTINCT FROM OLD.scope_kind
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
       OR NEW.canonical_name IS DISTINCT FROM OLD.canonical_name
       OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
       OR NEW.requested_provider_id IS DISTINCT FROM OLD.requested_provider_id
       OR NEW.mutation_kind IS DISTINCT FROM OLD.mutation_kind
       OR NEW.expected_secret_revision IS DISTINCT FROM OLD.expected_secret_revision
       OR NEW.reserved_secret_revision IS DISTINCT FROM OLD.reserved_secret_revision
       OR NEW.reserved_version_number IS DISTINCT FROM OLD.reserved_version_number
       OR NEW.confirmation_deadline_ms IS DISTINCT FROM OLD.confirmation_deadline_ms
       OR NEW.expected_predecessor_version_id IS DISTINCT FROM OLD.expected_predecessor_version_id
       OR NEW.expected_predecessor_version_number IS DISTINCT FROM OLD.expected_predecessor_version_number
       OR NEW.provider_create_request_id IS DISTINCT FROM OLD.provider_create_request_id
       OR NEW.reserved_by_principal_id IS DISTINCT FROM OLD.reserved_by_principal_id
       OR NEW.reserved_by_session_id IS DISTINCT FROM OLD.reserved_by_session_id
       OR NEW.reserved_authorization_revision IS DISTINCT FROM OLD.reserved_authorization_revision
       OR NEW.reserved_at_ms IS DISTINCT FROM OLD.reserved_at_ms THEN
        RAISE EXCEPTION 'secret version mutation intent is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_intent_immutable';
    END IF;

    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'secret version mutation updates require exact CAS'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_revision_cas';
    END IF;

    IF NOT (
        (OLD.state = 'reserved' AND NEW.state IN ('confirmed', 'cancelled'))
        OR (OLD.state = 'confirmed' AND NEW.state = 'superseded')
    ) THEN
        RAISE EXCEPTION 'invalid secret version mutation transition'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_transition';
    END IF;

    IF OLD.state = 'confirmed' AND (
        NEW.completion_kind IS DISTINCT FROM OLD.completion_kind
        OR NEW.committed_version_id IS DISTINCT FROM OLD.committed_version_id
        OR NEW.committed_version_number IS DISTINCT FROM OLD.committed_version_number
        OR NEW.confirmed_secret_revision IS DISTINCT FROM OLD.confirmed_secret_revision
        OR NEW.confirmed_by_principal_id IS DISTINCT FROM OLD.confirmed_by_principal_id
        OR NEW.confirmed_by_session_id IS DISTINCT FROM OLD.confirmed_by_session_id
        OR NEW.confirmed_authorization_revision IS DISTINCT FROM OLD.confirmed_authorization_revision
        OR NEW.confirmed_at_ms IS DISTINCT FROM OLD.confirmed_at_ms
        OR NEW.terminal_actor_kind IS DISTINCT FROM OLD.terminal_actor_kind
        OR NEW.expiration_authority IS DISTINCT FROM OLD.expiration_authority
        OR NEW.abandoned_version_id IS DISTINCT FROM OLD.abandoned_version_id
        OR NEW.abandoned_version_number IS DISTINCT FROM OLD.abandoned_version_number
    ) THEN
        RAISE EXCEPTION 'confirmed secret version receipt is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_receipt_immutable';
    END IF;

    IF OLD.state = 'reserved' AND NEW.terminal_actor_kind = 'human' THEN
        SELECT principal_id, authorization_revision
        INTO confirmer_principal, confirmer_revision
        FROM human_sessions
        WHERE tenant_id = NEW.tenant_id
          AND id = NEW.confirmed_by_session_id
        FOR SHARE;
        IF confirmer_principal IS DISTINCT FROM NEW.confirmed_by_principal_id
           OR confirmer_revision IS DISTINCT FROM NEW.confirmed_authorization_revision THEN
            RAISE EXCEPTION 'secret mutation confirmer evidence is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_confirmer_exact';
        END IF;
    END IF;

    SELECT * INTO secret_row
    FROM secrets
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id
    FOR UPDATE;

    IF secret_row.id IS NULL
       OR secret_row.scope_kind <> NEW.scope_kind
       OR secret_row.repository_id IS DISTINCT FROM NEW.repository_id
       OR secret_row.environment_id IS DISTINCT FROM NEW.environment_id
       OR secret_row.canonical_name <> NEW.canonical_name
       OR secret_row.provider_id <> NEW.provider_id THEN
        RAISE EXCEPTION 'secret version mutation lost its exact descriptor'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_descriptor_exact';
    END IF;

    IF NEW.completion_kind = 'builtin_created' THEN
        IF NEW.provider_id <> 'builtin'
           OR NEW.committed_version_id IS NULL
           OR NEW.committed_version_id =
              '00000000-0000-0000-0000-000000000000'::UUID THEN
            RAISE EXCEPTION 'built-in mutation receipt has no exact winner'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_winner_exact';
        END IF;

        SELECT * INTO winner_row
        FROM secret_versions
        WHERE tenant_id = NEW.tenant_id
          AND provider_id = NEW.provider_id
          AND create_request_id = NEW.provider_create_request_id
        FOR SHARE;
        SELECT * INTO winner_lifecycle
        FROM secret_version_lifecycle
        WHERE tenant_id = NEW.tenant_id
          AND secret_version_id = NEW.committed_version_id
        FOR SHARE;

        SELECT count(*) INTO builtin_head_count
        FROM secret_version_envelope_heads AS head
        JOIN secret_version_envelopes AS envelope
          ON envelope.tenant_id = head.tenant_id
         AND envelope.secret_version_id = head.secret_version_id
         AND envelope.envelope_generation = head.envelope_generation
        WHERE head.tenant_id = NEW.tenant_id
          AND head.secret_version_id = NEW.committed_version_id;

        SELECT
            (SELECT count(*) FROM secret_provider_locator_envelopes
             WHERE tenant_id = NEW.tenant_id AND secret_id = NEW.secret_id)
          + (SELECT count(*) FROM secret_provider_locator_envelope_heads
             WHERE tenant_id = NEW.tenant_id AND secret_id = NEW.secret_id)
          + (SELECT count(*) FROM secret_provider_version_envelopes
             WHERE tenant_id = NEW.tenant_id
               AND secret_version_id = NEW.committed_version_id)
          + (SELECT count(*) FROM secret_provider_version_envelope_heads
             WHERE tenant_id = NEW.tenant_id
               AND secret_version_id = NEW.committed_version_id)
        INTO external_reference_count;

        IF winner_row.id IS NULL
           OR winner_row.id IS DISTINCT FROM NEW.committed_version_id
           OR winner_row.secret_id <> NEW.secret_id
           OR winner_row.version_number IS DISTINCT FROM NEW.reserved_version_number
           OR NEW.committed_version_number IS DISTINCT FROM NEW.reserved_version_number
           OR winner_row.storage_kind <> 'built_in_ciphertext'
           OR winner_lifecycle.secret_version_id IS NULL
           OR winner_lifecycle.mutation_id IS DISTINCT FROM NEW.mutation_id
           OR builtin_head_count <> 1
           OR external_reference_count <> 0 THEN
            RAISE EXCEPTION 'secret version mutation winner is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_winner_exact';
        END IF;

        IF NEW.mutation_kind = 'create' THEN
            IF winner_row.version_number <> 1 THEN
                RAISE EXCEPTION 'secret creation winner has a predecessor'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_winner_predecessor';
            END IF;
        ELSIF winner_row.version_number <= NEW.expected_predecessor_version_number THEN
            RAISE EXCEPTION 'secret replacement winner has the wrong predecessor'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_winner_predecessor';
        END IF;

        IF NEW.state = 'confirmed' THEN
            IF secret_row.status <> 'active'
               OR secret_row.current_version_id IS DISTINCT FROM winner_row.id
               OR secret_row.current_version_number IS DISTINCT FROM winner_row.version_number
               OR secret_row.revision <> NEW.reserved_secret_revision + 1
               OR NEW.confirmed_secret_revision <> NEW.reserved_secret_revision + 1
               OR winner_lifecycle.status <> 'active' THEN
                RAISE EXCEPTION 'confirmed mutation winner is not current'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_winner_head';
            END IF;
        ELSIF NEW.terminal_reason = 'applied_then_superseded' THEN
            IF secret_row.status NOT IN ('active', 'disabled')
               OR secret_row.current_version_number <= winner_row.version_number
               OR winner_lifecycle.status <> 'superseded' THEN
                RAISE EXCEPTION 'superseded mutation winner has the wrong head'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_winner_head';
            END IF;
        ELSIF NEW.terminal_reason = 'applied_then_deleted' THEN
            IF secret_row.status <> 'deleted'
               OR winner_lifecycle.status NOT IN (
                    'active', 'superseded', 'disabled',
                    'destroy_pending', 'destroyed'
               ) THEN
                RAISE EXCEPTION 'deleted mutation winner has the wrong lifecycle'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_winner_head';
            END IF;
        END IF;
    ELSIF NEW.completion_kind = 'cas_lost' THEN
        IF EXISTS (
            SELECT 1 FROM secret_versions
            WHERE tenant_id = NEW.tenant_id
              AND provider_id = NEW.provider_id
              AND create_request_id = NEW.provider_create_request_id
        ) OR secret_row.status = 'deleted' OR NOT (
            (NEW.mutation_kind = 'create' AND (
                secret_row.status <> 'provisioning'
                OR secret_row.revision <> NEW.reserved_secret_revision
                OR secret_row.current_version_id IS NOT NULL
                OR secret_row.current_version_number IS NOT NULL
            )) OR
            (NEW.mutation_kind = 'replace' AND (
                secret_row.status <> 'active'
                OR secret_row.revision <> NEW.reserved_secret_revision
                OR secret_row.current_version_id IS DISTINCT FROM NEW.expected_predecessor_version_id
                OR secret_row.current_version_number IS DISTINCT FROM NEW.expected_predecessor_version_number
            ))
        ) THEN
            RAISE EXCEPTION 'secret version mutation has not definitively lost CAS'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_cas_lost';
        END IF;
    ELSIF NEW.completion_kind = 'system_cancelled' THEN
        IF EXISTS (
            SELECT 1
            FROM secret_versions AS version
            LEFT JOIN secret_version_lifecycle AS lifecycle
              ON lifecycle.tenant_id = version.tenant_id
             AND lifecycle.secret_version_id = version.id
            WHERE version.tenant_id = NEW.tenant_id
              AND version.provider_id = NEW.provider_id
              AND version.create_request_id = NEW.provider_create_request_id
              AND (
                  lifecycle.mutation_id IS DISTINCT FROM NEW.mutation_id
                  OR lifecycle.status NOT IN ('staged', 'destroy_pending', 'destroyed')
              )
        ) THEN
            RAISE EXCEPTION 'applied mutation cannot be recorded as cancelled'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_cancelled_unapplied';
        END IF;
    ELSIF NEW.completion_kind = 'reservation_expired' THEN
        IF NEW.confirmed_at_ms < NEW.confirmation_deadline_ms THEN
            RAISE EXCEPTION 'secret mutation cannot expire before its hard deadline'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_expiry_deadline';
        END IF;
        IF NEW.abandoned_version_id IS NULL THEN
            IF EXISTS (
                SELECT 1 FROM secret_versions
                WHERE tenant_id = NEW.tenant_id
                  AND provider_id = NEW.provider_id
                  AND create_request_id = NEW.provider_create_request_id
            ) THEN
                RAISE EXCEPTION 'expired mutation omitted its staged candidate'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_expiry_candidate';
            END IF;
        ELSE
            SELECT * INTO winner_row
            FROM secret_versions
            WHERE tenant_id = NEW.tenant_id
              AND provider_id = NEW.provider_id
              AND create_request_id = NEW.provider_create_request_id
            FOR SHARE;
            SELECT * INTO winner_lifecycle
            FROM secret_version_lifecycle
            WHERE tenant_id = NEW.tenant_id
              AND secret_version_id = NEW.abandoned_version_id
            FOR SHARE;
            IF winner_row.id IS NULL
               OR winner_row.id IS DISTINCT FROM NEW.abandoned_version_id
               OR winner_row.secret_id <> NEW.secret_id
               OR winner_row.version_number IS DISTINCT FROM NEW.reserved_version_number
               OR winner_lifecycle.mutation_id IS DISTINCT FROM NEW.mutation_id
               OR winner_lifecycle.status <> 'staged' THEN
                RAISE EXCEPTION 'expired mutation candidate is not exact and staged'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_expiry_candidate';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_secret_versions_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'secret versions are immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_versions_immutable';
END;
$$;

CREATE FUNCTION automata_secret_workload_grant_environment_current() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    environment repository_environments%ROWTYPE;
    approval protected_environment_approval_requests%ROWTYPE;
    database_now_ms BIGINT;
BEGIN
    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    IF NEW.environment_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT * INTO STRICT environment
    FROM repository_environments
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND id = NEW.environment_id
    FOR SHARE;

    IF environment.status <> 'active' THEN
        RAISE EXCEPTION 'environment is not active'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_environment_current';
    END IF;

    IF environment.protection_mode = 'unprotected' THEN
        IF NEW.environment_approval_request_id IS NOT NULL THEN
            RAISE EXCEPTION 'unprotected environment cannot use approval evidence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'secret_workload_grants_environment_current';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.environment_approval_request_id IS NULL THEN
        RAISE EXCEPTION 'protected environment approval is required'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_environment_current';
    END IF;

    SELECT * INTO STRICT approval
    FROM protected_environment_approval_requests
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND environment_id = NEW.environment_id
      AND run_id = NEW.run_id
      AND job_id = NEW.job_id
      AND attempt_id = NEW.attempt_id
      AND id = NEW.environment_approval_request_id
    FOR SHARE;

    IF approval.status <> 'approved'
       OR approval.environment_revision <> environment.revision
       OR approval.required_approvals <> environment.required_approvals
       OR approval.prevent_self_review <> environment.prevent_self_review
       OR approval.resolved_at_ms IS NULL
       OR approval.resolved_at_ms >= approval.expires_at_ms
       OR NEW.issued_at_ms < approval.resolved_at_ms
       OR NEW.issued_at_ms >= approval.expires_at_ms
       OR NEW.issued_at_ms > database_now_ms
       OR database_now_ms >= approval.expires_at_ms
       OR database_now_ms >= NEW.expires_at_ms THEN
        RAISE EXCEPTION 'protected environment approval is stale or expired'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_workload_grants_environment_current';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_secret_workload_grant_identity_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.job_id IS DISTINCT FROM OLD.job_id
       OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.fencing_token IS DISTINCT FROM OLD.fencing_token
       OR NEW.secret_id IS DISTINCT FROM OLD.secret_id
       OR NEW.secret_version_id IS DISTINCT FROM OLD.secret_version_id
       OR NEW.secret_version_number IS DISTINCT FROM OLD.secret_version_number
       OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
       OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
       OR NEW.environment_approval_request_id IS DISTINCT FROM OLD.environment_approval_request_id
       OR NEW.grant_mode IS DISTINCT FROM OLD.grant_mode
       OR NEW.event_trust IS DISTINCT FROM OLD.event_trust
       OR NEW.source_kind IS DISTINCT FROM OLD.source_kind
       OR NEW.authority_digest IS DISTINCT FROM OLD.authority_digest
       OR NEW.authority_digest_key_id IS DISTINCT FROM OLD.authority_digest_key_id
       OR NEW.issued_at_ms IS DISTINCT FROM OLD.issued_at_ms
       OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms THEN
        RAISE EXCEPTION 'workload grant identity and authority are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_workload_grants_identity_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_secret_workload_grant_invocation_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.invocation_kind IS DISTINCT FROM OLD.invocation_kind
       OR NEW.reusable_secret_permission IS DISTINCT FROM OLD.reusable_secret_permission
       OR NEW.lease_id IS DISTINCT FROM OLD.lease_id THEN
        RAISE EXCEPTION 'secret grant invocation authority is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_workload_grants_invocation_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_secret_workload_grant_terminal_monotonic() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.status <> 'active' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal secret workload grants are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_workload_grants_terminal_monotonic';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_security_audit_events_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'Automata security audit events are append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'security_audit_events_append_only';
END;
$$;

CREATE FUNCTION automata_seed_builtin_secret_provider() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO secret_providers (
        tenant_id, provider_id, adapter_kind, display_name,
        supports_create_version, supports_destroy_version,
        supports_dynamic_leases, supports_renew_leases, supports_revoke_leases,
        is_default, status, health, revision, created_at_ms, updated_at_ms
    ) VALUES (
        NEW.id, 'builtin', 'builtin_postgres', 'Built-in encrypted PostgreSQL',
        TRUE, TRUE, FALSE, FALSE, FALSE,
        TRUE, 'unconfigured', 'unknown', 1, NEW.created_at_ms, NEW.updated_at_ms
    );
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_seed_initial_job_environment_gate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM automata_seed_job_environment_gate(
        NEW.instance_id, NEW.job_id, NEW.initial_attempt_id, NEW.committed_at_ms
    );
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_seed_job_environment_gate(target_instance_id uuid, target_job_id uuid, target_attempt_id uuid, target_created_at_ms bigint) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    logical_job logical_workflow_jobs%ROWTYPE;
    concrete logical_workflow_concrete_jobs%ROWTYPE;
    tenant TEXT;
    repository UUID;
    root_invocation UUID;
    initial_state TEXT;
BEGIN
    SELECT * INTO STRICT concrete
    FROM logical_workflow_concrete_jobs
    WHERE instance_id = target_instance_id AND job_id = target_job_id;
    SELECT * INTO STRICT logical_job
    FROM logical_workflow_jobs
    WHERE run_id = concrete.run_id
      AND invocation_id = concrete.invocation_id
      AND id = concrete.logical_job_id;
    SELECT repository_row.tenant_id, run.repository_id, marker.root_invocation_id
    INTO STRICT tenant, repository, root_invocation
    FROM workflow_runs AS run
    JOIN repositories AS repository_row ON repository_row.id = run.repository_id
    JOIN logical_workflow_runs AS marker ON marker.run_id = run.id
    WHERE run.id = concrete.run_id;

    IF logical_job.environment_requirement_kind = 'unclassified' THEN
        initial_state := 'unclassified';
    ELSIF logical_job.environment_requirement_kind = 'none'
          AND cardinality(logical_job.secret_reference_names) = 0
          AND cardinality(logical_job.variable_reference_names) = 0 THEN
        initial_state := 'resolving';
    ELSE
        -- Selection evidence is immutable once resolution begins.  Even a
        -- no-environment job therefore pauses here until its authenticated
        -- trust/source projection has been recorded.
        initial_state := 'selection_pending';
    END IF;

    INSERT INTO job_environment_gates (
        tenant_id, repository_id, run_id, invocation_id, logical_job_id,
        instance_id, job_id, attempt_id, environment_requirement_kind,
        environment_template_digest, invocation_kind, state,
        resolution_digest, resolved_secret_count, missing_secret_count,
        resolved_variable_count, missing_variable_count,
        created_at_ms, updated_at_ms
    ) VALUES (
        tenant, repository, concrete.run_id, concrete.invocation_id,
        concrete.logical_job_id, concrete.instance_id, target_job_id,
        target_attempt_id, logical_job.environment_requirement_kind,
        logical_job.environment_template_digest,
        CASE WHEN concrete.invocation_id = root_invocation
             THEN 'direct' ELSE 'reusable' END,
        initial_state, NULL, NULL, NULL, NULL, NULL,
        target_created_at_ms, target_created_at_ms
    ) ON CONFLICT (attempt_id) DO NOTHING;

    IF logical_job.environment_requirement_kind = 'none'
       AND cardinality(logical_job.secret_reference_names) = 0
       AND cardinality(logical_job.variable_reference_names) = 0 THEN
        UPDATE job_environment_gates
        SET state = 'ready',
            resolution_digest = automata_job_credential_resolution_digest(target_attempt_id),
            resolved_secret_count = 0,
            missing_secret_count = 0,
            resolved_variable_count = 0,
            missing_variable_count = 0,
            revision = revision + 1
        WHERE attempt_id = target_attempt_id AND state = 'resolving';
    END IF;
END;
$$;

CREATE FUNCTION automata_seed_repository_publication_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO repository_publication_policies (
        tenant_id, repository_id, dashboard_audience, log_audience,
        artifact_audience, revision, created_at_ms, updated_at_ms
    ) VALUES (
        NEW.tenant_id, NEW.id, 'private', 'private', 'private', 1,
        NEW.created_at_ms, NEW.updated_at_ms
    );
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_seed_retry_job_environment_gate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    concrete_instance UUID;
BEGIN
    SELECT instance_id INTO concrete_instance
    FROM logical_workflow_concrete_jobs
    WHERE job_id = NEW.job_id;
    IF concrete_instance IS NOT NULL THEN
        PERFORM automata_seed_job_environment_gate(
            concrete_instance, NEW.job_id, NEW.id, NEW.queued_at_ms
        );
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_seed_secret_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO secret_policies (
        tenant_id, secret_id, secret_scope_kind,
        tenant_repository_access_mode, minimum_event_trust,
        allow_fork_pull_requests, allow_dependabot, reusable_workflow_mode,
        revision, created_at_ms, updated_at_ms
    ) VALUES (
        NEW.tenant_id, NEW.id, NEW.scope_kind,
        CASE
            WHEN NEW.scope_kind = 'tenant' THEN 'selected_repositories'
            ELSE 'scope_only'
        END,
        'trusted', FALSE, FALSE, 'disabled',
        1, NEW.created_at_ms, NEW.updated_at_ms
    );
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_server_cancellation_terminal_digest(target_attempt_id uuid, target_operation_id uuid, requested_by text, reason text, requested_at_ms bigint) RETURNS bytea
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $_$
SELECT pg_catalog.sha256(
    convert_to('automata.store.server-cancellation-terminal.v1', 'UTF8')
    || decode('00', 'hex')
    || uuid_send($1)
    || uuid_send($2)
    || int4send(octet_length(convert_to($3, 'UTF8')))
    || convert_to($3, 'UTF8')
    || CASE
        WHEN $4 IS NULL THEN int4send(-1)
        ELSE int4send(octet_length(convert_to($4, 'UTF8')))
             || convert_to($4, 'UTF8')
       END
    || int8send($5)
    || convert_to('cancelled', 'UTF8')
);
$_$;

CREATE FUNCTION automata_validate_activation_preparation_authority_profile() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_runs AS run
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN github_workflow_run_manifest_origins AS origin
          ON origin.tenant_id = repository.tenant_id
         AND origin.repository_id = run.repository_id
         AND origin.run_id = run.id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        WHERE run.id = NEW.run_id
          AND automata_logical_workflow_invocation_published(
              run.id, NEW.invocation_id
          )
          AND manifest.authority_profile = NEW.authority_profile
    ) THEN
        RAISE EXCEPTION 'logical activation preparation lacks exact historical authority profile'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_activation_preparation_historical_profile';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_activation_publication_authority_profile() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_jobs AS job
        JOIN logical_workflow_activation_preparations AS preparation
          ON preparation.logical_job_id = job.id
         AND preparation.run_id = job.run_id
         AND preparation.invocation_id = job.invocation_id
        WHERE job.id = NEW.logical_job_id
          AND job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.authority_profile = NEW.authority_profile
          AND preparation.authority_profile = NEW.authority_profile
          AND preparation.activation_input_digest = NEW.activation_input_digest
    ) THEN
        RAISE EXCEPTION 'activation publication authority profile is inconsistent'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_workflow_activation_publications_profile_binding';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_activation_real_claim_quarantine() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now BIGINT;
    receipt logical_workflow_activation_work_selections%ROWTYPE;
    existing_quarantine logical_workflow_activation_work_quarantines%ROWTYPE;
    authority RECORD;
    internal_poison BOOLEAN := FALSE;
BEGIN
    SELECT * INTO receipt
    FROM logical_workflow_activation_work_selections
    WHERE selection_id = NEW.selection_id
    FOR UPDATE;
    PERFORM 1
    FROM logical_workflow_work_selection_replay_horizons
    WHERE queue_name = 'activation'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'activation quarantine replay horizon is absent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_quarantine_horizon_required';
    END IF;
    SELECT * INTO existing_quarantine
    FROM logical_workflow_activation_work_quarantines
    WHERE logical_job_id = NEW.logical_job_id
    FOR UPDATE;
    IF existing_quarantine.logical_job_id IS NOT NULL THEN
        RAISE EXCEPTION 'activation quarantine already has immutable evidence'
            USING ERRCODE = 'unique_violation',
                  CONSTRAINT = 'workflow_activation_quarantine_already_exists';
    END IF;

    PERFORM automata_require_active_unquarantined_workflow_phase(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id, NULL
    );

    IF NEW.authority_kind = 'preparation' THEN
        SELECT repository.tenant_id, job.run_id, job.invocation_id,
               claim.origin_selection_id, claim.owner_id, claim.generation,
               claim.descriptor_digest AS digest, claim.claimed_at_ms,
               claim.expires_at_ms, claim.state
          INTO authority
        FROM logical_workflow_activation_preparation_claims AS claim
        JOIN logical_workflow_jobs AS job ON job.id = claim.logical_job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE claim.logical_job_id = NEW.logical_job_id
        FOR UPDATE OF claim, job;
    ELSE
        SELECT repository.tenant_id, job.run_id, job.invocation_id,
               job.activation_origin_selection_id AS origin_selection_id,
               job.activation_owner_id AS owner_id,
               job.activation_fence AS generation,
               job.activation_input_digest AS digest,
               job.activation_claimed_at_ms AS claimed_at_ms,
               job.activation_expires_at_ms AS expires_at_ms,
               job.state
          INTO authority
        FROM logical_workflow_jobs AS job
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE job.id = NEW.logical_job_id
        FOR UPDATE OF job;
    END IF;

    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    internal_poison := NEW.failure_kind = 'generation_exhausted'
        AND receipt.outcome = 'selecting';
    IF receipt.selection_id IS NULL
        OR receipt.owner_id IS DISTINCT FROM NEW.selection_owner_id
        OR receipt.requested_at_ms IS DISTINCT FROM NEW.selection_requested_at_ms
        OR receipt.duration_ms IS DISTINCT FROM NEW.selection_duration_ms
    THEN
        RAISE EXCEPTION 'activation quarantine lacks its exact selection request'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_quarantine_selection_request_exact';
    END IF;
    IF internal_poison THEN
        IF receipt.claimed_at_ms IS NOT NULL OR receipt.expires_at_ms IS NOT NULL
            OR receipt.tenant_id IS NOT NULL OR receipt.run_id IS NOT NULL
            OR receipt.invocation_id IS NOT NULL OR receipt.logical_job_id IS NOT NULL
            OR receipt.generation IS NOT NULL OR receipt.authority_kind IS NOT NULL
            OR receipt.authority_digest IS NOT NULL
            OR NEW.selection_generation <> NEW.authority_generation
            OR NEW.selection_claimed_at_ms > database_now
            OR database_now - NEW.selection_claimed_at_ms > 60000
            OR NEW.selection_expires_at_ms - database_now < 1000
            OR NEW.authority_generation <> 9223372036854775807
            OR NEW.authority_expires_at_ms > database_now
        THEN
            RAISE EXCEPTION 'activation generation poison is not an exact provisional capture'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_quarantine_generation_poison_exact';
        END IF;
    ELSIF NEW.failure_kind = 'generation_exhausted'
        OR receipt.outcome <> 'claimed'
        OR receipt.claimed_at_ms IS DISTINCT FROM NEW.selection_claimed_at_ms
        OR receipt.expires_at_ms IS DISTINCT FROM NEW.selection_expires_at_ms
        OR receipt.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR receipt.run_id IS DISTINCT FROM NEW.run_id
        OR receipt.invocation_id IS DISTINCT FROM NEW.invocation_id
        OR receipt.logical_job_id IS DISTINCT FROM NEW.logical_job_id
        OR receipt.generation IS DISTINCT FROM NEW.selection_generation
        OR receipt.authority_kind IS DISTINCT FROM NEW.authority_kind
        OR receipt.authority_digest IS DISTINCT FROM NEW.authority_digest
    THEN
        RAISE EXCEPTION 'activation quarantine lacks the exact claimed receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_quarantine_selection_exact';
    END IF;

    IF authority IS NULL
        OR (authority.tenant_id, authority.run_id, authority.invocation_id)
           IS DISTINCT FROM (NEW.tenant_id, NEW.run_id, NEW.invocation_id)
        OR authority.owner_id IS DISTINCT FROM NEW.authority_owner_id
        OR authority.generation IS DISTINCT FROM NEW.authority_generation
        OR authority.generation < NEW.selection_generation
        OR authority.digest IS DISTINCT FROM NEW.authority_digest
        OR authority.claimed_at_ms IS DISTINCT FROM NEW.authority_claimed_at_ms
        OR authority.expires_at_ms IS DISTINCT FROM NEW.authority_expires_at_ms
        OR authority.claimed_at_ms > database_now
        OR authority.state IS DISTINCT FROM (
            CASE WHEN NEW.authority_kind = 'preparation'
                 THEN 'preparing' ELSE 'activating' END
        )
        OR (NOT internal_poison AND (
            authority.origin_selection_id IS DISTINCT FROM NEW.selection_id
            OR authority.owner_id IS DISTINCT FROM NEW.selection_owner_id))
    THEN
        RAISE EXCEPTION 'activation quarantine lacks exact unsuperseded authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_quarantine_authority_exact';
    END IF;
    NEW.quarantined_at_ms := database_now;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_activation_real_claim_renewal_receipt() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    selection logical_workflow_activation_work_selections%ROWTYPE;
    authority RECORD;
    database_now BIGINT;
    receipt_count BIGINT;
    predecessor_exact BOOLEAN := FALSE;
BEGIN
    SELECT * INTO selection
    FROM logical_workflow_activation_work_selections
    WHERE selection_id = NEW.selection_id;
    SELECT count(*) INTO receipt_count
    FROM logical_workflow_activation_renewal_receipts
    WHERE selection_id = NEW.selection_id;
    IF NEW.authority_kind = 'preparation' THEN
        SELECT claim.state, claim.origin_selection_id, claim.owner_id,
               claim.generation, claim.claimed_at_ms, claim.expires_at_ms,
               claim.descriptor_digest AS authority_digest,
               claim.runtime_policy_revision, claim.runtime_policy_digest
          INTO authority
        FROM logical_workflow_activation_preparation_claims AS claim
        WHERE claim.logical_job_id = NEW.logical_job_id
        FOR UPDATE;
    ELSE
        SELECT job.state, job.activation_origin_selection_id AS origin_selection_id,
               job.activation_owner_id AS owner_id,
               job.activation_fence AS generation,
               job.activation_claimed_at_ms AS claimed_at_ms,
               job.activation_expires_at_ms AS expires_at_ms,
               job.activation_input_digest AS authority_digest,
               job.runtime_policy_revision, job.runtime_policy_digest
          INTO authority
        FROM logical_workflow_jobs AS job
        WHERE job.id = NEW.logical_job_id
        FOR UPDATE;
    END IF;
    IF selection.selection_id IS NULL OR selection.outcome <> 'claimed'
        OR selection.authority_kind IS DISTINCT FROM NEW.authority_kind
        OR (selection.tenant_id, selection.run_id, selection.invocation_id,
            selection.logical_job_id, selection.owner_id,
            selection.authority_digest)
           IS DISTINCT FROM
           (NEW.tenant_id, NEW.run_id, NEW.invocation_id,
            NEW.logical_job_id, NEW.owner_id, NEW.authority_digest)
    THEN
        RAISE EXCEPTION 'activation renewal lacks its exact selection origin'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_renewal_selection_exact';
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
            FROM logical_workflow_activation_renewal_receipts AS prior
            WHERE prior.selection_id = NEW.selection_id
              AND prior.logical_job_id = NEW.logical_job_id
              AND prior.authority_kind = NEW.authority_kind
              AND prior.successor_generation = NEW.predecessor_generation
              AND prior.successor_claimed_at_ms = NEW.predecessor_claimed_at_ms
              AND prior.successor_expires_at_ms = NEW.predecessor_expires_at_ms
              AND prior.owner_id = NEW.owner_id
              AND prior.runtime_policy_revision = NEW.runtime_policy_revision
              AND prior.runtime_policy_digest = NEW.runtime_policy_digest
              AND prior.authority_digest = NEW.authority_digest
        ) INTO predecessor_exact;
    END IF;
    IF predecessor_exact IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'activation renewal does not extend its exact predecessor chain'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_renewal_predecessor_exact';
    END IF;
    IF receipt_count >= 64 THEN
        RAISE EXCEPTION 'activation selection renewal history is full'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_renewal_history_bounded';
    END IF;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF authority IS NULL
        OR authority.state IS DISTINCT FROM (
            CASE WHEN NEW.authority_kind = 'preparation'
                 THEN 'preparing' ELSE 'activating' END
        )
        OR authority.origin_selection_id IS DISTINCT FROM NEW.selection_id
        OR authority.owner_id IS DISTINCT FROM NEW.owner_id
        OR authority.generation IS DISTINCT FROM NEW.successor_generation
        OR authority.claimed_at_ms IS DISTINCT FROM NEW.successor_claimed_at_ms
        OR authority.expires_at_ms IS DISTINCT FROM NEW.successor_expires_at_ms
        OR authority.authority_digest IS DISTINCT FROM NEW.authority_digest
        OR (authority.runtime_policy_revision, authority.runtime_policy_digest)
           IS DISTINCT FROM
           (NEW.runtime_policy_revision, NEW.runtime_policy_digest)
        OR NEW.successor_expires_at_ms - database_now < 1000
    THEN
        RAISE EXCEPTION 'activation renewal lacks the exact live successor authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_renewal_successor_exact';
    END IF;
    NEW.validated_at_ms := database_now;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_activation_work_selection_transition() RETURNS trigger
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
            RAISE EXCEPTION 'activation selection must begin as a provisional reservation'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_selection_reservation_first';
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
        RAISE EXCEPTION 'activation selection transition is immutable or invalid'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_transition';
    END IF;
    SELECT replay_floor_ms INTO replay_floor
    FROM logical_workflow_work_selection_replay_horizons
    WHERE queue_name = 'activation'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'activation selection replay authority is absent'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_horizon_required';
    END IF;
    database_now := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    IF NEW.requested_at_ms <= replay_floor
        OR NEW.requested_at_ms < database_now - 60000
        OR NEW.requested_at_ms > database_now + 60000
    THEN
        RAISE EXCEPTION 'activation selection request is outside replay authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_request_time';
    END IF;
    IF NEW.claimed_at_ms > database_now
        OR database_now - NEW.claimed_at_ms > 60000
        OR (NEW.outcome <> 'quarantined' AND (
            NEW.expires_at_ms <= database_now
            OR NEW.expires_at_ms - database_now < 1000
        ))
    THEN
        RAISE EXCEPTION 'activation selection issue time is not database-current'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_database_time';
    END IF;

    IF NEW.outcome = 'claimed' AND NEW.authority_kind = 'preparation' THEN
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_activation_preparation_claims AS claim
            JOIN logical_workflow_jobs AS job ON job.id = claim.logical_job_id
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE claim.logical_job_id = NEW.logical_job_id
              AND repository.tenant_id = NEW.tenant_id
              AND job.run_id = NEW.run_id
              AND job.invocation_id = NEW.invocation_id
              AND claim.origin_selection_id = NEW.selection_id
              AND claim.owner_id = NEW.owner_id
              AND claim.generation = NEW.generation
              AND claim.descriptor_digest = NEW.authority_digest
              AND claim.claimed_at_ms = NEW.claimed_at_ms
              AND claim.expires_at_ms = NEW.expires_at_ms
              AND claim.state = 'preparing'
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'claimed' AND NEW.authority_kind = 'activation' THEN
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_jobs AS job
            JOIN workflow_runs AS run ON run.id = job.run_id
            JOIN repositories AS repository ON repository.id = run.repository_id
            WHERE job.id = NEW.logical_job_id
              AND repository.tenant_id = NEW.tenant_id
              AND job.run_id = NEW.run_id
              AND job.invocation_id = NEW.invocation_id
              AND job.activation_origin_selection_id = NEW.selection_id
              AND job.activation_owner_id = NEW.owner_id
              AND job.activation_fence = NEW.generation
              AND job.activation_input_digest = NEW.authority_digest
              AND job.activation_claimed_at_ms = NEW.claimed_at_ms
              AND job.activation_expires_at_ms = NEW.expires_at_ms
              AND job.state = 'activating'
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'quarantined' THEN
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_activation_work_quarantines AS quarantine
            WHERE quarantine.logical_job_id = NEW.logical_job_id
              AND quarantine.tenant_id = NEW.tenant_id
              AND quarantine.run_id = NEW.run_id
              AND quarantine.invocation_id = NEW.invocation_id
              AND quarantine.selection_id = NEW.selection_id
              AND quarantine.selection_owner_id = NEW.owner_id
              AND quarantine.selection_requested_at_ms = NEW.requested_at_ms
              AND quarantine.selection_duration_ms = NEW.duration_ms
              AND quarantine.selection_generation = NEW.generation
              AND quarantine.selection_claimed_at_ms = NEW.claimed_at_ms
              AND quarantine.selection_expires_at_ms = NEW.expires_at_ms
              AND quarantine.authority_kind = NEW.authority_kind
              AND quarantine.authority_digest = NEW.authority_digest
        ) INTO exact_evidence;
    ELSIF NEW.outcome = 'contended' THEN
        exact_evidence := TRUE;
    ELSE
        SELECT EXISTS (
            SELECT 1
            FROM logical_workflow_jobs AS job
            JOIN logical_workflow_invocations AS invocation
              ON invocation.run_id = job.run_id
             AND invocation.id = job.invocation_id
            JOIN logical_workflow_runs AS marker ON marker.run_id = job.run_id
            JOIN workflow_runs AS run ON run.id = marker.run_id
            LEFT JOIN logical_workflow_activation_preparation_claims AS preparation
              ON preparation.logical_job_id = job.id
            LEFT JOIN logical_workflow_activation_work_quarantines AS quarantine
              ON quarantine.logical_job_id = job.id
            WHERE job.execution_kind = 'steps'
              AND automata_logical_workflow_invocation_published(
                  marker.run_id, invocation.id
              )
              AND invocation.state IN ('pending', 'active')
              AND marker.state IN ('pending', 'active')
              AND run.status IN ('queued', 'in_progress')
              AND quarantine.logical_job_id IS NULL
              AND ((job.state = 'pending' AND (
                  preparation.logical_job_id IS NULL OR preparation.state = 'prepared'
                  OR (preparation.state = 'preparing'
                      AND preparation.expires_at_ms <= NEW.claimed_at_ms)
              )) OR (job.state = 'activating'
                     AND job.activation_expires_at_ms <= NEW.claimed_at_ms))
              AND NOT EXISTS (
                  SELECT 1
                  FROM logical_workflow_dependencies AS dependency
                  LEFT JOIN logical_workflow_job_result_claims AS result_claim
                    ON result_claim.logical_job_id = dependency.prerequisite_job_id
                   AND result_claim.state = 'finalized'
                  WHERE dependency.run_id = job.run_id
                    AND dependency.invocation_id = job.invocation_id
                    AND dependency.logical_job_id = job.id
                    AND result_claim.logical_job_id IS NULL
              )
        ) INTO ready_exists;
        exact_evidence := NOT ready_exists;
    END IF;
    IF exact_evidence IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'activation selection lacks exact durable evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_selection_receipt_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_artifact_safety_snapshot() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    attempt_exposure TEXT;
    run_artifact_visibility TEXT;
BEGIN
    SELECT secret_exposure_class
    INTO attempt_exposure
    FROM job_attempts
    WHERE id = NEW.attempt_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    SELECT requested_artifact_visibility
    INTO run_artifact_visibility
    FROM workflow_runs
    WHERE id = NEW.run_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF NEW.secret_exposure_class IS DISTINCT FROM attempt_exposure THEN
        RAISE EXCEPTION 'artifact exposure must equal the immutable attempt ceiling'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_artifacts_attempt_exposure_snapshot';
    END IF;
    IF NEW.requested_visibility IS DISTINCT FROM run_artifact_visibility THEN
        RAISE EXCEPTION 'artifact audience must equal the immutable run request'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_artifacts_run_visibility_snapshot';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_attempt_log_safety_snapshot() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    attempt_exposure TEXT;
    attempt_raw_disposition TEXT;
    attempt_requested_visibility TEXT;
    attempt_effective_visibility TEXT;
    attempt_reason TEXT;
    attempt_schema INTEGER;
BEGIN
    SELECT
        secret_exposure_class,
        raw_log_disposition,
        requested_log_visibility,
        effective_log_visibility,
        output_safety_reason,
        output_safety_schema
    INTO
        attempt_exposure,
        attempt_raw_disposition,
        attempt_requested_visibility,
        attempt_effective_visibility,
        attempt_reason,
        attempt_schema
    FROM job_attempts
    WHERE id = NEW.attempt_id;

    -- Preserve the existing foreign-key error for a nonexistent attempt.
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF NEW.secret_exposure_class IS DISTINCT FROM attempt_exposure
       OR NEW.raw_log_disposition IS DISTINCT FROM attempt_raw_disposition
       OR NEW.requested_visibility IS DISTINCT FROM attempt_requested_visibility
       OR NEW.effective_visibility IS DISTINCT FROM attempt_effective_visibility
       OR NEW.output_safety_reason IS DISTINCT FROM attempt_reason
       OR NEW.output_safety_schema IS DISTINCT FROM attempt_schema THEN
        RAISE EXCEPTION 'attempt log safety must equal the immutable attempt snapshot'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'attempt_log_streams_attempt_safety_snapshot';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_concrete_job_authority_profile() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_materialization_claims AS claim
        WHERE claim.instance_id = NEW.instance_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.authority_profile = NEW.authority_profile
    ) THEN
        RAISE EXCEPTION 'concrete job authority profile is inconsistent'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'logical_workflow_concrete_jobs_profile_binding';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_concurrency_pending_run() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM concurrency_groups AS concurrency
        WHERE concurrency.repository_id = NEW.repository_id
          AND concurrency.normalized_key = NEW.normalized_key
          AND concurrency.running_run_id = NEW.run_id
    ) THEN
        RAISE EXCEPTION 'Concurrency run cannot occupy running and pending positions'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_concurrency_running_run() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.running_run_id IS NOT NULL AND EXISTS (
        SELECT 1
        FROM concurrency_group_pending_runs AS pending
        WHERE pending.repository_id = NEW.repository_id
          AND pending.normalized_key = NEW.normalized_key
          AND pending.run_id = NEW.running_run_id
    ) THEN
        RAISE EXCEPTION 'Concurrency run cannot occupy running and pending positions'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_environment_approval_decision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    request protected_environment_approval_requests%ROWTYPE;
    environment repository_environments%ROWTYPE;
    database_now_ms BIGINT;
BEGIN
    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    SELECT * INTO STRICT request
    FROM protected_environment_approval_requests
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.request_id
    FOR SHARE;

    SELECT * INTO STRICT environment
    FROM repository_environments
    WHERE tenant_id = request.tenant_id
      AND repository_id = request.repository_id
      AND id = request.environment_id
    FOR SHARE;

    IF request.status <> 'pending' THEN
        RAISE EXCEPTION 'environment approval request is terminal'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'protected_environment_approval_decisions_pending';
    END IF;
    IF request.environment_revision <> environment.revision
       OR request.required_approvals <> environment.required_approvals
       OR request.prevent_self_review <> environment.prevent_self_review
       OR environment.protection_mode <> 'required_approvals'
       OR environment.status <> 'active' THEN
        RAISE EXCEPTION 'environment approval request policy is stale'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'protected_environment_approval_decisions_current_policy';
    END IF;
    IF NEW.decided_at_ms < request.created_at_ms
       OR NEW.decided_at_ms >= request.expires_at_ms
       OR NEW.decided_at_ms > database_now_ms
       OR database_now_ms - NEW.decided_at_ms > 60000
       OR database_now_ms >= request.expires_at_ms THEN
        RAISE EXCEPTION 'environment approval decision is outside the request lifetime'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'protected_environment_approval_decisions_lifetime';
    END IF;
    IF request.prevent_self_review
       AND request.requested_by_principal_id = NEW.principal_id THEN
        RAISE EXCEPTION 'environment requester cannot approve their own workload'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'protected_environment_approval_decisions_self_review';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_github_oidc_authority_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT automata_lock_github_oidc_authority_dependencies(NEW)
        OR NOT automata_github_oidc_authority_is_current(
            NEW, NEW.reserved_at_ms, NEW.reserved_at_ms + 1
        )
    THEN
        RAISE EXCEPTION 'GitHub-compatible OIDC authority is not current'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_oidc_authority_current_execution';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_github_oidc_issuance_slot() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    authority github_oidc_authorities%ROWTYPE;
    slot_count BIGINT;
BEGIN
    IF NEW.issued_at_seconds > 9223372036854774 THEN
        RAISE EXCEPTION 'GitHub-compatible OIDC issuance time is out of range'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_oidc_issuance_current_authority';
    END IF;
    SELECT * INTO authority
    FROM github_oidc_authorities
    WHERE authority_id = NEW.authority_id
    FOR UPDATE;
    IF authority.authority_id IS NULL
        OR NOT automata_lock_github_oidc_authority_dependencies(authority)
        OR NEW.resolved_audience IS DISTINCT FROM coalesce(
            NEW.requested_audience, authority.default_audience
        )
        OR NEW.issued_at_seconds < authority.request_bearer_iat_seconds
        OR NEW.not_before_seconds < authority.request_bearer_iat_seconds
        OR NEW.expires_at_seconds > authority.request_bearer_exp_seconds
        OR NOT automata_github_oidc_authority_is_current(
            authority,
            NEW.issued_at_seconds * 1000,
            (NEW.issued_at_seconds + 1) * 1000
        )
    THEN
        RAISE EXCEPTION 'GitHub-compatible OIDC issuance lacks current authority'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_oidc_issuance_current_authority';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.generation <> 1
            OR NEW.created_at_seconds <> NEW.issued_at_seconds
        THEN
            RAISE EXCEPTION 'GitHub-compatible OIDC initial issuance is invalid'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_oidc_issuance_slot_initial';
        END IF;
        SELECT count(*) INTO slot_count
        FROM github_oidc_issuance_slots
        WHERE authority_id = NEW.authority_id;
        IF slot_count >= 64 THEN
            RAISE EXCEPTION 'GitHub-compatible OIDC audience slot bound exceeded'
                USING ERRCODE = 'program_limit_exceeded',
                      CONSTRAINT = 'github_oidc_issuance_slot_bound';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_validate_github_runtime_authority_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.state <> 'claimed'
        OR NEW.mint_attempt_count <> 1
        OR NEW.mint_claim_fence <> 1
        OR NOT automata_github_runtime_authority_is_current(
            NEW, NEW.mint_claimed_at_ms
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority does not match current JobIR attempt authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_current_attempt_insert';
    END IF;
    RETURN NEW;
END;
$$;
