-- Frozen greenfield baseline. Add a new migration instead of editing this stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_retain_runner_payload_tombstone() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.payload_tombstone_reason IS NOT NULL THEN
        RAISE EXCEPTION 'runner payload tombstone metadata must be retained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = TG_TABLE_NAME || '_tombstone_retained';
    END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION automata_reusable_secret_identity_chain_is_exact(target_run_id uuid, target_invocation_id uuid, target_canonical_name text) RETURNS boolean
    LANGUAGE plpgsql STABLE
    AS $_$
DECLARE
    current_invocation_id UUID := target_invocation_id;
    parent_invocation_id UUID;
    current_depth SMALLINT;
    expected_depth SMALLINT;
    matching_target_count BIGINT;
    same_name_source_count BIGINT;
    visited_invocations UUID[] := ARRAY[]::UUID[];
BEGIN
    IF target_canonical_name IS NULL
       OR target_canonical_name !~ '^[A-Z_][A-Z0-9_]*$'
       OR target_canonical_name ~ '^(GITHUB_|ACTIONS_|RUNNER_|AUTOMATA_)'
       OR octet_length(target_canonical_name) > 255 THEN
        RETURN FALSE;
    END IF;

    LOOP
        IF current_invocation_id = ANY(visited_invocations) THEN
            RETURN FALSE;
        END IF;
        visited_invocations := array_append(
            visited_invocations,
            current_invocation_id
        );

        SELECT expansion.parent_invocation_id, expansion.depth
          INTO parent_invocation_id, current_depth
        FROM logical_workflow_reusable_invocation_expansions AS expansion
        WHERE expansion.run_id = target_run_id
          AND expansion.invocation_id = current_invocation_id;
        IF NOT FOUND
           OR expected_depth IS NOT NULL AND current_depth <> expected_depth THEN
            RETURN FALSE;
        END IF;
        IF parent_invocation_id IS NULL THEN
            RETURN current_depth = 0;
        END IF;
        IF current_depth <= 0 THEN
            RETURN FALSE;
        END IF;

        SELECT count(*),
               count(*) FILTER (
                   WHERE upper(binding.source_name) = target_canonical_name
               )
          INTO matching_target_count, same_name_source_count
        FROM logical_workflow_reusable_secret_bindings AS binding
        WHERE binding.run_id = target_run_id
          AND binding.invocation_id = current_invocation_id
          AND upper(binding.target_name) = target_canonical_name;
        IF matching_target_count <> 1 OR same_name_source_count <> 1 THEN
            RETURN FALSE;
        END IF;

        expected_depth := current_depth - 1;
        current_invocation_id := parent_invocation_id;
    END LOOP;
END;
$_$;

CREATE FUNCTION automata_reusable_workflow_oidc_permission_authorized(target_run_id uuid, target_invocation_id uuid) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT EXISTS (
        SELECT 1
        FROM logical_workflow_runs AS marker
        WHERE marker.run_id = target_run_id
          AND (
              marker.root_invocation_id = target_invocation_id
              OR (
                  automata_logical_workflow_invocation_published(
                      target_run_id, target_invocation_id
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM logical_workflow_reusable_invocation_expansions AS planned
                      JOIN logical_workflow_reusable_call_publications AS publication
                        ON publication.run_id = planned.run_id
                       AND publication.child_invocation_id = planned.invocation_id
                       AND publication.parent_invocation_id = planned.parent_invocation_id
                       AND publication.caller_logical_job_id =
                           planned.caller_logical_job_id
                       AND publication.permission_digest = planned.permission_digest
                       AND publication.condition_matched
                       AND publication.child_graph_sealed_at_ms =
                           publication.published_at_ms
                      JOIN logical_workflow_reusable_permission_snapshots AS permission_snapshot
                        ON permission_snapshot.run_id = planned.run_id
                       AND permission_snapshot.invocation_id = planned.invocation_id
                       AND permission_snapshot.permission_digest = planned.permission_digest
                      LEFT JOIN logical_workflow_reusable_permission_grants AS id_token_grant
                        ON id_token_grant.run_id = permission_snapshot.run_id
                       AND id_token_grant.invocation_id =
                           permission_snapshot.invocation_id
                       AND id_token_grant.permission_name = 'id-token'
                      WHERE planned.run_id = target_run_id
                        AND planned.invocation_id = target_invocation_id
                        AND planned.depth > 0
                        AND COALESCE(
                            id_token_grant.permission_level,
                            permission_snapshot.default_level
                        ) = 'write'
                  )
              )
          )
    )
$$;

CREATE FUNCTION automata_role_binding_authorization_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP <> 'DELETE' THEN
        UPDATE tenant_human_memberships
        SET authorization_revision = authorization_revision + 1
        WHERE tenant_id = NEW.tenant_id AND principal_id = NEW.principal_id;
    END IF;
    IF TG_OP <> 'INSERT' AND (
        TG_OP = 'DELETE'
        OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR OLD.principal_id IS DISTINCT FROM NEW.principal_id
    ) THEN
        UPDATE tenant_human_memberships
        SET authorization_revision = authorization_revision + 1
        WHERE tenant_id = OLD.tenant_id AND principal_id = OLD.principal_id;
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_role_permission_authorization_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP <> 'DELETE' THEN
        UPDATE tenant_human_memberships AS membership
        SET authorization_revision = membership.authorization_revision + 1
        WHERE membership.tenant_id = NEW.tenant_id
          AND EXISTS (
              SELECT 1 FROM rbac_role_bindings AS binding
              WHERE binding.tenant_id = NEW.tenant_id
                AND binding.principal_id = membership.principal_id
                AND binding.role_id = NEW.role_id
                AND binding.status = 'active'
          );
    END IF;
    IF TG_OP <> 'INSERT' AND (
        TG_OP = 'DELETE'
        OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR OLD.role_id IS DISTINCT FROM NEW.role_id
    ) THEN
        UPDATE tenant_human_memberships AS membership
        SET authorization_revision = membership.authorization_revision + 1
        WHERE membership.tenant_id = OLD.tenant_id
          AND EXISTS (
              SELECT 1 FROM rbac_role_bindings AS binding
              WHERE binding.tenant_id = OLD.tenant_id
                AND binding.principal_id = membership.principal_id
                AND binding.role_id = OLD.role_id
                AND binding.status = 'active'
          );
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_runner_certificate_authority_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.leaf_sha256 IS DISTINCT FROM OLD.leaf_sha256
       OR NEW.runner_id IS DISTINCT FROM OLD.runner_id
       OR NEW.expires_at_seconds IS DISTINCT FROM OLD.expires_at_seconds THEN
        RAISE EXCEPTION 'runner machine certificate authority is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'runner_machine_certificates_authority_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_runner_certificate_revocation_write_once() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.revoked_at_seconds IS NOT NULL
       AND NEW.revoked_at_seconds IS DISTINCT FROM OLD.revoked_at_seconds THEN
        RAISE EXCEPTION 'runner machine certificate revocation is write-once'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'runner_machine_certificates_revocation_write_once';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_runner_enrollment_token_consume_once() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.runner_group_id IS DISTINCT FROM OLD.runner_group_id
       OR NEW.token_sha256 IS DISTINCT FROM OLD.token_sha256
       OR NEW.issuer_kind IS DISTINCT FROM OLD.issuer_kind
       OR NEW.issued_by_principal_id IS DISTINCT FROM OLD.issued_by_principal_id
       OR NEW.issued_by_session_id IS DISTINCT FROM OLD.issued_by_session_id
       OR NEW.issued_authorization_revision IS DISTINCT FROM OLD.issued_authorization_revision
       OR NEW.installation_authority_sha256 IS DISTINCT FROM OLD.installation_authority_sha256
       OR NEW.issued_at_ms IS DISTINCT FROM OLD.issued_at_ms
       OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
       OR (OLD.consumed_at_ms IS NOT NULL AND (
           NEW.consumed_at_ms IS DISTINCT FROM OLD.consumed_at_ms
           OR NEW.consumed_runner_id IS DISTINCT FROM OLD.consumed_runner_id
           OR NEW.redeem_operation_id IS DISTINCT FROM OLD.redeem_operation_id
           OR NEW.redeem_request_sha256 IS DISTINCT FROM OLD.redeem_request_sha256
           OR NEW.redeem_response IS DISTINCT FROM OLD.redeem_response
           OR NEW.redeem_certificate_expires_at_seconds IS DISTINCT FROM OLD.redeem_certificate_expires_at_seconds
       )) THEN
        RAISE EXCEPTION 'runner enrollment token authority is immutable and consumption is write-once'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'runner_enrollment_tokens_consume_once';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_seal_github_schedule_registry() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    revision_count SMALLINT;
    revision_digest BYTEA;
    actual_count BIGINT;
    minimum_ordinal SMALLINT;
    maximum_ordinal SMALLINT;
BEGIN
    SELECT schedule_count, inventory_digest
      INTO revision_count, revision_digest
     FROM github_schedule_registry_revisions
     WHERE registry_id = NEW.registry_id
     FOR UPDATE;
    SELECT count(*), min(ordinal), max(ordinal)
      INTO actual_count, minimum_ordinal, maximum_ordinal
      FROM github_schedule_registry_entries
     WHERE registry_id = NEW.registry_id;
    IF revision_count IS NULL
        OR revision_count <> NEW.schedule_count
        OR revision_digest <> NEW.inventory_digest
        OR actual_count <> NEW.schedule_count
        OR (
            NEW.schedule_count > 0
            AND (minimum_ordinal <> 0 OR maximum_ordinal <> NEW.schedule_count - 1)
        )
    THEN
        RAISE EXCEPTION 'GitHub schedule registry seal does not match exact entries'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_schedule_registry_seal_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_seal_reusable_call_publication() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.parent_invocation_id IS DISTINCT FROM OLD.parent_invocation_id
        OR NEW.caller_logical_job_id IS DISTINCT FROM OLD.caller_logical_job_id
        OR NEW.caller_instance_id IS DISTINCT FROM OLD.caller_instance_id
        OR NEW.child_invocation_id IS DISTINCT FROM OLD.child_invocation_id
        OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
        OR NEW.activation_generation IS DISTINCT FROM OLD.activation_generation
        OR NEW.activation_input_digest IS DISTINCT FROM OLD.activation_input_digest
        OR NEW.condition_matched IS DISTINCT FROM OLD.condition_matched
        OR NEW.matrix_digest IS DISTINCT FROM OLD.matrix_digest
        OR NEW.runtime_context_digest IS DISTINCT FROM OLD.runtime_context_digest
        OR NEW.runtime_context_object_key IS DISTINCT FROM OLD.runtime_context_object_key
        OR NEW.runtime_context_size_bytes IS DISTINCT FROM OLD.runtime_context_size_bytes
        OR NEW.runtime_context_media_type IS DISTINCT FROM OLD.runtime_context_media_type
        OR NEW.runtime_context_schema IS DISTINCT FROM OLD.runtime_context_schema
        OR NEW.permission_digest IS DISTINCT FROM OLD.permission_digest
        OR NEW.output_mapping_count IS DISTINCT FROM OLD.output_mapping_count
        OR NEW.output_mapping_digest IS DISTINCT FROM OLD.output_mapping_digest
        OR NEW.publication_digest IS DISTINCT FROM OLD.publication_digest
        OR NEW.runtime_policy_revision IS DISTINCT FROM OLD.runtime_policy_revision
        OR NEW.runtime_policy_digest IS DISTINCT FROM OLD.runtime_policy_digest
        OR NEW.authority_profile IS DISTINCT FROM OLD.authority_profile
        OR NEW.published_at_ms IS DISTINCT FROM OLD.published_at_ms
        OR OLD.child_graph_sealed_at_ms IS NOT NULL
        OR NEW.child_graph_sealed_at_ms IS DISTINCT FROM NEW.published_at_ms
    THEN
        RAISE EXCEPTION 'reusable call publication is immutable outside its seal transition'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_call_publication_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_seal_reusable_call_result() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.parent_invocation_id IS DISTINCT FROM OLD.parent_invocation_id
        OR NEW.caller_logical_job_id IS DISTINCT FROM OLD.caller_logical_job_id
        OR NEW.caller_instance_id IS DISTINCT FROM OLD.caller_instance_id
        OR NEW.child_invocation_id IS DISTINCT FROM OLD.child_invocation_id
        OR NEW.publication_operation_id IS DISTINCT FROM OLD.publication_operation_id
        OR NEW.completion_operation_id IS DISTINCT FROM OLD.completion_operation_id
        OR NEW.callee_plan_digest IS DISTINCT FROM OLD.callee_plan_digest
        OR NEW.evaluator_schema IS DISTINCT FROM OLD.evaluator_schema
        OR NEW.child_job_count IS DISTINCT FROM OLD.child_job_count
        OR NEW.child_jobs_digest IS DISTINCT FROM OLD.child_jobs_digest
        OR NEW.workflow_output_evaluation_digest IS DISTINCT FROM
           OLD.workflow_output_evaluation_digest
        OR NEW.descriptor_digest IS DISTINCT FROM OLD.descriptor_digest
        OR NEW.effective_conclusion IS DISTINCT FROM OLD.effective_conclusion
        OR NEW.output_count IS DISTINCT FROM OLD.output_count
        OR NEW.outputs_digest IS DISTINCT FROM OLD.outputs_digest
        OR NEW.commit_digest IS DISTINCT FROM OLD.commit_digest
        OR NEW.parent_result_descriptor_digest IS DISTINCT FROM
           OLD.parent_result_descriptor_digest
        OR NEW.parent_instances_digest IS DISTINCT FROM OLD.parent_instances_digest
        OR NEW.parent_prerequisites_digest IS DISTINCT FROM
           OLD.parent_prerequisites_digest
        OR NEW.parent_outputs_digest IS DISTINCT FROM OLD.parent_outputs_digest
        OR NEW.parent_commit_digest IS DISTINCT FROM OLD.parent_commit_digest
        OR NEW.completed_at_ms IS DISTINCT FROM OLD.completed_at_ms
        OR OLD.sealed_at_ms IS NOT NULL
        OR NEW.sealed_at_ms IS DISTINCT FROM NEW.completed_at_ms
    THEN
        RAISE EXCEPTION 'reusable call result is immutable outside its seal transition'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_call_result_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_secret_cleanup_delete_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'secret cleanup receipts cannot be deleted'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_cleanup_delete_forbidden';
END;
$$;

CREATE FUNCTION automata_secret_cleanup_transition_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.operation_id = '00000000-0000-0000-0000-000000000000'::UUID
           OR NEW.status <> 'pending'
           OR NEW.attempts <> 0
           OR NEW.claim_generation <> 0
           OR NEW.locked_by IS NOT NULL
           OR NEW.locked_at_ms IS NOT NULL
           OR NEW.last_failure_kind IS NOT NULL
           OR NEW.completed_at_ms IS NOT NULL
           OR NEW.next_attempt_at_ms < NEW.created_at_ms THEN
            RAISE EXCEPTION 'secret cleanup must begin as an unfenced pending task'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_cleanup_initial_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.sequence IS DISTINCT FROM OLD.sequence
       OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
       OR NEW.cleanup_kind IS DISTINCT FROM OLD.cleanup_kind
       OR NEW.provider_lease_record_id IS DISTINCT FROM OLD.provider_lease_record_id
       OR NEW.secret_id IS DISTINCT FROM OLD.secret_id
       OR NEW.secret_version_id IS DISTINCT FROM OLD.secret_version_id
       OR NEW.version_number IS DISTINCT FROM OLD.version_number
       OR NEW.envelope_generation IS DISTINCT FROM OLD.envelope_generation
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'secret cleanup task identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_cleanup_identity_immutable';
    END IF;

    IF OLD.status = 'pending' AND NEW.status = 'in_progress' THEN
        IF NEW.attempts IS DISTINCT FROM OLD.attempts + 1
           OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation + 1
           OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
           OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
           OR octet_length(NEW.locked_by) NOT BETWEEN 1 AND 255
           OR NEW.locked_by ~ '[[:cntrl:]]'
           OR NEW.locked_at_ms < OLD.next_attempt_at_ms
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'secret cleanup claim is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_cleanup_claim_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'in_progress' AND NEW.status = 'in_progress' THEN
        IF NEW.attempts IS DISTINCT FROM OLD.attempts
           OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation + 1
           OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
           OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
           OR octet_length(NEW.locked_by) NOT BETWEEN 1 AND 255
           OR NEW.locked_by ~ '[[:cntrl:]]'
           OR NEW.locked_at_ms <= OLD.locked_at_ms
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'secret cleanup takeover is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_cleanup_takeover_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'in_progress' AND NEW.status IN ('pending', 'dead_letter') THEN
        IF NEW.attempts IS DISTINCT FROM OLD.attempts
           OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation
           OR NEW.next_attempt_at_ms <= OLD.locked_at_ms
           OR NEW.next_attempt_at_ms > OLD.locked_at_ms + 86400000
           OR NEW.locked_by IS NOT NULL
           OR NEW.locked_at_ms IS NOT NULL
           OR NEW.last_failure_kind IS NULL
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'secret cleanup retry is not fence-bound'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_cleanup_retry_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'in_progress' AND NEW.status = 'completed' THEN
        IF NEW.attempts IS DISTINCT FROM OLD.attempts
           OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation
           OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
           OR NEW.locked_by IS NOT NULL
           OR NEW.locked_at_ms IS NOT NULL
           OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
           OR NEW.completed_at_ms < OLD.locked_at_ms THEN
            RAISE EXCEPTION 'secret cleanup completion is not fence-bound'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_cleanup_completion_exact';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid secret cleanup transition'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_cleanup_transition_exact';
END;
$$;

CREATE FUNCTION automata_secret_custody_canary_require_fresh_key() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- A concurrent exact first writer is resolved by the primary key. Do not
    -- reject that replay merely because a write composed after its winner has
    -- already begun using the now-attested identity.
    IF EXISTS (
        SELECT 1 FROM secret_custody_key_canaries
        WHERE wrapping_key_id = NEW.wrapping_key_id
    ) THEN
        RETURN NEW;
    END IF;

    IF EXISTS (
        SELECT 1 FROM secret_provider_configuration_envelopes
        WHERE wrapping_key_id = NEW.wrapping_key_id
    ) OR EXISTS (
        SELECT 1 FROM secret_provider_locator_envelopes
        WHERE wrapping_key_id = NEW.wrapping_key_id
    ) OR EXISTS (
        SELECT 1 FROM secret_provider_version_envelopes
        WHERE wrapping_key_id = NEW.wrapping_key_id
    ) OR EXISTS (
        SELECT 1 FROM secret_version_envelopes
        WHERE wrapping_key_id = NEW.wrapping_key_id
    ) OR EXISTS (
        SELECT 1 FROM secret_provider_lease_envelopes
        WHERE wrapping_key_id = NEW.wrapping_key_id
    ) OR EXISTS (
        SELECT 1 FROM secret_key_rotations
        WHERE from_wrapping_key_id = NEW.wrapping_key_id
           OR to_wrapping_key_id = NEW.wrapping_key_id
    ) THEN
        RAISE EXCEPTION 'referenced secret custody keys require a prior canary'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_custody_key_canaries_fresh_key';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_secret_custody_key_canaries_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'secret custody key canaries are immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_custody_key_canaries_immutable';
END;
$$;

CREATE FUNCTION automata_secret_descriptor_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.canonical_name IS DISTINCT FROM OLD.canonical_name
       OR NEW.scope_kind IS DISTINCT FROM OLD.scope_kind
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
       OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
       OR NEW.created_by_principal_id IS DISTINCT FROM OLD.created_by_principal_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'logical secret descriptors are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secrets_descriptor_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE job_environment_gates (
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    run_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    logical_job_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    job_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    environment_requirement_kind text NOT NULL,
    environment_template_digest bytea,
    environment_id uuid,
    environment_revision bigint,
    approval_request_id uuid,
    event_trust text DEFAULT 'unknown'::text NOT NULL,
    source_kind text DEFAULT 'unknown'::text NOT NULL,
    invocation_kind text NOT NULL,
    reusable_secret_permission text DEFAULT 'none'::text NOT NULL,
    state text NOT NULL,
    resolution_digest bytea,
    resolved_secret_count integer,
    missing_secret_count integer,
    resolved_variable_count integer,
    missing_variable_count integer,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    CONSTRAINT job_environment_gates_environment_shape CHECK (((((environment_requirement_kind = ANY (ARRAY['unclassified'::text, 'none'::text])) AND (environment_template_digest IS NULL) AND (environment_id IS NULL) AND (environment_revision IS NULL) AND (approval_request_id IS NULL)) OR ((environment_requirement_kind = 'environment'::text) AND (octet_length(environment_template_digest) = 32) AND (((state = 'selection_pending'::text) AND (environment_id IS NULL) AND (environment_revision IS NULL) AND (approval_request_id IS NULL)) OR ((state = 'cancelled'::text) AND (((environment_id IS NULL) AND (environment_revision IS NULL) AND (approval_request_id IS NULL)) OR ((environment_id IS NOT NULL) AND (environment_revision > 0)))) OR ((state <> ALL (ARRAY['selection_pending'::text, 'cancelled'::text])) AND (environment_id IS NOT NULL) AND (environment_revision > 0))))) IS TRUE)),
    CONSTRAINT job_environment_gates_event_trust CHECK ((event_trust = ANY (ARRAY['unknown'::text, 'trusted'::text, 'untrusted'::text]))),
    CONSTRAINT job_environment_gates_invocation_kind CHECK ((invocation_kind = ANY (ARRAY['direct'::text, 'reusable'::text]))),
    CONSTRAINT job_environment_gates_requirement CHECK ((environment_requirement_kind = ANY (ARRAY['unclassified'::text, 'none'::text, 'environment'::text]))),
    CONSTRAINT job_environment_gates_resolution_shape CHECK (((((state = 'ready'::text) AND (octet_length(resolution_digest) = 32) AND (resolved_secret_count >= 0) AND (missing_secret_count >= 0) AND (resolved_variable_count >= 0) AND (missing_variable_count >= 0)) OR ((state <> 'ready'::text) AND (resolution_digest IS NULL) AND (resolved_secret_count IS NULL) AND (missing_secret_count IS NULL) AND (resolved_variable_count IS NULL) AND (missing_variable_count IS NULL))) IS TRUE)),
    CONSTRAINT job_environment_gates_reusable_permission CHECK (((reusable_secret_permission = ANY (ARRAY['none'::text, 'explicit'::text])) AND ((invocation_kind = 'reusable'::text) OR (reusable_secret_permission = 'none'::text)))),
    CONSTRAINT job_environment_gates_revision_positive CHECK ((revision > 0)),
    CONSTRAINT job_environment_gates_source_kind CHECK ((source_kind = ANY (ARRAY['same_repository'::text, 'fork'::text, 'dependabot'::text, 'unknown'::text]))),
    CONSTRAINT job_environment_gates_state CHECK ((state = ANY (ARRAY['unclassified'::text, 'selection_pending'::text, 'waiting'::text, 'resolving'::text, 'ready'::text, 'rejected'::text, 'expired'::text, 'cancelled'::text]))),
    CONSTRAINT job_environment_gates_time CHECK (((created_at_ms >= 0) AND (updated_at_ms >= created_at_ms)))
);

CREATE TABLE secret_policies (
    tenant_id text NOT NULL,
    secret_id uuid NOT NULL,
    secret_scope_kind text NOT NULL,
    tenant_repository_access_mode text DEFAULT 'selected_repositories'::text NOT NULL,
    minimum_event_trust text DEFAULT 'trusted'::text NOT NULL,
    allow_fork_pull_requests boolean DEFAULT false NOT NULL,
    allow_dependabot boolean DEFAULT false NOT NULL,
    reusable_workflow_mode text DEFAULT 'disabled'::text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    updated_by_principal_id uuid,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    CONSTRAINT secret_policies_event_trust CHECK ((minimum_event_trust = ANY (ARRAY['trusted'::text, 'untrusted'::text]))),
    CONSTRAINT secret_policies_repository_access_mode CHECK ((tenant_repository_access_mode = ANY (ARRAY['selected_repositories'::text, 'all_repositories'::text, 'scope_only'::text]))),
    CONSTRAINT secret_policies_reusable_workflow_mode CHECK ((reusable_workflow_mode = ANY (ARRAY['disabled'::text, 'explicit_only'::text]))),
    CONSTRAINT secret_policies_revision_positive CHECK ((revision > 0)),
    CONSTRAINT secret_policies_scope_access_shape CHECK ((((secret_scope_kind = 'tenant'::text) AND (tenant_repository_access_mode = ANY (ARRAY['selected_repositories'::text, 'all_repositories'::text]))) OR ((secret_scope_kind = ANY (ARRAY['repository'::text, 'environment'::text])) AND (tenant_repository_access_mode = 'scope_only'::text)))),
    CONSTRAINT secret_policies_time_monotonic CHECK ((updated_at_ms >= created_at_ms))
);

CREATE TABLE secrets (
    tenant_id text NOT NULL,
    id uuid NOT NULL,
    canonical_name text NOT NULL,
    scope_kind text NOT NULL,
    repository_id uuid,
    environment_id uuid,
    provider_id text NOT NULL,
    current_version_id uuid,
    current_version_number bigint,
    status text DEFAULT 'provisioning'::text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_by_principal_id uuid,
    updated_by_principal_id uuid,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    deleted_at_ms bigint,
    CONSTRAINT secrets_name_shape CHECK ((((octet_length(canonical_name) >= 1) AND (octet_length(canonical_name) <= 255)) AND (canonical_name ~ '^[A-Z_][A-Z0-9_]*$'::text) AND (canonical_name !~ '^(GITHUB_|ACTIONS_|RUNNER_|AUTOMATA_)'::text))),
    CONSTRAINT secrets_revision_positive CHECK ((revision > 0)),
    CONSTRAINT secrets_scope_kind CHECK ((scope_kind = ANY (ARRAY['tenant'::text, 'repository'::text, 'environment'::text]))),
    CONSTRAINT secrets_scope_shape CHECK (((((scope_kind = 'tenant'::text) AND (repository_id IS NULL) AND (environment_id IS NULL)) OR ((scope_kind = 'repository'::text) AND (repository_id IS NOT NULL) AND (environment_id IS NULL)) OR ((scope_kind = 'environment'::text) AND (repository_id IS NOT NULL) AND (environment_id IS NOT NULL))) IS TRUE)),
    CONSTRAINT secrets_status CHECK ((status = ANY (ARRAY['provisioning'::text, 'active'::text, 'disabled'::text, 'deleted'::text]))),
    CONSTRAINT secrets_status_shape CHECK (((((status = 'provisioning'::text) AND (current_version_id IS NULL) AND (current_version_number IS NULL) AND (deleted_at_ms IS NULL)) OR ((status = ANY (ARRAY['active'::text, 'disabled'::text])) AND (current_version_id IS NOT NULL) AND (current_version_number > 0) AND (deleted_at_ms IS NULL)) OR ((status = 'deleted'::text) AND (((current_version_id IS NULL) AND (current_version_number IS NULL)) OR ((current_version_id IS NOT NULL) AND (current_version_number > 0))) AND (deleted_at_ms >= created_at_ms))) IS TRUE)),
    CONSTRAINT secrets_time_monotonic CHECK ((updated_at_ms >= created_at_ms))
);

CREATE FUNCTION automata_secret_is_available_to_gate(target_secret secrets, target_policy secret_policies, target_gate job_environment_gates) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
SELECT (target_secret).status = 'active'
   AND (target_secret).current_version_id IS NOT NULL
   AND (target_policy).minimum_event_trust IN ('trusted', 'untrusted')
   AND ((target_policy).minimum_event_trust <> 'trusted'
        OR (target_gate).event_trust = 'trusted')
   AND ((target_gate).source_kind <> 'fork' OR (target_policy).allow_fork_pull_requests)
   AND ((target_gate).source_kind <> 'dependabot' OR (target_policy).allow_dependabot)
   AND (target_gate).source_kind <> 'unknown'
   AND (
       (target_gate).invocation_kind = 'direct'
       OR (
           (target_gate).reusable_secret_permission = 'explicit'
           AND (target_policy).reusable_workflow_mode = 'explicit_only'
           AND automata_reusable_secret_identity_chain_is_exact(
               (target_gate).run_id,
               (target_gate).invocation_id,
               (target_secret).canonical_name
           )
       )
   )
   AND (
       ((target_secret).scope_kind = 'environment'
        AND (target_secret).repository_id = (target_gate).repository_id
        AND (target_secret).environment_id = (target_gate).environment_id)
       OR ((target_secret).scope_kind = 'repository'
           AND (target_secret).repository_id = (target_gate).repository_id)
       OR ((target_secret).scope_kind = 'tenant'
           AND ((target_policy).tenant_repository_access_mode = 'all_repositories'
                OR EXISTS (
                    SELECT 1 FROM secret_repository_access AS access
                    WHERE access.tenant_id = (target_secret).tenant_id
                      AND access.secret_id = (target_secret).id
                      AND access.repository_id = (target_gate).repository_id
                )))
   );
$$;

CREATE FUNCTION automata_secret_mutation_recovery_deferred_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    mutation_row secret_version_mutations%ROWTYPE;
    recovery_row secret_mutation_recovery_outbox%ROWTYPE;
BEGIN
    SELECT * INTO mutation_row
    FROM secret_version_mutations
    WHERE tenant_id = NEW.tenant_id AND mutation_id = NEW.mutation_id;

    SELECT * INTO recovery_row
    FROM secret_mutation_recovery_outbox
    WHERE tenant_id = NEW.tenant_id AND mutation_id = NEW.mutation_id;

    IF mutation_row.mutation_id IS NULL
       OR recovery_row.mutation_id IS NULL
       OR recovery_row.created_at_ms <> mutation_row.reserved_at_ms
       OR recovery_row.next_attempt_at_ms <> mutation_row.confirmation_deadline_ms
       OR (
           mutation_row.state = 'reserved'
           AND recovery_row.status NOT IN ('pending', 'in_progress')
       )
       OR (
           mutation_row.state <> 'reserved'
           AND recovery_row.status <> 'completed'
       ) THEN
        RAISE EXCEPTION 'secret mutation recovery schedule is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_mutation_recovery_schedule_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_secret_mutation_recovery_delete_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'secret mutation recovery receipts cannot be deleted'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_mutation_recovery_delete_forbidden';
END;
$$;

CREATE FUNCTION automata_secret_mutation_recovery_insert_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    greatest_reserved_number BIGINT;
    session_revision BIGINT;
    session_principal UUID;
BEGIN
    SELECT authorization_revision, principal_id
    INTO session_revision, session_principal
    FROM human_sessions
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.reserved_by_session_id
    FOR SHARE;

    IF session_principal IS DISTINCT FROM NEW.reserved_by_principal_id
       OR session_revision IS DISTINCT FROM NEW.reserved_authorization_revision THEN
        RAISE EXCEPTION 'secret mutation reserver evidence is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_reserver_exact';
    END IF;

    SELECT max(reserved_version_number)
    INTO greatest_reserved_number
    FROM secret_version_mutations
    WHERE tenant_id = NEW.tenant_id AND secret_id = NEW.secret_id;

    IF (
        NEW.mutation_kind = 'create'
        AND (greatest_reserved_number IS NOT NULL OR NEW.reserved_version_number <> 1)
    ) OR (
        NEW.mutation_kind = 'replace'
        AND (
            greatest_reserved_number < NEW.expected_predecessor_version_number
            OR NEW.reserved_version_number IS DISTINCT FROM CASE
                WHEN greatest_reserved_number < 9223372036854775807
                    THEN greatest_reserved_number + 1
                ELSE NULL
            END
        )
    ) THEN
        RAISE EXCEPTION 'secret mutation version reservation is not the next attempt ordinal'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_reserved_version_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_secret_mutation_recovery_operation_id(text, uuid) RETURNS uuid
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
WITH raw(bytes) AS (
    SELECT substring(
        sha256(
            convert_to('automata.store.secret-mutation-recovery.v1', 'UTF8')
            || decode('00', 'hex')
            || int8send(octet_length(convert_to($1, 'UTF8'))::BIGINT)
            || convert_to($1, 'UTF8')
            || uuid_send($2)
        )
        FROM 1 FOR 16
    )
), shaped(bytes) AS (
    SELECT set_byte(
        set_byte(bytes, 6, (get_byte(bytes, 6) & 15) | 128),
        8,
        (get_byte(bytes, 8) & 63) | 128
    )
    FROM raw
), encoded(hex) AS (
    SELECT encode(bytes, 'hex') FROM shaped
)
SELECT (
    substring(hex FROM 1 FOR 8) || '-' ||
    substring(hex FROM 9 FOR 4) || '-' ||
    substring(hex FROM 13 FOR 4) || '-' ||
    substring(hex FROM 17 FOR 4) || '-' ||
    substring(hex FROM 21 FOR 12)
)::UUID
FROM encoded
$_$;

CREATE FUNCTION automata_secret_mutation_recovery_transition_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    mutation_state TEXT;
    mutation_completion TEXT;
    mutation_reason TEXT;
    mutation_completed_at BIGINT;
    expected_resolution TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending'
           OR NEW.attempts <> 0
           OR NEW.claim_generation <> 0
           OR NEW.locked_by IS NOT NULL
           OR NEW.locked_at_ms IS NOT NULL
           OR NEW.completed_by IS NOT NULL
           OR NEW.completed_claim_generation IS NOT NULL
           OR NEW.completed_locked_at_ms IS NOT NULL
           OR NEW.resolution IS NOT NULL
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'secret mutation recovery must begin pending'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_mutation_recovery_initial_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.sequence IS DISTINCT FROM OLD.sequence
       OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.mutation_id IS DISTINCT FROM OLD.mutation_id
       OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'secret mutation recovery identity and timing are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_mutation_recovery_identity_immutable';
    END IF;

    IF OLD.status = 'pending' AND NEW.status = 'in_progress' THEN
        IF OLD.attempts <> 0
           OR OLD.claim_generation <> 0
           OR NEW.attempts <> 1
           OR NEW.claim_generation <> 1
           OR octet_length(NEW.locked_by) NOT BETWEEN 1 AND 255
           OR NEW.locked_by ~ '[[:cntrl:]]'
           OR NEW.locked_at_ms < OLD.next_attempt_at_ms
           OR NEW.completed_by IS NOT NULL
           OR NEW.completed_claim_generation IS NOT NULL
           OR NEW.completed_locked_at_ms IS NOT NULL
           OR NEW.resolution IS NOT NULL
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'secret mutation recovery initial claim is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_mutation_recovery_claim_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'in_progress' AND NEW.status = 'in_progress' THEN
        IF NEW.attempts IS DISTINCT FROM OLD.attempts
           OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation + 1
           OR octet_length(NEW.locked_by) NOT BETWEEN 1 AND 255
           OR NEW.locked_by ~ '[[:cntrl:]]'
           OR NEW.locked_at_ms <= OLD.locked_at_ms
           OR NEW.completed_by IS DISTINCT FROM OLD.completed_by
           OR NEW.completed_claim_generation IS DISTINCT FROM OLD.completed_claim_generation
           OR NEW.completed_locked_at_ms IS DISTINCT FROM OLD.completed_locked_at_ms
           OR NEW.resolution IS DISTINCT FROM OLD.resolution
           OR NEW.completed_at_ms IS DISTINCT FROM OLD.completed_at_ms THEN
            RAISE EXCEPTION 'secret mutation recovery takeover is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_mutation_recovery_takeover_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status IN ('pending', 'in_progress') AND NEW.status = 'completed' THEN
        SELECT state, completion_kind, terminal_reason, confirmed_at_ms
        INTO mutation_state, mutation_completion, mutation_reason, mutation_completed_at
        FROM secret_version_mutations
        WHERE tenant_id = OLD.tenant_id AND mutation_id = OLD.mutation_id;

        IF mutation_state IS NULL OR mutation_state = 'reserved'
           OR NEW.attempts IS DISTINCT FROM OLD.attempts
           OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation
           OR NEW.locked_by IS NOT NULL
           OR NEW.locked_at_ms IS NOT NULL
           OR NEW.completed_at_ms IS DISTINCT FROM mutation_completed_at THEN
            RAISE EXCEPTION 'secret mutation recovery completion has no exact terminal receipt'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_mutation_recovery_completion_exact';
        END IF;

        IF mutation_completion = 'reservation_expired' THEN
            expected_resolution := CASE mutation_reason
                WHEN 'reservation_expired_no_stage' THEN 'expired_without_stage'
                WHEN 'reservation_expired_staged' THEN 'expired_with_cleanup'
                ELSE NULL
            END;
            IF OLD.status <> 'in_progress'
               OR expected_resolution IS NULL
               OR NEW.resolution IS DISTINCT FROM expected_resolution
               OR NEW.completed_by IS DISTINCT FROM OLD.locked_by
               OR NEW.completed_claim_generation IS DISTINCT FROM OLD.claim_generation
               OR NEW.completed_locked_at_ms IS DISTINCT FROM OLD.locked_at_ms THEN
                RAISE EXCEPTION 'secret mutation recovery expiry is not fence-bound'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_mutation_recovery_expiry_fence_exact';
            END IF;
        ELSIF NEW.resolution IS DISTINCT FROM 'human_terminal'
              OR NEW.completed_by IS NOT NULL
              OR NEW.completed_claim_generation IS NOT NULL
              OR NEW.completed_locked_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'human terminal recovery closure is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_mutation_recovery_human_terminal_exact';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid secret mutation recovery transition'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_mutation_recovery_transition_exact';
END;
$$;

CREATE FUNCTION automata_secret_mutation_terminal_deferred_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    secret_row secrets%ROWTYPE;
    lifecycle_status TEXT;
BEGIN
    IF NEW.state <> 'cancelled' THEN
        RETURN NULL;
    END IF;

    SELECT * INTO secret_row
    FROM secrets
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id;

    IF NEW.completion_kind = 'system_cancelled' THEN
        IF secret_row.status IS DISTINCT FROM 'deleted' THEN
            RAISE EXCEPTION 'deletion cancellation committed without deleted descriptor'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_delete_terminal';
        END IF;
    ELSIF NEW.completion_kind = 'reservation_expired' THEN
        IF NEW.abandoned_version_id IS NOT NULL THEN
            SELECT status INTO lifecycle_status
            FROM secret_version_lifecycle
            WHERE tenant_id = NEW.tenant_id
              AND secret_version_id = NEW.abandoned_version_id;
            IF lifecycle_status NOT IN ('destroy_pending', 'destroyed') THEN
                RAISE EXCEPTION 'expired staged candidate was not handed to erasure'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_expiry_cleanup';
            END IF;
        END IF;

        IF NEW.mutation_kind = 'create' THEN
            IF secret_row.status IS DISTINCT FROM 'deleted'
               OR secret_row.current_version_id IS NOT NULL
               OR secret_row.current_version_number IS NOT NULL THEN
                RAISE EXCEPTION 'expired creation retained a live descriptor'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_expiry_descriptor';
            END IF;
        ELSIF secret_row.status NOT IN ('active', 'disabled')
              OR (
                  NEW.abandoned_version_id IS NOT NULL
                  AND secret_row.current_version_id = NEW.abandoned_version_id
              ) THEN
            RAISE EXCEPTION 'expired replacement changed the logical head'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_expiry_descriptor';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_secret_provider_configuration_delete_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM secret_provider_configuration_envelope_heads
        WHERE tenant_id = OLD.tenant_id
          AND provider_id = OLD.provider_id
          AND envelope_generation = OLD.envelope_generation
    ) THEN
        RAISE EXCEPTION 'current provider configuration envelope cannot be removed'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_provider_configuration_envelopes_current';
    END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION automata_secret_provider_configuration_envelopes_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'secret provider configuration envelopes are immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_provider_configuration_envelopes_immutable';
END;
$$;

CREATE FUNCTION automata_secret_provider_lease_delete_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    lease_status TEXT;
BEGIN
    SELECT status
    INTO STRICT lease_status
    FROM secret_provider_leases
    WHERE tenant_id = OLD.tenant_id
      AND id = OLD.provider_lease_record_id;

    IF lease_status NOT IN ('revoked', 'expired') THEN
        RAISE EXCEPTION 'provider lease handles may only be removed when terminal'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_provider_lease_envelopes_terminal_lease';
    END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION automata_secret_provider_locator_delete_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    secret_status TEXT;
BEGIN
    SELECT status
    INTO STRICT secret_status
    FROM secrets
    WHERE tenant_id = OLD.tenant_id
      AND id = OLD.secret_id;

    IF secret_status <> 'deleted' THEN
        RAISE EXCEPTION 'provider locators may only be removed for deleted secrets'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_provider_locator_envelopes_deleted_secret';
    END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION automata_secret_provider_reference_envelopes_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'secret provider reference envelopes are immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_provider_reference_envelopes_immutable';
END;
$$;

CREATE FUNCTION automata_secret_version_deferred_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    exact_stage_count BIGINT;
BEGIN
    IF NEW.provider_id <> 'builtin'
       OR NEW.storage_kind <> 'built_in_ciphertext' THEN
        RAISE EXCEPTION 'secret versions require the composed built-in mutation path'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_versions_mutation_stage_exact';
    END IF;

    SELECT count(*) INTO exact_stage_count
    FROM secret_version_lifecycle AS lifecycle
    JOIN secret_version_mutations AS mutation
      ON mutation.tenant_id = lifecycle.tenant_id
     AND mutation.mutation_id = lifecycle.mutation_id
     AND mutation.secret_id = lifecycle.secret_id
     AND mutation.provider_id = lifecycle.provider_id
    WHERE lifecycle.tenant_id = NEW.tenant_id
      AND lifecycle.secret_version_id = NEW.id
      AND lifecycle.secret_id = NEW.secret_id
      AND lifecycle.version_number = NEW.version_number
      AND lifecycle.provider_id = NEW.provider_id
      AND mutation.provider_create_request_id = NEW.create_request_id;

    IF exact_stage_count <> 1 THEN
        RAISE EXCEPTION 'secret version has no exact mutation stage'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_versions_mutation_stage_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_secret_version_envelope_delete_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    lifecycle_status TEXT;
BEGIN
    SELECT status
    INTO STRICT lifecycle_status
    FROM secret_version_lifecycle
    WHERE tenant_id = OLD.tenant_id
      AND secret_version_id = OLD.secret_version_id;

    IF lifecycle_status <> 'destroy_pending' THEN
        RAISE EXCEPTION 'secret version envelopes may only be cryptographically destroyed'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_envelopes_destroy_pending';
    END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION automata_secret_version_envelopes_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'secret version envelopes are immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_version_envelopes_immutable';
END;
$$;

CREATE FUNCTION automata_secret_version_lifecycle_deferred_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    secret_row secrets%ROWTYPE;
    mutation_row secret_version_mutations%ROWTYPE;
    builtin_head_count BIGINT;
    external_reference_count BIGINT;
    expired_cleanup BOOLEAN;
BEGIN
    SELECT * INTO secret_row
    FROM secrets
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id;
    SELECT * INTO mutation_row
    FROM secret_version_mutations
    WHERE tenant_id = NEW.tenant_id AND mutation_id = NEW.mutation_id;

    SELECT count(*) INTO builtin_head_count
    FROM secret_version_envelope_heads AS head
    JOIN secret_version_envelopes AS envelope
      ON envelope.tenant_id = head.tenant_id
     AND envelope.secret_version_id = head.secret_version_id
     AND envelope.envelope_generation = head.envelope_generation
    WHERE head.tenant_id = NEW.tenant_id
      AND head.secret_version_id = NEW.secret_version_id;

    SELECT
        (SELECT count(*) FROM secret_provider_locator_envelopes
         WHERE tenant_id = NEW.tenant_id AND secret_id = NEW.secret_id)
      + (SELECT count(*) FROM secret_provider_locator_envelope_heads
         WHERE tenant_id = NEW.tenant_id AND secret_id = NEW.secret_id)
      + (SELECT count(*) FROM secret_provider_version_envelopes
         WHERE tenant_id = NEW.tenant_id
           AND secret_version_id = NEW.secret_version_id)
      + (SELECT count(*) FROM secret_provider_version_envelope_heads
         WHERE tenant_id = NEW.tenant_id
           AND secret_version_id = NEW.secret_version_id)
    INTO external_reference_count;

    IF secret_row.id IS NULL
       OR mutation_row.mutation_id IS NULL
       OR mutation_row.secret_id <> NEW.secret_id
       OR mutation_row.provider_id <> NEW.provider_id
       OR mutation_row.reserved_version_number <> NEW.version_number
       OR secret_row.scope_kind <> mutation_row.scope_kind
       OR secret_row.repository_id IS DISTINCT FROM mutation_row.repository_id
       OR secret_row.environment_id IS DISTINCT FROM mutation_row.environment_id
       OR secret_row.canonical_name <> mutation_row.canonical_name
       OR builtin_head_count <> (CASE WHEN NEW.status = 'destroyed' THEN 0 ELSE 1 END)
       OR external_reference_count <> 0 THEN
        RAISE EXCEPTION 'secret lifecycle lost its exact encrypted mutation join'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_deferred_exact';
    END IF;

    IF NEW.status = 'staged' THEN
        IF mutation_row.state <> 'reserved'
           OR secret_row.revision <> mutation_row.reserved_secret_revision
           OR secret_row.current_version_id IS DISTINCT FROM mutation_row.expected_predecessor_version_id
           OR secret_row.current_version_number IS DISTINCT FROM mutation_row.expected_predecessor_version_number THEN
            RAISE EXCEPTION 'staged lifecycle committed without its reservation'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_deferred_state';
        END IF;
    ELSIF NEW.status IN ('active', 'disabled') THEN
        IF mutation_row.state <> 'confirmed'
           OR mutation_row.committed_version_id IS DISTINCT FROM NEW.secret_version_id
           OR mutation_row.committed_version_number IS DISTINCT FROM NEW.version_number
           OR mutation_row.confirmed_secret_revision <> mutation_row.reserved_secret_revision + 1
           OR secret_row.status IS DISTINCT FROM NEW.status
           OR secret_row.current_version_id IS DISTINCT FROM NEW.secret_version_id
           OR secret_row.current_version_number IS DISTINCT FROM NEW.version_number THEN
            RAISE EXCEPTION 'active lifecycle committed without its exact receipt'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_deferred_state';
        END IF;
    ELSIF NEW.status = 'superseded' THEN
        IF mutation_row.state <> 'superseded'
           OR mutation_row.committed_version_id IS DISTINCT FROM NEW.secret_version_id
           OR mutation_row.committed_version_number IS DISTINCT FROM NEW.version_number
           OR mutation_row.terminal_reason NOT IN (
                'applied_then_superseded', 'applied_then_deleted'
           )
           OR (
               mutation_row.terminal_reason = 'applied_then_superseded'
               AND (
                   secret_row.status NOT IN ('active', 'disabled')
                   OR secret_row.current_version_number <= NEW.version_number
               )
           )
           OR (
               mutation_row.terminal_reason = 'applied_then_deleted'
               AND secret_row.status <> 'deleted'
           ) THEN
            RAISE EXCEPTION 'superseded lifecycle committed without its exact receipt'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_deferred_state';
        END IF;
    ELSIF NEW.status IN ('destroy_pending', 'destroyed') THEN
        expired_cleanup := (
            mutation_row.state = 'cancelled'
            AND mutation_row.completion_kind = 'reservation_expired'
            AND mutation_row.terminal_reason = 'reservation_expired_staged'
            AND mutation_row.abandoned_version_id = NEW.secret_version_id
            AND mutation_row.abandoned_version_number = NEW.version_number
            AND (
                (
                    mutation_row.mutation_kind = 'create'
                    AND secret_row.status = 'deleted'
                    AND secret_row.current_version_id IS NULL
                    AND secret_row.current_version_number IS NULL
                ) OR (
                    mutation_row.mutation_kind = 'replace'
                    AND secret_row.status IN ('active', 'disabled')
                    AND secret_row.current_version_id IS DISTINCT FROM NEW.secret_version_id
                )
            )
        );
        IF NOT (
            (
                secret_row.status = 'deleted'
                AND (
                    (
                        mutation_row.state = 'cancelled'
                        AND mutation_row.completion_kind = 'system_cancelled'
                        AND mutation_row.terminal_reason = 'secret_deleted'
                    ) OR (
                        mutation_row.state = 'superseded'
                        AND mutation_row.completion_kind = 'builtin_created'
                        AND mutation_row.terminal_reason IN (
                            'applied_then_superseded', 'applied_then_deleted'
                        )
                    )
                )
            ) OR expired_cleanup
        ) THEN
            RAISE EXCEPTION 'destroy lifecycle committed without exact terminalization'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_deferred_state';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_secret_version_lifecycle_delete_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'secret version lifecycle rows are append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_version_lifecycle_append_only';
END;
$$;

CREATE FUNCTION automata_secret_version_lifecycle_insert_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    secret_row secrets%ROWTYPE;
    mutation_row secret_version_mutations%ROWTYPE;
    version_row secret_versions%ROWTYPE;
    predecessor_status TEXT;
    predecessor_receipt_count BIGINT;
BEGIN
    IF NEW.mutation_id IS NULL OR NEW.status <> 'staged' THEN
        RAISE EXCEPTION 'new secret versions must begin as a staged mutation candidate'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_initial_staged';
    END IF;

    SELECT * INTO secret_row
    FROM secrets
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id
    FOR UPDATE;

    SELECT * INTO mutation_row
    FROM secret_version_mutations
    WHERE tenant_id = NEW.tenant_id AND mutation_id = NEW.mutation_id
    FOR SHARE;

    SELECT * INTO version_row
    FROM secret_versions
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_version_id
    FOR SHARE;

    IF secret_row.id IS NULL
       OR mutation_row.mutation_id IS NULL
       OR version_row.id IS NULL
       OR mutation_row.state <> 'reserved'
       OR mutation_row.secret_id <> NEW.secret_id
       OR mutation_row.provider_id <> NEW.provider_id
       OR mutation_row.reserved_version_number <> NEW.version_number
       OR mutation_row.provider_create_request_id <> version_row.create_request_id
       OR version_row.secret_id <> NEW.secret_id
       OR version_row.version_number <> NEW.version_number
       OR version_row.provider_id <> NEW.provider_id
       OR version_row.storage_kind <> 'built_in_ciphertext'
       OR secret_row.scope_kind <> mutation_row.scope_kind
       OR secret_row.repository_id IS DISTINCT FROM mutation_row.repository_id
       OR secret_row.environment_id IS DISTINCT FROM mutation_row.environment_id
       OR secret_row.canonical_name <> mutation_row.canonical_name
       OR secret_row.provider_id <> mutation_row.provider_id THEN
        RAISE EXCEPTION 'staged secret version is not joined to its exact intent'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_staged_intent_exact';
    END IF;

    IF mutation_row.mutation_kind = 'create' THEN
        IF NEW.version_number <> 1
           OR secret_row.status <> 'provisioning'
           OR secret_row.revision <> mutation_row.reserved_secret_revision
           OR secret_row.current_version_id IS NOT NULL
           OR secret_row.current_version_number IS NOT NULL THEN
            RAISE EXCEPTION 'staged creation candidate has a stale descriptor'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_staged_head';
        END IF;
    ELSE
        SELECT status INTO predecessor_status
        FROM secret_version_lifecycle
        WHERE tenant_id = NEW.tenant_id
          AND secret_version_id = mutation_row.expected_predecessor_version_id
        FOR SHARE;

        SELECT count(*) INTO predecessor_receipt_count
        FROM secret_version_mutations
        WHERE tenant_id = NEW.tenant_id
          AND secret_id = NEW.secret_id
          AND state = 'confirmed'
          AND completion_kind = 'builtin_created'
          AND committed_version_id = mutation_row.expected_predecessor_version_id
          AND committed_version_number = mutation_row.expected_predecessor_version_number;

        IF secret_row.status <> 'active'
           OR secret_row.revision <> mutation_row.reserved_secret_revision
           OR secret_row.current_version_id IS DISTINCT FROM mutation_row.expected_predecessor_version_id
           OR secret_row.current_version_number IS DISTINCT FROM mutation_row.expected_predecessor_version_number
           OR NEW.version_number <> mutation_row.reserved_version_number
           OR NEW.version_number <= mutation_row.expected_predecessor_version_number
           OR predecessor_status IS DISTINCT FROM 'active'
           OR predecessor_receipt_count <> 1 THEN
            RAISE EXCEPTION 'staged replacement candidate has a stale predecessor'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_staged_head';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_secret_version_lifecycle_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    secret_row secrets%ROWTYPE;
    mutation_row secret_version_mutations%ROWTYPE;
    cleanup_is_valid BOOLEAN;
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.secret_version_id IS DISTINCT FROM OLD.secret_version_id
       OR NEW.secret_id IS DISTINCT FROM OLD.secret_id
       OR NEW.version_number IS DISTINCT FROM OLD.version_number
       OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
       OR NEW.mutation_id IS DISTINCT FROM OLD.mutation_id THEN
        RAISE EXCEPTION 'secret version lifecycle identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_identity_immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1
       OR NEW.changed_at_ms < OLD.changed_at_ms THEN
        RAISE EXCEPTION 'secret version lifecycle updates require monotonic CAS'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_cas';
    END IF;
    IF OLD.destroy_request_id IS NOT NULL
       AND NEW.destroy_request_id IS DISTINCT FROM OLD.destroy_request_id THEN
        RAISE EXCEPTION 'secret version destroy request identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_destroy_request_immutable';
    END IF;
    IF NOT (
        (OLD.status = 'staged' AND NEW.status IN ('active', 'destroy_pending'))
        OR (OLD.status = 'active' AND NEW.status IN ('superseded', 'disabled', 'destroy_pending'))
        OR (OLD.status = 'superseded' AND NEW.status IN ('disabled', 'destroy_pending'))
        OR (OLD.status = 'disabled' AND NEW.status IN ('active', 'destroy_pending'))
        OR (OLD.status = 'destroy_pending' AND NEW.status = 'destroyed')
    ) THEN
        RAISE EXCEPTION 'invalid secret version lifecycle transition'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_transition';
    END IF;

    IF OLD.status = 'staged' THEN
        SELECT * INTO secret_row
        FROM secrets
        WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id
        FOR UPDATE;
        SELECT * INTO mutation_row
        FROM secret_version_mutations
        WHERE tenant_id = NEW.tenant_id AND mutation_id = NEW.mutation_id
        FOR SHARE;

        IF NEW.status = 'active' THEN
            IF mutation_row.state <> 'reserved'
               OR NEW.version_number <> mutation_row.reserved_version_number
               OR secret_row.status <> (CASE mutation_row.mutation_kind
                   WHEN 'create' THEN 'provisioning' ELSE 'active' END)
               OR secret_row.revision <> mutation_row.reserved_secret_revision
               OR secret_row.current_version_id IS DISTINCT FROM mutation_row.expected_predecessor_version_id
               OR secret_row.current_version_number IS DISTINCT FROM mutation_row.expected_predecessor_version_number THEN
                RAISE EXCEPTION 'staged candidate promotion lost its reservation CAS'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_lifecycle_staged_promotion';
            END IF;
        ELSE
            cleanup_is_valid := (
                mutation_row.state = 'cancelled'
                AND (
                    (
                        mutation_row.completion_kind = 'system_cancelled'
                        AND mutation_row.terminal_reason = 'secret_deleted'
                        AND secret_row.status = 'deleted'
                    ) OR (
                        mutation_row.completion_kind = 'reservation_expired'
                        AND mutation_row.terminal_reason = 'reservation_expired_staged'
                        AND mutation_row.abandoned_version_id = NEW.secret_version_id
                        AND mutation_row.abandoned_version_number = NEW.version_number
                        AND (
                            (
                                mutation_row.mutation_kind = 'create'
                                AND secret_row.status = 'deleted'
                                AND secret_row.current_version_id IS NULL
                                AND secret_row.current_version_number IS NULL
                            ) OR (
                                mutation_row.mutation_kind = 'replace'
                                AND secret_row.status IN ('active', 'disabled')
                                AND secret_row.current_version_id IS DISTINCT FROM NEW.secret_version_id
                            )
                        )
                    )
                )
            );
            IF cleanup_is_valid IS NOT TRUE THEN
                RAISE EXCEPTION 'staged candidate cleanup requires exact cancellation'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_lifecycle_staged_cleanup';
            END IF;
        END IF;
    END IF;

    IF NEW.status = 'destroyed'
       AND (
           EXISTS (
               SELECT 1 FROM secret_version_envelopes
               WHERE tenant_id = NEW.tenant_id
                 AND secret_version_id = NEW.secret_version_id
           )
           OR EXISTS (
               SELECT 1 FROM secret_version_envelope_heads
               WHERE tenant_id = NEW.tenant_id
                 AND secret_version_id = NEW.secret_version_id
           )
           OR EXISTS (
               SELECT 1 FROM secret_provider_version_envelopes
               WHERE tenant_id = NEW.tenant_id
                 AND secret_version_id = NEW.secret_version_id
           )
           OR EXISTS (
               SELECT 1 FROM secret_provider_version_envelope_heads
               WHERE tenant_id = NEW.tenant_id
                 AND secret_version_id = NEW.secret_version_id
           )
       ) THEN
        RAISE EXCEPTION 'cryptographic material must be removed before destroy completes'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_crypto_destroyed';
    END IF;
    RETURN NEW;
END;
$$;
