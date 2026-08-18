-- Frozen greenfield baseline. Add a new migration instead of editing this stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_job_secret_binding_digest(target_attempt_id uuid, target_name text, target_tenant_id text, target_grant_id uuid, target_lease_id uuid, target_fencing_token bigint) RETURNS bytea
    LANGUAGE sql STABLE
    AS $_$
SELECT pg_catalog.sha256(
    convert_to('automata.store.job-secret-binding.v1', 'UTF8')
    || decode('00', 'hex') || uuid_send($1)
    || int4send(octet_length(convert_to($2, 'UTF8'))) || convert_to($2, 'UTF8')
    || int4send(octet_length(convert_to($3, 'UTF8'))) || convert_to($3, 'UTF8')
    || uuid_send($4) || uuid_send($5) || int8send($6)
    || workload_grant.authority_digest
    || int8send(workload_grant.expires_at_ms)
)
FROM secret_workload_grants AS workload_grant
WHERE workload_grant.tenant_id = $3 AND workload_grant.id = $4;
$_$;

CREATE FUNCTION automata_job_secret_selection_digest(target_attempt_id uuid, target_name text, target_tenant_id text, target_secret_id uuid, target_version_id uuid, target_version_number bigint, target_scope_kind text, target_environment_id uuid) RETURNS bytea
    LANGUAGE sql STABLE
    AS $_$
SELECT pg_catalog.sha256(
    convert_to('automata.store.job-secret-selection.v1', 'UTF8')
    || decode('00', 'hex') || uuid_send($1)
    || int4send(octet_length(convert_to($2, 'UTF8'))) || convert_to($2, 'UTF8')
    || int4send(octet_length(convert_to($3, 'UTF8'))) || convert_to($3, 'UTF8')
    || uuid_send($4) || uuid_send($5) || int8send($6)
    || int4send(octet_length(convert_to($7, 'UTF8'))) || convert_to($7, 'UTF8')
    || CASE WHEN $8 IS NULL THEN decode('00', 'hex')
            ELSE decode('01', 'hex') || uuid_send($8) END
    || int8send(policy.revision)
    || int8send(secret.revision)
    || int4send(octet_length(convert_to(gate.event_trust, 'UTF8')))
    || convert_to(gate.event_trust, 'UTF8')
    || int4send(octet_length(convert_to(gate.source_kind, 'UTF8')))
    || convert_to(gate.source_kind, 'UTF8')
    || int4send(octet_length(convert_to(gate.invocation_kind, 'UTF8')))
    || convert_to(gate.invocation_kind, 'UTF8')
)
FROM secrets AS secret
JOIN secret_policies AS policy
  ON policy.tenant_id = secret.tenant_id AND policy.secret_id = secret.id
JOIN job_environment_gates AS gate ON gate.attempt_id = $1
WHERE secret.tenant_id = $3 AND secret.id = $4
  AND secret.current_version_id = $5 AND secret.current_version_number = $6;
$_$;

CREATE FUNCTION automata_job_variable_binding_digest(target_attempt_id uuid, target_name text, target_tenant_id text, target_variable_id uuid, target_version_id uuid, target_version_number bigint, target_scope_kind text, target_environment_id uuid) RETURNS bytea
    LANGUAGE sql STABLE
    AS $_$
SELECT pg_catalog.sha256(
    convert_to('automata.store.job-variable-binding.v1', 'UTF8')
    || decode('00', 'hex') || uuid_send($1)
    || int4send(octet_length(convert_to($2, 'UTF8'))) || convert_to($2, 'UTF8')
    || int4send(octet_length(convert_to($3, 'UTF8'))) || convert_to($3, 'UTF8')
    || uuid_send($4) || uuid_send($5) || int8send($6)
    || int4send(octet_length(convert_to($7, 'UTF8'))) || convert_to($7, 'UTF8')
    || CASE WHEN $8 IS NULL THEN decode('00', 'hex')
            ELSE decode('01', 'hex') || uuid_send($8) END
    || version.value_ciphertext_sha256
    || int8send(version.value_size_bytes)
    || int2send(version.envelope_schema)
)
FROM workflow_variable_versions AS version
WHERE version.tenant_id = $3 AND version.id = $5
  AND version.variable_id = $4 AND version.version_number = $6;
$_$;

CREATE FUNCTION automata_lock_workload_oidc_authority_dependencies(authority workload_oidc_authorities) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    origin_visibility TEXT;
    private_authority_id UUID;
BEGIN
    SELECT origin.repository_visibility,
           origin.private_source_authority_id
      INTO origin_visibility, private_authority_id
    FROM job_attempts AS attempt
    JOIN jobs AS job
      ON job.id = attempt.job_id
     AND job.id = authority.job_id
     AND job.run_id = authority.run_id
    JOIN workflow_runs AS run
      ON run.id = job.run_id
     AND run.id = authority.run_id
     AND run.repository_id = authority.repository_id
    JOIN repositories AS repository
      ON repository.id = run.repository_id
     AND repository.tenant_id = authority.tenant_id
    JOIN workflow_definitions AS workflow
      ON workflow.id = run.workflow_id
     AND workflow.repository_id = run.repository_id
    JOIN workflow_snapshots AS snapshot
      ON snapshot.id = run.snapshot_id
     AND snapshot.workflow_id = run.workflow_id
    JOIN logical_workflow_runs AS marker ON marker.run_id = run.id
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
    JOIN runner_sessions AS session
      ON session.id = attempt.runner_session_id
     AND session.id = authority.runner_session_id
     AND session.runner_id = authority.runner_id
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
     AND checks_authority.provider_connection_id = origin.provider_connection_id
     AND checks_authority.provider_installation_id =
         origin.provider_installation_id
     AND checks_authority.github_repository_id = origin.github_repository_id
     AND checks_authority.github_repository_name =
         origin.github_repository_name
     AND checks_authority.service_scope = 'checks_write'
     AND checks_authority.identity_digest =
         origin.checks_authority_identity_digest
     AND checks_authority.app_configuration_revision =
         origin.checks_authority_app_configuration_revision
     AND checks_authority.policy_revision =
         origin.checks_authority_policy_revision
    WHERE attempt.id = authority.attempt_id
      AND materialization.state = 'materialized'
      AND (
          origin.origin_kind = 'provider_delivery'
          AND origin.admission_idempotency_kind = 'provider_delivery'
          OR origin.origin_kind IN ('scheduled_fire', 'workflow_rerun')
          AND origin.admission_idempotency_kind = 'operation'
      )
      AND logical_job.activation_input_digest = preparation.activation_input_digest
      AND preparation_claim.state = 'prepared'
      AND activation_publication.condition_matched
      AND automata_logical_workflow_invocation_published(
          run.id, invocation.id
      )
      AND automata_reusable_workflow_oidc_permission_authorized(
          run.id, invocation.id
      )
      AND manifest.authority_profile = 'standard'
      AND logical_job.authority_profile = 'standard'
      AND preparation_claim.authority_profile = 'standard'
      AND preparation.authority_profile = 'standard'
      AND activation_publication.authority_profile = 'standard'
      AND materialization.authority_profile = 'standard'
      AND concrete.authority_profile = 'standard'
      AND checks_authority.state = 'active'
    FOR SHARE OF attempt, job, run, repository, workflow, snapshot, marker,
                 invocation, logical_job, preparation_claim, preparation,
                 activation_publication, instance, concrete, materialization,
                 runner, session,
                 admission_receipt, manifest, checks_authority;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    IF origin_visibility = 'public' THEN
        RETURN private_authority_id IS NULL;
    END IF;
    IF origin_visibility <> 'private' OR private_authority_id IS NULL THEN
        RETURN FALSE;
    END IF;

    PERFORM 1
    FROM github_workflow_run_manifest_origins AS origin
    JOIN github_server_service_authorities AS private_authority
      ON private_authority.tenant_id = origin.tenant_id
     AND private_authority.id = origin.private_source_authority_id
     AND private_authority.repository_id = origin.repository_id
     AND private_authority.provider_connection_id =
         origin.provider_connection_id
     AND private_authority.provider_installation_id =
         origin.provider_installation_id
     AND private_authority.github_repository_id =
         origin.github_repository_id
     AND private_authority.github_repository_name =
         origin.github_repository_name
     AND private_authority.service_scope = 'private_repository_source_read'
     AND private_authority.identity_digest =
         origin.private_source_authority_identity_digest
     AND private_authority.app_configuration_revision =
         origin.private_source_authority_app_configuration_revision
     AND private_authority.policy_revision =
         origin.private_source_authority_policy_revision
    WHERE origin.tenant_id = authority.tenant_id
      AND origin.repository_id = authority.repository_id
      AND origin.workflow_id = authority.workflow_id
      AND origin.run_id = authority.run_id
      AND origin.subject_evidence_sha256 =
          authority.github_run_subject_evidence_sha256
      AND origin.private_source_authority_id = private_authority_id
      AND private_authority.state = 'active'
    FOR SHARE OF private_authority;
    RETURN FOUND;
END;
$$;

CREATE FUNCTION automata_lock_reusable_call_output_contract() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM 1
    FROM logical_workflow_runs AS marker
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN logical_workflow_reusable_invocation_expansions AS expansion
      ON expansion.run_id = marker.run_id
     AND expansion.invocation_id = NEW.child_invocation_id
    WHERE marker.run_id = NEW.run_id
      AND marker.admission_graph_sealed_at_ms IS NOT NULL
      AND marker.state IN ('pending', 'active')
      AND run.status IN ('queued', 'in_progress')
      AND expansion.depth > 0
      AND NOT EXISTS (
          SELECT 1 FROM logical_workflow_run_result_claims AS claim
          WHERE claim.run_id = marker.run_id
      )
    FOR UPDATE OF marker, run;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'reusable call output contract lacks a live planned call'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_call_output_contract_window';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_lock_reusable_call_publication() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM 1
    FROM logical_workflow_runs AS marker
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    JOIN logical_workflow_invocations AS parent
      ON parent.run_id = marker.run_id
     AND parent.id = NEW.parent_invocation_id
    JOIN logical_workflow_jobs AS caller
      ON caller.run_id = parent.run_id
     AND caller.invocation_id = parent.id
     AND caller.id = NEW.caller_logical_job_id
    JOIN logical_workflow_runtime_policy_pins AS pin
      ON pin.run_id = marker.run_id
    JOIN logical_workflow_reusable_invocation_expansions AS planned
      ON planned.run_id = caller.run_id
     AND planned.parent_invocation_id = caller.invocation_id
     AND planned.caller_logical_job_id = caller.id
     AND planned.invocation_id = NEW.child_invocation_id
    JOIN logical_workflow_reusable_permission_snapshots AS permissions
      ON permissions.run_id = planned.run_id
     AND permissions.invocation_id = planned.invocation_id
    JOIN logical_workflow_reusable_call_output_contracts AS output_contract
      ON output_contract.run_id = planned.run_id
     AND output_contract.child_invocation_id = planned.invocation_id
    WHERE marker.run_id = NEW.run_id
      AND repository.tenant_id = NEW.tenant_id
      AND repository.id = NEW.repository_id
      AND marker.admission_graph_sealed_at_ms IS NOT NULL
      AND marker.state IN ('pending', 'active')
      AND run.status IN ('queued', 'in_progress')
      AND parent.state IN ('pending', 'active')
      AND caller.execution_kind = 'reusable_workflow'
      AND caller.state = 'pending'
      AND caller.activation_fence = 0
      AND caller.activation_owner_id IS NULL
      AND caller.activation_claimed_at_ms IS NULL
      AND caller.activation_expires_at_ms IS NULL
      AND caller.activation_input_digest IS NULL
      AND caller.activation_origin_selection_id IS NULL
      AND planned.depth > 0
      AND permissions.permission_digest = NEW.permission_digest
      AND output_contract.mapping_count = NEW.output_mapping_count
      AND output_contract.mapping_digest = NEW.output_mapping_digest
      AND pin.policy_revision = NEW.runtime_policy_revision
      AND pin.policy_digest = NEW.runtime_policy_digest
      AND NOT EXISTS (
          SELECT 1
          FROM logical_workflow_dependencies AS dependency
          LEFT JOIN logical_workflow_job_results AS result
            ON result.run_id = dependency.run_id
           AND result.invocation_id = dependency.invocation_id
           AND result.logical_job_id = dependency.prerequisite_job_id
          LEFT JOIN logical_workflow_job_result_claims AS claim
            ON claim.logical_job_id = result.logical_job_id
           AND claim.state = 'finalized'
          WHERE dependency.run_id = caller.run_id
            AND dependency.invocation_id = caller.invocation_id
            AND dependency.logical_job_id = caller.id
            AND (result.logical_job_id IS NULL OR claim.logical_job_id IS NULL)
      )
      AND NOT EXISTS (
          SELECT 1 FROM logical_workflow_run_result_claims AS claim
          WHERE claim.run_id = marker.run_id
      )
    FOR UPDATE OF marker, run, parent, caller;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'reusable call publication lacks a ready live parent instance'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_call_publication_window';
    END IF;
    IF NEW.child_graph_sealed_at_ms IS NOT NULL THEN
        RAISE EXCEPTION 'reusable child graph must begin unsealed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_call_publication_unsealed';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_lock_reusable_call_result() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    matched BOOLEAN;
    expected_conclusion TEXT;
BEGIN
    SELECT publication.condition_matched
      INTO matched
    FROM logical_workflow_reusable_call_publications AS publication
    JOIN logical_workflow_runs AS marker ON marker.run_id = publication.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    JOIN logical_workflow_jobs AS caller
      ON caller.run_id = publication.run_id
     AND caller.invocation_id = publication.parent_invocation_id
     AND caller.id = publication.caller_logical_job_id
    WHERE publication.run_id = NEW.run_id
      AND publication.parent_invocation_id = NEW.parent_invocation_id
      AND publication.caller_logical_job_id = NEW.caller_logical_job_id
      AND publication.caller_instance_id = NEW.caller_instance_id
      AND publication.child_invocation_id = NEW.child_invocation_id
      AND publication.operation_id = NEW.publication_operation_id
      AND publication.child_graph_sealed_at_ms IS NOT NULL
      AND repository.tenant_id = NEW.tenant_id
      AND repository.id = NEW.repository_id
      AND marker.state IN ('pending', 'active')
      AND run.status IN ('queued', 'in_progress')
      AND caller.state = CASE WHEN publication.condition_matched
          THEN 'activated' ELSE 'skipped' END
      AND caller.activation_fence = publication.activation_generation
      AND caller.activation_input_digest = publication.activation_input_digest
      AND caller.updated_at_ms = publication.published_at_ms
      AND NEW.completed_at_ms >= publication.published_at_ms
      AND NOT EXISTS (
          SELECT 1 FROM logical_workflow_run_result_claims AS claim
          WHERE claim.run_id = marker.run_id
      )
    FOR UPDATE OF marker, run, caller;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'reusable call result lacks an exact live publication'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_call_result_window';
    END IF;

    IF NEW.sealed_at_ms IS NOT NULL THEN
        RAISE EXCEPTION 'reusable call result must begin unsealed'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_call_result_unsealed';
    END IF;

    IF NOT matched THEN
        IF NEW.child_job_count <> 0
            OR NEW.output_count <> 0
            OR NEW.effective_conclusion <> 'skipped'
        THEN
            RAISE EXCEPTION 'skipped reusable call result is not empty'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'logical_workflow_reusable_call_result_skipped';
        END IF;
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM logical_workflow_invocations AS child
    JOIN logical_workflow_reusable_workflow_catalog AS catalog
      ON catalog.run_id = child.run_id
     AND catalog.plan_digest = child.plan_digest
    WHERE child.run_id = NEW.run_id
      AND child.id = NEW.child_invocation_id
      AND child.invocation_kind = 'reusable'
      AND child.state = 'active'
      AND child.plan_digest = NEW.callee_plan_digest
      AND NEW.completed_at_ms >= child.updated_at_ms
    FOR UPDATE OF child;
    IF NOT FOUND OR EXISTS (
        SELECT 1
        FROM logical_workflow_jobs AS child_job
        LEFT JOIN logical_workflow_job_results AS child_result
          ON child_result.run_id = child_job.run_id
         AND child_result.invocation_id = child_job.invocation_id
         AND child_result.logical_job_id = child_job.id
        LEFT JOIN logical_workflow_job_result_claims AS child_claim
          ON child_claim.logical_job_id = child_result.logical_job_id
         AND child_claim.state = 'finalized'
        WHERE child_job.run_id = NEW.run_id
          AND child_job.invocation_id = NEW.child_invocation_id
          AND (child_result.logical_job_id IS NULL
               OR child_claim.logical_job_id IS NULL
               OR child_result.finalized_at_ms > NEW.completed_at_ms)
    ) THEN
        RAISE EXCEPTION 'reusable child invocation is not exactly complete'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_child_results_complete';
    END IF;

    SELECT CASE
        WHEN bool_or(child_result.effective_conclusion = 'failure') THEN 'failure'
        WHEN bool_or(child_result.effective_conclusion = 'timed_out') THEN 'timed_out'
        WHEN bool_or(child_result.effective_conclusion = 'cancelled') THEN 'cancelled'
        WHEN bool_or(child_result.effective_conclusion = 'success') THEN 'success'
        ELSE 'skipped'
    END
      INTO expected_conclusion
    FROM logical_workflow_jobs AS child_job
    JOIN logical_workflow_job_results AS child_result
      ON child_result.run_id = child_job.run_id
     AND child_result.invocation_id = child_job.invocation_id
     AND child_result.logical_job_id = child_job.id
    WHERE child_job.run_id = NEW.run_id
      AND child_job.invocation_id = NEW.child_invocation_id;

    IF NEW.child_job_count <> (
            SELECT count(*) FROM logical_workflow_jobs AS child_job
            WHERE child_job.run_id = NEW.run_id
              AND child_job.invocation_id = NEW.child_invocation_id
        )
        OR NEW.output_count <> (
            SELECT output_count
            FROM logical_workflow_reusable_invocation_expansions AS expansion
            WHERE expansion.run_id = NEW.run_id
              AND expansion.invocation_id = NEW.child_invocation_id
        )
        OR NEW.effective_conclusion IS DISTINCT FROM expected_conclusion
    THEN
        RAISE EXCEPTION 'reusable call result aggregate is inexact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_call_result_aggregate';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_lock_reusable_workflow_expansion_window() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM 1
    FROM logical_workflow_runs AS marker
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN logical_workflow_invocations AS root
      ON root.run_id = marker.run_id
     AND root.id = marker.root_invocation_id
    WHERE marker.run_id = NEW.run_id
      AND marker.root_invocation_id = NEW.root_invocation_id
      AND marker.state IN ('pending', 'active')
      AND marker.admission_graph_sealed_at_ms IS NOT NULL
      AND run.status IN ('queued', 'in_progress')
      AND root.invocation_kind = 'root'
      AND root.state IN ('pending', 'active')
      AND NOT EXISTS (
          SELECT 1
          FROM logical_workflow_run_result_claims AS claim
          WHERE claim.run_id = marker.run_id
      )
    FOR UPDATE OF marker, run, root;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'reusable workflow expansion requires a live unfinalized root'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_reusable_expansion_window';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_managed_secret_delivery_no_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'managed secret delivery evidence is append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'managed_secret_delivery_operations_no_delete';
END;
$$;

CREATE FUNCTION automata_managed_secret_delivery_operation_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.job_id IS DISTINCT FROM OLD.job_id
       OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
       OR NEW.lease_id IS DISTINCT FROM OLD.lease_id
       OR NEW.fencing_token IS DISTINCT FROM OLD.fencing_token
       OR NEW.runner_id IS DISTINCT FROM OLD.runner_id
       OR NEW.runner_session_id IS DISTINCT FROM OLD.runner_session_id
       OR NEW.runner_session_epoch IS DISTINCT FROM OLD.runner_session_epoch
       OR NEW.runner_generation IS DISTINCT FROM OLD.runner_generation
       OR NEW.runner_slot IS DISTINCT FROM OLD.runner_slot
       OR NEW.runtime_context_digest IS DISTINCT FROM OLD.runtime_context_digest
       OR NEW.binding_set_digest IS DISTINCT FROM OLD.binding_set_digest
       OR NEW.authority_evidence_schema IS DISTINCT FROM OLD.authority_evidence_schema
       OR NEW.authority_evidence_digest IS DISTINCT FROM OLD.authority_evidence_digest
       OR NEW.credential_key_id IS DISTINCT FROM OLD.credential_key_id
       OR NEW.credential_sha256 IS DISTINCT FROM OLD.credential_sha256
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.usable_until_ms IS DISTINCT FROM OLD.usable_until_ms THEN
        RAISE EXCEPTION 'managed secret delivery evidence is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'managed_secret_delivery_operations_evidence_immutable';
    END IF;
    IF OLD.state <> 'pending' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal managed secret delivery operations are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'managed_secret_delivery_operations_terminal_monotonic';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_membership_status_authorization_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.authorization_revision < OLD.authorization_revision THEN
        RAISE EXCEPTION 'membership authorization revision cannot decrease';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        NEW.authorization_revision := GREATEST(
            NEW.authorization_revision,
            OLD.authorization_revision + 1
        );
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_pin_github_scheduled_workflow_runtime_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    rows_inserted BIGINT;
BEGIN
    INSERT INTO logical_workflow_runtime_policy_pins (
        run_id, tenant_id, repository_id, policy_revision,
        policy_digest, pinned_at_ms
    )
    SELECT NEW.run_id, NEW.tenant_id, NEW.repository_id,
           manifest.runtime_policy_revision, manifest.runtime_policy_digest,
           NEW.admitted_at_ms
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
    WHERE origin.origin_kind = 'scheduled_fire'
      AND origin.origin_id = NEW.schedule_fire_id
      AND origin.run_id = NEW.run_id
      AND origin.tenant_id = NEW.tenant_id
      AND origin.repository_id = NEW.repository_id;
    GET DIAGNOSTICS rows_inserted = ROW_COUNT;
    IF rows_inserted <> 1 THEN
        RAISE EXCEPTION 'scheduled GitHub logical workflow run lacks its historical manifest runtime policy'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_runtime_policy_pin_required';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_pin_github_workflow_runtime_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    rows_inserted BIGINT;
BEGIN
    INSERT INTO logical_workflow_runtime_policy_pins (
        run_id, tenant_id, repository_id, policy_revision,
        policy_digest, pinned_at_ms
    )
    SELECT NEW.run_id, NEW.tenant_id, NEW.repository_id,
           manifest.runtime_policy_revision, manifest.runtime_policy_digest,
           NEW.admitted_at_ms
    FROM github_provider_delivery_evidence AS delivery
    JOIN github_provider_manifest_revisions AS manifest
      ON manifest.tenant_id = delivery.tenant_id
     AND manifest.repository_id = delivery.repository_id
     AND manifest.provider_connection_id = delivery.provider_connection_id
     AND manifest.manifest_revision = delivery.provider_manifest_revision
     AND manifest.manifest_digest = delivery.provider_manifest_digest
    JOIN workflow_runtime_policy_revisions AS policy
      ON policy.tenant_id = manifest.tenant_id
     AND policy.repository_id = manifest.repository_id
     AND policy.policy_revision = manifest.runtime_policy_revision
     AND policy.policy_digest = manifest.runtime_policy_digest
     AND policy.state = 'sealed'
    WHERE delivery.provider_delivery_id = NEW.provider_delivery_id
      AND delivery.tenant_id = NEW.tenant_id
      AND delivery.repository_id = NEW.repository_id;
    GET DIAGNOSTICS rows_inserted = ROW_COUNT;
    IF rows_inserted <> 1 THEN
        RAISE EXCEPTION 'GitHub logical workflow run lacks its historical manifest runtime policy'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'logical_workflow_runtime_policy_pin_required';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_principal_has_repository_permission(target_tenant_id text, target_principal_id uuid, target_repository_id uuid, target_permission_name text, target_now_ms bigint) RETURNS boolean
    LANGUAGE sql STABLE
    AS $_$
SELECT EXISTS (
    SELECT 1
    FROM tenant_human_memberships AS membership
    JOIN rbac_role_bindings AS binding
      ON binding.tenant_id = membership.tenant_id
     AND binding.principal_id = membership.principal_id
    JOIN rbac_role_permissions AS permission
      ON permission.tenant_id = binding.tenant_id
     AND permission.role_id = binding.role_id
    WHERE membership.tenant_id = $1
      AND membership.principal_id = $2
      AND membership.status = 'active'
      AND binding.status = 'active'
      AND (binding.valid_until_ms IS NULL OR binding.valid_until_ms > $5)
      AND permission.permission_name = $4
      AND (
          binding.scope_kind = 'tenant'
          OR (binding.scope_kind = 'repository'
              AND binding.repository_id = $3)
      )
);
$_$;

CREATE FUNCTION automata_protect_attempt_terminal_result_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF ROW(
        NEW.attempt_id, NEW.terminal_authority,
        NEW.runner_session_id, NEW.operation_id,
        NEW.runner_id, NEW.runner_session_epoch, NEW.runner_generation,
        NEW.runner_slot, NEW.lease_id, NEW.fencing_token, NEW.result_schema,
        NEW.result_size_bytes, NEW.result_digest, NEW.result_object_key,
        NEW.server_cancellation_operation_id, NEW.server_cancellation_digest,
        NEW.conclusion, NEW.completed_at_ms, NEW.committed_at_ms
    ) IS DISTINCT FROM ROW(
        OLD.attempt_id, OLD.terminal_authority,
        OLD.runner_session_id, OLD.operation_id,
        OLD.runner_id, OLD.runner_session_epoch, OLD.runner_generation,
        OLD.runner_slot, OLD.lease_id, OLD.fencing_token, OLD.result_schema,
        OLD.result_size_bytes, OLD.result_digest, OLD.result_object_key,
        OLD.server_cancellation_operation_id, OLD.server_cancellation_digest,
        OLD.conclusion, OLD.completed_at_ms, OLD.committed_at_ms
    ) THEN
        RAISE EXCEPTION 'attempt terminal result evidence is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_protect_server_cancellation_intent() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM attempt_terminal_results AS terminal
        WHERE terminal.attempt_id = OLD.attempt_id
          AND terminal.terminal_authority = 'server_cancellation'
    ) AND ROW(
        NEW.attempt_id, NEW.operation_id, NEW.requested_by, NEW.reason,
        NEW.requested_at_ms, NEW.delivery_session_id,
        NEW.delivery_command_sequence, NEW.acknowledged_at_ms
    ) IS DISTINCT FROM ROW(
        OLD.attempt_id, OLD.operation_id, OLD.requested_by, OLD.reason,
        OLD.requested_at_ms, OLD.delivery_session_id,
        OLD.delivery_command_sequence, OLD.acknowledged_at_ms
    ) THEN
        RAISE EXCEPTION 'server cancellation intent authority is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_protect_logical_workflow_terminal_ordinal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.logical_workflow_logical_job_id IS DISTINCT FROM
           OLD.logical_workflow_logical_job_id
       OR NEW.logical_workflow_terminal_ordinal IS DISTINCT FROM
           OLD.logical_workflow_terminal_ordinal
    THEN
        IF OLD.logical_workflow_logical_job_id IS NULL
            AND OLD.logical_workflow_terminal_ordinal IS NULL
            AND NEW.logical_workflow_logical_job_id IS NOT NULL
            AND NEW.logical_workflow_terminal_ordinal > 0
            AND pg_trigger_depth() > 1
        THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'logical workflow terminal ordinal evidence is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_protected_environment_approval_is_current(target_tenant_id text, target_request_id uuid, target_now_ms bigint) RETURNS boolean
    LANGUAGE sql STABLE
    AS $_$
SELECT EXISTS (
    SELECT 1
    FROM protected_environment_approval_requests AS request
    JOIN repository_environments AS environment
      ON environment.tenant_id = request.tenant_id
     AND environment.repository_id = request.repository_id
     AND environment.id = request.environment_id
    WHERE request.tenant_id = $1
      AND request.id = $2
      AND request.status = 'approved'
      AND request.resolution_reason = 'approval_threshold_met'
      AND request.resolved_at_ms IS NOT NULL
      AND request.resolved_at_ms < request.expires_at_ms
      AND $3 < request.expires_at_ms
      AND environment.status = 'active'
      AND environment.protection_mode = 'required_approvals'
      AND environment.revision = request.environment_revision
      AND environment.required_approvals = request.required_approvals
      AND environment.prevent_self_review = request.prevent_self_review
      AND (
          NOT request.prevent_self_review
          OR request.requested_by_principal_id IS NOT NULL
      )
      AND (
          SELECT count(*)
          FROM protected_environment_approval_decisions AS decision
          WHERE decision.tenant_id = request.tenant_id
            AND decision.request_id = request.id
            AND decision.decision = 'approve'
            AND (
                NOT request.prevent_self_review
                OR decision.principal_id <> request.requested_by_principal_id
            )
            AND automata_environment_reviewer_assignment_is_current(
                request.tenant_id, request.repository_id, request.environment_id,
                request.environment_revision, decision.principal_id, $3
            )
      ) >= request.required_approvals
      AND NOT EXISTS (
          SELECT 1
          FROM protected_environment_approval_decisions AS decision
          WHERE decision.tenant_id = request.tenant_id
            AND decision.request_id = request.id
            AND decision.decision = 'reject'
            AND automata_environment_reviewer_assignment_is_current(
                request.tenant_id, request.repository_id, request.environment_id,
                request.environment_revision, decision.principal_id, $3
            )
      )
);
$_$;

CREATE FUNCTION automata_protected_environment_approval_snapshot() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    environment repository_environments%ROWTYPE;
    policy_is_current BOOLEAN;
    database_now_ms BIGINT;
BEGIN
    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    SELECT * INTO STRICT environment
    FROM repository_environments
    WHERE tenant_id = NEW.tenant_id
      AND repository_id = NEW.repository_id
      AND id = NEW.environment_id
    FOR SHARE;

    IF TG_OP = 'INSERT' THEN
        IF NEW.environment_revision IS NULL THEN
            NEW.environment_revision := environment.revision;
        END IF;
        IF NEW.status <> 'pending'
           OR NEW.required_approvals <> environment.required_approvals
           OR NEW.prevent_self_review <> environment.prevent_self_review
           OR NEW.environment_revision <> environment.revision
           OR environment.protection_mode <> 'required_approvals'
           OR environment.status <> 'active' THEN
            RAISE EXCEPTION 'approval request does not snapshot the current environment'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'protected_environment_approval_snapshot';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.job_id IS DISTINCT FROM OLD.job_id
       OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.required_approvals IS DISTINCT FROM OLD.required_approvals
       OR NEW.prevent_self_review IS DISTINCT FROM OLD.prevent_self_review
       OR NEW.requested_by_principal_id IS DISTINCT FROM OLD.requested_by_principal_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
       OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
       OR NEW.environment_revision IS DISTINCT FROM OLD.environment_revision THEN
        RAISE EXCEPTION 'approval request evidence is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'protected_environment_approval_evidence_immutable';
    END IF;
    IF OLD.status <> 'pending' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal approval requests are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'protected_environment_approval_terminal_monotonic';
    END IF;
    IF OLD.status = 'pending' AND NEW.status <> 'pending'
       AND NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'approval resolution requires one revision increment'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'protected_environment_approval_revision_guard';
    ELSIF OLD.status = 'pending' AND NEW.status = 'pending'
          AND NEW.revision <> OLD.revision THEN
        RAISE EXCEPTION 'pending approval revision is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'protected_environment_approval_revision_guard';
    END IF;

    IF OLD.status = 'pending' AND NEW.status <> 'pending' THEN
        policy_is_current :=
            OLD.environment_revision = environment.revision
            AND OLD.required_approvals = environment.required_approvals
            AND OLD.prevent_self_review = environment.prevent_self_review
            AND environment.protection_mode = 'required_approvals'
            AND environment.status = 'active';

        IF NEW.resolved_at_ms IS NULL
           OR NEW.resolved_at_ms > database_now_ms
           OR database_now_ms - NEW.resolved_at_ms > 60000 THEN
            RAISE EXCEPTION 'approval resolution time is not current database time'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'protected_environment_approval_resolution_time';
        END IF;

        IF NEW.status IN ('approved', 'rejected')
           AND (
               NOT policy_is_current
               OR NEW.resolved_at_ms IS NULL
               OR NEW.resolved_at_ms >= OLD.expires_at_ms
               OR database_now_ms >= OLD.expires_at_ms
           ) THEN
            RAISE EXCEPTION 'approval resolution no longer matches current environment policy'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'protected_environment_approval_resolution_current';
        END IF;

        IF NOT policy_is_current
           AND NOT (
               NEW.status = 'cancelled'
               AND NEW.resolution_reason = CASE
                   WHEN environment.status = 'disabled'
                       THEN 'environment_disabled'
                   ELSE 'policy_changed'
               END
           )
           AND NOT (
               NEW.status = 'expired'
               AND NEW.resolution_reason = 'approval_expired'
               AND NEW.resolved_at_ms >= OLD.expires_at_ms
           ) THEN
            RAISE EXCEPTION 'stale approval requires a typed cancellation or expiry'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'protected_environment_approval_stale_resolution';
        END IF;

        IF NEW.status = 'expired'
           AND (
               NEW.resolved_at_ms < OLD.expires_at_ms
               OR database_now_ms < OLD.expires_at_ms
           ) THEN
            RAISE EXCEPTION 'approval cannot expire before its deadline'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'protected_environment_approval_expiry_time';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_protected_environment_decision_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'protected environment decisions are append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'protected_environment_approval_decisions_immutable';
END;
$$;

CREATE FUNCTION automata_prove_protected_environment_approval_resolution() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    environment repository_environments%ROWTYPE;
    database_now_ms BIGINT;
    approved_count BIGINT;
    has_rejection BOOLEAN;
BEGIN
    IF OLD.status <> 'pending' OR NEW.status = 'pending' THEN
        RETURN NEW;
    END IF;
    database_now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    SELECT * INTO STRICT environment
    FROM repository_environments
    WHERE tenant_id = OLD.tenant_id
      AND repository_id = OLD.repository_id
      AND id = OLD.environment_id
    FOR SHARE;

    IF NEW.status = 'approved' THEN
        IF NEW.resolution_reason <> 'approval_threshold_met'
           OR environment.status <> 'active'
           OR environment.protection_mode <> 'required_approvals'
           OR environment.revision <> OLD.environment_revision
           OR environment.required_approvals <> OLD.required_approvals
           OR environment.prevent_self_review <> OLD.prevent_self_review
           OR NEW.resolved_at_ms IS NULL
           OR NEW.resolved_at_ms >= OLD.expires_at_ms
           OR database_now_ms >= OLD.expires_at_ms THEN
            RAISE EXCEPTION 'approval resolution is not current and threshold-backed'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'protected_environment_approval_resolution_proven';
        END IF;

        SELECT count(*) INTO approved_count
        FROM protected_environment_approval_decisions AS decision
        WHERE decision.tenant_id = OLD.tenant_id
          AND decision.request_id = OLD.id
          AND decision.decision = 'approve'
          AND (
              NOT OLD.prevent_self_review
              OR OLD.requested_by_principal_id IS NULL
              OR decision.principal_id <> OLD.requested_by_principal_id
          )
          AND automata_environment_reviewer_assignment_is_current(
              OLD.tenant_id, OLD.repository_id, OLD.environment_id,
              OLD.environment_revision, decision.principal_id, database_now_ms
          );
        SELECT EXISTS (
            SELECT 1
            FROM protected_environment_approval_decisions AS decision
            WHERE decision.tenant_id = OLD.tenant_id
              AND decision.request_id = OLD.id
              AND decision.decision = 'reject'
              AND automata_environment_reviewer_assignment_is_current(
                  OLD.tenant_id, OLD.repository_id, OLD.environment_id,
                  OLD.environment_revision, decision.principal_id, database_now_ms
              )
        ) INTO has_rejection;
        IF approved_count < OLD.required_approvals OR has_rejection THEN
            RAISE EXCEPTION 'approval threshold is not proven by current distinct reviewers'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'protected_environment_approval_threshold_proven';
        END IF;
    ELSIF NEW.status = 'rejected' THEN
        IF NEW.resolution_reason <> 'approval_rejected'
           OR NOT EXISTS (
               SELECT 1
               FROM protected_environment_approval_decisions AS decision
               WHERE decision.tenant_id = OLD.tenant_id
                 AND decision.request_id = OLD.id
                 AND decision.decision = 'reject'
                 AND automata_environment_reviewer_assignment_is_current(
                     OLD.tenant_id, OLD.repository_id, OLD.environment_id,
                     OLD.environment_revision, decision.principal_id, database_now_ms
                 )
           ) THEN
            RAISE EXCEPTION 'rejection lacks current authorized reviewer evidence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'protected_environment_approval_rejection_proven';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_provider_delivery_workflow_inventory_digest(uuid) RETURNS bytea
    LANGUAGE sql STABLE STRICT PARALLEL SAFE
    AS $_$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
        'automata.store.provider-delivery-workflow-inventory.v1', 'UTF8'
    )
    || pg_catalog.decode('00', 'hex')
    || inventory.manifest_digest
    || automata_digest_part(
        pg_catalog.convert_to(inventory.source_revision, 'UTF8')
    )
    || inventory.repository_source_digest
    || pg_catalog.int8send(inventory.workflow_count::BIGINT)
    || coalesce((
        SELECT string_agg(
            automata_digest_part(
                pg_catalog.convert_to(entry.workflow_path, 'UTF8')
            )
            || automata_digest_part(
                pg_catalog.convert_to(entry.source_state, 'UTF8')
            )
            || coalesce(entry.source_digest, ''::BYTEA),
            ''::BYTEA ORDER BY entry.ordinal
        )
        FROM provider_delivery_workflow_inventory_entries AS entry
        WHERE entry.inbox_id = inventory.inbox_id
    ), ''::BYTEA)
)
FROM provider_delivery_workflow_inventories AS inventory
WHERE inventory.inbox_id = $1
$_$;

CREATE FUNCTION automata_provider_token_scopes_are_canonical(candidate text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
    SELECT
        cardinality(candidate) <= 256
        AND array_position(candidate, NULL) IS NULL
        AND COALESCE((
            SELECT bool_and(
                octet_length(scope) BETWEEN 1 AND 255
                AND scope ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]*$'
            )
            FROM unnest(candidate) AS scope
        ), TRUE)
        AND cardinality(candidate) = (
            SELECT count(DISTINCT scope) FROM unnest(candidate) AS scope
        )
        AND candidate = ARRAY(
            SELECT scope FROM unnest(candidate) AS scope ORDER BY scope COLLATE "C"
        );
$_$;

CREATE FUNCTION automata_refresh_logical_workflow_activation_due_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM automata_refresh_logical_workflow_job_result_due(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id
    );
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_refresh_logical_workflow_attempt_lifecycle_due_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.lifecycle IS DISTINCT FROM OLD.lifecycle
       AND NEW.lifecycle IN (
           'succeeded', 'failed', 'cancelled', 'timed_out', 'skipped'
       )
    THEN
        PERFORM automata_refresh_logical_workflow_instance_result_due(NEW.id);
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_refresh_logical_workflow_instance_claim_due_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM automata_refresh_logical_workflow_instance_result_due(NEW.attempt_id);
    PERFORM 1
    FROM logical_workflow_jobs AS job
    WHERE job.run_id = NEW.run_id
      AND job.invocation_id = NEW.invocation_id
      AND job.id = NEW.logical_job_id
    FOR UPDATE;
    PERFORM automata_refresh_logical_workflow_job_result_due(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id
    );
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_refresh_logical_workflow_instance_result_due(target_attempt_id uuid) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO logical_workflow_instance_result_due (
        attempt_id, tenant_id, run_id, invocation_id, logical_job_id,
        source_order, ready_at_ms, available_at_ms
    )
    SELECT terminal.attempt_id, repository.tenant_id,
           concrete.run_id, concrete.invocation_id, concrete.logical_job_id,
           logical_job.source_order, terminal.committed_at_ms,
           COALESCE(claim.expires_at_ms, terminal.committed_at_ms)
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
    JOIN repositories AS repository ON repository.id = run.repository_id
    LEFT JOIN logical_workflow_instance_result_claims AS claim
      ON claim.attempt_id = terminal.attempt_id
    WHERE terminal.attempt_id = target_attempt_id
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
      AND terminal.logical_workflow_logical_job_id = concrete.logical_job_id
      AND terminal.logical_workflow_terminal_ordinal > 0
      AND terminal.completed_at_ms >= 0
      AND terminal.committed_at_ms >= terminal.completed_at_ms
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
      AND (claim.attempt_id IS NULL OR claim.state = 'projecting')
    ON CONFLICT (attempt_id) DO UPDATE SET
        tenant_id = EXCLUDED.tenant_id,
        run_id = EXCLUDED.run_id,
        invocation_id = EXCLUDED.invocation_id,
        logical_job_id = EXCLUDED.logical_job_id,
        source_order = EXCLUDED.source_order,
        ready_at_ms = EXCLUDED.ready_at_ms,
        available_at_ms = EXCLUDED.available_at_ms;

    IF NOT FOUND THEN
        DELETE FROM logical_workflow_instance_result_due
        WHERE attempt_id = target_attempt_id;
    END IF;
END;
$$;

CREATE FUNCTION automata_refresh_logical_workflow_job_claim_due_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    dependent RECORD;
BEGIN
    PERFORM automata_refresh_logical_workflow_job_result_due(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id
    );
    IF NEW.state = 'finalized' THEN
        FOR dependent IN
            SELECT dependency.run_id, dependency.invocation_id,
                   dependency.logical_job_id
            FROM logical_workflow_dependencies AS dependency
            JOIN logical_workflow_jobs AS job
              ON job.run_id = dependency.run_id
             AND job.invocation_id = dependency.invocation_id
             AND job.id = dependency.logical_job_id
            WHERE dependency.run_id = NEW.run_id
              AND dependency.invocation_id = NEW.invocation_id
              AND dependency.prerequisite_job_id = NEW.logical_job_id
            ORDER BY job.source_order, dependency.logical_job_id
            FOR UPDATE OF job
        LOOP
            PERFORM automata_refresh_logical_workflow_job_result_due(
                dependent.run_id,
                dependent.invocation_id,
                dependent.logical_job_id
            );
        END LOOP;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_refresh_logical_workflow_job_result_due(target_run_id uuid, target_invocation_id uuid, target_logical_job_id uuid) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO logical_workflow_job_result_due (
        logical_job_id, tenant_id, run_id, invocation_id, source_order,
        ready_at_ms, available_at_ms
    )
    SELECT job.id, repository.tenant_id, job.run_id, job.invocation_id,
           job.source_order, ready.ready_at_ms,
           GREATEST(ready.ready_at_ms,
                    COALESCE(claim.expires_at_ms, ready.ready_at_ms))
    FROM logical_workflow_jobs AS job
    JOIN logical_workflow_invocations AS invocation
      ON invocation.run_id = job.run_id AND invocation.id = job.invocation_id
    JOIN logical_workflow_runs AS marker ON marker.run_id = job.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    JOIN logical_workflow_activation_publications AS publication
      ON publication.run_id = job.run_id
     AND publication.invocation_id = job.invocation_id
     AND publication.logical_job_id = job.id
    LEFT JOIN logical_workflow_job_result_claims AS claim
      ON claim.logical_job_id = job.id
    CROSS JOIN LATERAL (
        SELECT GREATEST(
            publication.published_at_ms,
            COALESCE((
                SELECT max(result.finalized_at_ms)
                FROM logical_workflow_instances AS instance
                JOIN logical_workflow_instance_results AS result
                  ON result.instance_id = instance.id
                WHERE instance.run_id = job.run_id
                  AND instance.invocation_id = job.invocation_id
                  AND instance.logical_job_id = job.id
            ), 0),
            COALESCE((
                SELECT max(result.finalized_at_ms)
                FROM logical_workflow_dependencies AS dependency
                JOIN logical_workflow_job_results AS result
                  ON result.logical_job_id = dependency.prerequisite_job_id
                WHERE dependency.run_id = job.run_id
                  AND dependency.invocation_id = job.invocation_id
                  AND dependency.logical_job_id = job.id
            ), 0)
        ) AS ready_at_ms
    ) AS ready
    WHERE job.run_id = target_run_id
      AND job.invocation_id = target_invocation_id
      AND job.id = target_logical_job_id
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
      AND (claim.logical_job_id IS NULL OR claim.state = 'aggregating')
      AND publication.instance_count = (
          SELECT count(*)
          FROM logical_workflow_instances AS instance
          WHERE instance.run_id = job.run_id
            AND instance.invocation_id = job.invocation_id
            AND instance.logical_job_id = job.id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM logical_workflow_instances AS instance
          LEFT JOIN logical_workflow_instance_results AS result
            ON result.instance_id = instance.id
           AND result.run_id = instance.run_id
           AND result.invocation_id = instance.invocation_id
           AND result.logical_job_id = instance.logical_job_id
          LEFT JOIN logical_workflow_instance_result_claims AS instance_claim
            ON instance_claim.instance_id = result.instance_id
          WHERE instance.run_id = job.run_id
            AND instance.invocation_id = job.invocation_id
            AND instance.logical_job_id = job.id
            AND (result.instance_id IS NULL
                 OR instance_claim.state IS DISTINCT FROM 'finalized')
      )
      AND NOT EXISTS (
          SELECT 1
          FROM logical_workflow_dependencies AS dependency
          LEFT JOIN logical_workflow_job_results AS prerequisite_result
            ON prerequisite_result.run_id = dependency.run_id
           AND prerequisite_result.invocation_id = dependency.invocation_id
           AND prerequisite_result.logical_job_id =
               dependency.prerequisite_job_id
          LEFT JOIN logical_workflow_job_result_claims AS prerequisite_claim
            ON prerequisite_claim.logical_job_id =
               prerequisite_result.logical_job_id
          WHERE dependency.run_id = job.run_id
            AND dependency.invocation_id = job.invocation_id
            AND dependency.logical_job_id = job.id
            AND (prerequisite_result.logical_job_id IS NULL
                 OR prerequisite_claim.state IS DISTINCT FROM 'finalized')
      )
    ON CONFLICT (logical_job_id) DO UPDATE SET
        tenant_id = EXCLUDED.tenant_id,
        run_id = EXCLUDED.run_id,
        invocation_id = EXCLUDED.invocation_id,
        source_order = EXCLUDED.source_order,
        ready_at_ms = EXCLUDED.ready_at_ms,
        available_at_ms = EXCLUDED.available_at_ms;

    IF NOT FOUND THEN
        DELETE FROM logical_workflow_job_result_due
        WHERE logical_job_id = target_logical_job_id
          AND run_id = target_run_id
          AND invocation_id = target_invocation_id;
    END IF;
END;
$$;

CREATE FUNCTION automata_refresh_logical_workflow_job_state_due_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.state IS DISTINCT FROM OLD.state THEN
        PERFORM automata_refresh_logical_workflow_job_result_due(
            NEW.run_id, NEW.invocation_id, NEW.id
        );
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_refresh_logical_workflow_terminal_result_due_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM automata_refresh_logical_workflow_instance_result_due(NEW.attempt_id);
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_reject_github_check_removal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'GitHub Check durable evidence cannot be removed'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'github_check_evidence_removal_forbidden';
END;
$$;

CREATE FUNCTION automata_reject_workload_oidc_authority_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'Automata workload OIDC authority is immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'workload_oidc_authority_immutable';
END;
$$;

CREATE FUNCTION automata_reject_workload_oidc_issuance_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'Automata workload OIDC issuance slots are retained'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'workload_oidc_issuance_slot_retained';
END;
$$;
