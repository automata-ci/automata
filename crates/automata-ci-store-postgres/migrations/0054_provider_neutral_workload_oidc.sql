-- Keep the established baseline immutable while moving the live schema to the
-- provider-neutral workload OIDC vocabulary. Renames preserve rows and object
-- identities; the function replacements update stored SQL and PL/pgSQL bodies.

ALTER TABLE github_oidc_authorities RENAME TO workload_oidc_authorities;
ALTER TABLE github_oidc_issuance_slots RENAME TO workload_oidc_issuance_slots;
ALTER TABLE github_oidc_key_deadlines RENAME TO workload_oidc_key_deadlines;

ALTER FUNCTION automata_enforce_github_oidc_issuance_replacement()
    RENAME TO automata_enforce_workload_oidc_issuance_replacement;
ALTER FUNCTION automata_enforce_github_oidc_key_deadline()
    RENAME TO automata_enforce_workload_oidc_key_deadline;
ALTER FUNCTION automata_github_oidc_claim_set_valid(jsonb)
    RENAME TO automata_workload_oidc_claim_set_valid;
ALTER FUNCTION automata_github_oidc_authority_is_current(workload_oidc_authorities, bigint, bigint)
    RENAME TO automata_workload_oidc_authority_is_current;
ALTER FUNCTION automata_lock_github_oidc_authority_dependencies(workload_oidc_authorities)
    RENAME TO automata_lock_workload_oidc_authority_dependencies;
ALTER FUNCTION automata_reject_github_oidc_authority_mutation()
    RENAME TO automata_reject_workload_oidc_authority_mutation;
ALTER FUNCTION automata_reject_github_oidc_issuance_delete()
    RENAME TO automata_reject_workload_oidc_issuance_delete;
ALTER FUNCTION automata_require_standard_github_oidc_profile()
    RENAME TO automata_require_standard_workload_oidc_profile;
ALTER FUNCTION automata_validate_github_oidc_authority_insert()
    RENAME TO automata_validate_workload_oidc_authority_insert;
ALTER FUNCTION automata_validate_github_oidc_issuance_slot()
    RENAME TO automata_validate_workload_oidc_issuance_slot;

ALTER TABLE workload_oidc_authorities
    RENAME CONSTRAINT github_oidc_authorities_source_evidence_sha256_not_null
    TO workload_oidc_authorities_source_evidence_sha256_not_null;
ALTER TABLE workload_oidc_authorities
    RENAME CONSTRAINT github_oidc_authorities_request_bearer_verification_sk_not_null
    TO workload_oidc_authorities_bearer_skew_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_bearer_interval TO workload_oidc_authorities_bearer_interval;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_current_evidence_sha256 TO workload_oidc_authorities_current_evidence_sha256;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_current_schemas TO workload_oidc_authorities_current_schemas;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_execution_numbers TO workload_oidc_authorities_execution_numbers;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_github_repository TO workload_oidc_authorities_github_repository;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_key_id TO workload_oidc_authorities_key_id;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_non_nil_ids TO workload_oidc_authorities_non_nil_ids;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_permission_exact TO workload_oidc_authorities_permission_exact;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_principals TO workload_oidc_authorities_principals;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_stable_owner_policy TO workload_oidc_authorities_stable_owner_policy;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_authority_id_key TO workload_oidc_authorities_authority_id_key;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_primary_key TO workload_oidc_authorities_primary_key;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_concrete_job TO workload_oidc_authorities_concrete_job;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_job_attempt TO workload_oidc_authorities_job_attempt;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_repository_run TO workload_oidc_authorities_repository_run;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_repository_workflow TO workload_oidc_authorities_repository_workflow;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_run_job TO workload_oidc_authorities_run_job;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_runner_session TO workload_oidc_authorities_runner_session;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_signed_run_evidence TO workload_oidc_authorities_signed_run_evidence;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_tenant_repository TO workload_oidc_authorities_tenant_repository;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_tenant_runner TO workload_oidc_authorities_tenant_runner;

ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_audience TO workload_oidc_issuance_slots_audience;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_digest TO workload_oidc_issuance_slots_digest;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_generation TO workload_oidc_issuance_slots_generation;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_identity TO workload_oidc_issuance_slots_identity;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_interval TO workload_oidc_issuance_slots_interval;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_requested_audience TO workload_oidc_issuance_slots_requested_audience;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_primary_key TO workload_oidc_issuance_slots_primary_key;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_token_id_key TO workload_oidc_issuance_slots_token_id_key;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_authority_id_fkey TO workload_oidc_issuance_slots_authority_id_fkey;

ALTER TABLE workload_oidc_key_deadlines RENAME CONSTRAINT github_oidc_key_deadlines_key TO workload_oidc_key_deadlines_key;
ALTER TABLE workload_oidc_key_deadlines RENAME CONSTRAINT github_oidc_key_deadlines_time TO workload_oidc_key_deadlines_time;
ALTER TABLE workload_oidc_key_deadlines RENAME CONSTRAINT github_oidc_key_deadlines_use TO workload_oidc_key_deadlines_use;
ALTER TABLE workload_oidc_key_deadlines RENAME CONSTRAINT github_oidc_key_deadlines_primary_key TO workload_oidc_key_deadlines_primary_key;

-- PostgreSQL 18 gives implicit NOT NULL constraints table-derived names.
-- Rename each one so a migrated database is catalog-identical to a fresh
-- provider-neutral schema.
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_additional_claims_not_null TO workload_oidc_authorities_additional_claims_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_admission_epoch_not_null TO workload_oidc_authorities_admission_epoch_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_attempt_id_not_null TO workload_oidc_authorities_attempt_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_attempt_number_not_null TO workload_oidc_authorities_attempt_number_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_authority_id_not_null TO workload_oidc_authorities_authority_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_claim_evidence_sha256_not_null TO workload_oidc_authorities_claim_evidence_sha256_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_configuration_sha256_not_null TO workload_oidc_authorities_configuration_sha256_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_default_audience_not_null TO workload_oidc_authorities_default_audience_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_event_digest_not_null TO workload_oidc_authorities_event_digest_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_fencing_token_not_null TO workload_oidc_authorities_fencing_token_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_github_owner_id_not_null TO workload_oidc_authorities_github_owner_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_github_repository_id_not_null TO workload_oidc_authorities_github_repository_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_github_repository_name_not_null TO workload_oidc_authorities_github_repository_name_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_id_token_verifier_skew_seconds_not_null TO workload_oidc_authorities_id_token_verifier_skew_seconds_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_instance_id_not_null TO workload_oidc_authorities_instance_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_invocation_id_not_null TO workload_oidc_authorities_invocation_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_job_id_not_null TO workload_oidc_authorities_job_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_job_ir_digest_not_null TO workload_oidc_authorities_job_ir_digest_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_job_ir_object_key_not_null TO workload_oidc_authorities_job_ir_object_key_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_job_ir_schema_not_null TO workload_oidc_authorities_job_ir_schema_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_job_ir_size_bytes_not_null TO workload_oidc_authorities_job_ir_size_bytes_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_lease_expires_at_ms_not_null TO workload_oidc_authorities_lease_expires_at_ms_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_lease_id_not_null TO workload_oidc_authorities_lease_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_lease_issued_at_ms_not_null TO workload_oidc_authorities_lease_issued_at_ms_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_logical_job_id_not_null TO workload_oidc_authorities_logical_job_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_permission_evidence_sha256_not_null TO workload_oidc_authorities_permission_evidence_sha256_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_permission_mode_not_null TO workload_oidc_authorities_permission_mode_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_plan_digest_not_null TO workload_oidc_authorities_plan_digest_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_repository_id_not_null TO workload_oidc_authorities_repository_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_request_bearer_exp_seconds_not_null TO workload_oidc_authorities_request_bearer_exp_seconds_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_request_bearer_iat_seconds_not_null TO workload_oidc_authorities_request_bearer_iat_seconds_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_request_bearer_key_id_not_null TO workload_oidc_authorities_request_bearer_key_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_request_bearer_key_sha256_not_null TO workload_oidc_authorities_request_bearer_key_sha256_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_request_bearer_sha256_not_null TO workload_oidc_authorities_request_bearer_sha256_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_reserved_at_ms_not_null TO workload_oidc_authorities_reserved_at_ms_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_run_id_not_null TO workload_oidc_authorities_run_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_runner_generation_not_null TO workload_oidc_authorities_runner_generation_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_runner_id_not_null TO workload_oidc_authorities_runner_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_runner_session_epoch_not_null TO workload_oidc_authorities_runner_session_epoch_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_runner_session_id_not_null TO workload_oidc_authorities_runner_session_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_runner_slot_not_null TO workload_oidc_authorities_runner_slot_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_runtime_context_digest_not_null TO workload_oidc_authorities_runtime_context_digest_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_subject_not_null TO workload_oidc_authorities_subject_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_subject_policy_mode_not_null TO workload_oidc_authorities_subject_policy_mode_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_subject_policy_revision_not_null TO workload_oidc_authorities_subject_policy_revision_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_subject_policy_sha256_not_null TO workload_oidc_authorities_subject_policy_sha256_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_tenant_id_not_null TO workload_oidc_authorities_tenant_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_workflow_id_not_null TO workload_oidc_authorities_workflow_id_not_null;
ALTER TABLE workload_oidc_authorities RENAME CONSTRAINT github_oidc_authorities_workflow_plan_schema_not_null TO workload_oidc_authorities_workflow_plan_schema_not_null;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_audience_key_sha256_not_null TO workload_oidc_issuance_slots_audience_key_sha256_not_null;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_authority_id_not_null TO workload_oidc_issuance_slots_authority_id_not_null;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_created_at_seconds_not_null TO workload_oidc_issuance_slots_created_at_seconds_not_null;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_expires_at_seconds_not_null TO workload_oidc_issuance_slots_expires_at_seconds_not_null;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_generation_not_null TO workload_oidc_issuance_slots_generation_not_null;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_issued_at_seconds_not_null TO workload_oidc_issuance_slots_issued_at_seconds_not_null;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_not_before_seconds_not_null TO workload_oidc_issuance_slots_not_before_seconds_not_null;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_resolved_audience_not_null TO workload_oidc_issuance_slots_resolved_audience_not_null;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_signing_key_id_not_null TO workload_oidc_issuance_slots_signing_key_id_not_null;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_token_id_not_null TO workload_oidc_issuance_slots_token_id_not_null;
ALTER TABLE workload_oidc_issuance_slots RENAME CONSTRAINT github_oidc_issuance_slots_updated_at_seconds_not_null TO workload_oidc_issuance_slots_updated_at_seconds_not_null;
ALTER TABLE workload_oidc_key_deadlines RENAME CONSTRAINT github_oidc_key_deadlines_key_id_not_null TO workload_oidc_key_deadlines_key_id_not_null;
ALTER TABLE workload_oidc_key_deadlines RENAME CONSTRAINT github_oidc_key_deadlines_key_use_not_null TO workload_oidc_key_deadlines_key_use_not_null;
ALTER TABLE workload_oidc_key_deadlines RENAME CONSTRAINT github_oidc_key_deadlines_max_not_after_seconds_not_null TO workload_oidc_key_deadlines_max_not_after_seconds_not_null;
ALTER TABLE workload_oidc_key_deadlines RENAME CONSTRAINT github_oidc_key_deadlines_updated_at_seconds_not_null TO workload_oidc_key_deadlines_updated_at_seconds_not_null;

ALTER INDEX github_oidc_key_deadlines_active_lookup RENAME TO workload_oidc_key_deadlines_active_lookup;

ALTER TRIGGER github_oidc_authorities_00_historical_standard_profile ON workload_oidc_authorities RENAME TO workload_oidc_authorities_00_historical_standard_profile;
ALTER TRIGGER github_oidc_authorities_insert_guard ON workload_oidc_authorities RENAME TO workload_oidc_authorities_insert_guard;
ALTER TRIGGER github_oidc_authorities_reject_update ON workload_oidc_authorities RENAME TO workload_oidc_authorities_reject_update;
ALTER TRIGGER github_oidc_issuance_slots_reject_delete ON workload_oidc_issuance_slots RENAME TO workload_oidc_issuance_slots_reject_delete;
ALTER TRIGGER github_oidc_issuance_slots_replace ON workload_oidc_issuance_slots RENAME TO workload_oidc_issuance_slots_replace;
ALTER TRIGGER github_oidc_issuance_slots_validate ON workload_oidc_issuance_slots RENAME TO workload_oidc_issuance_slots_validate;
ALTER TRIGGER github_oidc_key_deadlines_monotonic ON workload_oidc_key_deadlines RENAME TO workload_oidc_key_deadlines_monotonic;
ALTER TRIGGER github_oidc_key_deadlines_reject_delete ON workload_oidc_key_deadlines RENAME TO workload_oidc_key_deadlines_reject_delete;

CREATE OR REPLACE FUNCTION automata_enforce_workload_oidc_issuance_replacement() RETURNS trigger
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

CREATE OR REPLACE FUNCTION automata_enforce_workload_oidc_key_deadline() RETURNS trigger
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

CREATE OR REPLACE FUNCTION automata_workload_oidc_claim_set_valid(claims jsonb) RETURNS boolean
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

CREATE OR REPLACE FUNCTION automata_workload_oidc_authority_is_current(authority workload_oidc_authorities, observed_at_ms bigint, required_current_before_ms bigint) RETURNS boolean
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
        LEFT JOIN github_server_service_authorities AS private_authority
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
         AND private_authority.service_scope =
             'private_repository_source_read'
         AND private_authority.identity_digest =
             origin.private_source_authority_identity_digest
         AND private_authority.app_configuration_revision =
             origin.private_source_authority_app_configuration_revision
         AND private_authority.policy_revision =
             origin.private_source_authority_policy_revision
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
          AND (
              origin.repository_visibility = 'public'
              AND origin.private_source_authority_id IS NULL
              AND private_authority.id IS NULL
              OR origin.repository_visibility = 'private'
              AND private_authority.id IS NOT NULL
              AND private_authority.state = 'active'
              AND private_authority.created_at_ms <= observed_at_ms
              AND private_authority.state_updated_at_ms <= observed_at_ms
          )
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

CREATE OR REPLACE FUNCTION automata_lock_workload_oidc_authority_dependencies(authority workload_oidc_authorities) RETURNS boolean
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

CREATE OR REPLACE FUNCTION automata_reject_workload_oidc_authority_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'Automata workload OIDC authority is immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'workload_oidc_authority_immutable';
END;
$$;

CREATE OR REPLACE FUNCTION automata_reject_workload_oidc_issuance_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'Automata workload OIDC issuance slots are retained'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'workload_oidc_issuance_slot_retained';
END;
$$;

CREATE OR REPLACE FUNCTION automata_require_standard_workload_oidc_profile() RETURNS trigger
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
        RAISE EXCEPTION 'Automata workload OIDC requires historical Standard authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workload_oidc_historical_standard_authority';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION automata_validate_workload_oidc_authority_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT automata_lock_workload_oidc_authority_dependencies(NEW)
        OR NOT automata_workload_oidc_authority_is_current(
            NEW, NEW.reserved_at_ms, NEW.reserved_at_ms + 1
        )
    THEN
        RAISE EXCEPTION 'Automata workload OIDC authority is not current'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workload_oidc_authority_current_execution';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION automata_validate_workload_oidc_issuance_slot() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    authority workload_oidc_authorities%ROWTYPE;
    slot_count BIGINT;
BEGIN
    IF NEW.issued_at_seconds > 9223372036854774 THEN
        RAISE EXCEPTION 'Automata workload OIDC issuance time is out of range'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workload_oidc_issuance_current_authority';
    END IF;
    SELECT * INTO authority
    FROM workload_oidc_authorities
    WHERE authority_id = NEW.authority_id
    FOR UPDATE;
    IF authority.authority_id IS NULL
        OR NOT automata_lock_workload_oidc_authority_dependencies(authority)
        OR NEW.resolved_audience IS DISTINCT FROM coalesce(
            NEW.requested_audience, authority.default_audience
        )
        OR NEW.issued_at_seconds < authority.request_bearer_iat_seconds
        OR NEW.not_before_seconds < authority.request_bearer_iat_seconds
        OR NEW.expires_at_seconds > authority.request_bearer_exp_seconds
        OR NOT automata_workload_oidc_authority_is_current(
            authority,
            NEW.issued_at_seconds * 1000,
            (NEW.issued_at_seconds + 1) * 1000
        )
    THEN
        RAISE EXCEPTION 'Automata workload OIDC issuance lacks current authority'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workload_oidc_issuance_current_authority';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.generation <> 1
            OR NEW.created_at_seconds <> NEW.issued_at_seconds
        THEN
            RAISE EXCEPTION 'Automata workload OIDC initial issuance is invalid'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'workload_oidc_issuance_slot_initial';
        END IF;
        SELECT count(*) INTO slot_count
        FROM workload_oidc_issuance_slots
        WHERE authority_id = NEW.authority_id;
        IF slot_count >= 64 THEN
            RAISE EXCEPTION 'Automata workload OIDC audience slot bound exceeded'
                USING ERRCODE = 'program_limit_exceeded',
                      CONSTRAINT = 'workload_oidc_issuance_slot_bound';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
