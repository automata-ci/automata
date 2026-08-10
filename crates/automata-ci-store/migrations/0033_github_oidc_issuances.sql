-- Current-only durable GitHub-compatible workload OIDC authority. Private
-- request bearers, ID tokens, and key material never enter this schema. One
-- immutable authority is fenced to an exact WorkflowPlan-v2 / JobIR-v5
-- execution; bounded audience slots preserve deterministic replay.

CREATE FUNCTION automata_github_oidc_claim_set_valid(claims JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $automata$
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
$automata$;

CREATE TABLE github_oidc_authorities (
    attempt_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    authority_id UUID NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    github_repository_id BIGINT NOT NULL,
    github_repository_name TEXT COLLATE "C" NOT NULL,
    github_owner_id BIGINT,
    workflow_id UUID NOT NULL,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    instance_id UUID NOT NULL,
    job_id UUID NOT NULL,
    attempt_number INTEGER NOT NULL,
    lease_id UUID NOT NULL,
    lease_issued_at_ms BIGINT NOT NULL,
    lease_expires_at_ms BIGINT NOT NULL,
    runner_id UUID NOT NULL,
    runner_session_id UUID NOT NULL,
    runner_session_epoch BIGINT NOT NULL,
    runner_generation BIGINT NOT NULL,
    runner_slot INTEGER NOT NULL,
    admission_epoch SMALLINT NOT NULL,
    workflow_plan_schema SMALLINT NOT NULL,
    plan_digest BYTEA NOT NULL,
    event_digest BYTEA NOT NULL,
    runtime_context_digest BYTEA NOT NULL,
    job_ir_schema SMALLINT NOT NULL,
    job_ir_size_bytes BIGINT NOT NULL,
    job_ir_digest BYTEA NOT NULL,
    job_ir_object_key TEXT COLLATE "C" NOT NULL,
    permission_mode TEXT COLLATE "C" NOT NULL,
    permission_evidence_sha256 BYTEA NOT NULL,
    subject_policy_mode TEXT COLLATE "C" NOT NULL,
    subject_policy_revision BIGINT NOT NULL,
    subject_policy_sha256 BYTEA NOT NULL,
    source_evidence_sha256 BYTEA NOT NULL,
    claim_evidence_sha256 BYTEA NOT NULL,
    subject TEXT COLLATE "C" NOT NULL,
    default_audience TEXT COLLATE "C" NOT NULL,
    additional_claims JSONB NOT NULL,
    configuration_sha256 BYTEA NOT NULL,
    request_bearer_key_id TEXT COLLATE "C" NOT NULL,
    request_bearer_key_sha256 BYTEA NOT NULL,
    request_bearer_verification_skew_seconds SMALLINT NOT NULL,
    id_token_verifier_skew_seconds SMALLINT NOT NULL,
    request_bearer_iat_seconds BIGINT NOT NULL,
    request_bearer_exp_seconds BIGINT NOT NULL,
    request_bearer_sha256 BYTEA NOT NULL,
    reserved_at_ms BIGINT NOT NULL,

    CONSTRAINT github_oidc_authorities_primary_key PRIMARY KEY (
        attempt_id, fencing_token
    ),
    CONSTRAINT github_oidc_authorities_tenant_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_oidc_authorities_repository_run
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_oidc_authorities_repository_workflow
        FOREIGN KEY (repository_id, workflow_id)
        REFERENCES workflow_definitions(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_oidc_authorities_run_job
        FOREIGN KEY (run_id, job_id)
        REFERENCES jobs(run_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_oidc_authorities_job_attempt
        FOREIGN KEY (job_id, attempt_id)
        REFERENCES job_attempts(job_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_oidc_authorities_concrete_job
        FOREIGN KEY (instance_id)
        REFERENCES workflow_plan_v2_concrete_jobs(instance_id) ON DELETE RESTRICT,
    CONSTRAINT github_oidc_authorities_tenant_runner
        FOREIGN KEY (tenant_id, runner_id)
        REFERENCES runners(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_oidc_authorities_runner_session
        FOREIGN KEY (
            runner_id, runner_session_id, runner_session_epoch, runner_generation
        ) REFERENCES runner_sessions(
            runner_id, id, session_epoch, runner_generation
        ) ON DELETE RESTRICT,
    CONSTRAINT github_oidc_authorities_non_nil_ids CHECK (
        attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND authority_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND workflow_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND instance_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND lease_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND runner_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND runner_session_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT github_oidc_authorities_execution_numbers CHECK (
        fencing_token > 0
        AND attempt_number > 0
        AND runner_session_epoch > 0
        AND runner_generation > 0
        AND runner_slot BETWEEN 1 AND 65535
    ),
    CONSTRAINT github_oidc_authorities_current_schemas CHECK (
        admission_epoch = 4
        AND workflow_plan_schema = 2
        AND job_ir_schema = 5
        AND job_ir_size_bytes BETWEEN 1 AND 16777216
        AND octet_length(job_ir_digest) = 32
        AND octet_length(job_ir_object_key) BETWEEN 1 AND 1024
        AND job_ir_object_key !~ '[[:cntrl:]]'
        AND left(job_ir_object_key, 1) <> '/'
        AND job_ir_object_key !~ '(^|/)\.\.(/|$)'
    ),
    CONSTRAINT github_oidc_authorities_evidence_sha256 CHECK (
        octet_length(plan_digest) = 32
        AND octet_length(event_digest) = 32
        AND octet_length(runtime_context_digest) = 32
        AND octet_length(permission_evidence_sha256) = 32
        AND octet_length(subject_policy_sha256) = 32
        AND octet_length(source_evidence_sha256) = 32
        AND octet_length(claim_evidence_sha256) = 32
        AND permission_evidence_sha256 = job_ir_digest
        AND source_evidence_sha256 = job_ir_digest
        AND octet_length(configuration_sha256) = 32
        AND octet_length(request_bearer_sha256) = 32
        AND octet_length(request_bearer_key_sha256) = 32
    ),
    CONSTRAINT github_oidc_authorities_github_repository CHECK (
        github_repository_id > 0
        AND octet_length(github_repository_name) BETWEEN 3 AND 140
        AND github_repository_name ~ '^[^/]+/[^/]+$'
        AND octet_length(split_part(github_repository_name, '/', 1)) BETWEEN 1 AND 39
        AND split_part(github_repository_name, '/', 1)
            ~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$'
        AND split_part(github_repository_name, '/', 1) NOT LIKE '%--%'
        AND octet_length(split_part(github_repository_name, '/', 2)) BETWEEN 1 AND 100
        AND split_part(github_repository_name, '/', 2) ~ '^[A-Za-z0-9._-]+$'
        AND split_part(github_repository_name, '/', 2) NOT IN ('.', '..')
        AND lower(split_part(github_repository_name, '/', 2)) NOT LIKE '%.git'
    ),
    CONSTRAINT github_oidc_authorities_permission_exact CHECK (
        permission_mode = 'id-token:write'
    ),
    CONSTRAINT github_oidc_authorities_subject_policy CHECK (
        subject_policy_revision > 0
        AND (
            (subject_policy_mode = 'repository_evidence' AND github_owner_id IS NULL)
            OR (
                subject_policy_mode = 'stable_owner_evidence'
                AND github_owner_id > 0
            )
        )
    ),
    CONSTRAINT github_oidc_authorities_principals CHECK (
        octet_length(subject) BETWEEN 1 AND 2048
        AND btrim(subject) <> ''
        AND subject !~ '[[:cntrl:]]'
        AND octet_length(default_audience) BETWEEN 1 AND 2048
        AND btrim(default_audience) <> ''
        AND default_audience !~ '[[:cntrl:]]'
        AND automata_github_oidc_claim_set_valid(additional_claims)
    ),
    CONSTRAINT github_oidc_authorities_key_id CHECK (
        octet_length(request_bearer_key_id) BETWEEN 1 AND 128
        AND request_bearer_key_id ~ '^[A-Za-z0-9._-]+$'
    ),
    CONSTRAINT github_oidc_authorities_bearer_interval CHECK (
        lease_issued_at_ms >= 0
        AND lease_expires_at_ms > lease_issued_at_ms
        AND reserved_at_ms >= lease_issued_at_ms
        AND reserved_at_ms < lease_expires_at_ms
        AND request_bearer_iat_seconds = lease_issued_at_ms / 1000
        AND reserved_at_ms / 1000 < request_bearer_exp_seconds
        AND request_bearer_exp_seconds > request_bearer_iat_seconds
        AND request_bearer_exp_seconds - request_bearer_iat_seconds <= 86400
        AND request_bearer_iat_seconds <= 9223372036854775
        AND request_bearer_exp_seconds <= 9223372036854775
        AND request_bearer_verification_skew_seconds BETWEEN 0 AND 300
        AND id_token_verifier_skew_seconds BETWEEN 0 AND 300
        AND request_bearer_exp_seconds
            <= 9223372036854775807 - request_bearer_verification_skew_seconds
    )
);

CREATE FUNCTION automata_github_oidc_authority_is_current(
    authority github_oidc_authorities,
    observed_at_ms BIGINT,
    required_current_before_ms BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $automata$
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
        JOIN workflow_plan_v2_runs AS marker
          ON marker.run_id = run.id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = run.id
         AND invocation.id = authority.invocation_id
        JOIN workflow_plan_v2_jobs AS logical_job
          ON logical_job.run_id = run.id
         AND logical_job.invocation_id = invocation.id
         AND logical_job.id = authority.logical_job_id
        JOIN workflow_plan_v2_instances AS instance
          ON instance.run_id = run.id
         AND instance.invocation_id = invocation.id
         AND instance.logical_job_id = logical_job.id
         AND instance.id = authority.instance_id
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.instance_id = instance.id
         AND concrete.run_id = run.id
         AND concrete.invocation_id = invocation.id
         AND concrete.logical_job_id = logical_job.id
         AND concrete.job_id = job.id
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
          AND job.admission_epoch = 4
          AND job.job_ir_schema = 5
          AND job.job_ir_schema = authority.job_ir_schema
          AND job.job_ir_size_bytes = authority.job_ir_size_bytes
          AND job.job_ir_digest = authority.job_ir_digest
          AND authority.permission_evidence_sha256 = authority.job_ir_digest
          AND authority.source_evidence_sha256 = authority.job_ir_digest
          AND job.job_ir_object_key = authority.job_ir_object_key
          AND job.requirements @> '{"features":["automata.core/oidc-tokens@v1"]}'::jsonb
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND run.plan_digest = authority.plan_digest
          AND run.event_digest = authority.event_digest
          AND run.status IN ('queued', 'in_progress')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND invocation.plan_schema = 2
          AND invocation.plan_digest = authority.plan_digest
          AND invocation.state IN ('pending', 'active')
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND instance.job_ir_version = 5
          AND instance.job_ir_digest = authority.job_ir_digest
          AND instance.job_ir_object_key = authority.job_ir_object_key
          AND instance.job_ir_size_bytes = authority.job_ir_size_bytes
          AND concrete.runtime_context_schema = 2
          AND concrete.runtime_context_digest = authority.runtime_context_digest
          AND concrete.requirements = job.requirements
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id = authority.github_repository_id::TEXT
          AND repository.owner || '/' || repository.name = authority.github_repository_name
          AND (
              NOT authority.additional_claims ? 'repository'
              OR authority.additional_claims ->> 'repository'
                  = authority.github_repository_name
          )
          AND (
              NOT authority.additional_claims ? 'repository_id'
              OR authority.additional_claims ->> 'repository_id'
                  = authority.github_repository_id::TEXT
          )
          AND (
              NOT authority.additional_claims ? 'repository_owner'
              OR authority.additional_claims ->> 'repository_owner'
                  = split_part(authority.github_repository_name, '/', 1)
          )
          AND authority.permission_mode = 'id-token:write'
          AND authority.subject_policy_revision > 0
          -- No current durable source authenticates GitHub's numeric owner ID.
          -- Never derive it from repository.owner or accept caller text.
          AND authority.subject_policy_mode = 'repository_evidence'
          AND authority.github_owner_id IS NULL
          AND NOT authority.additional_claims ? 'repository_owner_id'
          AND runner.status = 'online'
          AND runner.desired_state IN ('active', 'draining')
          AND runner.capabilities @> '{"features":["automata.core/oidc-tokens@v1"]}'::jsonb
          AND session.job_ir_schema = 5
          AND session.capability_snapshot @> '{"features":["automata.core/oidc-tokens@v1"]}'::jsonb
          AND session.disconnected_at_ms IS NULL
    )
$automata$;

CREATE FUNCTION automata_lock_github_oidc_authority_dependencies(
    authority github_oidc_authorities
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
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
     AND repository.id = authority.repository_id
     AND repository.tenant_id = authority.tenant_id
    JOIN workflow_plan_v2_runs AS marker
      ON marker.run_id = run.id
    JOIN workflow_plan_v2_invocations AS invocation
      ON invocation.run_id = run.id
     AND invocation.id = authority.invocation_id
    JOIN workflow_plan_v2_jobs AS logical_job
      ON logical_job.run_id = run.id
     AND logical_job.invocation_id = invocation.id
     AND logical_job.id = authority.logical_job_id
    JOIN workflow_plan_v2_instances AS instance
      ON instance.run_id = run.id
     AND instance.invocation_id = invocation.id
     AND instance.logical_job_id = logical_job.id
     AND instance.id = authority.instance_id
    JOIN workflow_plan_v2_concrete_jobs AS concrete
      ON concrete.instance_id = instance.id
     AND concrete.run_id = run.id
     AND concrete.invocation_id = invocation.id
     AND concrete.logical_job_id = logical_job.id
     AND concrete.job_id = job.id
    JOIN runners AS runner
      ON runner.id = attempt.runner_id
     AND runner.id = authority.runner_id
     AND runner.tenant_id = authority.tenant_id
    JOIN runner_sessions AS session
      ON session.id = attempt.runner_session_id
     AND session.id = authority.runner_session_id
     AND session.runner_id = authority.runner_id
    WHERE attempt.id = authority.attempt_id
    FOR SHARE OF attempt, job, run, repository, marker, invocation,
                 logical_job, instance, concrete, runner, session;
    RETURN FOUND;
END;
$automata$;

CREATE FUNCTION automata_validate_github_oidc_authority_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE TRIGGER github_oidc_authorities_insert_guard
BEFORE INSERT ON github_oidc_authorities
FOR EACH ROW EXECUTE FUNCTION automata_validate_github_oidc_authority_insert();

CREATE FUNCTION automata_reject_github_oidc_authority_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub-compatible OIDC authority is immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'github_oidc_authority_immutable';
END;
$automata$;

CREATE TRIGGER github_oidc_authorities_reject_update
BEFORE UPDATE OR DELETE ON github_oidc_authorities
FOR EACH ROW EXECUTE FUNCTION automata_reject_github_oidc_authority_mutation();

CREATE TABLE github_oidc_issuance_slots (
    authority_id UUID NOT NULL
        REFERENCES github_oidc_authorities(authority_id) ON DELETE RESTRICT,
    audience_key_sha256 BYTEA NOT NULL,
    requested_audience TEXT COLLATE "C",
    generation BIGINT NOT NULL,
    token_id UUID NOT NULL UNIQUE,
    signing_key_id TEXT COLLATE "C" NOT NULL,
    resolved_audience TEXT COLLATE "C" NOT NULL,
    issued_at_seconds BIGINT NOT NULL,
    not_before_seconds BIGINT NOT NULL,
    expires_at_seconds BIGINT NOT NULL,
    created_at_seconds BIGINT NOT NULL,
    updated_at_seconds BIGINT NOT NULL,
    CONSTRAINT github_oidc_issuance_slots_primary_key PRIMARY KEY (
        authority_id, audience_key_sha256
    ),
    CONSTRAINT github_oidc_issuance_slots_digest CHECK (
        octet_length(audience_key_sha256) = 32
    ),
    CONSTRAINT github_oidc_issuance_slots_requested_audience CHECK (
        requested_audience IS NULL OR (
            octet_length(requested_audience) BETWEEN 1 AND 2048
            AND btrim(requested_audience) <> ''
            AND requested_audience !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT github_oidc_issuance_slots_generation CHECK (generation > 0),
    CONSTRAINT github_oidc_issuance_slots_identity CHECK (
        token_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND octet_length(signing_key_id) BETWEEN 1 AND 128
        AND signing_key_id ~ '^[A-Za-z0-9._-]+$'
    ),
    CONSTRAINT github_oidc_issuance_slots_audience CHECK (
        octet_length(resolved_audience) BETWEEN 1 AND 2048
        AND btrim(resolved_audience) <> ''
        AND resolved_audience !~ '[[:cntrl:]]'
    ),
    CONSTRAINT github_oidc_issuance_slots_interval CHECK (
        issued_at_seconds >= 0
        AND not_before_seconds >= 0
        AND not_before_seconds <= issued_at_seconds
        AND expires_at_seconds > issued_at_seconds
        AND expires_at_seconds - issued_at_seconds <= 3600
        AND issued_at_seconds <= 9223372036854775
        AND created_at_seconds >= 0
        AND updated_at_seconds >= created_at_seconds
        AND updated_at_seconds = issued_at_seconds
    )
);

CREATE FUNCTION automata_validate_github_oidc_issuance_slot()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE TRIGGER github_oidc_issuance_slots_validate
BEFORE INSERT OR UPDATE ON github_oidc_issuance_slots
FOR EACH ROW EXECUTE FUNCTION automata_validate_github_oidc_issuance_slot();

CREATE FUNCTION automata_enforce_github_oidc_issuance_replacement()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.authority_id IS DISTINCT FROM OLD.authority_id
        OR NEW.audience_key_sha256 IS DISTINCT FROM OLD.audience_key_sha256
        OR NEW.requested_audience IS DISTINCT FROM OLD.requested_audience
        OR NEW.created_at_seconds IS DISTINCT FROM OLD.created_at_seconds
        OR NEW.generation <> OLD.generation + 1
        OR NEW.issued_at_seconds < OLD.expires_at_seconds
    THEN
        RAISE EXCEPTION 'GitHub-compatible OIDC slot replacement is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_oidc_issuance_slot_replacement';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_oidc_issuance_slots_replace
BEFORE UPDATE ON github_oidc_issuance_slots
FOR EACH ROW EXECUTE FUNCTION automata_enforce_github_oidc_issuance_replacement();

CREATE FUNCTION automata_reject_github_oidc_issuance_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub-compatible OIDC issuance slots are retained'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'github_oidc_issuance_slot_retained';
END;
$automata$;

CREATE TRIGGER github_oidc_issuance_slots_reject_delete
BEFORE DELETE ON github_oidc_issuance_slots
FOR EACH ROW EXECUTE FUNCTION automata_reject_github_oidc_issuance_delete();

CREATE TABLE github_oidc_key_deadlines (
    key_use TEXT COLLATE "C" NOT NULL,
    key_id TEXT COLLATE "C" NOT NULL,
    key_sha256 BYTEA,
    max_not_after_seconds BIGINT NOT NULL,
    updated_at_seconds BIGINT NOT NULL,
    CONSTRAINT github_oidc_key_deadlines_primary_key PRIMARY KEY (key_use, key_id),
    CONSTRAINT github_oidc_key_deadlines_use CHECK (
        key_use IN ('request_bearer', 'id_token_signing')
    ),
    CONSTRAINT github_oidc_key_deadlines_key CHECK (
        octet_length(key_id) BETWEEN 1 AND 128
        AND key_id ~ '^[A-Za-z0-9._-]+$'
        AND (key_sha256 IS NULL OR octet_length(key_sha256) = 32)
    ),
    CONSTRAINT github_oidc_key_deadlines_time CHECK (
        max_not_after_seconds > 0
        AND updated_at_seconds >= 0
        AND updated_at_seconds <= max_not_after_seconds
    )
);

CREATE INDEX github_oidc_key_deadlines_active_lookup
ON github_oidc_key_deadlines (
    key_use, max_not_after_seconds, key_id
);

CREATE FUNCTION automata_enforce_github_oidc_key_deadline()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.key_use IS DISTINCT FROM OLD.key_use
        OR NEW.key_id IS DISTINCT FROM OLD.key_id
        OR NEW.key_sha256 IS DISTINCT FROM OLD.key_sha256
        OR NEW.max_not_after_seconds < OLD.max_not_after_seconds
        OR NEW.updated_at_seconds < OLD.updated_at_seconds
    THEN
        RAISE EXCEPTION 'GitHub-compatible OIDC key retention cannot regress'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_oidc_key_deadline_monotonic';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_oidc_key_deadlines_monotonic
BEFORE UPDATE ON github_oidc_key_deadlines
FOR EACH ROW EXECUTE FUNCTION automata_enforce_github_oidc_key_deadline();

CREATE TRIGGER github_oidc_key_deadlines_reject_delete
BEFORE DELETE ON github_oidc_key_deadlines
FOR EACH ROW EXECUTE FUNCTION automata_reject_github_oidc_issuance_delete();
