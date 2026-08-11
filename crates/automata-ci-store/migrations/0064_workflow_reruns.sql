-- Durable workflow reruns create a new physical workflow-run row for every
-- attempt while retaining the provider-visible identity of attempt one.  No
-- mutable provider/source fetch participates in this operation: all source,
-- plan, event, policy, and result identities are copied from immutable rows.

ALTER TABLE workflow_runs
    ADD COLUMN public_run_id_alias BIGINT,
    ADD COLUMN triggering_actor TEXT,
    ADD COLUMN concurrency_cancel_in_progress BOOLEAN,
    ADD CONSTRAINT workflow_runs_public_id_alias_positive CHECK (
        public_run_id_alias IS NULL
        OR public_run_id_alias BETWEEN 1 AND 9007199254740991
    ),
    ADD CONSTRAINT workflow_runs_triggering_actor_shape CHECK (
        triggering_actor IS NULL OR (
            octet_length(triggering_actor) BETWEEN 1 AND 1024
            AND triggering_actor !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT workflow_runs_concurrency_cancel_shape CHECK (
        concurrency_group_key IS NOT NULL
        OR concurrency_cancel_in_progress IS NULL
    );

-- Normal admissions continue to omit the provider-visible alias.  Identity
-- defaults are populated before row triggers, so a first-attempt insert can
-- derive its public identity from the newly allocated internal alias while a
-- rerun can provide the attempt-one alias explicitly.
CREATE FUNCTION automata_default_workflow_public_run_id_alias()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.public_run_id_alias IS NULL THEN
        NEW.public_run_id_alias := NEW.run_id_alias;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_runs_default_public_run_id_alias
BEFORE INSERT ON workflow_runs
FOR EACH ROW EXECUTE FUNCTION automata_default_workflow_public_run_id_alias();

-- Every pre-rerun physical row is its own provider-visible first attempt.
UPDATE workflow_runs
SET public_run_id_alias = run_id_alias
WHERE public_run_id_alias IS NULL;

ALTER TABLE workflow_runs
    ALTER COLUMN public_run_id_alias SET NOT NULL;

CREATE UNIQUE INDEX workflow_runs_public_id_attempt
    ON workflow_runs (workflow_id, public_run_id_alias, run_attempt);

CREATE FUNCTION automata_reject_workflow_run_rerun_identity_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE TRIGGER workflow_runs_rerun_identity_immutable
BEFORE UPDATE OF public_run_id_alias, triggering_actor ON workflow_runs
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_run_rerun_identity_mutation();

-- The first row for a group is lazily recorded when it is first rerun.  This
-- avoids backfilling or changing historical runs while making every later
-- physical attempt point at the same attempt-one root.
CREATE TABLE workflow_rerun_attempts (
    run_id UUID PRIMARY KEY
        REFERENCES workflow_runs(id) ON DELETE RESTRICT,
    root_run_id UUID NOT NULL
        REFERENCES workflow_runs(id) ON DELETE RESTRICT,
    source_run_id UUID
        REFERENCES workflow_runs(id) ON DELETE RESTRICT,
    attempt INTEGER NOT NULL,
    source_admission_digest BYTEA NOT NULL,
    source_plan_digest BYTEA NOT NULL,
    source_event_digest BYTEA NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_rerun_attempts_ids_non_nil CHECK (
        run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND root_run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND (source_run_id IS NULL OR source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid)
    ),
    CONSTRAINT workflow_rerun_attempts_root_shape CHECK (
        (source_run_id IS NULL AND run_id = root_run_id AND attempt = 1)
        OR (source_run_id IS NOT NULL AND run_id <> root_run_id AND attempt BETWEEN 2 AND 50)
    ),
    CONSTRAINT workflow_rerun_attempts_digest_shape CHECK (
        octet_length(source_admission_digest) = 32
        AND octet_length(source_plan_digest) = 32
        AND octet_length(source_event_digest) = 32
    ),
    CONSTRAINT workflow_rerun_attempts_time CHECK (created_at_ms >= 0),
    CONSTRAINT workflow_rerun_attempts_run_source_unique UNIQUE (run_id, source_run_id),
    CONSTRAINT workflow_rerun_attempts_root_attempt_unique UNIQUE (root_run_id, attempt)
);

CREATE INDEX workflow_rerun_attempts_source ON workflow_rerun_attempts (source_run_id)
    WHERE source_run_id IS NOT NULL;

CREATE FUNCTION automata_reject_workflow_rerun_attempt_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'workflow rerun attempt evidence is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'workflow_rerun_attempts_immutable';
END;
$automata$;

CREATE TRIGGER workflow_rerun_attempts_no_update_delete
BEFORE UPDATE OR DELETE ON workflow_rerun_attempts
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_rerun_attempt_mutation();

CREATE TRIGGER workflow_rerun_attempts_no_truncate
BEFORE TRUNCATE ON workflow_rerun_attempts
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_workflow_rerun_attempt_mutation();

-- Human rerun requests are their own operation-idempotency and audit boundary.
CREATE TABLE workflow_rerun_requests (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    operation_id UUID NOT NULL,
    request_digest BYTEA NOT NULL,
    repository_id UUID NOT NULL,
    source_run_id UUID NOT NULL,
    selection_kind TEXT NOT NULL,
    selected_source_job_id UUID,
    actor_principal_id UUID NOT NULL,
    actor_session_id UUID NOT NULL,
    authorization_revision BIGINT NOT NULL,
    rerun_run_id UUID,
    committed_at_ms BIGINT,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT workflow_rerun_requests_ids_non_nil CHECK (
        operation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND actor_principal_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND actor_session_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND (rerun_run_id IS NULL OR rerun_run_id <> '00000000-0000-0000-0000-000000000000'::uuid)
    ),
    CONSTRAINT workflow_rerun_requests_digest_shape CHECK (octet_length(request_digest) = 32),
    CONSTRAINT workflow_rerun_requests_selection_shape CHECK (
        (selection_kind IN ('entire_workflow', 'failed_jobs_and_dependents')
         AND selected_source_job_id IS NULL)
        OR (selection_kind = 'job_and_dependents'
            AND selected_source_job_id IS NOT NULL)
    ),
    CONSTRAINT workflow_rerun_requests_revision_positive CHECK (authorization_revision > 0),
    CONSTRAINT workflow_rerun_requests_completion_shape CHECK (
        (rerun_run_id IS NULL AND committed_at_ms IS NULL)
        OR (rerun_run_id IS NOT NULL AND committed_at_ms IS NOT NULL AND committed_at_ms >= 0)
    ),
    CONSTRAINT workflow_rerun_requests_actor_membership_fk FOREIGN KEY (
        tenant_id, actor_principal_id
    ) REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_requests_actor_session_fk FOREIGN KEY (
        tenant_id, actor_principal_id, actor_session_id
    ) REFERENCES human_sessions(tenant_id, principal_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_requests_repository_fk FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_requests_source_fk FOREIGN KEY (repository_id, source_run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_requests_rerun_fk FOREIGN KEY (repository_id, rerun_run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_requests_selected_job_fk FOREIGN KEY (selected_source_job_id)
        REFERENCES workflow_plan_v2_jobs(id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX workflow_rerun_requests_rerun_unique
    ON workflow_rerun_requests (rerun_run_id)
    WHERE rerun_run_id IS NOT NULL;

-- The source/new-job map is immutable proof that an attempt was cloned from
-- this exact terminal graph.  `selected` is the only executable closure.
CREATE TABLE workflow_rerun_attempt_jobs (
    run_id UUID NOT NULL
        REFERENCES workflow_rerun_attempts(run_id) ON DELETE RESTRICT,
    source_run_id UUID NOT NULL
        REFERENCES workflow_runs(id) ON DELETE RESTRICT,
    logical_job_id UUID NOT NULL
        REFERENCES workflow_plan_v2_jobs(id) ON DELETE RESTRICT,
    source_logical_job_id UUID NOT NULL
        REFERENCES workflow_plan_v2_jobs(id) ON DELETE RESTRICT,
    selected BOOLEAN NOT NULL,
    PRIMARY KEY (run_id, logical_job_id),
    CONSTRAINT workflow_rerun_attempt_jobs_ids_non_nil CHECK (
        source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND source_logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_rerun_attempt_jobs_source_run_fk FOREIGN KEY (
        run_id, source_run_id
    ) REFERENCES workflow_rerun_attempts(run_id, source_run_id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_attempt_jobs_source_job_fk FOREIGN KEY (
        source_run_id, source_logical_job_id
    ) REFERENCES workflow_plan_v2_run_result_jobs(run_id, logical_job_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_attempt_jobs_source_unique UNIQUE (run_id, source_logical_job_id)
);

CREATE INDEX workflow_rerun_attempt_jobs_source
    ON workflow_rerun_attempt_jobs (source_run_id, source_logical_job_id);

CREATE FUNCTION automata_reject_workflow_rerun_attempt_job_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'workflow rerun graph evidence is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'workflow_rerun_attempt_jobs_immutable';
END;
$automata$;

CREATE TRIGGER workflow_rerun_attempt_jobs_no_update_delete
BEFORE UPDATE OR DELETE ON workflow_rerun_attempt_jobs
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_rerun_attempt_job_mutation();

CREATE TRIGGER workflow_rerun_attempt_jobs_no_truncate
BEFORE TRUNCATE ON workflow_rerun_attempt_jobs
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_workflow_rerun_attempt_job_mutation();

-- Unselected source terminal results are never reinterpreted as newly run
-- work.  Their original result/output/commit digests are retained as an exact
-- immutable carry-forward proof and exposed through the effective views below.
CREATE TABLE workflow_rerun_carried_job_results (
    logical_job_id UUID PRIMARY KEY
        REFERENCES workflow_plan_v2_jobs(id) ON DELETE RESTRICT,
    run_id UUID NOT NULL
        REFERENCES workflow_rerun_attempts(run_id) ON DELETE RESTRICT,
    invocation_id UUID NOT NULL,
    source_run_id UUID NOT NULL,
    source_logical_job_id UUID NOT NULL,
    result_descriptor_digest BYTEA NOT NULL,
    logical_key TEXT COLLATE "C" NOT NULL,
    source_order INTEGER NOT NULL,
    plan_digest BYTEA NOT NULL,
    plan_object_key TEXT COLLATE "C" NOT NULL,
    plan_size_bytes BIGINT NOT NULL,
    plan_media_type TEXT COLLATE "C" NOT NULL,
    plan_schema SMALLINT NOT NULL,
    activation_output_digest BYTEA NOT NULL,
    condition_matched BOOLEAN NOT NULL,
    instance_count INTEGER NOT NULL,
    instances_digest BYTEA NOT NULL,
    prerequisite_count INTEGER NOT NULL,
    prerequisites_digest BYTEA NOT NULL,
    effective_conclusion TEXT NOT NULL,
    closure_has_failure BOOLEAN NOT NULL,
    closure_has_cancelled BOOLEAN NOT NULL,
    closure_has_skipped BOOLEAN NOT NULL,
    output_count INTEGER NOT NULL,
    outputs_digest BYTEA NOT NULL,
    commit_digest BYTEA NOT NULL,
    claim_owner_id UUID NOT NULL,
    claim_generation BIGINT NOT NULL,
    claim_started_at_ms BIGINT NOT NULL,
    claim_expires_at_ms BIGINT NOT NULL,
    finalized_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_rerun_carried_job_results_target_unique
        UNIQUE (run_id, invocation_id, logical_job_id),
    CONSTRAINT workflow_rerun_carried_job_results_source_unique
        UNIQUE (run_id, source_logical_job_id),
    CONSTRAINT workflow_rerun_carried_job_results_ids_non_nil CHECK (
        invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND source_run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND source_logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_rerun_carried_job_results_digest_shape CHECK (
        octet_length(result_descriptor_digest) = 32
        AND octet_length(plan_digest) = 32
        AND octet_length(activation_output_digest) = 32
        AND octet_length(instances_digest) = 32
        AND octet_length(prerequisites_digest) = 32
        AND octet_length(outputs_digest) = 32
        AND octet_length(commit_digest) = 32
    ),
    CONSTRAINT workflow_rerun_carried_job_results_shape CHECK (
        source_order BETWEEN 0 AND 1023
        AND plan_size_bytes BETWEEN 1 AND 16777216
        AND plan_media_type = 'application/vnd.automata.workflow-plan+json'
        AND plan_schema = 2
        AND instance_count BETWEEN 0 AND 256
        AND prerequisite_count BETWEEN 0 AND 128
        AND output_count BETWEEN 0 AND 256
        AND effective_conclusion IN ('success', 'failure', 'cancelled', 'timed_out', 'skipped')
        AND claim_generation > 0
        AND claim_started_at_ms >= 0
        AND claim_expires_at_ms > claim_started_at_ms
        AND claim_expires_at_ms - claim_started_at_ms <= 900000
        AND finalized_at_ms >= claim_started_at_ms
        AND finalized_at_ms < claim_expires_at_ms
        AND finalized_at_ms >= 0
    ),
    CONSTRAINT workflow_rerun_carried_job_results_plan_key_shape CHECK (
        octet_length(plan_object_key) BETWEEN 1 AND 1024
        AND plan_object_key !~ '[[:cntrl:]]'
        AND left(plan_object_key, 1) <> '/'
        AND plan_object_key !~ '(^|/)\.\.(/|$)'
    ),
    CONSTRAINT workflow_rerun_carried_job_results_source_run_fk FOREIGN KEY (
        run_id, source_run_id
    ) REFERENCES workflow_rerun_attempts(run_id, source_run_id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_carried_job_results_job_fk FOREIGN KEY (
        run_id, invocation_id, logical_job_id
    ) REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_rerun_carried_job_results_source_fk FOREIGN KEY (
        source_run_id, source_logical_job_id
    ) REFERENCES workflow_plan_v2_run_result_jobs(run_id, logical_job_id)
        ON DELETE RESTRICT
);

CREATE TABLE workflow_rerun_carried_job_outputs (
    logical_job_id UUID NOT NULL
        REFERENCES workflow_rerun_carried_job_results(logical_job_id) ON DELETE RESTRICT,
    output_name TEXT COLLATE "C" NOT NULL,
    sensitivity TEXT NOT NULL,
    public_value TEXT,
    PRIMARY KEY (logical_job_id, output_name),
    CONSTRAINT workflow_rerun_carried_job_outputs_name_shape CHECK (
        octet_length(output_name) BETWEEN 1 AND 256
        AND btrim(output_name) = output_name
        AND output_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_rerun_carried_job_outputs_classification CHECK (
        (sensitivity = 'public' AND public_value IS NOT NULL
            AND octet_length(public_value) <= 2097152)
        OR (sensitivity = 'secret_derived' AND public_value IS NULL)
    )
);

CREATE FUNCTION automata_reject_workflow_rerun_carry_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'workflow rerun carry-forward evidence is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'workflow_rerun_carry_forward_immutable';
END;
$automata$;

CREATE TRIGGER workflow_rerun_carried_job_results_no_update_delete
BEFORE UPDATE OR DELETE ON workflow_rerun_carried_job_results
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_rerun_carry_mutation();

CREATE TRIGGER workflow_rerun_carried_job_outputs_no_update_delete
BEFORE UPDATE OR DELETE ON workflow_rerun_carried_job_outputs
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_rerun_carry_mutation();

CREATE TRIGGER workflow_rerun_carried_job_results_no_truncate
BEFORE TRUNCATE ON workflow_rerun_carried_job_results
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_workflow_rerun_carry_mutation();

CREATE TRIGGER workflow_rerun_carried_job_outputs_no_truncate
BEFORE TRUNCATE ON workflow_rerun_carried_job_outputs
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_workflow_rerun_carry_mutation();

-- A carried result is terminal evidence, never executable pending work. Keep
-- that distinction on the logical job itself so every selector remains
-- fail-closed even if a future query forgets to join the rerun ledger.
ALTER TABLE workflow_plan_v2_jobs
    ADD COLUMN rerun_carried BOOLEAN NOT NULL DEFAULT FALSE;

CREATE OR REPLACE FUNCTION automata_require_pristine_logical_job_admission()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
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
                  CONSTRAINT = 'workflow_plan_v2_jobs_activation_admission_pristine';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_reject_workflow_rerun_carried_flag_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.rerun_carried IS DISTINCT FROM OLD.rerun_carried THEN
        RAISE EXCEPTION 'logical job rerun carry classification is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_jobs_rerun_carried_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_jobs_rerun_carried_immutable
BEFORE UPDATE OF rerun_carried ON workflow_plan_v2_jobs
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_rerun_carried_flag_mutation();

CREATE FUNCTION automata_validate_workflow_rerun_job_classification()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    durable_job workflow_plan_v2_jobs%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'workflow_plan_v2_jobs' THEN
        durable_job := NEW;
    ELSE
        SELECT * INTO durable_job
        FROM workflow_plan_v2_jobs
        WHERE run_id = NEW.run_id
          AND id = NEW.logical_job_id;
    END IF;

    IF durable_job.rerun_carried THEN
        IF NOT EXISTS (
            SELECT 1
            FROM workflow_rerun_attempt_jobs AS mapping
            JOIN workflow_rerun_carried_job_results AS carried
              ON carried.run_id = mapping.run_id
             AND carried.logical_job_id = mapping.logical_job_id
             AND carried.source_run_id = mapping.source_run_id
             AND carried.source_logical_job_id = mapping.source_logical_job_id
            WHERE mapping.run_id = durable_job.run_id
              AND mapping.logical_job_id = durable_job.id
              AND NOT mapping.selected
              AND durable_job.state = CASE carried.effective_conclusion
                  WHEN 'success' THEN 'completed'
                  WHEN 'failure' THEN 'failed'
                  WHEN 'timed_out' THEN 'failed'
                  WHEN 'cancelled' THEN 'cancelled'
                  WHEN 'skipped' THEN 'skipped'
              END
        ) THEN
            RAISE EXCEPTION 'carried logical job lacks exact immutable source evidence'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'workflow_rerun_carried_job_exact';
        END IF;
    ELSIF EXISTS (
        SELECT 1
        FROM workflow_rerun_attempt_jobs AS mapping
        WHERE mapping.run_id = durable_job.run_id
          AND mapping.logical_job_id = durable_job.id
          AND NOT mapping.selected
    ) THEN
        RAISE EXCEPTION 'unselected rerun job is not classified as carried'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_rerun_carried_job_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_plan_v2_jobs_validate_rerun_classification
AFTER INSERT ON workflow_plan_v2_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_rerun_job_classification();

CREATE CONSTRAINT TRIGGER workflow_rerun_attempt_jobs_validate_classification
AFTER INSERT ON workflow_rerun_attempt_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_rerun_job_classification();

-- Current result consumers need no mutable source lookup.  They can join this
-- view when a selected job has a carried successful prerequisite.
CREATE VIEW workflow_plan_v2_effective_job_results AS
SELECT result.logical_job_id, result.run_id, result.invocation_id,
       result.descriptor_digest, result.logical_key, result.source_order,
       result.plan_digest, result.plan_object_key, result.plan_size_bytes,
       result.plan_media_type, result.plan_schema,
       result.activation_output_digest, result.condition_matched,
       result.instance_count, result.instances_digest,
       result.prerequisite_count, result.prerequisites_digest,
       result.effective_conclusion,
       result.closure_has_failure, result.closure_has_cancelled,
       result.closure_has_skipped, result.output_count, result.outputs_digest,
       result.commit_digest, result.claim_owner_id, result.claim_generation,
       result.claim_started_at_ms, result.claim_expires_at_ms,
       result.finalized_at_ms, claim.state AS claim_state, FALSE AS carried
FROM workflow_plan_v2_job_results AS result
JOIN workflow_plan_v2_job_result_claims AS claim
  ON claim.logical_job_id = result.logical_job_id
 AND claim.state = 'finalized'
UNION ALL
SELECT carried.logical_job_id, carried.run_id, carried.invocation_id,
       carried.result_descriptor_digest AS descriptor_digest,
       carried.logical_key, carried.source_order,
       carried.plan_digest, carried.plan_object_key, carried.plan_size_bytes,
       carried.plan_media_type, carried.plan_schema,
       carried.activation_output_digest, carried.condition_matched,
       carried.instance_count, carried.instances_digest,
       carried.prerequisite_count, carried.prerequisites_digest,
       carried.effective_conclusion, carried.closure_has_failure,
       carried.closure_has_cancelled, carried.closure_has_skipped,
       carried.output_count, carried.outputs_digest, carried.commit_digest,
       carried.claim_owner_id, carried.claim_generation,
       carried.claim_started_at_ms, carried.claim_expires_at_ms,
       carried.finalized_at_ms, 'finalized'::TEXT AS claim_state, TRUE AS carried
FROM workflow_rerun_carried_job_results AS carried;

CREATE VIEW workflow_plan_v2_effective_job_result_outputs AS
SELECT output.logical_job_id, output.output_name, output.sensitivity, output.public_value
FROM workflow_plan_v2_job_result_outputs AS output
JOIN workflow_plan_v2_job_result_claims AS claim
  ON claim.logical_job_id = output.logical_job_id
 AND claim.state = 'finalized'
UNION ALL
SELECT output.logical_job_id, output.output_name, output.sensitivity, output.public_value
FROM workflow_rerun_carried_job_outputs AS output;

-- Keep the signed/scheduled attempt-one origins separate, then extend the
-- stable manifest-origin view in place.  Existing trigger and authority
-- dependencies retain the view OID and therefore observe rerun attempts too.
CREATE VIEW github_workflow_run_base_manifest_origins AS
SELECT delivery_run.tenant_id,
       delivery_run.repository_id,
       delivery_run.workflow_id,
       delivery_run.snapshot_id,
       delivery_run.run_id,
       delivery_run.root_invocation_id,
       'provider_delivery'::TEXT AS origin_kind,
       delivery_run.provider_delivery_id AS origin_id,
       'provider_delivery'::TEXT AS admission_idempotency_kind,
       delivery_run.provider_delivery_idempotency_key AS admission_idempotency_key,
       delivery_run.github_check_subject_id,
       delivery_run.github_check_head_sha,
       delivery_run.workflow_path,
       delivery_run.source_digest,
       delivery_run.event_name,
       delivery_run.event_digest,
       delivery_run.git_ref,
       delivery_run.workflow_plan_schema,
       delivery_run.plan_digest,
       delivery_run.logical_admission_digest,
       delivery_run.admitted_at_ms,
       delivery_run.subject_evidence_sha256,
       delivery.provider_connection_id,
       delivery.provider_installation_id,
       delivery.github_repository_id,
       delivery.github_repository_owner_id,
       delivery.github_repository_name,
       delivery.repository_visibility,
       delivery.provider_manifest_revision,
       delivery.provider_manifest_digest,
       delivery.authenticated_webhook_verifier_fingerprint_sha256,
       delivery.authenticated_webhook_verifier_revision,
       delivery.checks_authority_id,
       delivery.checks_authority_identity_digest,
       delivery.checks_authority_app_configuration_revision,
       delivery.checks_authority_policy_revision,
       delivery.private_source_authority_id,
       delivery.private_source_authority_identity_digest,
       delivery.private_source_authority_app_configuration_revision,
       delivery.private_source_authority_policy_revision
FROM github_workflow_run_subject_evidence AS delivery_run
JOIN github_provider_delivery_evidence AS delivery
  ON delivery.tenant_id = delivery_run.tenant_id
 AND delivery.repository_id = delivery_run.repository_id
 AND delivery.provider_delivery_id = delivery_run.provider_delivery_id
UNION ALL
SELECT schedule_run.tenant_id,
       schedule_run.repository_id,
       schedule_run.workflow_id,
       schedule_run.snapshot_id,
       schedule_run.run_id,
       schedule_run.root_invocation_id,
       'scheduled_fire'::TEXT AS origin_kind,
       schedule_run.schedule_fire_id AS origin_id,
       'operation'::TEXT AS admission_idempotency_kind,
       schedule_run.schedule_fire_id::TEXT AS admission_idempotency_key,
       schedule_run.github_check_subject_id,
       schedule_run.github_check_head_sha,
       schedule_run.workflow_path,
       schedule_run.source_digest,
       schedule_run.event_name,
       schedule_run.event_digest,
       schedule_run.git_ref,
       schedule_run.workflow_plan_schema,
       schedule_run.plan_digest,
       schedule_run.logical_admission_digest,
       schedule_run.admitted_at_ms,
       schedule_run.subject_evidence_sha256,
       schedule_check.provider_connection_id,
       manifest.provider_installation_id,
       manifest.github_repository_id,
       schedule_run.github_repository_owner_id,
       manifest.github_repository_name,
       manifest.repository_visibility,
       schedule_check.provider_manifest_revision,
       schedule_check.provider_manifest_digest,
       manifest.webhook_verifier_fingerprint_sha256,
       manifest.webhook_verifier_revision,
       schedule_check.checks_authority_id,
       schedule_check.checks_authority_identity_digest,
       schedule_check.checks_authority_app_configuration_revision,
       schedule_check.checks_authority_policy_revision,
       registry.private_source_authority_id,
       registry.private_source_authority_identity_digest,
       registry.private_source_authority_app_configuration_revision,
       registry.private_source_authority_policy_revision
FROM github_schedule_workflow_run_subject_evidence AS schedule_run
JOIN github_schedule_check_evidence AS schedule_check
  ON schedule_check.schedule_fire_id = schedule_run.schedule_fire_id
 AND schedule_check.tenant_id = schedule_run.tenant_id
 AND schedule_check.repository_id = schedule_run.repository_id
 AND schedule_check.github_check_subject_id = schedule_run.github_check_subject_id
JOIN github_schedule_registry_revisions AS registry
  ON registry.tenant_id = schedule_check.tenant_id
 AND registry.repository_id = schedule_check.repository_id
 AND registry.provider_connection_id = schedule_check.provider_connection_id
 AND registry.registry_id = schedule_check.registry_id
 AND registry.manifest_revision = schedule_check.provider_manifest_revision
 AND registry.manifest_digest = schedule_check.provider_manifest_digest
 AND registry.default_branch_ref = schedule_check.default_branch_ref
 AND registry.source_revision = schedule_check.source_revision
JOIN github_provider_manifest_revisions AS manifest
  ON manifest.tenant_id = schedule_check.tenant_id
 AND manifest.repository_id = schedule_check.repository_id
 AND manifest.provider_connection_id = schedule_check.provider_connection_id
 AND manifest.manifest_revision = schedule_check.provider_manifest_revision
 AND manifest.manifest_digest = schedule_check.provider_manifest_digest;

CREATE OR REPLACE VIEW github_workflow_run_manifest_origins AS
SELECT * FROM github_workflow_run_base_manifest_origins
UNION ALL
SELECT origin.tenant_id,
       origin.repository_id,
       rerun.workflow_id,
       rerun.snapshot_id,
       attempt.run_id,
       marker.root_invocation_id,
       'workflow_rerun'::TEXT AS origin_kind,
       request.operation_id AS origin_id,
       'operation'::TEXT AS admission_idempotency_kind,
       ('workflow-rerun:' || request.operation_id::TEXT)::TEXT
           AS admission_idempotency_key,
       origin.github_check_subject_id,
       origin.github_check_head_sha,
       origin.workflow_path,
       origin.source_digest,
       origin.event_name,
       origin.event_digest,
       origin.git_ref,
       origin.workflow_plan_schema,
       origin.plan_digest,
       marker.admission_digest AS logical_admission_digest,
       marker.admitted_at_ms,
       origin.subject_evidence_sha256,
       origin.provider_connection_id,
       origin.provider_installation_id,
       origin.github_repository_id,
       origin.github_repository_owner_id,
       origin.github_repository_name,
       origin.repository_visibility,
       origin.provider_manifest_revision,
       origin.provider_manifest_digest,
       origin.authenticated_webhook_verifier_fingerprint_sha256,
       origin.authenticated_webhook_verifier_revision,
       origin.checks_authority_id,
       origin.checks_authority_identity_digest,
       origin.checks_authority_app_configuration_revision,
       origin.checks_authority_policy_revision,
       origin.private_source_authority_id,
       origin.private_source_authority_identity_digest,
       origin.private_source_authority_app_configuration_revision,
       origin.private_source_authority_policy_revision
FROM workflow_rerun_attempts AS attempt
JOIN workflow_rerun_requests AS request
  ON request.rerun_run_id = attempt.run_id
 AND request.committed_at_ms = attempt.created_at_ms
JOIN workflow_runs AS rerun ON rerun.id = attempt.run_id
JOIN workflow_plan_v2_runs AS marker ON marker.run_id = attempt.run_id
JOIN github_workflow_run_base_manifest_origins AS origin
  ON origin.run_id = attempt.root_run_id
WHERE attempt.source_run_id IS NOT NULL;

-- The deferred evidence seal and root graph window consume the same closed
-- manifest-origin projection for deliveries, schedules, and reruns.
CREATE OR REPLACE FUNCTION automata_required_github_subject_evidence_committed()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
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
        FROM github_workflow_run_manifest_origins AS origin
        WHERE origin.origin_kind = 'workflow_rerun'
          AND origin.tenant_id = receipt.tenant_id
          AND origin.repository_id = receipt.repository_id
          AND origin.run_id = receipt.run_id
          AND origin.admission_idempotency_kind = receipt.idempotency_kind
          AND origin.admission_idempotency_key = receipt.idempotency_key
          AND origin.logical_admission_digest = receipt.request_digest
          AND origin.admitted_at_ms = receipt.committed_at_ms;
    ELSIF receipt.github_subject_evidence_required
        AND receipt.idempotency_kind = 'operation'
        AND receipt.repository_id IS NOT NULL
        AND receipt.run_id IS NOT NULL
        AND receipt.committed_at_ms IS NOT NULL
    THEN
        SELECT count(*) INTO evidence_count
        FROM github_schedule_workflow_run_subject_evidence AS evidence
        WHERE evidence.tenant_id = receipt.tenant_id
          AND evidence.repository_id = receipt.repository_id
          AND evidence.run_id = receipt.run_id
          AND evidence.schedule_fire_id::TEXT = receipt.idempotency_key
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
$automata$;

CREATE OR REPLACE FUNCTION automata_require_open_workflow_admission_graph()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
    FROM workflow_plan_v2_runs AS marker
    JOIN workflow_admission_receipts AS receipt ON receipt.run_id = marker.run_id
    JOIN github_workflow_run_manifest_origins AS origin
      ON origin.run_id = marker.run_id
     AND origin.root_invocation_id = marker.root_invocation_id
    JOIN workflow_plan_v2_runtime_policy_pins AS pin ON pin.run_id = marker.run_id
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
    FROM workflow_plan_v2_reusable_call_publications AS publication
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = publication.run_id
    WHERE publication.run_id = NEW.run_id
      AND publication.child_invocation_id = NEW.invocation_id
      AND publication.child_graph_sealed_at_ms IS NULL
      AND marker.admission_graph_sealed_at_ms IS NOT NULL
      AND marker.state IN ('pending', 'active')
      AND NOT EXISTS (
          SELECT 1 FROM workflow_plan_v2_run_result_claims AS claim
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
$automata$;

-- Selected jobs consume carried prerequisites through the effective result
-- boundary.  The original result/claim pair and the carried row are both
-- immutable, and the latter is foreign-keyed to the source run aggregate.
CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_job_result_claim()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_jobs AS job
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = job.run_id
         AND invocation.id = job.invocation_id
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.invocation_id = job.invocation_id
         AND publication.logical_job_id = job.id
        WHERE job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.id = NEW.logical_job_id
          AND job.execution_kind = 'steps'
          AND job.state IN ('activated', 'skipped')
          AND invocation.plan_schema = 2
          AND invocation.plan_media_type =
              'application/vnd.automata.workflow-plan+json'
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND NEW.claimed_at_ms >= publication.published_at_ms
          AND (
              (publication.instance_count = 0 AND NOT EXISTS (
                  SELECT 1 FROM workflow_plan_v2_instances AS instance
                  WHERE instance.run_id = job.run_id
                    AND instance.invocation_id = job.invocation_id
                    AND instance.logical_job_id = job.id
              )) OR (
                  publication.instance_count > 0
                  AND publication.instance_count = (
                      SELECT count(*)
                      FROM workflow_plan_v2_instances AS instance
                      JOIN workflow_plan_v2_instance_results AS result
                        ON result.instance_id = instance.id
                       AND result.run_id = instance.run_id
                       AND result.invocation_id = instance.invocation_id
                       AND result.logical_job_id = instance.logical_job_id
                      JOIN workflow_plan_v2_instance_result_claims AS claim
                        ON claim.instance_id = result.instance_id
                       AND claim.state = 'finalized'
                      WHERE instance.run_id = job.run_id
                        AND instance.invocation_id = job.invocation_id
                        AND instance.logical_job_id = job.id
                  )
                  AND NEW.claimed_at_ms >= COALESCE((
                      SELECT max(result.finalized_at_ms)
                      FROM workflow_plan_v2_instance_results AS result
                      WHERE result.run_id = job.run_id
                        AND result.invocation_id = job.invocation_id
                        AND result.logical_job_id = job.id
                  ), 0)
              )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_dependencies AS dependency
              LEFT JOIN workflow_plan_v2_effective_job_results AS prerequisite
                ON prerequisite.logical_job_id = dependency.prerequisite_job_id
               AND prerequisite.run_id = dependency.run_id
               AND prerequisite.invocation_id = dependency.invocation_id
              WHERE dependency.run_id = job.run_id
                AND dependency.invocation_id = job.invocation_id
                AND dependency.logical_job_id = job.id
                AND (prerequisite.logical_job_id IS NULL
                     OR prerequisite.claim_state IS DISTINCT FROM 'finalized'
                     OR NEW.claimed_at_ms < prerequisite.finalized_at_ms)
          )
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 job-result claim is not exactly ready'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_run_result_claim()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state <> 'aggregating' THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_runs AS marker
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE marker.run_id = NEW.run_id
          AND marker.root_invocation_id = NEW.root_invocation_id
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND marker.revision < 9223372036854775807
          AND invocation.plan_schema = 2
          AND invocation.state IN ('pending', 'active')
          AND invocation.revision < 9223372036854775807
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND run.status IN ('queued', 'in_progress', 'cancelled')
          AND NEW.claimed_at_ms >= greatest(
              marker.updated_at_ms,
              invocation.updated_at_ms,
              run.updated_at_ms,
              COALESCE((
                  SELECT max(result.finalized_at_ms)
                  FROM workflow_plan_v2_effective_job_results AS result
                  WHERE result.run_id = marker.run_id
                    AND result.invocation_id = marker.root_invocation_id
              ), 0)
          )
          AND (SELECT count(*)
               FROM workflow_plan_v2_jobs AS job
               WHERE job.run_id = marker.run_id
                 AND job.invocation_id = marker.root_invocation_id)
              BETWEEN 1 AND 1024
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_jobs AS job
              LEFT JOIN workflow_plan_v2_effective_job_results AS result
                ON result.run_id = job.run_id
               AND result.invocation_id = job.invocation_id
               AND result.logical_job_id = job.id
              WHERE job.run_id = marker.run_id
                AND job.invocation_id = marker.root_invocation_id
                AND (
                    result.logical_job_id IS NULL
                    OR result.claim_state IS DISTINCT FROM 'finalized'
                    OR result.logical_key IS DISTINCT FROM job.logical_key
                    OR result.source_order IS DISTINCT FROM job.source_order
                    OR job.state IS DISTINCT FROM CASE result.effective_conclusion
                        WHEN 'success' THEN 'completed'
                        WHEN 'failure' THEN 'failed'
                        WHEN 'timed_out' THEN 'failed'
                        WHEN 'cancelled' THEN 'cancelled'
                        WHEN 'skipped' THEN 'skipped'
                    END
                    OR result.prerequisite_count IS DISTINCT FROM (
                        SELECT count(*)::INTEGER
                        FROM workflow_plan_v2_dependencies AS dependency
                        WHERE dependency.run_id = job.run_id
                          AND dependency.invocation_id = job.invocation_id
                          AND dependency.logical_job_id = job.id
                    )
                )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM (
                  SELECT job.source_order,
                         row_number() OVER (ORDER BY job.source_order) - 1 AS expected_order
                  FROM workflow_plan_v2_jobs AS job
                  WHERE job.run_id = marker.run_id
                    AND job.invocation_id = marker.root_invocation_id
              ) AS ordered
              WHERE ordered.source_order <> ordered.expected_order
          )
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run-result claim is not exactly ready'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_enforce_workflow_plan_v2_run_result_claim_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.root_invocation_id IS DISTINCT FROM OLD.root_invocation_id
        OR NEW.descriptor_digest IS DISTINCT FROM OLD.descriptor_digest
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run-result claim identity is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.state = 'aggregating' AND NEW.state = 'aggregating' THEN
        IF NEW.generation <> OLD.generation + 1
            OR NEW.claimed_at_ms < OLD.expires_at_ms
            OR NEW.expires_at_ms <= NEW.claimed_at_ms
            OR NEW.expires_at_ms - NEW.claimed_at_ms > 900000
            OR NEW.updated_at_ms <> NEW.claimed_at_ms
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 run-result takeover is not fenced'
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
                FROM workflow_plan_v2_run_results AS result
                JOIN workflow_plan_v2_invocations AS invocation
                  ON invocation.run_id = result.run_id
                 AND invocation.id = result.root_invocation_id
                JOIN workflow_plan_v2_runs AS marker ON marker.run_id = result.run_id
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
                      FROM workflow_plan_v2_run_result_jobs AS evidence
                      WHERE evidence.run_id = result.run_id
                  )
                  AND result.job_count = (
                      SELECT count(*)::INTEGER
                      FROM workflow_plan_v2_jobs AS job
                      WHERE job.run_id = result.run_id
                        AND job.invocation_id = result.root_invocation_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM workflow_plan_v2_jobs AS job
                      LEFT JOIN workflow_plan_v2_run_result_jobs AS evidence
                        ON evidence.run_id = job.run_id
                       AND evidence.root_invocation_id = job.invocation_id
                       AND evidence.logical_job_id = job.id
                      LEFT JOIN workflow_plan_v2_effective_job_results AS logical_result
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
                          SELECT 1 FROM workflow_plan_v2_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion = 'failure'
                      ) THEN 'failure'
                      WHEN EXISTS (
                          SELECT 1 FROM workflow_plan_v2_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion = 'timed_out'
                      ) THEN 'timed_out'
                      WHEN EXISTS (
                          SELECT 1 FROM workflow_plan_v2_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion = 'cancelled'
                      ) THEN 'cancelled'
                      WHEN NOT EXISTS (
                          SELECT 1 FROM workflow_plan_v2_run_result_jobs AS evidence
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
            RAISE EXCEPTION 'WorkflowPlan-v2 run-result finalization lacks exact evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'WorkflowPlan-v2 run-result claim transition is invalid'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_run_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_run_result_claims AS claim
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = claim.run_id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE claim.run_id = NEW.run_id
          AND claim.root_invocation_id = NEW.root_invocation_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.state = 'aggregating'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND marker.root_invocation_id = NEW.root_invocation_id
          AND marker.admission_digest = NEW.admission_digest
          AND marker.state = NEW.marker_state
          AND marker.revision = NEW.marker_revision
          AND marker.updated_at_ms = NEW.marker_updated_at_ms
          AND invocation.state = NEW.invocation_state
          AND invocation.revision = NEW.invocation_revision
          AND invocation.updated_at_ms = NEW.invocation_updated_at_ms
          AND run.status = NEW.workflow_status
          AND run.updated_at_ms = NEW.workflow_updated_at_ms
          AND NEW.job_count = (
              SELECT count(*)::INTEGER
              FROM workflow_plan_v2_jobs AS job
              WHERE job.run_id = NEW.run_id
                AND job.invocation_id = NEW.root_invocation_id
          )
          AND NEW.finalized_at_ms >= greatest(
              NEW.marker_updated_at_ms,
              NEW.invocation_updated_at_ms,
              NEW.workflow_updated_at_ms,
              COALESCE((
                  SELECT max(result.finalized_at_ms)
                  FROM workflow_plan_v2_effective_job_results AS result
                  WHERE result.run_id = NEW.run_id
                    AND result.invocation_id = NEW.root_invocation_id
              ), 0)
          )
          AND NEW.finalized_at_ms < claim.expires_at_ms
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run result lacks exact descriptor/fence evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_run_result_job()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_run_results AS run_result
        JOIN workflow_plan_v2_run_result_claims AS run_claim
          ON run_claim.run_id = run_result.run_id
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = run_result.run_id
         AND job.invocation_id = run_result.root_invocation_id
         AND job.id = NEW.logical_job_id
        JOIN workflow_plan_v2_effective_job_results AS logical_result
          ON logical_result.run_id = job.run_id
         AND logical_result.invocation_id = job.invocation_id
         AND logical_result.logical_job_id = job.id
        WHERE run_result.run_id = NEW.run_id
          AND run_result.root_invocation_id = NEW.root_invocation_id
          AND run_claim.state = 'aggregating'
          AND job.logical_key = NEW.logical_key
          AND job.source_order = NEW.source_order
          AND logical_result.claim_state = 'finalized'
          AND logical_result.descriptor_digest = NEW.descriptor_digest
          AND logical_result.effective_conclusion = NEW.effective_conclusion
          AND logical_result.closure_has_failure = NEW.closure_has_failure
          AND logical_result.closure_has_cancelled = NEW.closure_has_cancelled
          AND logical_result.closure_has_skipped = NEW.closure_has_skipped
          AND logical_result.instance_count = NEW.instance_count
          AND logical_result.instances_digest = NEW.instances_digest
          AND logical_result.prerequisite_count = NEW.prerequisite_count
          AND logical_result.prerequisites_digest = NEW.prerequisites_digest
          AND logical_result.output_count = NEW.output_count
          AND logical_result.outputs_digest = NEW.outputs_digest
          AND logical_result.commit_digest = NEW.job_commit_digest
          AND logical_result.finalized_at_ms = NEW.job_finalized_at_ms
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run-result job evidence is not exact'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;
