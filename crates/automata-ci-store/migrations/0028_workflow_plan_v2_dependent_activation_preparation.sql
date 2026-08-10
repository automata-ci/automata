-- Current-only durable preparation for logical-job activation. The claim pins
-- the exact admitted plan/event/execution metadata, trusted workspace-policy
-- output, and every finalized direct prerequisite result/output. Canonical
-- runtime-context blobs are written outside SQL and bound under a live fence.

-- There is deliberately no conversion from the retired root-only activation
-- path. Existing activation state must be recreated under the current contract.
DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM workflow_plan_v2_activation_publications)
        OR EXISTS (
            SELECT 1
            FROM workflow_plan_v2_jobs
            WHERE activation_input_digest IS NOT NULL
               OR state <> 'pending'
        )
    THEN
        RAISE EXCEPTION 'logical activation state must be recreated before durable preparation'
            USING ERRCODE = '23514';
    END IF;
END;
$automata$;

CREATE FUNCTION automata_is_canonical_logical_activation_workspace(
    workspace TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $automata$
DECLARE
    component TEXT;
    components TEXT[];
BEGIN
    IF octet_length(workspace) NOT BETWEEN 2 AND 1024
        OR workspace ~ '[[:cntrl:]]'
        OR btrim(workspace) <> workspace
    THEN
        RETURN FALSE;
    END IF;

    IF left(workspace, 1) = '/' THEN
        IF workspace = '/' OR position('//' IN workspace) > 0 THEN
            RETURN FALSE;
        END IF;
        components := string_to_array(substring(workspace FROM 2), '/');
    ELSIF workspace ~ E'^[A-Za-z]:\\\\' THEN
        IF position('/' IN workspace) > 0
            OR position(E'\\\\\\\\' IN workspace) > 0
        THEN
            RETURN FALSE;
        END IF;
        components := string_to_array(substring(workspace FROM 4), E'\\');
    ELSE
        RETURN FALSE;
    END IF;

    FOREACH component IN ARRAY components LOOP
        IF component = '' OR component = '.' OR component = '..' THEN
            RETURN FALSE;
        END IF;
    END LOOP;
    RETURN TRUE;
END;
$automata$;

CREATE TABLE workflow_plan_v2_activation_preparation_claims (
    logical_job_id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    descriptor_digest BYTEA NOT NULL,
    logical_key TEXT COLLATE "C" NOT NULL,
    source_order INTEGER NOT NULL,
    workflow_id UUID NOT NULL,
    workflow_name TEXT COLLATE "C" NOT NULL,
    git_ref TEXT COLLATE "C" NOT NULL,
    actor TEXT COLLATE "C",
    run_number BIGINT NOT NULL,
    run_attempt INTEGER NOT NULL,
    plan_digest BYTEA NOT NULL,
    plan_object_key TEXT COLLATE "C" NOT NULL,
    plan_size_bytes BIGINT NOT NULL,
    plan_media_type TEXT COLLATE "C" NOT NULL,
    plan_schema SMALLINT NOT NULL,
    event_digest BYTEA NOT NULL,
    event_object_key TEXT COLLATE "C" NOT NULL,
    event_size_bytes BIGINT NOT NULL,
    event_media_type TEXT COLLATE "C" NOT NULL,
    base_context_kind TEXT NOT NULL,
    workspace TEXT COLLATE "C" NOT NULL,
    prerequisite_count INTEGER NOT NULL,
    prerequisites_digest BYTEA NOT NULL,
    aggregate_status TEXT NOT NULL,
    evidence_ready_at_ms BIGINT NOT NULL,
    state TEXT NOT NULL,
    owner_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    claimed_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_activation_preparation_claims_identity_unique
        UNIQUE (run_id, invocation_id, logical_job_id),
    CONSTRAINT workflow_plan_v2_activation_preparation_claims_target_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id)
        ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_activation_preparation_claims_ids CHECK (
        logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND workflow_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_activation_preparation_claims_digests CHECK (
        octet_length(descriptor_digest) = 32
        AND octet_length(plan_digest) = 32
        AND octet_length(event_digest) = 32
        AND octet_length(prerequisites_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_activation_preparation_claims_key CHECK (
        octet_length(logical_key) BETWEEN 1 AND 256
        AND btrim(logical_key) = logical_key
        AND logical_key !~ '[[:cntrl:]]'
        AND source_order BETWEEN 0 AND 1023
    ),
    CONSTRAINT workflow_plan_v2_activation_preparation_claims_execution CHECK (
        octet_length(workflow_name) BETWEEN 1 AND 1024
        AND workflow_name !~ '[[:cntrl:]]'
        AND octet_length(git_ref) BETWEEN 6 AND 1024
        AND git_ref LIKE 'refs/%'
        AND git_ref !~ '[[:cntrl:]]'
        AND (actor IS NULL OR (
            octet_length(actor) BETWEEN 1 AND 1024
            AND actor !~ '[[:cntrl:]]'
        ))
        AND run_number > 0
        AND run_attempt > 0
    ),
    CONSTRAINT workflow_plan_v2_activation_preparation_claims_plan CHECK (
        octet_length(plan_object_key) BETWEEN 1 AND 1024
        AND plan_object_key !~ '[[:cntrl:]]'
        AND left(plan_object_key, 1) <> '/'
        AND plan_object_key !~ '(^|/)\.\.(/|$)'
        AND plan_size_bytes BETWEEN 1 AND 16777216
        AND plan_media_type = 'application/vnd.automata.workflow-plan+json'
        AND plan_schema = 2
    ),
    CONSTRAINT workflow_plan_v2_activation_preparation_claims_event CHECK (
        octet_length(event_object_key) BETWEEN 1 AND 1024
        AND event_object_key !~ '[[:cntrl:]]'
        AND left(event_object_key, 1) <> '/'
        AND event_object_key !~ '(^|/)\.\.(/|$)'
        AND event_size_bytes BETWEEN 1 AND 26214400
        AND event_media_type = 'application/json'
    ),
    CONSTRAINT workflow_plan_v2_activation_preparation_claims_authority CHECK (
        base_context_kind = 'root_empty'
        AND automata_is_canonical_logical_activation_workspace(workspace)
    ),
    CONSTRAINT workflow_plan_v2_activation_preparation_claims_evidence CHECK (
        prerequisite_count BETWEEN 0 AND 128
        AND aggregate_status IN ('success', 'failure', 'cancelled', 'skipped')
        AND evidence_ready_at_ms >= 0
    ),
    CONSTRAINT workflow_plan_v2_activation_preparation_claims_state CHECK (
        state IN ('preparing', 'prepared')
    ),
    CONSTRAINT workflow_plan_v2_activation_preparation_claims_fence CHECK (
        generation > 0
        AND claimed_at_ms >= evidence_ready_at_ms
        AND expires_at_ms > claimed_at_ms
        AND expires_at_ms - claimed_at_ms <= 900000
        AND created_at_ms <= claimed_at_ms
        AND updated_at_ms >= claimed_at_ms
    )
);

CREATE INDEX workflow_plan_v2_activation_preparation_claims_expired
    ON workflow_plan_v2_activation_preparation_claims (
        expires_at_ms, run_id, invocation_id, logical_job_id
    ) WHERE state = 'preparing';

CREATE TABLE workflow_plan_v2_activation_preparation_prerequisites (
    logical_job_id UUID NOT NULL
        REFERENCES workflow_plan_v2_activation_preparation_claims(logical_job_id)
        ON DELETE CASCADE,
    prerequisite_job_id UUID NOT NULL,
    logical_key TEXT COLLATE "C" NOT NULL,
    source_order INTEGER NOT NULL,
    result_descriptor_digest BYTEA NOT NULL,
    outputs_digest BYTEA NOT NULL,
    commit_digest BYTEA NOT NULL,
    effective_conclusion TEXT NOT NULL,
    closure_has_failure BOOLEAN NOT NULL,
    closure_has_cancelled BOOLEAN NOT NULL,
    closure_has_skipped BOOLEAN NOT NULL,
    output_count INTEGER NOT NULL,
    finalized_at_ms BIGINT NOT NULL,
    PRIMARY KEY (logical_job_id, prerequisite_job_id),
    UNIQUE (logical_job_id, logical_key),
    UNIQUE (logical_job_id, source_order),
    CONSTRAINT workflow_plan_v2_activation_preparation_prerequisites_shape CHECK (
        prerequisite_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND octet_length(logical_key) BETWEEN 1 AND 256
        AND btrim(logical_key) = logical_key
        AND logical_key !~ '[[:cntrl:]]'
        AND source_order BETWEEN 0 AND 1023
        AND octet_length(result_descriptor_digest) = 32
        AND octet_length(outputs_digest) = 32
        AND octet_length(commit_digest) = 32
        AND effective_conclusion IN (
            'success', 'failure', 'cancelled', 'timed_out', 'skipped'
        )
        AND output_count BETWEEN 0 AND 256
        AND finalized_at_ms >= 0
        AND (effective_conclusion NOT IN ('failure', 'timed_out')
             OR closure_has_failure)
        AND (effective_conclusion <> 'cancelled' OR closure_has_cancelled)
        AND (effective_conclusion <> 'skipped' OR closure_has_skipped)
    )
);

CREATE TABLE workflow_plan_v2_activation_preparation_outputs (
    logical_job_id UUID NOT NULL,
    prerequisite_job_id UUID NOT NULL,
    output_name TEXT COLLATE "C" NOT NULL,
    sensitivity TEXT NOT NULL,
    public_value TEXT,
    PRIMARY KEY (logical_job_id, prerequisite_job_id, output_name),
    CONSTRAINT workflow_plan_v2_activation_preparation_outputs_prerequisite_fk
        FOREIGN KEY (logical_job_id, prerequisite_job_id)
        REFERENCES workflow_plan_v2_activation_preparation_prerequisites(
            logical_job_id, prerequisite_job_id
        ) ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_activation_preparation_outputs_shape CHECK (
        octet_length(output_name) BETWEEN 1 AND 256
        AND btrim(output_name) = output_name
        AND output_name !~ '[[:cntrl:]]'
        AND (
            (sensitivity = 'public' AND public_value IS NOT NULL
             AND octet_length(public_value) <= 2097152)
            OR (sensitivity = 'secret_derived' AND public_value IS NULL)
        )
    )
);

CREATE TABLE workflow_plan_v2_activation_preparations (
    logical_job_id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    descriptor_digest BYTEA NOT NULL,
    base_context_digest BYTEA NOT NULL,
    base_context_object_key TEXT COLLATE "C" NOT NULL,
    base_context_size_bytes BIGINT NOT NULL,
    base_context_media_type TEXT COLLATE "C" NOT NULL,
    base_context_schema SMALLINT NOT NULL,
    prerequisite_context_digest BYTEA NOT NULL,
    prerequisite_context_object_key TEXT COLLATE "C" NOT NULL,
    prerequisite_context_size_bytes BIGINT NOT NULL,
    prerequisite_context_media_type TEXT COLLATE "C" NOT NULL,
    prerequisite_context_schema SMALLINT NOT NULL,
    activation_input_digest BYTEA NOT NULL,
    claim_owner_id UUID NOT NULL,
    claim_generation BIGINT NOT NULL,
    claim_started_at_ms BIGINT NOT NULL,
    claim_expires_at_ms BIGINT NOT NULL,
    bound_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_activation_preparations_claim_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_activation_preparation_claims(
            run_id, invocation_id, logical_job_id
        ) ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_activation_preparations_ids CHECK (
        logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_activation_preparations_digests CHECK (
        octet_length(descriptor_digest) = 32
        AND octet_length(base_context_digest) = 32
        AND octet_length(prerequisite_context_digest) = 32
        AND octet_length(activation_input_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_activation_preparations_contexts CHECK (
        base_context_object_key <> prerequisite_context_object_key
        AND octet_length(base_context_object_key) BETWEEN 1 AND 1024
        AND base_context_object_key !~ '[[:cntrl:]]'
        AND left(base_context_object_key, 1) <> '/'
        AND base_context_object_key !~ '(^|/)\.\.(/|$)'
        AND base_context_size_bytes BETWEEN 1 AND 16777216
        AND base_context_media_type =
            'application/vnd.automata.job-runtime-context.protobuf'
        AND base_context_schema = 2
        AND octet_length(prerequisite_context_object_key) BETWEEN 1 AND 1024
        AND prerequisite_context_object_key !~ '[[:cntrl:]]'
        AND left(prerequisite_context_object_key, 1) <> '/'
        AND prerequisite_context_object_key !~ '(^|/)\.\.(/|$)'
        AND prerequisite_context_size_bytes BETWEEN 1 AND 16777216
        AND prerequisite_context_media_type =
            'application/vnd.automata.job-runtime-context.protobuf'
        AND prerequisite_context_schema = 2
    ),
    CONSTRAINT workflow_plan_v2_activation_preparations_fence CHECK (
        claim_generation > 0
        AND claim_started_at_ms >= 0
        AND claim_expires_at_ms > claim_started_at_ms
        AND claim_expires_at_ms - claim_started_at_ms <= 900000
        AND bound_at_ms >= claim_started_at_ms
        AND bound_at_ms < claim_expires_at_ms
    )
);

CREATE FUNCTION automata_validate_logical_activation_preparation_claim()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    expected_count BIGINT;
    finalized_count BIGINT;
    latest_ready BIGINT;
    expected_status TEXT;
BEGIN
    SELECT count(dependency.prerequisite_job_id),
           count(result.logical_job_id),
           greatest(job.created_at_ms, coalesce(max(result.finalized_at_ms), 0)),
           CASE
               WHEN coalesce(bool_or(
                   result.closure_has_failure
                   OR result.effective_conclusion IN ('failure', 'timed_out')
               ), FALSE) THEN 'failure'
               WHEN coalesce(bool_or(
                   result.closure_has_cancelled
                   OR result.effective_conclusion = 'cancelled'
               ), FALSE) THEN 'cancelled'
               WHEN coalesce(bool_or(
                   result.closure_has_skipped
                   OR result.effective_conclusion = 'skipped'
               ), FALSE) THEN 'skipped'
               ELSE 'success'
           END
      INTO expected_count, finalized_count, latest_ready, expected_status
    FROM workflow_plan_v2_jobs AS job
    JOIN workflow_plan_v2_invocations AS invocation
      ON invocation.run_id = job.run_id AND invocation.id = job.invocation_id
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = job.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    LEFT JOIN workflow_plan_v2_dependencies AS dependency
      ON dependency.run_id = job.run_id
     AND dependency.invocation_id = job.invocation_id
     AND dependency.logical_job_id = job.id
    LEFT JOIN workflow_plan_v2_job_results AS result
      ON result.run_id = dependency.run_id
     AND result.invocation_id = dependency.invocation_id
     AND result.logical_job_id = dependency.prerequisite_job_id
     AND EXISTS (
         SELECT 1
         FROM workflow_plan_v2_job_result_claims AS result_claim
         WHERE result_claim.logical_job_id = result.logical_job_id
           AND result_claim.state = 'finalized'
     )
    WHERE job.run_id = NEW.run_id
      AND job.invocation_id = NEW.invocation_id
      AND job.id = NEW.logical_job_id
      AND job.logical_key = NEW.logical_key
      AND job.source_order = NEW.source_order
      AND job.execution_kind = 'steps'
      AND job.state = 'pending'
      AND invocation.id = marker.root_invocation_id
      AND invocation.plan_digest = NEW.plan_digest
      AND invocation.plan_object_key = NEW.plan_object_key
      AND invocation.plan_size_bytes = NEW.plan_size_bytes
      AND invocation.plan_media_type = NEW.plan_media_type
      AND invocation.plan_schema = NEW.plan_schema
      AND invocation.state IN ('pending', 'active')
      AND marker.orchestration_schema = 1
      AND marker.state IN ('pending', 'active')
      AND run.admission_epoch = 4
      AND run.plan_schema = 2
      AND run.workflow_id = NEW.workflow_id
      AND run.workflow_name = NEW.workflow_name
      AND run.git_ref = NEW.git_ref
      AND run.actor IS NOT DISTINCT FROM NEW.actor
      AND run.run_number = NEW.run_number
      AND run.run_attempt = NEW.run_attempt
      AND run.event_digest = NEW.event_digest
      AND run.event_object_key = NEW.event_object_key
      AND run.event_size_bytes = NEW.event_size_bytes
      AND run.event_media_type = NEW.event_media_type
    GROUP BY job.created_at_ms;

    IF NOT FOUND
        OR expected_count <> finalized_count
        OR expected_count <> NEW.prerequisite_count
        OR latest_ready <> NEW.evidence_ready_at_ms
        OR expected_status <> NEW.aggregate_status
        OR NEW.claimed_at_ms < latest_ready
        OR NEW.created_at_ms <> NEW.claimed_at_ms
    THEN
        RAISE EXCEPTION 'logical activation preparation claim lacks exact current evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_preparation_claims_validate
BEFORE INSERT ON workflow_plan_v2_activation_preparation_claims
FOR EACH ROW
EXECUTE FUNCTION automata_validate_logical_activation_preparation_claim();

CREATE FUNCTION automata_enforce_logical_activation_preparation_claim_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
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
        FROM workflow_plan_v2_jobs AS job
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = job.run_id AND invocation.id = job.invocation_id
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE job.run_id = OLD.run_id
          AND job.invocation_id = OLD.invocation_id
          AND job.id = OLD.logical_job_id
          AND job.execution_kind = 'steps'
          AND job.state = 'pending'
          AND invocation.id = marker.root_invocation_id
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
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
                FROM workflow_plan_v2_activation_preparations AS preparation
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
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_preparation_claims_enforce_update
BEFORE UPDATE ON workflow_plan_v2_activation_preparation_claims
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_logical_activation_preparation_claim_update();

CREATE FUNCTION automata_validate_logical_activation_preparation_prerequisite()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_activation_preparation_claims AS claim
        JOIN workflow_plan_v2_dependencies AS dependency
          ON dependency.run_id = claim.run_id
         AND dependency.invocation_id = claim.invocation_id
         AND dependency.logical_job_id = claim.logical_job_id
         AND dependency.prerequisite_job_id = NEW.prerequisite_job_id
        JOIN workflow_plan_v2_jobs AS prerequisite_job
          ON prerequisite_job.run_id = dependency.run_id
         AND prerequisite_job.invocation_id = dependency.invocation_id
         AND prerequisite_job.id = dependency.prerequisite_job_id
        JOIN workflow_plan_v2_job_results AS result
          ON result.run_id = dependency.run_id
         AND result.invocation_id = dependency.invocation_id
         AND result.logical_job_id = dependency.prerequisite_job_id
        JOIN workflow_plan_v2_job_result_claims AS result_claim
          ON result_claim.logical_job_id = result.logical_job_id
         AND result_claim.state = 'finalized'
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.state = 'preparing'
          AND prerequisite_job.logical_key = NEW.logical_key
          AND prerequisite_job.source_order = NEW.source_order
          AND result.descriptor_digest = NEW.result_descriptor_digest
          AND result.outputs_digest = NEW.outputs_digest
          AND result.commit_digest = NEW.commit_digest
          AND result.effective_conclusion = NEW.effective_conclusion
          AND result.closure_has_failure = NEW.closure_has_failure
          AND result.closure_has_cancelled = NEW.closure_has_cancelled
          AND result.closure_has_skipped = NEW.closure_has_skipped
          AND result.output_count = NEW.output_count
          AND result.finalized_at_ms = NEW.finalized_at_ms
          AND NEW.finalized_at_ms <= claim.evidence_ready_at_ms
    ) THEN
        RAISE EXCEPTION 'logical activation prerequisite pin lacks exact finalized result'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_preparation_prerequisites_validate
BEFORE INSERT ON workflow_plan_v2_activation_preparation_prerequisites
FOR EACH ROW
EXECUTE FUNCTION automata_validate_logical_activation_preparation_prerequisite();

CREATE FUNCTION automata_validate_logical_activation_preparation_output()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_activation_preparation_prerequisites AS pin
        JOIN workflow_plan_v2_activation_preparation_claims AS claim
          ON claim.logical_job_id = pin.logical_job_id
         AND claim.state = 'preparing'
        JOIN workflow_plan_v2_job_result_outputs AS output
          ON output.logical_job_id = pin.prerequisite_job_id
         AND output.output_name = NEW.output_name
        WHERE pin.logical_job_id = NEW.logical_job_id
          AND pin.prerequisite_job_id = NEW.prerequisite_job_id
          AND output.sensitivity = NEW.sensitivity
          AND output.public_value IS NOT DISTINCT FROM NEW.public_value
    ) THEN
        RAISE EXCEPTION 'logical activation output pin lacks exact classified result output'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_preparation_outputs_validate
BEFORE INSERT ON workflow_plan_v2_activation_preparation_outputs
FOR EACH ROW
EXECUTE FUNCTION automata_validate_logical_activation_preparation_output();

CREATE FUNCTION automata_validate_logical_activation_preparation_complete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    expected_prerequisites INTEGER;
    actual_prerequisites BIGINT;
BEGIN
    SELECT claim.prerequisite_count
      INTO expected_prerequisites
    FROM workflow_plan_v2_activation_preparation_claims AS claim
    WHERE claim.logical_job_id = NEW.logical_job_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT count(*) INTO actual_prerequisites
    FROM workflow_plan_v2_activation_preparation_prerequisites AS pin
    WHERE pin.logical_job_id = NEW.logical_job_id
      AND pin.output_count = (
          SELECT count(*)
          FROM workflow_plan_v2_activation_preparation_outputs AS output
          WHERE output.logical_job_id = pin.logical_job_id
            AND output.prerequisite_job_id = pin.prerequisite_job_id
      );
    IF actual_prerequisites <> expected_prerequisites THEN
        RAISE EXCEPTION 'logical activation preparation pin set is incomplete'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_plan_v2_activation_preparation_claim_complete
AFTER INSERT OR UPDATE ON workflow_plan_v2_activation_preparation_claims
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_validate_logical_activation_preparation_complete();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_activation_preparation_pin_complete
AFTER INSERT ON workflow_plan_v2_activation_preparation_prerequisites
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_validate_logical_activation_preparation_complete();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_activation_preparation_output_complete
AFTER INSERT ON workflow_plan_v2_activation_preparation_outputs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_validate_logical_activation_preparation_complete();

CREATE FUNCTION automata_validate_logical_activation_preparation_binding()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_activation_preparation_claims AS claim
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.state = 'preparing'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND NEW.bound_at_ms >= claim.claimed_at_ms
          AND NEW.bound_at_ms < claim.expires_at_ms
    ) THEN
        RAISE EXCEPTION 'logical activation preparation binding lacks a live exact fence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_preparations_validate
BEFORE INSERT ON workflow_plan_v2_activation_preparations
FOR EACH ROW
EXECUTE FUNCTION automata_validate_logical_activation_preparation_binding();

CREATE FUNCTION automata_reject_logical_activation_preparation_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'logical activation preparation evidence is immutable'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_preparations_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_activation_preparations
FOR EACH ROW
EXECUTE FUNCTION automata_reject_logical_activation_preparation_mutation();

CREATE TRIGGER workflow_plan_v2_activation_preparation_prerequisites_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_activation_preparation_prerequisites
FOR EACH ROW
EXECUTE FUNCTION automata_reject_logical_activation_preparation_mutation();

CREATE TRIGGER workflow_plan_v2_activation_preparation_outputs_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_activation_preparation_outputs
FOR EACH ROW
EXECUTE FUNCTION automata_reject_logical_activation_preparation_mutation();

CREATE FUNCTION automata_reject_logical_activation_preparation_claim_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'logical activation preparation claim is durable'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_preparation_claims_reject_delete
BEFORE DELETE ON workflow_plan_v2_activation_preparation_claims
FOR EACH ROW
EXECUTE FUNCTION automata_reject_logical_activation_preparation_claim_delete();

-- The first activation claim, every renewal, and every takeover must use the
-- immutable prepared input digest. No caller-created context can enter through
-- the lower-level activation table update.
CREATE OR REPLACE FUNCTION automata_enforce_workflow_plan_v2_activation_input()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.activation_input_digest IS NOT NULL
        AND NEW.activation_input_digest IS DISTINCT FROM OLD.activation_input_digest
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 activation input digest is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.state = 'activating' AND NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_activation_preparations AS preparation
        JOIN workflow_plan_v2_activation_preparation_claims AS preparation_claim
          ON preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.state = 'prepared'
        WHERE preparation.run_id = NEW.run_id
          AND preparation.invocation_id = NEW.invocation_id
          AND preparation.logical_job_id = NEW.id
          AND preparation.activation_input_digest = NEW.activation_input_digest
          AND preparation.bound_at_ms <= NEW.activation_claimed_at_ms
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 activation input lacks durable preparation'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

-- Publication is current only when it uses the exact immutable prepared input.
CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_activation_publication()
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
        JOIN workflow_plan_v2_activation_preparations AS preparation
          ON preparation.run_id = job.run_id
         AND preparation.invocation_id = job.invocation_id
         AND preparation.logical_job_id = job.id
        JOIN workflow_plan_v2_activation_preparation_claims AS preparation_claim
          ON preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.state = 'prepared'
        WHERE job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.id = NEW.logical_job_id
          AND job.execution_kind = 'steps'
          AND job.state = 'activating'
          AND job.activation_owner_id = NEW.activation_owner_id
          AND job.activation_fence = NEW.activation_generation
          AND job.activation_input_digest = NEW.activation_input_digest
          AND job.activation_claimed_at_ms = NEW.activation_claimed_at_ms
          AND job.activation_expires_at_ms = NEW.activation_expires_at_ms
          AND job.activation_claimed_at_ms <= NEW.published_at_ms
          AND job.activation_expires_at_ms > NEW.published_at_ms
          AND preparation.activation_input_digest = NEW.activation_input_digest
          AND preparation.bound_at_ms <= job.activation_claimed_at_ms
          AND invocation.plan_schema = 2
          AND invocation.state IN ('pending', 'active')
          AND invocation.id = marker.root_invocation_id
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 publication lacks an exact prepared live claim'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;
